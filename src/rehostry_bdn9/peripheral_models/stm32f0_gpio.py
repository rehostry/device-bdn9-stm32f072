# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GPIOA..GPIOF -- and why this must not be a catch-all.

Under the ``AutoPeripheral`` catch-all, reading an input port is a tight loop
reading **one address from one PC**, which is precisely the shape the busy-wait
breaker mistakes for a stalled poll: it escalates the value it returns until the
read "changes", and a keyboard fed escalating ``IDR`` values sees phantom keys
for ever (playbook 2.40).

So ``IDR`` is **derived**, not stored:

* a pin configured as an **output** (``MODER`` = 01) reads back its ``ODR`` bit;
* a pin configured as an **input** reads its pull resistor -- ``PUPDR`` = 10
  (pull-down) reads 0, anything else reads 1 (a pulled-up switch input);
* **unless** something in the modelled world is holding it low.

THE SWITCH WIRING IS NOT GUESSED -- IT IS READ OUT OF THE IMAGE.  This board has
**no matrix scan at all**: it uses QMK's ``DIRECT_PINS``, nine switches each on
its own pin.  The reader at 0x0800221C walks a table of ChibiOS ``ioline_t``
values (``port_base | pad``) at **0x0800AE2C**, three per row, and treats a pin
that reads **0** as pressed::

    r2 = 12 * row;  r2 += 0x0800AE2C
    for (3 columns) {
        line = *(uint32_t *)r2;
        if (line == 0xFFFFFFFF) continue;      /* NO_PIN */
        bit = (*(uint32_t *)((line & ~0xF) + 0x10) >> (line & 0xF)) & 1;
        result |= (bit - 1) & mask;            /* active LOW */
        mask <<= 1;  r2 += 4;
    }

which decodes to ``PB12 PB5 PB6 / PB14 PB4 PB7 / PA3 PF1 PF0``.  The three
rotary encoders are read the same way at 0x0800592C from two more tables --
pad A at 0x0800AF7C (``PA4 PA15 PA9``) and pad B at 0x0800AF88
(``PA8 PB3 PA10``).  ``tools/extract_firmware.py`` re-verifies all fifteen
words, so a different build fails loudly instead of injecting into thin air.

Finding that mattered twice.  A model written for a *scanned* matrix waits for a
column to be driven low, and on this firmware nothing ever is: the only
``BSRR`` writer in a whole boot is the **WS2812 bit-bang** at 0x08005A70 (an
8-bit loop of ``set; nops; clear; nops``), which a scan-shaped model happily
mislearns as a column.

NOTE what this device does **not** claim from any of it.  PROVENANCE.md 3b shows
statically that the keymap is nine ``KC_TRANSPARENT`` halfwords on a single
layer, so no key on this build can ever emit a HID report.  This model exists so
the firmware's own input paths run correctly, and so ``attack.py`` can *test*
that prediction against the wire rather than asserting it.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from halucinator import hal_log
from halucinator.peripheral_models.generic import GenericPeripheral

from . import usb_pump
from .guest_clock import get_clock

log = hal_log.getHalLogger()

PORT_STRIDE = 0x400
PORT_NAMES = "ABCDEF"

MODER, OTYPER, OSPEEDR, PUPDR, IDR, ODR, BSRR, LCKR, AFRL, AFRH, BRR = (
    0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28)

_TRACE = os.environ.get("HAL_BDN9_GPIO_TRACE") == "1"

#: Input reads between quadrature phases.  One full encoder+switch poll is
#: nine direct-pin reads plus six encoder-pad reads, so this is about one phase
#: per poll -- fast enough to finish a detent promptly, slow enough that the
#: firmware's own driver sees every transition.
ENC_PHASE_EVERY = int(os.environ.get("HAL_BDN9_ENC_PHASE_EVERY", "16"))


def _pin(port: str, pad: int) -> Tuple[int, int]:
    return (PORT_NAMES.index(port), pad)


def _name(pin: Tuple[int, int]) -> str:
    return "P%s%d" % (PORT_NAMES[pin[0]], pin[1])


#: DIRECT_PINS[row][col], flattened -- table at 0x0800AE2C.
DIRECT_PINS: List[Tuple[int, int]] = [
    _pin("B", 12), _pin("B", 5), _pin("B", 6),
    _pin("B", 14), _pin("B", 4), _pin("B", 7),
    _pin("A", 3), _pin("F", 1), _pin("F", 0),
]
#: encoders_pad_a[] at 0x0800AF7C and encoders_pad_b[] at 0x0800AF88.
ENCODER_PAD_A: List[Tuple[int, int]] = [_pin("A", 4), _pin("A", 15), _pin("A", 9)]
ENCODER_PAD_B: List[Tuple[int, int]] = [_pin("A", 8), _pin("B", 3), _pin("A", 10)]

_GPIO: Optional["Stm32F0GpioPage"] = None


def get_gpio() -> Optional["Stm32F0GpioPage"]:
    return _GPIO


class Stm32F0GpioPage(GenericPeripheral):
    """The whole GPIO band (0x48000000, 6 ports x 0x400) as one model."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.clock = get_clock()
        # GPIOA..GPIOF: six ports.  The band is mapped 8 kB wide because a
        # HALucinator region must be a 4 kB multiple; the two pages past
        # GPIOF are unused address space.
        self.n_ports = min(len(PORT_NAMES), max(1, size // PORT_STRIDE))
        self.regs: List[Dict[int, int]] = [
            {MODER: 0, OTYPER: 0, OSPEEDR: 0, PUPDR: 0, ODR: 0}
            for _ in range(self.n_ports)]
        # GPIOA's MODER/PUPDR reset values put PA13/PA14 in AF (SWD); nothing
        # in this firmware reads them before writing, so 0 is safe.
        self._lock = threading.RLock()

        #: (port, pin) pairs the modelled world is holding low: a pressed
        #: direct-pin switch, or an encoder pad at its current quadrature level.
        self._forced_low: Set[Tuple[int, int]] = set()
        self._pressed: Set[int] = set()
        #: quadrature phase per encoder, and how many phase steps are still owed
        self._enc_phase: List[int] = [3] * len(ENCODER_PAD_A)
        self._enc_pending: List[int] = [0] * len(ENCODER_PAD_A)
        self._enc_dir: List[int] = [1] * len(ENCODER_PAD_A)
        self.enc_steps_applied = 0
        self.idr_reads = 0
        global _GPIO
        _GPIO = self
        for i in range(len(ENCODER_PAD_A)):
            self._apply_phase(i)
        log.info("Stm32F0GpioPage: modelling GPIO%s..GPIO%s at 0x%08x "
                 "(IDR is DERIVED, never escalated); direct-pin switches %s, "
                 "encoder pads A=%s B=%s -- all read out of the image",
                 PORT_NAMES[0], PORT_NAMES[self.n_ports - 1], address,
                 [_name(p) for p in DIRECT_PINS],
                 [_name(p) for p in ENCODER_PAD_A],
                 [_name(p) for p in ENCODER_PAD_B])

    # ---- host-facing --------------------------------------------------
    def wiring(self) -> Dict[str, Any]:
        return {
            "direct_pins": [_name(p) for p in DIRECT_PINS],
            "encoder_pad_a": [_name(p) for p in ENCODER_PAD_A],
            "encoder_pad_b": [_name(p) for p in ENCODER_PAD_B],
            "pressed": sorted(self._pressed),
            "idr_reads": self.idr_reads,
            "encoder_steps_applied": self.enc_steps_applied,
        }

    def press(self, index: int) -> Optional[str]:
        """Hold switch ``index`` (0..8) down: its own pin reads 0."""
        if not 0 <= index < len(DIRECT_PINS):
            return None
        log.info("Stm32F0GpioPage: switch %d (%s) DOWN "
                 "[encoder phases %s, pending %s]", index,
                 _name(DIRECT_PINS[index]), self._enc_phase, self._enc_pending)
        with self._lock:
            self._pressed.add(index)
            self._forced_low.add(DIRECT_PINS[index])
        return _name(DIRECT_PINS[index])

    def release(self, index: Optional[int] = None) -> None:
        log.info("Stm32F0GpioPage: switch %s UP [encoder steps applied %d]",
                 index, self.enc_steps_applied)
        with self._lock:
            if index is None:
                for i in list(self._pressed):
                    self._forced_low.discard(DIRECT_PINS[i])
                self._pressed.clear()
            elif index in self._pressed:
                self._pressed.discard(index)
                self._forced_low.discard(DIRECT_PINS[index])

    def encoder_turn(self, index: int, clockwise: bool,
                     detents: int = 1) -> bool:
        """Queue ``detents`` detents of rotation on encoder ``index``.

        A detent is ENCODER_RESOLUTION quadrature phases; the phases are applied
        one per ``ENC_PHASE_EVERY`` input reads so the firmware's own poll sees
        each transition, exactly as it would on a turning shaft.
        """
        if not 0 <= index < len(ENCODER_PAD_A):
            return False
        with self._lock:
            # QMK's encoder_update (0x080059CC) accumulates
            # `pulses += encoder_LUT[state]` from the LUT at 0x0800AF6C and
            # calls its handler with `clockwise = false` on `pulses >= +4` and
            # `clockwise = true` on `pulses <= -4`.  So walking the Gray code
            # FORWARD is QMK's counter-clockwise, and this sign flip is what
            # makes "cw" here mean "cw" there.  Measured: getting it backwards
            # turns a volume knob the wrong way and nothing complains.
            self._enc_dir[index] = -1 if clockwise else 1
            self._enc_pending[index] += 4 * max(1, detents)
        return True

    #: Gray code the pads walk: phase -> (pad A level, pad B level).
    _PHASE = ((0, 0), (1, 0), (1, 1), (0, 1))

    def _apply_phase(self, index: int) -> None:
        a, b = self._PHASE[self._enc_phase[index] & 3]
        for pin, level in ((ENCODER_PAD_A[index], a), (ENCODER_PAD_B[index], b)):
            if level:
                self._forced_low.discard(pin)
            else:
                self._forced_low.add(pin)

    def _advance_encoders(self) -> None:
        for i in range(len(ENCODER_PAD_A)):
            if self._enc_pending[i] <= 0:
                continue
            self._enc_pending[i] -= 1
            self._enc_phase[i] = (self._enc_phase[i] + self._enc_dir[i]) & 3
            self._apply_phase(i)
            self.enc_steps_applied += 1
            if _TRACE:
                log.info("Stm32F0GpioPage: encoder %d -> phase %d (%d left)",
                         i, self._enc_phase[i], self._enc_pending[i])

    @staticmethod
    def _pin_name(pin: Tuple[int, int]) -> str:
        return _name(pin)

    # ---- derived IDR ---------------------------------------------------
    def _pin_mode(self, port: int, pin: int) -> int:
        return (self.regs[port][MODER] >> (pin * 2)) & 0x3

    def _pin_pull(self, port: int, pin: int) -> int:
        return (self.regs[port][PUPDR] >> (pin * 2)) & 0x3

    def _idr(self, port: int) -> int:
        value = 0
        for pin in range(16):
            mode = self._pin_mode(port, pin)
            if mode == 1:                                    # output
                bit = (self.regs[port][ODR] >> pin) & 1
            else:
                pull = self._pin_pull(port, pin)
                bit = 0 if pull == 2 else 1                  # pull-down -> 0
                if (port, pin) in self._forced_low:
                    bit = 0
            value |= bit << pin
        return value

    # ---- MMIO ------------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        port = offset // PORT_STRIDE
        off = (offset % PORT_STRIDE) & ~0x3
        if port >= self.n_ports:
            return 0
        self.clock.advance_from_activity()
        usb_pump.pump()
        with self._lock:
            if off == IDR:
                self.idr_reads += 1
                if self.idr_reads % ENC_PHASE_EVERY == 0:
                    self._advance_encoders()
                value = self._idr(port)
            else:
                value = self.regs[port].get(off, 0)
        if _TRACE:
            log.info("GPIO%s READ  pc=0x%08x +0x%02x -> 0x%08x",
                     PORT_NAMES[port], pc, off, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        port = offset // PORT_STRIDE
        off = (offset % PORT_STRIDE) & ~0x3
        if port >= self.n_ports:
            return True
        value &= 0xFFFFFFFF
        self.clock.advance_from_activity()
        usb_pump.pump()
        with self._lock:
            if off == BSRR:
                odr = self.regs[port][ODR]
                odr |= value & 0xFFFF                 # BS[15:0] set
                odr &= ~((value >> 16) & 0xFFFF)      # BR[31:16] reset
                self.regs[port][ODR] = odr & 0xFFFF
            elif off == BRR:
                self.regs[port][ODR] &= ~(value & 0xFFFF)
            elif off == ODR:
                self.regs[port][ODR] = value & 0xFFFF
            else:
                self.regs[port][off] = value
        if _TRACE:
            log.info("GPIO%s WRITE pc=0x%08x +0x%02x = 0x%08x",
                     PORT_NAMES[port], pc, off, value)
        return True
