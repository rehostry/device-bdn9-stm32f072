# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The two STM32F0 timers this firmware genuinely depends on.

``Stm32F0Tim2Page`` -- 0x40000000, covering **TIM2** (+0x000) and TIM3 (+0x400).
    TIM2 is ChibiOS' system time base.  ``mcuconf.h`` sets
    ``STM32_ST_USE_TIMER = 2`` and ``chconf.h`` sets ``CH_CFG_ST_TIMEDELTA = 2``,
    so the port runs in **free-running (tickless) mode**: ``st_lld_init``
    programs ``PSC = 48 MHz/10 kHz - 1``, ``ARR = 0xFFFFFFFF``, ``CR1 = CEN``,
    and thereafter

        st_lld_get_counter()  -> TIM2->CNT
        st_lld_start_alarm(t) -> TIM2->CCR1 = t; TIM2->SR = 0; TIM2->DIER = CC1IE
        st_lld_set_alarm(t)   -> TIM2->CCR1 = t
        st_lld_stop_alarm()   -> TIM2->DIER = 0

    **The compare is the whole point.**  A CNT that merely advances gives the
    kernel correct timestamps and correct deltas, and *nothing ever wakes*: every
    ``chThdSleep`` blocks for ever (playbook 2.89).  So this model raises
    ``SR.CC1IF`` when the clock reaches ``CCR1`` and records a pending IRQ 15
    for the pump to deliver -- models raise flags, handlers inject (playbook
    2.95).

    The compare is **one-shot** (playbook 2.128): a reached deadline stays
    reached, so re-firing on every subsequent visit would starve every other
    line.  It re-arms when the firmware writes ``CCR1`` again, which is exactly
    what ``st_lld_set_alarm`` does from inside the ISR.

    Note the vector table proves this is *not* a SysTick device: slot 15
    (SysTick) is the weak ``_unhandled_exception`` stub while slot 31 (IRQ 15,
    TIM2) has a real handler at 0x08008D0C.  One check that saves applying playbook 2.6's recipe to a
    kernel that does not use SysTick at all (playbook 2.41).

``Stm32F0Tim14Page`` -- 0x40002000, covering **TIM14** (+0x000), RTC (+0x800)
    and WWDG (+0xC00).
    TIM14 is a microsecond delay: ``gptStart(&GPTD14, {1 MHz})`` then
    ``gptPolledDelay(&GPTD14, t)``, which is

        ARR = t-1;  EGR = UG;  CR1 = OPM|URS|CEN;  while (!(SR & UIF));  SR = 0;

    -- a **polled** wait on the update flag.  Left to the catch-all the
    busy-wait breaker does eventually escape it, but only by returning garbage
    into a register the firmware also reads for other purposes.  Modelling it
    is four lines: accept the one-pulse start, report ``UIF`` set.

    The delay is **not** made to cost real time here beyond the shared clock's
    activity-driven advance; a rehost that actually spun for `t` microseconds of
    wall time would take hours to boot.  Stated in STATUS.md.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from halucinator import hal_log
from halucinator.peripheral_models.generic import GenericPeripheral

from . import usb_pump
from .guest_clock import MASK32, elapsed_ge, get_clock

log = hal_log.getHalLogger()

#: HAL_BDN9_TIM_TRACE=1 logs the first access to each (pc, offset) on the timer
#: pages.  On a stripped image that is the cheapest way to answer "is my model
#: even being reached, and at which offset" (playbook 2.131: instrument, do not
#: hypothesise).
_TRACE = __import__("os").environ.get("HAL_BDN9_TIM_TRACE") == "1"
_seen = set()


def _trace(tag, pc, offset, value):
    key = (tag, pc, offset)
    if key in _seen:
        return
    _seen.add(key)
    log.info("%s pc=0x%08x +0x%03x = 0x%08x", tag, pc, offset, value)

# ---- STM32 general-purpose timer register offsets -------------------------
CR1, CR2, SMCR, DIER, SR, EGR = 0x00, 0x04, 0x08, 0x0C, 0x10, 0x14
CCMR1, CCMR2, CCER, CNT, PSC, ARR = 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C
CCR1, CCR2, CCR3, CCR4 = 0x34, 0x38, 0x3C, 0x40

CR1_CEN, CR1_URS, CR1_OPM = 1 << 0, 1 << 2, 1 << 3
DIER_UIE, DIER_CC1IE = 1 << 0, 1 << 1
SR_UIF, SR_CC1IF = 1 << 0, 1 << 1
EGR_UG = 1 << 0

#: STM32F072 NVIC line for TIM2 (RM0091 table 37).  ``inject_irq(15)`` reaches
#: vector slot (16 + 15) * 4 = 0x7C, which this image fills with a real handler.
TIM2_IRQ = 15


class PolledOneShotTimer:
    """A general-purpose STM32 timer used only through ``gptPolledDelay``.

    ChibiOS' ``gpt_lld_polled_delay`` is::

        ARR = t-1;  EGR = UG;  CR1 = OPM|URS|CEN;  while (!(SR & UIF));  SR = 0;

    -- a **polled** wait on the update flag with no interrupt involved.  Two of
    this board's timers are driven that way and BOTH have to be modelled: TIM14
    is the generic microsecond delay.  **TIM3 has a live vector in this
    image** (slot 32 = IRQ 16 -> 0x08008DA0), so it is not spare storage
    either: it is left with the same one-pulse ``UIF`` semantics so a polled
    delay through it ends, and its interrupt is delivered only if the firmware
    actually arms ``DIER``.

    Modelling only TIM14 leaves the other timer falling through to plain
    storage, ``SR.UIF`` reading 0 for ever, and the boot spinning in the *same
    four instructions* of the *same shared LLD function* -- a PC histogram
    identical to the TIM14 case, pointing at code that is provably working,
    because the firmware reaches it through a different driver object (playbook
    2.69: a seam on a driver method is a seam on every instance of that
    driver).
    """

    def __init__(self, label: str) -> None:
        self.label = label
        self.regs: Dict[int, int] = {}
        self.sr = 0
        self.delays = 0
        self.periodic = False

    def read(self, off: int) -> int:
        if off == SR:
            return self.sr
        if off == CNT:
            return self.regs.get(ARR, 0)          # one-pulse: parked at the top
        return self.regs.get(off, 0)

    def write(self, off: int, value: int) -> None:
        if off == SR:
            # write-0-to-clear; NEVER echo (playbook 2.67)
            self.sr &= value
            return
        if off == CR1:
            self.regs[off] = value
            if value & CR1_CEN:
                if value & CR1_OPM:
                    # The one-pulse delay has started.  Report it complete: the
                    # firmware's own `while (!(SR & UIF))` ends on its next read.
                    self.sr |= SR_UIF
                    self.delays += 1
                else:
                    self.periodic = True
            return
        if off == EGR and value & EGR_UG:
            return
        self.regs[off] = value

_TIM2: Optional["Stm32F0Tim2Page"] = None


def get_tim2() -> Optional["Stm32F0Tim2Page"]:
    return _TIM2


class Stm32F0Tim2Page(GenericPeripheral):
    """TIM2 (ChibiOS' free-running system clock + its compare) and TIM3."""

    TIM2_OFF, TIM3_OFF = 0x000, 0x400

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.clock = get_clock()
        self.regs: Dict[int, int] = {}           # TIM2
        #: TIM3 (+0x400) is NOT spare storage -- ui_init() drives it through
        #: gptPolledDelay before it starts it continuously, so it needs the
        #: same one-pulse UIF semantics as TIM14.
        self.tim3 = PolledOneShotTimer("TIM3")
        self.sr = 0
        self.armed = False                       # DIER.CC1IE
        self.ccr1 = 0
        self._fired_ccr: Optional[int] = None
        self.compares = 0
        self.pending_irq = False
        global _TIM2
        _TIM2 = self
        log.info("Stm32F0Tim2Page: TIM2 is ChibiOS' tickless time base "
                 "(10 kHz free-running CNT + CC1 compare -> IRQ %d)", TIM2_IRQ)

    # -- interface for the pump --------------------------------------------
    def alarm_deadline(self) -> Optional[int]:
        """The compare value the kernel is waiting for, or None."""
        if not self.armed:
            return None
        if self._fired_ccr is not None and self._fired_ccr == self.ccr1:
            return None                          # already delivered this one
        return self.ccr1 & MASK32

    def poll_compare(self) -> bool:
        """Latch CC1IF if the clock has reached the armed compare.

        Returns True when a *new* interrupt became pending.  Called from the
        pump, not from an MMIO callback -- a model raises the flag, the handler
        injects (playbook 2.95).
        """
        dl = self.alarm_deadline()
        if dl is None:
            return False
        if not elapsed_ge(self.clock.ticks, dl):
            return False
        self._fired_ccr = self.ccr1
        self.sr |= SR_CC1IF
        self.compares += 1
        self.pending_irq = True
        return True

    def take_pending_irq(self) -> Optional[int]:
        if not self.pending_irq:
            return None
        self.pending_irq = False
        return TIM2_IRQ

    # -- MMIO ---------------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if offset >= self.TIM3_OFF:
            self.clock.advance_from_activity()
            if _TRACE:
                _trace("TIM3 READ ", pc, offset - self.TIM3_OFF, 0)
            return self.tim3.read((offset - self.TIM3_OFF) & ~0x3)
        off = offset & ~0x3
        if off == CNT:
            # The kernel reads CNT constantly, which makes it the cheapest
            # "the guest is executing" signal on this device -- so the USB
            # host is stepped from here as well as from the idle seam.
            usb_pump.pump()
            # A READ MUST NOT ADVANCE THE CLOCK (playbook 2.66-1): the kernel
            # arms "now + delta", so a self-advancing counter makes every
            # deadline recede exactly as fast as it is chased.
            return self.clock.ticks
        if off == SR:
            return self.sr
        if off == CCR1:
            return self.ccr1
        if off == DIER:
            return DIER_CC1IE if self.armed else 0
        return self.regs.get(off, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if offset >= self.TIM3_OFF:
            self.clock.advance_from_activity()
            if _TRACE:
                _trace("TIM3 WRITE", pc, offset - self.TIM3_OFF, value)
            self.tim3.write((offset - self.TIM3_OFF) & ~0x3, value & 0xFFFFFFFF)
            return True
        off = offset & ~0x3
        value &= 0xFFFFFFFF
        if off == SR:
            # Write-0-to-clear on the STM32 timers: the ISR writes 0 to drop
            # every flag.  Never echo (playbook 2.67) -- a status register that
            # stores what was written makes the wait immortal.
            self.sr &= value
            return True
        if off == CCR1:
            self.ccr1 = value
            self._fired_ccr = None               # re-arm: this is a NEW alarm
            return True
        if off == DIER:
            was = self.armed
            self.armed = bool(value & DIER_CC1IE)
            if self.armed and not was:
                self._fired_ccr = None
            return True
        if off == EGR and value & EGR_UG:
            return True                          # UG reloads; CNT is our clock
        self.regs[off] = value
        return True


class Stm32F0Tim14Page(GenericPeripheral):
    """TIM14 (the ``gptPolledDelay`` microsecond timer), RTC and WWDG."""

    TIM14_OFF, RTC_OFF, WWDG_OFF = 0x000, 0x800, 0xC00

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.clock = get_clock()
        self.tim14 = PolledOneShotTimer("TIM14")
        self.other: Dict[int, int] = {}
        log.info("Stm32F0Tim14Page: TIM14 serves gptPolledDelay (one-pulse "
                 "microsecond waits)")

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if _TRACE:
            _trace("TIM14 READ ", pc, offset, 0)
        if offset >= self.RTC_OFF:
            return self.other.get(offset & ~0x3, 0)
        return self.tim14.read(offset & ~0x3)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if _TRACE:
            _trace("TIM14 WRITE", pc, offset, value)
        if offset >= self.RTC_OFF:
            self.other[offset & ~0x3] = value & 0xFFFFFFFF
            return True
        self.tim14.write(offset & ~0x3, value & 0xFFFFFFFF)
        # A microsecond delay is not made to cost real time -- a rehost that
        # actually spun would take hours to boot -- but it is guest ACTIVITY,
        # so the shared clock moves.  Stated in STATUS.md.
        self.clock.advance_from_activity(8)
        return True
