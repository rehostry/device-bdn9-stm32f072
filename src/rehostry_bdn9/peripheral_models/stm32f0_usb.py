# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The STM32F0 USB device peripheral -- the only wire a BDN9 speaks on.

A macropad has no console, no network and no debug UART.  The vector table
proves the seam: every USART slot in this image is the weak
``_unhandled_exception`` stub, while slot 31 (USB) has a real handler at
0x08008E00.  Reaching anything the firmware computes therefore means modelling
the device peripheral *and* writing the host that drives it (playbook 2.80).

TWO REGIONS, because the block is split:

``USB registers`` at 0x40005C00 (RM0091 30.6)
    ``EP0R..EP7R`` (0x00..0x1C), ``CNTR`` (0x40), ``ISTR`` (0x44), ``FNR``
    (0x48), ``DADDR`` (0x4C), ``BTABLE`` (0x50), and -- **new on the F0, absent
    on the F1** -- ``BCDR`` (0x58) whose ``DPPU`` bit is the D+ pull-up.
    ``usbConnectBus()`` is ``BCDR |= DPPU``: that is the firmware saying "you may
    now consider me plugged in", and a host that enumerates before it is a host
    talking to a device that has not attached (playbook 2.140's ST-HAL
    soft-disconnect trap, in F0 clothing).  QMK's ``init_usb_driver()`` does
    ``usbDisconnectBus(); chThdSleepMilliseconds(1500); usbStart(); usbConnectBus();``
    -- so the host waits, and 1.5 s of *guest* time has to actually elapse
    before it can do anything at all.

``Packet memory (PMA)`` at 0x40006000
    **THE ACCESS SCHEME IS NOT THE F1's.**  On the STM32F1 the CPU sees PMA as
    16-bit halfwords in 32-bit slots, so a PMA byte offset ``n`` lives at CPU
    offset ``2n``.  On the STM32F0 (and L0/F3) it is a flat **1:1** mapping --
    ChibiOS selects between them with ``STM32_USB_ACCESS_SCHEME_2x16``, which
    ``STM32F0xx/stm32_registry.h`` sets ``TRUE``, making ``stm32_usb_pma_t`` a
    ``uint16_t`` so ``USB_ADDR2PTR(addr) = addr * 1 + PMA_BASE`` and a buffer
    descriptor is 4 x uint16 = **8 bytes**.  Port the F1 model across unchanged
    and every buffer address is doubled: the firmware then parses descriptor
    bytes out of the wrong place, which reads as a protocol bug and is an
    addressing one.

THE ENDPOINT REGISTERS ARE NOT ORDINARY STORAGE.  Each ``EPnR`` mixes:

  * **toggle** bits -- ``STAT_TX`` (5:4), ``STAT_RX`` (13:12), ``DTOG_TX`` (6),
    ``DTOG_RX`` (14).  A write **XORs** them; it does not assign them.
  * **write-0-to-clear** bits -- ``CTR_TX`` (7), ``CTR_RX`` (15).  Writing 1
    leaves them alone.  (ChibiOS' ``EPR_CLEAR_CTR_RX`` relies on exactly this:
    it writes ``CTR_TX`` set and ``CTR_RX`` clear to drop only the RX flag.)
  * plain read/write bits -- type, kind, address.

AND ``ISTR.CTR`` IS DERIVED, NOT STORED.  ChibiOS' low-priority ISR is::

    while (istr & ISTR_CTR) { usb_serve_endpoints(usbp, istr & EP_ID); istr = ISTR; }

It never writes ISTR to clear ``CTR`` -- on silicon that bit is a live OR of
every endpoint's ``CTR_RX``/``CTR_TX``, and ``EP_ID``/``DIR`` name one endpoint
that has one set.  A model that latches ``ISTR = CTR | ep`` and waits to be
written clear therefore **spins in that while loop for ever**.  Compute it.
"""
from __future__ import annotations

import os
import struct
import threading
from typing import Any, Dict, List, Optional

from halucinator import hal_log
from halucinator.peripheral_models.generic import GenericPeripheral

from .guest_clock import get_clock

log = hal_log.getHalLogger()

# ---- register offsets within the USB block --------------------------------
USB_BASE_IN_PAGE = 0xC00          # 0x40005C00 within the 0x40005000 page
CNTR, ISTR, FNR, DADDR, BTABLE, LPMCSR, BCDR = (0x40, 0x44, 0x48, 0x4C, 0x50,
                                                0x54, 0x58)
N_ENDPOINTS = 8

# EPnR bit fields (RM0091 30.6.2)
EP_CTR_RX = 1 << 15
EP_DTOG_RX = 1 << 14
EP_STAT_RX = 0x3 << 12
EP_SETUP = 1 << 11
EP_TYPE = 0x3 << 9
EP_KIND = 1 << 8
EP_CTR_TX = 1 << 7
EP_DTOG_TX = 1 << 6
EP_STAT_TX = 0x3 << 4
EP_EA = 0x0F

EP_TOGGLE_MASK = EP_STAT_RX | EP_DTOG_RX | EP_STAT_TX | EP_DTOG_TX
EP_W0C_MASK = EP_CTR_RX | EP_CTR_TX
EP_RW_MASK = EP_TYPE | EP_KIND | EP_EA

STAT_DISABLED, STAT_STALL, STAT_NAK, STAT_VALID = 0, 1, 2, 3

# CNTR bits
CNTR_FRES = 1 << 0
CNTR_PDWN = 1 << 1

# ISTR bits
ISTR_CTR = 1 << 15
ISTR_RESET = 1 << 10
ISTR_SUSP = 1 << 11
ISTR_WKUP = 1 << 12
ISTR_SOF = 1 << 9
ISTR_ESOF = 1 << 8
ISTR_DIR = 1 << 4
ISTR_EP_ID = 0x0F

# BCDR
BCDR_DPPU = 1 << 15

#: The F0's packet memory is 1 KB.
PMA_SIZE = 1024

_REGS: Optional["Stm32F0UsbRegs"] = None
_PMA: Optional["Stm32F0UsbPma"] = None

_TRACE = os.environ.get("HAL_BDN9_USB_TRACE") == "1"


def get_usb() -> Optional["Stm32F0UsbRegs"]:
    return _REGS


def get_pma() -> Optional["Stm32F0UsbPma"]:
    return _PMA


class Stm32F0UsbPma(GenericPeripheral):
    """USB packet memory: 1 KB, seen by the CPU **1:1** (not the F1's 2:1)."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.mem = bytearray(PMA_SIZE)
        #: The page also carries the **CRS** (clock recovery system) block at
        #: +0xC00, which trims HSI48 against USB SOF.  It has no wait loop in
        #: this firmware, so plain storage is enough -- but it must not be
        #: swallowed by the PMA bounds check, or the write vanishes and the
        #: read that follows it returns a byte of packet memory.
        self.storage: Dict[int, int] = {}
        self._lock = threading.RLock()
        global _PMA
        _PMA = self
        log.info("Stm32F0UsbPma: %d bytes of packet memory at 0x%08x "
                 "(STM32F0 access scheme: 1:1, NOT the F1's halfword-in-slot)",
                 PMA_SIZE, address)

    # -- flat view, for the modelled host ----------------------------------
    def read_flat(self, offset: int, length: int) -> bytes:
        with self._lock:
            return bytes(self.mem[offset:offset + length])

    def write_flat(self, offset: int, data: bytes) -> None:
        with self._lock:
            self.mem[offset:offset + len(data)] = data

    # -- CPU view (identical addressing) ------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if offset + size > PMA_SIZE:
            return self.storage.get(offset & ~0x3, 0)
        with self._lock:
            raw = bytes(self.mem[offset:offset + size])
        return int.from_bytes(raw, "little")

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if offset + size > PMA_SIZE:
            self.storage[offset & ~0x3] = value & 0xFFFFFFFF
            return True
        with self._lock:
            self.mem[offset:offset + size] = (value & ((1 << (size * 8)) - 1)
                                              ).to_bytes(size, "little")
        return True


class Stm32F0UsbRegs(GenericPeripheral):
    """USB control/endpoint registers, with correct toggle + derived-ISTR
    semantics.  Shares its 4 kB page with I2C1 (+0x400) and I2C2 (+0x800),
    which fall through to plain storage."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.storage: Dict[int, int] = {}
        self.regs: Dict[int, int] = {}
        self.epr: List[int] = [0] * N_ENDPOINTS
        self.events = 0                # ISTR bits other than CTR (RESET, ...)
        self.enabled = False
        self.attached = False          # BCDR.DPPU -- the firmware "plugged in"
        self.resets = 0
        self.sofs = 0
        self._lock = threading.RLock()
        self.clock = get_clock()
        global _REGS
        _REGS = self
        log.info("Stm32F0UsbRegs: modelling the USB device peripheral at "
                 "0x%08x", address + USB_BASE_IN_PAGE)
        # BIND THE HOST BRIDGE HERE, at config-load time, and NOT lazily on the
        # first pump.  A lazy bind is gated on the guest reaching
        # `CNTR &= ~PDWN`, which makes the stalled-guest control vacuous: with
        # no bridge there is nothing to connect to, so "the client saw nothing"
        # would be indistinguishable from "the client could not attach at all"
        # (playbook: a control that asserts an absence is vacuous under a stall
        # that also produces that absence).  Binding here keeps the entire host
        # stack demonstrably alive while every firmware-side field goes false.
        from . import usb_host                      # deferred: usb_host imports
        usb_host.get_host()                         # this module for EP_CTR_*

    # -- interface for the modelled host -----------------------------------
    def btable(self) -> int:
        with self._lock:
            return self.regs.get(BTABLE, 0) & 0xFFF8

    def daddr(self) -> int:
        with self._lock:
            return self.regs.get(DADDR, 0) & 0x7F

    def daddr_enabled(self) -> bool:
        with self._lock:
            return bool(self.regs.get(DADDR, 0) & 0x80)

    def ep_stat_rx(self, ep: int) -> int:
        return (self.epr[ep] & EP_STAT_RX) >> 12

    def ep_stat_tx(self, ep: int) -> int:
        return (self.epr[ep] & EP_STAT_TX) >> 4

    def raise_ctr_rx(self, ep: int, setup: bool = False) -> None:
        """'A packet arrived on this endpoint', the way the silicon does it."""
        with self._lock:
            self.epr[ep] |= EP_CTR_RX
            if setup:
                self.epr[ep] |= EP_SETUP
            else:
                self.epr[ep] &= ~EP_SETUP
            # Receiving leaves the endpoint NAK until the firmware re-arms it.
            self.epr[ep] = (self.epr[ep] & ~EP_STAT_RX) | (STAT_NAK << 12)

    def raise_ctr_tx(self, ep: int) -> None:
        with self._lock:
            self.epr[ep] |= EP_CTR_TX
            self.epr[ep] = (self.epr[ep] & ~EP_STAT_TX) | (STAT_NAK << 4)

    def raise_reset(self) -> None:
        with self._lock:
            self.events |= ISTR_RESET
            self.resets += 1

    def raise_sof(self) -> None:
        """Latch a Start-Of-Frame.  **This is not decoration.**

        A USB host emits a SOF token every 1 ms, and ChibiOS' CDC driver hangs
        its output flush off it: ``sof_handler`` -> ``sduSOFHookI`` ->
        ``obqTryFlushI`` -> ``usbStartTransmitI``.  An output queue holds a
        partially-filled buffer until it is full **or** a SOF flushes it, so a
        modelled host that never generates SOF produces a device that composes
        its entire reply, buffers it, and transmits nothing -- with the shell
        thread then blocked in ``VNAShell_readLine`` and every other part of the
        system looking perfectly healthy.  (Same family as playbook 2.47 and
        2.70: check the publish side before blaming the parser.)
        """
        with self._lock:
            self.events |= ISTR_SOF
            self.sofs += 1

    # -- ISTR is COMPUTED ---------------------------------------------------
    def _istr(self) -> int:
        """ISTR as the hardware presents it: ``CTR`` ORed across the endpoints,
        with ``EP_ID``/``DIR`` naming one that has a transfer complete."""
        value = self.events
        for ep in range(N_ENDPOINTS):
            epr = self.epr[ep]
            if epr & (EP_CTR_RX | EP_CTR_TX):
                value |= ISTR_CTR | (ep & ISTR_EP_ID)
                # DIR: 0 = the completed transaction was IN (CTR_TX),
                #      1 = it was OUT/SETUP (CTR_RX).  RX wins when both are
                #      set, matching the reference manual.
                if epr & EP_CTR_RX:
                    value |= ISTR_DIR
                break
        return value & 0xFFFF

    # -- MMIO ---------------------------------------------------------------
    def _usb_off(self, offset: int) -> Optional[int]:
        if USB_BASE_IN_PAGE <= offset < USB_BASE_IN_PAGE + 0x60:
            return offset - USB_BASE_IN_PAGE
        return None

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        off = self._usb_off(offset)
        if off is None:
            return self.storage.get(offset & ~0x3, 0)
        self.clock.advance_from_activity()
        with self._lock:
            if off < N_ENDPOINTS * 4:
                value = self.epr[off // 4]
            elif off == ISTR:
                value = self._istr()
            elif off == FNR:
                value = 0
            else:
                value = self.regs.get(off, 0)
        if _TRACE:
            log.info("Usb: READ  pc=0x%08x +0x%02x -> 0x%04x", pc, off, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        off = self._usb_off(offset)
        if off is None:
            self.storage[offset & ~0x3] = value
            return True
        value &= 0xFFFF
        self.clock.advance_from_activity()
        with self._lock:
            if off < N_ENDPOINTS * 4:
                ep = off // 4
                cur = self.epr[ep]
                new = (cur & EP_TOGGLE_MASK) ^ (value & EP_TOGGLE_MASK)
                new |= (cur & EP_W0C_MASK) & (value & EP_W0C_MASK)
                new |= value & EP_RW_MASK
                new |= cur & EP_SETUP          # SETUP is read-only to the CPU
                self.epr[ep] = new & 0xFFFF
                if _TRACE:
                    log.info("Usb: EP%dR pc=0x%08x write 0x%04x: 0x%04x -> "
                             "0x%04x (STAT_RX=%d STAT_TX=%d)", ep, pc, value,
                             cur, self.epr[ep], self.ep_stat_rx(ep),
                             self.ep_stat_tx(ep))
                return True
            if off == ISTR:
                # Write-0-to-clear, and only the latched events are ours to
                # clear -- CTR is derived from the endpoint registers.
                self.events &= value
                if _TRACE:
                    log.info("Usb: ISTR  pc=0x%08x write 0x%04x -> events "
                             "0x%04x", pc, value, self.events)
                return True
            if off == CNTR:
                was = self.enabled
                self.enabled = not (value & (CNTR_PDWN | CNTR_FRES))
                if self.enabled and not was:
                    log.info("Stm32F0UsbRegs: firmware released the USB reset "
                             "(CNTR=0x%04x) -- the transceiver is powered",
                             value)
                self.regs[off] = value
                return True
            if off == BCDR:
                was = self.attached
                self.attached = bool(value & BCDR_DPPU)
                if self.attached != was:
                    log.info("Stm32F0UsbRegs: firmware %s the D+ pull-up "
                             "(BCDR.DPPU) -- the device is %s the bus",
                             "asserted" if self.attached else "released",
                             "ON" if self.attached else "OFF")
                self.regs[off] = value
                return True
            if off == DADDR:
                prev = self.regs.get(off, 0)
                self.regs[off] = value
                if (value & 0x7F) != (prev & 0x7F) and (value & 0x7F):
                    log.info("Stm32F0UsbRegs: firmware accepted USB address %d",
                             value & 0x7F)
                return True
            self.regs[off] = value
        if _TRACE:
            log.info("Usb: WRITE pc=0x%08x +0x%02x = 0x%04x", pc, off, value)
        return True
