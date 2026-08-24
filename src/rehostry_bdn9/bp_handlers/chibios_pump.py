# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The three seams that make ChibiOS' ARMv6-M port actually run under unicorn.

All three are addresses recovered by disassembling the image
(``tools/extract_firmware.py`` verifies every one of them against the bytes
before the config is allowed to load).

--------------------------------------------------------------------------
1. ``ChibiosNmiSwitch`` -- the context switch (``port_exit_from_isr_spin``)
--------------------------------------------------------------------------

**ChibiOS' ARMv6-M port performs its post-interrupt context switch through an
NMI**, and unicorn implements no such thing.  ``_port_exit_from_isr`` in this
image is::

    080001c6:  bl   0x8007ec8          @ chSchDoReschedule()
    080001ca:  ldr  r2, =0xE000ED04    @ SCB->ICSR
    080001cc:  ldr  r3, =0x80000000    @ NMIPENDSET
    080001ce:  str  r3, [r2, #0]
    080001d0:  b    .                  @ <- and waits here for the NMI

The core watches ``SCB->ICSR`` for **PENDSVSET** (bit 28) and delivers PendSV;
it has no NMIPENDSET path, and the private peripheral bus is otherwise plain RW
memory, so on an unmodified core that store is a no-op and the kernel spins in
``b .`` for ever.  The failure has no fault, no output and no MMIO: it looks
exactly like a hung scheduler, and it happens on the **first** interrupt the
device ever takes.

The fix is a device-side seam, not a core change: intercept the spin and inject
exception 2.  ``inject_irq(-14)`` reaches it because the backend computes
``vtor + (16 + n) * 4`` and ``vtor`` is 0 -- **Cortex-M0 has no VTOR**, so the
vector table really is at address 0, which is why the config maps flash at both
0x00000000 and 0x08000000.

Architecturally this is right rather than a hack: NMI is non-maskable, the
firmware has just requested it, and it can make no further progress until it
arrives.  ChibiOS' NMI handler discards the frame the NMI itself stacked so the
exception return pops the real thread context underneath -- which is why the
injection must stack on **PSP** (``crt0`` sets ``CONTROL = 2``) and carry
``EXC_RETURN = 0xFFFFFFFD``.  The core's Cortex-M path does both.

⚠ **AND THE NMI MUST ARRIVE ALONE, WHICH COSTS A REAL DEBUGGING SESSION TO
LEARN.**  The NMI handler in this image is four instructions::

    08008088: mrs r3, PSP ; adds r3, #32 ; msr PSP, r3 ; cpsie i ; bx lr

-- it discards **exactly one** stacked frame, assuming the frame beneath it is
the thread context.  On silicon that assumption holds because NMI is the
highest priority there is and a peripheral interrupt arriving during the switch
is *tail-chained*, not stacked.  Under a rehost nothing enforces that: the USB
line is drained from the backend's pending queue at whatever instruction the
chunk boundary happens to fall on, and if that lands inside
``_port_exit_from_isr`` the core stacks an **extra** 32-byte frame that the NMI
handler will never discard.

Nothing complains.  The run keeps working -- for minutes.  Each occurrence
leaks 32 bytes of the *current thread's* stack, and a ChibiOS working area is a
few hundred bytes, so eventually ``_port_switch`` pops a corrupted context and
the guest branches into hyperspace.  Measured on this device: **six clean
minutes** -- a complete enumeration, sixteen class round trips, a 20-second key
hold -- and then ``UC_ERR_WRITE_UNMAPPED`` at ``PC=0x00000008``, which is the
guest executing the *NMI vector word* as if it were code.  A wall that arrives
only after everything visible already works is the expensive kind.

**And draining the queue at the window's entry is NOT enough**, which is the
second half of the lesson.  ``chSchDoReschedule`` calls
``chVTGetSystemTimeX``, which **reads TIM2->CNT** -- and this device steps its
USB host from exactly that read, because a counter read is the cheapest "the
guest is executing" signal it has.  So the queue is refilled a handful of
instructions after it is drained, and the refilled entry is delivered at the
next chunk boundary, which lands inside the window often enough to matter.

So the entry breakpoint **inhibits** ``usb_pump`` from raising the line at all
until the NMI has been injected at the spin, and the idle seam lifts the
inhibit unconditionally so a window that somehow failed to close cannot deafen
the device silently.  Nothing is lost either way: the USB notification stays
latched in the endpoint registers, and ``usb_pump`` re-raises it on its next
visit.

--------------------------------------------------------------------------
2. ``ChibiosIdlePump`` -- the idle thread (``idle_thread_wfi``)
--------------------------------------------------------------------------

``_idle_thread`` here is two halfwords: ``wfi; b .-2`` at 0x08007F0C.  Reaching
it is the kernel *stating* it has nothing to run until a timer deadline, which
makes it the honest place to catch guest time up to the armed ``TIM2->CCR1``
compare and to deliver queued interrupts.  Jumping straight to the deadline
needs no rate calibration and cannot fire at a moment the firmware is not
expecting one (playbook 2.121: an idle-only catch-up, guards before the tick).

This matters enormously on *this* firmware, because QMK's ``init_usb_driver()``
does ``usbDisconnectBus(); chThdSleepMilliseconds(1500); usbStart();
usbConnectBus();``.  Without a clock that advances while the kernel sleeps, the
device never attaches to the bus at all and every USB claim in this repository
would be untestable.

ONE DELIVERER PER LINE (playbook 2.74).  TIM2 is delivered here; USB goes
through ``usb_pump`` and nowhere else, so exactly one code path can queue IRQ 31
whether the CPU is idle or busy.

--------------------------------------------------------------------------
3. ``ChibiosHaltProbe`` -- the firmware's own panic address
--------------------------------------------------------------------------

``chSysHalt()`` ends in ``b .`` at 0x08007B70 and ``_unhandled_exception`` at
0x08000196.  These are *not* pumped -- they are watched, so that "the device
looks busy" can never be mistaken for "the device is working".  A run that
reaches either has failed however healthy everything else looks, and
``attack.py`` reads the count back over the bridge.
"""
from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

from ..peripheral_models import backend_ref
from ..peripheral_models import stm32f0_timers as tim_mod
from ..peripheral_models import usb_pump
from ..peripheral_models.guest_clock import get_clock

log = hal_log.getHalLogger()

#: NMI is exception 2, and the backend computes exc = 16 + irq.
NMI_IRQ = -14

#: System ticks (100 us each) added per idle visit when NO compare is armed.
IDLE_DRIP = int(os.environ.get("HAL_BDN9_IDLE_DRIP", "1"))

#: Counters the panel and the attack read back.
HALTS = {"sys_halt": 0, "unhandled_exception": 0, "bootloader_jump": 0}


class ChibiosIdlePump(BPHandler):
    """Advance guest time and deliver queued interrupts at the idle seam."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.visits = 0
        self.tim2_delivered = 0
        self.deferred_ticks = 0
        self.jumps = 0
        self._announced = False
        self.qemu = None

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        self.qemu = qemu
        # The one place a device is handed the live backend (playbook 2.95):
        # the flash model needs it to erase real guest memory and usb_pump
        # needs it to queue IRQ 31 from an MMIO callback.
        backend_ref.set_backend(qemu)
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["idle_thread_wfi"])
    def idle(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        self.visits += 1
        if not self._announced:
            self._announced = True
            log.info("ChibiosIdlePump: armed at the ChibiOS idle thread's "
                     "`wfi` 0x%08x", bp_addr)

        clock = get_clock()
        tim2 = tim_mod.get_tim2()

        # --- 1. USB, through the single deliverer.  Reaching the idle thread
        # means any context switch has completed, so lift the inhibit
        # unconditionally: a window that somehow failed to close would
        # otherwise deafen the device silently.
        usb_pump.inhibit(False)
        usb_pump.pump(force=True)

        # --- 2. Time.  GUARDS BEFORE THE TICK (playbook 2.121).
        if tim2 is not None:
            # A compare that was DEFERRED (because something was already queued)
            # must be delivered here, before anything else.  The first version
            # of this handler just re-set the flag -- and `poll_compare()` had
            # already recorded the compare as fired, so `alarm_deadline()`
            # returned None for ever after and the deferred tick was simply
            # LOST.  The kernel then never woke from its timed sleep: USB kept
            # working (it is pumped from MMIO, not from the tick), the console
            # stayed silent, and the only visible symptom was that turning an
            # encoder produced nothing at all.  A dropped tick on a tickless
            # kernel is a stopped clock, not a late one.
            if tim2.pending_irq:
                if getattr(qemu, "_pending_irqs", None):
                    return False, None          # still busy; try again next visit
                irq = tim2.take_pending_irq()
                if irq is not None and self._vector_is_live(qemu, irq):
                    qemu.inject_irq(irq)
                    self.tim2_delivered += 1
                    self.deferred_ticks += 1
                return False, None

            deadline = tim2.alarm_deadline()
            if deadline is not None:
                if clock.catch_up_to(deadline):
                    self.jumps += 1
                if tim2.poll_compare():
                    # ONE EXCEPTION AT A TIME.  usb_pump.pump() ran a few lines
                    # up and may have just queued IRQ 31; adding TIM2 on top
                    # makes cont() synthesise the second entry on a handler
                    # that has not executed one instruction (playbook 2.98).
                    # Measured: TIM2 delivered *inside* the USB ISR --
                    # `exc_return 0xfffffff1 popped from MSP, resuming at
                    # 0x8008e00`.  `pending_irq` stays set and the branch above
                    # delivers it on the next visit.
                    if getattr(qemu, "_pending_irqs", None):
                        return False, None
                    irq = tim2.take_pending_irq()
                    if irq is not None and self._vector_is_live(qemu, irq):
                        qemu.inject_irq(irq)
                        self.tim2_delivered += 1
                        if (self.tim2_delivered in (1, 10, 100)
                                or self.tim2_delivered % 5000 == 0):
                            log.info("ChibiosIdlePump: delivered %d TIM2 "
                                     "compare interrupt(s), %d of them "
                                     "deferred; guest clock = %.3f s "
                                     "(idle visits=%d)",
                                     self.tim2_delivered, self.deferred_ticks,
                                     clock.ticks / 10000.0, self.visits)
                    return False, None
            else:
                clock.advance(IDLE_DRIP)
        return False, None

    @staticmethod
    def _vector_is_live(qemu, irq: int) -> bool:
        """Never inject an IRQ the firmware never wired up (playbook 2.74)."""
        try:
            slot = qemu.read_memory((16 + irq) * 4, 4, 1)
        except Exception:  # noqa: BLE001
            return True
        return bool(slot)


class ChibiosNmiSwitch(BPHandler):
    """Deliver the NMI ChibiOS' ARMv6-M context switch pends and waits for."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.switches = 0
        self.deferred = 0
        self._announced = False

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        self.qemu = qemu
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["port_exit_from_isr_spin"])
    def switch(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        if not self._announced:
            self._announced = True
            log.info("ChibiosNmiSwitch: armed at _port_exit_from_isr's spin "
                     "0x%08x -- ChibiOS ARMv6-M switches context through NMI",
                     bp_addr)
        # THE NMI MUST ARRIVE ALONE.  See the class docstring's third section:
        # ChibiOS' NMI handler discards exactly ONE stacked frame, so any other
        # exception delivered into this window leaks 32 bytes of the *thread's*
        # stack, and a ChibiOS working area is a few hundred bytes.
        pending = getattr(qemu, "_pending_irqs", None)
        if pending is not None:
            if NMI_IRQ in pending:
                return False, None          # already queued; do not pile up
            foreign = [i for i in pending if i != NMI_IRQ]
            if foreign:
                del pending[:]
                self.deferred += len(foreign)
                if self.deferred in (1, 10, 100) or self.deferred % 500 == 0:
                    log.info("ChibiosNmiSwitch: held back %d peripheral IRQ(s) "
                             "queued while the kernel was mid-context-switch "
                             "(latched in the peripheral, re-raised next pump)",
                             self.deferred)
        self.switches += 1
        if self.switches in (1, 10, 100) or self.switches % 5000 == 0:
            log.info("ChibiosNmiSwitch: delivered %d context-switch NMI(s)",
                     self.switches)
        qemu.inject_irq(NMI_IRQ)
        usb_pump.inhibit(False)         # the window closes here
        return False, None

    @bp_handler(["port_exit_from_isr"])
    def entering(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        """Same guard, one instruction earlier.

        ``_port_exit_from_isr`` starts with ``bl chSchDoReschedule``, and that
        call is the part of the window that is longest and least reentrant --
        it walks the ready list and runs ``_port_switch``.  Draining foreign
        IRQs here as well shrinks the window to the handful of instructions
        between the two breakpoints.
        """
        usb_pump.inhibit(True)
        pending = getattr(qemu, "_pending_irqs", None)
        if pending:
            foreign = [i for i in pending if i != NMI_IRQ]
            if foreign:
                del pending[:]
                self.deferred += len(foreign)
        return False, None


class ChibiosHaltProbe(BPHandler):
    """Watch the firmware's own failure addresses.  Pumps nothing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["sys_halt_spin"])
    def halted(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        HALTS["sys_halt"] += 1
        if HALTS["sys_halt"] == 1:
            log.error("ChibiosHaltProbe: *** the firmware reached its own "
                      "chSysHalt() spin at 0x%08x -- this run has FAILED ***",
                      bp_addr)
        return False, None

    @bp_handler(["unhandled_exception_spin"])
    def unhandled(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        HALTS["unhandled_exception"] += 1
        if HALTS["unhandled_exception"] == 1:
            log.error("ChibiosHaltProbe: *** the firmware took an exception it "
                      "has no handler for (0x%08x) -- this run has FAILED ***",
                      bp_addr)
        return False, None

    @bp_handler(["bootloader_jump_spin"])
    def dfu(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        HALTS["bootloader_jump"] += 1
        if HALTS["bootloader_jump"] == 1:
            log.info("ChibiosHaltProbe: the firmware jumped to the STM32F0 DFU "
                     "ROM (bootloader_jump, 0x%08x)", bp_addr)
        return False, None
