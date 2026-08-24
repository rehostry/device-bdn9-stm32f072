# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The one place USB transactions are stepped and IRQ 31 is raised.

WHY NOT JUST THE IDLE SEAM.  The obvious home for an interrupt pump is the RTOS
idle thread, and that is right until the firmware stops idling.  QMK's
``keyboard_task()`` runs a matrix scan every ``MATRIX_SCAN`` iteration of a
loop that never blocks for long, so between scans the CPU is busy, not idle.
A pump attached only to the idle seam then services USB in bursts separated by
whole scan periods -- and during the 1.5 s ``chThdSleepMilliseconds`` in
``init_usb_driver()`` there is no traffic to service at all.

So this module is called from **both**: from the modelled MMIO paths (the
matrix scan is the hottest, three GPIO accesses per column) and from the idle
seam, and it is the *only* code that can put IRQ 31 on the backend's pending
list (playbook 2.74 -- one deliverer per line).

HOW THE INTERRUPT IS RAISED, and why not ``inject_irq``.  ``inject_irq()``
appends to the backend's pending queue **and calls ``emu_stop()``**, which from
inside an MMIO callback abandons the instruction in flight.  A bare
``list.append`` is safe from there; the backend drains the queue at the top of
its run loop, which is a clean instruction boundary (playbook 2.99).  That drain
is only reached because ``spawn.py`` sets ``HAL_IRQ_CHUNK`` -- ``irq_chunk``
defaults to **0** on cortex-m, i.e. an unbounded ``emu_start`` that never
returns to the drain point (playbook 2.50).

AND IT REFUSES TO QUEUE A SECOND while one is outstanding: two entries in that
queue is a *nested* exception, not two interrupts (playbook 2.98).  Nothing is
lost by waiting -- the notification stays latched in the endpoint registers.

SOF.  A real full-speed host emits a Start-Of-Frame every 1 ms.  ChibiOS' USB
driver and QMK's HID send path both hang work off it, so it is generated here,
paced off the **guest** clock rather than the host's, which keeps a run
reproducible.
"""
from __future__ import annotations

import os
from typing import Optional

from halucinator import hal_log

from . import backend_ref
from . import stm32f0_usb as usb_mod
from . import usb_host as host_mod
from .guest_clock import elapsed_ge, get_clock

log = hal_log.getHalLogger()

#: STM32F072 NVIC line 31 = USB (RM0091 table 37).  Vector slot 47.
USB_IRQ = 31

#: Modelled MMIO accesses per host step while the guest is busy.
STEP_EVERY = int(os.environ.get("HAL_BDN9_USB_STEP_EVERY", "48"))

#: Guest system ticks (100 us each) between SOF tokens.  10 == 1 ms.
SOF_PERIOD_TICKS = int(os.environ.get("HAL_BDN9_SOF_TICKS", "10"))

_calls = 0
_next_sof = 0
_delivered = 0
_steps = 0
_inhibited = 0
_vector_ok: Optional[bool] = None
_inhibit_budget = 0

#: Pump calls the inhibit may last.  The window it covers is a handful of
#: TIM2->CNT reads, so this is generous -- but it MUST be bounded.  A latch
#: that is set at one breakpoint and cleared at another is only correct while
#: both are reached, and the first version of this file was not: one run where
#: the guest never came back to the closing breakpoint left the line withheld
#: for ever, and the device went permanently deaf with EP0's CTR_TX stuck set
#: and no fault anywhere.  An inhibit that cannot expire is a deadlock waiting
#: for the right interleaving.
INHIBIT_BUDGET = int(os.environ.get("HAL_BDN9_INHIBIT_BUDGET", "64"))


def inhibited() -> bool:
    return _inhibit_budget > 0


def inhibit(on: bool) -> None:
    """Stop raising IRQ 31 while the kernel is mid-context-switch.

    ``_port_exit_from_isr`` -> ``chSchDoReschedule`` -> ``chVTGetSystemTimeX``
    **reads TIM2->CNT**, and this module is stepped from that read (it is the
    cheapest "the guest is executing" signal on this device).  So the USB line
    gets queued from *inside* the one window where an extra stacked exception
    permanently leaks 32 bytes of the running thread's stack -- see
    ``bp_handlers/chibios_pump.py``.  Draining the queue at the window's
    entry breakpoint is not enough, because the queue is refilled a few
    instructions later.

    Nothing is lost: the endpoint's ``CTR`` flags stay latched, so the next
    pump after the window raises the same notification.
    """
    global _inhibit_budget, _inhibited
    if on:
        if _inhibit_budget == 0:
            _inhibited += 1
            if _inhibited in (1, 1000, 10000) or _inhibited % 50000 == 0:
                log.info("usb_pump: withheld the USB line across %d "
                         "context-switch window(s)", _inhibited)
        _inhibit_budget = INHIBIT_BUDGET
    else:
        _inhibit_budget = 0


def delivered() -> int:
    return _delivered


def steps() -> int:
    return _steps


def pump(force: bool = False) -> None:
    """Advance the USB host at most one transaction; raise IRQ 31 if needed.

    Safe to call from an MMIO callback.
    """
    global _calls, _delivered, _vector_ok, _next_sof, _steps, _inhibit_budget
    backend = backend_ref.get_backend()
    if backend is None:
        return
    # Spend the inhibit budget on EVERY visit, not only on the visits that
    # would have raised the line -- otherwise a window that opens during a
    # quiet stretch stays open for thousands of instructions.
    if _inhibit_budget > 0:
        _inhibit_budget -= 1
    if not force:
        _calls += 1
        if _calls < STEP_EVERY:
            return
        _calls = 0
    usb = usb_mod.get_usb()
    pma = usb_mod.get_pma()
    if usb is None or pma is None or not usb.enabled:
        return
    host = host_mod.get_host()

    raise_irq = False
    if usb.attached:
        now = get_clock().ticks
        if elapsed_ge(now, _next_sof):
            _next_sof = (now + SOF_PERIOD_TICKS) & 0xFFFFFFFF
            usb.raise_sof()
            raise_irq = True

    _steps += 1
    if host.step(usb, pma) and host.pending_irq:
        raise_irq = True
    if not raise_irq:
        return

    if _inhibit_budget > 0:
        # Mid-context-switch: the notification stays latched in the endpoint
        # registers and the next pump raises it.
        return
    pending = getattr(backend, "_pending_irqs", None)
    if pending is None:
        return
    if pending:
        return
    if _vector_ok is None:
        # Never inject an IRQ the firmware never wired up -- an unused vector
        # slot is literally 0 and inject_irq would load it into PC (2.74).
        try:
            slot = backend.read_memory((16 + USB_IRQ) * 4, 4, 1)
            _vector_ok = bool(slot)
        except Exception:  # noqa: BLE001
            _vector_ok = True
        if not _vector_ok:
            log.error("usb_pump: vector slot for IRQ %d is zero -- the "
                      "firmware never installed a USB handler", USB_IRQ)
    if not _vector_ok:
        return
    pending.append(USB_IRQ)
    _delivered += 1
    if _delivered in (1, 10, 100) or _delivered % 20000 == 0:
        log.info("usb_pump: raised USB IRQ %d (#%d); host state=%s",
                 USB_IRQ, _delivered, host.state)
