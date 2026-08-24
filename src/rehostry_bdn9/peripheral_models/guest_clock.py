# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The one time base the whole rehost shares.

ChibiOS is configured **tickless** here: there is no periodic tick at all.  The kernel reads a free-running 32-bit counter for "now"
and programs a **compare** for the next deadline it cares about.  So this device
needs a monotonic counter *and* the compare interrupt that counter raises --
modelling only the counter produces a firmware that reads plausible timestamps
and computes correct deltas while no delayed work item ever runs (playbook
2.89).

Units are ChibiOS **system ticks**: 10 kHz, i.e. 100 us each -- what
``STM32_ST_TIM->PSC = (48 MHz / 10 kHz) - 1`` programs on the real part.  This
matters concretely on a BDN9: QMK's ``init_usb_driver()`` sleeps **1500 ms**
between ``usbDisconnectBus()`` and ``usbConnectBus()``, so 15 000 of these ticks
have to elapse before the device is electrically on the bus at all.

TWO THINGS MOVE IT, and both are deliberate:

``advance_from_activity()``
    Called from the peripheral models on MMIO accesses.  An MMIO access is
    evidence the guest is executing, so this keeps time moving while the
    firmware is *busy* -- scanning the matrix, driving the RGB output -- where
    no idle seam is ever reached (playbook 2.77).  It is deliberately coarse and
    explicitly **not calibrated**: see STATUS.md.

``catch_up_to(deadline)``
    Called **only** from the idle seam, and only when the kernel has armed a
    compare it is waiting for.  The idle thread running *is* the firmware
    stating it has nothing to do until that deadline, so jumping straight there
    is the honest model and needs no rate calibration at all (playbook 2.121
    calls for exactly this shape: an idle-only catch-up, with every guard
    evaluated before the first tick).

INVARIANTS (playbook 2.66):

1. **A read never advances it.**  Otherwise the kernel re-arms "now + delta"
   for ever and the alarm recedes as fast as it is chased.
2. **It never goes backwards.**  A non-monotonic counter walks the delta list
   off the end.
3. It is 32 bits and wraps, like the hardware; every comparison against it is a
   *signed* difference, never ``>=`` (playbook 2.101).
"""
from __future__ import annotations

import os
import threading

from halucinator import hal_log

log = hal_log.getHalLogger()

MASK32 = 0xFFFFFFFF

#: MMIO accesses per system tick while the guest is busy.  Chosen so a boot's
#: worth of SPI/LCD traffic advances time at a plausible-but-uncalibrated rate;
#: too fast and periodic work runs before what it operates on is initialised
#: (playbook 2.124), too slow and elapsed-time waits never expire.
ACTIVITY_PER_TICK = int(os.environ.get("HAL_BDN9_MMIO_PER_TICK", "64"))


class GuestClock:
    """A monotonic 32-bit 10 kHz counter, plus the compare it feeds."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ticks = 0
        self._activity = 0

    # -- reading ------------------------------------------------------------
    @property
    def ticks(self) -> int:
        return self._ticks & MASK32

    # -- advancing ----------------------------------------------------------
    def advance_from_activity(self, n: int = 1) -> None:
        # HOT PATH -- called from every modelled MMIO access, millions of times
        # per boot (the matrix scan alone is three GPIO accesses per column).  No
        # lock: a bare int increment is atomic under the GIL, and the only
        # cross-thread reader wants a monotonically increasing number, not an
        # exact one.  Taking an RLock here measurably slowed the boot.
        self._activity += n
        if self._activity >= ACTIVITY_PER_TICK:
            self._ticks = (self._ticks
                           + self._activity // ACTIVITY_PER_TICK) & MASK32
            self._activity %= ACTIVITY_PER_TICK

    def catch_up_to(self, deadline: int) -> bool:
        """Jump to ``deadline`` if it is in the future.  Idle seam only.

        Returns True if time moved.  Uses a *signed* 32-bit difference so a
        deadline just past a wrap is still recognised as in the future.
        """
        with self._lock:
            delta = (deadline - self._ticks) & MASK32
            if delta == 0 or delta >= 0x80000000:
                return False                     # already reached, or past
            self._ticks = deadline & MASK32
            return True

    def advance(self, n: int) -> None:
        with self._lock:
            self._ticks = (self._ticks + n) & MASK32


_CLOCK = GuestClock()


def get_clock() -> GuestClock:
    return _CLOCK


def elapsed_ge(now: int, deadline: int) -> bool:
    """True once ``now`` has reached ``deadline``, wrap-safely."""
    return ((now - deadline) & MASK32) < 0x80000000
