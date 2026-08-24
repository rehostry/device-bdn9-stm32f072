# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SoC catch-all for the STM32F072 pages this device does not model.

Straight subclass of ``AutoPeripheral`` under a **different class name**, which
is the point: the core sets ``backend.skip_svc = True`` for any peripheral class
whose ``__name__`` is exactly ``AutoPeripheral`` (playbook trap 2.11), and that
suppresses ``svc`` vectoring for the whole run.

It happens not to matter for ChibiOS' ARMv6-M port -- it switches context by
pending an **NMI**, not by ``svc``, and the SVCall vector in this image is the
weak ``_unhandled_exception`` stub -- but the renamed subclass costs nothing and
removes a whole class of silent failure if a later config ever needs SVC.

DIAGNOSTICS
-----------

``HAL_BDN9_READ_TRACE=1``
    Log every distinct ``(pc, address)`` read pair once.  On a stripped image
    the PC histogram says *where* the firmware is spinning but not *what* it is
    waiting for; this names the register the hot instruction reads.  Deduped, so
    a loop running millions of times still produces one line.

``HAL_BDN9_WRITE_TRACE=1``
    The same for writes -- which is how you find out which peripheral bases the
    firmware actually touches, as opposed to which ones appear as literals
    (playbook 2.76).
"""
from __future__ import annotations

import os
from typing import Any, Set, Tuple

from halucinator.peripheral_models.auto_model import AutoPeripheral
from halucinator import hal_log

log = hal_log.getHalLogger()

_READ_TRACE = os.environ.get("HAL_BDN9_READ_TRACE") == "1"
_WRITE_TRACE = os.environ.get("HAL_BDN9_WRITE_TRACE") == "1"
_seen_r: Set[Tuple[int, int]] = set()
_seen_w: Set[Tuple[int, int]] = set()


class SocCatchAll(AutoPeripheral):
    """AutoPeripheral behaviour, without tripping the core's `skip_svc` check."""

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        value = super().hw_read(offset, size, pc=pc, **kwargs)
        if _READ_TRACE:
            key = (pc, self.address + offset)
            if key not in _seen_r:
                _seen_r.add(key)
                log.info("SocCatchAll: READ  pc=0x%08x addr=0x%08x -> 0x%08x",
                         pc, self.address + offset, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if _WRITE_TRACE:
            key = (pc, self.address + offset)
            if key not in _seen_w:
                _seen_w.add(key)
                log.info("SocCatchAll: WRITE pc=0x%08x addr=0x%08x <- 0x%08x",
                         pc, self.address + offset, value)
        return super().hw_write(offset, size, value, pc=pc, **kwargs)
