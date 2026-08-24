# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The live backend, published once so peripheral models can reach guest memory.

A peripheral model is never handed the backend; a **bp_handler is**, at
``register_handler`` time, and that is the one place a device gets it (playbook
2.95). Two models here need it:

``stm32f0_rcc.Stm32F0FlashIface``
    to perform a real page erase.  A flash controller that accepts the erase
    and leaves the bytes alone turns "the calibration store was wiped" into
    "the firmware asked for it to be wiped", which is a much weaker claim -- and
    a storage layer that reads the sector back would catch it (playbook 2.135).

``usb_pump``
    to queue the USB interrupt on the backend's own pending list.

Guest **memory** access from an MMIO callback is fine, and deferring it is
actively harmful (playbook 2.95); it is exceptions and ``emu_stop`` that must
wait for a safe context.
"""
from __future__ import annotations

from typing import Any, Optional

_BACKEND: Optional[Any] = None


def set_backend(qemu: Any) -> None:
    global _BACKEND
    _BACKEND = qemu


def get_backend() -> Optional[Any]:
    return _BACKEND
