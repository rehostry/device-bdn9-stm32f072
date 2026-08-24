# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-bdn9 -- a Keebio BDN9 rev2 macropad (QMK on ChibiOS, STM32F072 /
Cortex-M0) as a standalone, pip-installable HALucinator device.

Nine direct-pin switches, three rotary encoders, and a USB HID stack with three
interfaces.  The device is self-contained: its configs ship as package data and
are referenced by the installed module path (`rehostry_bdn9.*`), with no
`project.` symlink and no `HALUCINATOR_SRC` source-tree injection.  The firmware
itself is GPLv2 QMK and is NOT redistributed -- `tools/extract_firmware.py`
regenerates it, and hard-fails if the image is not the one this device was
built against.

See PROVENANCE.md for the pre-boot prediction (its own commit, ahead of
everything that can boot the firmware) and STATUS.md for what was earned.
"""
from . import paths, spawn
from .binding import bdn9

__version__ = "0.0.1"

__all__ = ["paths", "spawn", "bdn9", "__version__"]


# This device spawns halucinator in a CHILD process, so this parent never
# imports `halucinator` and needs no sys.path guard -- `spawn.py` strips
# HALUCINATOR_SRC/PYTHONPATH from the child env instead.  (An IN-PROCESS device
# would need the `_prefer_installed_core()` guard here; see device-solo1.)
