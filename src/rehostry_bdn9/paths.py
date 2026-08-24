# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Resource paths for the packaged HALucinator configs (+ firmware, if it is
redistributable).

Everything the device needs to run ships inside the installed package. These
helpers resolve those paths from the *installed* location via
``importlib.resources``, so the device runs from anywhere -- no cwd assumptions,
no `project.` PYTHONPATH hack.

"""
from __future__ import annotations

import importlib.resources as _ir
from pathlib import Path

PACKAGE = "rehostry_bdn9"

# The config files handed to `halucinator.main -c ...`, in load order. This is
# the base (headless) run; any host-bridge overlay is appended on demand -- see
# BRIDGE_CONFIG / config_paths(bridge=True).
CONFIG_FILES = [
    "bdn9_config.yaml",
    "bdn9_addrs.yaml",
]

# This device has no bridge overlay: the modelled USB host binds its control
# bridge as part of the base config, because the bridge IS the seam -- there is
# no version of this device that runs without a USB host.
BRIDGE_CONFIG = None

FIRMWARE_BIN = "bdn9.bin"
FIRMWARE_ELF = "bdn9.elf"


def configs_dir() -> Path:
    """Absolute path to the packaged configs/ dir (also where firmware lives)."""
    return Path(str(_ir.files(PACKAGE))) / "configs"


def config_paths(bridge: bool = False) -> list[Path]:
    files = list(CONFIG_FILES)
    if bridge and BRIDGE_CONFIG:
        files.append(BRIDGE_CONFIG)
    return [configs_dir() / f for f in files]


def firmware_bin() -> Path:
    return configs_dir() / FIRMWARE_BIN


def firmware_elf() -> Path:
    return configs_dir() / FIRMWARE_ELF


def firmware_present() -> bool:
    return firmware_bin().is_file()
