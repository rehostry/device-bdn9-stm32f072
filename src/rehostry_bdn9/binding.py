# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Orchestrator binding: expose this device to rehostry/orchestrator.

This is the adapter a co-simulation scenario imports. It depends on the
orchestrator package (`rehostry`), so it's an OPTIONAL extra -- the device runs
fine standalone (via the CLI) without it. The import is lazy so merely importing
`rehostry_bdn9` never requires the orchestrator to be installed.

"""
from __future__ import annotations

from typing import Optional

from . import paths, spawn

# Static description of the device (also what a future halucinator entry-point
# plugin hook would advertise).
bdn9 = {
    "name": "bdn9",
    "uart_seam": spawn.UART_SEAM,
    "config_files": paths.CONFIG_FILES,
    "bridge_config": None,          # the USB host's bridge is always present
    "bridge_port": spawn.BRIDGE_PORT,
    "panel_port": spawn.PANEL_PORT,
    "telemetry": "line protocol over tcp/%d: REQ/RESP drives EP0 control "
                 "transfers, IN publishes HID reports, KEY/ENC inject the "
                 "nine direct-pin switches and the three rotary encoders"
                 % spawn.BRIDGE_PORT,
}


def make_device(name: str = "bdn9",
                halucinator_src: Optional[str] = None,
                bridge: bool = True,
                python: Optional[str] = None, log_path: Optional[str] = None):
    """Build a rehostry.Device for this device, wired with the spawn recipe.

    Requires the `rehostry` orchestrator package
    (install `rehostry-bdn9[orchestrator]`).
    """
    try:
        from rehostry import Device, SpawnSpec
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "make_device needs the orchestrator: pip install 'rehostry-bdn9[orchestrator]'"
        ) from e

    spec = SpawnSpec(
        argv=spawn.spawn_argv(python=python),
        cwd=spawn.spawn_cwd(),
        env=spawn.spawn_env(halucinator_src=halucinator_src),
        log_path=log_path,
        readiness_marker=None,
        join_delay=6.0,
    )
    return Device(name, None, uart_id=spawn.BRIDGE_PORT, spawn=spec)
