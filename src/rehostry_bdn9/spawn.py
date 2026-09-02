# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single source of truth for *how to run this device* under HALucinator.

Both the standalone CLI (`rehostry-bdn9 run`) and the orchestrator binding
build their HALucinator invocation from here, so there is exactly one spawn
recipe: HALucinator is run on the **unicorn** backend with this device's
config(s), optionally overlaying a host bridge.

HALucinator is a *runtime* dependency reached as a separate process; it is not
imported here. It must be importable by the spawned interpreter, which is the
*installed* ``halucinator`` in the running interpreter's environment
(``sys.executable``, overridable via the ``HAL_PY`` env var). We deliberately do
NOT splice any source tree onto PYTHONPATH: a polluted ``HALUCINATOR_SRC`` /
``PYTHONPATH`` must never resurrect an out-of-tree core, so both are stripped
from the child env (see :func:`spawn_env`).
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from . import paths

# The host-facing seam is the modelled USB host's line bridge: it accepts
# `REQ <tag> <bmRequestType> <bRequest> <wValue> <wIndex> <wLength> [outhex]`
# and publishes `RESP <tag> ok|stall <hex>` / `IN <ep> <hex>` lines.  Ports come
# from this device's DEVICE-QUEUE.md row (27260-27279), not from a guess.
BRIDGE_PORT = int(os.environ.get("BDN9_BRIDGE_PORT", "27260"))
PANEL_PORT = int(os.environ.get("BDN9_PANEL_PORT", "27261"))
#: Symbolic seam id, for the binding.
UART_SEAM = "usb-ep0-control (STM32F0 USB device peripheral @0x40005C00, IRQ 31)"


# ZMQ peripheral-bus ports. HALucinator's peripheral_server.start() BINDS the
# machine-global ipc endpoints /tmp/IoServer2Halucinator<rx> and
# /tmp/Halucinator2IoServer<tx>; its own defaults are 5555/5556, so two devices
# left on the default silently share one bus and inject each other's peripheral
# messages into the wrong guest. This device therefore owns a distinct default
# pair, overridable via the env vars below.
DEFAULT_RX_PORT = int(os.environ.get("BDN9_RX_PORT", "27262"))
DEFAULT_TX_PORT = int(os.environ.get("BDN9_TX_PORT", "27263"))


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               bridge: bool = False,
               rx_port: Optional[int] = None,
               tx_port: Optional[int] = None) -> list[str]:
    """argv for ``python -m halucinator.main`` with this device's configs.

    Config files are passed by basename and resolved against :func:`spawn_cwd`.
    With ``bridge=True`` the host-bridge overlay is appended.
    """
    argv = [python or os.environ.get("HAL_PY") or sys.executable,
            "-m", "halucinator.main"]
    for f in (paths.CONFIG_FILES
              + ([paths.BRIDGE_CONFIG] if (bridge and paths.BRIDGE_CONFIG)
                 else [])):
        argv += ["-c", f]
    argv += ["--emulator", emulator]
    if rx_port is None:
        rx_port = DEFAULT_RX_PORT
    if tx_port is None:
        tx_port = DEFAULT_TX_PORT
    argv += ["--rx_port", str(rx_port), "--tx_port", str(tx_port)]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames + the relative
    ``file: bdn9.bin`` in the memory config resolve."""
    return str(paths.configs_dir())


def spawn_env(halucinator_src: Optional[str] = None,
              extra: Optional[dict] = None) -> dict:
    """Environment for the spawned HALucinator process.

    The child runs the *installed* ``halucinator@dev``, so we defensively strip
    ``HALUCINATOR_SRC`` and ``PYTHONPATH`` from the inherited environment: a
    polluted value must not resurrect an out-of-tree core. The
    ``halucinator_src`` argument is accepted for API compatibility but ignored.
    Force unbuffered output so the console streams promptly.
    """
    env = dict(os.environ)
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"
    # HAL_IRQ_CHUNK: `irq_chunk` defaults to 0 on cortex-m, i.e. an unbounded
    # emu_start that never returns to the point where the backend drains its
    # pending-IRQ queue.  usb_pump appends to that queue rather than calling
    # inject_irq (which would emu_stop from inside an MMIO callback), so
    # without a bounded chunk the USB interrupt is queued and never delivered
    # (playbook 2.50 / 2.99).
    env.setdefault("HAL_IRQ_CHUNK", "20000")
    # ARMv6-M runs on unicorn's cortex-m3 model; say so explicitly rather than
    # relying on the config alone.
    #
    # The value must be a `UC_CPU_ARM_*` CONSTANT NAME. The backend resolves it
    # with `getattr(arm_const, name) if name.startswith("UC_CPU_ARM_") else
    # None`, so the lowercase part name "cortex-m3" that used to be here was
    # REJECTED: the backend logged `unknown HAL_CORTEXM_CPU_MODEL='cortex-m3';
    # using UC_CPU_ARM_CORTEX_M3` on every run and fell back. The fallback
    # happens to be the core this device wants, so behaviour was correct by
    # luck and the explicit statement did nothing -- the same "looks like it
    # works and does nothing" trap as writing `cpu_model:` in the YAML.
    env.setdefault("HAL_CORTEXM_CPU_MODEL", "UC_CPU_ARM_CORTEX_M3")
    if extra:
        env.update(extra)
    return env
