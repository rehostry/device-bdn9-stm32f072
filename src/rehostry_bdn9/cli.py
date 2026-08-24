# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`rehostry-bdn9` CLI: `run` | `panel` | `attack`.

`run` boots the firmware under HALucinator (unicorn) and streams its log to
stdout for `--seconds`, then reaps only the process tree it started.  The
modelled USB host's control bridge comes up with the device -- there is no
separate overlay config to layer on -- so a real client (or the web panel) can
drive the firmware's own USB stack over tcp/27260 for as long as `run` lasts.

`panel` starts the live web panel; `attack` runs the graded attack.  No
orchestrator and no `project.` symlink: the config's handler classes import
straight from the installed `rehostry_bdn9` package.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from . import paths, spawn


def _descendants(pid: int) -> list[int]:
    out: list[int] = []
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)],
                              capture_output=True, text=True).stdout.split()
    except (OSError, ValueError):
        kids = []
    for k in kids:
        out.extend(_descendants(int(k)))
        out.append(int(k))
    return out


def _kill_tree(proc: subprocess.Popen) -> None:
    # Kill ONLY the PIDs we started (via the Popen handle). NEVER `pkill -f
    # halucinator` -- a global pattern kill takes out other sessions' emulators
    # and the victim sees rc=-15 with no fault in the log (playbook trap 10).
    pids = _descendants(proc.pid) + [proc.pid]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for p in pids:
            try:
                os.kill(p, sig)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def cmd_run(args: argparse.Namespace) -> int:
    if not paths.firmware_present():
        print(f"firmware not found at {paths.firmware_bin()}", file=sys.stderr)
        print("  (regenerate it with tools/extract_firmware.py -- see PROVENANCE.md)",
              file=sys.stderr)
        return 1

    argv = spawn.spawn_argv(emulator=args.emulator)
    env = spawn.spawn_env(extra={"BDN9_BRIDGE_PORT": str(args.port)})

    print(f"[rehostry-bdn9] booting: {' '.join(argv)}")
    print(f"[rehostry-bdn9] cwd={spawn.spawn_cwd()}  (configs from the installed package)")
    print(f"[rehostry-bdn9] USB control bridge on tcp/{args.port} -- try")
    print(f"[rehostry-bdn9]   nc 127.0.0.1 {args.port}")
    print("[rehostry-bdn9]   REQ mydev 0x80 6 0x0100 0 18     (GET_DESCRIPTOR device)")
    print("[rehostry-bdn9]   ENC 0 cw 1                       (turn the volume knob)")

    proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, preexec_fn=os.setsid)
    deadline = time.monotonic() + args.seconds
    try:
        assert proc.stdout is not None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                for line in proc.stdout:      # drain whatever is left
                    sys.stdout.write(line)
                print("[rehostry-bdn9] HALucinator exited early.", file=sys.stderr)
                return proc.returncode or 1
            line = proc.stdout.readline()
            if line:
                sys.stdout.write(line)
            else:
                time.sleep(0.05)
        print(f"[rehostry-bdn9] ran for {args.seconds:.0f}s; tearing down.")
        return 0
    finally:
        _kill_tree(proc)


def cmd_panel(args: argparse.Namespace) -> int:
    from . import bdn9_panel
    return bdn9_panel.main()


def cmd_attack(args: argparse.Namespace) -> int:
    from . import attack
    if args.decoy_selftest:
        return attack._decoy_selftest(spawn.BRIDGE_PORT)
    res = attack.run_attack(on_stage=attack._show, control=args.control)
    import json
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed", "milestone")}))
    return 0 if res.get("landed") else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-bdn9",
        description="Keebio BDN9 rev2 (QMK/ChibiOS on STM32F072) as a standalone HALucinator device.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="boot the firmware and stream its log")
    r.add_argument("--seconds", type=float, default=120.0)
    r.add_argument("--emulator", default="unicorn")
    r.add_argument("--port", type=int, default=spawn.BRIDGE_PORT,
                   help="USB control bridge port (default %d)" % spawn.BRIDGE_PORT)
    r.set_defaults(func=cmd_run)

    pa = sub.add_parser("panel", help="live web panel")
    pa.add_argument("--port", type=int, default=spawn.PANEL_PORT)
    pa.set_defaults(func=cmd_panel)

    at = sub.add_parser("attack", help="run the graded attack")
    at.add_argument("--control", action="store_true",
                    help="run against a guest stalled with `b .` throughout")
    at.add_argument("--decoy-selftest", action="store_true",
                    help="prove the attack refuses a no-emulator impostor")
    at.set_defaults(func=cmd_attack)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
