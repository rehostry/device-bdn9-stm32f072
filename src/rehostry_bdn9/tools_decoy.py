# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A no-emulator impostor, so the attack's guest authentication can be PROVEN.

In the 2026-08-05 batch an auditor stood up a ~60-line decoy with no emulator
and no firmware at all and got a byte-identical
``RESULT: {"booted": true, "landed": true}`` -- including "MATCH against the
pre-boot prediction" -- out of a device whose real guest was running blind with
``Errno 48``.  The lesson the fleet took from that is that an attack must
*demonstrate* it refuses an impostor, not assert it.

So this is that impostor, shipped in the device and run by
``python -m rehostry_bdn9.attack --decoy-selftest``.  It is deliberately
**generous**: it speaks the exact line protocol, greets with a structurally
perfect ``HELLO device=rehostry-bdn9 pid=<its own pid> nonce=<32 hex chars>``,
and replays a *real* recorded enumeration -- every descriptor byte-for-byte
correct, including a plausible serial string.  Everything a credulous harness
grades on, it answers correctly.

The two things it cannot do are the two things that matter:

* it cannot know the **per-spawn nonce** the parent generated and passed to its
  own child by env, nor the child's **pid**; and
* it cannot produce the serial string for a **die UID picked after it started**.

Both are checked, and ``landed`` is gated on the first before a single
descriptor is compared.
"""
from __future__ import annotations

import os
import secrets
import socket
import threading
from typing import Callable, Tuple

#: A genuine, complete enumeration recorded from a real run of this device --
#: which is exactly the point: correct bytes are not evidence of a live guest.
RECORDED = [
    "RESP dev8 ok 1201000200000040",
    "RESP setaddr ok ",
    "RESP dev ok 120100020000004010cb3321000201020301",
    "RESP cfg9 ok 090254000301"
    "00a0fa",
    "RESP cfg ok 09025400030100a0fa090400000103010100092111010001224400070581"
    "03080001090401000103000000092111010001227b00070582032000010904020001"
    "0300000009211101000122150007058303200001",
    "RESP str0 ok 04030904",
    "RESP str1 ok 0e034b0065006500620069006f00",
    "RESP str2 ok 1803420044004e00390020005200650076002e0020003200",
    "RESP str3 ok 4203450033004400430030003200320037004200360037004200460033"
    "003300390037004200450032004500300045003400300030003000300030003000"
    "3000300030",
    "RESP setcfg ok ",
    "RESP hid0 ok 092111010001224400",
    "RESP hid1 ok 092111010001227b00",
    "RESP hid2 ok 092111010001221500",
    "RESP rd0 ok 05010906a101050719e029e71500250195087501810295017508810105"
    "07190029ff150026ff0095067508810005081901290515002501950575019102950175"
    "039101c0",
    "RESP rd1 ok 05010902a10185020901a100050919012908150025019508750181020501"
    "093009311581257f95027508810609381581257f950175088106050c0a38021581257f95"
    "0175088106c0c005010980a1018503190" + "12ab700150126b700950175108100c0"
    "050c0901a101850419012aa002150126a002950175108100c0",
    "RESP rd2 ok 0631ff0974a1010975150026ff00952075088102c0",
]


def serve_decoy(port: int) -> Tuple[Callable[[], None], threading.Thread]:
    """Bind ``port`` on 127.0.0.1 and answer like a working device would."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    running = threading.Event()
    running.set()

    def handle(conn: socket.socket) -> None:
        # The client disconnects the moment it refuses us, which is the whole
        # point -- so a broken pipe here is SUCCESS, not an error.
        try:
            conn.sendall(("HELLO device=rehostry-bdn9 pid=%d nonce=%s\n"
                          % (os.getpid(), secrets.token_hex(16))).encode())
            for line in RECORDED:
                conn.sendall((line + "\n").encode())
            buf = b""
            while running.is_set():
                conn.settimeout(0.5)
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    parts = line.decode("latin-1").split()
                    if not parts:
                        continue
                    if parts[0] == "REQ" and len(parts) >= 2:
                        # Answer everything "ok" with empty data: a credulous
                        # harness sees no stalls and no errors.
                        conn.sendall(("RESP %s ok \n" % parts[1]).encode())
                    elif parts[0] == "WHOAMI":
                        conn.sendall(
                            ("IAM device=rehostry-bdn9 pid=%d nonce=%s\n"
                             % (os.getpid(), secrets.token_hex(16))).encode())
                    else:
                        conn.sendall(b"OK\n")
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def loop() -> None:
        srv.settimeout(0.5)
        while running.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    def stop() -> None:
        running.clear()
        try:
            srv.close()
        except OSError:
            pass

    return stop, thread


def main() -> int:
    import argparse
    import time
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=27260)
    ap.add_argument("--seconds", type=float, default=600)
    args = ap.parse_args()
    stop, thread = serve_decoy(args.port)
    print("decoy: NO emulator, NO firmware, answering on 127.0.0.1:%d"
          % args.port, flush=True)
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        stop()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
