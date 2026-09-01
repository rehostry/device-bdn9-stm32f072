# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drive the rehosted BDN9 over USB and grade it against a pre-boot prediction.

WHAT THIS DEMONSTRATES.  A Keebio BDN9 rev2 is a 9-key macropad with three
rotary encoders.  Plugged in, it enumerates and then reports -- to **anything**
that speaks USB, with no pairing, no authentication and no user confirmation.
This attack is a host that plugs itself in: it drives the bus reset, enumerates
the device, reads every descriptor it has, moves HID class state in both
directions, and turns a knob.  Everything it grades on is a byte the *firmware*
produced.

THE ORACLE HAS FOUR INDEPENDENT LEGS, and `landed` is their conjunction:

1. **Nine static descriptors, byte for byte, against a prediction committed
   before the firmware was ever booted** (PROVENANCE.md 4b, its own commit).
   The host cannot have synthesised them: it has no copy of the image.

2. **A value the guest COMPUTES from an input chosen this run.**  There is no
   serial-number string in the image.  `iSerialNumber = 3` is built at run time
   by the routine at 0x080073E4, which hex-expands the die UID at 0x1FFFF7AC
   through the firmware's own `"0123456789ABCDEF"` table at 0x0800AFC0.  This
   attack picks **twelve fresh random bytes per spawn** and serves them as that
   UID, so a replayed descriptor from any previous run fails.

3. **A bidirectional class round trip keyed to a per-run nonce.**  Sixteen
   random bits go in as `SET_PROTOCOL(wValue=b, wIndex=0)` and come back out as
   `GET_PROTOCOL`; a random byte goes in as `SET_IDLE` and comes back as
   `GET_IDLE`.  Host-chosen input, stored by the guest's own handler in guest
   RAM, returned over the guest's own EP0.

4. **A physical input the firmware turns into a HID report.**  A per-run random
   permutation of all six (encoder, direction) pairs must produce exactly the
   matching six reports, in that order, on **two different endpoints** -- a
   Consumer-Control report for the volume knob on EP2, and boot-keyboard
   reports for the other two on EP1.  This is the "rotary-encoder events" half
   of the queue row's seam, and it is the leg that makes this a *device* round
   trip rather than a descriptor dump.

AND IT MUST REFUSE THINGS TOO.  Two in-run rejection controls -- an unknown
descriptor type and an out-of-range string index -- must STALL and leak zero
bytes.  A mirror, an echo or a credulous harness passes leg 1 and fails these.
A third, predicted statically before the boot: **holding a key down must produce
nothing**, because this build's keymap is nine `KC_TRANSPARENT` halfwords
(PROVENANCE.md 3b).

IT AUTHENTICATES ITS OWN GUEST (runbook Step 3).  Bind-probe on **both**
0.0.0.0 and 127.0.0.1 **without** `SO_REUSEADDR`; a `HELLO` carrying
`device=`, the child's `pid=` and a per-spawn `nonce=` the parent generated; a
`WHOAMI`/`IAM` re-challenge after the traffic; and a grep of the child's own log
for its `BIND_OK` marker.  `landed` is gated on all four.  Run
`python -m rehostry_bdn9.attack --decoy-selftest` to watch it refuse a
no-emulator impostor.

AND IT SHIPS A CONTROL THAT ACTUALLY FALSIFIES.  `--control` runs the whole
thing against an image whose every halfword is `0xE7FE` (`b .`, the ARMv6-M
self-branch): the bridge still binds, the client still connects and is still
greeted, every request is still queued and logged -- and **every firmware-side
field goes false**.  The packaged image is never modified; its sha256 is
printed before and after to prove it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from . import paths, spawn


_LOG_POS: dict = {}
_LOG_BUF: dict = {}


def _read_log_incremental(path: str) -> str:
    """The spawn log so far, read INCREMENTALLY from a saved offset.

    This replaces ``open(path).read()``, which re-read the WHOLE file on every
    pass of a ~1 Hz readiness poll. That is harmless for this device's own few
    kB of log and catastrophic when anything else is writing to the same path:
    an abandoned emulator holding a multi-GB log open makes each pass cost
    seconds. The client then connects late, a frame the guest transmitted
    before the connect is missed, and the run grades the device BELOW its real
    rung -- an instrument artefact, not a property of the firmware.

    Reading from a saved offset makes the poll cost independent of the file's
    size and of any other writer. If the file shrank (a new run truncated it)
    the offset is reset so the fresh contents are not skipped.
    """
    try:
        size = os.path.getsize(path)
        if size < _LOG_POS.get(path, 0):
            _LOG_POS[path] = 0
            _LOG_BUF[path] = ""
        with open(path, "rb") as fh:
            fh.seek(_LOG_POS.get(path, 0))
            chunk = fh.read()
        if chunk:
            _LOG_POS[path] = _LOG_POS.get(path, 0) + len(chunk)
            _LOG_BUF[path] = _LOG_BUF.get(path, "") + chunk.decode("utf-8", "replace")
    except OSError:
        pass
    return _LOG_BUF.get(path, "")


# ---------------------------------------------------------------------------
# THE PRE-BOOT PREDICTION.  Copied verbatim from PROVENANCE.md section 4b,
# which was committed -- as its own commit, containing nothing that can boot the
# firmware -- before this device was booted for the first time.  Do not "fix"
# any byte here to make a run pass.
# ---------------------------------------------------------------------------
PREDICTED: Dict[str, str] = {
    # GET_DESCRIPTOR(DEVICE), first 8 bytes
    "dev8": "1201000200000040",
    # GET_DESCRIPTOR(DEVICE), all 18: VID 0xCB10 Keebio, PID 0x2133,
    # iManufacturer 1, iProduct 2, iSerialNumber 3
    "dev": "120100020000004010cb332100020102"
           "0301",
    # GET_DESCRIPTOR(CONFIGURATION), first 9: wTotalLength 84, 3 interfaces
    "cfg9": "090254000301"
            "00a0fa",
    # GET_DESCRIPTOR(CONFIGURATION), all 84: three HID interfaces, three IN
    # endpoints (0x81/8, 0x82/32, 0x83/32), and NO OUT endpoint anywhere
    "cfg": "09025400030100a0fa0904000001030101"
           "00092111010001224400070581030800"
           "01090401000103000000092111010001"
           "227b0007058203200001090402000103"
           "0000000921110100012215000705830320"
           "0001",
    # STRING 0: LANGID 0x0409
    "str0": "04030904",
    # STRING 1: "Keebio"
    "str1": "0e034b0065006500620069006f00",
    # STRING 2: "BDN9 Rev. 2"
    "str2": "180342004400"
            "4e0039002000520065007600"
            "2e0020003200",
    # HID descriptors, one per interface: wDescriptorLength 68 / 123 / 21
    "hid0": "092111010001224400",
    "hid1": "092111010001227b00",
    "hid2": "092111010001221500",
    # REPORT descriptor, interface 0 -- the boot keyboard, 68 bytes
    "rd0": "05010906a1010507"
           "19e029e7150025019508750181029501750881010507190029"
           "ff150026ff0095067508810005081901290515002501950575019102950175039101"
           "c0",
    # REPORT descriptor, interface 1 -- QMK's "shared" interface, 123 bytes:
    # mouse (ID 2), system control (ID 3), consumer control (ID 4)
    "rd1": "05010902a1018502"
           "0901a1000509190129081500250195087501810205010930"
           "09311581257f95027508810609381581257f950175088106"
           "050c0a38021581257f"
           "950175088106c0c005010980a10185031901"
           "2ab700150126b7009501751081"
           "00c0"
           "050c0901a1018504190"
           "12aa002150126a0029501751081"
           "00c0",
    # REPORT descriptor, interface 2 -- QMK's console, usage page 0xFF31
    "rd2": "0631ff0974a1010975150026ff00952075088102c0",
}

#: The bridge tags whose bytes are graded against PREDICTED, in request order.
STATIC_TAGS = ["dev8", "dev", "cfg9", "cfg", "str0", "str1", "str2",
               "hid0", "hid1", "hid2", "rd0", "rd1", "rd2"]
#: Tags with no data stage that must still be accepted.
ACK_TAGS = ["setaddr", "setcfg"]


DEFAULT_BRIDGE_PORT = int(os.environ.get("BDN9_BRIDGE_PORT", "27260"))

#: How long to wait for the automatic enumeration to finish.  Generous, and
#: judged by progress rather than by a wall clock wherever possible: under load
#: a fixed bound manufactures false walls (playbook, adversarial rule 4).
ENUM_TIMEOUT = float(os.environ.get("BDN9_ENUM_TIMEOUT", "300"))
#: Seconds to let the guest run per encoder detent / key press.
INPUT_SETTLE = float(os.environ.get("BDN9_INPUT_SETTLE", "20"))
#: The control cannot produce anything, so it does not need the settle time.
CONTROL_SETTLE = 3.0


#: What each encoder emits, per direction: (endpoint, report bytes).
#: MEASURED on this rehost -- PROVENANCE.md predicted only that *keys* emit
#: nothing, and said nothing about the encoders.  STATUS.md carries the
#: after-the-fact static derivation from the firmware's own tables.
#:
#: Encoder 0 is the volume knob and reports on the **shared** HID interface
#: (EP2) as a Consumer Control report, ID 4.  Encoders 1 and 2 report on the
#: **boot keyboard** interface (EP1) as ordinary 8-byte keyboard reports.
ENCODER_REPORT: Dict[int, Dict[str, Tuple[int, str]]] = {
    0: {"cw": (2, "04e900"),                    # Consumer: Volume Increment
        "ccw": (2, "04ea00")},                  # Consumer: Volume Decrement
    1: {"cw": (1, "0000510000000000"),          # KC_DOWN  (usage 0x51)
        "ccw": (1, "0000520000000000")},        # KC_UP    (usage 0x52)
    2: {"cw": (1, "00004e0000000000"),          # KC_PGDN  (usage 0x4E)
        "ccw": (1, "00004b0000000000")},        # KC_PGUP  (usage 0x4B)
}

#: The all-zero frame each of those is followed by when the key/knob releases.
RELEASE_FRAMES = {"040000", "0000000000000000"}

#: The endpoints that carry HID *reports*.  EP3 is QMK's **console** -- the
#: firmware's own printf -- and it must be excluded: counting console traffic
#: as input would report "the keyboard emitted something" every time the
#: firmware logged a line, which is how a run with a correct, provably inert
#: keymap first came back claiming three phantom keystrokes.
REPORT_ENDPOINTS = (1, 2)


def _first_press(reports: List[Tuple[int, bytes]]) -> Optional[Tuple[int, str]]:
    """The first HID report in a burst that actually carries something.

    An all-zero report is the *absence* of input, not input.
    """
    for ep, data in reports:
        if ep not in REPORT_ENDPOINTS:
            continue
        if data.hex() in RELEASE_FRAMES:
            continue
        return (ep, data.hex())
    return None


def _show(name: str, **data: Any) -> None:
    extra = " ".join("%s=%s" % (k, v) for k, v in data.items())
    print("[stage] %s%s" % (name, (": " + extra) if extra else ""), flush=True)


# ---------------------------------------------------------------------------
# guest identity + port hygiene
# ---------------------------------------------------------------------------
def _preflight(port: int, settle: float = 90.0) -> Tuple[bool, str]:
    """Bind-probe BOTH addresses, WITHOUT SO_REUSEADDR -- and classify a failure.

    A connect probe consumes the listener backlog and makes the guard flaky; a
    loopback-only probe misses a wildcard squatter entirely; and
    ``SO_REUSEADDR`` makes the probe succeed against exactly the squatter it is
    supposed to catch (measured on device-odrive-f405).  So: bind, both
    addresses, no reuse.

    **But a bind failure is not the same as a squatter**, and conflating the two
    breaks your own back-to-back runs.  Without ``SO_REUSEADDR`` a socket left
    in ``TIME_WAIT`` by the *previous* run blocks the bind for one 2*MSL window
    (~30 s on macOS) after everything has exited -- ``lsof`` shows nothing
    listening and the bind still fails on both addresses.  Measured here: two
    consecutive `M0` verdicts, seconds apart, on a device that was working.

    So a failed bind is *classified*, once, with a connect:

    * connect **succeeds** -> something is LISTENING.  Refuse: that is the
      squatter this guard exists for, and it may be a sibling rehost.
    * connect **refused** -> nobody is listening; the bind is blocked by a
      lingering socket.  Wait for it and re-probe.

    The connect probe is only reached on a failure, so it never touches a
    healthy device's backlog.
    """
    deadline = time.time() + settle
    waited = False
    while True:
        busy = []
        for host in ("0.0.0.0", "127.0.0.1"):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((host, port))
            except OSError as exc:
                busy.append((host, exc))
            finally:
                s.close()
        if not busy:
            note = ("tcp/%d free on 0.0.0.0 and 127.0.0.1 "
                    "(bind probe, no SO_REUSEADDR)" % port)
            if waited:
                note += " -- after waiting out a TIME_WAIT socket"
            return True, note
        host, exc = busy[0]
        try:
            c = socket.create_connection(("127.0.0.1", port), 0.5)
            c.close()
            return False, ("tcp/%d has a LISTENER that is not this attack's "
                           "guest (%s on %s) -- refusing" % (port, exc, host))
        except OSError:
            pass
        if time.time() >= deadline:
            return False, ("tcp/%d still unbindable after %.0fs with nothing "
                           "listening (%s on %s)" % (port, settle, exc, host))
        waited = True
        time.sleep(2.0)


def _parse_interfaces(cfg: bytes) -> List[Dict[str, Any]]:
    """Enumerate the interfaces the guest's OWN CONFIGURATION descriptor declares.

    This is the registered inventory (`INVENTORY.md`).  It is walked out of the
    bytes the device returned, not read from a table in this package: a USB
    configuration descriptor is exactly a device's published statement of the
    interfaces it offers, and it cannot shrink because we implemented fewer
    handlers.  Drop a handler and the interface is still declared here, still
    enumerated, and still fails its assertion.

    Each interface's *obligations* are derived from its own declared bytes --
    `bInterfaceSubClass` decides whether GET_PROTOCOL must be honoured or
    stalled, and the HID descriptor's `wDescriptorLength` decides how many
    report-descriptor bytes it must return.
    """
    out: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    i = 0
    while i + 1 < len(cfg):
        blen, btype = cfg[i], cfg[i + 1]
        if blen == 0:
            break
        if btype == 0x04 and i + 8 <= len(cfg):            # INTERFACE
            cur = {"num": cfg[i + 2], "cls": cfg[i + 5], "sub": cfg[i + 6],
                   "proto": cfg[i + 7], "eps": [], "report_len": None}
            out.append(cur)
        elif btype == 0x05 and cur is not None and i + 6 <= len(cfg):  # ENDPOINT
            cur["eps"].append((cfg[i + 2],
                               int.from_bytes(cfg[i + 4:i + 6], "little")))
        elif btype == 0x21 and cur is not None and i + 9 <= len(cfg):  # HID
            cur["report_len"] = int.from_bytes(cfg[i + 7:i + 9], "little")
        i += blen
    return out


class _Bridge:
    """Line client for the modelled USB host's control bridge."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.hello = ""
        self.responses: Dict[str, Tuple[str, bytes]] = {}
        self.in_reports: List[Tuple[int, bytes]] = []

    def connect(self, deadline: float) -> bool:
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection(("127.0.0.1", self.port),
                                                     1.0)
                return True
            except OSError:
                time.sleep(0.4)
        return False

    def send(self, line: str) -> None:
        assert self.sock is not None
        self.sock.sendall((line + "\n").encode())

    def readline(self, timeout: float) -> Optional[str]:
        assert self.sock is not None
        self.sock.settimeout(0.5)
        end = time.time() + timeout
        while time.time() < end:
            if b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                return line.decode("latin-1").strip()
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            self.buf += chunk
        return None

    def pump(self, timeout: float) -> Optional[str]:
        """Read one line, filing RESP/IN lines as it goes."""
        line = self.readline(timeout)
        if line is None:
            return None
        if line.startswith("HELLO") and not self.hello:
            self.hello = line
        elif line.startswith("RESP "):
            parts = line.split()
            payload = bytes.fromhex(parts[3]) if len(parts) > 3 else b""
            self.responses[parts[1]] = (parts[2], payload)
        elif line.startswith("IN "):
            parts = line.split()
            self.in_reports.append((int(parts[1]),
                                    bytes.fromhex(parts[2]) if len(parts) > 2
                                    else b""))
        return line

    def wait_for(self, tags: List[str], timeout: float) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if all(t in self.responses for t in tags):
                return True
            if self.pump(2.0) is None and self.sock is None:
                return False
        return all(t in self.responses for t in tags)

    def drain(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.pump(1.0)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------
def _stalled_image(dest_dir: str) -> str:
    """Copy the configs into ``dest_dir`` with the firmware replaced by `b .`.

    Every halfword becomes 0xE7FE -- the ARMv6-M unconditional self-branch --
    so the guest cannot execute anything, while the host stack (the bridge, the
    peripheral models, the panel) is completely unaffected.  The packaged image
    is never touched.
    """
    cfg_dir = paths.configs_dir()
    for name in os.listdir(cfg_dir):
        if name.endswith(".yaml"):
            shutil.copy2(os.path.join(cfg_dir, name),
                         os.path.join(dest_dir, name))
    size = os.path.getsize(paths.firmware_bin())
    with open(os.path.join(dest_dir, paths.FIRMWARE_BIN), "wb") as fh:
        fh.write(b"\xfe\xe7" * (size // 2))
    return dest_dir


def run_attack(on_stage=None, log_dir: Optional[str] = None,
               control: bool = False, port: Optional[int] = None,
               skip_preflight: bool = False) -> dict:
    """Boot the device, drive USB, and verify from firmware-side evidence."""
    stage = on_stage or (lambda *a, **k: None)
    port = port or DEFAULT_BRIDGE_PORT
    settle = CONTROL_SETTLE if control else INPUT_SETTLE
    log_dir = log_dir or tempfile.mkdtemp(prefix="bdn9-attack-")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "emulator.log")

    res: Dict[str, Any] = {
        "device": "rehostry-bdn9",
        "control": control,
        "booted": False,
        "landed": False,
        "milestone": "M0",
        "usb_round_trip": False,
        "hid_keystroke_round_trip": False,
        "hid_encoder_report_round_trip": False,
        "raw_hid_via_interface_present": False,
        # Per-interface verdicts over the registered inventory.  Seeded false,
        # not left absent: the --control arm must be able to show an explicit
        # negative for every claim, and a missing key reads as None, which is
        # not evidence of anything.
        "iface0_boot_keyboard_round_trip": False,
        "iface1_shared_hid_round_trip": False,
        "iface2_console_hid_round_trip": False,
        "isolation_m5": False,
        "stateful_m6": False,
        "adversarial_m7": False,
        "interface_parity": "0/0",
        "inventory": [],
        "inventory_size": 0,
        "per_interface": {},
        "checks": {},
        "log": log_path,
    }
    checks: Dict[str, bool] = {}

    # --- 0. port hygiene ---------------------------------------------------
    if skip_preflight:
        checks["preflight_port_free_on_both_addresses"] = True
        stage("preflight [skipped]", note="--no-preflight: identity guard only")
    else:
        ok, why = _preflight(port)
        checks["preflight_port_free_on_both_addresses"] = ok
        stage("preflight" + (" [ok]" if ok else " [FAIL]"), note=why)
        if not ok:
            res["checks"] = checks
            res["error"] = why
            return res

    # --- 1. per-spawn secrets ---------------------------------------------
    nonce = secrets.token_hex(16)
    uid = secrets.token_bytes(12)
    expected_serial = (uid + b"\x00" * 4).hex().upper()
    expected_str3 = bytes((0x42, 0x03)) + expected_serial.encode("utf-16-le")

    env = spawn.spawn_env(extra={
        "HAL_BDN9_NONCE": nonce,
        "HAL_BDN9_DIE_UID": uid.hex(),
        "BDN9_BRIDGE_PORT": str(port),
    })
    argv = spawn.spawn_argv()
    cwd = spawn.spawn_cwd()

    fw_sha_before = hashlib.sha256(open(paths.firmware_bin(), "rb").read()
                                   ).hexdigest()
    tmpdir = None
    if control:
        tmpdir = tempfile.mkdtemp(prefix="bdn9-control-")
        cwd = _stalled_image(tmpdir)
        stage("control", note="guest image replaced with 0xE7FE (`b .`) "
                              "throughout; host stack untouched")

    proc = subprocess.Popen(argv, cwd=cwd, env=env,
                            stdout=open(log_path, "w"),
                            stderr=subprocess.STDOUT)
    res["pid"] = proc.pid
    stage("boot", note="QMK/ChibiOS on a rehosted STM32F072 (Cortex-M0)",
          pid=proc.pid)

    bridge = _Bridge(port)
    try:
        deadline = time.time() + (60 if control else 120)
        if not bridge.connect(deadline):
            res["error"] = "could not connect to the bridge on tcp/%d" % port
            checks["guest_greeted_with_its_own_pid_and_nonce"] = False
            res["checks"] = checks
            return res

        # --- 2. challenge the peer ----------------------------------------
        bridge.pump(30.0)
        want = ("device=rehostry-bdn9 pid=%d nonce=%s" % (proc.pid, nonce))
        greeted = bridge.hello.endswith(want)
        checks["guest_greeted_with_its_own_pid_and_nonce"] = greeted
        stage("challenge" + (" [ok]" if greeted else " [FAIL]"),
              peer=bridge.hello or "(no greeting)")
        if not greeted:
            res["checks"] = checks
            res["error"] = "the peer on tcp/%d is not this attack's guest" % port
            return res

        # --- 3. the child's OWN log must show the bind --------------------
        marker = re.compile(r"BIND_OK bridge BOUND and LISTENing on "
                            r"127\.0\.0\.1:%d \(pid=%d\)" % (port, proc.pid))
        bound = False
        for _ in range(40):
            try:
                if marker.search(_read_log_incremental(log_path)):
                    bound = True
                    break
            except OSError:
                pass
            time.sleep(0.5)
        checks["bridge_bound_in_the_childs_own_log"] = bound
        stage("bind-marker" + (" [ok]" if bound else " [FAIL]"),
              note="127.0.0.1:%d pid=%d" % (port, proc.pid))

        # --- 4. enumeration ------------------------------------------------
        got = bridge.wait_for(STATIC_TAGS + ACK_TAGS + ["str3"],
                              30 if control else ENUM_TIMEOUT)
        res["booted"] = bool(bridge.responses)
        matches: Dict[str, bool] = {}
        for tag in STATIC_TAGS:
            status, payload = bridge.responses.get(tag, ("missing", b""))
            matches[tag] = (status == "ok"
                            and payload.hex() == PREDICTED[tag])
        acked = all(bridge.responses.get(t, ("", b""))[0] == "ok"
                    for t in ACK_TAGS)
        all_static = all(matches.values())
        checks["descriptors_match_the_pre_boot_prediction"] = all_static
        checks["set_configuration_honoured_unauthenticated"] = acked
        res["descriptor_matches"] = matches
        stage("enumerate" + (" [ok]" if got and all_static else " [FAIL]"),
              note="%d/%d static descriptors byte-identical to PROVENANCE.md"
                   % (sum(matches.values()), len(matches)))

        # --- 5. the guest-computed serial ---------------------------------
        s_status, s_payload = bridge.responses.get("str3", ("missing", b""))
        serial_ok = (s_status == "ok" and s_payload == expected_str3)
        checks["serial_string_matches_the_live_die_uid"] = serial_ok
        res["die_uid_served_this_spawn"] = uid.hex()
        res["serial_string"] = (s_payload[2:].decode("utf-16-le", "replace")
                                if len(s_payload) > 2 else None)
        stage("guest-derived" + (" [ok]" if serial_ok else " [FAIL]"),
              uid=uid.hex(), serial=res["serial_string"])

        if bridge.responses.get("dev", ("", b""))[1][8:12]:
            vid, pid_ = struct.unpack("<HH",
                                      bridge.responses["dev"][1][8:12])
            res["vid_pid"] = "%04x:%04x" % (vid, pid_)
            stage("identity", vid_pid=res["vid_pid"],
                  manufacturer="Keebio", product="BDN9 Rev. 2")

        # --- 6. bidirectional class round trip, keyed to this run ----------
        bits = [secrets.randbelow(2) for _ in range(16)]
        idle_byte = 1 + secrets.randbelow(255)
        for i, b in enumerate(bits):
            bridge.send("REQ setp%d 0x21 11 %d 0 0" % (i, b))
            bridge.send("REQ getp%d 0xA1 3 0 0 1" % i)
        bridge.send("REQ setidle 0x21 10 0x%04x 0 0" % ((idle_byte << 8) | 1))
        bridge.send("REQ getidle 0xA1 2 1 0 1")
        # --- 7. in-run rejection controls ---------------------------------
        bridge.send("REQ bogustype 0x80 6 0x9900 0 16")
        bridge.send("REQ badstrindex 0x80 6 0x0307 0x0409 64")
        bridge.send("REQ keyreport 0xA1 1 0x0100 0 8")
        tags = (["setp%d" % i for i in range(16)]
                + ["getp%d" % i for i in range(16)]
                + ["setidle", "getidle", "bogustype", "badstrindex",
                   "keyreport"])
        bridge.wait_for(tags, 120 if not control else 20)

        readback = [bridge.responses.get("getp%d" % i, ("", b""))[1]
                    for i in range(16)]
        proto_ok = all(len(r) == 1 and r[0] == b
                       for r, b in zip(readback, bits))
        checks["protocol_nonce_round_tripped"] = proto_ok
        res["protocol_nonce_sent"] = "".join(str(b) for b in bits)
        res["protocol_nonce_readback"] = "".join(
            str(r[0]) if len(r) == 1 else "?" for r in readback)
        stage("class-round-trip" + (" [ok]" if proto_ok else " [FAIL]"),
              sent=res["protocol_nonce_sent"],
              readback=res["protocol_nonce_readback"])

        idle_back = bridge.responses.get("getidle", ("", b""))[1]
        idle_ok = len(idle_back) == 1 and idle_back[0] == idle_byte
        checks["idle_byte_round_tripped"] = idle_ok
        stage("idle-round-trip" + (" [ok]" if idle_ok else " [FAIL]"),
              sent="0x%02x" % idle_byte,
              readback=idle_back.hex() or "(none)")

        stalled_bogus = bridge.responses.get("bogustype", ("", b""))
        stalled_badstr = bridge.responses.get("badstrindex", ("", b""))
        rej_ok = (stalled_bogus[0] == "stall" and not stalled_bogus[1]
                  and stalled_badstr[0] == "stall" and not stalled_badstr[1])
        checks["unknown_requests_are_stalled_not_answered"] = rej_ok
        stage("negative-control" + (" [ok]" if rej_ok else " [FAIL]"),
              note="GET_DESCRIPTOR(type=0x99) -> %s, "
                   "GET_DESCRIPTOR(string, index=7) -> %s"
                   % (stalled_bogus[0] or "missing",
                      stalled_badstr[0] or "missing"))

        # --- 8. the predicted NEGATIVE: a key press emits nothing ---------
        # Drain whatever is still in flight BEFORE clearing, or a report
        # published during an earlier stage is parsed inside this window and
        # counted as if the key had produced it.
        bridge.drain(2.0)
        bridge.in_reports.clear()
        bridge.send("KEY 0 down")
        bridge.drain(settle)
        bridge.send("KEY 0 up")
        bridge.drain(2.0)
        # AN ALL-ZERO REPORT IS THE ABSENCE OF A KEYSTROKE, NOT A KEYSTROKE.
        # Leg 3 above sets a non-zero HID idle rate, and a non-zero idle rate
        # is precisely an instruction to **re-send the current report
        # periodically** -- so a correct, provably inert keymap emits a stream
        # of empty boot-keyboard frames on EP1 for the rest of the run,
        # entirely because this attack asked for them.  Counting frames rather
        # than keycodes made this device report between 0 and 16 "keystrokes"
        # from the same firmware depending on the random idle byte, which read
        # as an intermittent firmware bug and was an oracle bug.  EP3 is
        # excluded for the same reason: it is QMK's console, not a report
        # endpoint.  The question is "did a KEYCODE come out", and
        # `_first_press` is what answers it.
        key_press = _first_press(bridge.in_reports)
        key_frames = len(bridge.in_reports)
        # In a CONTROL run this is trivially true -- a stalled guest emits
        # nothing at all -- so it is not allowed to contribute there.
        checks["empty_keymap_emits_nothing"] = (key_press is None) and not control
        res["hid_keystroke_round_trip"] = key_press is not None
        res["keystroke_frames_seen"] = key_frames
        stage("keystroke" + (" [ok, as predicted]" if key_press is None
                             else " [UNEXPECTED]"),
              note="switch 0 (PB12) held %.0fs -> %d frame(s), %d carrying a "
                   "keycode%s; PROVENANCE.md 3b predicted 0 "
                   "(keymap is 9x KC_TRANSPARENT)"
                   % (settle, key_frames, 0 if key_press is None else 1,
                      "" if key_press is None else " (ep%d:%s)" % key_press))

        # --- 9. the real input round trip: the encoders -------------------
        # A per-run random plan over all six (encoder, direction) pairs, so
        # the firmware has to produce six DIFFERENT reports on TWO different
        # endpoints in an order the host chose this run.  A recording of any
        # previous run is the wrong sequence.
        plan = [(i, d) for i in ENCODER_REPORT for d in ("cw", "ccw")]
        random.shuffle(plan)
        observed: List[str] = []
        expected: List[str] = []
        for index, direction in plan:
            bridge.drain(1.0)
            bridge.in_reports.clear()
            bridge.send("ENC %d %s 1" % (index, direction))
            bridge.drain(settle)
            ep_hex = ENCODER_REPORT[index][direction]
            expected.append("ep%d:%s" % ep_hex)
            seen = _first_press(bridge.in_reports)
            observed.append("ep%d:%s" % seen if seen else "(none)")
        enc_ok = observed == expected
        checks["encoder_rotation_emits_the_matching_hid_report"] = enc_ok
        res["encoder_plan"] = ["enc%d-%s" % (i, d) for i, d in plan]
        res["encoder_expected"] = expected
        res["encoder_observed"] = observed
        res["hid_encoder_report_round_trip"] = enc_ok
        stage("encoder" + (" [ok]" if enc_ok else " [FAIL]"),
              plan=" ".join(res["encoder_plan"]))
        for p, e, o in zip(res["encoder_plan"], expected, observed):
            stage("  " + p, expected=e, observed=o,
                  match="MATCH" if e == o else "MISMATCH")

        # ==================================================================
        # 9b. The registered inventory (INVENTORY.md) and its predictions
        # (PREDICTIONS.md), both committed 2026-09-01T16:34:19-05:00 --
        # BEFORE this block existed.
        #
        # The inventory is PARSED OUT OF THE DESCRIPTOR THE GUEST RETURNED,
        # not read from a table here, and each interface's obligations are
        # DERIVED FROM ITS OWN DECLARED BYTES.  Change the image and both
        # follow it.
        # ==================================================================
        ifaces = _parse_interfaces(bridge.responses.get("cfg", ("", b""))[1])
        res["inventory"] = [
            {"interface": f["num"], "subclass": f["sub"],
             "report_descriptor_len": f.get("report_len"),
             "endpoints": ["0x%02x" % e for e, _ in f["eps"]]}
            for f in ifaces]
        res["inventory_size"] = len(ifaces)
        stage("inventory",
              note="%d interface(s) parsed from the guest's own CONFIGURATION "
                   "descriptor: %s"
                   % (len(ifaces),
                      "; ".join("iface %d subclass %d, %s-byte report desc, "
                                "EP 0x%02x" % (f["num"], f["sub"],
                                               f.get("report_len"),
                                               f["eps"][0][0] if f["eps"] else 0)
                                for f in ifaces)))

        # --- 9b-i. each interface's OWN report descriptor, at its own wIndex
        for f in ifaces:
            bridge.send("REQ rdsc%d 0x81 6 0x2200 %d 255" % (f["num"], f["num"]))
        # --- 9b-ii. the boot-subclass discrimination -----------------------
        # HID 1.11 §7.2.5: GET_PROTOCOL is defined ONLY for boot-subclass
        # interfaces.  The obligation per interface is read off that
        # interface's own subclass byte, so this is not a constant we chose.
        for f in ifaces:
            bridge.send("REQ prot%d 0xA1 3 0 %d 1" % (f["num"], f["num"]))
        # --- 9b-iii. per-interface idle state, attacker-chosen -------------
        idle_a = {f["num"]: 1 + secrets.randbelow(255) for f in ifaces}
        for n, v in idle_a.items():
            bridge.send("REQ sidle%d 0x21 10 0x%04x %d 0" % (n, v << 8, n))
        for n in idle_a:
            bridge.send("REQ gidle%d 0xA1 2 0 %d 1" % (n, n))
        tags = (["rdsc%d" % f["num"] for f in ifaces]
                + ["prot%d" % f["num"] for f in ifaces]
                + ["sidle%d" % n for n in idle_a]
                + ["gidle%d" % n for n in idle_a])
        bridge.wait_for(tags, 40 if control else 180)

        per_iface: Dict[str, Any] = {}
        iface_pass: Dict[int, bool] = {}
        for f in ifaces:
            n = f["num"]
            r_st, r_pl = bridge.responses.get("rdsc%d" % n, ("missing", b""))
            # DERIVED: the length this interface's own HID descriptor declares.
            rd_ok = (r_st == "ok" and len(r_pl) == f.get("report_len"))
            p_st, p_pl = bridge.responses.get("prot%d" % n, ("missing", b""))
            if f["sub"] == 1:
                prot_ok = (p_st == "ok" and len(p_pl) == 1)
                prot_why = "subclass 1 (boot) -> must be honoured"
            else:
                prot_ok = (p_st == "stall" and not p_pl)
                prot_why = "subclass 0 -> must STALL"
            i_st, i_pl = bridge.responses.get("gidle%d" % n, ("missing", b""))
            idle_stored = (i_st == "ok" and len(i_pl) == 1
                           and i_pl[0] == idle_a[n])
            per_iface[str(n)] = {
                "report_descriptor_bytes": len(r_pl),
                "report_descriptor_declared": f.get("report_len"),
                "report_descriptor_ok": rd_ok,
                "get_protocol": p_st, "get_protocol_ok": prot_ok,
                "get_protocol_rule": prot_why,
                "idle_sent": "0x%02x" % idle_a[n],
                "idle_readback": i_pl.hex() or None,
                "idle_stored": idle_stored,
            }
            iface_pass[n] = bool(rd_ok and prot_ok)
            stage("  iface %d" % n,
                  report_desc="%d/%s bytes %s" % (len(r_pl), f.get("report_len"),
                                                  "OK" if rd_ok else "MISMATCH"),
                  get_protocol="%s (%s) %s" % (p_st, prot_why,
                                               "OK" if prot_ok else "WRONG"),
                  idle="sent 0x%02x readback %s" % (idle_a[n],
                                                    i_pl.hex() or "(none)"))

        # Endpoint evidence, from the reports already collected this run:
        # interface 0's keycodes arrived on 0x81 and interface 1's consumer
        # reports on 0x82, in a host-chosen order.  Interface 2's round trip is
        # its control-pipe idle state (INVENTORY.md: it has no OUT endpoint).
        ep_seen = {1: any(o.startswith("ep1:") for o in res.get("encoder_observed", [])),
                   2: any(o.startswith("ep2:") for o in res.get("encoder_observed", []))}
        per_iface.setdefault("0", {})["endpoint_reports"] = ep_seen.get(1, False)
        per_iface.setdefault("1", {})["endpoint_reports"] = ep_seen.get(2, False)
        per_iface.setdefault("2", {})["console_printf"] = None  # filled at 10b

        # --- 9b-iv. M5 isolation: the state is PER-interface, not global ----
        # Two interfaces, two DIFFERENT attacker-chosen bytes, both read back;
        # then swapped and re-read, so a harness that recorded the first answer
        # fails too.  A single global store returns the same byte for both.
        pair = [f["num"] for f in ifaces if f["num"] in (0, 2)]
        iso_ok = False
        if len(pair) == 2:
            x, y = pair
            a, b_ = idle_a[x], idle_a[y]
            while b_ == a:
                b_ = 1 + secrets.randbelow(255)
            bridge.send("REQ swx 0x21 10 0x%04x %d 0" % (b_ << 8, x))
            bridge.send("REQ swy 0x21 10 0x%04x %d 0" % (a << 8, y))
            bridge.send("REQ gwx 0xA1 2 0 %d 1" % x)
            bridge.send("REQ gwy 0xA1 2 0 %d 1" % y)
            bridge.wait_for(["swx", "swy", "gwx", "gwy"], 30 if control else 120)
            gx = bridge.responses.get("gwx", ("", b""))[1]
            gy = bridge.responses.get("gwy", ("", b""))[1]
            before_differed = (per_iface[str(x)]["idle_stored"]
                               and per_iface[str(y)]["idle_stored"]
                               and idle_a[x] != idle_a[y])
            after_ok = (len(gx) == 1 and gx[0] == b_
                        and len(gy) == 1 and gy[0] == a)
            iso_ok = bool(before_differed and after_ok)
            res["m5_isolation"] = {
                "interfaces": [x, y],
                "before": {str(x): "0x%02x" % idle_a[x],
                           str(y): "0x%02x" % idle_a[y]},
                "after_swap_expected": {str(x): "0x%02x" % b_,
                                        str(y): "0x%02x" % a},
                "after_swap_readback": {str(x): gx.hex() or None,
                                        str(y): gy.hex() or None},
                "distinct_before": before_differed, "correct_after": after_ok}
            stage("m5-isolation" + (" [ok]" if iso_ok else " [FAIL]"),
                  note="iface %d and %d hold DIFFERENT attacker-chosen idle "
                       "bytes (0x%02x / 0x%02x), and both follow a swap "
                       "(-> %s / %s); a global store cannot"
                       % (x, y, idle_a[x], idle_a[y], gx.hex() or "-",
                          gy.hex() or "-"))
        checks["interface_state_is_per_interface_not_global"] = iso_ok

        # --- 9b-v. M7: adversarial control traffic --------------------------
        adv = [
            ("adv_type", "REQ adv_type 0x80 6 0x9900 0 16", "descriptor type 0x99"),
            ("adv_str", "REQ adv_str 0x80 6 0x0307 0x0409 64", "string index 7"),
            ("adv_iface", "REQ adv_iface 0xA1 3 0 9 1", "GET_PROTOCOL iface 9"),
            ("adv_req", "REQ adv_req 0xA1 0x99 0 0 1", "bRequest 0x99"),
            ("adv_recip", "REQ adv_recip 0xA3 3 0 0 1", "recipient=other"),
            ("adv_zlen", "REQ adv_zlen 0x80 6 0x0100 0 0", "wLength 0"),
            ("adv_ep9", "REQ adv_ep9 0x82 0 0 0x09 2", "GET_STATUS on ep 0x09"),
        ]
        for tag, line, _ in adv:
            bridge.send(line)
        # The bounds check: wLength far larger than the descriptor must return
        # the DESCRIPTOR's length, not wLength.  Answering 255 here would be a
        # buffer over-read, so this one must NOT stall.
        bridge.send("REQ adv_over 0x80 6 0x0100 0 255")
        bridge.wait_for([t for t, _, _ in adv] + ["adv_over"],
                        40 if control else 180)
        refused = {}
        for tag, _, what in adv:
            st, pl = bridge.responses.get(tag, ("missing", b""))
            refused[what] = (st == "stall" and not pl)
        over_st, over_pl = bridge.responses.get("adv_over", ("missing", b""))
        bounded = (over_st == "ok" and len(over_pl) == 18
                   and over_pl.hex() == PREDICTED["dev"])
        res["m7_refusals"] = refused
        res["m7_bounded_read"] = {
            "requested": 255, "returned": len(over_pl), "ok": bounded}
        stage("m7-adversarial"
              + (" [ok]" if all(refused.values()) and bounded else " [FAIL]"),
              note="%d/%d malformed requests stalled with 0 bytes; "
                   "GET_DESCRIPTOR(DEVICE, wLength=255) returned %d bytes "
                   "(the descriptor's true length is 18, not 255)"
                   % (sum(refused.values()), len(refused), len(over_pl)))
        for what, ok in refused.items():
            stage("    " + what, refused="yes" if ok else "NO -- ANSWERED")

        # --- 9b-vi. M7's real conjunct: known-good on ALL THREE afterwards ---
        rec_idle = {f["num"]: 1 + secrets.randbelow(255) for f in ifaces}
        bridge.send("REQ rec_dev 0x80 6 0x0100 0 18")
        bridge.send("REQ rec_prot 0xA1 3 0 0 1")
        for n, v in rec_idle.items():
            bridge.send("REQ rsi%d 0x21 10 0x%04x %d 0" % (n, v << 8, n))
        for n in rec_idle:
            bridge.send("REQ rgi%d 0xA1 2 0 %d 1" % (n, n))
        for f in ifaces:
            bridge.send("REQ rrd%d 0x81 6 0x2200 %d 255" % (f["num"], f["num"]))
        bridge.wait_for(["rec_dev", "rec_prot"]
                        + ["rsi%d" % n for n in rec_idle]
                        + ["rgi%d" % n for n in rec_idle]
                        + ["rrd%d" % f["num"] for f in ifaces],
                        40 if control else 180)
        rec_dev_ok = (bridge.responses.get("rec_dev", ("", b""))[1].hex()
                      == PREDICTED["dev"])
        rec_prot_ok = bridge.responses.get("rec_prot", ("", b""))[0] == "ok"
        # `all()` over an empty sequence is True, and the inventory IS empty in
        # the --control arm, where nothing enumerates.  Without the emptiness
        # guard these two read `true` for a guest that executed no instruction
        # -- a vacuous truth is not a passing check.  Caught by the control arm
        # itself, which is what a control is for.
        rec_rd_ok = bool(ifaces) and all(
            bridge.responses.get("rrd%d" % f["num"], ("", b""))[0] == "ok"
            and len(bridge.responses["rrd%d" % f["num"]][1]) == f.get("report_len")
            for f in ifaces)
        # Only the interfaces that stored an idle rate before are required to
        # store one now -- PREDICTIONS.md registers interface 1 as not storing.
        storing = [n for n in rec_idle
                   if per_iface.get(str(n), {}).get("idle_stored")]
        rec_idle_ok = bool(storing) and all(
            (bridge.responses.get("rgi%d" % n, ("", b""))[1] or b"\xff")[0]
            == rec_idle[n] for n in storing)
        recovered = bool(rec_dev_ok and rec_prot_ok and rec_rd_ok and rec_idle_ok)
        checks["known_good_traffic_survives_malformed_input"] = recovered
        res["m7_recovery"] = {
            "device_descriptor_still_identical": rec_dev_ok,
            "protocol_round_trip_iface0": rec_prot_ok,
            "report_descriptors_all_three": rec_rd_ok,
            "idle_round_trips": rec_idle_ok}
        stage("m7-recovery" + (" [ok]" if recovered else " [FAIL]"),
              note="after every malformed request: device descriptor identical="
                   "%s, iface0 protocol=%s, all three report descriptors=%s, "
                   "fresh idle round trips=%s"
                   % (rec_dev_ok, rec_prot_ok, rec_rd_ok, rec_idle_ok))

        res["per_interface"] = per_iface
        res["_iface_pass"] = iface_pass
        res["_iso_ok"] = iso_ok
        res["_adv_ok"] = bool(refused and all(refused.values()) and bounded)

        # --- 10. did the firmware panic? -----------------------------------
        text = _read_log_incremental(log_path)
        panicked = ("reached its own chSysHalt()" in text
                    or "took an exception it has no handler for" in text)
        faulted = bool(re.search(r"UC_ERR|FETCH-DERAIL", text))
        checks["no_firmware_panic_or_emulator_fault"] = not (panicked
                                                             or faulted)
        res["firmware_panicked"] = panicked
        res["emulator_faulted"] = faulted

        # --- 10b. the firmware's own console, if it spoke ---
        bridge.send("STATE")
        console = ""
        for _ in range(20):
            line = bridge.pump(2.0)
            if line and line.startswith("STATE "):
                try:
                    console = json.loads(line[6:]).get("console", "")
                except ValueError:
                    console = ""
                break
        res["firmware_console"] = console
        if console:
            stage("console", note="the firmware's own printf on its console "
                                  "endpoint (EP3): %r" % console)

        # --- 11. re-challenge -----------------------------------------------
        bridge.send("WHOAMI")
        iam = ""
        for _ in range(20):
            line = bridge.pump(2.0)
            if line and line.startswith("IAM"):
                iam = line
                break
        checks["re_challenge_after_traffic"] = iam.endswith(want)
        stage("re-challenge" + (" [ok]" if iam.endswith(want) else " [FAIL]"),
              peer=iam or "(no answer)")

    finally:
        bridge.close()
        _kill(proc)
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    fw_sha_after = hashlib.sha256(open(paths.firmware_bin(), "rb").read()
                                  ).hexdigest()
    checks["packaged_firmware_unmodified"] = (fw_sha_before == fw_sha_after)
    res["firmware_sha256"] = fw_sha_after

    # --- verdict ------------------------------------------------------------
    res["checks"] = checks
    res["failed_checks"] = sorted(k for k, v in checks.items() if not v)
    res["usb_round_trip"] = bool(
        checks.get("descriptors_match_the_pre_boot_prediction")
        and checks.get("serial_string_matches_the_live_die_uid")
        and checks.get("set_configuration_honoured_unauthenticated")
        and checks.get("protocol_nonce_round_tripped")
        and checks.get("encoder_rotation_emits_the_matching_hid_report"))
    res["landed"] = bool(checks) and all(checks.values()) and res["usb_round_trip"]

    # ---- the breadth rungs, over the registered inventory -----------------
    iface_pass = res.pop("_iface_pass", {})
    iso_ok = res.pop("_iso_ok", False)
    adv_ok = res.pop("_adv_ok", False)
    pi = res.get("per_interface", {})

    def _iface(n: int, extra: bool) -> bool:
        """Interface n passes when its OWN declared obligations are met."""
        return bool(iface_pass.get(n) and extra)

    # iface 0: its own 68-byte report descriptor, GET_PROTOCOL honoured because
    # it declares subclass 1, the 16-bit protocol nonce, and keycodes on 0x81.
    res["iface0_boot_keyboard_round_trip"] = _iface(
        0, checks.get("protocol_nonce_round_tripped", False)
        and pi.get("0", {}).get("endpoint_reports", False))
    # iface 1: its own 123-byte report descriptor, GET_PROTOCOL correctly
    # STALLED because it declares subclass 0, and consumer reports on 0x82.
    res["iface1_shared_hid_round_trip"] = _iface(
        1, pi.get("1", {}).get("endpoint_reports", False))
    # iface 2: its own 21-byte report descriptor, GET_PROTOCOL correctly
    # STALLED, and an attacker-chosen idle byte round-tripped at wIndex 2 --
    # on the control pipe, because the image has no OUT endpoint at all.
    res["iface2_console_hid_round_trip"] = _iface(
        2, pi.get("2", {}).get("idle_stored", False))

    passed = [n for n in sorted(iface_pass) if res.get(
        {0: "iface0_boot_keyboard_round_trip",
         1: "iface1_shared_hid_round_trip",
         2: "iface2_console_hid_round_trip"}.get(n, ""), False)]
    res["interfaces_passed"] = passed
    res["interface_parity"] = "%d/%d" % (len(passed), res.get("inventory_size", 0))

    # M5 wants two or more INDEPENDENT interfaces.  Independence is not assumed
    # from them being listed separately: it is required to show up as behaviour
    # that differs per interface -- GET_PROTOCOL honoured on the boot-subclass
    # interface and stalled on the others, and class state that is per-interface
    # rather than global.
    res["isolation_m5"] = bool(len(passed) >= 2 and iso_ok)
    # M6: the same GET_PROTOCOL at sixteen states, and the same GET_IDLE before
    # and after a swap, each returning a different correct answer.
    res["stateful_m6"] = bool(checks.get("protocol_nonce_round_tripped")
                              and checks.get("idle_byte_round_tripped")
                              and iso_ok)
    # M7: seven refusals, a bounded read that does not over-read, and known-good
    # traffic on all three interfaces afterwards.
    res["adversarial_m7"] = bool(
        adv_ok and checks.get("unknown_requests_are_stalled_not_answered")
        and checks.get("known_good_traffic_survives_malformed_input"))

    milestone = "M4" if res["landed"] else "M3" if res.get("booted") else "M0"
    if milestone == "M4" and res["isolation_m5"]:
        milestone = "M5"
    if milestone == "M5" and res["stateful_m6"]:
        milestone = "M6"
    if milestone == "M6" and res["adversarial_m7"]:
        milestone = "M7"
    # M8 -- parity over the WHOLE inventory -- is claimed only when every
    # interface the guest's own descriptor declares has passed.  The parity
    # pair is reported either way so that 2/3 cannot be read as 3/3.
    res["m8_claimed"] = bool(milestone == "M7"
                             and res.get("inventory_size")
                             and len(passed) == res["inventory_size"])
    if res["m8_claimed"]:
        milestone = "M8"
    res["milestone"] = milestone
    return res




def _kill(proc: subprocess.Popen) -> None:
    """Tear down ONLY the process this attack started (playbook: never pkill)."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(10)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# decoy self-test
# ---------------------------------------------------------------------------
def _decoy_selftest(port: int) -> int:
    """Stand up a no-emulator impostor and prove this attack refuses it."""
    from .tools_decoy import serve_decoy  # noqa: PLC0415

    stop, thread = serve_decoy(port)
    _show("decoy", note="a no-emulator impostor now holds tcp/%d" % port)
    try:
        _show("decoy/layer-1", note="preflight bind probe should refuse")
        res = run_attack(on_stage=_show, port=port)
        layer1 = (not res["landed"]
                  and not res["checks"].get(
                      "preflight_port_free_on_both_addresses", True))
        _show("decoy/layer-1" + (" [ok]" if layer1 else " [FAIL]"),
              landed=res["landed"], error=res.get("error"))

        _show("decoy/layer-2", note="preflight disabled -- the identity "
                                    "challenge must refuse on its own")
        res2 = run_attack(on_stage=_show, port=port, skip_preflight=True)
        layer2 = (not res2["landed"]
                  and not res2["checks"].get(
                      "guest_greeted_with_its_own_pid_and_nonce", True))
        _show("decoy/layer-2" + (" [ok]" if layer2 else " [FAIL]"),
              landed=res2["landed"], error=res2.get("error"))
    finally:
        stop()
        thread.join(timeout=5)
    ok = layer1 and layer2
    print("RESULT:", json.dumps({"decoy_refused": ok, "landed": False}))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="attack the rehosted BDN9 rev2")
    ap.add_argument("--control", action="store_true",
                    help="run against a guest stalled with `b .` throughout")
    ap.add_argument("--decoy-selftest", action="store_true",
                    help="prove this attack refuses a no-emulator impostor")
    ap.add_argument("--port", type=int, default=DEFAULT_BRIDGE_PORT)
    ap.add_argument("--log-dir", default=None)
    ap.add_argument("--no-preflight", action="store_true")
    args = ap.parse_args()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(130))

    if args.decoy_selftest:
        return _decoy_selftest(args.port)

    res = run_attack(on_stage=_show, log_dir=args.log_dir,
                     control=args.control, port=args.port,
                     skip_preflight=args.no_preflight)
    if res.get("failed_checks"):
        print("[stage] failed-checks: %s" % ", ".join(res["failed_checks"]),
              flush=True)
    print("[stage] milestone: %s (usb_round_trip=%s)"
          % (res["milestone"], res["usb_round_trip"]), flush=True)
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed", "milestone",
                                          "usb_round_trip",
                                          "hid_keystroke_round_trip",
                                          "hid_encoder_report_round_trip",
                                          "raw_hid_via_interface_present",
                                          "iface0_boot_keyboard_round_trip",
                                          "iface1_shared_hid_round_trip",
                                          "iface2_console_hid_round_trip",
                                          "isolation_m5", "stateful_m6",
                                          "adversarial_m7", "m8_claimed",
                                          "interface_parity", "inventory",
                                          "interfaces_passed", "per_interface",
                                          "m5_isolation", "m7_refusals",
                                          "m7_bounded_read", "m7_recovery",
                                          "control")}))
    # Non-zero below M4. Compare the RUNG, not the string: the first run
    # to grade M5+ would otherwise exit 1 and be read as a failure.
    import re as _re
    _m = _re.match(r"M(\d+)", res.get("milestone") or "")
    return 0 if (res.get("landed") and _m and int(_m.group(1)) >= 4) else 1


if __name__ == "__main__":
    raise SystemExit(main())
