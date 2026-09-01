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
    res["milestone"] = ("M4" if res["landed"]
                        else "M3" if res.get("booted") else "M0")
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
                                          "control")}))
    # Non-zero below M4. Compare the RUNG, not the string: the first run
    # to grade M5+ would otherwise exit 1 and be read as a failure.
    import re as _re
    _m = _re.match(r"M(\d+)", res.get("milestone") or "")
    return 0 if (res.get("landed") and _m and int(_m.group(1)) >= 4) else 1


if __name__ == "__main__":
    raise SystemExit(main())
