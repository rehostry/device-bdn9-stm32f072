# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A USB **host** for this device, plus the authenticated bridge that drives it.

A USB device does nothing until something plugs it in.  Measured before this
existed, the firmware wrote ``CNTR = FRES``, then ``CNTR = 0``, programmed
``BTABLE``, opened EP0, asserted ``BCDR.DPPU`` and stopped -- a device correctly
waiting for a host.

HOW A PACKET MOVES on the STM32F0 USB block (RM0091 30.6):

  * ``BTABLE`` points into packet memory at four **halfwords** per endpoint --
    ``ADDR_TX``, ``COUNT_TX``, ``ADDR_RX``, ``COUNT_RX`` -- i.e. 8 bytes per
    endpoint at the F0's **1:1** PMA mapping (see ``stm32f0_usb``).
  * To give the device a packet: write the bytes into PMA at ``ADDR_RX``, put
    the length in the low 10 bits of ``COUNT_RX`` **preserving** the
    buffer-size bits 15:10 the firmware programmed, set ``CTR_RX`` (plus
    ``SETUP`` for a setup packet), and raise the USB interrupt.
  * To take a packet: the device has set ``STAT_TX = VALID``; read ``COUNT_TX``
    bytes from PMA at ``ADDR_TX``, then set ``CTR_TX``.

ORDER OF OPERATIONS THAT ACTUALLY MATTERS

* **Wait for the D+ pull-up.**  QMK's ``init_usb_driver()`` is
  ``usbDisconnectBus(); chThdSleepMilliseconds(1500); usbStart(); usbConnectBus();``
  -- resetting the bus before ``BCDR.DPPU`` is a host talking to a device that
  has not attached.
* **Wait for EP0's buffer descriptor, not just for ``EP0R``.**  ``EP0R`` becomes
  non-zero when the type/address bits are programmed, which happens *before*
  ``BTABLE[0]`` has an ``ADDR_RX``.  Writing a SETUP packet in that window puts
  eight bytes at PMA offset 0 and the firmware parses whatever else lives there.
* **A control endpoint cannot NAK a SETUP.**  The silicon always accepts SETUP
  and forces ``STAT_RX`` to NAK afterwards -- which is exactly the state correct
  firmware leaves EP0 in after reset.  Waiting for ``STAT_RX == VALID`` before
  sending SETUP deadlocks against a *working* device.
* **One transaction per step**, so the firmware always runs in between -- AND
  never touch an endpoint while one of its ``CTR`` flags is still set.  This one
  cost a real debugging session.  ``CTR_RX`` and ``CTR_TX`` are the device's
  *unserviced* transfer-complete flags; ChibiOS' ISR is
  ``while (ISTR & CTR) { serve(ISTR & EP_ID); }`` and, with both set on EP0, the
  reference manual makes ``DIR`` name the **OUT** one first.  So a host that
  takes an IN packet (setting ``CTR_TX``) and then immediately sends the
  zero-length status OUT (setting ``CTR_RX``) makes the firmware service its
  **status stage before the data-IN completion of the packet it just sent** --
  and ChibiOS then arms the *next* chunk of the previous descriptor against the
  *next* SETUP.  Measured: ``GET_DESCRIPTOR(configuration, 84)`` returned
  ``COUNT_TX = 20`` on its **first** packet -- bytes 64..83, the tail of the
  descriptor, with the head silently missing.  Nothing faults, nothing stalls,
  and the 20 bytes that come back are genuine firmware bytes from the right
  descriptor, which is what makes it dangerous.
* **The two control shapes end differently.**  A transfer with an IN data stage
  ends with a host->device zero-length OUT; one without ends with a
  device->host zero-length IN.  An OUT-data transfer (SET_REPORT) sends its
  data on EP0 OUT and then takes a zero-length IN.
* **A STALL must persist before it is believed.**  ``STAT_TX``/``STAT_RX`` pass
  through STALL transiently while ChibiOS re-arms EP0, so a stall is only
  reported after ``STALL_PATIENCE`` consecutive observations.

THE BRIDGE AUTHENTICATES ITSELF (runbook Step 3).  It binds **127.0.0.1 only**,
greets ``HELLO device=rehostry-bdn9 pid=<pid> nonce=<per-spawn secret>``, and
logs ``BIND_OK``/``BIND_FAIL`` so the parent can grep its own child's log.  The
nonce comes from the parent by env, so a sibling rehost answering the port
fails on shape *and* on value.

AND IT REPLAYS A BACKLOG ON ACCEPT.  unicorn holds the GIL for long stretches,
so the kernel completes a client's TCP handshake out of the listen backlog long
before this process reaches ``accept()``.  Without the replay, every ``RESP``
line published in that window goes to nobody and the attack waits out its
timeout on a device that already answered.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from halucinator import hal_log

from .stm32f0_usb import EP_CTR_RX, EP_CTR_TX

log = hal_log.getHalLogger()

STAT_DISABLED, STAT_STALL, STAT_NAK, STAT_VALID = 0, 1, 2, 3

SET_ADDRESS = 5
GET_DESCRIPTOR = 6
SET_CONFIGURATION = 9

#: The address this host assigns.
DEVICE_ADDRESS = 9
MAX_PACKET0 = 64

#: Consecutive observations of STAT == STALL before it is believed.
STALL_PATIENCE = 24
#: Steps a stage may sit unchanged before the transfer is abandoned.
STEP_PATIENCE = 4000

_TRACE = os.environ.get("HAL_BDN9_HOST_TRACE") == "1"

_HOST: Optional["UsbHost"] = None
_HOST_LOCK = threading.Lock()


def get_host() -> "UsbHost":
    """The single host driving this device.

    Peripheral models are constructed more than once while a config resolves
    (playbook 2.3), so the listener is bound exactly once, here, behind a lock
    -- not in a model's ``__init__``, where the second instance would fail
    silently and take the listener with it.
    """
    global _HOST
    with _HOST_LOCK:
        if _HOST is None:
            _HOST = UsbHost()
            if os.environ.get("HAL_BDN9_USB_BRIDGE", "1") == "1":
                _HOST.start_bridge(
                    int(os.environ.get("BDN9_BRIDGE_PORT", "27260")))
        return _HOST


class _Xfer:
    """One queued control transfer."""

    def __init__(self, tag: str, bm: int, req: int, value: int, index: int,
                 length: int, out_data: bytes = b"") -> None:
        self.tag = tag
        self.setup = struct.pack("<BBHHH", bm, req, value, index, length)
        self.want = length if (bm & 0x80) else 0
        self.out_data = out_data if not (bm & 0x80) else b""
        self.data = bytearray()
        self.stalled = False


class UsbHost:
    """Bus reset, enumeration, then arbitrary host-driven control transfers."""

    def __init__(self) -> None:
        self.state = "wait_attach"
        self.pending_irq = False
        self.configured = False
        self.enumerated = False
        self.address_set = False
        self._steps = 0
        self._stage_steps = 0
        self._stall_seen = 0
        self._lock = threading.RLock()
        self._clients: List[Any] = []
        self._backlog: Deque[str] = deque(maxlen=600)
        self._bridge_port: Optional[int] = None
        self._bridge_bound = False
        self.nonce = os.environ.get("HAL_BDN9_NONCE", "")
        self.pid = os.getpid()

        self._queue: Deque[_Xfer] = deque()
        self._cur: Optional[_Xfer] = None
        self.completed = 0
        self.stalls = 0

        #: Bytes the firmware sent, keyed by tag -- for the panel.
        self.responses: Dict[str, str] = {}
        self.device_descriptor = b""
        self.config_descriptor = b""
        self.vid_pid: Optional[Tuple[int, int]] = None
        self.serial_string: Optional[str] = None
        #: IN packets seen on the interrupt endpoints (EP1/EP2/EP3).
        self.in_reports: List[Tuple[int, str]] = []
        #: EP3 is QMK's console (HID usage page 0xFF31) -- the firmware's own
        #: printf, cumulative.
        self.console = bytearray()

    # -- helpers over the device's packet memory ---------------------------
    @staticmethod
    def _ep_busy(usb, ep: int = 0) -> bool:
        """True while the device still owes its ISR a pass on this endpoint.

        See the module docstring: acting on an endpoint with a pending ``CTR``
        flag reorders the firmware's own transfer-completion handling.
        """
        return bool(usb.epr[ep] & (EP_CTR_RX | EP_CTR_TX))

    @staticmethod
    def _btable_entry(usb, pma, ep: int):
        base = usb.btable()
        raw = pma.read_flat(base + ep * 8, 8)
        return struct.unpack("<HHHH", raw)

    @staticmethod
    def _set_count_rx(pma, base: int, ep: int, length: int) -> None:
        off = base + ep * 8 + 6
        cur = struct.unpack("<H", pma.read_flat(off, 2))[0]
        # Preserve BL_SIZE/NUM_BLOCK (15:10): the firmware programmed those and
        # still needs them; only the byte count is ours.
        pma.write_flat(off, struct.pack("<H", (cur & 0xFC00) | (length & 0x3FF)))

    def _give(self, usb, pma, ep: int, data: bytes, setup: bool = False) -> None:
        base = usb.btable()
        _, _, addr_rx, _ = self._btable_entry(usb, pma, ep)
        if data:
            pma.write_flat(addr_rx, data)
        self._set_count_rx(pma, base, ep, len(data))
        usb.raise_ctr_rx(ep, setup=setup)
        self.pending_irq = True

    def _take(self, usb, pma, ep: int) -> bytes:
        addr_tx, count_tx, _, _ = self._btable_entry(usb, pma, ep)
        data = pma.read_flat(addr_tx, count_tx & 0x3FF)
        usb.raise_ctr_tx(ep)
        self.pending_irq = True
        return data

    # -- the state machine --------------------------------------------------
    def step(self, usb, pma) -> bool:
        self._steps += 1
        self.pending_irq = False
        st = self.state

        # A real host polls EVERY interrupt IN endpoint every frame, so drain
        # them on every step and not only when the control queue happens to be
        # empty.  Doing it only in the idle state loses whatever the firmware
        # published *during* a control transfer -- which is exactly when QMK
        # writes "USB configured." to its console endpoint, so that string was
        # captured in one run out of four before this.
        if st not in ("wait_attach", "reset", "wait_ep0"):
            for ep in (1, 2, 3):
                if self._ep_busy(usb, ep):
                    continue
                if usb.ep_stat_tx(ep) == STAT_VALID:
                    data = self._take(usb, pma, ep)
                    if data:
                        self._on_in_report(ep, data)
                    return True

        if st == "wait_attach":
            if usb.attached and usb.enabled:
                log.info("UsbHost: the firmware asserted D+ (BCDR.DPPU) -- "
                         "treating the BDN9 as plugged in")
                self.state = "reset"
            return False

        if st == "reset":
            usb.raise_reset()
            self.pending_irq = True
            self.state = "wait_ep0"
            log.info("UsbHost: driving a USB bus reset")
            return True

        if st == "wait_ep0":
            # NOT "EP0R != 0": that is true as soon as the type/address bits
            # are written, which is before BTABLE[0].ADDR_RX exists.
            if self._ep_busy(usb):
                return False
            if usb.epr[0] == 0 or not usb.daddr_enabled():
                return False
            _, _, addr_rx, count_rx = self._btable_entry(usb, pma, 0)
            if addr_rx == 0 or (count_rx & 0xFC00) == 0:
                return False
            log.info("UsbHost: EP0 is open (EPR=0x%04x, ADDR_RX=0x%03x, "
                     "COUNT_RX=0x%04x) -- enumerating", usb.epr[0], addr_rx,
                     count_rx)
            self._enqueue_enumeration()
            self.state = "advance"
            return False

        if st == "advance":
            if self._ep_busy(usb):
                return self._tick_patience(usb, pma)
            return self._start_next(usb, pma)

        if st == "data_in":
            return self._data_in(usb, pma)

        if st == "data_out":
            return self._data_out(usb, pma)

        if st == "status_out":
            if self._stalled(usb, out=True):
                return self._finish(usb, pma, stalled=True)
            if self._ep_busy(usb):
                return self._tick_patience(usb, pma)
            if usb.ep_stat_rx(0) == STAT_VALID:
                self._give(usb, pma, 0, b"")
                return self._finish(usb, pma)
            return self._tick_patience(usb, pma)

        if st == "status_in":
            if self._stalled(usb, out=False):
                return self._finish(usb, pma, stalled=True)
            if self._ep_busy(usb):
                return self._tick_patience(usb, pma)
            if usb.ep_stat_tx(0) == STAT_VALID:
                self._take(usb, pma, 0)
                return self._finish(usb, pma)
            return self._tick_patience(usb, pma)

        if st == "idle":
            if self._queue:
                self.state = "advance"
            return False

        return False

    # -- transfer plumbing ---------------------------------------------------
    def _stalled(self, usb, out: bool) -> bool:
        stat = usb.ep_stat_rx(0) if out else usb.ep_stat_tx(0)
        if stat == STAT_STALL:
            self._stall_seen += 1
            return self._stall_seen >= STALL_PATIENCE
        self._stall_seen = 0
        return False

    def _tick_patience(self, usb, pma) -> bool:
        self._stage_steps += 1
        if self._stage_steps > STEP_PATIENCE:
            log.error("UsbHost: transfer %s stalled out after %d steps in "
                      "state %s (EP0R=0x%04x)",
                      self._cur.tag if self._cur else "?", self._stage_steps,
                      self.state, usb.epr[0])
            return self._finish(usb, pma, stalled=True)
        return False

    def _data_in(self, usb, pma) -> bool:
        if self._stalled(usb, out=False):
            return self._finish(usb, pma, stalled=True)
        if self._ep_busy(usb) or usb.ep_stat_tx(0) != STAT_VALID:
            return self._tick_patience(usb, pma)
        pkt = self._take(usb, pma, 0)
        assert self._cur is not None
        self._cur.data += pkt
        if _TRACE:
            log.info("UsbHost: [%s] IN packet %d byte(s), total %d/%d",
                     self._cur.tag, len(pkt), len(self._cur.data),
                     self._cur.want)
        self._stage_steps = 0
        if len(pkt) < MAX_PACKET0 or len(self._cur.data) >= self._cur.want:
            self.state = "status_out"
        return True

    def _data_out(self, usb, pma) -> bool:
        if self._stalled(usb, out=True):
            return self._finish(usb, pma, stalled=True)
        if self._ep_busy(usb) or usb.ep_stat_rx(0) != STAT_VALID:
            return self._tick_patience(usb, pma)
        assert self._cur is not None
        self._give(usb, pma, 0, self._cur.out_data)
        self._stage_steps = 0
        self.state = "status_in"
        return True

    def _start_next(self, usb, pma) -> bool:
        if not self._queue:
            self.state = "idle"
            return False
        self._cur = self._queue.popleft()
        self._stage_steps = 0
        self._stall_seen = 0
        self._give(usb, pma, 0, self._cur.setup, setup=True)
        if self._cur.want:
            self.state = "data_in"
        elif self._cur.out_data:
            self.state = "data_out"
        else:
            self.state = "status_in"
        log.info("UsbHost: SETUP %s [%s] (%s)", self._cur.setup.hex(" "),
                 self._cur.tag,
                 "expects %d IN byte(s)" % self._cur.want if self._cur.want
                 else ("%d OUT byte(s)" % len(self._cur.out_data)
                       if self._cur.out_data else "no data stage"))
        return True

    def _finish(self, usb, pma, stalled: bool = False) -> bool:
        cur = self._cur
        self._cur = None
        self.state = "advance" if self._queue else "idle"
        self._stage_steps = 0
        self._stall_seen = 0
        if cur is None:
            return True
        data = bytes(cur.data)
        if stalled:
            self.stalls += 1
            log.info("UsbHost: [%s] the firmware STALLed (%d byte(s) leaked)",
                     cur.tag, len(data))
            self._publish("RESP %s stall %s" % (cur.tag, data.hex()))
        else:
            self.completed += 1
            log.info("UsbHost: [%s] ok, %d byte(s): %s", cur.tag, len(data),
                     data.hex(" ") if data else "(no data stage)")
            self._decode(cur, data)
            self._publish("RESP %s ok %s" % (cur.tag, data.hex()))
        with self._lock:
            self.responses[cur.tag] = ("stall:" if stalled else "") + data.hex()
        return True

    def _decode(self, cur: _Xfer, data: bytes) -> None:
        bm, req, value, index, _ = struct.unpack("<BBHHH", cur.setup)
        if bm & 0x60:
            # Class or vendor request: bRequest 9 there is HID SET_REPORT, not
            # SET_CONFIGURATION.  Decoding by bRequest alone mislabels it.
            return
        if req == SET_ADDRESS and not (bm & 0x80):
            self.address_set = True
        elif req == SET_CONFIGURATION and not (bm & 0x80):
            self.configured = True
            self.enumerated = True
            log.info("UsbHost: the BDN9 accepted SET_CONFIGURATION(%d) -- it "
                     "is CONFIGURED", value & 0xFF)
        elif req == GET_DESCRIPTOR and (bm & 0x80):
            dtype, dindex = value >> 8, value & 0xFF
            if dtype == 1 and len(data) >= 12:
                self.device_descriptor = data
                vid, pid = struct.unpack_from("<HH", data, 8)
                self.vid_pid = (vid, pid)
                log.info("UsbHost: VID:PID = %04x:%04x", vid, pid)
            elif dtype == 2 and len(data) >= 9:
                self.config_descriptor = data
            elif dtype == 3 and dindex == 3 and len(data) > 2:
                try:
                    self.serial_string = data[2:].decode("utf-16-le")
                except UnicodeDecodeError:
                    self.serial_string = None
                log.info("UsbHost: the firmware COMPUTED its serial string: "
                         "%r", self.serial_string)

    def _on_in_report(self, ep: int, data: bytes) -> None:
        with self._lock:
            self.in_reports.append((ep, data.hex()))
            self.in_reports = self.in_reports[-64:]
            if ep == 3:
                self.console += data.rstrip(b"\x00")
        log.info("UsbHost: %d byte(s) IN on EP%d: %s", len(data), ep,
                 data.hex(" "))
        self._publish("IN %d %s" % (ep, data.hex()))

    # -- the enumeration script ---------------------------------------------
    def _enqueue_enumeration(self) -> None:
        q = [
            ("dev8", 0x80, GET_DESCRIPTOR, 0x0100, 0, 8),
            ("setaddr", 0x00, SET_ADDRESS, DEVICE_ADDRESS, 0, 0),
            ("dev", 0x80, GET_DESCRIPTOR, 0x0100, 0, 18),
            ("cfg9", 0x80, GET_DESCRIPTOR, 0x0200, 0, 9),
            ("cfg", 0x80, GET_DESCRIPTOR, 0x0200, 0, 84),
            ("str0", 0x80, GET_DESCRIPTOR, 0x0300, 0, 255),
            ("str1", 0x80, GET_DESCRIPTOR, 0x0301, 0x0409, 255),
            ("str2", 0x80, GET_DESCRIPTOR, 0x0302, 0x0409, 255),
            ("str3", 0x80, GET_DESCRIPTOR, 0x0303, 0x0409, 255),
            ("setcfg", 0x00, SET_CONFIGURATION, 1, 0, 0),
            ("hid0", 0x81, GET_DESCRIPTOR, 0x2100, 0, 9),
            ("hid1", 0x81, GET_DESCRIPTOR, 0x2100, 1, 9),
            ("hid2", 0x81, GET_DESCRIPTOR, 0x2100, 2, 9),
            ("rd0", 0x81, GET_DESCRIPTOR, 0x2200, 0, 68),
            ("rd1", 0x81, GET_DESCRIPTOR, 0x2200, 1, 123),
            ("rd2", 0x81, GET_DESCRIPTOR, 0x2200, 2, 21),
        ]
        for tag, bm, req, value, index, length in q:
            self._queue.append(_Xfer(tag, bm, req, value, index, length))

    # -- host-side API ------------------------------------------------------
    def request(self, tag: str, bm: int, req: int, value: int, index: int,
                length: int, out_data: bytes = b"") -> None:
        with self._lock:
            self._queue.append(_Xfer(tag, bm, req, value, index, length,
                                     out_data))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "state": self.state,
                "attached": self.state != "wait_attach",
                "enumerated": self.enumerated,
                "configured": self.configured,
                "address_set": self.address_set,
                "transfers_completed": self.completed,
                "stalls": self.stalls,
                "vid_pid": ("%04x:%04x" % self.vid_pid) if self.vid_pid
                           else None,
                "serial": self.serial_string,
                "device_descriptor": self.device_descriptor.hex(),
                "config_descriptor": self.config_descriptor.hex(),
                "in_reports": list(self.in_reports[-8:]),
                "console": bytes(self.console).decode("latin-1"),
                "responses": dict(self.responses),
            }

    # -- TCP bridge ---------------------------------------------------------
    def _publish(self, line: str) -> None:
        with self._lock:
            self._backlog.append(line)
            clients = list(self._clients)
        payload = (line + "\n").encode()
        for c in clients:
            try:
                c.sendall(payload)
            except OSError:
                pass

    def start_bridge(self, port: int) -> None:
        if self._bridge_bound:
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # NO SO_REUSEADDR: if something else already holds this port we must
        # find out here, loudly, not share it (runbook Step 3).
        try:
            srv.bind(("127.0.0.1", port))
        except OSError as exc:
            # A failed bind looks exactly like a firmware wall: the device
            # boots, looks healthy, and nothing can ever be injected.
            log.error("UsbHost: BIND_FAIL tcp/%d (%s) -- the USB control "
                      "bridge is DEAD", port, exc)
            return
        srv.listen(4)
        self._bridge_bound = True
        self._bridge_port = port
        log.info("UsbHost: BIND_OK bridge BOUND and LISTENing on "
                 "127.0.0.1:%d (pid=%d)", port, self.pid)

        def accept_loop() -> None:
            while True:
                try:
                    conn, peer = srv.accept()
                except OSError:
                    return
                log.info("UsbHost: bridge accepted a client from %s", peer)
                greet = ("HELLO device=rehostry-bdn9 pid=%d nonce=%s\n"
                         % (self.pid, self.nonce)).encode()
                with self._lock:
                    self._clients.append(conn)
                    backlog = "".join(l + "\n" for l in self._backlog).encode()
                try:
                    conn.sendall(greet + backlog)
                except OSError:
                    pass
                threading.Thread(target=self._reader, args=(conn,),
                                 daemon=True).start()

        threading.Thread(target=accept_loop, daemon=True).start()

    def _reader(self, conn) -> None:
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._command(conn, line.decode("latin-1").strip())
        except OSError:
            pass
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _command(self, conn, line: str) -> None:
        if not line:
            return
        parts = line.split()
        cmd = parts[0].upper()
        try:
            if cmd == "PING":
                conn.sendall(b"PONG\n")
            elif cmd == "WHOAMI":
                conn.sendall(("IAM device=rehostry-bdn9 pid=%d nonce=%s\n"
                              % (self.pid, self.nonce)).encode())
            elif cmd == "STATE":
                import json
                conn.sendall(("STATE " + json.dumps(self.snapshot())
                              + "\n").encode())
            elif cmd == "REQ" and len(parts) >= 7:
                tag = parts[1]
                bm, req = int(parts[2], 0), int(parts[3], 0)
                val, idx = int(parts[4], 0), int(parts[5], 0)
                length = int(parts[6], 0)
                out = bytes.fromhex(parts[7]) if len(parts) > 7 else b""
                self.request(tag, bm, req, val, idx, length, out)
                conn.sendall(("QUEUED %s\n" % tag).encode())
            elif cmd == "KEY" and len(parts) >= 3:
                from .stm32f0_gpio import get_gpio
                gpio = get_gpio()
                index = int(parts[1])
                if gpio is None:
                    conn.sendall(b"ERR no-gpio\n")
                elif parts[2].lower() == "down":
                    name = gpio.press(index)
                    conn.sendall(("KEY %d %s\n"
                                  % (index, name or "unknown")).encode())
                else:
                    gpio.release(index)
                    conn.sendall(("KEY %d up\n" % index).encode())
            elif cmd == "ENC" and len(parts) >= 3:
                from .stm32f0_gpio import get_gpio
                gpio = get_gpio()
                index = int(parts[1])
                cw = parts[2].lower() in ("cw", "clockwise", "right")
                detents = int(parts[3]) if len(parts) > 3 else 1
                ok = gpio is not None and gpio.encoder_turn(index, cw, detents)
                conn.sendall(("ENC %d %s %d %s\n"
                              % (index, "cw" if cw else "ccw", detents,
                                 "queued" if ok else "err")).encode())
            elif cmd == "WIRING":
                import json
                from .stm32f0_gpio import get_gpio
                gpio = get_gpio()
                conn.sendall(("WIRING " + json.dumps(
                    gpio.wiring() if gpio else {}) + "\n").encode())
            else:
                conn.sendall(b"ERR unknown\n")
        except (OSError, ValueError) as exc:
            try:
                conn.sendall(("ERR %s\n" % exc).encode())
            except OSError:
                pass
