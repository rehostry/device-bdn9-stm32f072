#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fuzz-REACH hook targets for this row's USB control endpoint (EP0)
(lane s1011-laneAQ). Writes ``configs/fuzz_reach_targets.json``; ``--check``
re-derives and compares.

WHAT IS AN INPUT. The census lists this row's three HID interfaces
(``iface0``/``iface1``/``iface2``, from the CONFIGURATION descriptor the guest
returns; INVENTORY.md). The CONFIGURATION descriptor declares three interrupt
IN endpoints and NO interrupt OUT endpoint, so the only host input is EP0. Each
census interface is expanded into the control requests the image's own
dispatch parses for that interface (HID class requests and the HID/REPORT
GET_DESCRIPTOR arms, by ``wIndex``); device-level standard requests the
census does not list are added as ``X_*`` entries. There is no raw-HID / VIA
interface in this build, and the console (iface 2, usage page 0xFF31) is
IN-only, so there is no command set beyond EP0.

THE DISPATCH IS LOCATED BY CONTENT (the image is stripped; ARMv6-M, so no
cbz/tbb -- switches go through libgcc's ``__gnu_thumb1_case_*`` helpers):
* ``get_usb_descriptor``: the only function opening ``lsrs r5,r0,#8 ; cmp r5,#3``;
* its single ``bl`` caller is ``get_descriptor_cb``; the literal pointer to that
  callback sits in ChibiOS' ``USBConfig`` ``{event_cb, get_descriptor_cb,
  requests_hook_cb, sof_cb}``, which gives QMK's ``requests_hook_cb``;
* ChibiOS' ``_usb_ep0setup`` hook-load site is the only
  ``ldr r3,[r4,#4] ; ldr r3,[r3,#8] ; cmp r3,#0 ; bne`` sequence;
* the setup packet's offset in ``USBDriver`` is the hook's own
  ``adds r1,#off`` in its first three instructions;
* the case helpers are the functions opening ``push {r1}|{r0,r1} ; mov r1,lr ;
  lsrs r1,r1,#1``.

SRAM IS THE IMAGE'S OWN INITIAL STATE. QMK dispatches GET_REPORT / GET_IDLE /
SET_IDLE through per-interface ``usb_report_storage`` tables in ``.data``. The
tool runs the image's own crt0 (``.data`` copy, ``.bss`` zero) in a bare
unicorn instance and every dispatch run starts from that SRAM.

THE ARMS ARE FOUND BY EXECUTING THE FIRMWARE'S OWN DECODE, one request at a
time, on a scratch ``USBDriver`` whose setup bytes are the request. A LEVEL is
one function on the chain; its ARM is the first instruction executed after the
level's LAST conditional decision (b<cc>, a computed ``ldr pc``, or a case
helper) before the chain's first EFFECT. Effects: a store outside the stack
(other than inside an opaque call), a return, or -- in ChibiOS' standard switch
-- any call (as lane AC's rows). Inside QMK's hook a call is FOLLOWED (a new
level) when it is indirect (``blx`` through a table) or passes ``usbp`` in
``r0``; any other call there is executed OPAQUELY (run to its return, nothing
inside it recorded). A call to ``get_descriptor_cb`` ends the run and the chain
continues in ``get_usb_descriptor`` with the request's arguments. For
SET_REPORT the hook is run to its return to recover the OUT-stage callback and
buffer it installs (``usbp->ep0endcb``/``ep0next``) and that callback runs on
the entry's OUT bytes. An entry's OWN handler is the arm of the deepest level
that took a decision; the other levels' arms are ROUTE hooks, recorded and
never credited.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import capstone  # noqa: E402
import unicorn  # noqa: E402
from unicorn import arm_const as UA  # noqa: E402

from rehostry_bdn9 import paths  # noqa: E402

ROW = "device-bdn9-stm32f072"
LANE = "s1011-laneAQ"
BIN = "bdn9.bin"
BASE = 0x08000000
FLASH = 0x20000
SRAM, SRAM_SZ = 0x20000000, 0x4000
USB_IRQ = 31               # STM32F072 USB (usb_pump.USB_IRQ)
TICK_IRQ = 15              # TIM2: ChibiOS' tickless system time base
TICK_NAME = "TIM2_IRQHandler"

#: Census interface -> (what the census says)
CENSUS = {
    "iface0": "HID boot keyboard (wIndex 0)",
    "iface1": "HID QMK shared mouse/system/consumer (wIndex 1)",
    "iface2": "HID QMK console 0xFF31 (control pipe only, no OUT ep)",
}
S = None  # no OUT bytes

#: id -> (census interface or "device", (bm, bRequest, wValue, wIndex, wLength, OUT bytes))
#: Lengths are the ones this row's own host model / INVENTORY sends.
ENTRIES = {
    # ---- device-level standard requests (ChibiOS _usb_ep0setup) ----------
    "X_GET_STATUS_DEV": ("device", (0x80, 0, 0, 0, 2, S)),
    "X_GET_STATUS_IF": ("device", (0x81, 0, 0, 0, 2, S)),
    "X_GET_STATUS_EP_IN": ("device", (0x82, 0, 0, 0x81, 2, S)),
    "X_GET_STATUS_EP_OUT": ("device", (0x82, 0, 0, 0x01, 2, S)),
    "X_CLEAR_FEATURE_DEV_RW": ("device", (0x00, 1, 1, 0, 0, S)),
    "X_CLEAR_FEATURE_EP_IN": ("device", (0x02, 1, 0, 0x81, 0, S)),
    "X_CLEAR_FEATURE_EP_OUT": ("device", (0x02, 1, 0, 0x01, 0, S)),
    "X_SET_FEATURE_DEV_RW": ("device", (0x00, 3, 1, 0, 0, S)),
    "X_SET_FEATURE_EP_IN": ("device", (0x02, 3, 0, 0x81, 0, S)),
    "X_SET_FEATURE_EP_OUT": ("device", (0x02, 3, 0, 0x01, 0, S)),
    "X_SET_ADDRESS": ("device", (0x00, 5, 0x002A, 0, 0, S)),
    "E_DEVICE": ("device", (0x80, 6, 0x0100, 0, 18, S)),
    "E_CONFIG": ("device", (0x80, 6, 0x0200, 0, 84, S)),
    "E_STRING_0": ("device", (0x80, 6, 0x0300, 0, 255, S)),
    "E_STRING_1": ("device", (0x80, 6, 0x0301, 0x0409, 255, S)),
    "E_STRING_2": ("device", (0x80, 6, 0x0302, 0x0409, 255, S)),
    "E_STRING_3": ("device", (0x80, 6, 0x0303, 0x0409, 255, S)),
    "X_GET_CONFIGURATION": ("device", (0x80, 8, 0, 0, 1, S)),
    "X_SET_CONFIGURATION": ("device", (0x00, 9, 1, 0, 0, S)),
    "X_SYNCH_FRAME": ("device", (0x82, 0x0C, 0, 0x81, 2, S)),
    # ---- iface 0: boot keyboard -------------------------------------------
    "E_HID_CLASS_IF0": ("iface0", (0x81, 6, 0x2100, 0, 9, S)),
    "E_HID_REPORT_IF0": ("iface0", (0x81, 6, 0x2200, 0, 68, S)),
    "E_GET_REPORT_IF0": ("iface0", (0xA1, 1, 0x0100, 0, 8, S)),
    "E_GET_IDLE_IF0": ("iface0", (0xA1, 2, 0, 0, 1, S)),
    "E_SET_IDLE_IF0": ("iface0", (0x21, 0x0A, 0, 0, 0, S)),
    "E_GET_PROTOCOL_IF0": ("iface0", (0xA1, 3, 0, 0, 1, S)),
    "E_SET_PROTOCOL_IF0": ("iface0", (0x21, 0x0B, 1, 0, 0, S)),
    "E_SET_REPORT_IF0": ("iface0", (0x21, 9, 0x0200, 0, 1, b"\x02")),
    # ---- iface 1: shared mouse / system / consumer ------------------------
    "E_HID_CLASS_IF1": ("iface1", (0x81, 6, 0x2100, 1, 9, S)),
    "E_HID_REPORT_IF1": ("iface1", (0x81, 6, 0x2200, 1, 123, S)),
    # GET_REPORT_IF1_ID<k> are appended by derive() for every Report ID whose
    # storage slot the image's own .data populates.
    "E_GET_IDLE_IF1": ("iface1", (0xA1, 2, 0, 1, 1, S)),
    "E_SET_IDLE_IF1": ("iface1", (0x21, 0x0A, 0, 1, 0, S)),
    "E_SET_PROTOCOL_IF1": ("iface1", (0x21, 0x0B, 1, 1, 0, S)),
    "E_SET_REPORT_IF1_ID1": ("iface1", (0x21, 9, 0x0201, 1, 2, b"\x01\x02")),
    "E_SET_REPORT_IF1_ID6": ("iface1", (0x21, 9, 0x0206, 1, 2, b"\x06\x02")),
    # ---- iface 2: QMK console ---------------------------------------------
    "E_HID_CLASS_IF2": ("iface2", (0x81, 6, 0x2100, 2, 9, S)),
    "E_HID_REPORT_IF2": ("iface2", (0x81, 6, 0x2200, 2, 21, S)),
    "E_GET_REPORT_IF2": ("iface2", (0xA1, 1, 0x0100, 2, 32, S)),
    "E_GET_IDLE_IF2": ("iface2", (0xA1, 2, 0, 2, 1, S)),
    "E_SET_IDLE_IF2": ("iface2", (0x21, 0x0A, 0, 2, 0, S)),
    "E_SET_PROTOCOL_IF2": ("iface2", (0x21, 0x0B, 1, 2, 0, S)),
}
#: Report IDs tried for GET_REPORT on iface 1 (the dispatcher bounds it at 8).
IF1_REPORT_IDS = range(0, 9)

#: Undeclared or out-of-range requests: they must reach NO entry's own handler.
CONTROLS = {
    "ctl-desc-type-0x99": (0x80, 6, 0x9900, 0, 16, S),
    "ctl-string-index-4": (0x80, 6, 0x0304, 0x0409, 64, S),
    "ctl-hid-class-iface-9": (0x81, 6, 0x2100, 9, 9, S),
    "ctl-report-iface-9": (0x81, 6, 0x2200, 9, 64, S),
    "ctl-get-protocol-iface-1": (0xA1, 3, 0, 1, 1, S),
    "ctl-get-report-iface-9": (0xA1, 1, 0x0100, 9, 8, S),
    "ctl-set-report-iface-2": (0x21, 9, 0x0200, 2, 1, b"\x02"),
    "ctl-get-report-if1-id5": (0xA1, 1, 0x0105, 1, 32, S),
    "ctl-set-report-if1-id5-len2": (0x21, 9, 0x0205, 1, 2, b"\x05\x02"),
    "ctl-vendor-request": (0x40, 0x5A, 0, 0, 0, S),
    "ctl-get-interface": (0x81, 0x0A, 0, 0, 1, S),
    "ctl-set-interface": (0x01, 0x0B, 0, 0, 0, S),
    "ctl-silence": None,
}

FAKE = 0x30000000
USBP = FAKE + 0x1000
CFG = FAKE + 0x2000
STACK_LO, STACK_HI = FAKE + 0x6000, FAKE + 0x8000
CONDB = {"beq", "bne", "bhi", "bls", "bcs", "bcc", "bhs", "blo", "bmi", "bpl", "bge", "blt",
         "bgt", "ble", "bvs", "bvc", "cbz", "cbnz", "tbb", "tbh"}
MMIO = ((0x40000000, 0x30000), (0x48000000, 0x2000), (0x1FFFC000, 0x4000), (0xE0000000, 0x100000))

_CS = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
_CS.skipdata = True


def _need(cond, msg):
    if not cond:
        raise SystemExit("fuzz_reach_targets: " + msg)


def _uc(img):
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS)
    uc.mem_map(BASE, FLASH)
    uc.mem_write(BASE, img[:FLASH])
    uc.mem_map(SRAM, SRAM_SZ)
    return uc


def crt0_sram(img: bytes, reset: int) -> bytes:
    """Run the image's own Reset_Handler in a bare unicorn instance up to the
    first call made after SRAM was first written (``__late_init``): the
    ``.data`` copy and ``.bss`` zero are then done. Calls before that point
    (``__early_init``, clock setup) are skipped, not executed."""
    uc = _uc(img)
    for b, s in MMIO:
        uc.mem_map(b, s)
    st = {"wrote": False, "n": 0, "stop": None}

    def code(u, addr, size, _):
        st["n"] += 1
        i = next(_CS.disasm(img[addr - BASE:addr - BASE + 4], addr), None)
        if i is not None and i.mnemonic in ("bl", "blx"):
            if st["wrote"]:
                st["stop"] = addr
                u.emu_stop()
            else:
                u.reg_write(UA.UC_ARM_REG_PC, (addr + i.size) | 1)

    def mem(u, access, addr, size, value, _):
        if SRAM <= addr < SRAM + SRAM_SZ:
            st["wrote"] = True
    uc.hook_add(unicorn.UC_HOOK_CODE, code)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, mem)
    uc.reg_write(UA.UC_ARM_REG_SP, SRAM + 0x400)
    uc.emu_start(reset | 1, 0xFFFFFFFE, count=200000)
    _need(st["stop"] is not None, "crt0 never reached its post-init call")
    return bytes(uc.mem_read(SRAM, SRAM_SZ)), st["stop"]


class Arm:
    """Executes a dispatcher of THIS image on one request; see the module doc."""

    def __init__(self, img: bytes, sram: bytes, setup_off: int, helpers: dict, gdcb: int):
        self.img, self.sram, self.so, self.helpers, self.gdcb = img, sram, setup_off, helpers, gdcb
        self._ic: dict = {}

    def ins(self, a):
        if a not in self._ic:
            self._ic[a] = next(_CS.disasm(self.img[a - BASE:a - BASE + 4], a), None)
        return self._ic[a]

    def _in_helper(self, a):
        return any(s <= a <= e for s, e in self.helpers.values())

    def run(self, start, regs, setup, cfg, mode="qmk", ram=None, stack=None, collect=False,
            maxn=3000):
        """mode 'qmk': follow indirect / usbp calls, run others opaquely.
        mode 'std': any call ends the run (except the case helpers)."""
        uc = _uc(self.img)
        uc.mem_write(SRAM, self.sram)
        uc.mem_map(FAKE, 0x10000)
        for b, s in MMIO:
            uc.mem_map(b, s)
        for a, data in (ram or {}).items():
            uc.mem_write(a, data)
        uc.mem_write(USBP + self.so, setup)
        uc.mem_write(USBP + 4, struct.pack("<I", CFG))
        uc.mem_write(CFG, struct.pack("<4I", *cfg))
        sp = STACK_HI - 0x100
        uc.reg_write(UA.UC_ARM_REG_SP, sp)
        for off, v in (stack or {}).items():
            uc.mem_write(sp + off, struct.pack("<I", v))
        for k, v in regs.items():
            uc.reg_write(getattr(UA, "UC_ARM_REG_" + k.upper()), v)
        lv = [{"fn": start, "arm": None, "dec": False, "r": None}]
        st = {"levels": lv, "stop": None, "stop_pc": None, "call": None, "n": 0,
              "opaque": None, "helper": False, "stores": {}, "ret_r0": None}

        def code(u, addr, size, _):
            st["n"] += 1
            if st["n"] > maxn:
                st["stop"], st["stop_pc"] = "budget", addr
                u.emu_stop()
                return
            if st["opaque"] is not None:
                if addr != st["opaque"]:
                    return
                st["opaque"] = None
            if st["helper"]:
                if self._in_helper(addr):
                    return
                st["helper"] = False
            cur = lv[-1]
            if cur["dec"]:
                cur["arm"], cur["dec"] = addr, False
                cur["r"] = [u.reg_read(getattr(UA, "UC_ARM_REG_R%d" % k)) for k in range(4)]
            i = self.ins(addr)
            m = i.mnemonic if i else "?"
            if m in ("bl", "blx"):
                if i.op_str.startswith("#"):
                    tgt, indirect = int(i.op_str[1:], 16), False
                else:
                    tgt, indirect = u.reg_read(getattr(UA, "UC_ARM_REG_" + i.op_str.upper())), True
                tgt &= ~1
                if tgt in self.helpers:
                    cur["dec"], st["helper"] = True, True
                    return
                if collect:
                    st["opaque"] = addr + i.size
                    return
                if tgt == self.gdcb or mode == "std":
                    st["call"], st["stop"], st["stop_pc"] = tgt, "call", addr
                    u.emu_stop()
                    return
                if (indirect or u.reg_read(UA.UC_ARM_REG_R0) == USBP) and len(lv) < 4:
                    lv.append({"fn": tgt, "arm": None, "dec": False, "r": None, "via": addr})
                    return
                st["opaque"] = addr + i.size
                return
            if collect:
                if (m == "bx" and i.op_str == "lr") or (m.startswith("pop") and "pc" in i.op_str):
                    st["stop"], st["stop_pc"] = "ret", addr
                    st["ret_r0"] = u.reg_read(UA.UC_ARM_REG_R0)
                    u.emu_stop()
                return
            if m.startswith("ldr") and i.op_str.startswith("pc"):
                cur["dec"] = True
                return
            if (m == "bx" and i.op_str == "lr") or (m.startswith("pop") and "pc" in i.op_str):
                st["stop"], st["stop_pc"] = "ret", addr
                st["ret_r0"] = u.reg_read(UA.UC_ARM_REG_R0)
                u.emu_stop()
                return
            if m in CONDB:
                cur["dec"] = True

        def mem(u, access, addr, size, value, _):
            if access != unicorn.UC_MEM_WRITE or STACK_LO <= addr < STACK_HI:
                return
            if collect:
                st["stores"][addr] = value
                return
            if st["opaque"] is not None:
                return
            st["stop"], st["stop_pc"] = "store", u.reg_read(UA.UC_ARM_REG_PC)
            u.emu_stop()

        uc.hook_add(unicorn.UC_HOOK_CODE, code)
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, mem)
        try:
            uc.emu_start(start | 1, 0xFFFFFFFE, count=maxn + 5)
        except unicorn.UcError as exc:
            st["stop"], st["stop_pc"] = "fault:%s" % exc, uc.reg_read(UA.UC_ARM_REG_PC)
        return st


def _all_ins(img):
    return list(_CS.disasm(img, BASE))


def locate(img):
    ins = _all_ins(img)
    idx = {i.address: k for k, i in enumerate(ins)}
    gud = [i.address for k, i in enumerate(ins) if i.mnemonic == "lsrs" and i.op_str == "r5, r0, #8"
           and ins[k + 1].mnemonic == "cmp" and ins[k + 1].op_str == "r5, #3"]
    _need(len(gud) == 1, "get_usb_descriptor body candidates %r" % [hex(x) for x in gud])
    k = idx[gud[0]]
    while not ins[k].mnemonic.startswith("push"):
        k -= 1
    gud = ins[k].address
    callers = [i.address for i in ins if i.mnemonic == "bl" and i.op_str == "#0x%x" % gud]
    _need(len(callers) == 1, "get_usb_descriptor callers %r" % callers)
    k = idx[callers[0]]
    while not ins[k].mnemonic.startswith("push"):
        k -= 1
    gdcb = ins[k].address
    if ins[k - 1].mnemonic == "movs" and ins[k - 1].op_str.endswith("#0"):
        gdcb = ins[k - 1].address           # the compiler hoisted one movs above the push
    lits = [BASE + o for o in range(0, len(img) - 3, 4)
            if struct.unpack_from("<I", img, o)[0] == gdcb | 1]
    _need(len(lits) == 1, "USBConfig literal %r" % lits)
    usbcfg = lits[0] - 4
    ev, gd, hook, sof = struct.unpack_from("<4I", img, usbcfg - BASE)
    _need(gd == gdcb | 1 and hook & 1, "USBConfig %x" % usbcfg)
    hook &= ~1
    so = None
    for j in range(3):
        h = ins[idx[hook] + j]
        if h.mnemonic == "adds" and h.op_str.startswith("r1, #"):
            so = int(h.op_str.split("#")[1], 16)
    _need(so is not None, "hook setup offset")
    sites = []
    for k, i in enumerate(ins[:-4]):
        if i.mnemonic == "ldr" and i.op_str == "r3, [r4, #4]" and ins[k + 1].op_str == "r3, [r3, #8]" \
                and ins[k + 2].mnemonic == "cmp" and ins[k + 2].op_str == "r3, #0" \
                and ins[k + 3].mnemonic == "bne":
            sites.append(i.address)
    _need(len(sites) == 1, "_usb_ep0setup hook-load sites %r" % sites)
    helpers = {}
    for k, i in enumerate(ins[:-3]):
        if i.mnemonic == "push" and i.op_str in ("{r1}", "{r0, r1}") and ins[k + 1].mnemonic == "mov" \
                and ins[k + 1].op_str == "r1, lr" and ins[k + 2].op_str in ("r1, r1, #1", "r0, r0, #1"):
            j = k
            while not (ins[j].mnemonic == "bx" and ins[j].op_str == "lr"):
                j += 1
            helpers[i.address] = (i.address, ins[j].address)
    _need(helpers, "no case helpers")
    reset = struct.unpack_from("<I", img, 4)[0] & ~1
    return {"gud": gud, "gdcb": gdcb, "usbcfg": usbcfg, "hook": hook, "ep0site": sites[0],
            "setup_off": so, "gud_caller": callers[0], "reset": reset,
            "case_helpers": sorted(helpers)}


def _setup(t):
    bm, rq, wv, wi, wl, _ = t
    return struct.pack("<BBHHH", bm, rq, wv, wi, wl)


def _lv(kind, st):
    out = []
    for k, l in enumerate(st["levels"]):
        out.append({"kind": kind if k == 0 else "%s.%d" % (kind, k), "fn": l["fn"], "arm": l["arm"],
                    "r": l["r"]})
    return out


def chain(a: Arm, L: dict, req):
    bm, rq, wv, wi, wl, out = req
    setup = _setup(req)
    cfg = (0, L["gdcb"] | 1, 0, 0)
    path, stops = [], []

    def gud():
        g = a.run(L["gud"], {"r0": wv, "r1": wi, "r2": wl, "r3": USBP + 0x200}, setup, cfg)
        path.extend(_lv("gud", g))
        stops.append(g["stop"])
    q = a.run(L["hook"], {"r0": USBP}, setup, cfg)
    path.extend(_lv("hook", q))
    stops.append(q["stop"])
    declined = q["stop"] == "ret" and q["ret_r0"] == 0 and len(q["levels"]) == 1
    if q["stop"] == "call" and q["call"] == L["gdcb"]:
        gud()
    elif declined:
        c = a.run(L["ep0site"], {"r4": USBP}, setup, cfg, mode="std", stack={4: USBP + a.so})
        path.extend(_lv("std", c))
        stops.append(c["stop"])
        if c["stop"] == "call" and c["call"] == L["gdcb"]:
            gud()
    if out is not None and not declined:
        full = a.run(L["hook"], {"r0": USBP}, setup, cfg, collect=True)
        g = lambda off: full["stores"].get(USBP + off)  # noqa: E731
        nxt, cb = g(a.so - 0x0C), g(a.so - 0x04)
        if cb:
            r = a.run(cb & ~1, {"r0": USBP}, setup, cfg, ram={nxt: out})
            path.extend(_lv("cb", r))
            stops.append(r["stop"])
            path[-1]["cb"], path[-1]["buf"] = cb & ~1, nxt
    decided = [p for p in path if p["arm"] is not None]
    _need(decided, "request %s: no decision anywhere on its chain" % setup.hex())
    return decided, stops, declined


def _req(t):
    bm, rq, wv, wi, wl, out = t
    d = {"bm": bm, "req": rq, "value": wv, "index": wi, "length": wl, "setup_hex": _setup(t).hex()}
    if out is not None:
        d["out_hex"] = out.hex()
    return d


def derive() -> dict:
    img = paths.firmware_bin().read_bytes()
    L = locate(img)
    sram, crt0_stop = crt0_sram(img, L["reset"])
    a = Arm(img, sram, L["setup_off"], {h: None for h in L["case_helpers"]}, L["gdcb"])
    a.helpers = {}
    ins = _all_ins(img)
    for h in L["case_helpers"]:
        k = next(j for j, i in enumerate(ins) if i.address == h)
        while not (ins[k].mnemonic == "bx" and ins[k].op_str == "lr"):
            k += 1
        a.helpers[h] = (h, ins[k].address)
    nf = {}
    vend = (0x40, 0x5A, 0, 0, 0, None)
    p, _, dec = chain(a, L, vend)
    _need(dec, "vendor request was not declined by the hook")
    nf["hook_declines"] = next(x["arm"] for x in p if x["kind"] == "hook")
    nf["std_stall"] = next(x["arm"] for x in p if x["kind"] == "std")
    p, _, _ = chain(a, L, (0x80, 6, 0x9900, 0, 16, None))
    nf["gud_exit_or_not_found"] = p[-1]["arm"]
    p, _, _ = chain(a, L, (0xA1, 1, 0x0100, 9, 8, None))
    nf["get_report_dispatch_exit_or_no_iface"] = p[-1]["arm"]
    rows = [(eid, c, t) for eid, (c, t) in ENTRIES.items()]
    # GET_REPORT on iface 1, one entry per Report ID whose storage the image populates.
    found_if1 = []
    for rid in IF1_REPORT_IDS:
        t = (0xA1, 1, 0x0100 | rid, 1, 32, None)
        p, stops, _ = chain(a, L, t)
        # A populated slot goes on to copy the report (a store); an empty one
        # returns straight from the storage callee's own decision.
        if len(p) == 3 and stops[-1] != "ret":
            found_if1.append(rid)
            rows.append(("E_GET_REPORT_IF1_ID%d" % rid, "iface1", t))
        else:
            _need(nf.setdefault("get_report_if1_exit_or_absent_id", p[-1]["arm"]) == p[-1]["arm"],
                  "two different absent-Report-ID arms")
    nfs = {v for v in nf.values() if v is not None}
    entries = []
    for eid, cen, t in rows:
        p, stops, declined = chain(a, L, t)
        own = p[-1]
        _need(own["arm"] not in nfs, "%s reaches a not-found arm 0x%x" % (eid, own["arm"]))
        e = {"id": eid, "census_iface": cen, "class": "census-expansion" if cen != "device" else "extra",
             "setup": _req(t), "handler": "0x%x" % own["arm"], "handler_kind": own["kind"],
             "handler_fn": "0x%x" % own["fn"],
             "route": ["%s:0x%x" % (x["kind"], x["arm"]) for x in p[:-1]],
             "chain_stops": stops}
        if own["kind"].startswith("gud"):
            e["gud_r1_at_arm"] = own["r"][1] if own["r"] else None
        if own["kind"].startswith("cb"):
            e["out_cb"] = "0x%x" % own["fn"]
        entries.append(e)
    own_set = {int(e["handler"], 16) for e in entries}
    for e in entries:
        for r in e["route"]:
            _need(int(r.split(":")[1], 16) not in own_set,
                  "%s routes through another entry's own handler %s" % (e["id"], r))
    by_h: dict = {}
    for e in entries:
        by_h.setdefault(e["handler"], []).append(e["id"])
    for e in entries:
        e["handler_shared_with"] = [x for x in by_h[e["handler"]] if x != e["id"]]
    for k, e in enumerate(entries):
        e["next_entry"] = entries[(k + 1) % len(entries)]["id"]
    controls = []
    for cid, t in CONTROLS.items():
        if t is None:
            controls.append({"id": cid, "setup": None})
            continue
        p, _, _ = chain(a, L, t)
        _need(p[-1]["arm"] not in own_set, "control %s reaches an own handler 0x%x" % (cid, p[-1]["arm"]))
        controls.append({"id": cid, "setup": _req(t),
                         "static_path": ["%s:0x%x" % (x["kind"], x["arm"]) for x in p]})
    vt = [struct.unpack_from("<I", img, 4 * x)[0] for x in range(16 + USB_IRQ + 1)]
    tk = vt[16 + TICK_IRQ] & ~1
    tk_i = list(_CS.disasm(img[tk - BASE:tk - BASE + 8], tk))
    _need(not tk_i[0].mnemonic.startswith("b"), "%s is a thunk" % TICK_NAME)
    hooks = [{"kind": "entry", "addr": "0x%x" % L["hook"], "label": "requests_hook_cb"},
             {"kind": "route", "addr": "0x%x" % L["gud"], "label": "get_usb_descriptor"}]
    seen = {L["hook"], L["gud"]}
    for e in entries:
        h = int(e["handler"], 16)
        if h not in seen:
            seen.add(h)
            hooks.append({"kind": "own", "addr": e["handler"], "label": "+".join(by_h[e["handler"]]),
                          "akind": "cb" if e["handler_kind"].startswith("cb") else e["handler_kind"]})
    for e in entries:
        for r in e["route"]:
            k, h = r.split(":")
            if int(h, 16) not in seen:
                seen.add(int(h, 16))
                hooks.append({"kind": "route", "addr": h, "label": "route-%s-%s" % (k, h)})
    for nm, h in sorted(nf.items()):
        if h is not None and h not in seen:
            seen.add(h)
            hooks.append({"kind": "shared", "addr": "0x%x" % h, "label": nm})
    hooks.append({"kind": "isr", "addr": "0x%x" % tk_i[1].address,
                  "label": "%s+2(exc%d)" % (TICK_NAME, 16 + TICK_IRQ)})
    return {
        "row": ROW, "lane": LANE, "bin": BIN,
        "bin_sha256": hashlib.sha256(img).hexdigest(),
        "inventory_source": "census iface0/iface1/iface2 (INVENTORY.md: the CONFIGURATION descriptor the "
                            "guest returns), each expanded into the requests the image's own dispatch parses "
                            "for that wIndex; plus device-level standard requests (extras)",
        "census": CENSUS,
        "located": {k: ("0x%x" % v if isinstance(v, int) else ["0x%x" % x for x in v]) for k, v in L.items()},
        "crt0_stop": "0x%x" % crt0_stop,
        "sram_init_sha256": hashlib.sha256(sram).hexdigest(),
        "if1_report_ids_populated": found_if1,
        "not_found": {k: ("0x%x" % v if v is not None else None) for k, v in nf.items()},
        "usb_exc": 16 + USB_IRQ, "tick_exc": 16 + TICK_IRQ,
        "entries": entries, "controls": controls, "hooks": hooks,
    }


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    d = derive()
    out = paths.configs_dir() / "fuzz_reach_targets.json"
    js = json.dumps(d, indent=1) + "\n"
    if "--check" in argv:
        ok = out.exists() and out.read_text() == js
        print("fuzz_reach_targets --check: %s (%d entries, %d hooks, bin %s)"
              % ("PASS" if ok else "FAIL", len(d["entries"]), len(d["hooks"]), d["bin_sha256"][:16]))
        return 0 if ok else 1
    if "--print" in argv:
        for e in d["entries"]:
            print("%-26s %-7s %-10s %-9s route=%s shared=%s" % (e["id"], e["census_iface"], e["handler"],
                  e["handler_kind"], e["route"], e["handler_shared_with"]))
        for c in d["controls"]:
            print("%-30s %s" % (c["id"], c.get("static_path")))
        print(json.dumps({k: d[k] for k in ("located", "not_found", "if1_report_ids_populated", "crt0_stop")},
                         indent=1))
        return 0
    out.write_text(js)
    print("wrote %s: %d entries (%d census expansions, %d extras), %d hooks"
          % (out, len(d["entries"]), sum(e["class"] == "census-expansion" for e in d["entries"]),
             sum(e["class"] == "extra" for e in d["entries"]), len(d["hooks"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
