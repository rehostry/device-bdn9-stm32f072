#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive this device's flash image + synthetic symbol table from the staged image.

The BDN9 rev2 firmware is a **raw ARM binary** -- no ELF, no symbols, no
sections (`file` calls it "TTComp archive data", which is `file` guessing).
Everything this script emits is therefore recovered *from the bytes*:

  bdn9.bin         the staged image padded to the STM32F072CB flash size
                   (128 KB) with 0xFF, so a read past the end of the image
                   reads erased flash rather than faulting.
  bdn9_addrs.yaml  decimal-address -> synthetic-name map for the intercepts.
                   Every name here is one this project invented; none came
                   from the vendor.

It HARD-FAILS if the sha256, the size, the vector table, or any of the
recovered landmark addresses disagree with what `bdn9_config.yaml` and
`PROVENANCE.md` hardcode -- so a different image fails loudly instead of
booting into nonsense.

Firmware bytes are never committed (see .gitignore); run this to regenerate.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

FLASH_BASE = 0x08000000
FLASH_SIZE = 0x00020000  # STM32F072CB: 128 KB

SHA256 = "53d32e71da572ad716c9d9aa2d780a0e79b8b442cecec1e7d474a5b550b09b20"
SIZE = 46880

# --- vector table, read out of the image ------------------------------------
EXPECT_INIT_SP = 0x20000400  # __main_stack_end__
EXPECT_RESET = 0x08000191  # Reset_Handler | Thumb
EXPECT_NMI = 0x08008089
EXPECT_IRQ15 = 0x08008D0D  # TIM2  -- ChibiOS system tick
EXPECT_IRQ16 = 0x08008DA1  # TIM3
EXPECT_IRQ31 = 0x08008E01  # USB
N_VECTORS = 48  # 16 exceptions + 32 IRQ lines == STM32F0 == Cortex-M0

DEFAULT_HANDLER = 0x08000193  # every other vector

# --- landmarks recovered by disassembly (see PROVENANCE.md) -----------------
# name -> (address, expected halfword at that address)
LANDMARKS = {
    # ChibiOS crt0_v6m entry (reset_handler branches here)
    "crt0_entry": (0x080000C0, 0xB672),  # cpsid i
    # the weak _unhandled_exception: `bl .+0; b .`
    "unhandled_exception_spin": (0x08000196, 0xE7FE),
    # _port_exit_from_isr: writes SCB->ICSR.NMIPENDSET then spins.  ARMv6-M
    # ChibiOS context-switches through NMI and unicorn implements no
    # NMIPENDSET, so this spin is a mandatory intercept.
    "port_exit_from_isr_spin": (0x080001D0, 0xE7FE),
    # its first instruction: `bl chSchDoReschedule`
    "port_exit_from_isr": (0x080001C6, 0xF007),
    # ChibiOS idle thread: `wfi; b .-2`
    "idle_thread_wfi": (0x08007F0C, 0xBF30),
    # chSysHalt(): `cpsid i; ...; b .`  -- the firmware's own panic signature
    "sys_halt_spin": (0x08007B70, 0xE7FE),
    # QMK bootloader_jump(): loads MSP/entry from the DFU ROM at 0x1FFFC800
    "bootloader_jump_spin": (0x08006F4C, 0xE7FE),
    # main()
    "main": (0x08002350, 0xB510),
    # get_usb_descriptor(wValue, wIndex, wLength, &ptr)
    "get_usb_descriptor": (0x08007444, 0xB570),
    # the serial-string builder: hex-expands the die UID into RAM
    "serial_string_build": (0x080073E4, 0xB5F0),
    # get_hardware_id(): memset(16) then three words from 0x1FFFF7AC
    "get_hardware_id": (0x08006D7C, 0xB510),
    # keymap_key_to_keycode(layer, row, col)
    "keymap_key_to_keycode": (0x08000588, 0x2301),
    # usb_request_hook_cb()
    "usb_request_hook": (0x08006F60, 0x0001),
}

# --- data landmarks: (address, expected first bytes) ------------------------
DATA_LANDMARKS = {
    "usb_config_struct": (0x0800AF94, bytes.fromhex("ed700008")),
    "string_langid_descriptor": (0x0800AFFB, bytes.fromhex("04030904")),
    "string_manufacturer_descriptor": (0x0800AFEB, bytes.fromhex("0e034b00")),
    "string_product_descriptor": (0x0800AFD1, bytes.fromhex("18034200")),
    "configuration_descriptor": (0x0800AFFF, bytes.fromhex("09025400")),
    "device_descriptor": (0x0800B053, bytes.fromhex("12010002")),
    "report_descriptor_keyboard": (0x0800B0F5, bytes.fromhex("05010906")),
    "report_descriptor_shared": (0x0800B07A, bytes.fromhex("05010902")),
    "report_descriptor_console": (0x0800B065, bytes.fromhex("0631ff09")),
    "hid_descriptor_if0": (0x0800B011, bytes.fromhex("09211101")),
    "hid_descriptor_if1": (0x0800B02A, bytes.fromhex("09211101")),
    "hid_descriptor_if2": (0x0800B043, bytes.fromhex("09211101")),
    "hex_digit_table": (0x0800AFC0, b"0123456789ABCDEF"),
    # nine halfwords of KC_TRANSPARENT (0x0001): the whole keymap
    "keymaps": (0x0800A288, bytes.fromhex("010001000100010001000100010001000100")),
}

DEFAULT_SRC = (
    "/Users/user/Development/firmware-incoming/W3a-usb-hid/"
    "bdn9_rev2_stm32f072/keebio_bdn9_rev2_w3adefault.bin"
)


def fail(msg: str) -> int:
    print("FAIL: " + msg, file=sys.stderr)
    return 1


def main() -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outdir = os.path.join(here, "src", "rehostry_bdn9", "configs")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", default=DEFAULT_SRC, help="staged raw .bin")
    ap.add_argument("--outdir", default=outdir)
    args = ap.parse_args()

    if not os.path.exists(args.src):
        return fail("firmware not found: %s" % args.src)
    raw = open(args.src, "rb").read()

    digest = hashlib.sha256(raw).hexdigest()
    print("source : %s" % args.src)
    print("size   : %d" % len(raw))
    print("sha256 : %s" % digest)
    if len(raw) != SIZE:
        return fail("size %d != expected %d" % (len(raw), SIZE))
    if digest != SHA256:
        return fail("sha256 mismatch: %s != %s" % (digest, SHA256))

    # ---- vector table -------------------------------------------------------
    vec = list(struct.unpack_from("<%dI" % N_VECTORS, raw, 0))
    checks = [
        ("init_SP", vec[0], EXPECT_INIT_SP),
        ("reset", vec[1], EXPECT_RESET),
        ("NMI", vec[2], EXPECT_NMI),
        ("IRQ15/TIM2", vec[16 + 15], EXPECT_IRQ15),
        ("IRQ16/TIM3", vec[16 + 16], EXPECT_IRQ16),
        ("IRQ31/USB", vec[16 + 31], EXPECT_IRQ31),
    ]
    for name, got, want in checks:
        if got != want:
            return fail("vector %s = 0x%08x, expected 0x%08x" % (name, got, want))
        print("vector %-11s 0x%08x  OK" % (name, got))

    # every other vector must be the weak default handler; that 48-entry shape
    # (16 + 32 IRQ lines) is itself the Cortex-M0 / STM32F0 evidence.
    named = {0, 1, 2, 16 + 15, 16 + 16, 16 + 31}
    for i, v in enumerate(vec):
        if i in named:
            continue
        if v != DEFAULT_HANDLER:
            return fail("vector[%d] = 0x%08x, expected default 0x%08x"
                        % (i, v, DEFAULT_HANDLER))
    print("vectors    : 48 entries (16 exceptions + 32 IRQ lines) -- STM32F0/M0")

    # ---- code + data landmarks ---------------------------------------------
    for name, (addr, half) in sorted(LANDMARKS.items()):
        off = addr - FLASH_BASE
        got = struct.unpack_from("<H", raw, off)[0]
        if got != half:
            return fail("landmark %s @0x%08x: halfword 0x%04x != 0x%04x"
                        % (name, addr, got, half))
    print("landmarks  : %d code sites verified" % len(LANDMARKS))

    for name, (addr, want) in sorted(DATA_LANDMARKS.items()):
        off = addr - FLASH_BASE
        got = raw[off:off + len(want)]
        if got != want:
            return fail("data %s @0x%08x: %s != %s"
                        % (name, addr, got.hex(), want.hex()))
    print("data       : %d descriptor/table sites verified" % len(DATA_LANDMARKS))

    # ---- emit ---------------------------------------------------------------
    os.makedirs(args.outdir, exist_ok=True)
    img = bytearray(b"\xff" * FLASH_SIZE)
    img[0:len(raw)] = raw
    binpath = os.path.join(args.outdir, "bdn9.bin")
    with open(binpath, "wb") as fh:
        fh.write(img)
    print("wrote      : %s (%d bytes, padded to 0x%x)" % (binpath, len(img), FLASH_SIZE))

    lines = [
        "# Copyright 2026 Christopher Wright",
        "# SPDX-License-Identifier: AGPL-3.0-or-later",
        "#",
        "# GENERATED by tools/extract_firmware.py -- do not edit.",
        "#",
        "# The BDN9 image carries NO symbols.  Every name below is synthetic:",
        "# it was recovered by disassembling the raw image (see PROVENANCE.md)",
        "# and named by this project, not by the vendor.",
        "symbols:",
    ]
    syms = {addr: name for name, (addr, _) in LANDMARKS.items()}
    for addr in sorted(syms):
        lines.append("  %d: %s" % (addr, syms[addr]))
    ypath = os.path.join(args.outdir, "bdn9_addrs.yaml")
    with open(ypath, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote      : %s (%d symbols)" % (ypath, len(syms)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
