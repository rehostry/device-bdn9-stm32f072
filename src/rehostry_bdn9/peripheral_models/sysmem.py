# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ST's system-memory band: the DFU ROM, the flash-size word, and the die UID.

The 16 kB at 0x1FFFC000 is one region because HALucinator peripheral regions
must be 4 kB-aligned, non-overlapping multiples of 4 kB (playbook 2.61), and
this firmware touches two widely-separated addresses inside it:

``0x1FFFC800`` -- the STM32F0 **system-memory DFU bootloader**.
    ``bootloader_jump()`` (0x08006F3E) loads MSP from ``[0x1FFFC800]`` and the
    entry point from ``[0x1FFFC804]`` and branches.  Nothing in *this* build can
    reach it (the only caller is ``QK_BOOT`` and the keymap is nine
    ``KC_TRANSPARENT`` halfwords -- PROVENANCE.md 3b), but an unmapped read
    there would be a hard fault rather than a wrong number, so it is served.

``0x1FFFF7AC..0x1FFFF7B7`` -- the 96-bit **unique device ID**.
    THIS IS THE ORACLE.  QMK's ``get_hardware_id()`` (0x08006D7C) copies those
    three words into a 16-byte buffer and ``0x080073E4`` hex-expands them into
    the USB serial-number string descriptor, uppercase, UTF-16LE, with the four
    zero bytes 12..15 becoming the trailing ``"00000000"``.

    ``attack.py`` picks twelve **fresh random bytes per spawn** and passes them
    in ``HAL_BDN9_DIE_UID``.  The host knows what the serial string must be and
    can check it byte for byte, but nothing in the host stack can *produce* it:
    the guest's own nibble/table loop has to run.  A replayed descriptor from a
    previous run fails, because the UID differs.  That is the difference between
    a value the firmware **stores** and one it **computes** (runbook Step 3).

``0x1FFFF7CC`` -- the flash-size word, in kilobytes.  128 for an STM32F072CB.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from halucinator import hal_log
from halucinator.peripheral_models.generic import GenericPeripheral

log = hal_log.getHalLogger()

BASE = 0x1FFFC000
DFU_ROM = 0x1FFFC800
UID_BASE = 0x1FFFF7AC
FLASH_SIZE_WORD = 0x1FFFF7CC

#: What the DFU ROM's vector table would hold: a stack top in SRAM and an entry
#: point inside system memory.  Only ever read by an unreachable path.
DFU_MSP = 0x20002000
DFU_ENTRY = 0x1FFFC805

_DEFAULT_UID = bytes.fromhex("cb102133" "424e3932" "72657632")

_SYSMEM: Optional["Stm32F0SystemMemory"] = None


def get_sysmem() -> Optional["Stm32F0SystemMemory"]:
    return _SYSMEM


def _uid_from_env() -> bytes:
    raw = os.environ.get("HAL_BDN9_DIE_UID", "")
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        data = b""
    if len(data) != 12:
        return _DEFAULT_UID
    return data


class Stm32F0SystemMemory(GenericPeripheral):
    """Read-only ST system memory: DFU ROM stub + factory calibration words."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.uid = _uid_from_env()
        self.uid_reads = 0
        global _SYSMEM
        _SYSMEM = self
        log.info("Stm32F0SystemMemory: die UID for this spawn = %s "
                 "(serial string the firmware must build: %s)",
                 self.uid.hex(),
                 (self.uid + b"\x00" * 4).hex().upper())

    # -- what the guest is required to turn into a serial string -----------
    def expected_serial_string(self) -> str:
        return (self.uid + b"\x00" * 4).hex().upper()

    def expected_serial_descriptor(self) -> bytes:
        """The 66 bytes GET_DESCRIPTOR(string, 3) must return."""
        text = self.expected_serial_string()
        return bytes((0x42, 0x03)) + text.encode("utf-16-le")

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = BASE + offset
        if UID_BASE <= addr < UID_BASE + 12:
            self.uid_reads += 1
            off = addr - UID_BASE
            chunk = (self.uid + b"\x00" * 4)[off:off + size]
            if self.uid_reads <= 3:
                log.info("Stm32F0SystemMemory: guest read UID word at "
                         "0x%08x (pc=0x%08x)", addr, pc)
            return int.from_bytes(chunk.ljust(size, b"\x00"), "little")
        if addr == FLASH_SIZE_WORD:
            return 128                    # KB -- STM32F072CB
        if addr == DFU_ROM:
            log.info("Stm32F0SystemMemory: guest read the DFU ROM stack top "
                     "(bootloader_jump, pc=0x%08x)", pc)
            return DFU_MSP
        if addr == DFU_ROM + 4:
            return DFU_ENTRY
        return 0

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        # System memory is read-only on silicon; swallow, do not fault.
        return True
