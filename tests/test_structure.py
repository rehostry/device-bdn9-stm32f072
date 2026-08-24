# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural tests -- no emulator, no firmware bytes required.

These check the things that go wrong *silently*: a config that names a symbol
the addr map does not define, a spawn recipe that stops running the installed
core, a prediction table that has drifted from PROVENANCE.md, and the two
places where a wrong constant would be invisible (the ARMv6-M flash alias and
the pin tables read out of the image).
"""
from __future__ import annotations

import os
import re

import pytest
import yaml

from rehostry_bdn9 import paths, spawn
from rehostry_bdn9.attack import PREDICTED, STATIC_TAGS, ENCODER_REPORT
from rehostry_bdn9.peripheral_models import stm32f0_gpio

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _config():
    with open(paths.configs_dir() / "bdn9_config.yaml") as fh:
        return yaml.safe_load(fh)


def _addrs():
    with open(paths.configs_dir() / "bdn9_addrs.yaml") as fh:
        return yaml.safe_load(fh)["symbols"]


# --- config / symbol agreement --------------------------------------------
def test_every_intercept_symbol_is_defined():
    names = set(_addrs().values())
    for entry in _config()["intercepts"]:
        assert entry["function"] in names, entry["function"]


def test_machine_is_armv6m_shaped():
    m = _config()["machine"]
    # Cortex-M0 has no VTOR: vectors are fetched from address 0.
    assert m["vector_base"] == 0
    assert m["entry_addr"] == 0x080000C1          # crt0 | Thumb
    assert m["init_sp"] == 0x20000400             # __main_stack_end__


def test_flash_is_mapped_at_both_bases():
    mem = _config()["memories"]
    assert mem["alias"]["base_addr"] == 0x00000000
    assert mem["flash"]["base_addr"] == 0x08000000
    # Both must be backed by the SAME image: the alias is where every vector
    # is fetched from, so a mismatch here is a device that takes the wrong
    # interrupts and never says so.
    assert mem["alias"]["file"] == mem["flash"]["file"] == paths.FIRMWARE_BIN
    assert mem["alias"]["size"] == mem["flash"]["size"] == 0x00020000


def test_peripheral_regions_are_page_aligned_and_disjoint():
    regions = []
    for name, p in _config()["peripherals"].items():
        base, size = p["base_addr"], p["size"]
        assert base % 0x1000 == 0, name
        assert size % 0x1000 == 0 and size > 0, name
        regions.append((base, base + size, name))
    regions.sort()
    for (a0, a1, an), (b0, _b1, bn) in zip(regions, regions[1:]):
        assert a1 <= b0, "%s overlaps %s" % (an, bn)


def test_the_usb_block_is_where_the_image_says_it_is():
    p = _config()["peripherals"]
    # 19 literal-pool references to 0x40005C00 and 4 to 0x40006000 in the
    # image; the models serve those offsets inside these pages.
    assert p["usb_regs"]["base_addr"] == 0x40005000
    assert p["usb_pma"]["base_addr"] == 0x40006000


# --- spawn recipe ----------------------------------------------------------
def test_spawn_argv_runs_the_installed_core():
    argv = spawn.spawn_argv()
    assert argv[1:3] == ["-m", "halucinator.main"]
    assert "--emulator" in argv and "unicorn" in argv


def test_spawn_env_strips_source_tree_injection():
    env = spawn.spawn_env(extra=None)
    assert "HALUCINATOR_SRC" not in env
    assert "PYTHONPATH" not in env
    # irq_chunk defaults to 0 on cortex-m, i.e. an unbounded emu_start that
    # never returns to the pending-IRQ drain -- so the USB interrupt would be
    # queued and never delivered.
    assert int(env["HAL_IRQ_CHUNK"]) > 0


def test_ports_come_from_the_queue_row_block():
    for port in (spawn.BRIDGE_PORT, spawn.PANEL_PORT,
                 spawn.DEFAULT_RX_PORT, spawn.DEFAULT_TX_PORT):
        assert 27260 <= port <= 27279, port
    assert len({spawn.BRIDGE_PORT, spawn.PANEL_PORT,
                spawn.DEFAULT_RX_PORT, spawn.DEFAULT_TX_PORT}) == 4


# --- the prediction --------------------------------------------------------
@pytest.mark.parametrize("tag", STATIC_TAGS)
def test_predicted_bytes_are_well_formed(tag):
    value = PREDICTED[tag]
    assert re.fullmatch(r"[0-9a-f]+", value), tag
    assert len(value) % 2 == 0, tag


def test_the_prediction_is_self_consistent():
    """The config descriptor's own fields must agree with the other tags."""
    cfg = bytes.fromhex(PREDICTED["cfg"])
    assert cfg[0] == 9 and cfg[1] == 2
    assert cfg[2] | (cfg[3] << 8) == len(cfg) == 84       # wTotalLength
    assert cfg[4] == 3                                    # three interfaces
    dev = bytes.fromhex(PREDICTED["dev"])
    assert dev[:8].hex() == PREDICTED["dev8"]             # the 8-byte probe
    assert cfg[:9].hex() == PREDICTED["cfg9"]
    assert (dev[8] | (dev[9] << 8)) == 0xCB10             # Keebio
    assert (dev[10] | (dev[11] << 8)) == 0x2133           # BDN9 rev2
    assert dev[16] == 3                                   # iSerialNumber
    # Each HID descriptor's wDescriptorLength must equal the length of the
    # report descriptor it points at -- a coupling that a typo in either would
    # break silently.
    for i, tag in enumerate(("rd0", "rd1", "rd2")):
        hid = bytes.fromhex(PREDICTED["hid%d" % i])
        assert hid[0] == 9 and hid[1] == 0x21 and hid[6] == 0x22
        assert hid[7] | (hid[8] << 8) == len(bytes.fromhex(PREDICTED[tag]))


def test_no_out_endpoint_and_no_raw_hid_usage_page():
    """The two negative facts the queue row got wrong (PROVENANCE.md 3a)."""
    cfg = bytes.fromhex(PREDICTED["cfg"])
    i = 0
    endpoints = []
    while i < len(cfg):
        length, dtype = cfg[i], cfg[i + 1]
        if dtype == 0x05:
            endpoints.append(cfg[i + 2])
        i += length
    assert endpoints == [0x81, 0x82, 0x83]
    assert all(a & 0x80 for a in endpoints), "an OUT endpoint appeared"
    for tag in ("rd0", "rd1", "rd2"):
        assert "0660ff" not in PREDICTED[tag], "raw-HID usage page 0xFF60"


# --- the pin tables, read out of the image ---------------------------------
def test_direct_pins_and_encoder_pads():
    names = [stm32f0_gpio._name(p) for p in stm32f0_gpio.DIRECT_PINS]
    assert names == ["PB12", "PB5", "PB6", "PB14", "PB4", "PB7",
                     "PA3", "PF1", "PF0"]
    assert [stm32f0_gpio._name(p) for p in stm32f0_gpio.ENCODER_PAD_A] == \
        ["PA4", "PA15", "PA9"]
    assert [stm32f0_gpio._name(p) for p in stm32f0_gpio.ENCODER_PAD_B] == \
        ["PA8", "PB3", "PA10"]
    # every pin distinct: a duplicate would silently alias two inputs
    allpins = (stm32f0_gpio.DIRECT_PINS + stm32f0_gpio.ENCODER_PAD_A
               + stm32f0_gpio.ENCODER_PAD_B)
    assert len(set(allpins)) == len(allpins)


def test_encoder_reports_are_distinct_and_on_the_right_endpoints():
    seen = set()
    for index, table in ENCODER_REPORT.items():
        for direction, (ep, payload) in table.items():
            assert (ep, payload) not in seen, (index, direction)
            seen.add((ep, payload))
    # The volume knob is a Consumer Control report (ID 4) on the shared
    # interface; the other two are boot-keyboard reports.
    assert ENCODER_REPORT[0]["cw"][0] == 2
    assert bytes.fromhex(ENCODER_REPORT[0]["cw"][1])[0] == 4
    for i in (1, 2):
        for d in ("cw", "ccw"):
            ep, payload = ENCODER_REPORT[i][d]
            assert ep == 1 and len(bytes.fromhex(payload)) == 8


# --- housekeeping ----------------------------------------------------------
def test_firmware_is_not_committed():
    with open(os.path.join(HERE, ".gitignore")) as fh:
        ignored = fh.read()
    assert "*.bin" in ignored


def test_every_source_file_carries_the_licence_header():
    root = os.path.join(HERE, "src", "rehostry_bdn9")
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith(".py"):
                continue
            with open(os.path.join(dirpath, name)) as fh:
                head = fh.read(400)
            assert "Copyright 2026 Christopher Wright" in head, name
            assert "AGPL-3.0-or-later" in head, name
