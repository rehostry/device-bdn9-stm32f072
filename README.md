<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# device-bdn9-stm32f072

A **Keebio BDN9 rev2** — a nine-key USB macropad with three rotary encoders,
running **QMK on ChibiOS on an STM32F072 (Cortex-M0 / ARMv6-M)** — rehosted
under [HALucinator](https://github.com/rehostry/halucinator) on the unicorn
backend, from the vendor's own 46 880-byte stripped binary. No hardware, no
vendor simulator, no stub of the device's behaviour: the firmware executes
instruction by instruction and everything this repository claims is a byte the
firmware produced.

**Milestone: M8** — full interface parity, **3 / 3**, on top of a real USB round
trip. Adversarially reviewed and upheld. See `STATUS.md` for the evidence and
`PROVENANCE.md` for the prediction it was graded against, which is committed
*ahead* of everything that can boot the firmware so its timestamp proves it
came first.

---

## Quick start

This builds a fresh environment from the public core, for a reader who has just
cloned the repository. **It is not the environment this device was graded in** —
that one is recorded in `STATUS.md` under "THE ENVIRONMENT", and the `.venv`
below is not expected to exist in a rehostry working tree. Use `STATUS.md` if
you are reproducing the milestone; use this if you are starting from scratch.

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install "halucinator[unicorn] @ git+https://github.com/rehostry/halucinator.git@dev"
pip install -e .

# The firmware is GPLv2 QMK and is NOT redistributed here.  Point the
# extractor at your copy; it hard-fails unless it is byte-identical to the
# image this device was built against.
python3 tools/extract_firmware.py --src /path/to/keebio_bdn9_rev2_w3adefault.bin

rehostry-bdn9-attack          # the graded attack
rehostry-bdn9-panel           # the live web panel, http://127.0.0.1:27261/
rehostry-bdn9 run --seconds 180   # boot it and talk to the bridge yourself
```

## What the attack does

It is a USB host that plugs itself in. It drives a bus reset, enumerates the
macropad, reads every descriptor it has, moves HID class state in **both**
directions, and turns the knobs — with no pairing, no authentication and no
user confirmation of any kind. `landed` is the conjunction of four independent
firmware-side legs plus every guard:

| leg | what makes it non-circular |
|---|---|
| thirteen static descriptors, byte for byte | graded against `PROVENANCE.md`, committed **before the first boot**; the host has no copy of the image |
| the serial-number string | there isn't one in the image — the guest **computes** it at run time from a die UID this attack picks fresh each spawn |
| `SET_PROTOCOL`/`GET_PROTOCOL` × 16, `SET_IDLE`/`GET_IDLE` | a per-run random nonce goes in over EP0 and comes back out of guest RAM |
| six encoder rotations, in a random order | each must produce its own distinct HID report, on **two different endpoints** |

and it must **refuse** three things: an unknown descriptor type must STALL, an
out-of-range string index must STALL, and holding a key down must produce
nothing at all — which `PROVENANCE.md` predicted statically before the boot.

```
$ rehostry-bdn9-attack --decoy-selftest   # prove it refuses an impostor
$ rehostry-bdn9-attack --control          # prove the evidence is guest-derived
```

## Talking to it by hand

`rehostry-bdn9 run` brings up a line protocol on **tcp/27260** (loopback only,
greeted with a per-spawn nonce):

```
$ nc 127.0.0.1 27260
HELLO device=rehostry-bdn9 pid=51234 nonce=…
REQ mine 0x80 6 0x0100 0 18          # GET_DESCRIPTOR(DEVICE)
RESP mine ok 120100020000004010cb3321000201020301
ENC 0 cw 1                           # turn the volume knob clockwise
IN 2 04e900                          #   -> Consumer: Volume Increment
IN 2 040000                          #   -> release
KEY 4 down                           # press the middle switch (PB4)
                                     #   -> nothing: this build's keymap is
                                     #      nine KC_TRANSPARENT halfwords
WIRING                               # the pin map, read out of the image
```

## Layout

```
PROVENANCE.md              the pre-boot prediction (its own commit)
STATUS.md                  what was earned, what was not, and every wall
tools/extract_firmware.py  regenerates the image; verifies 48 vector entries,
                           12 code landmarks and 14 descriptor/table sites
src/rehostry_bdn9/
  configs/                 the HALucinator config + derived symbol map
  peripheral_models/       STM32F0 USB device block + PMA, RCC, flash, TIM2,
                           GPIO (direct pins + encoders), system memory,
                           the modelled USB host and its bridge
  bp_handlers/             the ARMv6-M NMI context switch, the idle pump,
                           and a watcher on the firmware's own panic addresses
  attack.py                run_attack(on_stage, log_dir) -> dict
  bdn9_panel.py            polling web panel with an on-page briefing
tests/test_structure.py    no emulator needed
```

## Licence

AGPL-3.0-or-later. The BDN9 firmware itself is GPLv2 (QMK) and is **not**
redistributed in this repository.
