<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Provenance — Keebio BDN9 rev2 (QMK on ChibiOS, STM32F072, Cortex-M0)

**This file was written and committed BEFORE the firmware was booted for the
first time.** It is the falsifiable prediction the rehost is graded against.
Everything below was derived by disassembling the raw image; nothing in it was
observed from a running emulator. Its commit is deliberately kept ahead of every
file that is capable of booting the firmware (this commit contains `LICENSE`,
`PROVENANCE.md` and `tools/extract_firmware.py` and nothing else), so the commit
timestamp proves the prediction preceded the run.

---

## 1. The image

| | |
|---|---|
| device | Keebio **BDN9 rev2** — 9-key macropad, 3 rotary encoders |
| firmware | `firmware-incoming/W3a-usb-hid/bdn9_rev2_stm32f072/keebio_bdn9_rev2_w3adefault.bin` |
| source | github.com/qmk/qmk_firmware `master`, `keyboards/keebio/bdn9/rev2`, compiled via api.qmk.fm job `f26212ed-f0af-4755-bfe2-e15950994a81` |
| licence | GPLv2 (QMK). **Not redistributed here** — `.gitignore` excludes `*.bin`; `tools/extract_firmware.py` regenerates it from the staged copy. |
| sha256 | `53d32e71da572ad716c9d9aa2d780a0e79b8b442cecec1e7d474a5b550b09b20` |
| size | 46 880 B (0xB720) |
| format | **raw ARM binary** — no ELF, no symbols, no sections. (`file` reports "TTComp archive data"; that is `file` guessing.) |
| load base | `0x08000000` |

Every address in this document is an address in that image at that base, and
every name attached to one is **synthetic** — invented by this project while
reading the disassembly. The vendor supplied no symbols.

---

## 2. The architecture claim, checked against the bytes

The queue row asserts *"STM32F072 / Cortex-M0 — CONFIRMED — SP=0x20000400,
reset=0x08000191 Thumb"*. The row's `arch:` line is a hypothesis until the bytes
agree. They do, on five independent counts:

1. **Vector table.** `SP = 0x20000400` (into SRAM at `0x20000000`), `reset =
   0x08000191` — odd, so Thumb, and pointing into flash. Both plausible.
2. **The table is exactly 48 entries long.** Entries 0..47 are all `0x080001xx`
   or the weak default handler `0x08000193`; entry 48 (`+0xC0`) is `0xb672`
   (`cpsid i`), the first instruction of `crt0`. 48 = **16 exceptions + 32 IRQ
   lines**, which is the STM32F0 interrupt count. An STM32F103 (Cortex-M3) has
   60+ IRQ lines and a ≥76-entry table.
3. **`crt0` is ChibiOS `crt0_v6m.S`, not `crt0_v7m.S`.** At `0x080000C0`:
   `cpsid i` / `msr MSP` / `msr PSP` / `msr CONTROL,#2` / `isb`. There is **no
   `msr BASEPRI`** and **no CPACR/FPU enable** — both of which the v7m variant
   emits, and both of which the fleet's Cortex-M4 sibling
   (`device-onekey-at32f415`) shows.
4. **No ARMv7-M-only encoding survives inspection.** A `--force-thumb`
   disassembly of the whole file throws up 8 `cbz`, 2 `cbnz` and 3 `and.w`; all
   thirteen sit inside literal pools (e.g. `b13c 0800` at `0x08007B34` is the
   word `0x0800B13C`, a flash pointer, not a `CBZ`). No `it`, `movw`, `ldrd`,
   `sdiv`, `tbb`, `ubfx` or VFP opcode occurs anywhere.
5. **The die-UID base is the F0 one.** The image loads `0x1FFFF7AC` /
   `0x1FFFF7B0` / `0x1FFFF7B4` (STM32F0 `UID_BASE`), not the F1's `0x1FFFF7E8`.
   It also loads `0x1FFFC800` — the STM32F0 system-memory DFU ROM.

**Verdict: the row's arch line matched.** ARMv6-M / Cortex-M0 / STM32F0x2.

Two consequences that shape the rehost:

- **Cortex-M0 has no VTOR.** Vectors are fetched from address 0, so flash must
  be mapped at **both** `0x00000000` and `0x08000000`.
- **ChibiOS's ARMv6-M port context-switches through an NMI.** `_port_exit_from_isr`
  at `0x080001C6` does `bl`; `ldr r2,=0xE000ED04`; `ldr r3,=0x80000000`;
  `str r3,[r2]`; `b .` — i.e. it sets `SCB->ICSR.NMIPENDSET` and spins at
  `0x080001D0` waiting for the NMI to take it. unicorn implements no
  `NMIPENDSET`, so that spin is a mandatory intercept.

### Memory map recovered from `crt0`

| region | range | from |
|---|---|---|
| main stack (MSP) | `0x20000000`–`0x20000400` | `msr MSP, 0x20000400`; fill loop bounds |
| process stack (PSP) | `0x20000400`–`0x20000C00` | `msr PSP, 0x20000C00` |
| `.data` | `0x20000C00`–`0x2000106C` ← flash `0x0800B2A4` | crt0 copy loop |
| `.bss` | `0x20001070`–`0x200027B8` | crt0 zero loop |
| SRAM | `0x20000000`–`0x20004000` (16 KB) | STM32F072CB |
| flash | `0x08000000`–`0x08020000` (128 KB) | STM32F072CB |

`main()` is at `0x08002350` (the `bl` between crt0's two `init_array` loops).

---

## 3. The seam, checked against the bytes

The queue row's seam is *"USB HID + **VIA / RAW HID** + rotary-encoder events +
STM32F072 DFU"*. Two of those four are **not in this image**, and the check that
settles it is static:

### 3a. There is no VIA / RAW HID interface

The CONFIGURATION descriptor at `0x0800AFFF` has `wTotalLength = 84` and
declares **three** HID interfaces, and **every endpoint in it is IN**:

| iface | class/sub/proto | report desc | endpoint | what it is |
|---|---|---|---|---|
| 0 | `03 / 01 / 01` | 68 B @ `0x0800B0F5` | `0x81` IN, 8 B, 1 ms | boot keyboard |
| 1 | `03 / 00 / 00` | 123 B @ `0x0800B07A` | `0x82` IN, 32 B, 1 ms | QMK "shared" (mouse + system + consumer) |
| 2 | `03 / 00 / 00` | 21 B @ `0x0800B065` | `0x83` IN, 32 B, 1 ms | QMK console (usage page `0xFF31`) |

There is **no OUT endpoint at all**, the byte sequence `06 60 FF` (HID usage
page `0xFF60`, which is what a QMK raw-HID/VIA interface must declare) does not
occur anywhere in the 46 880 bytes, and the strings `via`/`VIA`/`RAW` do not
occur either. Interface 2's 21-byte report descriptor is byte-identical to
QMK's **console** descriptor (`06 31 FF …`), not the raw-HID one.

This is the **fourth** api.qmk.fm `default` build in this fleet found to lack the
raw-HID interface its queue row promised (`device-keychron-v1-stm32l432`,
`device-tac-k1-wb32fq95`, `device-onekey-at32f415`).

### 3b. No keypress on this build can ever emit a HID report

`keymap_key_to_keycode(layer, row, col)` is at `0x08000588`:

```
8000588: movs r3,#1          ; default: KC_TRANSPARENT
800058a: cmp  r0,#0          ; layer != 0 -> return KC_TRANSPARENT
800058c: bne  0x80005a2
800058e: cmp  r1,#2          ; row > 2   -> return KC_TRANSPARENT
8000590: bhi  0x80005a2
8000592: cmp  r2,#2          ; col > 2   -> return KC_TRANSPARENT
8000594: bhi  0x80005a2
8000596: adds r3,#2          ; r3 = 3  (MATRIX_COLS)
8000598: muls r3,r1
800059a: ldr  r0,[pc,#12]    ; -> 0x0800A288   == `keymaps`
800059c: adds r3,r3,r2
800059e: lsls r3,r3,#1
80005a0: ldrh r3,[r3,r0]
80005a2: movs r0,r3
80005a4: bx   lr
```

So `MATRIX_ROWS == 3`, `MATRIX_COLS == 3`, there is **exactly one layer**, and
the keymap is the nine halfwords at `0x0800A288`:

```
0800a288  01 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00
```

All nine are `0x0001` = `KC_TRANSPARENT`. **Prediction: pressing any of the nine
keys produces no HID report, on any layer, ever.** This device therefore reports
`hid_keystroke_round_trip: false` as its own field and `landed` does not depend
on it. (Encoder events resolve through the same keymap and are likewise dead.)

### 3c. What *is* in the image: a rich EP0 control surface

Which makes **USB enumeration and HID class control transfers** the M4 seam —
the same choice `device-dekrispator-synth`, `device-atreus-stm32f103`,
`device-keychron-v1-stm32l432` and `device-tac-k1-wb32fq95` made, and a legitimate
one: it is a real protocol round trip with firmware-generated bytes out and
host-chosen bytes in.

The USB peripheral is the ST **USB-FS device block with packet memory** —
registers at `0x40005C00` (19 literal-pool references), PMA at `0x40006000`
(4 references), **IRQ 31**. Not an OTG core.

The ChibiOS `USBConfig` is the four words at `0x0800AF94`:
`{event_cb = 0x080070ED, get_descriptor_cb = 0x0800705D, requests_hook_cb = 0x08006F61, sof_cb = 0}`.

---

## 4. THE PREDICTION — exact bytes the firmware must emit

### 4a. `get_usb_descriptor()` — decoded from `0x08007444`

```
size_t get_usb_descriptor(uint16_t wValue, uint16_t wIndex,
                          uint16_t wLength, const uint8_t **out);
```
switches on `wValue >> 8`:

| `wValue>>8` | behaviour (from the disassembly) |
|---|---|
| `0x01` DEVICE | `*out = 0x0800B053`, return 18 |
| `0x02` CONFIGURATION | `*out = 0x0800AFFF`, return 84 |
| `0x03` STRING | jump table at `0x08007490` (`__gnu_thumb1_case_uqi`, bytes `17 02 05 08`), on `wValue & 0xFF`; index > 3 returns 0 |
| `0x21` HID | `wIndex > 2` → 0; else `*out = ((void**)0x0800AFB4)[wIndex]`, return 9 |
| `0x22` REPORT | `wIndex > 2` → 0; else `*out = ((void**)0x0800AFA8)[wIndex]`, return `((uint8_t*)0x0800AFA4)[wIndex]` |
| anything else | return 0, `*out` left NULL |

and `get_descriptor_cb` (`0x0800705C`) returns `NULL` when `*out` is NULL, which
makes ChibiOS **STALL** EP0. That is the negative control in §4e.

The two dispatch tables, read out of the image:

```
0800afa8  f5 b0 00 08  7a b0 00 08  65 b0 00 08     ; report descriptors
0800afa4  44 7b 15 00                                ; their lengths: 68, 123, 21
0800afb4  11 b0 00 08  2a b0 00 08  43 b0 00 08     ; HID descriptors
```
The three report-descriptor lengths `44 / 7b / 15` must equal the three
`wDescriptorLength` fields inside the CONFIGURATION descriptor. They do.

### 4b. The nine static descriptors, byte for byte

**`GET_DESCRIPTOR(type=0x01 DEVICE)` → 18 bytes**
```
12 01 00 02 00 00 00 40 10 cb 33 21 00 02 01 02
03 01
```
`bcdUSB 0x0200`, `bMaxPacketSize0 64`, **`idVendor 0xCB10` (Keebio)**,
**`idProduct 0x2133`**, `bcdDevice 0x0200`, `iManufacturer 1`, `iProduct 2`,
**`iSerialNumber 3`**, `bNumConfigurations 1`.

**`GET_DESCRIPTOR(type=0x02 CONFIGURATION)` → 84 bytes**
```
09 02 54 00 03 01 00 a0 fa 09 04 00 00 01 03 01
01 00 09 21 11 01 00 01 22 44 00 07 05 81 03 08
00 01 09 04 01 00 01 03 00 00 00 09 21 11 01 00
01 22 7b 00 07 05 82 03 20 00 01 09 04 02 00 01
03 00 00 00 09 21 11 01 00 01 22 15 00 07 05 83
03 20 00 01
```

**`GET_DESCRIPTOR(type=0x03, index=0)` → 4 bytes** (LANGID 0x0409)
```
04 03 09 04
```

**`GET_DESCRIPTOR(type=0x03, index=1)` → 14 bytes** (`"Keebio"`)
```
0e 03 4b 00 65 00 65 00 62 00 69 00 6f 00
```

**`GET_DESCRIPTOR(type=0x03, index=2)` → 24 bytes** (`"BDN9 Rev. 2"`)
```
18 03 42 00 44 00 4e 00 39 00 20 00 52 00 65 00
76 00 2e 00 20 00 32 00
```

**`GET_DESCRIPTOR(type=0x21 HID, index=0/1/2)` → 9 bytes each**
```
if0: 09 21 11 01 00 01 22 44 00
if1: 09 21 11 01 00 01 22 7b 00
if2: 09 21 11 01 00 01 22 15 00
```

**`GET_DESCRIPTOR(type=0x22 REPORT, index=0)` → 68 bytes** (boot keyboard)
```
05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01
95 08 75 01 81 02 95 01 75 08 81 01 05 07 19 00
29 ff 15 00 26 ff 00 95 06 75 08 81 00 05 08 19
01 29 05 15 00 25 01 95 05 75 01 91 02 95 01 75
03 91 01 c0
```

**`GET_DESCRIPTOR(type=0x22 REPORT, index=1)` → 123 bytes** (shared)
```
05 01 09 02 a1 01 85 02 09 01 a1 00 05 09 19 01
29 08 15 00 25 01 95 08 75 01 81 02 05 01 09 30
09 31 15 81 25 7f 95 02 75 08 81 06 09 38 15 81
25 7f 95 01 75 08 81 06 05 0c 0a 38 02 15 81 25
7f 95 01 75 08 81 06 c0 c0 05 01 09 80 a1 01 85
03 19 01 2a b7 00 15 01 26 b7 00 95 01 75 10 81
00 c0 05 0c 09 01 a1 01 85 04 19 01 2a a0 02 15
01 26 a0 02 95 01 75 10 81 00 c0
```

**`GET_DESCRIPTOR(type=0x22 REPORT, index=2)` → 21 bytes** (console, page `0xFF31`)
```
06 31 ff 09 74 a1 01 09 75 15 00 26 ff 00 95 20
75 08 81 02 c0
```

### 4c. String 3 is COMPUTED AT RUN TIME from the die UID — the keyed leg

There is no serial-number string in the image; `iSerialNumber = 3` is served by
the builder at `0x080073E4`, which the jump table reaches for `index == 3`:

```
80073e4: ldr r3,=0x200021CF   ; a one-shot "already built" flag
80073ea: ldrb r5,[r3,#0]
80073ee: bne  <return>
80073f8: strb #1,[r3,#0]
80073fa: bl   0x8006d7c       ; get_hardware_id(uint8_t out[16])
                              ;   memset(out,0,16)
                              ;   out[0..3]  = *(u32*)0x1FFFF7AC
                              ;   out[4..7]  = *(u32*)0x1FFFF7B0
                              ;   out[8..11] = *(u32*)0x1FFFF7B4
   ; then, for i in 0..15:
   ;   out16 = (uint8_t*)0x200021D0
   ;   out16[2 + 4*i + 0] = "0123456789ABCDEF"[uid[i] >> 4]   ; table @0x0800AFC0
   ;   out16[2 + 4*i + 1] = 0
   ;   out16[2 + 4*i + 2] = "0123456789ABCDEF"[uid[i] & 0x0F]
   ;   out16[2 + 4*i + 3] = 0
800742a: adds r3,#34 -> 66 ; strb -> out16[0] = 0x42   (bLength 66)
800742e: subs r3,#63 ->  3 ; strb -> out16[1] = 0x03   (bDescriptorType STRING)
```

**Prediction.** With the twelve UID bytes at `0x1FFFF7AC..0x1FFFF7B7` set to
`U[0..11]` (little-endian words) — a value this rehost picks **freshly at every
spawn, from `os.urandom`, and writes into guest memory before the guest runs** —
`GET_DESCRIPTOR(type=0x03, index=3)` must return exactly **66 bytes**:

```
0x42 0x03  then UTF-16LE of  UPPERCASE-HEX( U[0..11] || 00 00 00 00 )
```

i.e. 32 hex characters, each followed by a `0x00`; the last eight characters are
always `"00000000"` because `get_hardware_id` zeroes bytes 12..15 and only fills
three words. The host knows `U` and can compute the expected 66 bytes, but
**nothing in the host stack produces them** — the guest's own nibble/table loop
must run. A replay of a previous run's descriptor fails, because `U` differs.

### 4d. A bidirectional class round trip: SET_PROTOCOL → GET_PROTOCOL

`usb_request_hook_cb` at `0x08006F60` handles `bmRequestType & 0x7F == 0x21`
(HID class, interface recipient):

| bRequest | direction | handler | behaviour |
|---|---|---|---|
| `0x01` GET_REPORT | IN | `0x080077FC` | driver vtable `+4`, length from `0x200000B4[0x48]` |
| `0x02` GET_IDLE | IN | `0x08007A48` | driver vtable `+20`: returns `(p[reportID][0] >> 2)`, 1 byte at `0x20002364` |
| `0x03` GET_PROTOCOL | IN | inline `0x08006F8C` | `wIndex` must be 0; returns `*(uint8_t*)0x20000C4A`, 1 byte staged at `0x200021C8` |
| `0x09` SET_REPORT | OUT | inline `0x08006FCA` | `wIndex <= 1`; receives 2 bytes into `0x200021CC`, end-callback `0x08007098` sets `*(uint8_t*)0x20000C49` (the LED state) |
| `0x0A` SET_IDLE | OUT | `0x08006FEC` + `0x08007A9C` | `*(uint8_t*)0x20000C48 = wValue>>8`, and driver vtable `+16`: `p[reportID][0] = (wValue>>8) << 2` |
| `0x0B` SET_PROTOCOL | OUT | inline `0x08006FD4` | `wIndex` must be 0; `*(uint8_t*)0x20000C4A = (wValue & 0xFF) != 0` |

`0x08006C6C` (setter) and `0x08006C8C` (getter) are the two halves:

```
8006c6c: subs r3,r0,#1 ; sbcs r0,r3   ; r0 = (r0 != 0)
8006c72: ldr  r1,=0x20000C48
8006c76: strb r0,[r1,#2]              ; protocol := !!wValue
...
8006c8c: ldr  r3,=0x20000C48
8006c8e: ldrb r0,[r3,#2]              ; return protocol
8006c90: bx   lr
```

**Prediction.** For a random bit string `b[0..15]` chosen fresh this run, the
sequence `SET_PROTOCOL(wValue=b[i], wIndex=0)` followed by `GET_PROTOCOL(wIndex=0)`
must return the single byte `b[i]` for every `i`, reproducing the whole 16-bit
nonce. This is host-chosen input entering the guest over EP0, being stored by
the guest's own handler in guest RAM, and coming back out over EP0 — in both
directions, sixteen times, with content the host picked this run.

The same applies to `SET_IDLE(wValue = (D<<8) | reportID) → GET_IDLE(reportID)`
returning `D` for a random byte `D`, **provided** the driver has a registered
report with that ID (`p[reportID] != NULL`, checked at run time); that leg is
reported separately and is not required for `landed`.

### 4e. In-run rejection control (makes the round trip non-circular)

`get_usb_descriptor` returns 0 with `*out` untouched for any `wValue>>8` outside
`{0x01, 0x02, 0x03, 0x21, 0x22}`, and for `type=0x03` with `index > 3`, and for
`type=0x21/0x22` with `wIndex > 2`. `get_descriptor_cb` then returns NULL and
ChibiOS stalls EP0.

**Prediction:** `GET_DESCRIPTOR(type=0x99, index=0, wLength=16)` and
`GET_DESCRIPTOR(type=0x03, index=7, wLength=64)` must both **STALL and leak zero
bytes**. A mirror, an echo, or a credulous harness passes §4b and fails this.

### 4f. The firmware's own panic signature (so the oracle is not the panic path)

`chSysHalt()` is at `0x08007B64`: `cpsid i` / `str r0,[0x20002704]` /
`strb #3,[…]` / `b .` at `0x08007B70`. The weak `_unhandled_exception` parks at
`0x08000196`. `__default_exit` (main returned) parks at `0x08007AF0`. A run that
reaches any of those three addresses has failed, whatever else it produced, and
the attack checks that it did not.

---

## 5. What this predicts will NOT happen

- **No keystroke → HID report.** §3b. Static, and total: the keymap is nine
  `KC_TRANSPARENT` halfwords and there is only one layer.
- **No VIA / raw-HID command seam.** §3a. There is no OUT endpoint in the image.
- **No `bootloader_jump`.** `0x08006F3E` reads the DFU ROM vector at
  `0x1FFFC800` and jumps; `QK_BOOT` is the only thing that calls it and no key
  maps to it, so this path is unreachable in this build.

---

## 6. Verification hook

`tools/extract_firmware.py` re-derives the image and **hard-fails** unless the
sha256, the size, all 48 vector-table entries, 13 code landmarks and 15
descriptor/table sites match what this document states. Run it before believing
anything else in this repository.
