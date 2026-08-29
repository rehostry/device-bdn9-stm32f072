<!-- rehostry-census: milestone=M4 landed=true verdict=M4-OK verified=2026-08-29 method=live-run -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Status — device-bdn9-stm32f072

**Milestone reached: M4.** A Keebio BDN9 rev2 — a nine-key macropad with three
rotary encoders, **QMK on ChibiOS on an STM32F072, Cortex-M0 / ARMv6-M** — boots
from its own stripped 46 880-byte vendor image, brings up its clocks and its
wear-levelling flash EEPROM, runs the ChibiOS scheduler through its ARMv6-M NMI
context switch, enumerates against a modelled USB host, emits **every descriptor
byte-for-byte as predicted before the first boot**, round-trips a per-run nonce
through HID class requests, and turns its **encoders into real HID reports on
two different endpoints**.

| level | means | status |
|---|---|---|
| M1 | boots without faulting | **earned** — no `UC_ERR` / `Traceback` / `FETCH-DERAIL`; the firmware's own `chSysHalt()` spin (0x08007B70) and `_unhandled_exception` (0x08000196) are intercepted and counted, and both stay at 0 |
| M2 | drivers initialise | **earned** — the firmware's own RCC/PLL bring-up (`SW=0` → `SW=2`), its flash-controller unlock and four real page erases at 0x0801E000–0x0801FFFF, its `CNTR`/`BTABLE`/`EP0R` USB setup, its `BCDR.DPPU` attach, and **its own printf** — `"USB configured.\n"` on its console HID endpoint (EP3, usage page `0xFF31`) |
| M3 | scheduler runs | **earned** — ChibiOS context-switches through `NMI` on every reschedule (thousands per run), sleeps its 1500 ms `chThdSleepMilliseconds` in `init_usb_driver()` against its own tickless TIM2 compare, and idles in its own `wfi` |
| M4 | real protocol round trip | **earned** — full USB enumeration byte-identical to `PROVENANCE.md`, a serial string the guest computes from a die UID chosen this spawn, a 16-bit nonce round-tripped through `SET_PROTOCOL`/`GET_PROTOCOL`, and six encoder rotations producing six distinct HID reports |

**Bucket A: no core change.** `cortex-m3` was already in `_ARCH_MAP` and unicorn's
Cortex-M3 model decodes ARMv6-M as a subset. Runs on a private venv off the
pinned core `hal-b0818-on-9bde2c0` @ `60619b7`.

---

## The row's claims, checked against the bytes

The queue row said *"STM32F072 / Cortex-M0 — Seam: USB HID + **VIA / RAW HID** +
rotary-encoder events + STM32F072 DFU"*.

**The arch line was right**, on five independent counts (`PROVENANCE.md` §2):
a 48-entry vector table (16 exceptions + 32 IRQ lines — an F1/M3 would have
≥76), ChibiOS's `crt0_v6m` with no `msr BASEPRI` and no FPU enable, no surviving
ARMv7-M-only encoding anywhere in the image, and the F0's `UID_BASE`
(`0x1FFFF7AC`) and DFU ROM (`0x1FFFC800`) rather than the F1's.

**Half the seam line was wrong, and it is wrong in a way this fleet has now seen
four times.**

- **There is no VIA / raw-HID interface in this build.** The configuration
  descriptor is 84 bytes and declares three HID interfaces whose endpoints are
  `0x81`, `0x82`, `0x83` — **all IN**. There is no OUT endpoint anywhere, the
  byte sequence `06 60 FF` (usage page `0xFF60`, which a QMK raw-HID interface
  must declare) does not occur in the image, and the strings `via`/`VIA`/`RAW`
  do not occur either. Interface 2's 21-byte report descriptor is QMK's
  **console** descriptor (`06 31 FF …`), not raw HID. Same finding as
  `device-keychron-v1-stm32l432`, `device-tac-k1-wb32fq95` and
  `device-onekey-at32f415`.
- **No key on this build can emit anything.** `keymap_key_to_keycode` at
  `0x08000588` indexes `keymaps` at `0x0800A288` with `MATRIX_ROWS = 3`,
  `MATRIX_COLS = 3` and **one layer**, and those nine halfwords are all
  `0x0001` = `KC_TRANSPARENT`. Predicted statically before the first boot, and
  the attack tests it: switch 0 (`PB12`) held down for 20 s produces **zero**
  HID reports. `hid_keystroke_round_trip` is reported as its own boolean and
  `landed` does not depend on it.
- **The encoder half of the seam is real, and it is the strongest leg of the
  M4.** See below.
- The **DFU** half is present but unreachable: `bootloader_jump()` at
  `0x08006F3E` loads MSP/entry from the F0 system-memory ROM at `0x1FFFC800`,
  and its only caller is `QK_BOOT`, which no key maps to. The path is modelled
  and instrumented; it never fires in this build.

---

## M4 — the round trip, and the prediction it matched

`PROVENANCE.md` records the exact bytes, disassembled out of the image **before
the first boot**, and its commit is kept ahead of everything that can boot the
firmware so its timestamp proves it. The bracket, measured:

| | |
|---|---|
| `.git` created | 20:30:32 |
| prediction commit `674dcf2` (LICENSE + PROVENANCE.md + the extractor, and nothing else) | **20:33:48** |
| first bootable artifact anywhere (`configs/bdn9.bin`) | 20:42:03 |
| first emulator log | 20:42:19 |

so the prediction pre-dates **every** file capable of booting this firmware by
8 min 15 s, and every run log by 8 min 31 s. The commit is kept in the published
history; it was never squashed away. Live:

```
$ rehostry-bdn9-attack
[stage] preflight [ok]: tcp/27260 free on 0.0.0.0 and 127.0.0.1 (bind probe, no SO_REUSEADDR)
[stage] boot: QMK/ChibiOS on a rehosted STM32F072 (Cortex-M0) pid=98861
[stage] challenge [ok]: peer=HELLO device=rehostry-bdn9 pid=98861 nonce=…
[stage] bind-marker [ok]: 127.0.0.1:27260 pid=98861
[stage] enumerate [ok]: 13/13 static descriptors byte-identical to PROVENANCE.md
[stage] guest-derived [ok]: uid=… serial=…00000000
[stage] identity: vid_pid=cb10:2133  manufacturer=Keebio  product=BDN9 Rev. 2
[stage] class-round-trip [ok]: sent=0010110100011100 readback=0010110100011100
[stage] idle-round-trip [ok]: sent=0xd9 readback=d9
[stage] negative-control [ok]: GET_DESCRIPTOR(type=0x99) -> stall,
                               GET_DESCRIPTOR(string, index=7) -> stall
[stage] keystroke [ok, as predicted]: switch 0 (PB12) held 20s -> 3 frame(s),
                               0 carrying a keycode
[stage] encoder [ok]: plan=enc2-cw enc1-ccw enc1-cw enc0-ccw enc2-ccw enc0-cw
[stage]   enc2-cw : expected=ep1:00004e0000000000  observed=ep1:00004e0000000000  MATCH
[stage]   enc1-ccw: expected=ep1:0000520000000000  observed=ep1:0000520000000000  MATCH
[stage]   enc1-cw : expected=ep1:0000510000000000  observed=ep1:0000510000000000  MATCH
[stage]   enc0-ccw: expected=ep2:04ea00            observed=ep2:04ea00            MATCH
[stage]   enc2-ccw: expected=ep1:00004b0000000000  observed=ep1:00004b0000000000  MATCH
[stage]   enc0-cw : expected=ep2:04e900            observed=ep2:04e900            MATCH
[stage] console: the firmware's own printf on its console endpoint (EP3):
                 'USB configured.\n'
[stage] re-challenge [ok]: peer=IAM device=rehostry-bdn9 pid=98861 nonce=…
[stage] milestone: M4 (usb_round_trip=True)
RESULT: {"booted": true, "landed": true, "milestone": "M4",
         "usb_round_trip": true, "hid_keystroke_round_trip": false,
         "hid_encoder_report_round_trip": true,
         "raw_hid_via_interface_present": false}
```

Three consecutive runs on the shipped code landed `M4` with **zero** `UC_ERR`,
`Traceback` or `FETCH-DERAIL` in any of them, and with the firmware's own
`chSysHalt()` and `_unhandled_exception` intercepts never firing.

### Leg 1 — thirteen descriptors, byte for byte

Every one of `dev8 dev cfg9 cfg str0 str1 str2 hid0 hid1 hid2 rd0 rd1 rd2`
matched `PROVENANCE.md` §4b exactly, including the 84-byte configuration
descriptor and the 68- and 123-byte report descriptors. The host has no copy of
the image and cannot have synthesised them.

### Leg 2 — a value the guest COMPUTES, keyed to this run

There is no serial-number string in the image. `iSerialNumber = 3` is served by
the builder at `0x080073E4`, which memsets a 16-byte buffer, copies the three
UID words from `0x1FFFF7AC/B0/B4`, and hex-expands them through the firmware's
own `"0123456789ABCDEF"` table at `0x0800AFC0` into UTF-16LE, finishing with
`out[0] = 66` and `out[1] = 3`.

The attack picks **twelve fresh random bytes per spawn** and serves them as that
UID. The 66 bytes that come back are exactly `42 03` followed by the uppercase
hex of those bytes plus the trailing `"00000000"` the memset guarantees. A
descriptor replayed from any previous run fails.

### Leg 3 — a bidirectional class round trip

`usb_request_hook_cb` at `0x08006F60` handles the HID class requests. Sixteen
random bits go in as `SET_PROTOCOL(wValue=b, wIndex=0)` — which the inline
handler at `0x08006FD4` turns into `*(uint8_t *)0x20000C4A = (wValue != 0)` —
and come back out as `GET_PROTOCOL`, one bit at a time, reproducing the whole
nonce. A random byte goes in as `SET_IDLE` (`p[reportID][0] = duration << 2`,
through the driver vtable at `+16`) and comes back as `GET_IDLE`
(`(p[reportID][0] >> 2)`). Host-chosen input, stored by the guest's own handler
in guest RAM, returned over the guest's own EP0.

### Leg 4 — a physical input the firmware turns into a HID report

**This is the leg that makes the device a device.** The image has no matrix
scan at all: it uses QMK's `DIRECT_PINS`, and the reader at `0x0800221C` walks a
table of ChibiOS `ioline_t` values at `0x0800AE2C`, treating a pin that reads
**0** as pressed. The encoders are read the same way at `0x0800592C` from two
more tables. All fifteen words are re-verified by `tools/extract_firmware.py`:

| | recovered from the image |
|---|---|
| nine switches | `PB12 PB5 PB6 / PB14 PB4 PB7 / PA3 PF1 PF0` |
| encoder pad A | `PA4 PA15 PA9` |
| encoder pad B | `PA8 PB3 PA10` |

`encoder_update` at `0x080059CC` is QMK's, verbatim: it accumulates
`pulses += encoder_LUT[state]` from the sixteen-entry LUT at `0x0800AF6C`
(`{0,-1,1,0, 1,0,0,-1, -1,0,0,1, 0,1,-1,0}` — QMK's table exactly) and calls its
handler with `clockwise = false` on `pulses >= +4`, `true` on `pulses <= -4`.
`encoder_update_kb` at `0x08000548` then decides:

```
index 0:  clockwise ? 0xA9 (KC_AUDIO_VOL_UP) : 0xAA (KC_AUDIO_VOL_DOWN)
index 1:  clockwise ? 0x51 (KC_DOWN)         : 0x52 (KC_UP)
index 2:  clockwise ? 0x4E (KC_PGDN)         : 0x4B (KC_PGUP)
```

Measured, and byte-identical to that:

| rotation | endpoint | report | meaning |
|---|---|---|---|
| enc 0 cw | EP2 | `04 e9 00` | Consumer ID 4, usage `0x00E9` Volume Increment |
| enc 0 ccw | EP2 | `04 ea 00` | Consumer usage `0x00EA` Volume Decrement |
| enc 1 cw | EP1 | `00 00 51 00 00 00 00 00` | boot keyboard, `KC_DOWN` |
| enc 1 ccw | EP1 | `00 00 52 …` | `KC_UP` |
| enc 2 cw | EP1 | `00 00 4e …` | `KC_PGDN` |
| enc 2 ccw | EP1 | `00 00 4b …` | `KC_PGUP` |

each followed by its own all-zero release frame. The attack drives all six
(encoder, direction) pairs in a **random order chosen this run** and requires the
six reports back in that order, on the right endpoints — so a recording of any
previous run is the wrong sequence.

**Honesty note on provenance.** `PROVENANCE.md` predicted, before the boot, that
*keys* emit nothing. It said nothing about the encoders — the encoder path was
found *after* the first boot and the static derivation above was done
afterwards. It is therefore reported as **measured-then-derived**, not as a
pre-boot prediction, and legs 1–3 stand on their own without it.

### The in-run rejection controls

`get_usb_descriptor` (`0x08007444`) returns 0 with the pointer untouched for any
`wValue>>8` outside `{0x01, 0x02, 0x03, 0x21, 0x22}`, for `type=0x03` with
`index > 3`, and for `type=0x21/0x22` with `wIndex > 2`; the ChibiOS callback
then returns `NULL` and EP0 stalls. Both `GET_DESCRIPTOR(type=0x99)` and
`GET_DESCRIPTOR(string, index=7)` **STALL and leak zero bytes**. A mirror, an
echo or a credulous harness passes leg 1 and fails these.

---

## The controls

### Guest stall — the evidence really is guest-derived

`rehostry-bdn9-attack --control` runs the identical attack against an image
whose every halfword is `0xE7FE` (`b .`, the ARMv6-M self-branch). The host
stack is untouched: the peripheral models load, the bridge **binds and greets**,
the client connects and is authenticated, and every request is queued and
logged. And every firmware-side field goes false — no descriptors, no serial,
no nonce readback, no reports. `landed: false`.

The packaged image is never modified — the stalled copy is built in a temp
directory the run is spawned from — and the attack prints the packaged image's
sha256 before and after and gates a check on it being unchanged. Live:

```
$ rehostry-bdn9-attack --control
4928398d043e615ae3ea213c73da7b6e6d044215ee9d6d70a51e31fb2c56d6da   (image before)
[stage] preflight   [ok]  tcp/27260 free on both addresses
[stage] control           guest image replaced with 0xE7FE (`b .`) throughout
[stage] challenge   [ok]  peer=HELLO device=rehostry-bdn9 pid=99191 nonce=…
[stage] bind-marker [ok]  127.0.0.1:27260 pid=99191
[stage] enumerate  [FAIL] 0/13 static descriptors byte-identical
[stage] guest-derived [FAIL] serial=None
[stage] class-round-trip [FAIL] sent=1100100111011011 readback=????????????????
[stage] idle-round-trip  [FAIL] sent=0xf4 readback=(none)
[stage] negative-control [FAIL] both requests -> missing (nothing answered at all)
[stage] encoder    [FAIL] 0/6
[stage] re-challenge [ok] peer=IAM device=rehostry-bdn9 pid=99191 nonce=…
RESULT: {"control": true, "booted": false, "landed": false, "milestone": "M0"}
4928398d043e615ae3ea213c73da7b6e6d044215ee9d6d70a51e31fb2c56d6da   (image after)
```

Note what stays green: the port guard, the bind, the greeting and the
re-challenge. The host stack is demonstrably alive and answering throughout —
this is not "the run died", it is "the guest cannot execute and every
firmware-side field went false".

### Decoy — the attack refuses an impostor it did not start

`rehostry-bdn9-attack --decoy-selftest` stands up `tools_decoy.py`: **no
emulator, no firmware**, answering the exact line protocol, greeting with a
structurally perfect `HELLO device=rehostry-bdn9 pid=… nonce=…`, and replaying a
**genuine recorded enumeration** — every descriptor byte correct, serial string
included. Everything a credulous harness grades on, it answers correctly.

Two layers refuse it independently:

1. the pre-flight **bind** probe (both `0.0.0.0` and `127.0.0.1`, **no**
   `SO_REUSEADDR`) fails with `EADDRINUSE` before a byte is exchanged;
2. with the pre-flight disabled, the **identity challenge** refuses on its own —
   the decoy cannot produce this spawn's `pid` or its `nonce`, and the attack
   aborts before comparing a single descriptor.

Live:

```
$ rehostry-bdn9-attack --decoy-selftest
[stage] decoy: a no-emulator impostor now holds tcp/27260
[stage] preflight [FAIL]: tcp/27260 has a LISTENER that is not this attack's
                          guest ([Errno 48] on 0.0.0.0) -- refusing
[stage] decoy/layer-1 [ok]: landed=False
[stage] preflight [skipped]: --no-preflight: identity guard only
[stage] challenge [FAIL]: peer=HELLO device=rehostry-bdn9 pid=99346 nonce=…
[stage] decoy/layer-2 [ok]: landed=False
                            error=the peer on tcp/27260 is not this attack's guest
RESULT: {"decoy_refused": true, "landed": false}
```

The decoy's greeting is structurally perfect and its descriptors are real; what
it cannot produce is the **pid of a child this attack spawned** and the
**nonce this attack generated**. `landed` is gated on both, plus a grep of the
child's own log for its `BIND_OK` marker, plus a `WHOAMI`/`IAM` re-challenge
after all the traffic.

---

## Walls hit, and what they cost

### 1. The USB host must not touch EP0 while a `CTR` flag is pending

`CTR_RX`/`CTR_TX` are the device's *unserviced* transfer-complete flags, and
ChibiOS's ISR is `while (ISTR & CTR) { serve(ISTR & EP_ID); }` — with both set on
EP0 the reference manual makes `DIR` name the **OUT** one first. So a host that
takes an IN packet (setting `CTR_TX`) and then immediately sends the zero-length
status OUT (setting `CTR_RX`) makes the firmware service its **status stage
before the data-IN completion of the packet it just sent**, and ChibiOS then
arms the *next* chunk of the previous descriptor against the *next* SETUP.

Measured: `GET_DESCRIPTOR(configuration, 84)` came back as **20 bytes** —
`COUNT_TX = 20` on its *first* packet, which is bytes 64..83, the **tail** of
the descriptor with the head silently missing. `GET_DESCRIPTOR(report, 68)` lost
its head the same way. Nothing faults, nothing stalls, and the bytes that do come
back are genuine firmware bytes from the right descriptor — which is what makes
it dangerous. Two of the thirteen descriptors were quietly wrong while eleven
were perfect.

The fix is one guard, applied to every EP0 action: never act on an endpoint
whose `CTR` flags are still set.

### 2. The NMI must arrive alone — a wall six minutes deep

ChibiOS's ARMv6-M NMI handler is four instructions (`mrs r3, PSP; adds r3, #32;
msr PSP, r3; cpsie i; bx lr`): it discards **exactly one** stacked frame,
assuming the frame beneath is the thread context. On silicon that holds because
NMI outranks everything and a peripheral interrupt arriving mid-switch is
*tail-chained*, not stacked. Under a rehost nothing enforces it — the USB line
is drained from the backend's pending queue at whatever instruction the chunk
boundary lands on, and if that is inside `_port_exit_from_isr` the core stacks an
**extra** frame the NMI handler will never discard.

Nothing complains. Each occurrence leaks 32 bytes of the *current thread's*
stack, and a ChibiOS working area is a few hundred bytes. Measured: **six clean
minutes** — a complete enumeration, sixteen class round trips, a 20-second key
hold, all correct — and then `UC_ERR_WRITE_UNMAPPED` at `PC=0x00000008`, which is
the guest executing the *NMI vector word* as if it were code. A wall that only
arrives after everything visible already works is the expensive kind.

**Draining the queue at the window's entry is not enough**, which is the second
half of it. `chSchDoReschedule` calls `chVTGetSystemTimeX`, which **reads
TIM2->CNT** — and this device steps its USB host from exactly that read, because
a counter read is the cheapest "the guest is executing" signal it has. So the
queue is refilled a handful of instructions after it is drained. The entry
breakpoint therefore *inhibits* `usb_pump` from raising the line at all until
the NMI has been injected at the spin.

### 3. An inhibit that cannot expire is a deadlock waiting for an interleaving

The first version of that inhibit was a plain latch: set at one breakpoint,
cleared at another. One run then never came back to the closing breakpoint, the
line stayed withheld for ever, and the device went **permanently deaf with EP0's
`CTR_TX` stuck set** — no fault, no panic, the host politely timing out every
transfer against a firmware that had never been told a packet arrived. The
inhibit is now budgeted (`INHIBIT_BUDGET` pump calls) and the idle seam lifts it
unconditionally.

### 4. One exception at a time, on *every* line

The idle handler called `usb_pump.pump()` and then `qemu.inject_irq(15)` for
TIM2 without checking what the first call had already queued. Two entries in the
backend's pending list is a **nested** exception, not two interrupts. Measured:
`inject_irq(15): exc 31 … exc_return 0xfffffff1 … popped from MSP, resuming at
0x8008e00` — TIM2 delivered *inside* the USB ISR. The compare stays latched, so
the guard costs one idle visit and nothing else.

### 5. A pre-flight bind probe must tell `TIME_WAIT` from a listener

Omitting `SO_REUSEADDR` is what makes the probe catch a wildcard squatter — and
it is also what makes a socket left in `TIME_WAIT` by the *previous* run block
the bind for one 2×MSL window (~30 s on macOS) after everything has exited.
`lsof` shows nothing listening and the bind still fails on both addresses.
Measured here: two consecutive `M0` verdicts, seconds apart, on a device that
was working. A failed bind is now classified once with a connect — connect
succeeds means a real listener and the run refuses; connect refused means a
lingering socket and the probe waits it out.

### 6. `SET_IDLE` turns a correct keyboard into a phantom firmware bug

A non-zero HID idle rate is precisely an instruction to **re-send the current
report periodically**. Leg 3 of this attack sets one — a random byte, chosen per
run — so for the rest of the run a correct, provably inert keymap emits a stream
of **empty** boot-keyboard frames on EP1, entirely because the attack asked for
them.

The keystroke check counted *frames*. The same firmware therefore reported
between **0 and 16 "keystrokes"** across otherwise identical runs, depending on
the random idle byte: five runs split 3 × `M4` / 2 × `M3`, and the `M3`s looked
exactly like an intermittent firmware bug. It was an oracle bug. The check now
asks the question it means — *did a report carry a keycode* — and ignores
all-zero frames and the console endpoint entirely. (EP3 is QMK's console; an
early version counted `"USB configured.\n"` as three keystrokes.)

Two smaller versions of the same mistake were fixed alongside it: the client
must drain whatever is still in flight **before** clearing its report list, or a
report published during an earlier stage is parsed inside the measurement window
and attributed to it; and a `str.replace`-based patch that silently matched
nothing left the old check running for four runs while the new one sat
un-executed a few lines away.

### 7. A model written for a scanned matrix learns the RGB driver instead

The first GPIO model waited for a column to be driven low. On this firmware
nothing ever is — it uses `DIRECT_PINS` — and the only `BSRR` writer in an entire
boot is the **WS2812 bit-bang** at `0x08005A70`, an 8-bit loop of
`set; nops; clear; nops`, which a scan-shaped model happily mislearns as a
column being strobed. The pin tables were read out of the image instead.

### 8. Cortex-M0 has no VTOR

Flash is mapped at **both** `0x00000000` and `0x08000000`; every vector is
fetched from the low alias. `vector_base: 0x00000000` and nothing calls
`set_vtor()`.

---

## Known limitations

- **No keystroke → HID report, and it is a property of this build.** Proven
  statically (nine `KC_TRANSPARENT` halfwords, one layer) and tested live. A
  `keymaps/via` build of the same board would have both a real keymap and the
  raw-HID interface, and would be a strictly better fuzz target.
- **The encoder mapping is measured-then-derived, not predicted.** See the
  honesty note above.
- **Guest time is not calibrated.** The shared clock advances one 100 µs tick per
  `HAL_BDN9_MMIO_PER_TICK` (64) modelled MMIO accesses while the guest is busy,
  and jumps straight to the armed `TIM2->CCR1` compare at the idle seam. That
  makes elapsed-time behaviour correct in *order* but not in *rate*; nothing in
  this device's evidence depends on a wall-clock duration.
- **`gptPolledDelay` does not cost real time.** The one-pulse `UIF` is reported
  set on the start write. A rehost that actually spun would take hours to boot.
- **A full graded attack takes ~4 minutes**, most of it the six encoder legs at
  their 20 s settle each (`BDN9_INPUT_SETTLE`). Boot to enumeration is ~60–90 s
  on a quiet box with instrumentation off, dominated by the firmware's own
  1500 ms attach sleep expanded by the emulation ratio. Do not quote a figure
  measured under load or with `HAL_BDN9_*_TRACE` enabled.
- **The firmware's console line is reported, not graded.** `"USB configured.\n"`
  on EP3 is real firmware output and appears on every recent run, but it is a
  *static* string in the image, so it would survive a replay and is deliberately
  not part of `landed`.
- **TIM3 has a live vector (IRQ 16) and is modelled only as a polled one-shot.**
  Nothing in this build was observed to arm its interrupt; if a future build
  does, it will need the same treatment TIM2 has.
- **The USB host is a host for *this* device, not a USB stack.** No hub, no
  error recovery, no isochronous scheduling, no alternate settings, one
  configuration.

## Core changes

**None.** Bucket A. Nothing outside this device directory was modified except
this device's own row in `DEVICE-QUEUE.md`.

## Reproducing

```bash
python3 tools/extract_firmware.py --src /path/to/keebio_bdn9_rev2_w3adefault.bin
rehostry-bdn9-attack                    # the graded attack
rehostry-bdn9-attack --control          # the guest-stall falsification control
rehostry-bdn9-attack --decoy-selftest   # the impostor refusal
python -m pytest tests/                 # structural checks, no emulator needed
```
