<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Registered predictions — written BEFORE the assertions that read them

Registered against the inventory in `INVENTORY.md`. Each entry says what the
firmware **must** do and where that expectation comes from.

Sources, strongest first:

- **ATTACKER-CHOSEN** — the harness picks the value at run time, so the correct
  answer differs every run and no recorded output can satisfy it.
- **SPEC** — fixed by USB 2.0 or HID 1.11. Known before the guest ever ran.
- **IMAGE-DERIVED** — fixed by a byte in the guest's own descriptor, read from
  the guest this run, so the expectation is *computed from the device's own
  declaration* rather than hard-coded.

None of these is taken from a previous run's output.

---

## The per-interface obligation table (IMAGE-DERIVED)

The harness parses the CONFIGURATION descriptor the guest returned and, **for
each interface it finds**, derives that interface's obligations from that
interface's own declared bytes:

| declared | obligation | source |
|---|---|---|
| `bInterfaceSubClass == 1` | `GET_PROTOCOL`/`SET_PROTOCOL` at that `wIndex` must be **honoured** | HID 1.11 §7.2.5-7.2.6 |
| `bInterfaceSubClass == 0` | `GET_PROTOCOL` at that `wIndex` must **STALL** | HID 1.11 §7.2.5 |
| `wDescriptorLength = N` in that interface's HID descriptor | `GET_DESCRIPTOR(REPORT, wIndex=i)` must return exactly **N** bytes | HID 1.11 §7.1.1 |
| every interface | `SET_IDLE`/`GET_IDLE` at that `wIndex` is addressed to *that* interface | HID 1.11 §7.2.3-7.2.4 |

Nothing in that table is a constant this package chose. For this image it
resolves to: interface 0 honours protocol requests and returns 68 report-
descriptor bytes; interfaces 1 and 2 stall protocol requests and return 123 and
21 bytes. Change the image and the table follows it.

## Entry: interface 0 — boot keyboard, EP `0x81`

1. **Report descriptor** (IMAGE-DERIVED): exactly 68 bytes, matching
   `PROVENANCE.md` §4b byte for byte.
2. **`SET_PROTOCOL` / `GET_PROTOCOL` round trip** (ATTACKER-CHOSEN): sixteen
   random bits are written one at a time as `SET_PROTOCOL(wValue=b, wIndex=0)`
   and read back with `GET_PROTOCOL(wIndex=0)`. **All sixteen must match.**
   This is the Rule-2 conjunct for this interface: an interface that answers
   once and then repeats its last valid answer fails at the first bit flip.
   Honoured **because** this interface declares subclass 1.
3. **Encoder reports** (ATTACKER-CHOSEN order): encoders 1 and 2, in a random
   permutation chosen this run, must produce their four *distinct* 8-byte boot
   keyboard reports on endpoint `0x81`, in the order the host asked for.

## Entry: interface 1 — QMK shared, EP `0x82`

1. **Report descriptor** (IMAGE-DERIVED): exactly 123 bytes.
2. **`GET_PROTOCOL(wIndex=1)` must STALL** (SPEC + IMAGE-DERIVED), because this
   interface declares subclass 0. This is the per-interface discrimination: the
   *same* request that interface 0 honours must be refused here.
3. **Encoder reports** (ATTACKER-CHOSEN order): encoder 0, the volume knob, must
   produce Consumer-Control reports on endpoint `0x82` — report ID 4, usage
   `0xE9` Volume Increment clockwise and `0xEA` Volume Decrement
   counter-clockwise (HID Usage Tables §15) — and these must appear on `0x82`,
   **not** on `0x81`.

## Entry: interface 2 — QMK console, EP `0x83`

1. **Report descriptor** (IMAGE-DERIVED): exactly 21 bytes, declaring vendor
   usage page `0xFF31`.
2. **`GET_PROTOCOL(wIndex=2)` must STALL** (SPEC + IMAGE-DERIVED), subclass 0.
3. **`SET_IDLE` / `GET_IDLE` round trip** (ATTACKER-CHOSEN): a random non-zero
   byte written as `SET_IDLE(wValue=byte<<8, wIndex=2)` must come back from
   `GET_IDLE(wIndex=2)`. This is interface 2's round trip, and it is made on the
   **control** pipe because the image has no OUT endpoint — stated in
   `INVENTORY.md` before the run.
4. **The firmware's own `printf`** on endpoint `0x83`.

## M5 — the isolation conjunct

Interface state must be **per-interface, not global**. Two interfaces are given
**different** attacker-chosen idle bytes in the same run and both must read back
their own value:

```
SET_IDLE(a, wIndex=0)   SET_IDLE(b, wIndex=2)   with a != b, both random
GET_IDLE(wIndex=0) == a       GET_IDLE(wIndex=2) == b
```

A single global store returns the same byte for both and fails. Then the two are
**swapped** and re-read, so a harness that merely recorded the first answer also
fails.

## M6 — stateful behaviour

Two independent state axes, both predicted from the spec:

1. **Protocol state, sixteen times** — `GET_PROTOCOL(wIndex=0)` is the *same
   request* throughout; the answer must differ according to the `SET_PROTOCOL`
   that preceded it, for sixteen attacker-chosen bits.
2. **Idle state, swapped** — the same `GET_IDLE(wIndex=i)` must return one value
   before the swap and a different, equally correct value after it.

## M7 — adversarial tolerance

Each of these must be **refused**, and none may leak a byte:

| stimulus | required response | source |
|---|---|---|
| `GET_DESCRIPTOR(type=0x99)` | STALL, 0 bytes | no such descriptor type |
| `GET_DESCRIPTOR(STRING, index=7)` | STALL, 0 bytes | only indices 0-3 exist |
| `GET_PROTOCOL(wIndex=9)` | STALL, 0 bytes | no interface 9 is declared |
| `bRequest = 0x99` on the class interface | STALL, 0 bytes | undefined request |
| class request with recipient = *other* (`bmRequestType 0xA3`) | STALL, 0 bytes | USB 2.0 §9.3.1 |
| `GET_DESCRIPTOR(DEVICE, wLength=0)` | STALL, 0 bytes | zero-length data stage |
| `GET_STATUS` on endpoint `0x09` | STALL, 0 bytes | no such endpoint |

And one that must **not** be refused, and must not over-read — the bounds check:

| stimulus | required response |
|---|---|
| `GET_DESCRIPTOR(DEVICE, wLength=255)` | exactly **18** bytes, the true descriptor length, not 255 |

Returning 255 bytes here would be a buffer over-read. Returning 18 is USB 2.0
§9.3.5 behaviour: the device sends the shorter of `wLength` and the descriptor.

**The conjunct that makes it M7 rather than a list of stalls:** after every one
of the above has been sent, known-good traffic must still work on **all three
interfaces** — the device descriptor still byte-identical to the prediction, a
fresh attacker-chosen protocol round trip on interface 0, and fresh
attacker-chosen idle round trips on interfaces 0 and 2.

## Registered NEGATIVE predictions — expected to FAIL

- **`SET_IDLE`/`GET_IDLE` on interface 1 does not store.** Interface 1 returns
  `0x00` for any value written. This is recorded here, before the run, so that
  the result is a prediction met rather than an excuse. Interface 1's round trip
  is therefore carried by its encoder reports on `0x82` and its 123-byte report
  descriptor, and **not** by an idle round trip; it is graded on what it does
  do, and the thing it does not do is named.
- **A key press emits nothing.** `PROVENANCE.md` §3b: the keymap is nine
  `KC_TRANSPARENT` halfwords, so holding switch 0 must produce no keycode. This
  is a predicted *negative* and remains one.
