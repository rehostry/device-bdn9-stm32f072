<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Interface inventory — registered before any per-interface assertion exists

## Provenance: the firmware's own CONFIGURATION descriptor

This inventory is **not** the set of things `attack.py` happens to drive, and it
is not derived from the handlers in `peripheral_models/`. Deriving it that way
would make parity `|I_pass| = |I_impl|`, a predicate maximised by implementing
*less* — a rehost that modelled nothing would score a perfect 0 = 0.

It is **parsed at run time, by the harness, out of the CONFIGURATION descriptor
the guest itself returns.** The USB configuration descriptor is precisely a
device's published statement of the interfaces it offers: a host has no other way
to learn them, and the device cannot offer an interface it does not declare
there. It lives in the firmware image at `0x0800AFFF`, so it does not shrink when
we implement fewer handlers — drop a handler and the interface is still declared,
still enumerated by this parser, and still fails its assertion.

`GET_DESCRIPTOR(CONFIGURATION)` returns 84 bytes with `bNumInterfaces = 3`:

```
iface 0   class 3 (HID)  subclass 1 (BOOT)  protocol 1 (keyboard)
          report descriptor 68 bytes        endpoint 0x81 IN, 8 bytes
iface 1   class 3 (HID)  subclass 0         protocol 0
          report descriptor 123 bytes       endpoint 0x82 IN, 32 bytes
iface 2   class 3 (HID)  subclass 0         protocol 0
          report descriptor 21 bytes        endpoint 0x83 IN, 32 bytes
```

**|inventory| = 3.**

The parse is done by the harness from the returned bytes, not read from a table
in this package, so an interface added to or removed from the image changes the
inventory automatically. `PROVENANCE.md` §4b records the same 84 bytes as a
pre-boot prediction, which is an independent corroboration written before this
work and for a different purpose.

## Why these three are independent interfaces, not one counted three times

This is the question M5 exists to catch, so it is answered explicitly rather
than assumed.

| | iface 0 | iface 1 | iface 2 |
|---|---|---|---|
| what it is | boot keyboard | QMK "shared" (mouse / system / consumer) | QMK console |
| subclass | **1 (boot)** | 0 | 0 |
| report descriptor | 68 bytes | 123 bytes | 21 bytes |
| usage page | `0x01` generic desktop | `0x01` + `0x0C` consumer | **`0xFF31` vendor** |
| IN endpoint | `0x81`, 8 bytes | `0x82`, 32 bytes | `0x83`, 32 bytes |
| report format | 8-byte boot keyboard | report-ID-prefixed, 3 bytes | 32-byte text |
| class state | addressed by `wIndex = 0` | `wIndex = 1` | `wIndex = 2` |

The decisive property is the **subclass byte**, because the HID 1.11
specification attaches *different obligations* to it. `Get_Protocol` and
`Set_Protocol` (§7.2.5, §7.2.6) are defined **only for boot-subclass
interfaces**. Interface 0 declares subclass 1 and must therefore answer them;
interfaces 1 and 2 declare subclass 0 and must therefore **stall** them.

That gives a per-interface discrimination that a single shared handler cannot
fake: the *same* control request, differing only in `wIndex`, must be **honoured
on one interface and refused on the other two**, and which is which is fixed by a
byte in the descriptor the guest itself emitted. A device with one global class
handler answers all three, or stalls all three, and fails either way.

## Scope notes, stated now rather than after the results

- **There is no VIA / raw-HID interface, and none is claimed.** `PROVENANCE.md`
  §3a establishes that the image contains no OUT endpoint at all and that the
  usage page `0xFF60` a QMK raw-HID interface must declare does not occur. The
  queue row that promised one was wrong about this build. Interface 2 is QMK's
  **console** (`0xFF31`), not raw HID.
- **Interface 2 is device-to-host only.** With no OUT endpoint anywhere in the
  image, its `0x83` pipe cannot carry a request. Its round trip is therefore
  necessarily made on the **control** pipe addressed to interface 2
  (`wIndex = 2`), not on `0x83`. `0x83` is separately shown carrying the
  firmware's own `printf`. This is stated here, before the results, rather than
  being presented afterwards as though a bidirectional interrupt pipe had been
  exercised.
- **All three share the USB transport and one enumeration.** They are
  independent *interfaces*, not independent *buses*. Breaking the USB device
  peripheral would break all three at once. That is equally true of the modes on
  `device-bpv5`, which all ride one console, and the claim is scoped the same
  way.

## Registered predictions

Per-interface expected bytes are registered in `PREDICTIONS.md`, written in the
same change as this file and **before** any assertion that reads them.
