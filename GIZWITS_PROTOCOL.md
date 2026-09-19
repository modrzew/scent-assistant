# Gizwits BLE Protocol — "XPG-GAgent" diffusers (Scent Online app)

Status: **verified against real hardware** on 2026-09-19. Every byte in §1–§7
was sent to / received from a physical diffuser advertising as
`XPG-GAgent-d97c` using `gizwits_ble.py` (repo root, `uv run gizwits_ble.py
--help`). That script is the reference implementation; if this document and
the script ever disagree, the script wins.

The earlier version of this document (derived only from decompiling the
Android app + its native library) got several things wrong. Do **not** trust
the Gizwits code currently in `custom_components/scent_assistant/` (commits
`dfaa9b7..b1ce739`) — it was written against that earlier document and never
worked. Concretely it uses the wrong product schema (45 attributes instead of
35), inverts the LOGIN result polarity, ignores the `0x0091` report channel
the device actually uses, and wraps DP payloads in a `0x72` "entity tag"
envelope the device never sees. §9 lists the differences.

Anything *not* verified is confined to §10 (other product models, the V5
transport) and is clearly marked.

---

## 0. Quick reference

```
Identify   adv service UUID 0000ABF0 + manufacturer records "06 <MAC>" and
           "10 <16-byte product key> 01 <flags>"; local name "XPG-GAgent-xxxx"
GATT       service 0000ABF0-0000-1000-8000-00805f9b34fb
           char    0000ABF7-0000-1000-8000-00805f9b34fb  (write-without-response | notify)
Frame      00 00 00 03 | LEN varint | 00 | CMD u16 BE | BODY      (LEN counts from the 00 flag byte)
Auth       TX 0000000303000006                       BIND
           RX 000000030f000007 000a 4f46534449485357524f   -> passcode "OFSDIHSWRO"
           TX 000000030f000008 000a 4f46534449485357524f   LOGIN(passcode)
           RX 0000000304000009 00                          -> 0x00 = success
Read all   TX 000000030d000093 00000000 12 ffffffffff      NEW_DATA_POINT sn=0, P0 READ, all attrs
           RX 00000003c6010000 94 00000000 13 ffffffffff <191-byte values>  (arrives in 20-byte chunks)
Write      TX 000000030e000093 00000000 11 0000000008 01   fanOnOff=1
           RX 0000000307000094 00000000                    ack (empty P0)
           RX 000000030a000091 14 0000000008 01            report: fanOnOff changed to 1
```

Product key `c79041f7731b4a4f889d52c5ec9598c0` → schema in §6 (35 attributes,
5-byte presence bitmap). Power = `onOff` (id 2), fan = `fanOnOff` (id 3),
intensity = `CurPLGears` (id 12, 1–20), mode = `devMode` (id 7), oil level =
`oilQuantity` (id 8, %).

---

## 1. Identifying the device (advertisement)

Verified advertisement of the test unit (bleak on macOS):

```
local name        XPG-GAgent-d97c
service UUIDs     ['0000abf0-0000-1000-8000-00805f9b34fb']
manufacturer data {0x8c06: bfea41d97c10c79041f7731b4a4f889d52c5ec9598c00101}
```

The device is a Gizwits **"GAgent" BLE module, protocol generation V2**
(the app's `GizProtocolVersionEnum.V2`). The name suffix is the last two MAC
bytes.

### 1.1 Manufacturer-specific data

The device transmits **two** manufacturer-specific AD structures (type
`0xFF`), one in the advertising PDU and one in the scan response. Their raw
payloads (after the AD length/type bytes) are:

```
record A (7 bytes):   06 | 8c bf ea 41 d9 7c
                      ^    ^-- BLE MAC, 8c:bf:ea:41:d9:7c
                      +------- tag 0x06

record B (19 bytes):  10 | c7 90 41 f7 73 1b 4a 4f 88 9d 52 c5 ec 95 98 c0 | 01 | 01
                      ^    ^-- product key (16 raw bytes, hex = the config file name)   ^    ^-- flags
                      +------- product-key length (0x10 = 16)                           +------- flags length (1)
```

`flags` bits (from the app's scanner, `GizBluetoothModuleFactory`):

| bit | meaning | test unit |
|-----|---------|-----------|
| 0 | `0` = configured, `1` = not configured (Wi-Fi provisioning state; irrelevant for BLE) | 1 → not configured |
| 1 | `0` = **authentication required**, `1` = no authentication | 0 → **auth required** |

Everything else in the byte is unused. Note the inverted sense of both bits.

### 1.2 How BLE stacks present these records — parse defensively

Bluetooth stacks split each manufacturer record into a 2-byte little-endian
"company ID" plus data, and how the two records are delivered differs:

* **CoreBluetooth (macOS)** concatenates both records into one blob:
  key `0x8c06` (= LE of `06 8c`), data = the remaining 24 bytes.
* **BlueZ / HA / ESPHome proxies** typically deliver them as two dict entries
  (advertisement and scan response merged): key `0x8c06` with 5 bytes of data
  (`bfea41d97c`) and key `0xc710` (= LE of `10 c7`) with 17 bytes
  (`9041f7...98c0 01 01`). The "company IDs" are therefore **meaningless and
  device-specific** (they are just the first two bytes of each record —
  the MAC's first byte and the product key's first byte leak into them).
  Never match on the company ID.

Robust parser: for every `(company_id, data)` entry, reconstruct
`raw = company_id.to_bytes(2, "little") + data`, then walk `raw`:

```
i = 0
while i < len(raw):
    if raw[i] == 0x06 and i + 7 <= len(raw):            # MAC record
        mac = raw[i+1:i+7]; i += 7
    elif raw[i] == 0x10 and i + 19 <= len(raw) and raw[i+17] == 0x01:
        product_key = raw[i+1:i+17].hex(); flags = raw[i+18]; i += 19
    else:
        break
```

(`gizwits_ble.parse_gizwits_adv`). Because the two records arrive in
different packets, a scan callback can fire with only the MAC record present;
keep scanning until the product key has been seen (it appears within a few
hundred ms).

The **service UUID `0000ABF0`** is the reliable family signal; the app also
scans for `0000ABF8`, `0000F8AB`, `0000F0AB` (V2 byte-order variants) and
`0000ABD0`/`0000D0AB` (V5, see §10).

### 1.3 What to persist per device

* BLE address (the OS handle) and the MAC from record A (they are the same
  thing on Linux; on macOS the address is a CoreBluetooth UUID).
* `product_key` — selects the data-point schema (§6). Different product keys
  have **different, incompatible** schemas; don't hard-code one.
* `requires_auth` flag.
* Optionally the `passcode` obtained by BIND (§4) — it is stable, so LOGIN can
  be sent directly on reconnect.

---

## 2. GATT layer

```
Service          0000ABF0-0000-1000-8000-00805f9b34fb
Characteristic   0000ABF7-0000-1000-8000-00805f9b34fb   properties: write-without-response, notify
CCCD             00002902-0000-1000-8000-00805f9b34fb   (standard; enable notifications)
```

One characteristic carries both directions. Verified connection sequence:

1. Connect. (bleak on macOS negotiated MTU 515; the Android app requests
   MTU 515 for V2 and then falls back to whatever it gets.)
2. Enable notifications on `ABF7` (write `01 00` to its CCCD / `start_notify`).
   The earlier HA attempt saw transient GATT error 133 on `start_notify`
   right after connecting through an ESPHome proxy — retry with a short
   backoff, it is a transport hiccup, not protocol.
3. Authenticate (§4). Nothing else works before this.
4. Read/write data points (§5).

Writes are **write-without-response** (the characteristic has no `write`
property). The app serialises writes with a mutex and sleeps 100 ms after each
packet; the device answered every command within ~100 ms in testing.

### 2.1 Chunking

There is **no per-chunk header** in either direction. A packet (§3) is simply
split at the ATT payload size and written piece by piece; the receiver
reassembles by reading the `LEN` field of the first bytes.

* **RX**: the device always notifies in **20-byte chunks regardless of MTU**
  (observed with MTU 515: the 204-byte read reply arrived as 10 × 20 + 4
  bytes). Reassembly across notifications is mandatory.
* **TX**: verified that a 26-byte packet written as 20 + 6 bytes
  (`--chunk 20`) is reassembled and acted on by the device, and that whole
  packets ≤ MTU work too. Splitting at `mtu - 3` (or a flat 20 for an
  unnegotiated link) is safe.

---

## 3. Transport framing (Gizwits "LAN protocol" over BLE)

V2 reuses Gizwits' classic Wi-Fi-module LAN packet format on the single
characteristic:

```
offset  size  field
0       4     header, always 00 00 00 03
4       1–2   LEN  — unsigned varint: 7 bits per byte, LSB group first, bit 7 = "more bytes follow"
              counts every byte AFTER the varint (flag + cmd + body)
+0      1     flag, always 00 in every packet seen (both directions)
+1      2     CMD, big-endian
+3      n     BODY (command-specific, may be empty)
```

Encoder / decoder (`gizwits_ble.build_packet`, `FrameBuffer`):

```python
def varint(n):                       # 0..127 -> 1 byte, 128..16383 -> 2 bytes
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def build_packet(cmd, body=b"", flag=0):
    inner = bytes([flag]) + cmd.to_bytes(2, "big") + body
    return b"\x00\x00\x00\x03" + varint(len(inner)) + inner
```

Receive side: append every notification to a buffer; while the buffer holds
≥ 5 bytes, check for the header, decode the varint, and pop one packet once
`4 + varint_len + LEN` bytes are present. Examples of LEN encoding seen on the
wire: `03` (3), `0f` (15), `15` (21), `c6 01` (0x46 + (1 << 7) = 198).

### 3.1 Command set

| CMD | direction | name (SDK `DeviceCommandConstant`) | body | status |
|-----|-----------|------------------------------------|------|--------|
| `0x0006` | app → dev | `BIND_DEVICE` | empty | **verified** |
| `0x0007` | dev → app | bind reply | `[u16 BE len][passcode ASCII]` | **verified** |
| `0x0008` | app → dev | `LOGIN_DEVICE` | `[u16 BE len][passcode ASCII]` | **verified** |
| `0x0009` | dev → app | login reply | `[u8 result]`, `0x00` = success | **verified** |
| `0x0093` | app → dev | `NEW_DATA_POINT` | `[u32 BE sn][P0]` | **verified** |
| `0x0094` | dev → app | reply to `0x0093` | `[u32 BE sn][P0]` — P0 empty = write ack | **verified** |
| `0x0091` | dev → app | unsolicited data-point report | `[P0]` (no sn) | **verified** |
| `0x0090` | app → dev | `OLD_DATA_POINT` (no sn) | `[P0]` | not used, not tested |
| `0x0013`/`0x0014` | app → dev / reply | `READ_DEVICE_INFO` | firmware/module versions | not tested |
| `0x0001`, `0x0003`, `0x0005`, `0x0019`, `0x0062`–`0x0064`, `0x0092`, `0x010d` | — | Wi-Fi provisioning / discovery / connection state / reset | — | not relevant for BLE control |

The device **only ever sent** `0x0007`, `0x0009`, `0x0091`, `0x0094` during
testing. Treat any other incoming CMD as "log and ignore".

---

## 4. Authentication

**Login is mandatory and enforced.** Before a successful LOGIN the device
silently drops every `0x0093` — no reply at all (verified with
`--no-auth`), which looks exactly like a dead link. The advertisement's
`requires_auth` flag (§1.1) said so too. Nothing in the flow needs the cloud,
the app's "product secret", or any per-user account: the device hands out its
own passcode.

### 4.1 BIND_DEVICE → passcode

```
TX  00 00 00 03 | 03 | 00 | 00 06
RX  00 00 00 03 | 0f | 00 | 00 07 | 00 0a | 4f 46 53 44 49 48 53 57 52 4f
                                    ^len=10  ^"OFSDIHSWRO"
```

The passcode is a 10-character upper-case ASCII string. It was **identical on
every connection** (6+ sessions), so it can be cached and BIND skipped
(verified: `LOGIN` with the cached passcode straight after connecting works).
The Android app nevertheless does BIND+LOGIN on every connection — doing the
same costs one extra round trip (~50 ms) and self-heals if the passcode ever
changes (e.g. after a factory reset via `recoverySet`).

### 4.2 LOGIN_DEVICE

```
TX  00 00 00 03 | 0f | 00 | 00 08 | 00 0a | 4f 46 53 44 49 48 53 57 52 4f
RX  00 00 00 03 | 04 | 00 | 00 09 | 00
```

Result byte: **`0x00` = success** (the app's `LoginDeviceResponseCommand
.isLoginSuccess()` is `loginResult == 0`). Non-zero = failure. The earlier
document/code had this inverted.

Quirk: the device often sends the `0x0009` reply **twice** — once
immediately and once again ~100 ms later, sometimes interleaved with the
reply to the next command. Ignore duplicates; do not treat a stray `0x0009`
as an error.

### 4.3 Session lifetime

Login state is per BLE connection. Reconnecting requires logging in again.
There is no keep-alive/ping requirement over BLE: the LAN protocol's
`0x0015/0x0016` ping was never sent, and the device held a completely idle
connection for 150 s (test duration) without dropping it.

---

## 5. Data points — the P0 payload

All state lives in "data points" (attributes) of the product schema (§6).
They travel inside the body of `0x0093` / `0x0094` / `0x0091` as a **P0
payload**:

```
P0 = [action u8] [presence bitmap] [packed values]
```

| action | name | direction | packed values |
|--------|------|-----------|---------------|
| `0x11` | WRITE | app → dev | the attributes being written |
| `0x12` | READ | app → dev | none — bitmap selects what to read (`FF FF FF FF FF` = everything) |
| `0x13` | READ reply | dev → app | every requested attribute |
| `0x14` | REPORT | dev → app | attributes that changed (unsolicited, `0x0091`) |

(`0x01`–`0x04` are the same four actions for Gizwits' *fixed-length*
products; this product line is `protocolType: "var_len"` and uses `0x1x`.)

### 5.1 Presence bitmap

`ceil(attr_count / 8)` bytes — **5 bytes** for the 35-attribute schema.
The bitmap is **big-endian**: attribute id 0 is bit 0 of the **last** byte.

```
byte index = bitmap_len - 1 - (id >> 3)
bit        = id & 7
```

Verified examples (5-byte bitmaps):

| attrs | bitmap |
|-------|--------|
| onOff (2) | `00 00 00 00 04` |
| fanOnOff (3) | `00 00 00 00 08` |
| fanOnOff (3) + CurPLGears (12) | `00 00 00 10 08` |
| devTime (17) | `00 00 02 00 00` |
| devRunStatus (18) | `00 00 04 00 00` |
| CurPLGears (12) + PL_SetTime1 (21) | `00 00 20 10 00` |
| PL_SetTime7 (27) | `00 08 00 00 00` |
| all | `ff ff ff ff ff` |

### 5.2 Packed values

Only attributes whose bit is set are present, in **ascending id order**, laid
out as:

1. **Bit-packed region** — all present `bool` (1 bit) and `enum`
   attributes, packed LSB-first into `ceil(total_bits / 8)` bytes. (`enum`
   width is `ceil(log2(option_count))` bits according to the decompiled
   native packer; this schema has no enum attribute, so that part is
   unverified.) **Omitted entirely when no bool/enum is
   present** (verified: the CurPLGears+PL_SetTime1 report has no bitfield
   byte).
2. **Byte-aligned region** — the remaining present attributes in id order:
   `uint8` = 1 byte, `uint16` = 2 bytes BE, `uint32` = 4 bytes BE,
   `binary` = exactly its declared byte length.

Numeric attributes with a `uint_spec` (`ratio`, `addition`) are transported as
`raw = (value - addition) / ratio`; every attribute in this schema has
`ratio 1, addition 0`.

Worked example — the 35-attribute read reply (`0x13`, bitmap all ones):

```
13 ff ff ff ff ff            action + bitmap
14                           bit region: 0b00010100 -> devLifting=0 recoverySet=0 onOff=1 fanOnOff=0 lcd_Switch=1
00 00 02 64 00 0a 02 01 00 00 00     11 × uint8: devEnergyStatus=0 devBattery=0 devMode=2 oilQuantity=100
                                     group_manage_datapoint=0 devType=10 oilDepthMode=2 CurPLGears=1
                                     blePasswordEnable=0 sharePasswordEnable=0 oilResetting=0
00 00                        oilType (uint16) = 0
14 17 05 06 0c 08 2e 06      devTime      (8)
01 01 00 0a 02 58 09 00 15 00 00 00 02 58   devRunStatus (14)
00 00 00 00 05 4c 56 38      blePassword  (8)
00 00 00 00 05 4c 56 38      sharePassword(8)
01 01 7f 09 00 15 00 01      PL_SetTime1  (8)   ... PL_SetTime2..7 (8 each)
01 00 0a 02 58 7f 09 00 15 00 01   PE_SetTime1 (11) ... PE_SetTime2..7 (11 each)
```

Total 1 + 5 + 1 + 11 + 2 + 8 + 14 + 8 + 8 + 7×8 + 7×11 = **191 bytes**.

Encoder/decoder: `gizwits_ble.encode_p0` / `decode_p0` (schema-driven,
~40 lines each).

### 5.3 Reading

```
TX  0x0093  [sn u32 BE] 12 ff ff ff ff ff
RX  0x0094  [same sn]   13 ff ff ff ff ff <191 bytes>
```

A partial read (bitmap with only some bits) is allowed by the format but was
not tested; reading everything is a 204-byte reply and takes ~100 ms, so just read
all.

**The read reply is served from the Gizwits module's cache of the last values
the MCU reported, not from a fresh query of the MCU.** This is visible on
`devTime`: a read returned a clock value 5 minutes stale, and ~200 ms after
every read the MCU pushed a `0x0091` report with the current time (§5.5).
For everything that matters (switches, gear, oil level) the cache is kept
current by the MCU's own reports, so the reply is trustworthy — but after a
read, keep consuming the reports that follow it.

`sn` is a free-running counter chosen by the app (the Android SDK starts at 0
and increments per request; wraps are fine). The device echoes it, so replies
can be matched to requests. Unsolicited `0x0091` reports have no sn.

### 5.4 Writing

```
TX  0x0093  [sn] 11 <bitmap> <values>
RX  0x0094  [same sn]                       <- ack: body is ONLY the sn, P0 empty
RX  0x0091  14 <bitmap> <values>            <- one or more reports of what changed
```

Verified writes (all acked, all read back as expected):

| command | TX packet |
|---------|-----------|
| fanOnOff = 1 | `00000003 0e 00 0093 00000000 11 0000000008 01` |
| fanOnOff = 0 | `00000003 0e 00 0093 00000000 11 0000000008 00` |
| onOff = 0 | `00000003 0e 00 0093 00000000 11 0000000004 00` |
| onOff = 1 | `00000003 0e 00 0093 00000000 11 0000000004 01` |
| fanOnOff = 0, CurPLGears = 2 | `00000003 0f 00 0093 00000000 11 0000001008 00 02` |
| PL_SetTime7 = `07107f0000000000` | `00000003 15 00 0093 00000000 11 0008000000 07107f0000000000` |

Raw frames for `fanOnOff = 1`, exactly as notified:

```
TX 000000030e0000930000000011000000000801
RX 000000030700009400000000              ack, sn 0, no P0
RX 000000030a00009114000000000801        report 0x14, bitmap 0000000008, bit byte 01
```

The ack always came first (within ~50 ms), reports followed within ~100 ms.
The reports are the authoritative new state — a write that the device
rejects would presumably be acked without a matching report (not observed;
every tested write was accepted).

Side-effects observed (the device reports them, so a state cache that applies
every `0x14` report stays correct automatically):

* Writing `CurPLGears` → reports `CurPLGears` **and** `PL_SetTime1` (the
  gear is copied into the currently active PL slot) **and** `devRunStatus`.
* Writing `onOff=1` → reports `onOff`, then `devRunStatus` (work/pause
  countdown restarted).
* Writing any `PL_SetTime*` → reports `devRunStatus`.

### 5.5 Unsolicited reports

`0x0091` / `0x14` reports carry whatever the MCU decides to report. Observed
triggers:

* **After every READ and after LOGIN**: one `devTime` report (current
  clock) ~200 ms later. This is the only "spontaneous" traffic seen; it is
  not timer-driven — a 150 s idle connection produced nothing at all.
* **After every WRITE**: the written attribute(s) plus dependent ones
  (§5.4).
* Presumably when the user presses physical buttons or a schedule
  phase changes — not observed during testing (no `devRunStatus` report
  arrived over 150 s idle even though the schedule window was active), so
  do not rely on the device to announce its own phase transitions.

Practical model: read everything once after login and apply every report;
re-read (cheap, ~100 ms) whenever fresh `devRunStatus`/`devTime` is
needed. There is no harm in reading periodically — nothing beeps or
blinks.

---

## 6. Product schema `c79041f7731b4a4f889d52c5ec9598c0` ("香愿香薰机_V2")

Source: `assets/productConfig/c79041f7731b4a4f889d52c5ec9598c0.json` inside
the Scent Online APK (`protocolType: var_len`, `packetVersion 0x00000004`,
one entity `entity0`). The `desc` strings there (translated below) document
the binary layouts — all of them checked against live data.

`id` is the attribute's index in the config's `attrs` array and is what the
presence bitmap and packing order use. `rw` = `status_writable`, `ro` =
`status_readonly`.

| id | name | type | size | rw | meaning / values | observed |
|----|------|------|------|----|------------------|----------|
| 0 | `devLifting` | bool | 1 bit | rw | cartridge platform lift: 1 = up, 0 = down | 0 |
| 1 | `recoverySet` | bool | 1 bit | rw | 1 = factory reset (write-only trigger) | 0 |
| 2 | **`onOff`** | bool | 1 bit | rw | **power**: 1 = on, 0 = off | 1 |
| 3 | **`fanOnOff`** | bool | 1 bit | rw | **fan**: 1 = on | 0 |
| 4 | `lcd_Switch` | bool | 1 bit | rw | display: 1 = on | 1 |
| 5 | `devEnergyStatus` | uint8 | 1 | rw | 0 = sport(运动), 1 = comfort(舒适), 2 = eco(节能) | 0 |
| 6 | `devBattery` | uint8 | 1 | ro | battery % (0 on this mains-powered unit) | 0 |
| 7 | **`devMode`** | uint8 | 1 | rw | **1 = PL "gear" mode, 2 = PE "engineering" (work/pause seconds) mode** | 2 |
| 8 | **`oilQuantity`** | uint8 | 1 | ro | **oil remaining %** | 100 |
| 9 | `group_manage_datapoint` | uint8 | 1 | rw | request group: 1 = work status, 2 = system time, 3 = PL times, 4 = PE times, 5 = oil check (purpose unclear; likely tells the MCU which group to (re)report) | 0 |
| 10 | `devType` | uint8 | 1 | ro | model: 1 = SBW150S, 2 = SBW500M, 3 = SBW1000L, 4 = SBW1000H (test unit reports 10 — undocumented) | 10 |
| 11 | `oilDepthMode` | uint8 | 1 | rw | concentration: 1 = low, 2 = medium, 3 = high | 2 |
| 12 | **`CurPLGears`** | uint8 | 1 | rw | **current PL intensity gear, 1–20** | 1 |
| 13 | `blePasswordEnable` | uint8 | 1 | rw | 1 = require local BLE password | 0 |
| 14 | `sharePasswordEnable` | uint8 | 1 | rw | 1 = require share password | 0 |
| 15 | `oilResetting` | uint8 | 1 | rw | write 0–100 to reset the oil % counter | 0 |
| 16 | `oilType` | uint16 | 2 | ro | 0 = non-system oil / user defined | 0 |
| 17 | `devTime` | binary | 8 | rw | device clock, §6.1 | 2023-05-06 12:08:46 (not synced) |
| 18 | `devRunStatus` | binary | 14 | ro | live run status, §6.2 | |
| 19 | `blePassword` | binary | 8 | rw | local BLE password as **uint64 BE** (default 88888888 = `00000000054c5638`), §6.3 | 88888888 |
| 20 | `sharePassword` | binary | 8 | rw | share password, same encoding | 88888888 |
| 21–27 | `PL_SetTime1`..`7` | binary | 8 | rw | PL schedule slots 1–7, §6.4 | slot 1 enabled 09:00–21:00 gear 1 |
| 28–34 | `PE_SetTime1`..`7` | binary | 11 | rw | PE schedule slots 1–7, §6.5 | slot 1 enabled 09:00–21:00 10 s / 600 s |

There is no separate "spray now / phase" attribute; spraying is governed by
`onOff` + `devMode` + the active schedule slot, and `devRunStatus` exposes
the live countdown.

### 6.1 `devTime` (8 bytes)

```
[0] year / 100   [1] year % 100   [2] month   [3] day   [4] hour   [5] min   [6] sec   [7] weekday 1=Mon..7=Sun
14 17 05 06 0c 08 2e 06   ->  2023-05-06 12:08:46, Saturday
```

The year is two *decimal* bytes (20, 23), not a uint16. Writable, so the
clock can be set (the app presumably does this; not tested — it's the only
way the schedules can run at the right wall-clock time).

### 6.2 `devRunStatus` (14 bytes, read-only)

```
[0]     current schedule slot (1–7)
[1]     current PL gear (1–20)
[2:4]   u16 BE  work-phase length, seconds
[4:6]   u16 BE  pause-phase length, seconds
[6],[7] active window start hour, minute
[8],[9] active window end hour, minute
[10:12] u16 BE  seconds left in the current work phase
[12:14] u16 BE  seconds left in the current pause phase
01 01 00 0a 02 58 09 00 15 00 00 0a 02 58  ->  slot 1, gear 1, 10 s on / 600 s off, 09:00–21:00, work 10 s left, pause 600 s left
```

Bytes 10–13 are the countdown of the current phase **as of the MCU's last
report**, not a live counter: reads 15 s apart returned identical values
(`0000 0258`), a report after a write showed a mid-phase value (`00a4` =
164 s), and `onOff=1` resets both to the phase lengths. Treat them as
"remaining at last report".

### 6.3 `blePassword` / `sharePassword` (8 bytes)

The numeric password as an unsigned 64-bit big-endian integer:
`00 00 00 00 05 4c 56 38` = 0x054C5638 = **88888888** (the factory default
per the config). Only relevant if `blePasswordEnable` is set; on the test
unit it is 0 and login (§4) needed no password.

### 6.4 `PL_SetTime1..7` (8 bytes each) — "gear" schedule

```
[0] slot number (1–7, matches the attribute)   [1] PL gear 1–20
[2] weekday mask, bit0 = Monday … bit6 = Sunday (0x7f = every day)
[3],[4] start hour, minute   [5],[6] end hour, minute   [7] enabled 0/1
01 01 7f 09 00 15 00 01  -> slot 1, gear 1, every day, 09:00–21:00, enabled
02 10 7f 00 00 00 00 00  -> slot 2, gear 16, every day, 00:00–00:00, disabled (factory default for unused slots)
```

### 6.5 `PE_SetTime1..7` (11 bytes each) — "work/pause seconds" schedule

```
[0] slot number   [1:3] u16 BE work seconds (0–999)   [3:5] u16 BE pause seconds (10–999)
[5] weekday mask   [6],[7] start h, m   [8],[9] end h, m   [10] enabled 0/1
01 00 0a 02 58 7f 09 00 15 00 01  -> slot 1, 10 s on / 600 s off, every day, 09:00–21:00, enabled
02 00 0a 00 5a 7f 00 00 00 00 00  -> slot 2, 10 s / 90 s, disabled (factory default)
```

Which of PL/PE applies is selected by `devMode` (1 = PL, 2 = PE). Writing a
whole 8/11-byte slot at once is the only way to change a schedule (there are
no per-field attributes); verified with a no-op rewrite of `PL_SetTime7`.

---

## 7. Captured session (test vectors)

Complete first session, as logged by `gizwits_ble.py status`. Use these to
unit-test framing, reassembly and the codec without hardware.

```
TX 0000000303000006
RX 000000030f000007000a4f46534449485357524f              20 bytes, one notification
TX 000000030f000008000a4f46534449485357524f
RX 000000030400000900
TX 000000030d0000930000000012ffffffffff
RX 000000030400000900                                    duplicate login reply (ignore)
RX 00000003c6010000940000000013ffffffffff14              read reply, notification 1/11
RX 00000264000a02010000000000141705060c082e              2/11
RX 060101000a025809001500000002580000000005              3/11
RX 4c563800000000054c563801017f090015000102              4/11
RX 107f000000000003107f000000000004107f0000              5/11
RX 00000005107f000000000006107f000000000007              6/11
RX 107f000000000001000a02587f09001500010200              7/11
RX 0a005a7f000000000003000a005a7f0000000000              8/11
RX 04000a005a7f000000000005000a005a7f000000              9/11
RX 000006000a005a7f000000000007000a005a7f00              10/11
RX 00000000                                              11/11
```

Reassembled read reply body (after `00 0094`):

```
00000000 13 ffffffffff 14 00000264000a02010000000000 141705060c082e06
0101000a0258090015000000025800000000054c563800000000054c5638
01017f0900150001 02107f0000000000 03107f0000000000 04107f0000000000
05107f0000000000 06107f0000000000 07107f0000000000
01000a02587f0900150001 02000a005a7f0000000000 03000a005a7f0000000000
04000a005a7f0000000000 05000a005a7f0000000000 06000a005a7f0000000000
07000a005a7f0000000000
```

Decoded: see the "observed" column of §6 (`onOff=1 fanOnOff=0 lcd_Switch=1
devMode=2 oilQuantity=100 devType=10 oilDepthMode=2 CurPLGears=1 …`).

Write session (`set CurPLGears=2 fanOnOff=0`):

```
TX 000000030f000093000000001100000010080002
RX 0000000307000094 00000000                                    ack
RX 000000031200009114 0000201000 02 01027f0900150001            report CurPLGears=2, PL_SetTime1 gear→2
RX 000000031700009114 0000040000 0102000a025809001500000a0258   report devRunStatus
TX 000000030d0000930000000112ffffffffff                          read back (sn=1)
RX 00000003c601000094 00000001 13 ffffffffff 14 ...             CurPLGears=2 confirmed
```

Report pushed ~200 ms after a read (fresh clock; the read reply itself
carried a stale `devTime`):

```
RX 000000031100009114 0000020000 141705060c173506               devTime = 2023-05-06 12:23:53 Sat
```

---

## 8. Recommended control flow (protocol level)

```
scan          match service ABF0; parse adv → mac, product_key, requires_auth
connect       enable notify on ABF7 (retry on GATT 133)
auth          BIND → passcode (or reuse cached) ; LOGIN → expect 0x0009 00
              on failure/timeout: retry once after 500 ms, then reconnect
sync          0x0093 sn 12 FF×5  → 0x0094 sn 13 …  → full state
control       0x0093 sn 11 bitmap values → wait for 0x0094 with same sn (ack)
              → state comes from the 0x0091 reports that follow
idle          keep the connection (no keep-alive needed); apply every 0x0091 report;
              re-read on demand — the device does not announce phase changes on its own
timeouts      3 s per reply is generous (replies arrive in ≤ 100 ms)
```

Requests are strictly sequential in the app (mutex + 100 ms gap); the device
was never observed to need more, but don't pipeline writes.

---

## 9. What the current addon code gets wrong (for whoever fixes it)

`custom_components/scent_assistant/{const,protocol_ble,device}.py` as of
`b1ce739`:

1. **Schema**: `GIZWITS_BLE_SCHEMA` is the 45-attribute `_BLE` config
   (6-byte bitmap, `onOff` id 2 but `CurPLGears` id 13, `devBattery` id 8…).
   The real device uses the 35-attribute schema in §6 (5-byte bitmap,
   `CurPLGears` id 12, `oilQuantity` id 8, `devMode` id 7). Every write
   after the bool block was landing on the wrong attribute and the bitmap
   was one byte too long. Select the schema by product key.
2. **Login polarity**: `_parse_packet` sets `login_complete = payload[0] != 0`;
   success is `== 0`.
3. **Report channel**: replies with cmd `0x0091` (no sn) are discarded; that
   is where all state changes arrive. `0x0094` with an empty P0 is an ack,
   not an error.
4. **Advertisement parsing**: `extract_gizwits_metadata` handles the
   BlueZ-style split records (16/19-byte) but not the 7-byte MAC record or
   the CoreBluetooth concatenated form, and doesn't surface the product key
   as the schema selector. The V5 `0x3D00` manufacturer-ID path is
   irrelevant for this device.
5. **`0x72` entity envelope / `GIZ_BT_MARKER`**: not part of the wire
   format for this device; the P0 goes straight after the sn.
6. The framing (`_giz_v2_build_packet`, `_feed_v2`) and the bitmap byte
   order are correct and can be kept.

---

## 10. Not verified — other models and the V5 transport

Everything in this section comes only from the decompiled app and has **not**
been exercised against hardware. Keep it out of the critical path.

### 10.1 Other product keys

The APK bundles six `var_len` product configs for the same OEM line
(香愿 / Xiangyuan). Only the second one is verified. A device advertising a
different key needs its config's attribute list before any DP can be
encoded — the ids, counts and bitmap widths differ.

| product key | config name | attrs | bitmap bytes |
|-------------|-------------|-------|--------------|
| `8b6a4a9bdd5a43b1a9ba5aadff82f85a` | 香愿香薰机 | 23 | 3 |
| **`c79041f7731b4a4f889d52c5ec9598c0`** | **香愿香薰机_V2 (this document)** | **35** | **5** |
| `1821608aedc14675a9f81d281ac53df1` | 香愿香熏机V3_3 | 45 | 6 |
| `fbd8e831fc644362a1447176a541426c` | 香愿香熏机V3 | 45 | 6 |
| `4eb9228ec0db400e9794ffaa2deb2365` | 香愿香熏机_BLE | 45 | 6 |
| `611806df39ca4e2695f6c4a5334e4bbe` | 香愿香熏机_BLE_V1_1 | 45 | 6 |
| `2d2077b01327432db867d77323f45100` | 香愿香薰机V5 | 170 | 22 |

The 45-attribute configs share the V2 attribute names but insert
`ledPower`/`ledFollowPump` bools, `ledBrightness/Mode/Speed`, `TermOfValidity_*`,
`OilCapacity`, `ledRGB`, `OilName`; ids shift accordingly. The 170-attribute
V5 config is a 10-cartridge hub. The transport (§2–§5) is expected to be
identical for all V2 devices since it is implemented by the Gizwits module,
not the OEM MCU.

### 10.2 V5 transport (service `0000ABD0`)

Newer Gizwits modules advertise manufacturer data starting `3d 00` and use
service `0000ABD0` with separate characteristics (`ABD4` read, `ABD5` write,
`ABD6` indicate, `ABD7` write-no-response, `ABD8` notify) and a per-chunk
header `[sn|ver][cmd][seq|frames][len][payload]` with cmd 2 = APP_CTRL,
3 = DEVICE_REPLY, 1 = DEVICE_REPORT, 8/9 = bleKey login (16-byte key derived
from `sha256(product_key + "+" + mac + "+" + product_secret)`, which needs a
cloud-only `product_secret`). None of this applies to `XPG-GAgent` V2
devices and none of it has been tested. The earlier revision of this file in
git history (`git show b1ce739:GIZWITS_PROTOCOL.md`) has the full
decompilation notes if a V5 device ever shows up.

### 10.3 Open questions on the verified device

* `devType = 10` is not in the config's model list.
* Semantics of `group_manage_datapoint`, `devEnergyStatus` and
  `oilResetting` writes were not exercised.
* Whether a rejected write (e.g. `CurPLGears = 0`) produces an error or is
  silently ignored.
* Behaviour when `blePasswordEnable = 1` (whether LOGIN still succeeds with
  the BIND passcode alone).
* Whether the MCU ever reports `devRunStatus` / button presses on its own
  (nothing arrived in 150 s idle; only write- and read-triggered reports
  were seen). If it doesn't, live phase state needs periodic reads.
