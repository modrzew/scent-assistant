# Gizwits BLE Protocol — Reverse-Engineering Notes

Status: **unverified against real hardware**. Everything here was derived by
decompiling the `Scent Online` Android app (`com.scentonline.apps`,
v1.6.70 APKPure build) with `jadx`, and disassembling/decompiling its bundled
native library `libNativeCommandParser.so` (armeabi-v7a) with Ghidra
headless. No BLE traffic was captured from a live device. Treat every byte
offset below as a hypothesis to be confirmed by testing against a real
diffuser (e.g. an Airscent.au Tower Stream 2), not as ground truth.

Confidence markers used throughout:
- **[confirmed]** — read directly out of decompiled Kotlin/Java or Ghidra's
  decompilation of the native encoder/decoder; should be byte-accurate.
- **[inferred]** — a reasonable interpretation of confirmed code, but not
  independently exercised.
- **[unknown]** — named/typed in the product schema but never observed
  being encoded/decoded anywhere in the app; a real capture is needed.

---

## 1. Why this is a different protocol family

`Scent Online` is built on the **Gizwits IoT SDK**
(`com.gizwits.smart.sdk.*`), a Chinese IoT platform independent of Tuya. This
is unrelated to every protocol already implemented in this repo (Tuya BLE,
Aroma-Link, Scentiment, Scent Marketing AK/GW, Aromely). The underlying
hardware OEM is a diffuser line called **香愿 (Xiangyuan)** — the app ships
local product configs for six of their diffuser hardware/firmware
revisions.

## 2. GATT layer **[confirmed]**

Gizwits BLE has two protocol generations. Which one a given device speaks is
determined at scan time (see §5) — **check both against the real device
with `nRF Connect` or similar before assuming V5.**

| | Service | Characteristics |
|---|---|---|
| **V2** (legacy) | `0000ABF0-0000-1000-8000-00805f9b34fb` | `0000ABF7-...` — single combo read/write/notify channel |
| **V5** (current) | `0000ABD0-0000-1000-8000-00805f9b34fb` | Read `ABD4`, Write (with response) `ABD5`, Indicate `ABD6`, Write-no-response `ABD7`, Notify `ABD8` |

CCCD descriptor is the standard `00002902`.

The app's scanner (`GizBluetoothModuleFactory.initialize()`) filters on
these service UUIDs: `0000ABF8`, `0000ABF0` (V2 discovery + connect),
`0000F8AB`, `0000F0AB` (byte-order variants for older Android BLE stacks),
`0000ABD0`, `0000D0AB` (V5).

## 3. On-wire framing (V5) **[confirmed]**

Source: `BaseParserV5.parse()` / `.packOsBMiQA()` /
`BasePackParserV5` (decompiled Kotlin, not obfuscated further at the JVM
level — this part didn't need Ghidra).

```
byte0: sn  = byte0 & 0x1F        (5-bit sequence/session number)
       ver = (byte0 & 0x30) >> 4 (2-bit protocol sub-version)
byte1: cmd = byte1 & 0x7F
byte2: seq    = byte2 & 0x0F        (chunk index within this command, 0-based)
       frames = (byte2 & 0xF0) >> 4 (total chunk count - 1, i.e. last seq value)
byte3: length of THIS chunk's payload (0-255)
byte4+: payload chunk
```

Outgoing multi-chunk commands: split the payload into `mtu - 4`-byte
pieces (MTU defaults to 256 in the SDK, but the real BLE MTU after
negotiation will usually be smaller — 20 bytes minus 4 header bytes on an
unnegotiated link) and prefix each with the header above, `seq` counting
from 0.

Incoming notifications reassemble by matching `cmd`/`frames` across chunks
with consecutive `seq`, concatenating `payload`, until `seq >= frames`.
**No checksum** — Gizwits relies on GATT's own delivery guarantees.

Command bytes (V5), from `DeviceCommandConstantV5`:

| Value | Name | Direction |
|-------|------|-----------|
| 1 | `DEVICE_REPORT` | device → app, unsolicited state push |
| 2 | `APP_CTRL` | app → device, DP write **and** DP read-request |
| 3 | `DEVICE_REPLY` | device → app |
| 4 | `DEVICE_CTRL` | device → app? (rarely used in the app) |
| 5 | `APP_REPLY` | app → device (ack) |
| 8 | `APP_SEND_BLE_KEY` | app → device, login |
| 9 | `DEVICE_REPLY_BLE_KEY` | device → app, login result |
| 10 / 11 | `APP_BIND` / `DEVICE_REPLY_BIND` | binding handshake (not needed for local control) |
| 32-38 | OTA opcodes | firmware update, ignore |
| 64-66 | Wi-Fi provisioning opcodes | ignore for BLE-only control |

V2 uses an **entirely different, older opcode set**
(`DeviceCommandConstant`): `LOGIN_DEVICE=8`, `OLD_DATA_POINT=144`,
`NEW_DATA_POINT=147`, `CONNECTION_STATE=146`, etc. **[unknown]** how these
map onto V2's single ABF7 channel byte-for-byte — not decompiled in this
pass. If the real device turns out to speak V2 (advertises `0000ABF0`
instead of `0000ABD0`), this needs a follow-up RE pass.

## 4. Login / authentication **[confirmed mechanism, missing one input]**

Whether login is needed at all — and how hard it is — is **broadcast in
the device's own advertisement** (see §5). Three cases:

1. **`requiresAuthentication` = false** — connect and send `APP_CTRL` (cmd 2)
   writes directly, no login step. Simplest case, fully local.
2. **`requiresAuthentication` = true, method = `ONE_PRODUCT_KEY`** — the
   16-byte session key ("bleKey") is derived **offline**, no cloud call:
   ```python
   ble_key_hex = sha256(f"{product_key}+{mac.lower()}+{product_secret.lower()}")[:32]
   ble_key = bytes.fromhex(ble_key_hex)   # 16 raw bytes
   ```
   `product_key` is a 32-hex-char string (one of the six values in §7).
   **`product_secret` is the missing input** — it is not bundled in the
   APK. The app fetches it from Gizwits' cloud
   (`GizSDKManager.getConfiguration().getProductWithProductKey(key).getProductSecret()`)
   using the app's own API credentials, not a per-user account. It is
   *not* recoverable by static analysis of the client. Getting it
   requires either: a network capture of that one cloud lookup while
   running the real app, or asking a Gizwits/OEM contact, or (if the real
   device turns out to have `requiresAuthentication = false`) it's simply
   moot.
3. **method = `ONE_KEY`** — the app calls a Gizwits cloud endpoint
   (`OpenApi.getBleKey`) per-device. Fully cloud-dependent; out of scope
   for local control.

Handshake once a key is known:
```
app  -> cmd=8  payload = 16-byte bleKey
device -> cmd=9 payload[0] == 0x00  => success
```
Only after success does the device accept `APP_CTRL` writes. If the key is
wrong the device silently ignores subsequent writes (no error frame) —
this can look identical to "device unreachable" bugs, so it's worth
knowing about even when it's not immediately fixable.

## 5. Detecting the device + reading its login requirements from the advert

Source: `GizBluetoothModuleFactory`'s `ScanCallback.onScanResult()`.

The advertisement's Manufacturer-Specific-Data AD structure (AD type
`0xFF`) starts with a 2-byte "company ID"-shaped marker, then flag bytes:

```
raw AD payload (after the 0xFF type byte): [B0 B1] [B2] [B3] [4 bytes] [6 bytes] ...
                                             company   |    |   shot-     mac
                                             marker     |    |  product-
                                                        |    |    key
                                            bt-type-----+    |
                                                             +-- flags (see below)
```

- `B0, B1` — Android code checks `(B0<<8)|B1 == 15616 (0x3D00)`, i.e.
  `B0=0x3D, B1=0x00`. Per the Bluetooth spec, manufacturer-data company IDs
  are transmitted **LSB first**, so the actual company ID integer (the key
  bleak/HA report in `AdvertisementData.manufacturer_data`) is
  `B1<<8 | B0 = 0x003D = 61 decimal`. **[inferred — byte-order reasoning
  from the BT spec + this repo's existing manufacturer-ID constants being
  used unswapped; not independently verified against a live capture.]**
  Verify this against the real device's advertisement before trusting it;
  service-UUID detection (§2) is the safer primary signal.
- `B2` bits 4-7: BLE transport sub-type.
- `B3` bit 4 (`0x10`): **`requiresAuthentication`**.
- `B3` bit 5 (`0x20`): **auth method** — `0` = `ONE_PRODUCT_KEY`, `1` = `ONE_KEY`.
- `B3` bit 3 (`0x08`): supports OTA.
- next 4 bytes: "shot product key" — a truncated hash identifying which of
  the product configs (§7) applies; the app looks it up via
  `getProductWithShotProductKey(hex)`. We don't have the reverse mapping
  (hash → full product key) since that table lives in Gizwits' cloud, not
  the APK.
- next 6 bytes: device MAC.

**Practical takeaway:** service UUID `0000ABD0` (V5) or `0000ABF0` (V2) is
the reliable device-family signal. The manufacturer-data flags are a nice
bonus (tells you instantly whether login is even necessary) but decode them
defensively — confirm bit 4 of that 4th byte really flips between an
auth-required and auth-free device before trusting it blindly.

## 6. Data-point (DP) write format — the "var_len" / "variety" protocol **[confirmed]**

Source: Ghidra decompilation of `libNativeCommandParser.so`
(`GizWifiSDKEncodeBTData`, `GizWifiSDKEncodeSignleBT`, `GizWifiSDKEncode`,
`FUN_0001d250` — the var_len struct packer, resolved via Ghidra's
`Function.getThunkedFunction()` since the public symbols are thunks to
these).

### Outer BT envelope — `GizWifiSDKEncodeBTData(flag=1, ...)`
```
[0x72] [flag: 2 bytes big-endian]
```
`0x72` (ASCII 'r') is a fixed marker. `flag` is `0x0001` for every call
site observed (`dataPointPackControl` and `dataPointPackGetDeviceStataus`
both call it with `1`). Everything after this 3-byte header is one or more
tagged entries, concatenated.

### Tagged entry — `GizWifiSDKEncodeSignleBT`
```
[nameLen: 1 byte] [name: nameLen bytes, ASCII] [valueLen: 2 bytes big-endian] [value: valueLen bytes]
```
`name` is **not** a numeric DP id (unlike Tuya) — it's the literal entity
name string from the product config's `entities[0].name` field, which is
`"entity0"` in every one of the six bundled configs. In practice a single
write/read appears to carry exactly one tagged entry naming the one
entity, whose `value` blob packs whichever attributes you're setting.

### Inside `value` — `FUN_0001d250` (var_len struct packer)
```
[presence-bitmap: ceil(total_attr_count / 8) bytes]
[packed values, attribute-id order, only for attributes marked present]
```
- Presence bitmap: bit `id & 7` of byte `id >> 3` is set (`1 << (id & 7)`,
  LSB-first within each byte) when that attribute id is included in this
  write. `total_attr_count` is the schema's attribute count (45 for the
  two BLE-only configs — see §7), so the bitmap is 6 bytes for those.
- Per attribute, in ascending id order, only for attributes marked
  present:

  | `data_type` | Wire encoding |
  |---|---|
  | `bool` | 1 bit, packed contiguously (not byte-aligned) |
  | `enum` | `ceil(log2(num_options))` bits, contiguously packed |
  | `uint8` | 1 byte |
  | `uint16` | 2 bytes, big-endian |
  | `uint32` | 4 bytes, big-endian |
  | `binary` / string | raw bytes, **byte-aligned**, length = the attribute's declared byte length (JSON layer base64-encodes this for transport to the native lib; the *wire* bytes are raw, not base64) |

  Bit-packed fields (bool/enum) continue packing into the same bitstream
  across byte boundaries, in attribute-id order; byte-aligned fields
  (uint8/16/32/binary) each start at their own byte.

  **Important:** offsets are **not** the `position.byte_offset` /
  `bit_offset` fields baked into the bundled JSON configs — those are all
  zero placeholders. The real layout is computed fresh, at write time, by
  `FUN_0001ca20`, which walks *only the attributes included in this
  particular write* and lays out a minimal struct for just that subset.
  Both encode and decode sides must agree on which attributes are present
  (via the presence bitmap) to reconstruct the same offsets — you can't
  precompute a fixed struct offset table per attribute independent of
  which other attributes are in the same call.

There is a second packer, `FUN_0001cd50`, used for products whose
`protocolType` is *not* `var_len` (a fixed byte/bit-offset struct format
instead) — irrelevant here since every product config we found for this
line declares `"protocolType": "var_len"`.

### Read requests
`GetDeviceStatusParserV5.pack()` calls a *different* native entry point
(`GizCommandParser.encodeReadDataPoint`, backed by
`GizWifiSDKEncodeGetStatus`) that was **not decompiled in this pass**
**[unknown]**. It's cmd 2 (`APP_CTRL`) just like a write, so devices may
simply be told the same way, or (more likely, given typical Gizwits
behaviour on other transports) push full state unsolicited after connect +
login as a `DEVICE_REPORT` (cmd 1) — in which case an explicit read may not
even be necessary. Needs confirming against real hardware.

### Response parsing
`GizWifiSDKDecode` is a general P0-frame decoder shared with Gizwits' Wi-Fi
transport and branches on a leading marker byte (`0x06`, `0x55`, `0x16`
seen in the disassembly) that doesn't obviously match the BT-write marker
`0x72` — **[unknown]** whether `DEVICE_REPORT` pushes reuse the
`0x72`-tagged layout on the way back or a different one of those markers.
Needs a live capture or further static work to pin down.

## 7. Product / attribute schema

Six product configs are bundled at
`assets/productConfig/*.json` inside the APK (paths given relative to the
extracted xapk), one per hardware/firmware revision of the same OEM
diffuser line. All use `protocolType: "var_len"`, `packetVersion:
0x00000004`, single entity `entities[0].name == "entity0"`.

| `product_key` | Config `name` | Attr count |
|---|---|---|
| `8b6a4a9bdd5a43b1a9ba5aadff82f85a` | 香愿香薰机 | 23 |
| `c79041f7731b4a4f889d52c5ec9598c0` | 香愿香薰机_V2 | 35 |
| `1821608aedc14675a9f81d281ac53df1` | 香愿香熏机V3_3 | 45 |
| `fbd8e831fc644362a1447176a541426c` | 香愿香熏机V3 | 45 |
| `4eb9228ec0db400e9794ffaa2deb2365` | 香愿香熏机_BLE | 45 |
| `611806df39ca4e2695f6c4a5334e4bbe` | 香愿香熏机_BLE_V1_1 | 45 |
| `2d2077b01327432db867d77323f45100` | 香愿香薰机V5 | 170 |

We don't have a way to map a specific physical unit (e.g. "Airscent.au
Tower Stream 2") to one of these rows without either the advertisement's
"shot product key" hash (§5) or a live capture. The two `_BLE` configs are
identical in schema and are the most likely match for a Bluetooth-only
product; the 170-attribute `V5` config supports up to **10 independent
scent cartridges/pumps** plus light/motion sensors and integrated audio
controls, and would be the match if the real unit turns out to be a
multi-cartridge "tower" hub rather than a single-cartridge desktop diffuser.

### The 45-attribute `_BLE` / `_BLE_V1_1` schema (identical in both)

`id` is the attribute's position in the JSON `attrs` array — this is what
gets bit-tested in the presence bitmap and determines packing order.

| id | name | type | len | writable | notes |
|----|------|------|-----|----------|-------|
| 0 | devLifting | bool | 1 bit | rw | cartridge stand lift up/down |
| 1 | recoverySet | bool | 1 bit | rw | factory reset |
| 2 | **onOff** | bool | 1 bit | rw | **power** |
| 3 | **fanOnOff** | bool | 1 bit | rw | **fan** |
| 4 | lcd_Switch | bool | 1 bit | rw | display on/off |
| 5 | ledPower | bool | 1 bit | rw | LED on/off |
| 6 | ledFollowPump | bool | 1 bit | rw | LED follows pump cycle |
| 7 | devEnergyStatus | uint8 | 1 byte | rw | |
| 8 | devBattery | uint8 | 1 byte | ro | battery % |
| 9 | devMode | uint8 | 1 byte | rw | device mode |
| 10 | oilQuantity | uint8 | 1 byte | ro | fragrance level % |
| 11 | group_manage_datapoint | uint8 | 1 byte | rw | |
| 12 | oilDepthMode | uint8 | 1 byte | rw | fragrance concentration mode |
| 13 | CurPLGears | uint8 | 1 byte | rw | current intensity/gear level |
| 14 | blePasswordEnable | uint8 | 1 byte | rw | local BLE password lock enable |
| 15 | sharePasswordEnable | uint8 | 1 byte | rw | guest-access password enable |
| 16 | oilResetting | uint8 | 1 byte | rw | reset oil % counter |
| 17 | ledBrightness | uint8 | 1 byte | rw | |
| 18 | ledMode | uint8 | 1 byte | rw | |
| 19 | ledSpeed | uint8 | 1 byte | rw | |
| 20 | TermOfValidity_mon | uint8 | 1 byte | ro | oil expiry month |
| 21 | oilType | uint16 | 2 bytes | ro | |
| 22 | devType | uint16 | 2 bytes | ro | device model code |
| 23 | OilCapacity | uint16 | 2 bytes | rw | |
| 24 | TermOfValidity_year | uint16 | 2 bytes | ro | oil expiry year |
| 25 | devTime | binary | 8 bytes | rw | time sync — internal layout **[unknown]** |
| 26 | devRunStatus | binary | 14 bytes | ro | live status block — internal layout **[unknown]** |
| 27 | blePassword | binary | 8 bytes | rw | |
| 28 | sharePassword | binary | 8 bytes | rw | |
| 29-35 | PL_SetTime1..7 | binary | 8 bytes each | rw | one weekly schedule slot per weekday — internal layout **[unknown]** |
| 36-42 | PE_SetTime1..7 | binary | 11 bytes each | rw | a second, richer per-weekday schedule — internal layout **[unknown]** |
| 43 | ledRGB | binary | 3 bytes | rw | presumably R,G,B — order **[unknown]** |
| 44 | OilName | binary | 50 bytes | rw | fragrance name string |

For the 8/11-byte `PL_SetTime`/`PE_SetTime` and the 3-byte `ledRGB`, we
know the *outer* type (binary, N bytes) but never saw code that parses
their *internal* fields — no decompiled evidence for where
hour/minute/work/pause/day-mask sit inside those blobs. Do not assume they
mirror the Aroma-Link or ShinePick internal schedule layouts; that would be
guessing, not reverse-engineering. This needs either a live capture or a
further disassembly pass specifically hunting for code that touches these
attribute names.

## 8. Recommended next step

Everything in §2-§6 is directly testable without a packet capture: connect,
check which GATT service is present, try the login-free `APP_CTRL` power
write and see what happens. Getting the schedule/RGB internals and
confirming the login requirement will need either a live BLE capture (HCI
snoop + the real app) or the missing `productSecret` from Gizwits/the OEM.
