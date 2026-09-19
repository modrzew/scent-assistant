"""Offline Gizwits BLE V2 regression checks; run with unittest, without HA
or bleak installed.

Test vectors are taken verbatim from GIZWITS_PROTOCOL.md (captured against
real hardware advertising as XPG-GAgent-d97c, product key
c79041f7731b4a4f889d52c5ec9598c0, 2026-09-19). Where a test asserts a value,
that value can be found in the protocol doc's §1, §5, §6 or §7 — this file
exists to catch a divergence between the doc and the implementation, so
tests should be checked against the doc, not against whatever the code
currently does.
"""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "_scent_protocol_test"
package = ModuleType(PACKAGE)
package.__path__ = [str(ROOT / "custom_components/scent_assistant")]
sys.modules[PACKAGE] = package


def load_module(name):
    fullname = f"{PACKAGE}.{name}"
    spec = importlib.util.spec_from_file_location(
        fullname, ROOT / "custom_components/scent_assistant" / f"{name}.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = module
    spec.loader.exec_module(module)
    return module


const = load_module("const")
protocol = load_module("protocol_ble")


def advertisement(service_uuids=None, manufacturer_data=None):
    return SimpleNamespace(
        service_uuids=service_uuids or [],
        manufacturer_data=manufacturer_data or {},
    )


class VarintTests(unittest.TestCase):
    def test_encode_matches_doc_examples(self):
        # GIZWITS_PROTOCOL.md §3: "03" (3), "0f" (15), "15" (21),
        # "c6 01" (0x46 + (1 << 7) = 198).
        self.assertEqual(protocol._giz_varint_encode(3), bytes.fromhex("03"))
        self.assertEqual(protocol._giz_varint_encode(15), bytes.fromhex("0f"))
        self.assertEqual(protocol._giz_varint_encode(21), bytes.fromhex("15"))
        self.assertEqual(protocol._giz_varint_encode(198), bytes.fromhex("c601"))

    def test_round_trip(self):
        for n in (0, 1, 127, 128, 198, 16383, 16384):
            encoded = protocol._giz_varint_encode(n)
            decoded = protocol._giz_varint_decode(encoded + b"\xAA", 0)
            self.assertEqual(decoded, (n, len(encoded)))

    def test_incomplete_varint_returns_none(self):
        self.assertIsNone(protocol._giz_varint_decode(bytes.fromhex("c6"), 0))


class FrameTests(unittest.TestCase):
    def test_build_bind_matches_doc(self):
        self.assertEqual(
            protocol._giz_build_packet(const.GIZ_CMD_BIND),
            bytes.fromhex("0000000303000006"),
        )

    def test_build_login_matches_doc(self):
        passcode = b"OFSDIHSWRO"
        body = len(passcode).to_bytes(2, "big") + passcode
        pkt = protocol._giz_build_packet(const.GIZ_CMD_LOGIN, body)
        self.assertEqual(pkt, bytes.fromhex("000000030f000008000a4f46534449485357524f"))

    def test_build_query_matches_doc_quick_reference(self):
        p = protocol.GizwitsBleProtocol()
        self.assertEqual(p.build_query(), bytes.fromhex("000000030d0000930000000012ffffffffff"))

    def test_build_fan_on_matches_doc(self):
        p = protocol.GizwitsBleProtocol()
        self.assertEqual(p.build_fan(True), bytes.fromhex("000000030e0000930000000011000000000801"))

    def test_wire_chunks_no_header_flat_20_bytes(self):
        p = protocol.GizwitsBleProtocol()
        frame = bytes(range(26))
        chunks = p.wire_chunks(frame)
        self.assertEqual(chunks, [frame[:20], frame[20:]])
        self.assertEqual(b"".join(chunks), frame)


class BitmapEncodeTests(unittest.TestCase):
    """GIZWITS_PROTOCOL.md §5.1's presence-bitmap table, verified live."""

    def _bitmap(self, values):
        return protocol._gizwits_encode_entity(const.GIZWITS_SCHEMA, values)[:5].hex()

    def test_onoff(self):
        self.assertEqual(self._bitmap({"onOff": True}), "0000000004")

    def test_fanonoff(self):
        self.assertEqual(self._bitmap({"fanOnOff": True}), "0000000008")

    def test_fanonoff_plus_curplgears(self):
        self.assertEqual(
            self._bitmap({"fanOnOff": True, "CurPLGears": 1}), "0000001008",
        )

    def test_devtime(self):
        self.assertEqual(self._bitmap({"devTime": bytes(8)}), "0000020000")

    def test_devrunstatus(self):
        self.assertEqual(self._bitmap({"devRunStatus": bytes(14)}), "0000040000")

    def test_curplgears_plus_pl_settime1_no_bitfield_byte(self):
        # No bool attribute present -> the bit-packed region is omitted
        # entirely (GIZWITS_PROTOCOL.md §5.2).
        blob = protocol._gizwits_encode_entity(
            const.GIZWITS_SCHEMA, {"CurPLGears": 1, "PL_SetTime1": bytes(8)},
        )
        self.assertEqual(blob[:5].hex(), "0000201000")
        self.assertEqual(len(blob), 5 + 1 + 8)  # bitmap + CurPLGears + PL_SetTime1, no bitfield byte

    def test_pl_settime7(self):
        self.assertEqual(self._bitmap({"PL_SetTime7": bytes(8)}), "0008000000")


class EntityCodecTests(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        values = {
            "onOff": True, "fanOnOff": False, "lcd_Switch": True,
            "devMode": 2, "oilQuantity": 100, "CurPLGears": 1,
        }
        blob = protocol._gizwits_encode_entity(const.GIZWITS_SCHEMA, values)
        decoded = protocol._gizwits_decode_entity(const.GIZWITS_SCHEMA, blob)
        for key, value in values.items():
            self.assertEqual(decoded[key], value)

    def test_full_read_reply_matches_doc_5_2(self):
        # GIZWITS_PROTOCOL.md §5.2/§7's reassembled read-reply body (sn +
        # action + bitmap + values); slice off sn(4) and action(1) to get
        # the bitmap+values blob `_gizwits_decode_entity` expects.
        reassembled_body = bytes.fromhex(
            "00000000" "13" "ffffffffff" "14"
            "00000264000a02010000000000" "141705060c082e06"
            "0101000a0258090015000000025800000000054c563800000000054c5638"
            "01017f0900150001" "02107f0000000000" "03107f0000000000"
            "04107f0000000000" "05107f0000000000" "06107f0000000000"
            "07107f0000000000"
            "01000a02587f0900150001" "02000a005a7f0000000000"
            "03000a005a7f0000000000" "04000a005a7f0000000000"
            "05000a005a7f0000000000" "06000a005a7f0000000000"
            "07000a005a7f0000000000"
        )
        self.assertEqual(reassembled_body[4], 0x13)  # action byte = READ_REPLY
        blob = reassembled_body[5:]  # drop sn(4) + action(1); bitmap+values remain
        decoded = protocol._gizwits_decode_entity(const.GIZWITS_SCHEMA, blob)
        self.assertEqual(decoded["onOff"], True)
        self.assertEqual(decoded["fanOnOff"], False)
        self.assertEqual(decoded["lcd_Switch"], True)
        self.assertEqual(decoded["devMode"], 2)
        self.assertEqual(decoded["oilQuantity"], 100)
        self.assertEqual(decoded["CurPLGears"], 1)
        self.assertEqual(decoded["devType"], 10)
        self.assertEqual(decoded["oilDepthMode"], 2)


class NotificationParsingTests(unittest.TestCase):
    def test_bind_reply_and_login_success(self):
        p = protocol.GizwitsBleProtocol()
        self.assertEqual(
            p.parse_notification(bytes.fromhex("000000030f000007000a4f46534449485357524f")),
            {},
        )
        self.assertTrue(p.passcode_received)
        self.assertEqual(
            p.build_login(),
            bytes.fromhex("000000030f000008000a4f46534449485357524f"),
        )
        p.parse_notification(bytes.fromhex("000000030400000900"))
        self.assertTrue(p.login_completed)

    def test_login_polarity_nonzero_is_failure(self):
        # Regression test: the earlier (superseded) implementation had
        # this inverted.
        p = protocol.GizwitsBleProtocol()
        p.parse_notification(bytes.fromhex("000000030400000901"))
        self.assertFalse(p.login_completed)

    def test_login_polarity_zero_is_success(self):
        p = protocol.GizwitsBleProtocol()
        p.parse_notification(bytes.fromhex("000000030400000900"))
        self.assertTrue(p.login_completed)

    def test_reset_login_state_clears_passcode_and_login(self):
        p = protocol.GizwitsBleProtocol()
        p.parse_notification(bytes.fromhex("000000030f000007000a4f46534449485357524f"))
        p.parse_notification(bytes.fromhex("000000030400000900"))
        p.reset_login_state()
        self.assertFalse(p.passcode_received)
        self.assertFalse(p.login_completed)

    def test_report_channel_0x91_has_no_sn_prefix(self):
        # GIZWITS_PROTOCOL.md §5.5: unsolicited reports on cmd 0x0091
        # carry P0 directly, with no leading sn field (unlike 0x0093/0x94).
        p0 = bytes([0x14]) + bytes.fromhex("0000000008") + bytes([0x01])  # REPORT fanOnOff=1
        frame = protocol._giz_build_packet(const.GIZ_CMD_DATA_POINT_REPORT, p0)
        result = protocol.GizwitsBleProtocol().parse_notification(frame)
        self.assertEqual(result, {"fan": True})

    def test_data_point_reply_0x94_strips_sn(self):
        # cmd 0x0094 replies are [sn(4)] + P0 — the sn must be dropped
        # before decoding, unlike 0x0091.
        sn = (5).to_bytes(4, "big")
        p0 = bytes([0x14]) + bytes.fromhex("0000000004") + bytes([0x01])  # REPORT onOff=1
        frame = protocol._giz_build_packet(const.GIZ_CMD_DATA_POINT_REPLY, sn + p0)
        result = protocol.GizwitsBleProtocol().parse_notification(frame)
        self.assertEqual(result, {"power": True, "phase": "idle"})

    def test_empty_p0_on_0x94_is_a_write_ack_not_an_error(self):
        sn = (0).to_bytes(4, "big")
        frame = protocol._giz_build_packet(const.GIZ_CMD_DATA_POINT_REPLY, sn)
        result = protocol.GizwitsBleProtocol().parse_notification(frame)
        self.assertEqual(result, {})

    def test_fan_write_ack_and_report_from_doc_session(self):
        p = protocol.GizwitsBleProtocol()
        fan_on = p.build_fan(True)
        self.assertEqual(fan_on, bytes.fromhex("000000030e0000930000000011000000000801"))
        ack = bytes.fromhex("000000030700009400000000")
        self.assertEqual(p.parse_notification(ack), {})
        report = bytes.fromhex("000000030a00009114000000000801")
        self.assertEqual(p.parse_notification(report), {"fan": True})

    def test_multi_notification_chunked_read_reply_from_doc_session(self):
        # GIZWITS_PROTOCOL.md §7: the 204-byte read reply arrives as 11
        # separate notifications with no per-chunk framing at all.
        chunks = [
            "00000003c6010000940000000013ffffffffff14",
            "00000264000a02010000000000141705060c082e",
            "060101000a025809001500000002580000000005",
            "4c563800000000054c563801017f090015000102",
            "107f000000000003107f000000000004107f0000",
            "00000005107f000000000006107f000000000007",
            "107f000000000001000a02587f09001500010200",
            "0a005a7f000000000003000a005a7f0000000000",
            "04000a005a7f000000000005000a005a7f000000",
            "000006000a005a7f000000000007000a005a7f00",
            "00000000",
        ]
        p = protocol.GizwitsBleProtocol()
        result = {}
        for chunk in chunks:
            result.update(p.parse_notification(bytes.fromhex(chunk)))
        self.assertEqual(result["power"], True)
        self.assertEqual(result["fan"], False)
        self.assertEqual(result["display"], True)
        self.assertEqual(result["lift"], False)
        self.assertEqual(result["spray_mode"], const.GIZ_MODE_PE)
        self.assertEqual(result["oil_remaining"], 100)
        self.assertEqual(result["battery"], 0)
        self.assertEqual(result["concentration"], 2)
        # devRunStatus (§6.2): slot 1, gear 1, 10s work / 600s pause,
        # 09:00-21:00. Remaining counters are "as of the MCU's last
        # report" (§6.2) — this snapshot shows 0s work-remaining / 600s
        # pause-remaining, distinct from the mid-cycle values in the
        # separate write-session capture below.
        self.assertEqual(result["schedule_slot"], 1)
        self.assertEqual(result["work_seconds"], 10)
        self.assertEqual(result["pause_seconds"], 600)
        self.assertEqual(result["start_hour"], 9)
        self.assertEqual(result["start_minute"], 0)
        self.assertEqual(result["end_hour"], 21)
        self.assertEqual(result["end_minute"], 0)
        self.assertEqual(result["work_remaining"], 0)
        self.assertEqual(result["pause_remaining"], 600)
        # PE_SetTime1 (§6.5): every day, enabled.
        self.assertEqual(result["weekday_mask"], 0x7F)
        self.assertTrue(result["schedule_enabled"])

    def test_write_session_curplgears_and_devrunstatus_reports(self):
        # GIZWITS_PROTOCOL.md §7's "set CurPLGears=2 fanOnOff=0" session:
        # the ack carries no P0, then two reports arrive — one for the
        # written attribute (plus PL_SetTime1's auto-synced gear), one
        # for the resulting devRunStatus change.
        p = protocol.GizwitsBleProtocol()
        ack = bytes.fromhex("0000000307000094" + "00000000")
        self.assertEqual(p.parse_notification(ack), {})
        report1 = bytes.fromhex("00000003120000911400002010000201027f0900150001")
        result1 = p.parse_notification(report1)
        self.assertEqual(result1["intensity"], 2)
        report2 = bytes.fromhex("0000000317000091140000040000" + "0102000a025809001500000a0258")
        result2 = p.parse_notification(report2)
        self.assertEqual(result2["schedule_slot"], 1)
        self.assertEqual(result2["intensity"], 2)
        self.assertEqual(result2["work_remaining"], 10)
        self.assertEqual(result2["pause_remaining"], 600)


class AdvertisementParsingTests(unittest.TestCase):
    """GIZWITS_PROTOCOL.md §1.1/§1.2 — the two records can arrive
    concatenated into one manufacturer_data entry (CoreBluetooth) or split
    across two entries with the first two bytes of each eaten as a bogus
    "company ID" (BlueZ/HA/ESPHome)."""

    MAC_RECORD = bytes.fromhex("068cbfea41d97c")  # 06 + 8c:bf:ea:41:d9:7c
    KEY_RECORD = bytes.fromhex(
        "10c79041f7731b4a4f889d52c5ec9598c00101"
    )  # 10 + 16-byte key + len(1) + flags(01)

    def test_detects_via_service_uuid(self):
        adv = advertisement(service_uuids=[const.GIZWITS_SERVICE_UUID])
        self.assertTrue(protocol._detect_gizwits(adv))
        self.assertEqual(protocol.detect_device_type("", adv), const.DeviceType.GIZWITS_BLE)

    def test_detects_via_name_prefix_when_service_uuid_not_surfaced(self):
        # Regression (#41): HA's BlueZ-based passive scanner doesn't
        # always surface service_uuids the way the doc's CoreBluetooth
        # capture did, and detect_device_type() used to silently fall
        # back to Aroma-Link (wrong FFF1/FFF2 characteristics) in that
        # case. The XPG-GAgent-xxxx name prefix must catch it instead.
        adv = advertisement(service_uuids=[])
        self.assertFalse(protocol._detect_gizwits(adv))
        self.assertEqual(
            protocol.detect_device_type("XPG-GAgent-d97c", adv),
            const.DeviceType.GIZWITS_BLE,
        )
        self.assertEqual(
            protocol.detect_device_type("XPG-GAgent-d97c", None),
            const.DeviceType.GIZWITS_BLE,
        )

    def test_corebluetooth_concatenated_single_entry(self):
        raw = self.MAC_RECORD + self.KEY_RECORD
        company_id = int.from_bytes(raw[:2], "little")
        data = raw[2:]
        adv = advertisement(manufacturer_data={company_id: data})
        meta = protocol.extract_gizwits_metadata(adv)
        self.assertEqual(meta["mac_from_adv"], "8cbfea41d97c")
        self.assertEqual(meta["product_key"], "c79041f7731b4a4f889d52c5ec9598c0")
        self.assertIs(meta["requires_auth"], True)  # flags=0x01, bit1=0

    def test_bluez_split_entries(self):
        mac_company = int.from_bytes(self.MAC_RECORD[:2], "little")
        mac_data = self.MAC_RECORD[2:]
        key_company = int.from_bytes(self.KEY_RECORD[:2], "little")
        key_data = self.KEY_RECORD[2:]
        adv = advertisement(manufacturer_data={
            mac_company: mac_data,
            key_company: key_data,
        })
        meta = protocol.extract_gizwits_metadata(adv)
        self.assertEqual(meta["mac_from_adv"], "8cbfea41d97c")
        self.assertEqual(meta["product_key"], "c79041f7731b4a4f889d52c5ec9598c0")
        self.assertIs(meta["requires_auth"], True)

    def test_auth_flag_polarity(self):
        # bit 1 of flags: 0 = auth required, 1 = no auth (inverted sense).
        for flags, requires_auth in ((0x00, True), (0x02, False), (0x03, False)):
            with self.subTest(flags=flags):
                record = bytes.fromhex(
                    "10c79041f7731b4a4f889d52c5ec9598c001"
                ) + bytes([flags])
                company_id = int.from_bytes(record[:2], "little")
                adv = advertisement(manufacturer_data={company_id: record[2:]})
                meta = protocol.extract_gizwits_metadata(adv)
                self.assertIs(meta["requires_auth"], requires_auth)

    def test_no_manufacturer_data_leaves_fields_none(self):
        adv = advertisement(service_uuids=[const.GIZWITS_SERVICE_UUID])
        meta = protocol.extract_gizwits_metadata(adv)
        self.assertIsNone(meta["product_key"])
        self.assertIsNone(meta["requires_auth"])


class GizwitsConnectTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end BIND/LOGIN handshake through `device.py`'s connect path,
    against a fake BLE client that replies with the doc's real bytes.
    """

    async def make_device(self, requires_auth=None, drop_login_reply=False):
        self.writes = []
        self.callback = None
        client = SimpleNamespace(is_connected=True)
        client.services = SimpleNamespace(get_characteristic=lambda _: SimpleNamespace(
            properties=["write-without-response", "notify"],
        ))

        async def notify(uuid, callback):
            self.callback = callback

        async def write(uuid, frame, response):
            self.writes.append(frame)
            self.assertFalse(response)
            replies = {
                bytes.fromhex("0000000303000006"):
                    bytes.fromhex("000000030f000007000a4f46534449485357524f"),
                bytes.fromhex("000000030f000008000a4f46534449485357524f"):
                    bytes.fromhex("000000030400000900"),
            }
            if drop_login_reply:
                replies.pop(bytes.fromhex("000000030f000008000a4f46534449485357524f"))
            if frame in replies:
                reply = replies[frame]
                self.callback(1, bytearray(reply[:5]))
                self.callback(1, bytearray(reply[5:]))

        client.start_notify = notify
        client.write_gatt_char = write
        client.stop_notify = AsyncMock()
        client.disconnect = AsyncMock()

        bluetooth = ModuleType("homeassistant.components.bluetooth")
        bluetooth.async_ble_device_from_address = lambda *a, **k: None
        bluetooth.async_last_service_info = lambda *a, **k: None
        components = ModuleType("homeassistant.components")
        components.bluetooth = bluetooth
        core = ModuleType("homeassistant.core")
        core.HomeAssistant = object
        bleak = ModuleType("bleak")
        bleak.BleakClient = object
        bleak.BleakScanner = object
        bleak.BleakError = type("BleakError", (Exception,), {})
        connector = ModuleType("bleak_retry_connector")
        connector.establish_connection = AsyncMock(return_value=client)
        cloud = ModuleType(f"{PACKAGE}.protocol_cloud")
        cloud.AromaLinkCloudClient = object
        with patch.dict(sys.modules, {
            "bleak": bleak, "bleak_retry_connector": connector,
            "homeassistant": ModuleType("homeassistant"),
            "homeassistant.components": components, "homeassistant.core": core,
            f"{PACKAGE}.protocol_cloud": cloud,
        }):
            device_module = load_module("device")
        device = device_module.ScentDiffuserDevice(
            hass=object(), ble_address="00:11:22:33:44:55", ble_name="Test Gizwits",
            device_type=const.DeviceType.GIZWITS_BLE,
            giz_metadata={"requires_auth": requires_auth},
        )
        self.addAsyncCleanup(device._teardown_ble_client)
        return device

    async def test_connect_completes_bind_login(self):
        device = await self.make_device()
        self.assertTrue(await device._ble_connect())
        # BIND + LOGIN, plus the automatic first-connection time sync
        # (devTime write, split into 2 wire chunks — build_time_sync is a
        # real command for this protocol, unlike most others).
        self.assertEqual(len(self.writes), 4)
        self.assertEqual(self.writes[0], bytes.fromhex("0000000303000006"))
        self.assertEqual(
            self.writes[1], bytes.fromhex("000000030f000008000a4f46534449485357524f"),
        )
        self.assertTrue(device._protocol.login_completed)

    async def test_connect_skips_login_when_not_required(self):
        device = await self.make_device(requires_auth=False)
        self.assertTrue(await device._ble_connect())
        # No BIND/LOGIN, but the time-sync write still happens.
        self.assertEqual(len(self.writes), 2)

    async def test_connect_fails_when_login_never_confirms(self):
        # Same fake client, but strip the LOGIN_DEVICE reply so the
        # handshake times out — the connection must be torn down and
        # report failure rather than silently proceeding to writes the
        # device would drop (GIZWITS_PROTOCOL.md §4: no login means every
        # subsequent write is silently ignored).
        device = await self.make_device(drop_login_reply=True)
        # Shrink the poll timeout so the test doesn't wait the real 2s.
        orig_wait_until = device._wait_until
        device._wait_until = lambda predicate, timeout=2.0, poll=0.2: orig_wait_until(
            predicate, timeout=0.05, poll=0.01,
        )
        result = await device._ble_connect()
        self.assertFalse(result)
        self.assertFalse(device._protocol.login_completed)
        self.assertTrue(device._protocol.passcode_received)  # BIND succeeded


if __name__ == "__main__":
    unittest.main()
