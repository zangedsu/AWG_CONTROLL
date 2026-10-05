"""AmneziaVPN guest import fixtures. No SSH or remote subprocesses are used.

The decoder follows Qt's qCompress/QDataStream framing independently of the
export helpers. Schema assertions follow amnezia-client 5.0.3.0 and dev's
ContainerConfig, Awg/WireGuardProtocolConfig and SelfHostedUserServerConfig.
"""
import base64
import importlib.util
import json
import random
import struct
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("awg_amnezia_export_fixture", ROOT / "scripts/remote.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def key(letter):
    return base64.b64encode(letter.encode() * 32).decode()


PRIVATE, PUBLIC, SERVER_PUBLIC, PSK, HEADER = map(key, "abcde")
SERVER_PRIVATE = key("z")
HOST = "vpn.example.invalid"
AWG = {
    "Jc": "4", "Jmin": "40", "Jmax": "80", "S1": "32", "S2": "24",
    "S3": "16", "S4": "8", "H1": "1-10", "H2": "11-20",
    "H3": "21-30", "H4": "31-40", "I1": "<b 0xff><r 20>",
    "I2": "<rc 12><t>", "I3": "<r 8>", "I4": "<r 9>", "I5": "<rd 5>",
    "HeaderProtectionKey": HEADER, "ContentPaddingAddition": "0-16",
    "RekeyAfterTime": "120-150", "RekeyTimeout": "5-10",
    "RejectAfterTime": "160-180", "KeepaliveTimeout": "10-20",
    "MaxHandshakeAttempts": "16-20", "RandomTrailers": "on", "DisableCookies": "on",
}
SERVER = {
    "Address": "10.9.0.1/24, fd42::1/64", "ListenPort": "443",
    "PrivateKey": SERVER_PRIVATE, "password": "ssh-password-fixture",
    "userName": "root-fixture", "key_path": "/fixture/secret-ssh-key",
}


def native(parameters=None, dualstack=True, keepalive="25"):
    address = "10.9.0.2/32, fd42::2/128" if dualstack else "10.9.0.2/32"
    text = "[Interface]\nAddress = " + address + "\nDNS = 1.1.1.1, 2606:4700:4700::1111\n"
    text += "PrivateKey = " + PRIVATE + "\n"
    text += "".join(name + " = " + value + "\n" for name, value in (parameters or {}).items())
    text += "\n[Peer]\nPublicKey = " + SERVER_PUBLIC + "\nPresharedKey = " + PSK
    text += "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + HOST + ":443"
    return text + "\nPersistentKeepalive = " + keepalive + "\n"


def base64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_document(compressed):
    declared = int.from_bytes(compressed[:4], "big")
    raw = zlib.decompress(compressed[4:])
    if declared != len(raw):
        raise AssertionError("qCompress length must count UTF-8 bytes")
    return json.loads(raw)


def decode_qr_series(payloads):
    chunks = {}
    for payload in payloads:
        frame = base64url(payload)
        magic, count, index, length = struct.unpack(">hBBI", frame[:8])
        if magic != 1984 or count != len(payloads) or index >= count or index in chunks:
            raise AssertionError("Invalid Qt QR envelope")
        if not 1 <= length <= 850 or len(frame) != length + 8:
            raise AssertionError("Invalid QByteArray framing")
        if index < count - 1 and length != 850:
            raise AssertionError("Non-final chunks must fill 850 bytes")
        chunks[index] = frame[8:]
    return b"".join(chunks[index] for index in range(len(payloads)))


def imported_client(document):
    """Extract the fields read by the official self-hosted guest model."""
    if document.get("format_version", 0) > 1 or len(document["containers"]) != 1:
        raise AssertionError("Unsupported format")
    if any(document.get(name) for name in ("userName", "password", "port")):
        raise AssertionError("Guest import must not classify as SelfHostedAdmin")
    container = document["containers"][0]
    protocols = {"amnezia-awg": "awg", "amnezia-awg2": "awg", "amnezia-wireguard": "wireguard"}
    protocol = container[protocols[container["container"]]]
    if document["defaultContainer"] != container["container"]:
        raise AssertionError("Missing default container")
    if protocol.get("isThirdPartyConfig"):
        raise AssertionError("Guest import must not classify as Native")
    if not isinstance(protocol["port"], str) or not isinstance(protocol["last_config"], str):
        raise AssertionError("Protocol model needs string port and last_config")
    client = json.loads(protocol["last_config"])
    if not isinstance(client["port"], int) or not isinstance(client["allowed_ips"], list):
        raise AssertionError("Client model needs integer port and allowed_ips array")
    return protocol, client


class AmneziaExport(unittest.TestCase):
    def setUp(self):
        self.ns = {"__name__": "fixture", "REQUEST": {"host": HOST}}
        exec(compile(bridge.REMOTE_SCRIPT, "remote-amnezia-fixture", "exec"), self.ns)

    def export(self, parameters=None, container=None, tool="awg", **options):
        config = native(parameters, **options)
        result = self.ns["amnezia_client_export"](
            config, "Ноутбук Москва", PUBLIC, HOST, container, tool, SERVER
        )
        encoded = result["key"]
        self.assertTrue(encoded.startswith("vpn://"))
        self.assertNotIn("=", encoded)
        compressed = base64url(encoded[6:])
        self.assertEqual(decode_qr_series(result["qr_payloads"]), compressed)
        document = decode_document(compressed)
        protocol, client = imported_client(document)
        self.assertEqual(client["config"], config)
        return result, document, protocol, client

    def test_guest_key_and_qr_import_have_complete_awg3_metadata_without_ssh_access(self):
        result, document, protocol, client = self.export(AWG, "amnezia-awg2", keepalive="25-35")
        self.assertEqual(document["format_version"], 1)
        self.assertEqual(document["description"], "Ноутбук Москва")
        self.assertEqual(document["hostName"], HOST)
        self.assertEqual(document["defaultContainer"], "amnezia-awg2")
        self.assertEqual(document["dns1"], "1.1.1.1")
        self.assertEqual(document["dns2"], "1.1.1.1")
        self.assertEqual(protocol["protocol_version"], "3.1")
        self.assertEqual(protocol["subnet_address"], "10.9.0.0")
        self.assertEqual(protocol["subnet_cidr"], "24")
        for name, value in AWG.items():
            self.assertEqual(client[name], value, name)
            self.assertEqual(protocol[name], value, name)
        self.assertEqual(client["client_ip"], "10.9.0.2")
        self.assertIn("fd42::2/128", client["config"])
        self.assertIn("IPv4 DNS", result["warning"])
        self.assertEqual(client["client_priv_key"], PRIVATE)
        self.assertEqual(client["client_pub_key"], PUBLIC)
        self.assertEqual(client["clientId"], PUBLIC)
        self.assertEqual(client["server_pub_key"], SERVER_PUBLIC)
        self.assertEqual(client["psk_key"], PSK)
        self.assertEqual(client["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(client["persistent_keep_alive"], "25-35")
        self.assertEqual(result["filename"], "______________.vpn")
        serialized = json.dumps(document)
        for secret in (SERVER_PRIVATE, SERVER["password"], SERVER["userName"], SERVER["key_path"]):
            self.assertNotIn(secret, serialized)

    def test_wireguard_export_selects_wireguard_model_and_single_qr(self):
        result, document, protocol, client = self.export({}, tool="wg", dualstack=False)
        self.assertEqual(document["defaultContainer"], "amnezia-wireguard")
        self.assertEqual(len(result["qr_payloads"]), 1)
        self.assertEqual(protocol["subnet_mask"], "255.255.255.0")
        self.assertNotIn("protocol_version", protocol)
        self.assertEqual(client["client_ip"], "10.9.0.2")
        self.assertIn("warning", result, "Mixed DNS still needs a warning with IPv4-only addresses")
        self.assertFalse(set(AWG).intersection(client))

    def test_inferred_and_explicit_awg_container_versions(self):
        v1 = {name: value.split("-", 1)[0] for name, value in AWG.items()
              if name in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")}
        fixtures = [
            (v1, None, "amnezia-awg", None),
            (dict(v1, I1="<r 8>"), None, "amnezia-awg2", "1.5"),
            (dict(v1, S3="16", S4="8"), None, "amnezia-awg2", "2"),
            (AWG, None, "amnezia-awg2", "3.1"),
            (dict(v1, I1="<r 8>"), "amnezia-awg", "amnezia-awg", "1.5"),
            (v1, "amnezia-awg2", "amnezia-awg2", None),
            (AWG, "custom-system-container", "amnezia-awg2", "3.1"),
        ]
        for parameters, selected, expected, version in fixtures:
            with self.subTest(selected=selected, version=version):
                _, document, protocol, _ = self.export(parameters, selected)
                self.assertEqual(document["defaultContainer"], expected)
                self.assertEqual(protocol.get("protocol_version"), version)

    def test_multiple_qr_parts_reconstruct_full_compressed_key_in_any_scan_order(self):
        random_bytes = random.Random(42).randbytes(3000)
        parameters = dict(AWG, I1="<b 0x" + random_bytes.hex() + ">")
        result, _, _, client = self.export(parameters)
        self.assertGreater(len(result["qr_payloads"]), 1)
        self.assertEqual(decode_qr_series(list(reversed(result["qr_payloads"]))), base64url(result["key"][6:]))
        self.assertEqual(client["I1"], parameters["I1"])
        self.assertTrue(all(len(payload) <= 1144 for payload in result["qr_payloads"]))

    def test_qt_packet_boundaries_and_count_limit(self):
        encode = self.ns["amnezia_qr_payloads"]
        for size, count in ((1, 1), (849, 1), (850, 1), (851, 2), (1700, 2), (850 * 255, 255)):
            with self.subTest(size=size):
                data = b"x" * size
                payloads = encode(data)
                self.assertEqual(len(payloads), count)
                self.assertEqual(decode_qr_series(payloads), data)
        for data in (b"", b"x" * (850 * 255 + 1)):
            with self.assertRaises(self.ns["RemoteError"]):
                encode(data)

    def test_unavailable_protocol_is_rejected_before_encoding_guest(self):
        with self.assertRaisesRegex(self.ns["RemoteError"], "Unsupported protocol"):
            self.ns["amnezia_client_export"](
                native(AWG), "Phone", PUBLIC, HOST, None, "openvpn", SERVER
            )

    def test_optional_client_mtu_psk_and_single_dns_match_imported_metadata(self):
        config = native({}).replace("DNS = 1.1.1.1, 2606:4700:4700::1111", "DNS = 9.9.9.9")
        config = config.replace("PrivateKey = ", "MTU = 1280\nPrivateKey = ")
        config = config.replace("PresharedKey = " + PSK + "\n", "")
        result = self.ns["amnezia_client_export"](config, "Phone", PUBLIC, HOST, None, "wg", SERVER)
        document = decode_document(base64url(result["key"][6:]))
        _, client = imported_client(document)
        self.assertEqual(document["dns1"], "9.9.9.9")
        self.assertEqual(document["dns2"], "9.9.9.9")
        self.assertEqual(client["mtu"], "1280")
        self.assertEqual(client["config"], config)
        self.assertNotIn("psk_key", client)

    def test_ipv4_dns_metadata_preserves_all_native_dns_and_only_warns_for_ipv6(self):
        base = native({}, dualstack=False)
        for dns, expected, warned in [
            ("9.9.9.9, 149.112.112.112", ("9.9.9.9", "149.112.112.112"), False),
            ("2606:4700:4700::1111, 9.9.9.9, 149.112.112.112", ("9.9.9.9", "149.112.112.112"), True),
            ("9.9.9.9, 2606:4700:4700::1111", ("9.9.9.9", "9.9.9.9"), True),
        ]:
            with self.subTest(dns=dns):
                config = base.replace("1.1.1.1, 2606:4700:4700::1111", dns)
                result = self.ns["amnezia_client_export"](config, "Phone", PUBLIC, HOST, None, "wg", SERVER)
                document = decode_document(base64url(result["key"][6:]))
                _, client = imported_client(document)
                self.assertEqual((document["dns1"], document["dns2"]), expected)
                self.assertEqual(client["config"], config)
                self.assertEqual("warning" in result, warned)

    def test_ipv4_and_dns_endpoints_export_exact_guest_hostname(self):
        for host in ("198.51.100.42", "vpn.example.invalid"):
            with self.subTest(host=host):
                config = native(AWG).replace(HOST + ":443", host + ":443")
                result = self.ns["amnezia_client_export"](config, "Phone", PUBLIC, host, None, "awg", SERVER)
                document = decode_document(base64url(result["key"][6:]))
                _, client = imported_client(document)
                self.assertEqual(document["hostName"], host)
                self.assertEqual(client["hostName"], host)
                self.assertEqual(client["config"], config)

    def test_literal_ipv6_and_mapped_ipv6_endpoints_do_not_export_unusable_guest(self):
        for host in ("2001:db8::42", "::ffff:198.51.100.42"):
            with self.subTest(host=host):
                config = native(AWG).replace(HOST + ":443", "[" + host + "]:443")
                with self.assertRaisesRegex(self.ns["RemoteError"], "literal IPv6"):
                    self.ns["amnezia_client_export"](config, "Phone", PUBLIC, host, None, "awg", SERVER)

    def mutation_fixture(self):
        source = "[Interface]\nAddress = " + SERVER["Address"] + "\nListenPort = 443\nPrivateKey = " + SERVER_PRIVATE + "\n"
        source += "".join(name + " = " + value + "\n" for name, value in AWG.items())
        interface, peers = self.ns["parse_config"](source)
        path = "/opt/amnezia/awg/awg0.conf"
        events = []
        self.ns["selected_tunnel"] = lambda params: ("amnezia-awg2", "awg0", path, "awg", source, interface, peers)
        self.ns["context_read"] = lambda container, filename: "[]" if "clientsTable" in filename else source
        self.ns["backup_file"] = lambda container, filename, token: (events.append("backup") or filename + ".bak")
        self.ns["write_atomic"] = lambda *args: events.append("write")
        self.ns["synchronize"] = lambda *args: events.append("sync")
        commands = {("awg", "genkey"): PRIVATE, ("awg", "pubkey"): PUBLIC,
                    ("awg", "genpsk"): PSK, ("awg", "show", "awg0", "public-key"): SERVER_PUBLIC}
        self.ns["context_run"] = lambda container, args, *rest, **kwargs: {
            "ok": True, "stdout": commands[tuple(args)] + "\n", "stderr": "", "code": 0}
        return events

    def test_creation_prepares_guest_before_writes_and_exports_same_client(self):
        events = self.mutation_fixture()
        exporter = self.ns["amnezia_client_export"]
        self.ns["amnezia_client_export"] = lambda *args: (events.append("export") or exporter(*args))
        result = self.ns["mutate_client"]({"action": "client.create", "name": "Phone"})
        self.assertEqual(events[0], "export")
        self.assertEqual(result["protocol"], "AmneziaWG")
        self.assertEqual(result["protocol_version"], "3.1")
        _, client = imported_client(decode_document(base64url(result["amnezia"]["key"][6:])))
        self.assertEqual(client["config"], result["config"])
        self.assertEqual(client["client_pub_key"], result["public_key"])
        self.assertIsNone(result["amnezia_error"])

    def test_expected_export_failure_keeps_successful_native_creation(self):
        events = self.mutation_fixture()

        def unavailable(*args):
            self.assertFalse(events, "Export must happen before server writes")
            raise self.ns["RemoteError"]("Unsupported metadata")

        self.ns["amnezia_client_export"] = unavailable
        result = self.ns["mutate_client"]({"action": "client.create", "name": "Phone"})
        self.assertIsNone(result["amnezia"])
        self.assertTrue(result["amnezia_error"])
        self.assertIn("[Interface]", result["config"])
        self.assertIn("write", events)

    def test_unexpected_export_failure_cannot_leave_a_created_peer(self):
        events = self.mutation_fixture()

        def serialization_failure(*args):
            raise RuntimeError("Fixture serialization failure")

        self.ns["amnezia_client_export"] = serialization_failure
        with self.assertRaisesRegex(RuntimeError, "serialization failure"):
            self.ns["mutate_client"]({"action": "client.create", "name": "Phone"})
        self.assertEqual(events, [], "No backup, write or runtime sync may precede export serialization")

    def test_ipv6_only_dns_keeps_native_creation_without_misleading_guest_metadata(self):
        events = self.mutation_fixture()
        result = self.ns["mutate_client"]({"action": "client.create", "name": "Phone", "dns": "2606:4700:4700::1111"})
        self.assertIsNone(result["amnezia"])
        self.assertTrue(result["amnezia_error"])
        self.assertIn("DNS = 2606:4700:4700::1111", result["config"])
        self.assertIn("write", events)

    def test_literal_ipv6_host_keeps_bracketed_native_endpoint_and_creation(self):
        for host in ("2001:db8::42", "::ffff:198.51.100.42"):
            with self.subTest(host=host):
                events = self.mutation_fixture()
                self.ns["REQUEST"]["host"] = host
                result = self.ns["mutate_client"]({"action": "client.create", "name": "Phone"})
                self.assertIsNone(result["amnezia"])
                self.assertEqual(result["amnezia_error"], "Экспорт AmneziaVPN недоступен для сервера с IPv6-адресом. Используйте нативный .conf.")
                self.assertIn("Endpoint = [" + host + "]:443", result["config"])
                self.assertIn("write", events)


if __name__ == "__main__":
    unittest.main()
