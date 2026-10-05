"""Collector fixtures and policy checks. SSH and remote subprocesses are mocked."""
import base64
import importlib.util
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("awg_remote_fixture", ROOT / "scripts/remote.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def key(letter):
    return base64.b64encode(letter.encode() * 32).decode()


PRIVATE, PSK, HEADER = key("p"), key("s"), key("h")
PUBLIC_ONE, PUBLIC_TWO, SERVER_PUBLIC = key("a"), key("b"), key("c")
CONFIG = f"""[Interface]
Address = 10.9.0.1/24, fd42::1/64
ListenPort = 443
PrivateKey = {PRIVATE}
Jc = 4
Jmin = 40
Jmax = 80
S1 = 32
S2 = 32
S3 = 32
S4 = 32
H1 = 1-10
H2 = 11-20
H3 = 21-30
H4 = 31-40
I1 = <b 0xff><r 20>
HeaderProtectionKey = {HEADER}
ContentPaddingAddition = 0-16
RekeyAfterTime = 120-150
RekeyTimeout = 5-10
RejectAfterTime = 160-180
KeepaliveTimeout = 10-20
MaxHandshakeAttempts = 16-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = {PUBLIC_ONE}
PresharedKey = {PSK}
AllowedIPs = 10.9.0.2/32, fd42::2/128
PersistentKeepalive = 25

[Peer]
PublicKey = {PUBLIC_TWO}
AllowedIPs = 10.9.0.3/32
"""


def result(stdout="", ok=True):
    return {"ok": ok, "code": 0 if ok else 1, "stdout": stdout, "stderr": "", "truncated": False}


class RemoteFixtures(unittest.TestCase):
    def setUp(self):
        self.ns = {"__name__": "fixture", "REQUEST": {
            "operation": "snapshot", "host": "198.51.100.42", "params": {},
            "write_allowed": False, "protected": False,
        }}
        exec(compile(bridge.REMOTE_SCRIPT, "remote-fixture", "exec"), self.ns)
        self.tool_available = self.ns["context_tool_available"]
        # Ordinary fixtures specify supported commands themselves. The dedicated
        # preflight test below exercises the real availability helper.
        self.ns["context_tool_available"] = lambda container, tool: True

    def fixture_context(self, interface="awg0", container="amnezia-awg2", config_available=True):
        fields = {
            "peers": PUBLIC_ONE + "\n" + PUBLIC_TWO + "\n",
            "public-key": SERVER_PUBLIC + "\n", "listen-port": "443\n",
            "latest-handshakes": PUBLIC_ONE + "\t950\n" + PUBLIC_TWO + "\t0\n",
            "transfer": PUBLIC_ONE + "\t9876543210\t1234567890\n",
            "endpoints": PUBLIC_ONE + "\t203.0.113.1:10000\n" + PUBLIC_TWO + "\t(none)\n",
            "allowed-ips": PUBLIC_ONE + "\t10.9.0.2/32,fd42::2/128\n" + PUBLIC_TWO + "\t10.9.0.3/32\n",
        }

        def context_run(selected, args, *rest, **kwargs):
            if selected != container:
                return result(ok=False)
            if args == ["awg", "show", "interfaces"]:
                return result(interface + "\n")
            if len(args) == 4 and args[:3] == ["awg", "show", interface]:
                return result(fields.get(args[3], ""))
            self.fail("Unexpected collector command " + repr(args))

        def context_read(selected, path):
            if selected != container:
                return ""
            if config_available and path == "/opt/amnezia/awg/awg0.conf":
                return CONFIG
            if path.endswith("/clientsTable"):
                return json.dumps([{"clientId": PUBLIC_ONE, "userData": {"clientName": "Ноутбук"}}])
            return ""

        self.ns["context_run"] = context_run
        self.ns["context_read"] = context_read
        return [{"name": container, "awg": True, "state": "running", "logging_driver": "none"}]

    def test_parser_preserves_version_ranges_cps_and_dual_stack(self):
        interface, peers = self.ns["parse_config"](CONFIG)
        self.assertEqual(interface["H2"], "11-20")
        self.assertEqual(interface["I1"], "<b 0xff><r 20>")
        self.assertEqual(interface["RandomTrailers"], "on")
        self.assertEqual(interface["HeaderProtectionKey"], HEADER)
        self.assertEqual(len(peers), 2)
        self.assertIn("fd42::2/128", peers[0]["AllowedIPs"])

    def test_redaction_removes_known_secrets_in_conf_json_and_authorization(self):
        redact = self.ns["redact"]
        for text in [CONFIG, json.dumps({"PrivateKey": PRIVATE, "PresharedKey": PSK, "HeaderProtectionKey": HEADER}),
                     json.dumps({"private_key": PRIVATE, "password": PSK}, indent=2)]:
            redacted = redact(text)
            for secret in (PRIVATE, PSK, HEADER):
                self.assertNotIn(secret, redacted)
        self.assertIn(PUBLIC_ONE, redact(CONFIG))
        self.assertNotIn("fixture-bearer", redact("Authorization: Bearer fixture-bearer"))
        self.assertNotIn("fixture-private-data", redact("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-private-data\n-----END OPENSSH PRIVATE KEY-----"))

    def test_legacy_and_current_clients_table_names(self):
        table_names = self.ns["table_names"]
        current = [{"clientId": PUBLIC_ONE, "userData": {"clientName": "Ноутбук"}}, None, {"clientId": PUBLIC_TWO, "userData": None}]
        self.assertEqual(table_names(current)[PUBLIC_ONE], "Ноутбук")
        legacy = {PUBLIC_ONE: {"clientName": "Старый клиент"}}
        self.assertEqual(table_names(legacy)[PUBLIC_ONE], "Старый клиент")

    def test_tunnel_snapshot_joins_peers_without_exposing_keys(self):
        containers = self.fixture_context()
        with mock.patch.object(self.ns["time"], "time", return_value=1000):
            tunnels = self.ns["discover_tunnels"](containers)
        self.assertEqual(len(tunnels), 1)
        tunnel = tunnels[0]
        self.assertEqual(tunnel["peer_count"], 2)
        self.assertEqual(tunnel["parameters"]["H1"], "1-10")
        first = next(peer for peer in tunnel["peers"] if peer["public_key"] == PUBLIC_ONE)
        self.assertEqual(first["name"], "Ноутбук")
        self.assertTrue(first["online"])
        self.assertEqual(first["rx_bytes"], 9876543210)
        self.assertFalse(next(peer for peer in tunnel["peers"] if peer["public_key"] == PUBLIC_TWO)["online"])
        for secret in (PRIVATE, PSK, HEADER):
            self.assertNotIn(secret, json.dumps(tunnels))
        self.assertFalse(tunnel["capabilities"]["export_existing_private_keys"])

    def test_running_interface_does_not_select_another_interfaces_config(self):
        containers = self.fixture_context(interface="wg1")
        tunnels = self.ns["discover_tunnels"](containers)
        self.assertEqual(len(tunnels), 1)
        self.assertIsNone(tunnels[0]["config_path"])
        self.assertFalse(tunnels[0]["capabilities"]["manage_clients"])

    def test_empty_awg_interfaces_falls_back_to_wireguard(self):
        self.ns["context_read"] = lambda container, path: CONFIG if path == "/etc/wireguard/wg0.conf" else ""

        def run_context(container, args, *rest, **kwargs):
            if args == ["awg", "show", "interfaces"]:
                return result("")
            if args == ["wg", "show", "interfaces"]:
                return result("wg0\n")
            return result("")

        self.ns["context_run"] = run_context
        tunnels = self.ns["discover_tunnels"]([])
        self.assertEqual(len(tunnels), 1)
        self.assertEqual(tunnels[0]["tool"], "wg")
        self.assertEqual(tunnels[0]["config_path"], "/etc/wireguard/wg0.conf")

    def test_absent_vpn_tools_do_not_execute_missing_binaries_in_docker(self):
        entries = [
            {"Id": "dns-fixture", "Name": "/amnezia-dns", "Config": {"Image": "amnezia-dns:latest"}, "State": {"Status": "running"}},
            {"Id": "proxy-fixture", "Name": "/amnezia-xray", "Config": {"Image": "amnezia-xray:latest"}, "State": {"Status": "running"}},
            {"Id": "vpn-fixture", "Name": "/custom-vpn", "Config": {"Image": "amneziawg-go:latest"}, "State": {"Status": "running"}},
        ]

        def docker_inventory(args, *rest, **kwargs):
            if args[:3] == ["docker", "ps", "-a"]:
                return result("\n".join(json.dumps({"ID": entry["Id"]}) for entry in entries))
            if args[:2] == ["docker", "inspect"]:
                return result(json.dumps(entries))
            if args[:2] == ["docker", "stats"]:
                return result("")
            self.fail("Unexpected inventory command " + repr(args))

        self.ns["run"] = docker_inventory
        containers, _ = self.ns["docker_objects"]()
        self.assertEqual([item["name"] for item in containers if item["awg"]], ["custom-vpn"])
        self.assertTrue(all(item["amnezia"] for item in containers))
        calls = []

        def unavailable(container, args, *rest, **kwargs):
            calls.append((container, args))
            self.assertEqual(container, "custom-vpn")
            self.assertEqual(args[:4], ["sh", "-c", 'command -v "$1" >/dev/null 2>&1', "awg-control"])
            self.assertIn(args[-1], ("awg", "wg"))
            return result(ok=False)

        self.ns["context_run"] = unavailable
        self.ns["context_tool_available"] = self.tool_available
        self.ns["context_read"] = lambda container, path: CONFIG
        with mock.patch.object(self.ns["shutil"], "which", return_value=None):
            self.assertEqual(self.ns["discover_tunnels"](containers), [])
            with self.assertRaisesRegex(self.ns["RemoteError"], "must be running"):
                self.ns["selected_tunnel"]({"container": "custom-vpn", "interface": "awg0", "config_path": "/opt/amnezia/awg/awg0.conf"})
        self.assertEqual(len(calls), 4)
        with mock.patch.object(self.ns["shutil"], "which", side_effect=lambda tool: "/usr/bin/wg" if tool == "wg" else None):
            self.assertFalse(self.tool_available(None, "awg"))
            self.assertTrue(self.tool_available(None, "wg"))
        self.assertFalse(self.tool_available("custom-vpn", "unexpected-command"))
        self.assertEqual(len(calls), 4)

    def test_log_driver_none_reports_unavailable_without_docker_logs(self):
        calls = []

        def no_logs(args, *rest, **kwargs):
            calls.append(args)
            self.assertEqual(args, ["docker", "inspect", "amnezia-awg2"])
            return result(json.dumps([{"HostConfig": {"LogConfig": {"Type": "none"}}}]))

        self.ns["run"] = no_logs
        logs = self.ns["log_output"]({"source": "container:amnezia-awg2", "lines": 200})
        self.assertFalse(logs["available"])
        self.assertEqual(logs["lines"], 0)
        self.assertEqual(len(calls), 1)

    def test_remote_write_guard_rejects_before_commands(self):
        self.ns["run"] = lambda *args, **kwargs: self.fail("Read-only guard must run before any command")
        for request in [{"host": "192.0.2.10", "write_allowed": True},
                        {"host": "198.51.100.42", "protected": True, "write_allowed": True},
                        {"host": "198.51.100.42", "write_allowed": False}]:
            self.ns["REQUEST"] = request
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["execute_action"]({"action": "host.reboot", "confirmed": True})

    def mutation_fixture(self, config_text=CONFIG):
        config, peers = self.ns["parse_config"](config_text)
        table = [{"clientId": PUBLIC_ONE, "userData": {"clientName": "Ноутбук"}},
                 {"clientId": PUBLIC_TWO, "userData": {"clientName": "Телефон"}}]
        table_text = json.dumps(table)
        path = "/opt/amnezia/awg/awg0.conf"
        self.ns["selected_tunnel"] = lambda params: ("amnezia-awg2", "awg0", path, "awg", config_text, config, peers)
        self.ns["context_read"] = lambda container, filename: (
            table_text if "clientsTable" in filename else config_text
        )
        backups, writes, syncs = [], [], []
        self.ns["backup_file"] = lambda container, filename, token: (backups.append(filename) or filename + ".fixture.bak")
        self.ns["write_atomic"] = lambda container, filename, text, token: writes.append((filename, text))
        self.ns["synchronize"] = lambda *args: syncs.append(args)
        return backups, writes, syncs

    def test_new_client_export_preserves_awg3_and_allocates_unused_address(self):
        backups, writes, syncs = self.mutation_fixture()
        client_private, client_public, client_psk = key("d"), key("e"), key("f")
        commands = {
            ("awg", "genkey"): client_private,
            ("awg", "pubkey"): client_public,
            ("awg", "genpsk"): client_psk,
            ("awg", "show", "awg0", "public-key"): SERVER_PUBLIC,
        }
        self.ns["context_run"] = lambda container, args, *rest, **kwargs: result(commands[tuple(args)] + "\n")
        created = self.ns["mutate_client"]({"action": "client.create", "name": "Новый клиент"})
        self.assertEqual(created["address"], "10.9.0.4")
        self.assertEqual(created["ipv6_address"], "fd42::3")
        exported, exported_peers = self.ns["parse_config"](created["config"])
        original, _ = self.ns["parse_config"](CONFIG)
        for parameter in self.ns["AWG_PARAMETERS"]:
            if parameter in original:
                self.assertEqual(exported[parameter], original[parameter], parameter)
        self.assertEqual(exported["PrivateKey"], client_private)
        self.assertIn("fd42::3/128", exported["Address"])
        self.assertEqual(exported_peers[0]["PresharedKey"], client_psk)
        self.assertEqual(exported_peers[0]["PersistentKeepalive"], "25-35")
        persisted_config = next(text for path, text in writes if path.endswith("awg0.conf"))
        self.assertNotIn(client_private, persisted_config)
        self.assertIn(client_public, persisted_config)
        table = json.loads(next(text for path, text in writes if path.endswith("clientsTable")))
        self.assertEqual(table[-1]["userData"]["clientName"], "Новый клиент")
        self.assertEqual(len(backups), 2)
        self.assertEqual(len(syncs), 1)

    def test_commented_client_cps_survives_export_without_activating_server_comments(self):
        original = CONFIG.replace("I1 = <b 0xff><r 20>", "# I1 = <b 0xff><r 20>\n# I2 = <rc 12><t>\n# I5 = <rd 5>\n# PrivateKey = ignored-comment-secret\n# HeaderProtectionKey = ignored-header-secret")
        original = original.replace("[Peer]", "# I3 = <r 8>\n[Peer]", 1)
        original += "\n# I4 = <r 99>\n"
        _, writes, _ = self.mutation_fixture(original)
        client_keys = {("awg", "genkey"): key("d"), ("awg", "pubkey"): key("e"),
                       ("awg", "genpsk"): key("f"), ("awg", "show", "awg0", "public-key"): SERVER_PUBLIC}
        self.ns["context_run"] = lambda container, args, *rest, **kwargs: result(client_keys[tuple(args)] + "\n")
        created = self.ns["mutate_client"]({"action": "client.create", "name": "CPS fixture", "keepalive": "27-34"})
        exported, peers = self.ns["parse_config"](created["config"])
        self.assertEqual({key: exported[key] for key in ("I1", "I2", "I3", "I5")},
                         {"I1": "<b 0xff><r 20>", "I2": "<rc 12><t>", "I3": "<r 8>", "I5": "<rd 5>"})
        self.assertNotIn("I4", exported, "A peer-section comment is not client Interface metadata")
        self.assertEqual(peers[0]["PersistentKeepalive"], "27-34")
        self.assertNotIn("ignored-comment-secret", created["config"])
        self.assertNotIn("ignored-header-secret", created["config"])
        persisted = next(text for path, text in writes if path.endswith("awg0.conf"))
        active, _ = self.ns["parse_config"](persisted)
        self.assertTrue(all(key not in active for key in ("I1", "I2", "I3", "I4", "I5")))
        self.assertIn("# I1 = <b 0xff><r 20>", persisted)

    def test_active_cps_overrides_commented_defaults_and_comment_keys_are_allowlisted(self):
        text = "[Interface]\nI1 = <r 7>\n# I1 = <r 99>\n# I2 = <r 20> # metadata\n# I3 =\n# PrivateKey = secret\n# H1 = 4-8\n[Peer]\n# I5 = <r 1>\n"
        active, _ = self.ns["parse_config"](text)
        fallback = self.ns["client_cps_parameters"](text, active)
        self.assertEqual(fallback, {"I2": "<r 20>"})
        merged = dict(active, **fallback)
        self.assertEqual(merged["I1"], "<r 7>")
        self.assertNotIn("PrivateKey", merged)
        self.assertNotIn("H1", merged)

    def test_protocol_version_matches_official_markers_including_ranges_and_flags(self):
        infer = self.ns["infer_protocol_version"]
        for marker in self.ns["AWG3_MARKERS"]:
            with self.subTest(marker=marker):
                self.assertEqual(infer({marker: "0-0", "H1": "1-10"}), "3.1")
                self.assertEqual(infer({marker: "  ", "H1": "1"}), "1.0")
        for flag in ("RandomTrailers", "DisableCookies"):
            self.assertEqual(infer({flag: " ON "}), "3.1")
            self.assertEqual(infer({flag: "oFf", "S1": "12"}), "1.0")
        self.assertEqual(infer({"H2": "20-30", "I1": "<r 20>"}), "2.0")
        self.assertEqual(infer({"S3": "0"}), "2.0")
        self.assertEqual(infer({"S3": " ", "I2": "<rc 12>"}), "1.5")
        self.assertEqual(infer({"I1": "", "Address": "10.0.0.1/24"}), "WireGuard")

    def test_keepalive_ranges_are_bounded_and_only_allowed_for_awg3(self):
        keepalive = self.ns["client_keepalive"]
        awg3 = {"ContentPaddingAddition": "10-100"}
        legacy = {"Jc": "3", "H1": "1"}
        self.assertEqual(keepalive({}, awg3), "25-35")
        self.assertEqual(keepalive({}, legacy), "25")
        for value, expected in [(0, "0"), (65535, "65535"), (" 25 ", "25"),
                                ("0-0", "0-0"), ("0-65535", "0-65535"), ("025-035", "25-35")]:
            self.assertEqual(keepalive({"keepalive": value}, awg3), expected)
        for value in ("25-35", "0-0"):
            with self.assertRaises(self.ns["RemoteError"]): keepalive({"keepalive": value}, legacy)
        for value in (-1, True, None, 2.5, "", "65536", "1-65536", "35-25", "1--2",
                      "1 - 2", "1e2", "2.5", "25\nPostUp=reboot", "25;reboot", "1-2-3", "off"):
            with self.subTest(value=value), self.assertRaises(self.ns["RemoteError"]):
                keepalive({"keepalive": value}, awg3)

    def test_invalid_keepalive_fails_before_key_generation_or_server_writes(self):
        self.mutation_fixture()
        self.ns["context_run"] = lambda *args, **kwargs: self.fail("Invalid keepalive must fail before any key command")
        self.ns["backup_file"] = lambda *args, **kwargs: self.fail("Invalid keepalive must fail before backup writes")
        with self.assertRaises(self.ns["RemoteError"]):
            self.ns["mutate_client"]({"action": "client.create", "name": "Rejected", "keepalive": "40-20"})

    def test_peer_delete_preserves_other_peers_and_interface_parameters(self):
        _, writes, syncs = self.mutation_fixture()
        self.ns["mutate_client"]({"action": "client.delete", "public_key": PUBLIC_TWO})
        text = next(text for path, text in writes if path.endswith("awg0.conf"))
        config, peers = self.ns["parse_config"](text)
        self.assertEqual(config["HeaderProtectionKey"], HEADER)
        self.assertEqual(config["H1"], "1-10")
        self.assertEqual([peer["PublicKey"] for peer in peers], [PUBLIC_ONE])
        self.assertEqual(peers[0]["PresharedKey"], PSK)
        table = json.loads(next(text for path, text in writes if path.endswith("clientsTable")))
        self.assertEqual([entry["clientId"] for entry in table], [PUBLIC_ONE])
        self.assertEqual(len(syncs), 1)

    def test_failed_client_table_write_restores_configuration_and_interface(self):
        _, writes, syncs = self.mutation_fixture()

        def write_atomic(container, path, text, token):
            writes.append((path, text))
            if path.endswith("clientsTable") and not token.endswith("-rollback"):
                raise self.ns["RemoteError"]("Fixture disk failure")

        self.ns["write_atomic"] = write_atomic
        with self.assertRaises(self.ns["RemoteError"]):
            self.ns["mutate_client"]({"action": "client.delete", "public_key": PUBLIC_TWO})
        configs = [text for path, text in writes if path.endswith("awg0.conf")]
        self.assertEqual(configs[-1], CONFIG)
        self.assertEqual(len(syncs), 2, "Must apply changed config and restored config")

    def test_shell_metacharacters_and_path_traversal_are_rejected(self):
        for name in ["--privileged", "safe;reboot", "$(reboot)", "safe\nother"]:
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["validate_container"](name)
        with self.assertRaises(self.ns["RemoteError"]):
            self.ns["log_output"]({"source": "containerfile:safe:/var/log/../../etc/secret.log"})

    def test_journal_priority_is_applied_and_validated(self):
        calls = []
        self.ns["run"] = lambda args, *rest, **kwargs: (calls.append(args) or result("fixture event\n"))
        self.ns["log_output"]({"source": "journal", "priority": "err", "since": "2026-10-04 10:00:00"})
        self.assertIn("--priority", calls[0])
        self.assertIn("err", calls[0])
        self.assertIn("--since", calls[0])
        with self.assertRaises(self.ns["RemoteError"]):
            self.ns["log_output"]({"source": "journal", "priority": "err;reboot"})

    def compose_fixture(self):
        return {"Name": "/fixture-web", "Config": {"Image": "nginx:stable", "Labels": {
            "com.docker.compose.project": "fixture",
            "com.docker.compose.service": "web",
            "com.docker.compose.project.working_dir": "/srv/fixture",
            "com.docker.compose.project.config_files": "/srv/fixture/compose.yml",
        }}}

    def test_compose_update_rejects_awg_unmanaged_and_changed_images(self):
        info = self.compose_fixture()
        def run_compose(args, *rest, **kwargs):
            return result(json.dumps({"services": {"web": {"image": "nginx:stable"}}})) if args[-3:] == ["config", "--format", "json"] else result("web\n")
        self.ns["run"] = run_compose
        self.ns["readfile"] = lambda *args: "services: {web: {image: nginx:stable}}"
        with mock.patch.object(self.ns["os"].path, "isdir", return_value=True), mock.patch.object(self.ns["os"].path, "isfile", return_value=True), mock.patch.object(self.ns["os"].path, "getsize", return_value=40):
            context = self.ns["compose_context"](info, {})
            self.assertEqual(context["service"], "web")
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["compose_context"](dict(info, Name="/amnezia-awg2"), {})
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["compose_context"]({"Name": "/unmanaged", "Config": {}}, {})
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["compose_context"](info, {"image": "unreviewed:new"})
            info["Config"]["Labels"]["com.docker.compose.project.config_files"] = "/etc/outside.yml"
            with self.assertRaises(self.ns["RemoteError"]):
                self.ns["compose_context"](info, {})

    def test_compose_deployment_failure_invokes_backup_image_rollback(self):
        info = self.compose_fixture()
        calls = []
        base = ["docker", "compose", "--project-name", "fixture", "--project-directory", "/srv/fixture", "-f", "/srv/fixture/compose.yml"]
        self.ns["compose_context"] = lambda current, params: {"base": base, "files": ["/srv/fixture/compose.yml"], "service": "web", "project": "fixture"}
        self.ns["readfile"] = lambda *args: "services:\n  web:\n    image: nginx:stable\n"

        def run_fixture(args, *rest, **kwargs):
            calls.append(args)
            if args == ["docker", "inspect", "fixture-web"]:
                return result(json.dumps([info]))
            if args == base + ["up", "-d", "--no-deps", "web"]:
                return result(ok=False)
            return result("fixture-success\n")

        self.ns["run"] = run_fixture
        # All backup filesystem writes are redirected into a local test folder.
        prefix = "/var/backups/awg-control/"
        os_module = self.ns["os"]
        real_open, real_makedirs, real_chmod = os_module.open, os_module.makedirs, os_module.chmod
        with tempfile.TemporaryDirectory(prefix="awg-compose-fixture-") as folder:
            def mapped(path):
                self.assertTrue(str(path).startswith(prefix), "Unexpected filesystem write")
                return str(Path(folder) / str(path)[len(prefix):])

            with mock.patch.object(os_module, "open", side_effect=lambda path, *args: real_open(mapped(path), *args)), \
                 mock.patch.object(os_module, "makedirs", side_effect=lambda path, *args, **kwargs: real_makedirs(mapped(path), *args, **kwargs)), \
                 mock.patch.object(os_module, "chmod", side_effect=lambda path, mode: real_chmod(mapped(path), mode)):
                with self.assertRaisesRegex(self.ns["RemoteError"], "previous filesystem image restored"):
                    self.ns["update_compose_container"]({"container": "fixture-web"})
            saved = list(Path(folder).glob("*/rollback-command.json"))
            self.assertEqual(len(saved), 1)
            rollback = json.loads(saved[0].read_text())
            self.assertEqual(calls[-1], rollback)
            self.assertIn("--no-deps", rollback)
            self.assertTrue(any(args[:2] == ["docker", "commit"] for args in calls))

    def test_systemd_start_stop_restart_use_allowlisted_arguments(self):
        self.ns["REQUEST"] = {"host": "198.51.100.42", "write_allowed": True, "protected": False}
        for verb in ("start", "stop", "restart"):
            calls = []

            def run_fixture(args, *rest, **kwargs):
                calls.append(args)
                if args[0] == "ip":
                    return result("[]")
                if args[:2] == ["systemctl", "show"]:
                    return result("loaded\n")
                return result()

            self.ns["run"] = run_fixture
            params = {"action": "service." + verb, "service": "fixture.service", "confirmed": True}
            params["expected_precondition"] = self.ns["plan_action"](params)["precondition"]
            completed = self.ns["execute_action"](params)
            self.assertEqual(completed["action"], "service." + verb)
            self.assertEqual(calls[-1], ["systemctl", verb, "fixture.service"])

    def test_changed_remote_state_prevents_commands(self):
        self.ns["REQUEST"] = {"host": "198.51.100.42", "write_allowed": True, "protected": False}
        self.ns["plan_action"] = lambda params: {"precondition": "a" * 64, "executable": True}
        self.ns["run"] = lambda args, *rest, **kwargs: result("[]") if args[0] == "ip" else self.fail("Stale plans must not execute commands")
        with self.assertRaisesRegex(self.ns["RemoteError"], "changed after review"):
            self.ns["execute_action"]({"action": "host.reboot", "confirmed": True, "expected_precondition": "b" * 64})
        with self.assertRaisesRegex(self.ns["RemoteError"], "saved remote-state precondition"):
            self.ns["execute_action"]({"action": "host.reboot", "confirmed": True})

    def test_client_plan_digest_changes_with_clients_table_without_leaking_keys(self):
        self.mutation_fixture()
        self.ns["context_run"] = lambda *args, **kwargs: result(PUBLIC_ONE + "\n" + PUBLIC_TWO + "\n")
        params = {"action": "client.create", "name": "Fixture"}
        before = self.ns["plan_action"](params)
        self.ns["context_read"] = lambda *args: json.dumps([{"clientId": PUBLIC_ONE, "userData": {"clientName": "Changed"}}])
        after = self.ns["plan_action"](params)
        self.assertNotEqual(before["precondition"], after["precondition"])
        self.assertRegex(before["precondition"], r"^[a-f0-9]{64}$")
        for secret in (PRIVATE, PSK, HEADER):
            self.assertNotIn(secret, json.dumps(before))


class BridgePolicyTests(unittest.TestCase):
    def test_protected_address_and_dns_aliases_including_mapped_ipv6(self):
        base = {"username": "root", "port": 22, "read_only": False}
        self.assertTrue(bridge.protected_server(dict(base, host="192.0.2.10")))
        for address in ["192.0.2.10", "::ffff:192.0.2.10"]:
            row = (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 22))
            with mock.patch.object(bridge.socket, "getaddrinfo", return_value=[row]):
                self.assertTrue(bridge.protected_server(dict(base, host="alias.example")), address)
        with mock.patch.object(bridge.socket, "getaddrinfo", side_effect=socket.gaierror()):
            with self.assertRaises(bridge.BridgeError):
                bridge.protected_server(dict(base, host="unresolvable.example"))


if __name__ == "__main__":
    unittest.main()
