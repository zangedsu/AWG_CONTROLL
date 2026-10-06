"""Exercise HTTP safety boundaries in an isolated store. No SSH calls occur."""
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LocalApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("AWG_TEST_PHP") or shutil.which("php")
        if not cls.php:
            raise RuntimeError("PHP is required; set AWG_TEST_PHP to its absolute path")
        cls.temp = tempfile.TemporaryDirectory(prefix="awg-api-test-")
        cls.data_dir = Path(cls.temp.name) / "private"
        # Never let a missing isolation option write into the real project store.
        app_source = (ROOT / "app/App.php").read_text()
        if "AWG_DATA_DIR" not in app_source:
            cls.temp.cleanup()
            raise RuntimeError("API tests require the AWG_DATA_DIR isolation option")
        with socket.socket() as free_port:
            free_port.bind(("127.0.0.1", 0))
            cls.port = free_port.getsockname()[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.log = open(Path(cls.temp.name) / "php.log", "w+")
        cls.engine_log = Path(cls.temp.name) / "mock-engine.jsonl"
        # PHP dispatches its SSH bridge through python3. Replace that executable
        # only in this test process; the real bridge is never imported or run.
        if "proc_open(['python3'," not in app_source or any(c.isspace() for c in sys.executable):
            raise RuntimeError("Cannot safely install the isolated mock engine")
        mock_bin = Path(cls.temp.name) / "mock-bin"
        mock_bin.mkdir()
        mock_engine = mock_bin / "python3"
        mock_engine.write_text("#!" + sys.executable + "\n" + '''
import json, os, sys
request = json.load(sys.stdin)
server, params = request.get("server", {}), request.get("params", {})
entry = {"operation": request.get("operation"), "server_id": server.get("id"),
         "read_only": server.get("read_only"), "params": params}
with open(os.environ["AWG_TEST_ENGINE_LOG"], "a") as log:
    log.write(json.dumps(entry) + "\\n")
if entry["operation"] == "plan":
    response = {"ok": True, "data": {"summary": "Synthetic fixture plan", "commands": [],
                "warnings": [], "executable": True, "precondition": "a" * 64}}
elif (entry["operation"] == "execute" and server.get("read_only") is False
      and params.get("confirmed") is True and params.get("expected_precondition") == "a" * 64
      and params.get("action") == "container.restart"):
    response = {"ok": True, "data": {"mock": True, "action": params["action"], "message": "Fixture only"}}
else:
    response = {"ok": False, "error": "Unexpected or unapproved mock-engine operation", "code": "fixture_rejected"}
print(json.dumps(response))
''')
        mock_engine.chmod(0o700)
        env = dict(os.environ, AWG_DATA_DIR=str(cls.data_dir),
                   AWG_TEST_ENGINE_LOG=str(cls.engine_log),
                   PATH=str(mock_bin) + os.pathsep + os.environ.get("PATH", ""))
        cls.process = subprocess.Popen(
            [cls.php, "-S", f"127.0.0.1:{cls.port}", "-t", "public", "public/router.php"],
            cwd=ROOT, env=env, stdout=cls.log, stderr=cls.log,
        )
        for _ in range(100):
            if cls.process.poll() is not None:
                cls.log.seek(0)
                raise RuntimeError(cls.log.read())
            try:
                with urllib.request.urlopen(cls.base + "/api/bootstrap", timeout=0.2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise RuntimeError("Isolated PHP API did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait(timeout=3)
        cls.log.close()
        cls.temp.cleanup()

    def setUp(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        status, payload, _ = self.request("/api/bootstrap", client=False)
        self.assertEqual(status, 200, payload)
        self.csrf = payload["data"]["csrf"]

    def request(self, path, body=None, *, client=True, csrf=True, headers=None, opener=None):
        sent = dict(headers or {})
        if client:
            sent.setdefault("X-AWG-Client", "1")
        if body is not None:
            sent.setdefault("Content-Type", "application/json")
            if csrf:
                sent.setdefault("X-CSRF-Token", self.csrf)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=sent)
        try:
            response = (opener or self.opener).open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read().decode()
        status, returned_headers = response.status, response.headers
        response.close()
        payload = json.loads(raw) if path.startswith("/api/") else raw
        return status, payload, returned_headers

    def save_fixture(self, host="198.51.100.42", read_only=False):
        profile = {
            "id": "fixture_" + uuid.uuid4().hex,
            "host": host, "port": 22, "username": "root",
            "name": "Изолированный тест",
            "password": "Synthetic-Fixture-Password-Only",
        }
        if read_only is not None:
            profile["read_only"] = read_only
        status, payload, _ = self.request("/api/servers", profile)
        self.assertEqual(status, 200, payload)
        return payload["data"]

    def engine_calls(self):
        return [json.loads(line) for line in self.engine_log.read_text().splitlines()] if self.engine_log.exists() else []

    def executable_plan(self, profile):
        status, payload, _ = self.request("/api/actions/plan", {
            "mode": "live", "server_id": profile["id"],
            "action": "container.restart", "target": "fixture-awg",
        })
        self.assertEqual(status, 200, payload)
        return payload["data"]

    def set_read_only(self, profile, value):
        status, payload, _ = self.request("/api/servers", {"id": profile["id"], "read_only": value})
        self.assertEqual(status, 200, payload)
        return payload["data"]

    def local_plan(self, profile, target="fixture-host"):
        # server.update is a non-executable plan, and requires no connection.
        status, payload, _ = self.request("/api/actions/plan", {
            "mode": "live", "server_id": profile["id"],
            "action": "server.update", "target": target,
        })
        self.assertEqual(status, 200, payload)
        return payload["data"]

    def alter_plan_fixture(self, plan, **values):
        path = self.data_dir / ("plan." + plan["plan_id"] + ".json")
        stored = json.loads(path.read_text())
        stored.update(values)
        # Enables gate tests without allowing an actual command to reach SSH.
        stored["public"]["executable"] = True
        path.write_text(json.dumps(stored))

    def test_host_origin_client_header_and_csrf_guards(self):
        status, payload, _ = self.request("/api/bootstrap", headers={"Host": "attacker.example"}, client=False)
        self.assertEqual((status, payload["error"]["code"]), (403, "local_only"))
        status, payload, _ = self.request("/api/bootstrap", headers={"Origin": "https://attacker.example"}, client=False)
        self.assertEqual((status, payload["error"]["code"]), (403, "invalid_origin"))
        status, payload, _ = self.request("/api/audit", client=False)
        self.assertEqual((status, payload["error"]["code"]), (403, "client_header_required"))
        status, payload, _ = self.request("/api/servers", {"host": "198.51.100.42"}, csrf=False)
        self.assertEqual((status, payload["error"]["code"]), (403, "csrf_invalid"))

    def test_read_only_defaults_to_true_and_explicit_save_can_disable_it(self):
        calls = self.engine_calls()
        profile = self.save_fixture("192.0.2.10", read_only=None)
        self.assertTrue(profile["read_only"])
        self.assertFalse(profile.get("protected", False))
        enabled = self.set_read_only(profile, False)
        self.assertFalse(enabled["read_only"])
        self.assertFalse(enabled.get("protected", False))
        self.assertEqual(self.engine_calls(), calls, "Saving the mode must not contact or modify any server")

    def test_read_only_blocks_forged_plan_and_changing_mode_invalidates_it(self):
        profile = self.save_fixture("192.0.2.10", read_only=True)
        calls = self.engine_calls()
        plan = self.local_plan(profile)
        self.assertFalse(plan["executable"])
        self.alter_plan_fixture(plan)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (403, "read_only"))
        self.set_read_only(profile, False)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (409, "server_changed"))
        self.assertEqual(self.engine_calls(), calls)

    def test_write_enabled_plan_still_requires_confirmation_and_mode_roundtrip_invalidates_it(self):
        profile = self.save_fixture("192.0.2.10", read_only=False)
        calls = len(self.engine_calls())
        old_plan = self.executable_plan(profile)
        self.assertTrue(old_plan["executable"])
        self.set_read_only(profile, True)
        self.set_read_only(profile, False)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": old_plan["plan_id"], "confirmation": old_plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (409, "server_changed"))
        self.assertEqual(len(self.engine_calls()), calls + 1)
        plan = self.executable_plan(profile)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": "wrong-target",
        })
        self.assertEqual((status, payload["error"]["code"]), (400, "confirmation_required"))
        self.assertEqual(len(self.engine_calls()), calls + 2)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["data"]["mock"])
        executed = self.engine_calls()[calls:]
        self.assertEqual([call["operation"] for call in executed], ["plan", "plan", "execute"])
        self.assertTrue(all(call["read_only"] is False for call in executed))
        self.assertTrue(executed[-1]["params"]["confirmed"])
        self.assertEqual(executed[-1]["params"]["expected_precondition"], "a" * 64)

    def test_cached_snapshot_uses_current_profile_mode(self):
        profile = self.save_fixture("192.0.2.10", read_only=True)
        # Pin only a synthetic marker in this isolated store so the cache can be
        # exercised without SSH fingerprint discovery or trust actions.
        path = self.data_dir / "servers.json"
        profiles = json.loads(path.read_text())
        profiles[profile["id"]]["fingerprint"] = "SHA256:synthetic-fixture-only"
        path.write_text(json.dumps(profiles))
        cache = {"cached_at": int(time.time()), "data": {
            "server": dict(profile, protected=True), "protected": True,
            "host": {"hostname": "synthetic-cache"},
        }}
        (self.data_dir / ("snapshot." + profile["id"] + ".json")).write_text(json.dumps(cache))
        calls = self.engine_calls()
        self.set_read_only(profile, False)
        status, payload, _ = self.request("/api/snapshot?mode=live&server=" + profile["id"])
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["data"]["host"]["hostname"], "synthetic-cache")
        self.assertFalse(payload["data"]["server"]["read_only"])
        self.assertFalse(payload["data"]["server"].get("protected", False))
        self.assertFalse(payload["data"].get("protected", False))
        self.assertEqual(self.engine_calls(), calls)

    def test_credentials_are_encrypted_and_never_returned(self):
        profile = self.save_fixture()
        _, bootstrap, headers = self.request("/api/bootstrap", client=False)
        self.assertNotIn("Synthetic-Fixture-Password-Only", json.dumps(bootstrap))
        self.assertNotIn("password_encrypted", json.dumps(bootstrap))
        persisted = (self.data_dir / "servers.json").read_text()
        self.assertNotIn("Synthetic-Fixture-Password-Only", persisted)
        self.assertTrue(json.loads(persisted)[profile["id"]]["password_encrypted"])
        self.assertIn("no-store", headers.get("Cache-Control", "").split(", "))
        status, _, _ = self.request("/../var/private/servers.json")
        self.assertEqual(status, 404)

    def test_demo_data_and_plans_never_execute(self):
        status, payload, _ = self.request("/api/snapshot?mode=demo&server=demo")
        self.assertEqual(status, 200, payload)
        self.assertIn("clients", payload["data"])
        status, payload, _ = self.request("/api/actions/plan", {
            "server_id": "demo", "mode": "demo", "action": "container.restart", "target": "amnezia-awg2",
        })
        self.assertEqual(status, 200, payload)
        plan = payload["data"]
        self.assertFalse(plan["executable"])
        self.assertTrue(plan["read_only"])
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": "amnezia-awg2",
        })
        self.assertEqual((status, payload["error"]["code"]), (403, "read_only"))

    def test_live_connection_without_trust_never_falls_back_to_demo(self):
        profile = self.save_fixture()
        status, payload, _ = self.request("/api/snapshot?mode=live&server=" + profile["id"])
        self.assertEqual((status, payload["error"]["code"]), (409, "host_key_required"))
        self.assertFalse(payload["ok"])
        self.assertNotIn("data", payload)

    def test_plans_expire_are_session_bound_and_single_use(self):
        profile = self.save_fixture()
        plan = self.local_plan(profile)
        other = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        _, boot, _ = self.request("/api/bootstrap", client=False, opener=other)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        }, headers={"X-CSRF-Token": boot["data"]["csrf"]}, opener=other)
        self.assertEqual((status, payload["error"]["code"]), (404, "plan_not_found"))
        self.alter_plan_fixture(plan, expires=1)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (409, "plan_expired"))
        self.alter_plan_fixture(plan, expires=int(time.time()) + 600, consumed=True)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (409, "plan_expired"))

    def test_confirmation_and_profile_changes_prevent_execution(self):
        profile = self.save_fixture()
        plan = self.local_plan(profile)
        self.alter_plan_fixture(plan)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": "wrong-host",
        })
        self.assertEqual((status, payload["error"]["code"]), (400, "confirmation_required"))
        status, payload, _ = self.request("/api/servers", {"id": profile["id"], "port": 2222})
        self.assertEqual(status, 200, payload)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (409, "server_changed"))


if __name__ == "__main__":
    unittest.main()
