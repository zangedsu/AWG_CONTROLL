"""Exercise HTTP safety boundaries in an isolated store. No SSH calls occur."""
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
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
        env = dict(os.environ, AWG_DATA_DIR=str(cls.data_dir))
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
            "name": "Изолированный тест", "read_only": read_only,
            "password": "Synthetic-Fixture-Password-Only",
        }
        status, payload, _ = self.request("/api/servers", profile)
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

    def test_protected_host_cannot_enable_writes_even_with_forged_plan(self):
        profile = self.save_fixture("192.0.2.10", read_only=False)
        self.assertTrue(profile["read_only"])
        self.assertTrue(profile["protected"])
        plan = self.local_plan(profile)
        self.assertFalse(plan["executable"])
        self.alter_plan_fixture(plan)
        status, payload, _ = self.request("/api/actions/execute", {
            "plan_id": plan["plan_id"], "confirmation": plan["target"],
        })
        self.assertEqual((status, payload["error"]["code"]), (403, "read_only"))

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
