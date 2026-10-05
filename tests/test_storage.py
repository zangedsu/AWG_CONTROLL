"""Local security checks; never contacts a server or uses real credentials."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StorageSecurityTests(unittest.TestCase):
    def test_private_authenticated_storage_and_traversal_guard(self):
        php = os.environ.get("AWG_TEST_PHP") or shutil.which("php")
        self.assertIsNotNone(php, "PHP is required; set AWG_TEST_PHP to its absolute path")
        with tempfile.TemporaryDirectory(prefix="awg-store-test-") as tmp:
            result = subprocess.run(
                [php, str(ROOT / "tests/store_probe.php"), str(Path(tmp) / "data")],
                capture_output=True, text=True, timeout=10, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
