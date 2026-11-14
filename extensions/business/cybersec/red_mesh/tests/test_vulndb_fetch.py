import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
SCRIPT = ROOT / ".github/actions/fetch-vulndb/verify_vulndb.py"
spec = importlib.util.spec_from_file_location("verify_vulndb", SCRIPT)
vv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vv)

BUILD_ID = "vulndb-0123456789ab"


class VulndbFetchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "vulndb.sqlite"
        self.make_db(self.db)
        self.pin = {
            "schema": 1, "repo": vv.REPO, "build_id": BUILD_ID, "asset": vv.ASSET,
            "sha256": "a" * 64, "sha256_sqlite": hashlib.sha256(self.db.read_bytes()).hexdigest(),
        }

    @staticmethod
    def make_db(path, model=1, build_id=BUILD_ID):
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        conn.execute("INSERT INTO meta VALUES ('build_id', ?)", (build_id,))
        conn.execute("PRAGMA user_version = %d" % model)
        conn.commit()
        conn.close()

    def write_pin(self, **changes):
        path = self.tmp / "pin.json"
        path.write_text(json.dumps({**self.pin, **changes}))
        return path

    def test_valid_pin_and_database(self):
        pin = vv.load_pin(self.write_pin())
        vv.verify_sqlite(pin, self.db, supported=(1,))
        self.assertEqual(vv.main(["x", "pin", str(self.write_pin())]), 0)
        self.assertEqual(vv.main(["x", "verify", str(self.write_pin()), str(self.db)]), 0)

    def test_pin_fields_are_validated(self):
        for change in ({"repo": "evil/repo"}, {"asset": "../x"}, {"build_id": "v1; rm -rf /"},
                       {"sha256": "zz"}, {"schema": 2}, {"origin": "local"}):
            with self.assertRaises(ValueError, msg=str(change)):
                vv.load_pin(self.write_pin(**change))

    def test_verify_rejects_bad_files(self):
        pin = vv.load_pin(self.write_pin())
        with self.assertRaisesRegex(ValueError, "sha256_sqlite"):
            vv.verify_sqlite(dict(pin, sha256_sqlite="b" * 64), self.db, supported=(1,))
        with self.assertRaisesRegex(ValueError, "MODEL"):
            vv.verify_sqlite(pin, self.db, supported=(2,))
        with self.assertRaisesRegex(ValueError, "build_id"):
            vv.verify_sqlite(dict(pin, build_id="vulndb-ffffffffffff"), self.db, supported=(1,))

    def test_supported_models_come_from_package(self):
        self.assertEqual(vv._supported_models(), (1,))

    def test_local_pin_has_origin_and_no_built_at(self):
        out = self.tmp / "local.json"
        vv.write_local_pin(self.db, out)
        pin = json.loads(out.read_text())
        self.assertEqual(pin["origin"], "local")
        self.assertEqual(pin["build_id"], BUILD_ID)
        self.assertNotIn("built_at", pin)
        self.assertEqual(pin["sha256_sqlite"], self.pin["sha256_sqlite"])

    def test_workflows_call_action_and_pin_is_absent(self):
        for name, jobs in (("build_develop.yml", 4), ("build_main.yml", 2)):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertEqual(text.count("uses: ./.github/actions/fetch-vulndb"), jobs)
        self.assertFalse((ROOT / "extensions/business/cybersec/red_mesh/vulndb/pin.json").exists())


if __name__ == "__main__":
    unittest.main()
