import hashlib
import json
import os
import sqlite3
import statistics
import tempfile
import time
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.vulndb.reader import load_reader, load_vulndb

BUILD_ID = "vulndb-0123456789ab"
# (cve, product, constraint, source, confidence, reason, platform_dependent, client_side)
ROWS = [
  ("CVE-2021-0001", "apache", ">=2.4.49,<2.4.51", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2021-0002", "apache", "==2.4.50", "nvd", "tentative", "nvd_exact", 0, 0),
  ("CVE-2021-0002", "apache", "<2.4.60", "cna", "tentative", "cna_range", 0, 0),
  ("CVE-2021-0003", "apache", "<3.0", "nvd", "firm", "nvd_range", 1, 1),
  ("CVE-2021-0004", "apache", "<3.0", "nvd", "firm", "nvd_range", 0, 0),  # REJECTED vuln, never loaded
  ("CVE-2021-0005", "apache", "<bogus", "nvd", "firm", "nvd_range", 0, 0),  # does not parse: dropped
  ("CVE-2021-0006", "openssl", "<1.0.1g", "nvd", "firm", "nvd_range", 0, 0),
]


def make_db(path, model=1, rows=ROWS, schema="1.0.0", build_id=BUILD_ID):
  Path(path).unlink(missing_ok=True)
  conn = sqlite3.connect(path)
  conn.executescript(
    'CREATE TABLE vuln(cve_id TEXT PRIMARY KEY, state TEXT, published TEXT, title TEXT, cwe TEXT, kev INTEGER,'
    ' kev_date_added TEXT, epss REAL, epss_percentile REAL, display_cvss_version TEXT, display_cvss_score REAL,'
    ' display_cvss_source TEXT, severity TEXT);'
    'CREATE TABLE affected(product TEXT, "constraint" TEXT, cve_id TEXT, source TEXT, confidence TEXT, reason TEXT,'
    ' platform_dependent INTEGER, client_side INTEGER, PRIMARY KEY(product, cve_id, "constraint"));'
    "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);"
  )
  for cve in sorted({r[0] for r in rows}):
    state = "REJECTED" if cve == "CVE-2021-0004" else "PUBLISHED"
    conn.execute("INSERT INTO vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (cve, state, "2021-01-01", "t " + cve, "CWE-79", int(cve.endswith("1")), None, 0.5, 0.9,
                  "3.1", 9.8, "nvd", "CRITICAL"))
  conn.executemany(
    'INSERT INTO affected(cve_id, product, "constraint", source, confidence, reason, platform_dependent, client_side)'
    " VALUES (?,?,?,?,?,?,?,?)", rows)
  conn.execute("INSERT INTO meta VALUES ('schema', ?)", (schema,))
  conn.execute("INSERT INTO meta VALUES ('build_id', ?)", (build_id,))
  conn.execute("PRAGMA user_version = %d" % model)
  conn.commit()
  conn.close()


class VulndbReaderTests(unittest.TestCase):
  def setUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.dir = Path(tmp.name) / "a b#c"  # path needs URI quoting
    self.dir.mkdir()
    self.db, self.pin = self.dir / "v.sqlite", self.dir / "pin.json"

  def build(self, pin_extra=None, **kw):
    make_db(self.db, **kw)
    pin = {"build_id": BUILD_ID, "built_at": "2026-11-14T00:00:00Z",
           "sha256_sqlite": hashlib.sha256(self.db.read_bytes()).hexdigest()}
    pin.update(pin_extra or {})
    self.pin.write_text(json.dumps(pin))

  def error(self, flag="generated"):
    reader, keys = load_vulndb(flag, self.db, self.pin)
    return reader, keys

  def test_query_ranges_exact_and_dedup(self):
    self.build()
    reader, info = load_reader(self.db, self.pin)
    self.assertEqual(reader.dropped, 1)
    ids = lambda v: sorted(m.cve_id for m in reader.query("apache", v))
    self.assertEqual(ids("2.4.50"), ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"])  # 0002 once
    self.assertEqual(ids("2.4.50.0"), ids("2.4.50"))
    self.assertEqual(ids("Apache/2.4.52"), ["CVE-2021-0002", "CVE-2021-0003"])
    self.assertEqual(ids("3.1"), [])
    self.assertEqual(ids("garbage"), [])
    self.assertEqual(reader.query("nginx", "1.0"), [])
    self.assertEqual([m.cve_id for m in reader.query("openssl", "1.0.1f")], ["CVE-2021-0006"])
    self.assertEqual(info["build_id"], BUILD_ID)

  def test_rows_carry_flags_and_vuln_fields(self):
    self.build()
    reader, _ = load_reader(self.db, self.pin)
    row = {m.cve_id: m for m in reader.query("apache", "2.4.50")}["CVE-2021-0003"]
    self.assertEqual((row.platform_dependent, row.client_side, row.confidence), (1, 1, "firm"))
    self.assertEqual((row.severity, row.cvss_score, row.kev), ("CRITICAL", 9.8, 0))

  def test_rejected_never_matches(self):
    self.build()
    reader, _ = load_reader(self.db, self.pin)
    self.assertNotIn("CVE-2021-0004", [m.cve_id for m in reader.query("apache", "2.4.50")])

  def test_static_flag_loads_nothing(self):
    reader, keys = load_vulndb("static", self.dir / "none.sqlite", self.pin)
    self.assertIsNone(reader)
    self.assertEqual(keys, {"vulndb_source": "static", "vulndb_build_id": None, "vulndb_built_at": None,
                            "vulndb_origin": None, "vulndb_load_error": None})

  def test_generated_ok(self):
    self.build()
    reader, keys = self.error()
    self.assertIsNotNone(reader)
    self.assertEqual((keys["vulndb_source"], keys["vulndb_build_id"], keys["vulndb_built_at"]),
                     ("generated", BUILD_ID, "2026-11-14T00:00:00Z"))
    self.assertIsNone(keys["vulndb_load_error"])

  def test_local_origin_reports_meta_build_id_no_built_at(self):
    self.build(pin_extra={"origin": "local", "build_id": "ignored"})
    self.pin.write_text(json.dumps({"origin": "local", "sha256_sqlite": json.loads(self.pin.read_text())["sha256_sqlite"]}))
    _, keys = self.error()
    self.assertEqual((keys["vulndb_build_id"], keys["vulndb_built_at"], keys["vulndb_origin"]),
                     (BUILD_ID, None, "local"))

  def assert_fallback(self, cause):
    reader, keys = self.error()
    self.assertIsNone(reader)
    self.assertEqual((keys["vulndb_source"], keys["vulndb_build_id"], keys["vulndb_load_error"]),
                     ("static", None, cause))

  def test_fallbacks(self):
    self.assert_fallback("no_pin")
    self.pin.write_text(json.dumps({"sha256_sqlite": "0"}))
    self.assert_fallback("file_missing")
    self.build()
    self.db.write_bytes(self.db.read_bytes() + b"x")
    self.assert_fallback("hash_mismatch")
    self.build(model=99)
    self.assert_fallback("unknown_model")
    self.build(schema="2.0.0")
    self.assert_fallback("schema_mismatch")
    self.build(pin_extra={"build_id": "vulndb-other"})
    self.assert_fallback("build_id_mismatch")
    self.db.write_bytes(b"not sqlite")
    self.pin.write_text(json.dumps({"sha256_sqlite": hashlib.sha256(b"not sqlite").hexdigest()}))
    self.assert_fallback("load_failed:DatabaseError")

  def test_unknown_flag_value_is_static(self):
    self.assertEqual(load_vulndb("bogus", self.db, self.pin)[1]["vulndb_source"], "static")


@unittest.skipUnless(os.environ.get("VULNDB_BENCH_DB"), "set VULNDB_BENCH_DB to a real database (pin built from it)")
class VulndbBenchmark(unittest.TestCase):
  def test_vulhub_p95_and_rss(self):
    from extensions.business.cybersec.red_mesh.tests.test_cve_recall_offline import EXPECT
    db = Path(os.environ["VULNDB_BENCH_DB"])
    with tempfile.TemporaryDirectory() as tmp:
      pin = Path(tmp) / "pin.json"
      pin.write_text(json.dumps({"origin": "local", "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}))
      def rss():
        with open("/proc/self/status") as status:
          return int(next(l for l in status if l.startswith("VmRSS")).split()[1]) / 1024
      before = rss()
      start = time.perf_counter()
      reader, _ = load_reader(db, pin)
      load_s = time.perf_counter() - start
      growth = rss() - before
    times = []
    for _ in range(20):
      for product, version, _cve in EXPECT:
        t = time.perf_counter()
        reader.query(product, version)
        times.append((time.perf_counter() - t) * 1000)
    p95 = statistics.quantiles(times, n=100)[94]
    print("vulndb bench: rows=%d dropped=%d load=%.2fs rss_growth=%.1fMB p95=%.2fms max=%.2fms"
          % (reader.row_count, reader.dropped, load_s, growth, p95, max(times)))
    self.assertLessEqual(p95, 5.0)
    self.assertLessEqual(growth, 50.0)


if __name__ == "__main__":
  unittest.main()
