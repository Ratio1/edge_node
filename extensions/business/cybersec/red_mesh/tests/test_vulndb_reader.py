import hashlib
import json
import os
import sqlite3
import statistics
import tempfile
import time
import unittest
from unittest import mock
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

  def load_generated(self):
    return load_vulndb("generated", self.db, self.pin)

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
    reader, keys = self.load_generated()
    self.assertIsNotNone(reader)
    self.assertEqual((keys["vulndb_source"], keys["vulndb_build_id"], keys["vulndb_built_at"]),
                     ("generated", BUILD_ID, "2026-11-14T00:00:00Z"))
    self.assertIsNone(keys["vulndb_load_error"])

  def test_local_origin_reports_meta_build_id_no_built_at(self):
    self.build()
    sha = json.loads(self.pin.read_text())["sha256_sqlite"]
    self.pin.write_text(json.dumps({"origin": "local", "sha256_sqlite": sha}))
    _, keys = self.load_generated()
    self.assertEqual((keys["vulndb_build_id"], keys["vulndb_built_at"], keys["vulndb_origin"]),
                     (BUILD_ID, None, "local"))

  def assert_fallback(self, cause):
    reader, keys = self.load_generated()
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

  def test_unknown_flag_value_falls_back_with_error(self):
    reader, keys = load_vulndb("bogus", self.db, self.pin)
    self.assertEqual((reader, keys["vulndb_source"], keys["vulndb_load_error"]), (None, "static", "unknown_source"))

  def test_size_mismatch_and_unreadable_file(self):
    self.build(pin_extra={"size": 1})
    self.assert_fallback("hash_mismatch")
    self.build()
    os.chmod(self.db, 0)
    self.addCleanup(os.chmod, self.db, 0o600)
    if not os.access(self.db, os.R_OK):  # root ignores the mode
      self.assert_fallback("file_unreadable")

  def test_unreadable_read_simulated(self):
    self.build()
    with mock.patch.object(Path, "read_bytes", side_effect=PermissionError):
      self.assert_fallback("file_unreadable")

  def test_hostile_pin_never_raises(self):
    self.build()
    self.pin.write_text("[" * 100000)
    reader, keys = self.load_generated()
    self.assertIsNone(reader)
    self.assertEqual(keys["vulndb_source"], "static")
    self.assertTrue(keys["vulndb_load_error"])

  def test_strongest_row_per_cve(self):
    rows = [
      ("CVE-2021-0010", "apache", "==2.4.1", "nvd", "tentative", "nvd_exact", 0, 0),
      ("CVE-2021-0010", "apache", "<2.5", "nvd", "firm", "nvd_range", 1, 0),
      ("CVE-2021-0010", "apache", "<2.6", "nvd", "firm", "nvd_range", 0, 0),
    ]
    self.build(rows=rows)
    reader, _ = load_reader(self.db, self.pin)
    (match,) = reader.query("apache", "2.4.1")
    self.assertEqual((match.confidence, match.platform_dependent, match.constraint), ("firm", 0, "<2.6"))

  def test_query_parity_with_matcher(self):
    from extensions.business.cybersec.red_mesh.cve_db import _matches_constraint
    from extensions.business.cybersec.red_mesh.tests.test_cve_matcher_versions import UNIT
    extra = [("", "1.0", "==1.0rc1"), ("", "1.0rc1", "==1.0rc1"), ("openssl", "1.0.1f", "==1.0.1f"),
             ("openssl", "1.0.1", "==1.0.1f"), ("bind", "9.18.24-S1", "==9.18.24-S1"),
             ("bind", "9.18.24", "==9.18.24-S1"), ("bind", "9.10.3-P4", "==9.10.3-P4")]
    cases = [(p, v, c) for p, v, c, _e, _w in UNIT] + extra
    rows = [("CVE-2022-%04d" % i, p or "x", c, "nvd", "firm", "nvd_range", 0, 0) for i, (p, v, c) in enumerate(cases)]
    self.build(rows=rows)
    reader, _ = load_reader(self.db, self.pin)
    for i, (product, version, constraint) in enumerate(cases):
      with self.subTest(product=product, version=version, constraint=constraint):
        hit = "CVE-2022-%04d" % i in [m.cve_id for m in reader.query(product or "x", version)]
        self.assertEqual(hit, _matches_constraint(version, constraint, product or "x"))


  def _spans(self, product, version, rows, **kw):
    self.build(rows=rows)
    reader, _ = load_reader(self.db, self.pin)
    return {m.cve_id: (m.confidence, m.reason) for m in reader.query(product, version, **kw)}

  def test_truncated_banner_keeps_whole_prefix_rows_and_marks_the_rest(self):
    rows = [
      ("CVE-2022-0001", "apache", "<3.0", "nvd", "firm", "nvd_range", 0, 0),           # whole 2.4.x: unchanged
      ("CVE-2022-0002", "apache", "<2.4.50", "nvd", "firm", "nvd_range", 0, 0),        # 2.4.0 yes, 2.4.999999 no
      ("CVE-2022-0003", "apache", ">=2.4.49,<2.5", "nvd", "firm", "nvd_range", 0, 0),  # high end only
      ("CVE-2022-0004", "apache", ">=2.4.49,<2.4.51", "nvd", "firm", "nvd_range", 0, 0),  # strictly inside: possible
      ("CVE-2022-0005", "apache", "<2.4", "nvd", "firm", "nvd_range", 0, 0),           # below the prefix: dropped
      ("CVE-2022-0007", "apache", "==2.4.10", "nvd", "tentative", "nvd_exact", 0, 0),  # an exact version inside: possible
      ("CVE-2022-0008", "apache", "==2.5.1", "nvd", "tentative", "nvd_exact", 0, 0),   # outside: dropped
      ("CVE-2022-0009", "apache", ">=2.5,<2.6", "nvd", "firm", "nvd_range", 0, 0),     # outside: dropped
    ]
    self.assertEqual(self._spans("apache", "2.4", rows), {
      "CVE-2022-0001": ("firm", "nvd_range"),
      "CVE-2022-0002": ("tentative", "inferred_version"),
      "CVE-2022-0003": ("tentative", "inferred_version"),
      "CVE-2022-0004": ("tentative", "inferred_version"),
      "CVE-2022-0007": ("tentative", "inferred_version"),
    })
    self.assertEqual(sorted(self._spans("apache", "2.4.0", rows)), ["CVE-2022-0001", "CVE-2022-0002"])  # full precision
    self.assertEqual(sorted(self._spans("apache", "2.4.60", rows)), ["CVE-2022-0001", "CVE-2022-0003"])

  def test_wordpress_two_part_banner_is_a_full_version(self):
    rows = [("CVE-2022-0014", "wordpress", "<6.4.2", "nvd", "firm", "nvd_range", 0, 0)]
    self.assertEqual(self._spans("wordpress", "6.4", rows), {"CVE-2022-0014": ("firm", "nvd_range")})  # x.y.0 ships as x.y
    self.assertEqual(self._spans("wordpress", "6", rows), {"CVE-2022-0014": ("tentative", "inferred_version")})  # `6` is a prefix
    self.assertEqual(self._spans("wordpress", "6.4.2", rows), {})

  def test_libssh_three_part_banner_is_truncated_at_two_parts(self):
    rows = [("CVE-2022-0015", "libssh", "<0.8.4", "nvd", "firm", "nvd_range", 0, 0)]
    self.assertEqual(self._spans("libssh", "0.8", rows), {"CVE-2022-0015": ("tentative", "inferred_version")})

  def test_two_part_products_are_not_truncated_at_two_parts(self):
    rows = [("CVE-2022-0006", "openssh", "<9.0", "nvd", "firm", "nvd_range", 0, 0)]
    self.assertEqual(self._spans("openssh", "8.9", rows), {"CVE-2022-0006": ("firm", "nvd_range")})

  def test_inferred_span_keeps_rows_that_cover_the_whole_span(self):
    rows = [
      ("CVE-2022-0010", "openssl", ">=1.0.1,<1.0.1g", "nvd", "firm", "nvd_range", 0, 0),
      ("CVE-2022-0011", "openssl", ">=1.0.1a,<1.0.1u", "nvd", "firm", "nvd_range", 0, 0),  # starts inside the span
      ("CVE-2022-0012", "openssl", "<=1.0.1s", "nvd", "firm", "nvd_range", 0, 0),
      ("CVE-2022-0013", "openssl", ">=1.0.1g,<1.0.1u", "nvd", "firm", "nvd_range", 0, 0),
      ("CVE-2022-0016", "openssl", "==1.0.1c", "nvd", "tentative", "nvd_exact", 0, 0),
    ]
    span = ("1.0.1", "1.0.1f")
    self.assertEqual(self._spans("openssl", "1.0.1f", rows, inferred_span=span), {
      "CVE-2022-0010": ("firm", "nvd_range"),
      "CVE-2022-0011": ("tentative", "inferred_version"),
      "CVE-2022-0012": ("firm", "nvd_range"),
      "CVE-2022-0016": ("tentative", "inferred_version"),  # exact 1.0.1c is a possible version
    })
    self.assertEqual(sorted(self._spans("openssl", "1.0.1f", rows)),
                     ["CVE-2022-0010", "CVE-2022-0011", "CVE-2022-0012"])  # no span: today's behaviour


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
