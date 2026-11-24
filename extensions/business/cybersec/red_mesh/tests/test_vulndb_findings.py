"""RM-169 step 2c-i: CVE finding fields under `static` and `generated`, dedup across pins, plugin wiring."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_view import build_cve_view
from extensions.business.cybersec.red_mesh.findings import _finding_to_jsonable
from extensions.business.cybersec.red_mesh.mixins.report import _dedup_finding_list
from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import _RedMeshLlmAgentMixin
from extensions.business.cybersec.red_mesh.mixins.report import _dedup_finding_list
from extensions.business.cybersec.red_mesh.vulndb.reader import load_vulndb

from . import test_api as api_fixtures
from .test_vulndb_reader import make_db

CVE = "CVE-2024-6387"  # in the static catalog: openssh <4.4, CWE-362
V31 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
# (cve, product, constraint, source, confidence, reason, platform_dependent, client_side)
ROWS = [
  (CVE, "openssh", "<9.8", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0002", "redis", "<9", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0003", "redis", "<9", "nvd", "tentative", "nvd_exact", 0, 0),
  ("CVE-2030-0004", "redis", "<9", "nvd", "firm", "nvd_range", 1, 0),
  ("CVE-2030-0005", "redis", "<9", "nvd", "firm", "nvd_range", 0, 1),
  ("CVE-2030-0006", "redis", "<9", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0007", "redis", "<9", "cna", "tentative", "cna_range", 0, 0),
  ("CVE-2030-0010", "oldprod", ">=2.1,<3", "nvd", "firm", "nvd_range", 0, 0),  # starts inside the supported line
  ("CVE-2030-0011", "oldprod", "<1.9", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0012", "oldprod", ">=1.0,<1.8", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0013", "oldprod", ">=2.2,<2.5", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0013", "oldprod", "<1.2", "cna", "tentative", "cna_range", 0, 0),  # a row with no supported-line start
  ("CVE-2030-0014", "oldprod", "==2.3", "nvd", "tentative", "nvd_exact", 0, 0),  # `==` is a lower bound
  ("CVE-2030-0015", "oldprod", ">=2.5,<3", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0015", "oldprod", "<bogus", "nvd", "firm", "nvd_range", 0, 0),  # unparsed: counts as no lower bound
  ("CVE-2030-0016", "oldprod", ">=2.6,<3", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0016", "oldprod", ">=2.7,<3", "nvd", "firm", "nvd_range", 1, 1),  # any row flags the merged one
]


def build(dirpath, build_id="vulndb-aaaaaaaaaaaa", origin=None, kev=0, epss=0.5):
  db, pin = Path(dirpath) / ("%s.sqlite" % build_id), Path(dirpath) / ("%s.json" % build_id)
  make_db(db, rows=ROWS, build_id=build_id)
  conn = sqlite3.connect(db)
  conn.executescript(
    "CREATE TABLE cvss(cve_id TEXT, version TEXT, vector TEXT, score REAL, source TEXT);"
    "CREATE TABLE eol(product TEXT PRIMARY KEY, oldest_supported TEXT);"
    "INSERT INTO eol VALUES ('redis', '6.0'); INSERT INTO eol VALUES ('oldprod', '2.0');")
  conn.executemany("INSERT INTO cvss VALUES (?,?,?,?,?)", [
    (CVE, "4.0", V40, 9.3, "cna"), (CVE, "3.1", V31, 8.1, "nvd"), (CVE, "3.1", V31, 8.1, "cna")])
  conn.execute("UPDATE vuln SET kev = ?, epss = ?, display_cvss_version = '3.1', display_cvss_score = 8.1,"
               " display_cvss_source = 'nvd', severity = 'HIGH' WHERE cve_id = ?", (kev, epss, CVE))
  conn.execute("UPDATE vuln SET display_cvss_version = '4.0', display_cvss_score = 9.3, display_cvss_source = 'cna'"
               " WHERE cve_id = 'CVE-2030-0002'")
  conn.execute("UPDATE vuln SET severity = 'UNKNOWN', display_cvss_version = NULL WHERE cve_id = 'CVE-2030-0006'")
  conn.commit()
  conn.close()
  meta = {"build_id": build_id, "built_at": "2026-11-%s" % ("14" if build_id.endswith("a") else "15"),
          "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}
  if origin:
    meta["origin"] = origin
  pin.write_text(json.dumps(meta))
  return db, pin


class FindingFieldTests(unittest.TestCase):
  def setUp(self):
    self.addCleanup(cve_db.set_vulndb_reader, None)
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.dir = tmp.name

  def use(self, build_id="vulndb-aaaaaaaaaaaa", origin=None, **enrichment):
    reader, keys = load_vulndb("generated", *build(self.dir, build_id, origin, **enrichment))
    self.assertIsNone(keys["vulndb_load_error"])
    cve_db.set_vulndb_reader(reader)
    return reader

  def by_id(self, product, version, **kw):
    return {f.cve[0]: f for f in cve_db.check_cves(product, version, **kw) if f.cve}

  def test_static_changes_only_kev_and_reason(self):
    finding = self.by_id("openssh", "4.0")[CVE]
    self.assertIsNone(finding.kev)
    self.assertEqual((finding.confidence, finding.confidence_reason), ("tentative", "banner_only"))
    out = _finding_to_jsonable(finding)
    for key in ("vulndb_build_id", "cvss"):
      self.assertNotIn(key, out)
    self.assertEqual(out["cvss_source"], "nvd")
    self.assertIs(_finding_to_jsonable(cve_db.Finding(severity=cve_db.Severity.LOW, title="x", description="y"))["kev"], False)
    self.assertNotIn("confidence_reason", _finding_to_jsonable(cve_db.Finding(severity=cve_db.Severity.LOW, title="x", description="y")))

  def test_generated_fields(self):
    self.use()
    finding = self.by_id("openssh", "4.0")[CVE]
    self.assertEqual((finding.vulndb_build_id, finding.kev, finding.cvss_data_freshness),
                     ("vulndb-aaaaaaaaaaaa", False, "2026-11-14"))
    self.assertEqual((finding.cvss_version, finding.cvss_score, finding.cvss_source, finding.cvss_vector),
                     ("3.1", 8.1, "nvd", V31))
    self.assertEqual([(c["version"], c["source"]) for c in finding.cvss], [("3.1", "cna"), ("3.1", "nvd"), ("4.0", "cna")])
    self.assertEqual((finding.confidence, finding.confidence_reason), ("tentative", "banner_only"))
    self.assertEqual(finding.cwe_id, "CWE-362")  # frozen to the static row
    self.assertEqual(finding.cwe, (79,))  # display classification from the database
    self.assertEqual(_finding_to_jsonable(finding)["vulndb_build_id"], "vulndb-aaaaaaaaaaaa")

  def test_probe_confirmed_cve_names_build_and_kev(self):
    """A CVE a probe proves itself (Heartbleed) is a CVE finding too: build and KEV come from the database."""
    self.assertEqual(cve_db.probe_cve_fields(CVE), {"kev": None})  # static: KEV not evaluated
    self.use()
    self.assertEqual(cve_db.probe_cve_fields("CVE-2030-0011"), {"kev": True, "vulndb_build_id": "vulndb-aaaaaaaaaaaa"})
    self.assertEqual(cve_db.probe_cve_fields(CVE), {"kev": False, "vulndb_build_id": "vulndb-aaaaaaaaaaaa"})
    # No row in this build: the build is named, KEV stays not evaluated.
    self.assertEqual(cve_db.probe_cve_fields("CVE-1999-0001"), {"kev": None, "vulndb_build_id": "vulndb-aaaaaaaaaaaa"})

  def test_static_ignores_the_inferred_span(self):
    plain = self.by_id("openssl", "1.0.1f")
    spanned = self.by_id("openssl", "1.0.1f", inferred_span=("1.0.1", "1.0.1f"))
    self.assertIn("CVE-2016-2183", plain)  # the one static row that starts inside the span
    self.assertEqual({k: (f.confidence, f.confidence_reason) for k, f in plain.items()},
                     {k: (f.confidence, f.confidence_reason) for k, f in spanned.items()})

  def test_local_origin_has_no_freshness(self):
    self.use(origin="local")
    self.assertEqual(self.by_id("openssh", "4.0")[CVE].cvss_data_freshness, "")

  def test_reasons_and_label_rules(self):
    self.use()
    found = self.by_id("redis", "5.0")
    self.assertEqual({k: (f.confidence, f.confidence_reason) for k, f in found.items()}, {
      "CVE-2030-0002": ("tentative", "banner_only"),   # redis is a backported product, no package
      "CVE-2030-0003": ("tentative", "banner_only"),   # runtime reason outranks nvd_exact
      "CVE-2030-0004": ("tentative", "platform_dependent"),
      "CVE-2030-0006": ("tentative", "banner_only"),
      "CVE-2030-0007": ("tentative", "banner_only"),
    })
    v4 = found["CVE-2030-0002"]  # display CVSS 4.0: label empty, severity from the database
    self.assertEqual((v4.cvss_score, v4.cvss_vector, v4.cvss_source), (None, "", ""))
    self.assertEqual(found["CVE-2030-0006"].severity, cve_db.Severity.MEDIUM)  # UNKNOWN is not hidden
    self.assertTrue(found["CVE-2030-0002"].kev is False and found["CVE-2030-0002"].epss_score == 0.5)

  def test_unknown_tentative_reason_passes_through(self):
    reader = self.use()
    match = next(m for m in reader.query("redis", "5.0") if m.cve_id == "CVE-2030-0007")
    self.assertEqual(cve_db._confidence_reason("", match._replace(reason="future_reason"), "nonbackported"),
                     ("tentative", "future_reason"))

  def test_non_backported_product_keeps_the_row_reason(self):
    reader = self.use()
    rows = {m.cve_id: m for m in reader.query("redis", "5.0")}
    self.assertNotIn("nonbackported", cve_db._BACKPORTED_PRODUCTS)
    self.assertEqual(cve_db._confidence_reason("", rows["CVE-2030-0002"], "nonbackported"), ("firm", "nvd_range"))
    self.assertEqual(cve_db._confidence_reason("", rows["CVE-2030-0003"], "nonbackported"), ("tentative", "nvd_exact"))

  def test_findings_own_their_cvss_dicts(self):
    reader = self.use()
    finding = self.by_id("openssh", "4.0")[CVE]
    finding.cvss[0]["score"] = 0.0
    self.assertEqual(reader.query("openssh", "4.0")[0].cvss[0]["score"], 8.1)

  def test_eol_unassessed_and_the_unsupported_finding(self):
    self.use()
    found = cve_db.check_cves("oldprod", "1.5")
    cves = {f.cve[0]: f for f in found if f.cve}
    self.assertEqual(sorted(cves), ["CVE-2030-0010", "CVE-2030-0011", "CVE-2030-0012", "CVE-2030-0014"])
    # not 0013 (a row with no supported-line start), not 0015 (unparsed row); 0016 is client side (merged flag)
    self.assertEqual((cves["CVE-2030-0010"].confidence, cves["CVE-2030-0010"].confidence_reason), ("tentative", "eol_unassessed"))
    self.assertEqual(cves["CVE-2030-0014"].confidence_reason, "eol_unassessed")
    client = cve_db.check_cves("oldprod", "1.5", applicability=cve_db.CLIENT_APPLICABILITY)
    self.assertEqual([f for f in client if not f.cve], [])  # no unsupported finding for the client component
    self.assertEqual(cves["CVE-2030-0011"].confidence_reason, "nvd_range")  # matched by range, no lower bound
    self.assertEqual(cves["CVE-2030-0012"].confidence, "firm")
    unsupported = [f for f in found if not f.cve]
    self.assertEqual([(f.severity.value, f.confidence, f.finding_id == unsupported[0].finding_id) for f in unsupported],
                     [("HIGH", "firm", True)])
    self.assertEqual(unsupported[0].tags, ("vulndb_eol", "oldprod"))
    again = cve_db.check_cves("oldprod", "1.5")
    self.assertEqual([f.finding_id for f in again if not f.cve], [unsupported[0].finding_id])

  def test_the_merged_eol_row_is_flagged_when_any_row_is(self):
    reader = self.use()
    merged = next(m for m in reader.query("oldprod", "1.5") if m.cve_id == "CVE-2030-0016")
    self.assertEqual((merged.platform_dependent, merged.client_side, merged.reason), (1, 1, "eol_unassessed"))

  def test_two_unsupported_findings_on_one_port_collapse(self):
    self.use()
    eol = [_finding_to_jsonable(f) for f in cve_db.check_cves("oldprod", "1.5") if not f.cve][0]
    self.assertEqual(len(_dedup_finding_list([dict(eol), dict(eol, vulndb_build_id="vulndb-other")])), 1)

  def test_the_live_llm_payload_carries_the_view_under_generated_only(self):
    class Host(_RedMeshLlmAgentMixin):
      cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
    base = {"severity": "HIGH", "port": 80, "vulndb_build_id": "b", "confidence": "firm", "title": "t", "evidence": "e",
            "description": "apache 1.5 is vulnerable to CVE-2030-1. x", "cvss": []}
    findings = [dict(base, finding_id="a", cve=["CVE-2030-1"], kev=True, finding_signature="s1", title="CVE-2030-1: x"),
                dict(base, finding_id="b", cve=["CVE-2030-2"], kev=False, finding_signature="s2", title="CVE-2030-2: y")]
    def payload(items):
      report = {"nr_open_ports": 1, "ports_scanned": 1, "open_ports": [80], "correlation_findings": items}
      return Host()._build_llm_analysis_payload("j", report, {"scan_type": "network", "target": "t"}, "security_assessment")
    generated = payload(findings)
    self.assertEqual(generated["cve_view"]["counts"]["rolled_up"], 1)
    self.assertEqual(generated["cve_view"]["rollups"][0]["cve_count"], 1)
    self.assertEqual(generated["findings_summary"]["by_severity"], {"HIGH": 2})  # raw
    self.assertEqual(generated["findings_summary"]["cve_view_counts"]["listed"], 1)
    static = payload([dict(f, vulndb_build_id=None) for f in findings])
    self.assertNotIn("cve_view", static)
    self.assertNotIn("cve_view_counts", static["findings_summary"])

  def test_the_view_names_the_unsupported_finding_outside_raw(self):
    eol = {"finding_id": "eol1", "port": 80, "vulndb_build_id": "b", "tags": ["vulndb_eol", "apache"]}
    cve = {"finding_id": "c1", "cve": ["CVE-2030-1"], "vulndb_build_id": "b", "port": 80, "confidence": "firm", "kev": True,
           "description": "apache 1.5 is vulnerable to CVE-2030-1. x", "evidence": "Detected version: 1.5, affected: <2"}
    view = build_cve_view([cve, eol])
    self.assertEqual((view["services"][0]["unsupported"], view["counts"]["raw"]), ("eol1", 1))
    self.assertIsNone(build_cve_view([eol]))

  def test_llm_top_findings_send_listed_cves_only(self):
    class Host(_RedMeshLlmAgentMixin):
      def _extract_report_findings(self, report):
        return report["findings"]
    base = {"severity": "HIGH", "port": 80, "vulndb_build_id": "b", "confidence": "firm", "title": "t",
            "description": "apache 1.5 is vulnerable to CVE-2030-1. x", "evidence": "e"}
    findings = [dict(base, finding_id="a", cve=["CVE-2030-1"], kev=True, cvss=[], finding_signature="s1"),
                dict(base, finding_id="b", cve=["CVE-2030-2"], kev=False, cvss=[], finding_signature="s2")]
    compact, meta = Host()._build_llm_top_findings({"findings": findings}, "security_assessment")
    self.assertEqual([c["cve"] for c in compact], [["CVE-2030-1"]])
    self.assertEqual(meta["total_findings"], 2)

  def test_supported_version_and_product_without_eol_row_have_no_eol_findings(self):
    self.use()
    self.assertEqual([f.cve[0] for f in cve_db.check_cves("oldprod", "2.2") if not f.cve], [])
    self.assertEqual([f for f in cve_db.check_cves("oldprod", "2.2") if f.confidence_reason == "eol_unassessed"], [])
    self.assertTrue(all(f.cve for f in cve_db.check_cves("openssh", "4.0")))

  def test_package_not_fixed_is_firm_distro_package(self):
    self.use()
    package = cve_db.parse_distro_package("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    finding = self.by_id("openssh", "8.9p1", package=package)[CVE]
    self.assertEqual((finding.confidence, finding.confidence_reason, finding.backport_status),
                     ("firm", "distro_package", "not_fixed"))
    fixed = cve_db.parse_distro_package("OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
    self.assertNotIn(CVE, self.by_id("openssh", "8.9p1", package=fixed))

  def test_client_side_goes_to_the_collector(self):
    self.use()
    collector = {}
    token = cve_db.set_not_applicable_collector(collector)
    try:
      self.assertNotIn("CVE-2030-0005", self.by_id("redis", "5.0"))
      self.assertIn("CVE-2030-0005", self.by_id("redis", "5.0", applicability=cve_db.CLIENT_APPLICABILITY))
    finally:
      cve_db.reset_not_applicable_collector(token)
    self.assertEqual([v["reason"] for v in collector.values()], ["client_side"])

  def test_ids_stable_across_builds_and_sources_signature_moves_with_score(self):
    static = self.by_id("openssh", "4.0")[CVE]
    self.use("vulndb-aaaaaaaaaaaa")
    first = self.by_id("openssh", "4.0")[CVE]
    self.use("vulndb-bbbbbbbbbbbb")
    second = self.by_id("openssh", "4.0")[CVE]
    self.assertEqual(static.finding_id, first.finding_id)
    self.assertEqual(first.finding_id, second.finding_id)
    self.assertEqual(first.finding_signature, second.finding_signature)  # build id is not content
    self.assertNotEqual(static.finding_signature, first.finding_signature)  # score and vector are

  def test_kev_flip_moves_the_signature_and_keeps_the_id(self):
    # RM-258. Failing input: CVE-2024-6387 with kev 0 -> 1, nothing else changed.
    self.use(kev=0)
    before = self.by_id("openssh", "4.0")[CVE]
    self.use(kev=1)
    after = self.by_id("openssh", "4.0")[CVE]
    self.assertEqual((before.kev, after.kev), (False, True))
    self.assertEqual(before.finding_id, after.finding_id)
    self.assertNotEqual(before.finding_signature, after.finding_signature)

  def test_epss_moves_the_signature_only_across_a_band(self):
    # RM-258. Failing input: epss 0.05 -> 0.6 must move it; 0.5 -> 0.7 (same band) must not.
    def sig(epss):
      self.use(epss=epss)
      return self.by_id("openssh", "4.0")[CVE]
    low, mid, high, higher = sig(0.05), sig(0.5), sig(0.6), sig(0.7)
    self.assertNotEqual(low.finding_signature, high.finding_signature)
    self.assertEqual(mid.finding_signature, higher.finding_signature)
    self.assertEqual(low.finding_id, high.finding_id)

  def test_dedup_across_two_pins_follows_freshness(self):
    self.use("vulndb-aaaaaaaaaaaa")
    old = _finding_to_jsonable(self.by_id("openssh", "4.0")[CVE])
    self.use("vulndb-bbbbbbbbbbbb")
    new = _finding_to_jsonable(self.by_id("openssh", "4.0")[CVE])
    for order in ((old, new), (new, old)):
      merged = _dedup_finding_list([dict(order[0]), dict(order[1])])
      self.assertEqual(len(merged), 1)
      self.assertEqual((merged[0]["vulndb_build_id"], merged[0]["cvss_data_freshness"]),
                       ("vulndb-bbbbbbbbbbbb", "2026-11-15"))


class LocalVectorReasonTests(unittest.TestCase):
  """`local_vector` (step 2d): every v3 vector is AV:L or AV:P, so a banner cannot show the CVE applies."""

  @staticmethod
  def match(*vectors, confidence="firm", reason="nvd_range", pdep=0):
    cvss = tuple({"version": v.split("/")[0].split(":")[1], "vector": v, "score": 7.0, "source": "nvd"} for v in vectors)
    return type("M", (), {"confidence": confidence, "reason": reason, "platform_dependent": pdep, "cvss": cvss})()

  def reason(self, match, product="exim", status=cve_db.BACKPORT_UNKNOWN_NO_PACKAGE):
    return cve_db._confidence_reason(status, match, product)

  def test_local_only_is_tentative_local_vector(self):
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    self.assertEqual(self.reason(self.match(local), product="libssh"), ("tentative", "local_vector"))
    self.assertEqual(self.reason(self.match("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), product="libssh"),
                     ("tentative", "local_vector"))

  def test_any_network_or_adjacent_vector_keeps_the_build_reason(self):
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    for other in (V31, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
      self.assertEqual(self.reason(self.match(local, other), product="libssh"), ("firm", "nvd_range"))

  def test_no_v3_vector_is_not_local(self):
    self.assertEqual(self.reason(self.match(V40), product="libssh"), ("firm", "nvd_range"))
    self.assertEqual(self.reason(self.match(), product="libssh"), ("firm", "nvd_range"))

  def test_order_around_local_vector(self):
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    self.assertEqual(self.reason(self.match(local, pdep=1)), ("tentative", "platform_dependent"))
    self.assertEqual(self.reason(self.match(local, confidence="tentative", reason="inferred_version")),
                     ("tentative", "inferred_version"))
    self.assertEqual(self.reason(self.match(local)), ("tentative", "local_vector"))  # exim is a backported product

  def test_static_has_no_local_vector(self):
    for f in cve_db.check_cves("exim", "4.70"):
      self.assertNotEqual(f.confidence_reason, "local_vector")


class PluginWiringTests(unittest.TestCase):
  def run_init(self, source, db=None, pin=None):
    Plugin = api_fixtures.TestPhase3Archive()._get_plugin_class()
    base = next(cls for cls in Plugin.__mro__[1:] if "on_close" in cls.__dict__)
    plugin = Plugin.__new__(Plugin)
    plugin.cfg_vulndb_source = source
    plugin.P = lambda *a, **k: None
    with patch.object(base, "on_init", create=True), \
         patch("extensions.business.cybersec.red_mesh.pentester_api_01.load_vulndb",
               side_effect=lambda requested: load_vulndb(requested, db, pin) if db else load_vulndb(requested)):
      try:
        Plugin.on_init(plugin)
      except Exception:
        pass  # later init steps need the plugin runtime; the database is loaded first
    return Plugin, plugin

  def tearDown(self):
    cve_db.set_vulndb_reader(None)

  def test_generated_reaches_check_cves_and_the_capability_status(self):
    with tempfile.TemporaryDirectory() as tmp:
      Plugin, plugin = self.run_init("generated", *build(tmp))
      self.assertIsNotNone(cve_db._VULNDB_READER)
      with patch("extensions.business.cybersec.red_mesh.pentester_api_01.get_capability_status",
                 return_value={"model": 1}):
        status = Plugin.get_capability_status(plugin)
    self.assertEqual((status["model"], status["vulndb_source"], status["vulndb_build_id"], status["vulndb_load_error"]),
                     (1, "generated", "vulndb-aaaaaaaaaaaa", None))

  def test_load_failure_falls_back_to_static(self):
    cve_db.set_vulndb_reader(object())  # a stale reader must be reset by init
    with tempfile.TemporaryDirectory() as tmp:
      Plugin, plugin = self.run_init("generated", Path(tmp) / "none.sqlite", Path(tmp) / "none.json")
      self.assertIsNone(cve_db._VULNDB_READER)
      with patch("extensions.business.cybersec.red_mesh.pentester_api_01.get_capability_status", return_value={}):
        status = Plugin.get_capability_status(plugin)
    self.assertEqual((status["vulndb_source"], status["vulndb_build_id"]), ("static", None))
    self.assertTrue(status["vulndb_load_error"])

  def test_default_source_is_generated(self):
    """RM-169 Phase 3 (owner, 2026-11-17): `generated` by default; `static` stays the rollback value."""
    Plugin = api_fixtures.TestPhase3Archive()._get_plugin_class()
    self.assertEqual(Plugin.CONFIG["VULNDB_SOURCE"], "generated")


if __name__ == "__main__":
  unittest.main()
