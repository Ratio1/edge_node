"""RM-263: a probe CVE finding carries the database's EPSS and `cvss[]`, and a CVE-view subject (product)."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_view import build_cve_view
from extensions.business.cybersec.red_mesh.findings import Finding, Severity, _finding_to_jsonable
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin
from extensions.business.cybersec.red_mesh.vulndb.reader import load_vulndb

from .test_vulndb_reader import make_db

HEARTBLEED = "CVE-2014-0160"
JAVA = "CVE-2017-10271"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
ROWS = [
  (HEARTBLEED, "openssl", ">=1.0.1,<1.0.1g", "nvd", "firm", "nvd_range", 0, 0),
  (JAVA, "weblogic", ">=10.3.6,<12.2.2", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0001", "multi", "<2", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-0001", "other", "<2", "nvd", "firm", "nvd_range", 0, 0),
]
CVSS = {"version": "3.1", "vector": V31, "score": 7.5, "source": "nvd"}


class _Host(_RiskScoringMixin):
  pass


def probe_finding(cve, title=None, severity=Severity.HIGH, **kw):
  """A probe finding as the call sites build it: label and score its own, database fields spread last."""
  return Finding(severity=severity, title=title or "%s probe" % cve, description="d", cve=(cve,),
                 confidence="certain", cvss_score=8.0, cvss_vector="PROBE", **kw, **cve_db.probe_cve_fields(cve))


class ProbeEnrichmentTests(unittest.TestCase):
  def setUp(self):
    self.addCleanup(cve_db.set_vulndb_reader, None)

  def load(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    db, pin = Path(tmp.name) / "v.sqlite", Path(tmp.name) / "v.json"
    make_db(db, rows=ROWS, build_id="vulndb-aaaaaaaaaaaa")
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE cvss(cve_id TEXT, version TEXT, vector TEXT, score REAL, source TEXT);"
                       "CREATE TABLE eol(product TEXT PRIMARY KEY, oldest_supported TEXT);")
    conn.executemany("INSERT INTO cvss VALUES (?,?,?,?,?)", [(c, *CVSS.values()) for c in (HEARTBLEED, JAVA)])
    conn.execute("UPDATE vuln SET epss = 0.97 WHERE cve_id IN (?, ?)", (HEARTBLEED, JAVA))
    conn.commit(); conn.close()
    pin.write_text(json.dumps({"build_id": "vulndb-aaaaaaaaaaaa", "built_at": "2026-11-14",
                               "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}))
    reader, keys = load_vulndb("generated", db, pin)
    self.assertIsNone(keys["vulndb_load_error"])
    cve_db.set_vulndb_reader(reader)

  def test_heartbleed_and_java_carry_epss_cvss_and_product_with_a_reader(self):
    self.load()
    for cve, product in ((HEARTBLEED, "openssl"), (JAVA, "weblogic")):
      out = _finding_to_jsonable(probe_finding(cve))
      self.assertEqual((out["epss_score"], out["cvss"], out["product"]), (0.97, [CVSS], product), cve)
      self.assertNotIn("version", out)  # the probe knows no version: none is invented
      # the probe's own label and score are untouched
      self.assertEqual((out["cvss_score"], out["cvss_vector"], out["severity"]), (8.0, "PROBE", "HIGH"))

  def test_probe_matches_the_row_the_database_gives_a_version_match(self):
    self.load()
    row = {f.cve[0]: f for f in cve_db.check_cves("openssl", "1.0.1a")}[HEARTBLEED]
    probe = probe_finding(HEARTBLEED)
    self.assertEqual((probe.epss_score, probe.cvss, probe.kev), (row.epss_score, row.cvss, row.kev))

  def test_a_cve_on_several_products_names_none(self):
    self.load()
    self.assertEqual(cve_db.probe_cve_fields("CVE-2030-0001").get("product", ""), "")

  def test_a_probe_hint_picks_one_of_several_products(self):
    self.load()
    self.assertEqual(cve_db.probe_cve_fields("CVE-2030-0001", product_hint="multi")["product"], "multi")
    # A hint the build does not name for the CVE is ignored.
    self.assertEqual(cve_db.probe_cve_fields("CVE-2030-0001", product_hint="nope").get("product", ""), "")

  def test_a_cve_the_build_lacks_gets_no_enrichment(self):
    self.load()
    fields = cve_db.probe_cve_fields("CVE-2099-0001")
    self.assertEqual((fields["kev"], fields.get("epss_score"), fields.get("cvss", ()), fields.get("product", "")),
                     (None, None, (), ""))

  def test_without_a_reader_the_fields_are_today_s(self):
    self.assertEqual(cve_db.probe_cve_fields(HEARTBLEED), {"kev": None})
    out = _finding_to_jsonable(probe_finding(HEARTBLEED))
    for key in ("product", "version", "cvss", "vulndb_build_id"):
      self.assertNotIn(key, out)
    self.assertIsNone(out["epss_score"])

  def test_view_groups_a_probe_finding_with_the_service_row(self):
    self.load()
    row = _finding_to_jsonable({f.cve[0]: f for f in cve_db.check_cves("openssl", "1.0.1a")}[HEARTBLEED])
    other = _finding_to_jsonable(cve_db.check_cves("weblogic", "10.3.6")[0])
    probe = _finding_to_jsonable(probe_finding(JAVA))
    for f, port in ((row, 443), (other, 7001), (probe, 7001)):
      f["port"] = port
    other["finding_id"], probe["finding_id"] = "row", "probe"
    row["finding_id"] = "tls"
    services = {(s["port"], s["product"]) for s in build_cve_view([row, other, probe])["services"]}
    self.assertEqual(services, {(443, "openssl"), (7001, "weblogic")})

  def view(self, *findings):
    row = _finding_to_jsonable({f.cve[0]: f for f in cve_db.check_cves("openssl", "1.0.1a")}[HEARTBLEED])
    row.update(port=443, finding_id="r", confidence="firm", kev=False, cvss=[])
    other = dict(row, cve=["CVE-2099-1"], finding_id="r2")
    probes = []
    for name, kw in findings:
      p = _finding_to_jsonable(probe_finding(HEARTBLEED))
      p.update(port=443, finding_id=name, **kw)
      probes.append(p)
    return build_cve_view([other, *probes])["services"][0]

  def test_a_probe_member_keeps_the_service_version(self):
    self.load()
    for kw in ({"kev": True}, {"kev": False, "cvss": []}):
      service = self.view(("p", kw))
      self.assertEqual((service["product"], service["version"]), ("openssl", "1.0.1a"), kw)

  def test_a_probe_member_without_evidence_keeps_the_rollup_fix_version(self):
    self.load()
    service = self.view(("p", {"kev": False, "cvss": []}))
    self.assertEqual((service["rollup"]["fix_version"], service["rollup"]["cve_count"]), ("1.0.1g", 2))

  def test_a_service_of_probe_members_only_has_no_version_or_fix(self):
    self.load()
    p = _finding_to_jsonable(probe_finding(HEARTBLEED))
    p.update(port=443, finding_id="p", cvss=[])
    service = build_cve_view([p])["services"][0]
    self.assertEqual((service["version"], service["rollup"]["fix_version"]), ("", None))

  def test_identity_signature_moves_by_epss_band_only_finding_id_stays(self):
    plain = probe_finding(HEARTBLEED)
    ident = {"probe_id": "tls", "asset_canonical": ""}
    before = (plain.compute_signature(**ident), plain.compute_dedup_key(**ident))
    self.load()
    rich = probe_finding(HEARTBLEED)
    self.assertEqual(rich.compute_dedup_key(**ident), before[1])
    self.assertNotEqual(rich.compute_signature(**ident), before[0])  # EPSS is content (RM-258)
    # product and cvss[] are not content: same epss on both leaves the signature alone
    from dataclasses import replace
    self.assertEqual(replace(rich, product="x", cvss=()).compute_signature(**ident), rich.compute_signature(**ident))

  def test_the_probe_finding_that_wins_the_cve_dedup_keeps_epss_and_product(self):
    self.load()
    probe = _finding_to_jsonable(probe_finding(HEARTBLEED, title="TLS Heartbleed vulnerability (%s)" % HEARTBLEED,
                                          severity=Severity.CRITICAL))
    row = _finding_to_jsonable({f.cve[0]: f for f in cve_db.check_cves("openssl", "1.0.1a")}[HEARTBLEED])
    report = {"target": "t", "service_info": {"443/tcp": {"tls": {"findings": [probe, row]}}}}
    _risk, flat = _Host()._compute_risk_and_findings(report)
    survivors = [f for f in flat if HEARTBLEED in (f.get("cve") or ())]
    self.assertEqual(len(survivors), 1)
    self.assertEqual((survivors[0]["cvss_vector"], survivors[0]["epss_score"], survivors[0]["product"]),
                     ("PROBE", 0.97, "openssl"))


if __name__ == "__main__":
  unittest.main()
