"""RM-061 R4: a honeypot verdict folds the host's CVE rows (D42); RM-086 body checks for Ignition, /.env, /.git/."""

import unittest
from dataclasses import replace
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_view import build_cve_view
from extensions.business.cybersec.red_mesh.findings import probe_port_scope, probe_result
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.correlation import (
  _port_ratio_fires, apply_host_honeypot_verdict, host_honeypot_verdict,
)

from .test_probes import DummyOwner

DISCOVERY = "extensions.business.cybersec.red_mesh.worker.web.discovery.requests."


def cve_row(port, n, confidence="firm", reason="nvd_range", kev=False):
  return {
    "finding_id": f"id-{port}-{n}", "cve": [f"CVE-2020-{n:04d}"], "vulndb_build_id": "b1", "port": port,
    "severity": "HIGH", "confidence": confidence, "confidence_reason": reason, "kev": kev,
    "title": f"CVE-2020-{n:04d}: apache 2.2.22", "description": "apache 2.2.22 is vulnerable to CVE.",
    "evidence": "Detected version: 2.2.22, affected: <2.4", "finding_signature": "old",
  }


def web_row():
  return {"finding_id": "web-1", "severity": "MEDIUM", "confidence": "certain", "title": "Accessible resource: /admin"}


def report(open_ports, scanned=1000, os_claims=None, rows=None):
  """A merged job report, as `_get_aggregated_report` returns it."""
  return {
    "open_ports": list(open_ports), "ports_scanned": scanned,
    "scan_metadata": {"os_claims": os_claims or {}},
    "service_info": {8080: {"_service_info_http": {"findings": rows if rows is not None else [cve_row(8080, 1), cve_row(8080, 2)]}}},
    "web_tests_info": {8080: {"_web_test_common": {"findings": [web_row()]}}},
  }


def cve_rows(rep):
  return [f for info in rep["service_info"].values() for m in info.values() for f in m["findings"]]


class HoneypotFoldTests(unittest.TestCase):
  def test_port_ratio_verdict_demotes_cve_rows_and_keeps_them(self):
    rep = report(range(1, 601))
    self.assertEqual(apply_host_honeypot_verdict(rep), "port_ratio")
    rows = cve_rows(rep)
    self.assertEqual(len(rows), 2)
    for r in rows:
      self.assertEqual((r["confidence"], r["confidence_reason"]), ("tentative", "banner_unverified"))
      self.assertIn("honeypot_verdict=port_ratio", r["evidence"])
      self.assertIn("demoted_from=firm:nvd_range", r["evidence"])
      self.assertIn("Detected version: 2.2.22", r["evidence"])
      self.assertEqual(r["finding_id"], f"id-8080-{r['cve'][0][-1]}")

  def test_demoted_rows_fold_in_cve_view(self):
    rep = report(range(1, 601))
    apply_host_honeypot_verdict(rep)
    counts = build_cve_view(cve_rows(rep))["counts"]
    self.assertEqual((counts["raw"], counts["folded"], counts["listed"], counts["rolled_up"]), (2, 2, 0, 0))

  def test_signature_is_recomputed_like_confirm_cve(self):
    # probe id `x` is unregistered, so no probe enrichment moves hashed fields between the stamp and the row.
    with probe_port_scope(22):  # as in a scan: the identity is stamped inside the port scope
      base = replace(next(f for f in cve_db.check_cves("openssh", "8.9") if not f.kev), epss_score=0.4237)  # banded in the payload
      row = probe_result(findings=[base], probe_id="x")["findings"][0]
      mark = f"honeypot_verdict=port_ratio; demoted_from={row['confidence']}:{row['confidence_reason']}"
      expected = probe_result(findings=[cve_db.confirm_cve(base, "openssh", "8.9", mark, unverified=True)],
                              probe_id="x")["findings"][0]
    row["vulndb_build_id"] = "b1"  # the static table stamps no build id; the view and the fold read generated rows
    old_sig, old_id = row["finding_signature"], row["finding_id"]
    rep = report(range(1, 601))
    rep["service_info"] = {22: {"_service_info_ssh": {"findings": [row]}}}
    apply_host_honeypot_verdict(rep)
    self.assertNotEqual(row["finding_signature"], old_sig)
    self.assertEqual(row["finding_id"], old_id)
    self.assertEqual(row["epss_score"], 0.4237)
    self.assertEqual(row["finding_signature"], expected["finding_signature"])

  def test_os_mismatch_verdict_over_merged_claims(self):
    rep = report([22, 80], os_claims={"ssh:22": "Ubuntu", "redis:6379": "Darwin 21.6.0"})
    self.assertEqual(apply_host_honeypot_verdict(rep), "os_mismatch")
    for r in cve_rows(rep):
      self.assertIn("honeypot_verdict=os_mismatch", r["evidence"])

  def test_non_cve_rows_untouched(self):
    rep = report(range(1, 601))
    apply_host_honeypot_verdict(rep)
    self.assertEqual(rep["web_tests_info"][8080]["_web_test_common"]["findings"], [web_row()])

  def test_vulhub_like_host_keeps_firm_rows(self):
    rep = report(range(8000, 8057))  # 57 open of 1000: ratio not met
    self.assertIsNone(apply_host_honeypot_verdict(rep))
    for r in cve_rows(rep):
      self.assertEqual((r["confidence"], r["confidence_reason"]), ("firm", "nvd_range"))
      self.assertNotIn("honeypot_verdict", r["evidence"])

  def test_second_run_does_not_duplicate_evidence(self):
    rep = report(range(1, 601))
    apply_host_honeypot_verdict(rep)
    apply_host_honeypot_verdict(rep)
    for r in cve_rows(rep):
      self.assertEqual(r["evidence"].count("honeypot_verdict="), 1)

  def test_other_tentative_reason_is_demoted_and_recorded(self):
    rep = report(range(1, 601), rows=[cve_row(8080, 1, "tentative", "backport_unknown")])
    apply_host_honeypot_verdict(rep)
    row = cve_rows(rep)[0]
    self.assertEqual(row["confidence_reason"], "banner_unverified")
    self.assertIn("demoted_from=tentative:backport_unknown", row["evidence"])

  def test_already_unverified_row_keeps_one_mark_and_no_demoted_from(self):
    rep = report(range(1, 601), rows=[cve_row(8080, 1, "tentative", "banner_unverified")])
    apply_host_honeypot_verdict(rep)
    self.assertNotIn("demoted_from", cve_rows(rep)[0]["evidence"])

  def test_kev_and_certain_rows_are_exempt(self):
    rows = [cve_row(8080, 1, kev=True), cve_row(8080, 2, "certain", "behaviour_confirmed"), cve_row(8080, 3)]
    rep = report(range(1, 601), rows=rows)
    apply_host_honeypot_verdict(rep)
    self.assertEqual([r["confidence"] for r in rows], ["firm", "certain", "tentative"])
    self.assertNotIn("honeypot_verdict", rows[0]["evidence"] + rows[1]["evidence"])

  def test_every_mirror_copy_is_demoted(self):
    rep = report(range(1, 601), rows=[cve_row(8080, 1), cve_row(8080, 1)])
    rep["service_info"][8080]["_service_info_other"] = {"findings": [cve_row(8080, 1)]}
    apply_host_honeypot_verdict(rep)
    self.assertEqual({r["confidence"] for r in cve_rows(rep)}, {"tentative"})
    self.assertEqual(len(cve_rows(rep)), 3)


class HostVerdictOverBatchesTests(unittest.TestCase):
  """The verdict is per host: a worker sees one slice of the ports, the merged report sees them all."""

  def test_honeypot_split_over_16_batches_is_still_detected(self):
    # T-Pot 1-300: ~19 open of 19 scanned per batch never meets the >20 rule alone; merged, 300 of 300 does.
    batch_ports = [list(range(i * 19 + 1, i * 19 + 20)) for i in range(16)]
    self.assertTrue(all(not _port_ratio_fires(len(b), len(b)) for b in batch_ports))
    merged = report([p for b in batch_ports for p in b], scanned=sum(len(b) for b in batch_ports))
    self.assertEqual(host_honeypot_verdict(merged), "port_ratio")

  def test_normal_host_over_16_batches_never_demotes(self):
    merged = report([22, 80, 443, 8080], scanned=16 * 63)
    self.assertIsNone(apply_host_honeypot_verdict(merged))
    self.assertEqual({r["confidence"] for r in cve_rows(merged)}, {"firm"})

  def test_os_claims_split_over_batches_mismatch_after_merge(self):
    merged = report([22], os_claims={"ssh:22": "Ubuntu", "snmp:161": "Windows 10"})
    self.assertEqual(host_honeypot_verdict(merged), "os_mismatch")

  def test_worker_list_scanned_is_accepted(self):
    self.assertEqual(host_honeypot_verdict({"open_ports": list(range(30)), "ports_scanned": list(range(40))}), "port_ratio")


def fake_get_factory(routes):
  def fake_get(url, **kw):
    resp = MagicMock()
    resp.headers = {}
    resp.ok = False
    resp.status_code = 404
    resp.text = ""
    for suffix, (status, body) in routes.items():
      if url.endswith(suffix):
        resp.status_code, resp.text, resp.ok = status, body, status == 200
    return resp
  return fake_get


class BodyCheckTests(unittest.TestCase):
  def _w(self):
    w = PentestLocalWorker(owner=DummyOwner(), target="example.com", job_id="j", initiator="i@e",
                           local_id_prefix="1", worker_target_ports=[80])
    w.state["scan_metadata"] = {}
    w.stop_event = MagicMock()
    w.stop_event.is_set.return_value = False
    return w

  def titles(self, routes, probe="_web_test_common", port=80):
    with patch(DISCOVERY + "get", side_effect=fake_get_factory(routes)), patch(DISCOVERY + "post", side_effect=fake_get_factory({})):
      result = getattr(self._w(), probe)("example.com", port)
    return [f["title"] for f in result["findings"]]

  def test_env_with_key_value_body_is_reported(self):
    self.assertIn("Accessible resource: /.env", self.titles({"/.env": (200, "APP_KEY=base64:abc\nDB_PASSWORD=x\n")}))

  def test_env_html_200_is_not_reported(self):
    self.assertNotIn("Accessible resource: /.env", self.titles({"/.env": (200, "<html>hello</html>")}))

  def test_env_accepts_export_and_indent_rejects_inline_script_html(self):
    self.assertIn("Accessible resource: /.env", self.titles({"/.env": (200, "export APP_KEY=abc\n")}))
    self.assertIn("Accessible resource: /.env", self.titles({"/.env": (200, "  DB_HOST=localhost\n")}))
    self.assertNotIn("Accessible resource: /.env",
                     self.titles({"/.env": (200, "<script>\nwindow.__STATE__ = {}\n</script>")}))
    self.assertNotIn("Accessible resource: /.env", self.titles({"/.env": (200, "\n  <p>x</p>\nwindow.__STATE__ = {}")}))

  def test_git_head_with_ref_or_sha_is_reported(self):
    self.assertIn("Accessible resource: /.git/", self.titles({"/.git/HEAD": (200, "ref: refs/heads/main\n")}))
    self.assertIn("Accessible resource: /.git/", self.titles({"/.git/HEAD": (200, "a" * 40 + "\n")}))

  def test_git_config_core_is_reported(self):
    self.assertIn("Accessible resource: /.git/", self.titles({"/.git/config": (200, "[core]\n\trepositoryformatversion = 0")}))

  def test_git_listing_naming_head_and_refs_is_reported(self):
    self.assertIn("Accessible resource: /.git/", self.titles({"/.git/": (200, "<a href=\"HEAD\">HEAD</a> <a href=\"refs/\">refs/</a>")}))

  def test_git_probe_timeout_keeps_findings_already_collected(self):
    import requests as rq
    base = fake_get_factory({"/admin": (200, "x")})

    def get(url, **kw):
      if url.endswith("/.git/HEAD"):
        raise rq.exceptions.Timeout("slow")
      return base(url, **kw)
    with patch(DISCOVERY + "get", side_effect=get):
      result = self._w()._web_test_common("example.com", 80)
    self.assertIn("Accessible resource: /admin", [f["title"] for f in result["findings"]])

  def test_git_403_and_plain_html_are_not_reported(self):
    self.assertNotIn("Accessible resource: /.git/", self.titles({"/.git/": (403, "Forbidden")}))
    self.assertNotIn("Accessible resource: /.git/", self.titles({"/.git/": (200, "<html>Welcome</html>"),
                                                                 "/.git/HEAD": (200, "<html>Welcome</html>")}))

  def test_ignition_bare_ok_is_not_reported(self):
    t = self.titles({"/_ignition/health-check": (200, "OK")}, probe="_web_test_cms_fingerprint")
    self.assertFalse(any("Ignition" in x for x in t))

  def test_ignition_json_shape_is_reported(self):
    t = self.titles({"/_ignition/health-check": (200, '{"can_execute_commands":true}')}, probe="_web_test_cms_fingerprint")
    self.assertTrue(any("Ignition" in x for x in t))
