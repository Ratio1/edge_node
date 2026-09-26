"""RM-103 item 6: CVEs evaluated and found not applicable are listed, not dropped.

A client asked why CVE-2025-26465 (an OpenSSH client-side flaw) and
CVE-2024-6387 (regreSSHion, fixed by USN-6859-1 on Ubuntu 3ubuntu0.10) were
absent from the report of a host whose upstream version both match. The matcher
did evaluate them and skipped them silently, so the report could not show the
work. Each skip for one of those two reasons is now recorded, per port, in a
scan-local collector the worker emits as `cves_not_applicable`.

A version outside a CVE's range was never applicable and is not recorded.
"""

import unittest

from extensions.business.cybersec.red_mesh.cve_db import (
  NOT_APPLICABLE_BACKPORT_FIXED,
  NOT_APPLICABLE_CLIENT_SIDE,
  check_cves,
  parse_distro_package,
  reset_not_applicable_collector,
  set_not_applicable_collector,
)
from extensions.business.cybersec.red_mesh.findings import probe_port_scope
from extensions.business.cybersec.red_mesh.models.reports import (
  AggregatedScanData,
  NodeReport,
  ThreadReport,
)
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"


def _collect(product, version, *, package=None, port=22):
  collector = {}
  token = set_not_applicable_collector(collector)
  try:
    with probe_port_scope(port):
      findings = check_cves(product, version, package=package)
  finally:
    reset_not_applicable_collector(token)
  return findings, collector


class TestCheckCvesRecordsWhatItSkips(unittest.TestCase):

  def test_the_ubuntu_banner_lists_both_cves_with_their_reason(self):
    _findings, collector = _collect("openssh", "8.9", package=parse_distro_package(BANNER))
    client = collector["22/CVE-2025-26465"]
    self.assertEqual(client["reason"], NOT_APPLICABLE_CLIENT_SIDE)
    self.assertEqual((client["product"], client["version"], client["port"]), ("openssh", "8.9", 22))
    backport = collector["22/CVE-2024-6387"]
    self.assertEqual(backport["reason"], NOT_APPLICABLE_BACKPORT_FIXED)
    self.assertEqual(backport["advisory"], "USN-6859-1")
    self.assertEqual(backport["fixed_revision"], "3ubuntu0.10")
    self.assertEqual(backport["package"], "ubuntu 8.9p1-3ubuntu0.10")

  def test_a_version_outside_the_range_is_not_recorded(self):
    # CVE-2019-6111 is client-side but `<8.1`: never in scope for 8.9.
    _findings, collector = _collect("openssh", "8.9", package=parse_distro_package(BANNER))
    self.assertNotIn("22/CVE-2019-6111", collector)
    self.assertEqual(
      {e["reason"] for e in collector.values()},
      {NOT_APPLICABLE_CLIENT_SIDE, NOT_APPLICABLE_BACKPORT_FIXED},
    )

  def test_reported_cves_are_never_listed_as_not_applicable(self):
    # 8.4 without a package reports CVE-2021-41617 and skips client-side rows.
    findings, collector = _collect("openssh", "8.4")
    reported = {f.cve[0] for f in findings}
    listed = {e["cve_id"] for e in collector.values()}
    self.assertTrue(reported)
    self.assertFalse(reported & listed)

  def test_the_findings_do_not_depend_on_the_collector(self):
    package = parse_distro_package(BANNER)
    with_collector, _ = _collect("openssh", "8.9", package=package)
    without = check_cves("openssh", "8.9", package=package)
    self.assertEqual([f.cve for f in with_collector], [f.cve for f in without])

  def test_no_collector_records_nothing_and_does_not_fail(self):
    self.assertTrue(check_cves("openssh", "8.9"))

  def test_without_a_package_nothing_is_backport_fixed(self):
    findings, collector = _collect("openssh", "8.9")
    self.assertIn("CVE-2024-6387", {f.cve[0] for f in findings})
    self.assertEqual({e["reason"] for e in collector.values()}, {NOT_APPLICABLE_CLIENT_SIDE})
    self.assertEqual(collector["22/CVE-2025-26465"]["package"], "")


class TestWorkerEmitsTheList(unittest.TestCase):

  def _worker(self):
    from extensions.business.cybersec.red_mesh.tests.test_probes import DummyOwner
    return PentestLocalWorker(
      owner=DummyOwner(), target="example.com", job_id="job-1",
      initiator="init@example", local_id_prefix="1", worker_target_ports=[22],
    )

  def test_the_run_collects_into_state_and_status(self):
    worker = self._worker()
    worker.PHASE_EXECUTION_PLAN = [{"name": "stub"}]

    def phase(_config):
      with probe_port_scope(22):
        check_cves("openssh", "8.9", package=parse_distro_package(BANNER))

    worker._execute_phase = phase
    worker.execute_job()
    self.assertIn("22/CVE-2025-26465", worker.state["cves_not_applicable"])
    self.assertIn("22/CVE-2024-6387", worker.get_status()["cves_not_applicable"])

  def test_an_empty_list_is_not_emitted(self):
    self.assertNotIn("cves_not_applicable", self._worker().get_status())

  def test_the_field_merges_as_a_dict(self):
    self.assertIs(PentestLocalWorker.get_worker_specific_result_fields()["cves_not_applicable"], dict)


class TestTheListSurvivesAggregationAndArchive(unittest.TestCase):

  A = {"22/CVE-2025-26465": {"cve_id": "CVE-2025-26465", "port": 22, "reason": "client_side"}}
  B = {"2222/CVE-2024-6387": {"cve_id": "CVE-2024-6387", "port": 2222, "reason": "backport_fixed"}}

  def test_two_workers_merge_into_one_dict(self):
    from extensions.business.cybersec.red_mesh.tests.test_finalization_aggregation import _Host
    reports = {
      "w1": {"job_id": "j", "service_info": {}, "web_tests_info": {}, "completed_tests": [],
             "open_ports": [22], "cves_not_applicable": dict(self.A)},
      "w2": {"job_id": "j", "service_info": {}, "web_tests_info": {}, "completed_tests": [],
             "open_ports": [2222], "cves_not_applicable": dict(self.B)},
    }
    agg = _Host()._get_aggregated_report(reports, worker_cls=PentestLocalWorker)
    self.assertEqual(set(agg["cves_not_applicable"]), set(self.A) | set(self.B))

  def test_every_report_model_keeps_it(self):
    merged = {**self.A, **self.B}
    base = {"job_id": "j", "target": "t", "initiator": "i", "local_worker_id": "1",
            "start_port": 1, "end_port": 2, "open_ports": [], "service_info": {},
            "web_tests_info": {}, "completed_tests": [], "done": True,
            "cves_not_applicable": merged}
    for model in (ThreadReport, NodeReport, AggregatedScanData):
      with self.subTest(model=model.__name__):
        self.assertEqual(model.from_dict(base).to_dict()["cves_not_applicable"], merged)
        without = dict(base)
        without.pop("cves_not_applicable")
        self.assertNotIn("cves_not_applicable", model.from_dict(without).to_dict())


if __name__ == "__main__":
  unittest.main()
