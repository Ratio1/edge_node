"""RM-265: an HTTP page with no redirect to HTTPS, while the same target serves HTTPS (host-level correlation)."""

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.mixins.report import get_host_aggregated_report
from extensions.business.cybersec.red_mesh.worker.correlation import (
  HTTP_NO_HTTPS_REDIRECT_TITLE, http_without_https_redirect_findings,
)

from .test_probes import DummyOwner
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

COMMON = "extensions.business.cybersec.red_mesh.worker.service.common.requests.get"


def http_fact(port=80, final_status=200, location_scheme=None, final_scheme="http", empty=False, catch_all=False,
              same_host=True):
  return {
    "url": f"http://10.0.0.1:{port}" if port != 80 else "http://10.0.0.1", "status": final_status,
    "location_scheme": location_scheme, "final_status": final_status, "final_scheme": final_scheme,
    "same_host": same_host, "empty": empty, "catch_all": catch_all,
  }


def report(web_root):
  """A merged report as `_get_aggregated_report` returns it: no `target` key."""
  return {"scan_metadata": {"web_root": web_root}, "correlation_findings": []}


class RuleTests(unittest.TestCase):
  def test_http_200_with_tls_counterpart_gives_one_low_finding_per_http_port(self):
    rows = http_without_https_redirect_findings(report({
      80: http_fact(80), 8080: http_fact(8080), 443: {"tls": True},
    }))
    self.assertEqual(len(rows), 2)
    self.assertEqual(len({r["finding_id"] for r in rows}), 2)
    for r in rows:
      self.assertEqual((r["title"], r["severity"], r["cwe_id"], r["owasp_id"], r["confidence"]),
                       (HTTP_NO_HTTPS_REDIRECT_TITLE, "LOW", "CWE-319", "A02:2021", "firm"))
      self.assertIn("443", r["evidence"])
      self.assertIn("RM-165", r["description"])
      self.assertEqual(r["affected_assets"][0]["host"], "10.0.0.1")

  def test_no_finding_cases(self):
    cases = {
      "301 to https": http_fact(final_status=200, location_scheme="https", final_scheme="https"),
      "301 to https, then back to http": http_fact(location_scheme="https", final_scheme="http"),
      "page from another host": http_fact(same_host=False),
      "final scheme https": http_fact(final_scheme="https"),
      "catch-all": http_fact(catch_all=True),
      "catch-all never checked": http_fact(catch_all=None),
      "empty body": http_fact(empty=True),
      "non-2xx": http_fact(final_status=404),
    }
    for name, fact in cases.items():
      with self.subTest(name):
        self.assertEqual(http_without_https_redirect_findings(report({80: fact, 443: {"tls": True}})), [])

  def test_no_tls_counterpart_gives_no_finding(self):
    self.assertEqual(http_without_https_redirect_findings(report({80: http_fact()})), [])

  def test_302_to_http_same_host_with_tls_gives_finding(self):
    fact = http_fact(location_scheme="http")
    self.assertEqual(len(http_without_https_redirect_findings(report({80: fact, 443: {"tls": True}}))), 1)

  def test_int_and_str_port_keys_merge_into_one_port(self):
    # The str twin carries the catch-all verdict; only a merge by int(port) applies it to the int entry.
    rows = http_without_https_redirect_findings(report({80: http_fact(), "80": {"catch_all": True}, "443": {"tls": True}}))
    self.assertEqual(rows, [])
    rows = http_without_https_redirect_findings(report({"80": http_fact(), 80: {"status": 200}, "443": {"tls": True}}))
    self.assertEqual(len(rows), 1)

  def test_a_port_that_completed_tls_is_not_its_own_counterpart(self):
    rows = http_without_https_redirect_findings(report({8080: {**http_fact(8080), "tls": True}}))
    self.assertEqual(rows, [])


class RecordingTests(unittest.TestCase):
  def _worker(self):
    worker = PentestLocalWorker(
      owner=DummyOwner(), target="10.0.0.1", job_id="j", initiator="i", local_id_prefix="1", worker_target_ports=[80],
    )
    worker.state["scan_metadata"] = {}
    return worker

  def _resp(self, status, url, location=None, text="<html>x</html>", history=()):
    r = MagicMock(status_code=status, reason="OK", text=text, content=text.encode(), url=url, history=list(history))
    r.headers = {"Location": location} if location else {}
    return r

  def test_http_probe_records_first_hop_final_hop_and_catch_all_from_the_memo(self):
    worker = self._worker()
    first = self._resp(302, "http://10.0.0.1/", location="http://10.0.0.1/home")
    final = self._resp(200, "http://10.0.0.1/home", history=[first])
    worker._host_is_catch_all = MagicMock(return_value=True)
    with patch(COMMON, return_value=final), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.request", return_value=final
    ):
      worker._service_info_http("10.0.0.1", 80)
    fact = worker.state["scan_metadata"]["web_root"][80]
    self.assertEqual(
      (fact["status"], fact["location_scheme"], fact["final_status"], fact["final_scheme"], fact["empty"], fact["catch_all"]),
      (302, "http", 200, "http", False, True),
    )
    self.assertTrue(fact["same_host"])

  def test_location_on_a_200_is_not_a_redirect(self):
    worker = self._worker()
    page = self._resp(200, "http://10.0.0.1/", location="https://10.0.0.1/")
    worker._host_is_catch_all = MagicMock(return_value=False)
    with patch(COMMON, return_value=page), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.request", return_value=page
    ):
      worker._service_info_http("10.0.0.1", 80)
    fact = worker.state["scan_metadata"]["web_root"][80]
    self.assertIsNone(fact["location_scheme"])
    rows = http_without_https_redirect_findings(report({80: fact, 443: {"tls": True}}))
    self.assertEqual(len(rows), 1)

  def test_tls_handshake_records_fact_only_for_a_web_tls_port(self):
    for protocol, expected in (("https", True), ("smtps", None), (None, True)):
      with self.subTest(protocol):
        worker = self._worker()
        worker.state["port_protocols"] = {443: protocol} if protocol else {}
        worker._tls_unverified_connect = MagicMock(return_value=("TLSv1.3", "AES", None))
        for name in ("_tls_check_protocol", "_tls_check_certificate", "_tls_check_expiry", "_tls_check_default_cn",
                     "_tls_check_downgrade"):
          setattr(worker, name, MagicMock(return_value=[]))
        worker._tls_check_heartbleed = MagicMock(return_value=None)
        worker._service_info_tls("10.0.0.1", 443)
        self.assertEqual(worker.state["scan_metadata"].get("web_root", {}).get(443, {}).get("tls"), expected)


class AggregationTests(unittest.TestCase):
  def test_merge_appends_findings_once_and_a_failure_is_logged_by_type(self):
    merged = report({80: http_fact(), 443: {"tls": True}})
    owner = MagicMock()
    owner._get_aggregated_report.return_value = merged
    get_host_aggregated_report(owner, {"n": {}})
    get_host_aggregated_report(owner, {"n": {}})
    self.assertEqual([r["title"] for r in merged["correlation_findings"]], [HTTP_NO_HTTPS_REDIRECT_TITLE])
    broken = MagicMock()
    broken._get_aggregated_report.return_value = {"open_ports": [1]}
    with patch("extensions.business.cybersec.red_mesh.mixins.report.http_without_https_redirect_findings",
               side_effect=ValueError("secret-token")):
      get_host_aggregated_report(broken, {"n": {}})
    self.assertIn("ValueError", str(broken.P.call_args))
    self.assertNotIn("secret-token", str(broken.P.call_args))
