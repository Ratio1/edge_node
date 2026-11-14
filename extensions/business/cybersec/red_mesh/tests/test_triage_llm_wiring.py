"""Step 4a S6: closed and confirmed findings in the LLM payload of the agent mixin and in the structured input."""
import unittest

from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input
from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import _RedMeshLlmAgentMixin
from .test_execution_binding_models import binding_payload
from .test_triage_cve_view import compute
from .test_cve_view import raw
from .test_triage_store import TENANT_A, TENANT_B

HOST = "192.0.2.10"


class Host(_RedMeshLlmAgentMixin):
  cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
  cfg_instance_id = "inst"

  def __init__(self, records=None, tenant=TENANT_A):
    binding = {**binding_payload(), "tenant_id": tenant}
    self.record = {"job_id": "j", "execution_binding": binding}
    self.rows = records or {}

  def chainstore_hgetall(self, hkey):
    return dict(self.rows.get(hkey, {}))

  def chainstore_hget(self, hkey, key):
    return self.rows.get(hkey, {}).get(key)

  def _get_job_from_cstore(self, job_id):
    return self.record if job_id == "j" else None

  def P(self, *args, **kwargs):
    pass


def finding(n, severity="HIGH", **kw):
  f = raw(n, severity, **kw)
  f.update(severity=severity, port=80, probe="p", evidence="e", description="apache 1.5 is vulnerable to CVE-2030-%04d. x" % n)
  return f


def payload(host, findings):
  report = {"nr_open_ports": 1, "ports_scanned": 1, "open_ports": [80], "correlation_findings": findings}
  return host._build_llm_analysis_payload("j", report, {"scan_type": "network", "target": "t"}, "security_assessment")


def triage_row(tenant, finding_id, **fields):
  return {f"inst:triage:t:{tenant}": {f"{HOST}\x1f{finding_id}": {
    "job_id": "older", "finding_id": finding_id, "tenant_id": tenant, "host": HOST, **fields}}}


class TestAgentPayloadReadsHostTriage(unittest.TestCase):
  def findings(self):
    return [finding(1, "CRITICAL", kev=True), finding(2, "HIGH", kev=True)]

  def titles(self, result):
    return sorted(f["title"] for f in result["top_findings"])

  def test_a_closed_cve_is_not_sent_and_is_counted_closed(self):
    open_payload = payload(Host(), self.findings())
    self.assertEqual(open_payload["cve_view"]["counts"]["closed"], 0)
    self.assertEqual(len(open_payload["top_findings"]), 2)
    host = Host(triage_row(TENANT_A, "id0002", status="false_positive"))
    closed = payload(host, self.findings())
    self.assertEqual(closed["cve_view"]["counts"]["closed"], 1)
    self.assertEqual(len(closed["top_findings"]), 1)
    self.assertEqual(closed["findings_summary"]["cve_view_counts"]["closed"], 1)
    self.assertEqual(closed["findings_summary"]["by_severity"], {"CRITICAL": 1, "HIGH": 1})  # raw, as before

  def test_another_tenants_record_on_the_same_host_closes_nothing(self):
    host = Host(triage_row(TENANT_B, "id0002", status="false_positive"))
    self.assertEqual(payload(host, self.findings())["cve_view"]["counts"]["closed"], 0)

  def test_a_confirmed_possible_finding_is_listed(self):
    findings = [finding(1, "CRITICAL", kev=True, confidence="tentative", reason="banner_only")]
    self.assertEqual(payload(Host(), findings)["cve_view"]["counts"]["possible"], 1)
    host = Host(triage_row(TENANT_A, "id0001", status="open", confirmed=True, confirmed_by="a"))
    confirmed = payload(host, findings)
    self.assertEqual((confirmed["cve_view"]["counts"]["possible"], confirmed["cve_view"]["counts"]["listed"]), (0, 1))

  def test_an_unreadable_store_leaves_everything_open(self):
    class Broken(Host):
      def chainstore_hgetall(self, hkey):
        raise RuntimeError("down")
    self.assertEqual(payload(Broken(), self.findings())["cve_view"]["counts"]["closed"], 0)
    self.assertEqual(Host()._llm_host_triage("missing"), {})


class TestStructuredInputReadsStampedFindings(unittest.TestCase):
  def test_the_structured_llm_input_drops_a_closed_cve_via_the_stamp_from_the_report_build(self):
    # finalization passes the flat findings of `_compute_risk_and_findings` (stamped) to the structured analysis
    findings = [finding(1, "CRITICAL", kev=True), finding(2, "HIGH", kev=True)]
    _, flat = compute(findings, {"id0002": {"status": "remediated"}})
    out = build_llm_input(findings=flat, aggregated_report={})
    self.assertEqual(out.to_dict()["scan_summary"]["cve_view"]["counts"]["closed"], 1)
    self.assertEqual(len(out.to_dict()["findings"]), 1)


if __name__ == "__main__":
  unittest.main()
