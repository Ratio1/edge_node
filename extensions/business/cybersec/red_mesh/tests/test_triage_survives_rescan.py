"""RM-062 B7: triage applies to the same finding in every pass of a job.

Triage is stored per `job_id:finding_id`, and `finding_id` is the B2 dedup key.
A finding that is seen again in a later pass with reworded description or
evidence keeps its dedup key, so the analyst's decision applies to it there too.
A new endpoint is a new finding and inherits nothing.

The order follows production: triage is refused until the job has a `job_cid`,
and only finalization sets that, so every pass is already in the archive when
triage is written. Nothing carries triage from one job to the next; that is not
claimed here. The public `update_finding_triage` endpoint currently returns 503
pending its scoped workspace contract, so the write goes through the service
function; the read is the path `get_job_archive` uses.

The identity unit tests in `test_finding_identity_contract.py` prove the key
itself. This file proves the chain around it: real producers, the archive write
(`put_archive`), the triage write, and the checked archive read that merges
triage back by `finding_id`.

Titles are never reworded. A blackbox finding with no location still keys on its
title (`models/finding_identity.py:dedup_key`), until RM-061 attaches locations.
"""

from copy import deepcopy
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.findings import (
  AffectedAsset, Finding, Severity, probe_result,
)
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin
from extensions.business.cybersec.red_mesh.repositories import ArtifactRepository
from extensions.business.cybersec.red_mesh.services import triage
from .test_tenant_query_snapshots import QueryStore, archive_for, checked_job


class _Owner(QueryStore):
  """QueryStore plus what the write side needs.

  `QueryStore` is a read-only probe: it refuses to re-read the job record and
  has no writes. Triage re-reads the record and writes state and audit rows,
  and `put_archive` writes the archive, so this subclass adds those over the
  same dicts the checked read uses.
  """

  ee_addr = "node-a"

  def __init__(self, job):
    super().__init__()
    self.job = job

  def chainstore_hset(self, *, hkey, key, value):
    self.points[(hkey, key)] = value

  def _get_job_from_cstore(self, job_id):
    return self.job if job_id == self.job["job_id"] else None

  def add_json(self, payload, show_logs=False):
    cid = f"archive-{len(self.artifacts)}"
    self.artifacts[cid] = deepcopy(payload)
    return cid

  def P(self, *_args, **_kwargs):
    pass


class _Host(_RiskScoringMixin):
  pass


def _blackbox(description, csrf_evidence):
  """Two blackbox findings through the real probe → flat walk path."""
  result = probe_result(
    findings=[
      Finding(
        severity=Severity.HIGH,
        title="Default credentials accepted",
        description=description,
        confidence="certain",
      ),
      Finding(
        severity=Severity.MEDIUM,
        title="POST form missing CSRF token",
        description="Form posts without an anti-CSRF token.",
        evidence=csrf_evidence,
        confidence="firm",
        affected_assets=[AffectedAsset(
          host="192.0.2.10", port=443, url="/login", parameter="/session", method="POST",
        )],
      ),
    ],
    probe_id="_service_info_http",
  )
  _risk, flat = _Host()._compute_risk_and_findings({
    "target": "192.0.2.10",
    "port_protocols": {"443": "https"},
    "service_info": {"443": {"_service_info_http": result}},
  })
  return flat


def _graybox(url, evidence):
  return GrayboxFinding(
    scenario_id="PT-A01-01",
    title="Object reference not authorised",
    status="vulnerable",
    severity="HIGH",
    owasp="A01:2021",
    cwe=["CWE-639"],
    evidence=evidence,
    url=url,
    method="GET",
  ).to_flat_finding(port=443, protocol="https", probe_name="_graybox_access_control")


class TestTriageAppliesAcrossPasses(unittest.TestCase):

  def setUp(self):
    self.pass_1 = _blackbox("admin:*** accepted on first try", "csrf field absent") + [
      _graybox("https://192.0.2.10/api/records/1", ["status=200", "owner=other"]),
    ]
    self.pass_2 = _blackbox("admin:*** accepted (retested)", "csrf field absent; form re-read") + [
      _graybox("https://192.0.2.10/api/records/1", ["status=200", "owner=other", "retest=1"]),
      _graybox("https://192.0.2.10/api/invoices/7", ["status=200"]),
    ]
    # The record as finalization leaves it: archived, and launched by this node.
    self.job = checked_job()
    self.job.update(job_status="FINALIZED", launcher="node-a")
    self.owner = _Owner(self.job)
    archive = archive_for(self.job)
    archive["passes"] = [
      {"pass_nr": 1, "findings": deepcopy(self.pass_1)},
      {"pass_nr": 2, "findings": deepcopy(self.pass_2)},
    ]
    self.job["job_cid"] = ArtifactRepository(self.owner).put_archive(archive)

  def _triage_pass_1(self):
    with patch.object(triage, "emit_finding_event") as emit:
      for finding in self.pass_1:
        result = triage.update_finding_triage(
          self.owner, "job-1", finding["finding_id"], "accepted_risk",
          note="reviewed in pass 1", actor="analyst",
        )
        self.assertNotIn("error", result, result)
    self.assertEqual(emit.call_count, len(self.pass_1))
    for call in emit.call_args_list:
      self.assertEqual(call.kwargs["event_action"], "triaged")

  def _read(self):
    result = triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)
    self.assertNotIn("error", result, result)
    return result["archive"]["passes"]

  def test_the_rescan_really_reworded_each_finding(self):
    """Control: every twin pair shares its key and differs in content."""
    for first, second in zip(self.pass_1, self.pass_2):
      with self.subTest(title=first["title"]):
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertNotEqual(first["finding_signature"], second["finding_signature"])

  def test_pass_1_triage_attaches_to_its_twins_in_pass_2(self):
    self._triage_pass_1()
    passes = self._read()
    for finding in passes[0]["findings"]:
      with self.subTest(pass_nr=1, title=finding["title"]):
        self.assertEqual(finding.get("triage", {}).get("status"), "accepted_risk")
    for finding in passes[1]["findings"][:len(self.pass_1)]:
      with self.subTest(pass_nr=2, title=finding["title"]):
        self.assertEqual(
          finding.get("triage", {}).get("status"), "accepted_risk",
          "a triage decision did not follow its finding into the later pass",
        )

  def test_a_new_endpoint_inherits_no_triage(self):
    self._triage_pass_1()
    new_endpoint = self._read()[1]["findings"][-1]
    self.assertEqual(new_endpoint["affected_assets"][0]["url"], "https://192.0.2.10/api/invoices/7")
    self.assertNotIn(new_endpoint["finding_id"], {f["finding_id"] for f in self.pass_1})
    self.assertNotIn("triage", new_endpoint)


if __name__ == "__main__":
  unittest.main()
