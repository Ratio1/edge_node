"""Step 4a S1: host-scoped triage keys, the execution scope, and the record fields."""
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.models import FindingTriageAuditEntry, FindingTriageState
from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.execution import triage_scope
from .test_execution_binding_models import binding_payload

TENANT_A = "tn_11111111-1111-4111-8111-111111111111"
TENANT_B = "tn_22222222-2222-4222-8222-222222222222"


class _Store:
  """A CStore double that keeps hashes, so keys and isolation can be read back."""

  def __init__(self):
    self.hashes = {}
    self.cfg_instance_id = "inst"

  def chainstore_hset(self, hkey, key, value):
    if value is None:
      self.hashes.get(hkey, {}).pop(key, None)
    else:
      self.hashes.setdefault(hkey, {})[key] = value

  def chainstore_hget(self, hkey, key):
    return self.hashes.get(hkey, {}).get(key)

  def chainstore_hgetall(self, hkey):
    return dict(self.hashes.get(hkey, {}))


def state(tenant, host, finding="f1", job="job-1", status="false_positive"):
  return FindingTriageState(job_id=job, finding_id=finding, status=status, tenant_id=tenant, host=host)


class TestHostTriageStore(unittest.TestCase):
  def setUp(self):
    self.owner = _Store()
    self.repo = JobStateRepository(self.owner)

  def test_key_shape_and_prefix_disjointness(self):
    self.repo.put_host_triage(state(TENANT_A, "192.0.2.10"))
    self.repo.append_host_triage_audit(FindingTriageAuditEntry(
      job_id="job-1", finding_id="f1", status="open", tenant_id=TENANT_A, host="192.0.2.10"))
    self.assertEqual(set(self.owner.hashes), {f"inst:triage:t:{TENANT_A}", f"inst:triage:audit:{TENANT_A}"})
    self.assertIn("192.0.2.10\x1ff1", self.owner.hashes[f"inst:triage:t:{TENANT_A}"])
    # a tenant literally named `audit` cannot reach the audit hkey, nor the legacy ones
    hkey = self.repo.host_triage_hkey("audit")
    self.assertEqual(hkey, "inst:triage:t:audit")
    self.assertNotIn(hkey, ("inst:triage", "inst:triage:audit", self.repo.host_triage_audit_hkey("audit")))
    self.assertFalse(self.repo.host_triage_hkey("x").startswith("inst:triage:audit"))
    self.assertFalse(self.repo.host_triage_audit_hkey("x").startswith("inst:triage:t:"))

  def test_tenants_and_hosts_do_not_bleed(self):
    self.repo.put_host_triage(state(TENANT_A, "192.0.2.10"))
    self.repo.put_host_triage(state(TENANT_A, "192.0.2.11", finding="f2"))
    self.assertEqual(set(self.repo.list_host_triage(TENANT_A, "192.0.2.10")), {"f1"})
    self.assertEqual(self.repo.list_host_triage(TENANT_B, "192.0.2.10"), {})
    self.assertIsNone(self.repo.get_host_triage(TENANT_B, "192.0.2.10", "f1"))
    self.assertEqual(self.repo.get_host_triage(TENANT_A, "192.0.2.10", "f1")["tenant_id"], TENANT_A)

  def test_host_prefix_is_exact(self):
    self.repo.put_host_triage(state(TENANT_A, "a.example", finding="x"))
    self.repo.put_host_triage(state(TENANT_A, "a.example.org", finding="y"))
    self.assertEqual(set(self.repo.list_host_triage(TENANT_A, "a.example")), {"x"})

  def test_audit_appends(self):
    for status in ("open", "remediated"):
      log = self.repo.append_host_triage_audit(FindingTriageAuditEntry(
        job_id="job-1", finding_id="f1", status=status, tenant_id=TENANT_A, host="h"))
    self.assertEqual([e["status"] for e in log], ["open", "remediated"])
    self.assertEqual(len(self.repo.get_host_triage_audit(TENANT_A, "h", "f1")), 2)
    self.assertEqual(self.repo.get_host_triage_audit(TENANT_B, "h", "f1"), [])

  def test_unscoped_or_separator_input_is_refused(self):
    with self.assertRaises(ValueError):
      self.repo.put_host_triage(FindingTriageState(job_id="j", finding_id="f"))
    with self.assertRaises(ValueError):
      self.repo.put_host_triage(state(TENANT_A, "h", finding="a\x1fb"))
    with self.assertRaises(ValueError):
      self.repo.list_host_triage("", "h")
    self.assertEqual(self.owner.hashes, {})

  def test_record_fields_round_trip_and_legacy_shape_is_unchanged(self):
    full = FindingTriageState(job_id="j", finding_id="f", status="open", tenant_id=TENANT_A, host="h",
                              confirmed=True, confirmed_by="actor")
    self.assertEqual(FindingTriageState.from_dict(full.to_dict()), full)
    self.assertEqual(FindingTriageState(job_id="j", finding_id="f").to_dict(),
                     {"job_id": "j", "finding_id": "f", "status": "open", "note": "", "actor": "", "updated_at": 0.0})


class TestTriageScope(unittest.TestCase):
  def binding(self, target, tenant=TENANT_A):
    value = binding_payload()
    value.update(tenant_id=tenant, asset_target=target, asset_target_digest=canonical_digest(target))
    return value

  def test_network_and_webapp_hosts(self):
    self.assertEqual(triage_scope(self.binding({"kind": "network", "address": "192.0.2.10"})),
                     (TENANT_A, "192.0.2.10"))
    for url, host in (("https://app.example.com/x", "app.example.com"),
                      ("http://app.example.com:8080/x", "app.example.com"),
                      ("https://[2001:db8::1]:8443/x", "[2001:db8::1]")):
      target = {"kind": "webapp", "url": url, "allowedPathPrefix": "/"}
      self.assertEqual(triage_scope(self.binding(target)), (TENANT_A, host), url)

  def test_model_target_and_bad_binding_have_no_scope(self):
    model = {"kind": "model", "adapter": "openai_compatible",
             "endpointUrl": "https://api.example.com/v1/chat/completions", "model": "m"}
    self.assertIsNone(triage_scope(self.binding(model)))
    for bad in (None, {}, "x", {**binding_payload(), "tenant_id": "audit"}):
      self.assertIsNone(triage_scope(bad))


if __name__ == "__main__":
  unittest.main()
