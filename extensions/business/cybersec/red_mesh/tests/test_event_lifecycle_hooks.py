import os
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.event_hooks import (
  emit_attestation_status_event,
  emit_export_status_event,
  emit_finding_event,
  emit_lifecycle_event,
)
from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status


def _owner(event_export=None, wazuh_export=None):
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_ee_node_network = "devnet"
  owner.cfg_event_export = {
    "ENABLED": True,
    "SIGN_PAYLOADS": False,
    **(event_export or {}),
  }
  owner.cfg_wazuh_export = {
    "ENABLED": True,
    "MODE": "syslog",
    "SYSLOG_HOST": "127.0.0.1",
    **(wazuh_export or {}),
  }
  records = {}

  def hget(hkey, key):
    return records.get((hkey, key))

  def hset(hkey, key, value):
    records[(hkey, key)] = value

  owner.chainstore_hget.side_effect = hget
  owner.chainstore_hset.side_effect = hset
  owner._records = records
  return owner


def _job_specs():
  return {
    "job_id": "job-1",
    "job_pass": 1,
    "run_mode": "SINGLEPASS",
    "scan_type": "network",
    "target": "198.51.100.10",
    "authorized": True,
    "timeline": [],
  }


class TestEventLifecycleHooks(unittest.TestCase):

  def tearDown(self):
    os.environ.pop("REDMESH_EVENT_HMAC_SECRET", None)

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_lifecycle_hook_delivers_and_records_job_soc_status(self, deliver):
    def _sent(_owner, event, integration_id="wazuh"):
      return {
        "status": "sent",
        "integration_id": integration_id,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
      }

    deliver.side_effect = _sent
    owner = _owner()
    job_specs = _job_specs()

    result = emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.started",
      event_action="started",
      pass_nr=1,
    )

    self.assertEqual(result["status"], "sent")
    self.assertEqual(job_specs["soc_event_status"]["assessment_notice_status"], "sent")
    self.assertEqual(job_specs["soc_event_status"]["last_event_type"], "redmesh.job.started")
    self.assertEqual(owner._emit_timeline_event.call_args.args[1], "soc_event_export")
    delivered_event = deliver.call_args.args[1]
    self.assertEqual(delivered_event["target"]["display"], None)
    self.assertNotIn("198.51.100.10", str(delivered_event))

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_disabled_event_export_records_skipped_without_delivery(self, deliver):
    owner = _owner(event_export={"ENABLED": False})
    job_specs = _job_specs()

    result = emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.started",
      event_action="started",
      pass_nr=1,
    )

    self.assertEqual(result["status"], "skipped")
    self.assertEqual(result["error"], "event_export_disabled")
    self.assertEqual(job_specs["soc_event_status"]["assessment_notice_status"], "skipped")
    deliver.assert_not_called()

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_skipped_delivery_does_not_claim_wazuh_adapter(self, deliver):
    owner = _owner(wazuh_export={"ENABLED": False})
    job_specs = _job_specs()

    result = emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.started",
      event_action="started",
      pass_nr=1,
    )

    self.assertEqual(result["status"], "skipped")
    self.assertEqual(result["error"], "wazuh_disabled")
    self.assertIsNone(result["integration_id"])
    soc_status = job_specs["soc_event_status"]
    self.assertIsNone(soc_status["last_adapter"])
    self.assertEqual(soc_status.get("history") or [], [])
    self.assertFalse(owner._emit_timeline_event.called)
    deliver.assert_not_called()

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_disabled_skips_do_not_pollute_history_or_timeline(self, deliver):
    owner = _owner(wazuh_export={"ENABLED": False})
    job_specs = _job_specs()

    for event_action, event_type in [
      ("started", "redmesh.job.started"),
      ("pass_completed", "redmesh.job.pass_completed"),
      ("completed", "redmesh.job.completed"),
    ]:
      emit_lifecycle_event(
        owner,
        job_specs,
        event_type=event_type,
        event_action=event_action,
        pass_nr=1,
      )

    soc_status = job_specs["soc_event_status"]
    self.assertEqual(soc_status.get("history") or [], [])
    self.assertEqual(soc_status["last_event_type"], "redmesh.job.completed")
    self.assertEqual(soc_status["last_error_class"], "wazuh_disabled")
    self.assertFalse(owner._emit_timeline_event.called)
    deliver.assert_not_called()

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_delivery_exception_is_non_blocking_and_updates_integration_status(self, deliver):
    deliver.side_effect = RuntimeError("network down")
    owner = _owner()
    job_specs = _job_specs()

    result = emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.pass_completed",
      event_action="pass_completed",
      pass_nr=1,
    )

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "RuntimeError")
    self.assertEqual(job_specs["soc_event_status"]["last_status"], "error")
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertEqual(status["last_error_class"], "RuntimeError")
    self.assertIsNotNone(status["last_failure_at"])

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_export_attestation_and_finding_hooks_use_specific_event_types(self, deliver):
    seen = []

    def _sent(_owner, event, integration_id="wazuh"):
      seen.append(event["event_type"])
      return {
        "status": "sent",
        "integration_id": integration_id,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
      }

    deliver.side_effect = _sent
    owner = _owner()
    job_specs = _job_specs()

    emit_finding_event(owner, job_specs, finding={"finding_id": "f-1", "title": "Finding", "severity": "HIGH"}, event_action="created")
    emit_export_status_event(owner, job_specs, adapter_type="misp", status="completed", destination_label="misp")
    emit_attestation_status_event(owner, job_specs, state="submitted", network="sepolia", tx_hash="0xtx")

    self.assertIn("redmesh.finding.created", seen)
    self.assertIn("redmesh.export.misp.completed", seen)
    self.assertIn("redmesh.attestation.submitted", seen)
    self.assertEqual(job_specs["soc_event_status"]["last_attestation_event_status"], "sent")


if __name__ == "__main__":
  unittest.main()
