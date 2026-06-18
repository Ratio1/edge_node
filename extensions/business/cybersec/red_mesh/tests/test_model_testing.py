import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.model_testing import (
  get_capability_status,
  launch_model_test,
  validate_model_provider_credentials,
  validate_provider_url,
)
from extensions.business.cybersec.red_mesh.tests.conftest import mock_plugin_modules


PUBLIC_TEST_IP = "93.184.216.34"


def _owner(**kwargs):
  defaults = {
    "CONFIG": {},
    "config_data": {},
    "r1fs": MagicMock(),
    "chainstore_hset": MagicMock(),
    "chainstore_hgetall": MagicMock(return_value={}),
  }
  defaults.update(kwargs)
  return SimpleNamespace(**defaults)


def _provider(base_url=f"https://{PUBLIC_TEST_IP}/v1", credential_ref=""):
  result = {
    "adapter": "openai_compatible",
    "provider_label": "Unit Provider",
    "base_url": base_url,
    "model": "unit-model",
  }
  if credential_ref:
    result["credential_ref"] = credential_ref
  return result


def _valid_launch_kwargs(secret="sentinel-model-api-key"):
  return {
    "task_name": "CBRN smoke",
    "task_description": "Run reviewed CBRN safety pack",
    "created_by_name": "tester",
    "created_by_id": "user-123",
    "authorized": True,
    "test_set_id": "cbrn_safety_v1",
    "tested_model": _provider(),
    "tested_model_secret_payload": {"api_key": secret},
    "use_default_evaluator_model": False,
    "evaluator_model": _provider(),
    "evaluator_model_secret_payload": {"api_key": secret},
  }


class TestModelTestingCapability(unittest.TestCase):

  def test_capability_status_default_disabled_and_sanitized(self):
    owner = _owner(cfg_model_testing={
      "ENABLED": False,
      "RAW_EVIDENCE_SECRET_REF": "raw-secret-name",
      "DEFAULT_EVALUATOR_MODEL": {
        "provider_label": "Evaluator",
        "api_key": "super-secret",
      },
    })

    status = get_capability_status(owner)

    model_testing = status["model_testing"]
    self.assertFalse(model_testing["enabled"])
    self.assertEqual(model_testing["disabled_reason"], "disabled_by_policy")
    self.assertEqual(model_testing["restricted_raw_permission"], "job:view_raw_model_evidence")
    self.assertEqual(model_testing["restricted_raw_purge_permission"], "job:purge_raw_model_evidence")
    self.assertEqual(model_testing["default_evaluator_model_label"], "Evaluator")
    self.assertNotIn("super-secret", str(status))
    self.assertNotIn("raw-secret-name", str(status))

  def test_launch_model_test_disabled_fails_before_persistence(self):
    owner = _owner()

    result = launch_model_test(owner, **_valid_launch_kwargs())

    self.assertEqual(result["error"], "model_testing_disabled")
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()


class TestModelTestingProviderSecurity(unittest.TestCase):

  def test_provider_url_rejects_forbidden_url_shapes(self):
    bad_urls = [
      "http://provider.example/v1",
      "https://user:pw@provider.example/v1",
      "https://provider.example/v1?api_key=secret",
      "https://provider.example/v1#secret",
      "https://127.0.0.1/v1",
      "https://10.0.0.1/v1",
      "https://169.254.169.254/latest",
      "https://[::1]/v1",
    ]

    for base_url in bad_urls:
      with self.subTest(base_url=base_url):
        _, err = validate_provider_url(base_url)
        self.assertIsNotNone(err)
        self.assertIn(err["error_class"], {"invalid_url", "forbidden_destination"})

  def test_provider_url_rejects_mixed_dns_answers(self):
    def resolver(hostname, port, type=socket.SOCK_STREAM):
      return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_TEST_IP, 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
      ]

    _, err = validate_provider_url("https://provider.example/v1", resolver=resolver)

    self.assertIsNotNone(err)
    self.assertEqual(err["error_class"], "forbidden_destination")

  def test_duplicate_credential_sources_fail_closed(self):
    _, err = validate_model_provider_credentials(
      {
        "credential_ref": "model_provider/operator/user-123/provider-a",
      },
      {"api_key": "secret"},
      role="tested_model",
      created_by_id="user-123",
    )

    self.assertEqual(err["error_class"], "duplicate_credential_source")

  def test_inline_credential_fields_in_provider_config_fail_closed(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})

    for role, provider_key in (
      ("tested_model", "tested_model"),
      ("evaluator_model", "evaluator_model"),
    ):
      with self.subTest(role=role):
        kwargs = _valid_launch_kwargs()
        kwargs[provider_key] = {
          **kwargs[provider_key],
          "api_key": "inline-secret",
        }
        result = launch_model_test(owner, **kwargs)
        self.assertEqual(result["error"], "validation_error")
        self.assertEqual(result["error_class"], "invalid_provider_config")
        self.assertNotIn("inline-secret", str(result))
        owner.r1fs.add_json.assert_not_called()
        owner.chainstore_hset.assert_not_called()

  def test_inline_auth_headers_in_provider_config_fail_closed(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["tested_model"] = {
      **kwargs["tested_model"],
      "headers": {"Authorization": "Bearer inline-secret"},
    }

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertEqual(result["error_class"], "invalid_provider_config")
    self.assertNotIn("inline-secret", str(result))
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_invalid_credential_refs_use_same_sanitized_error(self):
    refs = [
      "not-a-model-provider-ref",
      "model_provider/operator/other/provider-a",
      "model_provider/operator/user-123/nested/provider",
      "model_provider/deploy/default_evaluator/provider-a",
      "model_provider/unknown/provider-a",
    ]

    for ref in refs:
      with self.subTest(ref=ref):
        _, err = validate_model_provider_credentials(
          {"credential_ref": ref},
          {},
          role="tested_model",
          created_by_id="user-123",
        )
        self.assertEqual(err["error_class"], "credential_unavailable")
        self.assertNotIn(ref, str(err))

  def test_enabled_launch_validates_but_does_not_persist_or_echo_secret(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    secret = "sentinel-model-api-key"
    kwargs = _valid_launch_kwargs(secret=secret)
    kwargs["limits"] = {
      "tested_max_tokens": 128,
      "api_key": secret,
      "unknown_secret_field": secret,
    }

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "not_implemented")
    self.assertEqual(result["job_type"], "model_test")
    self.assertNotIn(secret, str(result))
    self.assertTrue(result["job_config"]["tested_model"]["credential_ref_present"] is False)
    self.assertEqual(result["job_config"]["limits"]["tested_max_tokens"], 128)
    self.assertNotIn("api_key", result["job_config"]["limits"])
    self.assertNotIn("unknown_secret_field", result["job_config"]["limits"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_limits_above_v1_caps(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"tested_max_tokens": 257}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.tested_max_tokens", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_temperature_above_fixed_v1_cap(self):
    owner = _owner(cfg_model_testing={
      "ENABLED": True,
      "LIMITS": {"TEMPERATURE": 1},
    })
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"temperature": 0.1}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.temperature", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_non_finite_temperature(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"temperature": "nan"}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.temperature", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_raw_evidence_opt_in_rejected_while_policy_disabled(self):
    owner = _owner(cfg_model_testing={"ENABLED": True, "RAW_EVIDENCE_ENABLED": False})
    kwargs = _valid_launch_kwargs()
    kwargs["raw_evidence"] = {"enabled": True, "reason": "debug"}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertEqual(result["error_class"], "raw_evidence_disabled")
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()


class TestModelTestingRawEvidenceGuards(unittest.TestCase):

  def test_get_report_denies_raw_model_test_evidence_artifact(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.r1fs.get_json.return_value = {
      "kind": "redmesh_model_test_raw_evidence",
      "job_id": "job-1",
      "cases": [],
    }

    result = PentesterApi01Plugin.get_report(plugin, "raw-cid")

    self.assertEqual(result["error"], "forbidden")
    self.assertNotIn("cases", str(result))
