"""Sanitized Model Testing capability status."""

from ..services.config import get_model_testing_config
from .catalog import sanitized_model_test_catalog


def _disabled_reason(cfg):
  if not cfg["ENABLED"]:
    return "disabled_by_policy"
  return None


def get_capability_status(owner):
  """Return the sanitized RedMesh capability registry."""
  cfg = get_model_testing_config(owner)
  default_evaluator = cfg.get("DEFAULT_EVALUATOR_MODEL")
  default_label = None
  if isinstance(default_evaluator, dict):
    default_label = str(
      default_evaluator.get("provider_label")
      or default_evaluator.get("PROVIDER_LABEL")
      or ""
    ).strip() or None
  return {
    "network_scan": {
      "enabled": True,
      "disabled_reason": None,
      "policy_source": "pentester_config",
    },
    "graybox_scan": {
      "enabled": True,
      "disabled_reason": None,
      "policy_source": "pentester_config",
    },
    "model_testing": {
      "enabled": bool(cfg["ENABLED"]),
      "disabled_reason": _disabled_reason(cfg),
      "raw_evidence_enabled": bool(cfg["RAW_EVIDENCE_ENABLED"]),
      "raw_evaluator_evidence_enabled": bool(cfg["RAW_EVALUATOR_EVIDENCE_ENABLED"]),
      "raw_evidence_default_retention_days": cfg["RAW_EVIDENCE_DEFAULT_RETENTION_DAYS"],
      "raw_evidence_max_retention_days": cfg["RAW_EVIDENCE_MAX_RETENTION_DAYS"],
      "remote_provider_urls_enabled": bool(cfg["REMOTE_PROVIDER_URLS_ENABLED"]),
      "remote_provider_preflight_enabled": bool(cfg["REMOTE_PROVIDER_PREFLIGHT_ENABLED"]),
      "default_evaluator_model_available": bool(default_evaluator),
      "default_evaluator_model_label": default_label,
      "question_sets": sanitized_model_test_catalog(),
      "restricted_raw_permission": "job:view_raw_model_evidence",
      "restricted_raw_purge_permission": "job:purge_raw_model_evidence",
      "policy_source": "pentester_config",
    },
  }
