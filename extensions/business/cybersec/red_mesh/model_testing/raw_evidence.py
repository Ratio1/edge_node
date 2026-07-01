"""Restricted raw Model Testing evidence helpers."""

RAW_MODEL_TEST_EVIDENCE_KIND = "redmesh_model_test_raw_evidence"


def is_restricted_raw_evidence_artifact(payload):
  """Return True when payload is a restricted raw model-test artifact."""
  return isinstance(payload, dict) and payload.get("kind") == RAW_MODEL_TEST_EVIDENCE_KIND
