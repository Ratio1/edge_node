"""Tenancy and caller-identity support for the RedMesh plugin (RM-075, RM-026)."""


def tenancy_namespace(owner):
  """The CStore partition name for tenant data: the pipeline stream id (deeploy `app_id`), stripped.
  None when missing or empty, so every caller fails closed. Never read from config or a request."""
  value = getattr(owner, "_stream_id", None)
  value = value.strip() if isinstance(value, str) else ""
  return value or None
