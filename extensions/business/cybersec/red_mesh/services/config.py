def _config_attr_name(block_name):
  return f"cfg_{block_name.lower()}"


def resolve_config_block(owner, block_name, defaults, normalizer=None):
  """Resolve one shallow nested config block with partial override merge."""
  merged = dict(defaults or {})
  override = getattr(owner, _config_attr_name(block_name), None)
  if override is None:
    config = getattr(owner, "CONFIG", None)
    if isinstance(config, dict):
      override = config.get(block_name)
  if isinstance(override, dict):
    merged.update(override)

  if callable(normalizer):
    normalized = normalizer(dict(merged), dict(defaults or {}))
    if isinstance(normalized, dict):
      return normalized
  return merged
