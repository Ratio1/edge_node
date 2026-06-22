from .config import resolve_config_block


SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

DEFAULT_MISP_EXPORT_CONFIG = {
  "ENABLED": False,
  "AUTO_EXPORT": False,
  "MISP_URL": "",
  "MISP_API_KEY": "",
  "MISP_VERIFY_TLS": True,
  "MISP_DISTRIBUTION": 0,       # 0=org only, 1=community, 2=connected, 3=all
  "MISP_PUBLISH": False,
  "TIMEOUT": 30.0,
  "MIN_SEVERITY": "LOW",
}


def get_misp_export_config(owner):
  """Return normalized MISP export config."""
  def _normalize(merged, defaults):
    enabled = bool(merged.get("ENABLED", defaults["ENABLED"]))
    auto_export = bool(merged.get("AUTO_EXPORT", defaults["AUTO_EXPORT"]))

    url = str(merged.get("MISP_URL") or defaults["MISP_URL"]).strip().rstrip("/")
    api_key = str(merged.get("MISP_API_KEY") or defaults["MISP_API_KEY"]).strip()
    verify_tls = bool(merged.get("MISP_VERIFY_TLS", defaults["MISP_VERIFY_TLS"]))
    publish = bool(merged.get("MISP_PUBLISH", defaults["MISP_PUBLISH"]))

    try:
      distribution = int(merged.get("MISP_DISTRIBUTION", defaults["MISP_DISTRIBUTION"]))
    except (TypeError, ValueError):
      distribution = defaults["MISP_DISTRIBUTION"]
    if distribution < 0 or distribution > 3:
      distribution = defaults["MISP_DISTRIBUTION"]

    try:
      timeout = float(merged.get("TIMEOUT", defaults["TIMEOUT"]))
    except (TypeError, ValueError):
      timeout = defaults["TIMEOUT"]
    if timeout <= 0:
      timeout = defaults["TIMEOUT"]

    min_severity = str(
      merged.get("MIN_SEVERITY") or defaults["MIN_SEVERITY"]
    ).strip().upper()
    if min_severity not in SEVERITY_LEVELS:
      min_severity = defaults["MIN_SEVERITY"]

    return {
      "ENABLED": enabled,
      "AUTO_EXPORT": auto_export,
      "MISP_URL": url,
      "MISP_API_KEY": api_key,
      "MISP_VERIFY_TLS": verify_tls,
      "MISP_DISTRIBUTION": distribution,
      "MISP_PUBLISH": publish,
      "TIMEOUT": timeout,
      "MIN_SEVERITY": min_severity,
    }

  return resolve_config_block(
    owner,
    "MISP_EXPORT",
    DEFAULT_MISP_EXPORT_CONFIG,
    normalizer=_normalize,
  )
