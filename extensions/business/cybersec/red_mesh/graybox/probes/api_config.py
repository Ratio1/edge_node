"""API misconfiguration + inventory probes — OWASP API8 and API9."""

import re

import requests

from .base import ProbeBase


_DEBUG_BODY_MARKERS = (
  re.compile(r"(?i)\btraceback\b"),
  re.compile(r"(?i)\bstack trace\b"),
  re.compile(r"(?i)\bdebug\b"),
  re.compile(r"(?i)\bDEBUG\s*=\s*True"),
  re.compile(r"(?i)at\s+/(?:usr|home|opt|app)/"),
  re.compile(r"(?i)urlpattern"),
  re.compile(r"\"swagger\"\s*:"),
  re.compile(r"\"openapi\"\s*:"),
)

_VERBOSE_ERROR_MARKERS = (
  re.compile(r"(?i)\bTraceback\b"),
  re.compile(r"(?i)Exception"),
  re.compile(r"(?i)Stack trace"),
  re.compile(r"(?i)at\s+/(?:usr|home|opt|app)/"),
  re.compile(r"(?i)line\s+\d+"),
  re.compile(r"(?i)Werkzeug|Flask|Django|FastAPI"),
)


class ApiConfigProbes(ProbeBase):
  """OWASP API8 + API9 graybox probes.

  Scenarios implemented (Subphases 2.4 + 2.5):
    PT-OAPI8-01 / 02 / 03 / 04 / 05 — Subphase 2.4
    PT-OAPI9-01 / 02 / 03 — Subphase 2.5
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings

    # API8 misconfig probes — require a function endpoint to probe AGAINST
    # (CORS / methods) or run against `debug_path_candidates` directly.
    if getattr(api_security, "function_endpoints", None):
      self.run_safe("api_cors_misconfig", self._test_cors_misconfig)
      self.run_safe("api_security_headers", self._test_security_headers)
      self.run_safe("api_unexpected_methods", self._test_unexpected_methods)
      self.run_safe("api_verbose_error", self._test_verbose_error)
    self.run_safe("api_debug_endpoint", self._test_debug_endpoint_exposed)

    # API9 inventory
    self.run_safe("api_openapi_exposed", self._test_openapi_exposed)
    self.run_safe("api_version_sprawl", self._test_version_sprawl)
    self.run_safe("api_deprecated_live", self._test_deprecated_live)
    return self.findings

  # ── helpers ────────────────────────────────────────────────────────

  def _session(self):
    return self.auth.official_session or self.auth.regular_session

  def _anon_session(self):
    if hasattr(self.auth, "make_anonymous_session"):
      try:
        return self.auth.make_anonymous_session()
      except Exception:
        return None
    return None

  # ── PT-OAPI8-01 — Permissive CORS ─────────────────────────────────

  def _test_cors_misconfig(self):
    api_security = self.target_config.api_security
    session = self._session()
    if session is None:
      self.emit_inconclusive(
        "PT-OAPI8-01", "API permissive CORS configuration",
        "API8:2023", "no_authenticated_session",
      )
      return
    found_any = False
    for ep in api_security.function_endpoints:
      if not self.budget():
        return
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.get(
          url, headers={"Origin": "https://evil.example"},
          timeout=10, allow_redirects=False,
        )
      except requests.RequestException:
        continue

      acao = resp.headers.get("Access-Control-Allow-Origin", "")
      acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower()
      origin_echoes_evil = "evil.example" in acao
      wildcard_with_creds = acao == "*" and acac == "true"

      if wildcard_with_creds or (origin_echoes_evil and acac == "true"):
        severity = "HIGH"
      elif acao == "*":
        severity = "LOW"
      else:
        self.emit_clean(
          "PT-OAPI8-01", "API permissive CORS configuration", "API8:2023",
          [f"endpoint={url}", f"acao={acao or '<absent>'}",
           f"acac={acac or '<absent>'}"],
        )
        found_any = True
        continue

      self.emit_vulnerable(
        "PT-OAPI8-01", "API permissive CORS configuration",
        severity, "API8:2023", ["CWE-942"],
        [f"endpoint={url}", f"acao={acao}", f"acac={acac}",
         f"sent_origin=https://evil.example"],
        remediation=(
          "Replace permissive CORS with an explicit allowlist of trusted "
          "origins. Never echo an arbitrary Origin alongside "
          "Access-Control-Allow-Credentials: true."
        ),
      )
      found_any = True
    if not found_any:
      self.emit_inconclusive(
        "PT-OAPI8-01", "API permissive CORS configuration",
        "API8:2023", "no_evaluable_responses",
      )

  # ── PT-OAPI8-02 — Missing security headers ────────────────────────

  def _test_security_headers(self):
    api_security = self.target_config.api_security
    session = self._session()
    if session is None:
      return
    for ep in api_security.function_endpoints:
      if not self.budget():
        return
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      missing = []
      headers_lower = {k.lower(): v for k, v in resp.headers.items()}
      if "x-content-type-options" not in headers_lower:
        missing.append("X-Content-Type-Options")
      if self.target_url.startswith("https") and \
         "strict-transport-security" not in headers_lower:
        missing.append("Strict-Transport-Security")
      if "cache-control" not in headers_lower:
        missing.append("Cache-Control")
      if missing:
        self.emit_vulnerable(
          "PT-OAPI8-02", "API response missing security headers",
          "LOW", "API8:2023", ["CWE-693"],
          [f"endpoint={url}", "missing_headers=" + ",".join(missing)],
          remediation=(
            "Set the missing security headers via middleware. "
            "X-Content-Type-Options: nosniff and a sensible Cache-Control "
            "are appropriate on every API response; "
            "Strict-Transport-Security is mandatory over HTTPS."
          ),
        )
      else:
        self.emit_clean(
          "PT-OAPI8-02", "API response missing security headers",
          "API8:2023",
          [f"endpoint={url}", "all_expected_headers_present"],
        )

  # ── PT-OAPI8-03 — Debug endpoint exposed ─────────────────────────

  def _test_debug_endpoint_exposed(self):
    api_security = self.target_config.api_security
    session = self._session()
    if session is None:
      return
    for path in api_security.debug_path_candidates:
      if not self.budget():
        return
      url = self.target_url + path
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      if resp.status_code >= 400:
        continue
      body = (resp.text or "")[:2000]
      if any(p.search(body) for p in _DEBUG_BODY_MARKERS):
        self.emit_vulnerable(
          "PT-OAPI8-03", "API debug endpoint exposed",
          "MEDIUM", "API8:2023", ["CWE-200", "CWE-215"],
          [f"endpoint={url}", f"response_status={resp.status_code}",
           "debug_markers_present=true"],
          remediation=(
            "Remove debug / introspection endpoints from production "
            "deployments. If they must exist, gate them behind a "
            "non-public network or strong authentication."
          ),
        )

  # ── PT-OAPI8-04 — Verbose error response ─────────────────────────

  def _test_verbose_error(self):
    api_security = self.target_config.api_security
    session = self._session()
    if session is None:
      return
    for ep in api_security.function_endpoints:
      if not self.budget():
        return
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.post(
          url, data='{"x":', headers={"Content-Type": "application/json"},
          timeout=10, allow_redirects=False,
        )
      except requests.RequestException:
        continue
      body = (resp.text or "")[:2000]
      if any(p.search(body) for p in _VERBOSE_ERROR_MARKERS):
        self.emit_vulnerable(
          "PT-OAPI8-04", "API verbose error response leaks internals",
          "MEDIUM", "API8:2023", ["CWE-209"],
          [f"endpoint={url}", f"response_status={resp.status_code}",
           "stack_trace_or_framework_marker=present"],
          remediation=(
            "Catch unhandled exceptions and return a generic error body. "
            "Detailed exception traces belong in server logs, not API "
            "responses."
          ),
        )

  # ── PT-OAPI8-05 — Unexpected methods ─────────────────────────────

  def _test_unexpected_methods(self):
    api_security = self.target_config.api_security
    session = self._session()
    if session is None:
      return
    risky = {"TRACE", "PUT", "DELETE", "PATCH"}
    for ep in api_security.function_endpoints:
      if not self.budget():
        return
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.options(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      allow = (resp.headers.get("Allow") or "").upper()
      advertised = {m.strip() for m in allow.split(",") if m.strip()}
      offenders = advertised & risky
      # Skip when ep itself uses a mutating method legitimately.
      expected = {(ep.method or "GET").upper()}
      surprising = offenders - expected
      if surprising:
        self.emit_vulnerable(
          "PT-OAPI8-05", "API advertises unexpected HTTP methods",
          "LOW", "API8:2023", ["CWE-693"],
          [f"endpoint={url}", "allow_header=" + allow,
           "unexpected_methods=" + ",".join(sorted(surprising))],
          remediation=(
            "Restrict the endpoint's accepted HTTP methods to what it "
            "actually uses. TRACE is rarely needed in production; "
            "DELETE / PUT / PATCH should be present only on resources "
            "that genuinely require them."
          ),
        )

  # ── PT-OAPI9-01 — OpenAPI exposed ────────────────────────────────

  def _test_openapi_exposed(self):
    api_security = self.target_config.api_security
    inv = api_security.inventory_paths
    session = self._anon_session() or self._session()
    if session is None:
      return
    for path in inv.openapi_candidates:
      if not self.budget():
        return
      url = self.target_url + path
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      if resp.status_code >= 400:
        continue
      try:
        data = resp.json()
      except (ValueError, requests.exceptions.JSONDecodeError):
        continue
      if not isinstance(data, dict):
        continue
      if not (data.get("openapi") or data.get("swagger")):
        continue

      spec_paths = list((data.get("paths") or {}).keys())
      private = []
      for p in spec_paths:
        for pat in inv.private_path_patterns:
          if pat in p:
            private.append(p)
            break
      severity = "MEDIUM" if private else "LOW"
      ev = [f"path={url}", f"status={resp.status_code}",
             f"spec_paths_count={len(spec_paths)}",
             f"private_paths_count={len(private)}"]
      if private:
        ev.append("private_path_examples=" + ",".join(private[:3]))
      self.emit_vulnerable(
        "PT-OAPI9-01", "API OpenAPI/Swagger specification publicly exposed",
        severity, "API9:2023", ["CWE-1059", "CWE-538"], ev,
        remediation=(
          "Gate the OpenAPI/Swagger doc behind authentication, or "
          "publish only a curated subset of the spec covering public "
          "endpoints. Treat the unfiltered spec as if it were the source "
          "code — it advertises every internal route."
        ),
      )
      return  # one spec is enough
    self.emit_clean(
      "PT-OAPI9-01", "API OpenAPI/Swagger specification publicly exposed",
      "API9:2023", ["no_exposed_spec_at_candidates"],
    )

  # ── PT-OAPI9-02 — Version sprawl ─────────────────────────────────

  def _test_version_sprawl(self):
    api_security = self.target_config.api_security
    inv = api_security.inventory_paths
    if not inv.current_version or not inv.canonical_probe_path:
      return
    session = self._session()
    if session is None:
      return
    current = inv.current_version.rstrip("/")
    canonical = inv.canonical_probe_path
    if not canonical.startswith("/"):
      canonical = "/" + canonical

    for sibling in inv.version_sibling_candidates:
      if not self.budget():
        return
      sib = sibling.rstrip("/")
      if sib == current:
        continue
      sib_path = canonical.replace(current, sib, 1)
      sib_url = self.target_url + sib_path
      self.safety.throttle()
      try:
        resp = session.get(sib_url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      if 200 <= resp.status_code < 300:
        self.emit_vulnerable(
          "PT-OAPI9-02", "API legacy version still live (version sprawl)",
          "MEDIUM", "API9:2023", ["CWE-1059", "CWE-538"],
          [f"current_version={current}", f"sibling={sib}",
           f"sibling_url={sib_url}",
           f"sibling_status={resp.status_code}"],
          remediation=(
            "Decommission legacy API versions or gate them behind a "
            "deprecation policy. Live siblings often skip the security "
            "fixes applied to the current version."
          ),
        )

  # ── PT-OAPI9-03 — Deprecated still live ─────────────────────────

  def _test_deprecated_live(self):
    api_security = self.target_config.api_security
    inv = api_security.inventory_paths
    if not inv.deprecated_paths:
      return
    session = self._session()
    if session is None:
      return
    for path in inv.deprecated_paths:
      if not self.budget():
        return
      url = self.target_url + path
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue
      if 200 <= resp.status_code < 300:
        self.emit_vulnerable(
          "PT-OAPI9-03", "API deprecated path still serving requests",
          "MEDIUM", "API9:2023", ["CWE-1059"],
          [f"endpoint={url}", f"status={resp.status_code}"],
          remediation=(
            "Return 410 Gone (or a hard redirect to the supported "
            "endpoint) on deprecated paths."
          ),
        )
