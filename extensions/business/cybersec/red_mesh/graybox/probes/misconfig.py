"""
Security misconfiguration probes — A02 debug/CORS/headers/cookies/CSRF/session.
"""

from .base import ProbeBase
from ..findings import GrayboxFinding


class MisconfigProbes(ProbeBase):
  """PT-A02-01..06: debug exposure, CORS, headers, cookies, CSRF bypass, session token."""

  requires_auth = False
  requires_regular_session = False
  is_stateful = False

  def run(self):
    self.run_safe("debug_exposure", self._test_debug_exposure)
    self.run_safe("cors", self._test_cors)
    self.run_safe("security_headers", self._test_security_headers)
    self.run_safe("cookie_attributes", self._test_cookie_attributes)
    self.run_safe("csrf_bypass", self._test_csrf_bypass)
    self.run_safe("session_token", self._test_session_token)
    return self.findings

  def _test_debug_exposure(self):
    """PT-A02-01: check debug/config endpoints for information disclosure."""
    session = self.auth.anon_session or self.auth.official_session
    if not session:
      return

    debug_paths = self.target_config.misconfig.debug_paths
    exposed = []
    for path in debug_paths:
      self.safety.throttle()
      url = self.target_url + path
      try:
        resp = session.get(url, timeout=10)
      except Exception:
        continue
      if resp.status_code == 200 and len(resp.text) > 50:
        exposed.append(path)

    if exposed:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-01",
        title="Debug/config endpoint exposed",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A02:2021",
        cwe=["CWE-200"],
        evidence=[f"exposed_paths={', '.join(exposed)}"],
        remediation="Disable debug endpoints in production. Restrict access by IP or authentication.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-01",
        title="Debug endpoints — not exposed",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"paths_tested={len(debug_paths)}"],
      ))

  def _test_cors(self):
    """PT-A02-02: check for permissive CORS configuration."""
    session = self.auth.anon_session or self.auth.official_session
    if not session:
      return

    self.safety.throttle()
    try:
      resp = session.get(
        self.target_url + "/",
        headers={"Origin": "http://evil.example.com"},
        timeout=10,
      )
    except Exception:
      return

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-02",
        title="Permissive CORS: wildcard origin",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A02:2021",
        cwe=["CWE-942"],
        evidence=[
          f"access_control_allow_origin={acao}",
          f"allow_credentials={acac}",
        ],
        remediation="Restrict Access-Control-Allow-Origin to trusted domains. Never use * with credentials.",
      ))
    elif acao == "http://evil.example.com":
      severity = "HIGH" if acac == "true" else "MEDIUM"
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-02",
        title="CORS reflects arbitrary origin",
        status="vulnerable",
        severity=severity,
        owasp="A02:2021",
        cwe=["CWE-942"],
        evidence=[
          f"access_control_allow_origin={acao}",
          f"allow_credentials={acac}",
        ],
        remediation="Validate the Origin header against an allowlist. Do not reflect arbitrary origins.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-02",
        title="CORS configuration — no misconfiguration detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"access_control_allow_origin={acao or 'absent'}"],
      ))

  def _test_security_headers(self):
    """PT-A02-03: check for missing security headers."""
    session = self.auth.anon_session or self.auth.official_session
    if not session:
      return

    self.safety.throttle()
    try:
      resp = session.get(self.target_url + "/", timeout=10)
    except Exception:
      return

    headers = resp.headers
    missing = []
    checked = [
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Strict-Transport-Security",
      "Content-Security-Policy",
      "X-XSS-Protection",
    ]
    for h in checked:
      if h.lower() not in {k.lower(): k for k in headers}:
        missing.append(h)

    if missing:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-03",
        title="Missing security headers",
        status="vulnerable",
        severity="LOW",
        owasp="A02:2021",
        cwe=["CWE-693"],
        evidence=[f"missing_headers={', '.join(missing)}"],
        remediation="Add security headers: " + ", ".join(missing),
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-03",
        title="Security headers — all present",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"headers_checked={len(checked)}"],
      ))

  def _test_cookie_attributes(self):
    """PT-A02-04: check session cookie security attributes."""
    if not self.auth.official_session:
      return

    cookies = self.auth.official_session.cookies
    issues = []
    for cookie in cookies:
      if not cookie.secure:
        issues.append(f"{cookie.name}:missing_Secure")
      if not cookie.has_nonstandard_attr("HttpOnly"):
        issues.append(f"{cookie.name}:missing_HttpOnly")
      samesite = cookie.get_nonstandard_attr("SameSite")
      if not samesite or samesite.lower() == "none":
        issues.append(f"{cookie.name}:weak_SameSite={samesite or 'absent'}")

    if issues:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-04",
        title="Insecure cookie attributes",
        status="vulnerable",
        severity="LOW",
        owasp="A02:2021",
        cwe=["CWE-614"],
        evidence=issues,
        remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-04",
        title="Cookie attributes — all secure",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=["all_cookies_have_secure_attributes"],
      ))

  def _test_csrf_bypass(self):
    """
    PT-A02-05: test if CSRF protection is enforced on state-changing endpoints.

    Submit POST without CSRF token to state-changing endpoints.
    If the server accepts → CSRF bypass detected.
    """
    if not self.auth.official_session:
      return

    csrf_test_endpoints = []
    for ep in self.target_config.business_logic.workflow_endpoints:
      csrf_test_endpoints.append(ep.path)
    for form in self.discovered_forms:
      if form == self.target_config.login_path:
        continue
      csrf_test_endpoints.append(form)

    if not csrf_test_endpoints:
      return

    tested = 0
    vulnerable_endpoints = []
    for path in csrf_test_endpoints[:5]:
      self.safety.throttle()
      url = self.target_url + path
      try:
        resp = self.auth.official_session.post(
          url, data={"test": "csrf_probe"}, timeout=10,
          headers={"Referer": "http://evil.example.com"},
        )
      except Exception:
        continue
      tested += 1
      body_lower = resp.text.lower()
      csrf_rejected = any(m in body_lower for m in [
        "csrf", "forbidden", "token", "invalid request",
      ]) or resp.status_code == 403
      if not csrf_rejected and resp.status_code < 400:
        vulnerable_endpoints.append(path)

    if vulnerable_endpoints:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-05",
        title="CSRF protection bypass",
        status="vulnerable",
        severity="HIGH",
        owasp="A02:2021",
        cwe=["CWE-352"],
        attack=["T1185"],
        evidence=[
          f"endpoints_without_csrf={', '.join(vulnerable_endpoints)}",
          f"endpoints_tested={tested}",
        ],
        replay_steps=[
          "Log in as authenticated user.",
          f"POST to {vulnerable_endpoints[0]} without CSRF token.",
          "Observe request accepted despite missing CSRF protection.",
        ],
        remediation="Enforce CSRF tokens on all state-changing endpoints. "
                    "Use SameSite=Strict cookies as defense-in-depth.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-05",
        title="CSRF protection — no bypass detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))

  def _test_session_token(self):
    """
    PT-A02-06: basic session token quality checks.

    Tests JWT alg=none, short session IDs.
    """
    if not self.auth.official_session:
      return

    import base64
    import json as _json
    evidence = []
    status = "not_vulnerable"

    cookies = self.auth.official_session.cookies.get_dict()
    for name, value in cookies.items():
      parts = value.split(".")
      if len(parts) == 3:
        try:
          header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
          header = _json.loads(base64.urlsafe_b64decode(header_b64))
          alg = header.get("alg", "")
          if alg.lower() == "none":
            evidence.append(f"jwt_alg_none=True; cookie={name}")
            status = "vulnerable"
          elif alg.upper().startswith("HS") and len(parts[2]) < 10:
            evidence.append(f"jwt_weak_signature=True; cookie={name}")
            if status == "not_vulnerable":
              status = "inconclusive"
        except Exception:
          pass

      if len(value) < 16 and any(c.isalnum() for c in value):
        evidence.append(f"short_session_token={name}; length={len(value)}")
        if status == "not_vulnerable":
          status = "inconclusive"

    severity = "HIGH" if status == "vulnerable" else (
      "LOW" if status == "inconclusive" else "INFO"
    )
    self.findings.append(GrayboxFinding(
      scenario_id="PT-A02-06",
      title="Session token weakness detected" if status != "not_vulnerable" else "Session token quality",
      status=status,
      severity=severity,
      owasp="A02:2021",
      cwe=["CWE-331", "CWE-345"] if evidence else [],
      evidence=evidence or ["all_tokens_appear_adequate"],
      remediation="Use cryptographically random session IDs (128+ bits). "
                  "Never use alg=none in JWT. Validate JWT signatures server-side.",
    ))
