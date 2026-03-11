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
    self.run_safe("login_rate_limiting", self._test_login_rate_limiting)
    self.run_safe("password_reset_token", self._test_password_reset_token)
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
    """PT-A02-02: check for permissive CORS configuration.

    Tests both the root URL and discovered API routes, since many apps
    only set CORS headers on API endpoints (e.g. /api/*).
    """
    session = self.auth.anon_session or self.auth.official_session
    if not session:
      return

    # Build candidate URLs: root + configured endpoints + discovered API routes.
    # Many apps only set CORS headers on API routes, so we must test those too.
    test_paths = ["/"]
    # Add configured endpoints (IDOR, admin, workflow) — these are known API paths
    for ep in self.target_config.access_control.idor_endpoints:
      test_paths.append(ep.path.replace("{id}", "1"))
    for ep in self.target_config.access_control.admin_endpoints:
      test_paths.append(ep.path)
    for ep in self.target_config.business_logic.workflow_endpoints:
      test_paths.append(ep.path.replace("{id}", "1"))
    # Add discovered API-like routes
    for route in self.discovered_routes:
      if "/api/" in route.lower():
        test_paths.append(route)
    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in test_paths:
      if p not in seen:
        seen.add(p)
        unique_paths.append(p)

    worst_finding = None
    for path in unique_paths:
      self.safety.throttle()
      try:
        resp = session.get(
          self.target_url + path,
          headers={"Origin": "http://evil.example.com"},
          timeout=10,
          allow_redirects=False,
        )
      except Exception:
        continue

      acao = resp.headers.get("Access-Control-Allow-Origin", "")
      acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

      if acao == "*":
        finding = GrayboxFinding(
          scenario_id="PT-A02-02",
          title="Permissive CORS: wildcard origin",
          status="vulnerable",
          severity="HIGH" if acac == "true" else "MEDIUM",
          owasp="A02:2021",
          cwe=["CWE-942"],
          evidence=[
            f"path={path}",
            f"access_control_allow_origin={acao}",
            f"allow_credentials={acac}",
          ],
          remediation="Restrict Access-Control-Allow-Origin to trusted domains. Never use * with credentials.",
        )
        if not worst_finding or finding.severity == "HIGH":
          worst_finding = finding
      elif acao == "http://evil.example.com":
        severity = "HIGH" if acac == "true" else "MEDIUM"
        finding = GrayboxFinding(
          scenario_id="PT-A02-02",
          title="CORS reflects arbitrary origin",
          status="vulnerable",
          severity=severity,
          owasp="A02:2021",
          cwe=["CWE-942"],
          evidence=[
            f"path={path}",
            f"access_control_allow_origin={acao}",
            f"allow_credentials={acac}",
          ],
          remediation="Validate the Origin header against an allowlist. Do not reflect arbitrary origins.",
        )
        if not worst_finding or severity == "HIGH":
          worst_finding = finding

    if worst_finding:
      self.findings.append(worst_finding)
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-02",
        title="CORS configuration — no misconfiguration detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"paths_tested={len(unique_paths)}"],
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
      path = ep.path.replace("{id}", "1") if "{id}" in ep.path else ep.path
      csrf_test_endpoints.append(path)
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

  def _test_login_rate_limiting(self):
    """
    PT-A02-07: test if login endpoint enforces rate limiting or account lockout.

    Sends a bounded burst of failed login attempts and checks whether the
    server blocks, throttles, or continues to accept them unchanged.
    """
    session = self.auth.make_anonymous_session()
    login_url = self.target_url + self.target_config.login_path

    try:
      page = session.get(login_url, timeout=10)
    except Exception:
      session.close()
      return

    csrf_field = self.auth.detected_csrf_field
    csrf_token = None
    if csrf_field:
      csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

    # Use a non-existent username to avoid locking a real account
    test_username = "ratelimit_probe_user_nonexist"
    attempts = 8
    blocked = False
    lockout_markers = [
      "account locked", "too many attempts", "temporarily blocked",
      "account suspended", "try again later", "rate limit",
    ]

    for i in range(attempts):
      self.safety.throttle(min_delay=0.1)

      # Re-extract CSRF token each time (some frameworks rotate it)
      if csrf_field and i > 0:
        try:
          page = session.get(login_url, timeout=10)
          csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
        except Exception:
          pass

      payload = {
        self.target_config.username_field: test_username,
        self.target_config.password_field: f"wrong_password_{i}",
      }
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token

      try:
        resp = session.post(
          login_url, data=payload,
          headers={"Referer": login_url},
          timeout=10,
        )
      except Exception:
        continue

      if resp.status_code == 429:
        blocked = True
        break
      body_lower = resp.text.lower()
      if any(m in body_lower for m in lockout_markers):
        blocked = True
        break

    session.close()

    if not blocked:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-07",
        title="Login rate limiting not enforced",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A02:2021",
        cwe=["CWE-307"],
        attack=["T1110"],
        evidence=[
          f"endpoint={login_url}",
          f"attempts={attempts}",
          "lockout_triggered=False",
          "rate_limiting_detected=False",
        ],
        replay_steps=[
          f"Send {attempts} failed login attempts in rapid succession.",
          "Observe no lockout or rate limiting response.",
        ],
        remediation="Implement account lockout after repeated failures. "
                    "Add rate limiting (e.g. 429 responses) on login endpoints.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-07",
        title="Login rate limiting — enforced",
        status="not_vulnerable",
        severity="INFO",
        owasp="A02:2021",
        evidence=[
          f"endpoint={login_url}",
          f"lockout_triggered_after={attempts}_or_fewer_attempts",
        ],
      ))

  def _test_password_reset_token(self):
    """
    PT-A07-02: test password reset token predictability.

    Requests two reset tokens for the same user and checks:
    1. Token is exposed in the response body (info leak).
    2. Token matches a predictable pattern (e.g. reset-{username}).
    3. Token is identical across requests (no randomness).
    """
    reset_path = self.target_config.password_reset_path
    if not reset_path:
      return

    session = self.auth.make_anonymous_session()
    reset_url = self.target_url + reset_path
    test_username = self.auth.target_config.username_field and "admin"

    # Get CSRF token for the reset form
    try:
      page = session.get(reset_url, timeout=10)
    except Exception:
      session.close()
      return

    if page.status_code == 404:
      session.close()
      return

    csrf_field = self.auth.detected_csrf_field
    csrf_token = None
    if csrf_field:
      csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

    import re
    tokens = []
    for i in range(2):
      self.safety.throttle()
      if i > 0 and csrf_field:
        try:
          page = session.get(reset_url, timeout=10)
          csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
        except Exception:
          pass

      payload = {"username": test_username}
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token

      try:
        resp = session.post(
          reset_url, data=payload,
          headers={"Referer": reset_url},
          timeout=10, allow_redirects=True,
        )
      except Exception:
        continue

      # Look for token-like strings in the response
      body = resp.text
      # Common patterns: "token": "...", token=..., /confirm?token=...
      token_patterns = [
        re.compile(r'reset[-_]token["\s:=]+([a-zA-Z0-9_-]{4,})', re.I),
        re.compile(r'token["\s:=]+([a-zA-Z0-9_-]{8,})', re.I),
        re.compile(r'Your reset (?:token|code)[^<]*?(\S{4,})', re.I),
        # Direct token display (e.g. "reset-admin")
        re.compile(r'(reset-\w+)', re.I),
      ]
      for pat in token_patterns:
        m = pat.search(body)
        if m:
          tokens.append(m.group(1))
          break

    session.close()

    evidence = []
    status = "not_vulnerable"
    issues = []

    if len(tokens) >= 1:
      evidence.append(f"token_exposed_in_response=True")
      issues.append("token_leaked_in_body")

    if len(tokens) >= 2 and tokens[0] == tokens[1]:
      evidence.append(f"tokens_identical=True")
      issues.append("no_randomness")

    for token in tokens:
      # Check for predictable format: reset-{username}
      if token.lower() == f"reset-{test_username}".lower():
        evidence.append(f"predictable_token_format=reset-{{username}}")
        issues.append("predictable_format")
        break
      # Check for very short tokens
      if len(token) < 16:
        evidence.append(f"token_length={len(token)}")
        issues.append("short_token")
        break

    if "predictable_format" in issues or "no_randomness" in issues:
      status = "vulnerable"
    elif "token_leaked_in_body" in issues or "short_token" in issues:
      status = "inconclusive"

    if status == "vulnerable":
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-02",
        title="Predictable password reset tokens",
        status="vulnerable",
        severity="HIGH",
        owasp="A07:2021",
        cwe=["CWE-640", "CWE-330"],
        attack=["T1110"],
        evidence=evidence,
        replay_steps=[
          f"POST to {reset_path} with username={test_username}.",
          "Extract token from response body.",
          "Observe token matches predictable pattern.",
        ],
        remediation="Use cryptographically random tokens (128+ bits). "
                    "Never expose tokens in HTML responses. "
                    "Enforce single-use and short expiration.",
      ))
    elif status == "inconclusive":
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-02",
        title="Password reset token — potential weakness",
        status="inconclusive",
        severity="LOW",
        owasp="A07:2021",
        cwe=["CWE-640"],
        evidence=evidence,
        remediation="Use cryptographically random tokens (128+ bits). "
                    "Do not expose tokens in HTML responses.",
      ))
    elif tokens:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-02",
        title="Password reset token — no weakness detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A07:2021",
        evidence=[f"tokens_checked={len(tokens)}"],
      ))
