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
    self.run_safe("password_reset_token_reuse", self._test_password_reset_token_reuse)
    self.run_safe("account_enumeration_timing", self._test_account_enumeration_timing)
    self.run_safe("jwt_weak_alg", self._test_jwt_weak_alg)
    self.run_safe("session_fixation", self._test_session_fixation)
    self.run_safe("account_enumeration", self._test_account_enumeration)
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

    # Anonymous-session CSRF: fall back through detected → configured → default.
    csrf_field = (
      self.auth.detected_csrf_field
      or self.target_config.csrf_field
      or "csrfmiddlewaretoken"
    )
    csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

    import re
    tokens = []
    for i in range(2):
      self.safety.throttle()
      if i > 0:
        try:
          page = session.get(reset_url, timeout=10)
          csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
        except Exception:
          pass

      payload = {"username": test_username}
      headers = {"Referer": reset_url}
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token
        headers["X-CSRFToken"] = csrf_token

      try:
        resp = session.post(
          reset_url, data=payload,
          headers=headers,
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

  def _test_password_reset_token_reuse(self):
    """
    PT-A02-18: detect password reset tokens that aren't invalidated on use.

    Two requests for the same user produce the same token string when the
    reset table never marks rows ``is_used=True`` after consumption — the
    canonical "token not invalidated" bug. Issuing a fresh token twice and
    observing identity is a non-destructive proxy that still flags the
    underlying server-side issue.

    Conservative: emits ``inconclusive`` INFO when the reset endpoint is
    configured but tokens couldn't be extracted (probe couldn't observe
    the bug); ``vulnerable`` HIGH when both issued tokens are identical;
    ``not_vulnerable`` INFO when the issued tokens differ.

    Stays read-only — does NOT consume tokens or mutate user passwords.
    Destructive verification (true two-consume test) is tracked separately.
    """
    reset_path = self.target_config.password_reset_path
    if not reset_path:
      return

    session = self.auth.make_anonymous_session()
    reset_url = self.target_url + reset_path
    test_username = "admin"

    try:
      page = session.get(reset_url, timeout=10)
    except Exception:
      session.close()
      return
    if page.status_code == 404:
      session.close()
      return

    # Probes that run on an anonymous session can't rely on AuthManager's
    # detected_csrf_field (it's populated during auth, not for anon flows).
    # Fall back to the configured csrf_field, then to Django's default.
    csrf_field = (
      self.auth.detected_csrf_field
      or self.target_config.csrf_field
      or "csrfmiddlewaretoken"
    )

    import re
    token_patterns = [
      re.compile(r'reset[-_]token["\s:=]+([a-zA-Z0-9_-]{4,})', re.I),
      re.compile(r'token["\s:=]+([a-zA-Z0-9_-]{8,})', re.I),
      re.compile(r'(reset-\w+)', re.I),
    ]

    issued = []
    for _ in range(2):
      self.safety.throttle()
      csrf_token = None
      try:
        page = session.get(reset_url, timeout=10)
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
      except Exception:
        pass

      payload = {"username": test_username}
      headers = {"Referer": reset_url}
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token
        # Django checks the X-CSRFToken header against the cookie too —
        # send both so the form-protected POST is accepted.
        headers["X-CSRFToken"] = csrf_token

      try:
        resp = session.post(
          reset_url, data=payload, headers=headers,
          timeout=10, allow_redirects=True,
        )
      except Exception:
        continue

      for pat in token_patterns:
        m = pat.search(resp.text)
        if m:
          issued.append(m.group(1))
          break

    session.close()

    if len(issued) < 2:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-18",
        title="Password reset token reuse — could not extract two tokens",
        status="inconclusive",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"tokens_extracted={len(issued)}",
          f"reset_endpoint={reset_path}",
          "reason=insufficient_response_visibility",
        ],
      ))
      return

    if issued[0] == issued[1]:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-18",
        title="Password reset token not invalidated between requests",
        status="vulnerable",
        severity="HIGH",
        owasp="A07:2021",
        cwe=["CWE-640", "CWE-294"],
        attack=["T1110"],
        evidence=[
          f"reset_endpoint={reset_path}",
          f"tokens_observed={len(issued)}",
          f"first_token={issued[0]}",
          "tokens_identical=True",
        ],
        replay_steps=[
          f"POST {reset_path} for {test_username} (request #1).",
          f"POST {reset_path} for {test_username} (request #2).",
          "Compare tokens in the response bodies — observe identity.",
          "Confirms the issued token persists across requests, "
          "implying it is not invalidated on consumption either.",
        ],
        remediation="Issue a fresh, single-use token on every reset request. "
                    "Mark the prior token consumed AND invalidated when a new "
                    "one is issued. Treat reset tokens like one-time bearer "
                    "credentials with short TTL.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-18",
        title="Password reset token rotates between requests",
        status="not_vulnerable",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"reset_endpoint={reset_path}",
          "tokens_identical=False",
        ],
      ))

  def _test_account_enumeration_timing(self):
    """
    PT-A02-17: detect account enumeration via login response timing.

    Many auth backends short-circuit on unknown usernames (skip bcrypt
    verification entirely) — leaking which usernames exist via the
    response time delta. Sends N=6 login attempts with a known good
    username + wrong password and N=6 with random unknown usernames +
    wrong password, all read-only and bounded by ``safety.throttle``.

    Emits ``vulnerable`` HIGH when the median delta between known and
    unknown is > 100ms; ``not_vulnerable`` INFO when the timings are
    indistinguishable. Does not consume credentials or change state.
    """
    if not self.target_config.login_path:
      return

    import time as _time
    import secrets

    known_user = self.regular_username or "admin"
    login_url = self.target_url + self.target_config.login_path
    sample_size = 6

    csrf_field_default = (
      self.auth.detected_csrf_field
      or self.target_config.csrf_field
      or "csrfmiddlewaretoken"
    )

    def _measure(username: str) -> float | None:
      """Return wall-time of one POST in milliseconds, or None on error."""
      session = self.auth.make_anonymous_session()
      try:
        page = session.get(login_url, timeout=10)
      except Exception:
        session.close()
        return None
      csrf_field = csrf_field_default
      csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
      payload = {"username": username, "password": "wrong-" + secrets.token_hex(4)}
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token
      headers = {"Referer": login_url}
      if csrf_token:
        headers["X-CSRFToken"] = csrf_token
      t0 = _time.monotonic()
      try:
        session.post(login_url, data=payload, headers=headers,
                     timeout=10, allow_redirects=False)
      except Exception:
        session.close()
        return None
      elapsed_ms = (_time.monotonic() - t0) * 1000
      session.close()
      return elapsed_ms

    known_timings = []
    unknown_timings = []
    for _ in range(sample_size):
      self.safety.throttle()
      v = _measure(known_user)
      if v is not None:
        known_timings.append(v)
    for _ in range(sample_size):
      self.safety.throttle()
      v = _measure("nx-" + secrets.token_hex(4))
      if v is not None:
        unknown_timings.append(v)

    if len(known_timings) < sample_size // 2 or len(unknown_timings) < sample_size // 2:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-17",
        title="Account enumeration timing — insufficient samples",
        status="inconclusive",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"known_samples={len(known_timings)}",
          f"unknown_samples={len(unknown_timings)}",
        ],
      ))
      return

    def _median(xs):
      xs = sorted(xs)
      n = len(xs)
      return xs[n // 2] if n % 2 == 1 else (xs[n // 2 - 1] + xs[n // 2]) / 2

    median_known = _median(known_timings)
    median_unknown = _median(unknown_timings)
    delta_ms = median_known - median_unknown
    threshold_ms = 100.0

    if delta_ms > threshold_ms:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-17",
        title="Account enumeration via login response timing",
        status="vulnerable",
        severity="HIGH",
        owasp="A07:2021",
        cwe=["CWE-204", "CWE-208"],
        attack=["T1087"],
        evidence=[
          f"known_user={known_user}",
          f"median_known_ms={median_known:.1f}",
          f"median_unknown_ms={median_unknown:.1f}",
          f"delta_ms={delta_ms:.1f}",
          f"threshold_ms={threshold_ms:.1f}",
          f"samples_each={sample_size}",
        ],
        replay_steps=[
          f"POST {self.target_config.login_path} with username={known_user} "
          "and a wrong password; record response time.",
          f"POST {self.target_config.login_path} with a random nonexistent "
          "username and a wrong password; record response time.",
          "Repeat each ~6 times. Compare medians — observe deltas wide "
          "enough to distinguish valid from invalid usernames.",
        ],
        remediation="Run the password verification (bcrypt/argon2) for both "
                    "known and unknown usernames. Use a constant-time auth "
                    "path so the response time does not depend on whether "
                    "the username exists.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-17",
        title="Login response timing — no enumeration signal",
        status="not_vulnerable",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"median_known_ms={median_known:.1f}",
          f"median_unknown_ms={median_unknown:.1f}",
          f"delta_ms={delta_ms:.1f}",
          f"threshold_ms={threshold_ms:.1f}",
        ],
      ))

  def _test_jwt_weak_alg(self):
    """
    PT-A02-12: detect JWT verifiers that accept ``alg=none``.

    A JWT issuer is configured via ``misconfig.jwt_endpoints`` — the
    issue path returns a Bearer token, the protected path echoes the
    asserted identity. The probe:

      1. POST credentials to the issue path; capture the token.
      2. Decode the body half (no signature needed) and re-encode with
         ``alg=none`` and ``is_admin=true`` (or whichever marker the
         catalog row keys on).
      3. GET the protected path with the forged token in
         ``Authorization: Bearer <token>``.
      4. If the response shows the elevated claim, the verifier
         accepted ``alg=none`` — vulnerable.

    Read-only: never modifies application state.
    """
    jwt_cfg = self.target_config.misconfig.jwt_endpoints
    if not jwt_cfg or not jwt_cfg.token_path or not jwt_cfg.protected_path:
      return

    import base64
    import json as _json
    import secrets

    # Use the official credentials we already authenticated with — the
    # AuthManager doesn't expose them directly, but we can read from the
    # env shape passed at probe-init time.
    issue_creds = {
      "username": jwt_cfg.username or self.regular_username or "admin",
      "password": jwt_cfg.password or "",
    }
    if not issue_creds["password"]:
      # Without a password we can't issue a baseline token.
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-12",
        title="JWT weak-alg probe — issuer credentials not configured",
        status="inconclusive",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"token_path={jwt_cfg.token_path}",
                  "reason=jwt_endpoints.password not set in target_config"],
      ))
      return

    session = self.auth.make_anonymous_session()
    token_url = self.target_url + jwt_cfg.token_path
    protected_url = self.target_url + jwt_cfg.protected_path

    # Step 1 — issue a baseline token.
    try:
      resp = session.post(token_url, json=issue_creds, timeout=10)
    except Exception:
      session.close()
      return
    if resp.status_code != 200:
      session.close()
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A02-12",
        title="JWT weak-alg probe — issuer rejected credentials",
        status="inconclusive",
        severity="INFO",
        owasp="A02:2021",
        evidence=[f"token_path={jwt_cfg.token_path}",
                  f"status={resp.status_code}"],
      ))
      return
    try:
      issued = resp.json().get("access_token") or resp.json().get("token")
    except Exception:
      issued = None
    if not issued or "." not in issued:
      session.close()
      return

    def _b64url_decode(s):
      pad = "=" * (-len(s) % 4)
      return base64.urlsafe_b64decode(s + pad)

    def _b64url_encode(b):
      return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    parts = issued.split(".")
    if len(parts) != 3:
      session.close()
      return
    try:
      original_claims = _json.loads(_b64url_decode(parts[1]))
    except Exception:
      session.close()
      return

    # Step 2 — forge an alg=none token with elevated claims.
    forged_claims = dict(original_claims)
    forged_claims["is_admin"] = True
    forged_claims["sub"] = original_claims.get("sub", issue_creds["username"])
    none_header = _json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":"))
    forged_token = (
      f"{_b64url_encode(none_header.encode())}."
      f"{_b64url_encode(_json.dumps(forged_claims, separators=(',', ':')).encode())}."
    )

    # Step 3 — hit the protected endpoint with the forged token.
    try:
      me = session.get(
        protected_url,
        headers={"Authorization": f"Bearer {forged_token}"},
        timeout=10,
      )
    except Exception:
      session.close()
      return
    session.close()

    if me.status_code == 200:
      try:
        me_body = me.json()
      except Exception:
        me_body = {}
      admin_asserted = bool(me_body.get("is_admin")) or me_body.get("alg") == "none"
      if admin_asserted:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A02-12",
          title="JWT verifier accepts alg=none",
          status="vulnerable",
          severity="HIGH",
          owasp="A02:2021",
          cwe=["CWE-327", "CWE-345"],
          attack=["T1550"],
          evidence=[
            f"token_path={jwt_cfg.token_path}",
            f"protected_path={jwt_cfg.protected_path}",
            f"forged_alg=none",
            f"forged_claim_is_admin=True",
            f"server_returned={me_body!r}"[:500],
          ],
          replay_steps=[
            f"POST {jwt_cfg.token_path} with valid credentials.",
            "Decode the issued JWT body, set is_admin=true, "
            "re-encode with header alg=none and an empty signature.",
            f"GET {jwt_cfg.protected_path} with the forged token.",
            "Observe the server returns elevated claims.",
          ],
          remediation="Reject any JWT whose header advertises ``alg=none`` "
                      "(or any algorithm not in an explicit allowlist). "
                      "Pin the verification algorithm server-side rather "
                      "than reading it from the untrusted header.",
        ))
        return

    self.findings.append(GrayboxFinding(
      scenario_id="PT-A02-12",
      title="JWT verifier rejects alg=none",
      status="not_vulnerable",
      severity="INFO",
      owasp="A02:2021",
      evidence=[
        f"token_path={jwt_cfg.token_path}",
        f"protected_path={jwt_cfg.protected_path}",
        f"protected_status={me.status_code}",
      ],
    ))

  def _test_session_fixation(self):
    """
    PT-A07-03: test if session token rotates after successful login.

    Session fixation occurs when the session ID remains the same before
    and after authentication. An attacker who can set a pre-auth session
    cookie (via XSS, URL injection, or subdomain) gains full access once
    the victim logs in with that same session ID.

    Compares pre-auth cookies from a fresh anonymous session against the
    post-auth cookies on the already-established official session.
    Read-only: does not perform additional logins.
    """
    if not self.auth.official_session:
      return

    login_url = self.target_url + self.target_config.login_path

    # Step 1: GET login page with a fresh session, capture pre-auth cookies
    pre_session = self.auth.make_anonymous_session()
    try:
      pre_session.get(login_url, timeout=10, allow_redirects=True)
    except Exception:
      pre_session.close()
      return

    pre_cookies = pre_session.cookies
    if hasattr(pre_cookies, "get_dict"):
      pre_cookies = pre_cookies.get_dict()
    else:
      pre_cookies = dict(pre_cookies)

    pre_session.close()

    if not pre_cookies:
      return  # no pre-auth cookies → can't test fixation

    # Step 2: get post-auth cookies from the existing official session
    post_cookies = self.auth.official_session.cookies
    if hasattr(post_cookies, "get_dict"):
      post_cookies = post_cookies.get_dict()
    else:
      post_cookies = dict(post_cookies)

    if not post_cookies:
      return  # no post-auth cookies → can't compare

    # Step 3: compare session cookies
    # Find cookies that exist in BOTH pre-auth and post-auth with the same value
    csrf_field = self.auth.detected_csrf_field
    csrf_names = {"csrftoken", "csrf_token", "_csrf"}
    if csrf_field:
      csrf_names.add(csrf_field.lower())

    fixed_cookies = []
    for name, pre_value in pre_cookies.items():
      post_value = post_cookies.get(name)
      if post_value and pre_value == post_value:
        # Skip CSRF tokens — they're not session identifiers
        if name.lower() in csrf_names:
          continue
        fixed_cookies.append(name)

    if fixed_cookies:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-03",
        title="Session fixation — token not rotated after login",
        status="vulnerable",
        severity="HIGH",
        owasp="A07:2021",
        cwe=["CWE-384"],
        attack=["T1550"],
        evidence=[
          f"fixed_cookies={','.join(fixed_cookies)}",
          "pre_auth_value_equals_post_auth_value=True",
        ],
        replay_steps=[
          "Obtain a pre-authentication session cookie.",
          "Log in using valid credentials.",
          "Observe that the session cookie value did not change.",
          "An attacker who sets this cookie before login inherits the authenticated session.",
        ],
        remediation="Regenerate session ID after successful authentication. "
                    "Django: this is automatic. Flask: call session.regenerate(). "
                    "Rails: call reset_session in the login action.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-03",
        title="Session fixation — token properly rotated",
        status="not_vulnerable",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"pre_auth_cookies={len(pre_cookies)}",
          f"post_auth_cookies={len(post_cookies)}",
          "all_session_tokens_rotated=True",
        ],
      ))

  def _test_account_enumeration(self):
    """
    PT-A07-04: test if login responses differ for valid vs invalid usernames.

    Compares error responses when submitting:
    1. A known-valid username with a wrong password
    2. A definitely-invalid username with a wrong password

    If the responses differ (different error message, status code, or
    response length), attackers can enumerate valid accounts.

    Read-only: only submits failed login attempts.
    """
    login_url = self.target_url + self.target_config.login_path

    # We need a known-valid username — use the official account username
    valid_username = self.auth.target_config.username_field
    # Actually, we need the actual username value, not the field name.
    # We can infer it: if official_session exists, the configured username is valid.
    # The username is not stored in AuthManager — use the regular_username from probe
    # init, or fall back to common defaults.
    valid_username = self.regular_username or "admin"

    invalid_username = "enum_probe_nonexistent_user_x9z7q"
    wrong_password = "wrong_password_probe"

    session = self.auth.make_anonymous_session()

    def _submit_login(username):
      """Submit a failed login and return (status_code, body, content_length)."""
      try:
        page = session.get(login_url, timeout=10)
      except Exception:
        return None

      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

      payload = {
        self.target_config.username_field: username,
        self.target_config.password_field: wrong_password,
      }
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token

      try:
        resp = session.post(
          login_url, data=payload,
          headers={"Referer": login_url},
          timeout=10, allow_redirects=True,
        )
      except Exception:
        return None

      return (resp.status_code, resp.text, len(resp.text))

    self.safety.throttle()
    result_valid = _submit_login(valid_username)
    self.safety.throttle()
    result_invalid = _submit_login(invalid_username)

    session.close()

    if not result_valid or not result_invalid:
      return

    status_valid, body_valid, len_valid = result_valid
    status_invalid, body_invalid, len_invalid = result_invalid

    differences = []

    # Check status code difference
    if status_valid != status_invalid:
      differences.append(f"status_code: valid={status_valid}, invalid={status_invalid}")

    # Check for different error messages
    # Extract the specific error text near common patterns
    import re
    error_patterns = [
      r'(?:class=["\'][^"\']*error[^"\']*["\'][^>]*>)(.*?)<',
      r'(?:class=["\'][^"\']*alert[^"\']*["\'][^>]*>)(.*?)<',
      r'(?:class=["\'][^"\']*message[^"\']*["\'][^>]*>)(.*?)<',
    ]
    msg_valid = ""
    msg_invalid = ""
    for pat in error_patterns:
      m_valid = re.search(pat, body_valid, re.I | re.DOTALL)
      m_invalid = re.search(pat, body_invalid, re.I | re.DOTALL)
      if m_valid:
        msg_valid = m_valid.group(1).strip()
      if m_invalid:
        msg_invalid = m_invalid.group(1).strip()
      if msg_valid and msg_invalid:
        break

    if msg_valid and msg_invalid and msg_valid != msg_invalid:
      differences.append(f"error_message: valid_user='{msg_valid[:80]}', "
                         f"invalid_user='{msg_invalid[:80]}'")

    # Check response length difference (>10% threshold to avoid noise)
    if len_valid > 0 and len_invalid > 0:
      ratio = abs(len_valid - len_invalid) / max(len_valid, len_invalid)
      if ratio > 0.10:
        differences.append(f"response_length: valid={len_valid}, invalid={len_invalid}")

    if differences:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-04",
        title="Account enumeration via login response differences",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A07:2021",
        cwe=["CWE-204"],
        attack=["T1078"],
        evidence=differences,
        replay_steps=[
          f"Submit login with valid username '{valid_username}' and wrong password.",
          f"Submit login with invalid username '{invalid_username}' and wrong password.",
          "Compare responses — differences reveal account existence.",
        ],
        remediation="Return identical error messages for all failed login attempts. "
                    "Use generic text like 'Invalid credentials' regardless of "
                    "whether the username exists.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-04",
        title="Account enumeration — responses consistent",
        status="not_vulnerable",
        severity="INFO",
        owasp="A07:2021",
        evidence=[
          f"status_codes_match={status_valid == status_invalid}",
          f"response_lengths_similar=True",
        ],
      ))
