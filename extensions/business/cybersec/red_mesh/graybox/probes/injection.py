"""
Injection probes — A03 + A05 + API7.
"""

import re

from .base import ProbeBase
from ..findings import GrayboxFinding


class InjectionProbes(ProbeBase):
  """
  PT-A05-01: controlled injection on login form.
  PT-A03-01: authenticated injection on discovered forms.
  PT-A03-02: stored XSS (stateful — gated).
  PT-API7-01: SSRF checks on URL-fetch endpoints.
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    self.run_safe("login_injection", self._test_login_injection)
    if self.auth.official_session:
      self.run_safe("authenticated_injection", self._test_authenticated_injection)
      if self._allow_stateful:
        self.run_safe("stored_xss", self._test_stored_xss)
      else:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A03-02",
          title="Stored XSS probe skipped: stateful probes disabled",
          status="inconclusive",
          severity="INFO",
          owasp="A03:2021",
          evidence=["stateful_probes_disabled=True",
                    "reason=stored_xss_writes_data_to_target"],
        ))
    self.run_safe("ssrf", self._test_ssrf)
    return self.findings

  def _test_login_injection(self):
    """PT-A05-01: inject into login form fields (unauthenticated)."""
    session = self.auth.make_anonymous_session()
    login_url = self.target_url + self.target_config.login_path

    payloads = [
      ("xss", '<script>alert(1)</script>', "CWE-79"),
      ("sqli", "' OR '1'='1", "CWE-89"),
    ]

    try:
      page = session.get(login_url, timeout=10)
    except Exception:
      session.close()
      return

    # Extract CSRF token if present
    csrf_field = self.auth.detected_csrf_field
    csrf_token = None
    if csrf_field:
      csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

    vulnerable = []
    for label, payload, cwe in payloads:
      self.safety.throttle()
      form_data = {
        self.target_config.username_field: payload,
        self.target_config.password_field: "test",
      }
      if csrf_token and csrf_field:
        form_data[csrf_field] = csrf_token

      try:
        resp = session.post(login_url, data=form_data, timeout=10)
      except Exception:
        continue

      # Check for reflection
      if payload in resp.text:
        vulnerable.append((label, cwe, payload))

    session.close()

    if vulnerable:
      for label, cwe, payload in vulnerable:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A05-01",
          title=f"Reflected {label.upper()} in login form",
          status="vulnerable",
          severity="HIGH" if label == "sqli" else "MEDIUM",
          owasp="A05:2021" if label == "sqli" else "A03:2021",
          cwe=[cwe],
          evidence=[
            f"endpoint={login_url}",
            f"field={self.target_config.username_field}",
            f"payload={payload}",
            "payload_reflected=True",
          ],
          replay_steps=[
            f"Submit {payload} in the username field of {self.target_config.login_path}.",
            "Observe payload reflected in the response.",
          ],
          remediation="Apply input validation and output encoding on all form fields.",
        ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A05-01",
        title="Login form injection — no reflection detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A05:2021",
        evidence=[f"payloads_tested={len(payloads)}"],
      ))

  def _test_authenticated_injection(self):
    """
    PT-A03-01: inject into authenticated form fields.

    Tests each discovered form's text inputs with XSS/SQLi payloads.
    Skips login form (already tested by _test_login_injection).
    """
    if not self.discovered_forms:
      return

    payloads = [
      ("xss", "<script>alert(1)</script>", "CWE-79"),
      ("sqli", "' OR '1'='1", "CWE-89"),
    ]
    login_path = self.target_config.login_path
    tested = 0
    vulnerable_forms = []

    for form_action in self.discovered_forms:
      if form_action == login_path:
        continue
      self.safety.throttle()
      url = self.target_url + form_action

      try:
        page = self.auth.official_session.get(url, timeout=10)
      except Exception:
        continue

      # Extract input field names
      input_names = re.findall(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']?text',
        page.text, re.IGNORECASE,
      )
      textarea_names = re.findall(
        r'<textarea[^>]+name=["\']([^"\']+)["\']',
        page.text, re.IGNORECASE,
      )
      all_inputs = input_names + textarea_names
      if not all_inputs:
        continue

      # Include CSRF token
      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

      for label, payload, cwe in payloads:
        self.safety.throttle()
        form_data = {name: payload for name in all_inputs}
        if csrf_token and csrf_field:
          form_data[csrf_field] = csrf_token

        try:
          resp = self.auth.official_session.post(url, data=form_data, timeout=10)
        except Exception:
          continue
        tested += 1

        if payload in resp.text:
          vulnerable_forms.append((form_action, label, cwe, all_inputs[0]))

    for form_action, label, cwe, field in vulnerable_forms:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-01",
        title=f"Reflected {label.upper()} in authenticated form",
        status="vulnerable",
        severity="HIGH" if label == "sqli" else "MEDIUM",
        owasp="A03:2021",
        cwe=[cwe],
        evidence=[
          f"endpoint={self.target_url + form_action}",
          f"field={field}",
          "payload_reflected=True",
        ],
        replay_steps=[
          "Log in as authenticated user.",
          f"Submit payload in {field} at {form_action}.",
          "Observe payload reflected in the response.",
        ],
        remediation="Apply input validation and output encoding on all form fields.",
      ))

    if tested > 0 and not vulnerable_forms:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-01",
        title="Authenticated injection — no reflection detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"forms_tested={tested}"],
      ))

  def _test_stored_xss(self):
    """
    PT-A03-02: stored XSS via authenticated form submission.

    Submits canary payload via POST to text inputs, then reads back
    via GET to detect unescaped reflection. Gated behind allow_stateful.
    """
    if not self.discovered_forms:
      return

    import uuid
    canary = f"XSS-CANARY-{uuid.uuid4().hex[:8]}"
    payload = f"<img src=x onerror=alert('{canary}')>"
    skip_paths = {self.target_config.login_path, self.target_config.logout_path}

    tested = 0
    for form_action in self.discovered_forms[:3]:
      if form_action in skip_paths:
        continue
      self.safety.throttle()
      url = self.target_url + form_action

      try:
        page = self.auth.official_session.get(url, timeout=10)
      except Exception:
        continue

      input_names = re.findall(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']?text',
        page.text, re.IGNORECASE,
      )
      textarea_names = re.findall(
        r'<textarea[^>]+name=["\']([^"\']+)["\']',
        page.text, re.IGNORECASE,
      )
      all_inputs = input_names + textarea_names
      if not all_inputs:
        continue

      form_data = {name: payload for name in all_inputs}
      csrf_field = self.auth.detected_csrf_field
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)
        if csrf_token:
          form_data[csrf_field] = csrf_token

      try:
        self.auth.official_session.post(url, data=form_data, timeout=10)
      except Exception:
        continue
      tested += 1

      self.safety.throttle()
      try:
        readback = self.auth.official_session.get(url, timeout=10)
      except Exception:
        continue

      if canary in readback.text and payload in readback.text:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A03-02",
          title="Stored cross-site scripting (XSS)",
          status="vulnerable",
          severity="HIGH",
          owasp="A03:2021",
          cwe=["CWE-79"],
          attack=["T1059.007"],
          evidence=[
            f"endpoint={url}",
            f"input_fields={', '.join(all_inputs)}",
            f"canary={canary}",
            "payload_reflected_unescaped=True",
          ],
          replay_steps=[
            "Log in as authenticated user.",
            f"POST XSS payload to {form_action} in field {all_inputs[0]}.",
            f"GET {form_action} and observe unescaped payload in response.",
          ],
          remediation="Apply output encoding on all user-supplied content. "
                      "Use Content-Security-Policy to mitigate impact.",
        ))
        return

    if tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-02",
        title="Stored XSS — no vulnerability detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"forms_tested={tested}"],
      ))

  def _test_ssrf(self):
    """
    PT-API7-01: SSRF checks on URL-fetch endpoints.

    Tests configured endpoints for server-side URL fetching.
    Detects reflected SSRF and timing-based hints for blind SSRF.
    """
    ssrf_endpoints = self.target_config.injection.ssrf_endpoints
    if not ssrf_endpoints:
      return

    import time as _time
    payload_url = "http://127.0.0.1:1/internal-probe"
    baseline_url = "http://example.invalid/nonexistent"

    for ep in ssrf_endpoints:
      self.safety.throttle()
      url = self.target_url + "/" + ep.path.lstrip("/")
      session = self.auth.official_session or self.auth.anon_session

      try:
        t0 = _time.monotonic()
        session.get(url, params={ep.param: baseline_url}, timeout=10)
        baseline_ms = (_time.monotonic() - t0) * 1000
      except Exception:
        continue

      try:
        t0 = _time.monotonic()
        resp = session.get(url, params={ep.param: payload_url}, timeout=10)
        probe_ms = (_time.monotonic() - t0) * 1000
      except Exception:
        continue

      if resp.status_code == 200 and "internal-probe" in resp.text:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-API7-01",
          title="Server-side request forgery",
          status="vulnerable",
          severity="MEDIUM",
          owasp="API7:2023",
          cwe=["CWE-918"],
          attack=["T1190"],
          evidence=[
            f"endpoint={url}",
            f"payload={payload_url}",
            f"status={resp.status_code}",
          ],
          replay_steps=[
            f"Request GET {ep.path} with {ep.param}={payload_url}.",
            "Observe server-side fetch of local callback URL.",
          ],
          remediation="Apply strict outbound URL allowlists and block local network ranges.",
        ))
        return

      if probe_ms > baseline_ms + 2000:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-API7-01",
          title="Possible blind SSRF (timing anomaly)",
          status="inconclusive",
          severity="LOW",
          owasp="API7:2023",
          cwe=["CWE-918"],
          attack=["T1190"],
          evidence=[
            f"endpoint={url}",
            f"probe_ms={probe_ms:.0f}",
            f"baseline_ms={baseline_ms:.0f}",
          ],
          replay_steps=[
            f"Request GET {ep.path} with {ep.param}={payload_url}.",
            "Compare response time against baseline with non-routable URL.",
          ],
          remediation="Investigate with out-of-band callback to confirm blind SSRF.",
        ))
        return
