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
    self.run_safe("open_redirect", self._test_open_redirect)
    if self.auth.official_session:
      self.run_safe("path_traversal", self._test_path_traversal)
      self.run_safe("reflected_xss", self._test_reflected_xss)
      self.run_safe("template_injection", self._test_template_injection)
      self.run_safe("command_injection", self._test_command_injection)
      self.run_safe("header_injection", self._test_header_injection)
      self.run_safe("json_type_confusion", self._test_json_type_confusion)
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

  def _test_open_redirect(self):
    """
    PT-A01-04: test URL parameters for open redirect vulnerabilities.

    Tests common redirect parameter names (next, url, redirect, return_to,
    continue, dest, goto, forward) with an external domain payload.
    Checks if the response issues a redirect to the attacker-controlled domain.

    Read-only: only sends GET requests with modified query parameters.
    """
    session = self.auth.official_session or self.auth.anon_session
    if not session:
      return

    redirect_params = [
      "next", "url", "redirect", "redirect_url", "return_to", "return",
      "continue", "dest", "destination", "goto", "forward", "redir",
      "returnUrl", "redirect_uri", "callback",
    ]
    payload = "//evil.example.com"
    payload_alt = "https://evil.example.com"

    # Test against: login page (common redirect after login), discovered routes
    test_paths = [self.target_config.login_path, self.target_config.logout_path]
    for route in self.discovered_routes:
      test_paths.append(route)
    # Deduplicate
    seen = set()
    unique_paths = []
    for p in test_paths:
      if p and p not in seen:
        seen.add(p)
        unique_paths.append(p)

    tested = 0
    vulnerable_evidence = []

    for path in unique_paths[:10]:  # cap to avoid excessive requests
      for param in redirect_params:
        self.safety.throttle()
        url = self.target_url + path
        try:
          resp = session.get(
            url, params={param: payload},
            timeout=10, allow_redirects=False,
          )
        except Exception:
          continue
        tested += 1

        # Check for redirect to evil domain
        if resp.status_code in (301, 302, 303, 307, 308):
          location = resp.headers.get("Location", "")
          if "evil.example.com" in location:
            vulnerable_evidence.append(
              f"endpoint={path}; param={param}; location={location}"
            )
            break  # one redirect per path is enough

        # Also test the alternate payload (full URL)
        if not vulnerable_evidence or vulnerable_evidence[-1].split(";")[0] != f"endpoint={path}":
          self.safety.throttle()
          try:
            resp2 = session.get(
              url, params={param: payload_alt},
              timeout=10, allow_redirects=False,
            )
          except Exception:
            continue
          tested += 1

          if resp2.status_code in (301, 302, 303, 307, 308):
            location2 = resp2.headers.get("Location", "")
            if "evil.example.com" in location2:
              vulnerable_evidence.append(
                f"endpoint={path}; param={param}; location={location2}"
              )
              break

      if len(vulnerable_evidence) >= 3:
        break  # enough evidence

    if vulnerable_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-04",
        title="Open redirect via URL parameter",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A01:2021",
        cwe=["CWE-601"],
        attack=["T1566"],
        evidence=vulnerable_evidence,
        replay_steps=[
          "Navigate to the vulnerable endpoint with redirect parameter.",
          f"Set parameter to {payload} or {payload_alt}.",
          "Observe 3xx redirect to attacker-controlled domain.",
        ],
        remediation="Validate redirect targets against a server-side allowlist. "
                    "Use relative paths only, or verify the destination host "
                    "matches your domain. Never pass user input directly to "
                    "Location headers.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-04",
        title="Open redirect — no vulnerability detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"parameters_tested={tested}"],
      ))

  def _test_path_traversal(self):
    """
    PT-A03-03: test parameters for directory traversal vulnerabilities.

    Tests query parameters and path segments in discovered routes with
    path traversal payloads. Checks response body for OS file content
    markers (e.g. root:x: from /etc/passwd).

    Read-only: only sends GET requests with modified parameters.
    """
    session = self.auth.official_session
    if not session:
      return

    traversal_payloads = [
      ("../../../../../../etc/passwd", ["root:x:", "root:*:", "daemon:", "nobody:"]),
      ("..\\..\\..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]", "[mci extensions]"]),
      ("....//....//....//....//etc/passwd", ["root:x:", "root:*:"]),  # filter bypass
    ]
    # Common parameter names that might accept file paths
    file_params = [
      "file", "path", "page", "doc", "document", "template", "include",
      "name", "folder", "dir", "download", "filename", "filepath",
      "view", "content", "layout", "resource",
    ]

    # Collect routes that have query-like structure or path parameters
    test_routes = []
    for route in self.discovered_routes:
      test_routes.append(route)
    # Always test the root as well
    if "/" not in test_routes:
      test_routes.append("/")

    tested = 0
    vulnerable_evidence = []

    for route in test_routes[:10]:  # cap to avoid excessive requests
      url = self.target_url + route

      # Strategy 1: inject via query parameters
      for param in file_params:
        if tested > 60:
          break  # hard cap on total requests
        for payload, markers in traversal_payloads:
          self.safety.throttle()
          try:
            resp = session.get(url, params={param: payload}, timeout=10)
          except Exception:
            continue
          tested += 1

          if resp.status_code == 200:
            body = resp.text
            if any(m in body for m in markers):
              vulnerable_evidence.append(
                f"endpoint={route}; param={param}; payload={payload}"
              )
              break  # one hit per route+param is enough
        if vulnerable_evidence:
          break  # found a hit on this route, move on

      if len(vulnerable_evidence) >= 3:
        break

    if vulnerable_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-03",
        title="Path traversal — file content disclosed",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-22"],
        attack=["T1083"],
        evidence=vulnerable_evidence,
        replay_steps=[
          "Log in as authenticated user.",
          f"Request GET with traversal payload in file parameter.",
          "Observe OS file contents (e.g. /etc/passwd) in response body.",
        ],
        remediation="Validate and sanitize all file path inputs server-side. "
                    "Use a whitelist of allowed files, canonicalize paths, "
                    "and ensure they stay within the application's base directory. "
                    "Never pass user input directly to file system operations.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-03",
        title="Path traversal — no vulnerability detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))

  # ── Batch 2 — A03 family expansion ──────────────────────────────────────

  def _test_reflected_xss(self):
    """PT-A03-04: detect reflected XSS behind authentication.

    Sends a script payload to each configured xss_endpoint and looks
    for unescaped reflection in the response body.
    """
    endpoints = self.target_config.injection.xss_endpoints
    if not endpoints:
      return

    payload = "<script>alert(1)</script>"
    sentinel = "<script>alert(1)</script>"

    vulnerable = []
    tested = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = self.auth.official_session.get(
          url, params={ep.param: payload}, timeout=10,
        )
      except Exception:
        continue
      tested += 1
      if resp.status_code == 200 and sentinel in resp.text:
        vulnerable.append(f"endpoint={ep.path}; param={ep.param}; payload_reflected_unescaped=True")
        break

    if vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-04",
        title="Reflected XSS — payload echoed unescaped",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-79"],
        attack=["T1059.007"],
        evidence=vulnerable,
        replay_steps=[
          f"GET {endpoints[0].path}?{endpoints[0].param}=<script>alert(1)</script>",
          "Observe payload returned in body without HTML escaping.",
        ],
        remediation="Escape user input on output (Django ``|escape``, "
                    "Jinja autoescape, etc.). Apply a Content Security "
                    "Policy that disallows inline scripts.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-04",
        title="Reflected XSS — payload escaped or not reflected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))

  def _test_template_injection(self):
    """PT-A03-06: detect server-side template injection.

    Sends ``${7*7}`` and ``{{7*7}}`` to each ssti_endpoint; vulnerable
    if the response body contains ``49``.
    """
    endpoints = self.target_config.injection.ssti_endpoints
    if not endpoints:
      return

    payloads = ["${7*7}", "{{7*7}}", "{{ 7*7 }}"]
    sentinel = "49"

    vulnerable = []
    tested = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      for payload in payloads:
        self.safety.throttle()
        try:
          resp = self.auth.official_session.get(
            url, params={ep.param: payload}, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        # Avoid false positives on echo-only sinks: require the body to
        # contain ``49`` BUT NOT contain the literal ``7*7`` (an echo
        # would reflect both the payload and the sentinel).
        if (resp.status_code == 200 and sentinel in resp.text
            and "7*7" not in resp.text):
          vulnerable.append(
            f"endpoint={ep.path}; param={ep.param}; "
            f"payload={payload}; sentinel_in_body=True"
          )
          break
      if vulnerable:
        break

    if vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-06",
        title="Server-side template injection — expression evaluated",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-94", "CWE-1336"],
        attack=["T1059"],
        evidence=vulnerable,
        replay_steps=[
          f"GET {endpoints[0].path}?{endpoints[0].param}=" + r"${7*7}",
          "Observe the response body contains 49 (the evaluated result).",
        ],
        remediation="Never render user-controlled data through a template "
                    "engine. If templates must be dynamic, use a sandbox "
                    "or precompiled templates only.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-06",
        title="Template injection — no expression evaluation observed",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))

  def _test_command_injection(self):
    """PT-A03-07: detect OS command injection via shell metacharacters.

    Sends payloads ``;id`` and ``$(id)``; vulnerable if the response
    body shows the canonical ``uid=`` prefix from ``id(1)``.
    """
    endpoints = self.target_config.injection.cmd_endpoints
    if not endpoints:
      return

    payloads = [";id", "$(id)", "`id`", "|id"]
    import re as _re
    sentinel = _re.compile(r"uid=\d+\(")

    vulnerable = []
    tested = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      for payload in payloads:
        self.safety.throttle()
        try:
          resp = self.auth.official_session.get(
            url, params={ep.param: payload}, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        if resp.status_code == 200 and sentinel.search(resp.text):
          vulnerable.append(
            f"endpoint={ep.path}; param={ep.param}; "
            f"payload={payload}; uid_marker_in_body=True"
          )
          break
      if vulnerable:
        break

    if vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-07",
        title="OS command injection — shell metacharacters honored",
        status="vulnerable",
        severity="CRITICAL",
        owasp="A03:2021",
        cwe=["CWE-78"],
        attack=["T1059.004"],
        evidence=vulnerable,
        replay_steps=[
          f"GET {endpoints[0].path}?{endpoints[0].param}=;id",
          "Observe ``uid=...`` from id(1) in the response body.",
        ],
        remediation="Never invoke a shell with user-controlled input. "
                    "Use parameterised process invocation "
                    "(``subprocess.run([...], shell=False)``) and pass "
                    "the input as an argv element, never a substring of "
                    "the command line.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-07",
        title="Command injection — shell metacharacters had no effect",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))

  def _test_header_injection(self):
    """PT-A03-12: detect HTTP header injection via CRLF.

    Sends a value with a CRLF + injected header; vulnerable if the
    response carries the injected header (or splits/loses the
    location header in a way that proves CRLF was honored).
    """
    endpoints = self.target_config.injection.header_endpoints
    if not endpoints:
      return

    inject_name = "X-Injected"
    inject_value = "pwned"
    payload = f"/safe-target\r\n{inject_name}: {inject_value}"

    vulnerable = []
    tested = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = self.auth.official_session.get(
          url, params={ep.param: payload},
          allow_redirects=False, timeout=10,
        )
      except Exception:
        continue
      tested += 1
      if resp.headers.get(inject_name) == inject_value:
        vulnerable.append(
          f"endpoint={ep.path}; param={ep.param}; "
          f"injected_header={inject_name}: {inject_value}"
        )
        break

    if vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-12",
        title="HTTP header injection via CRLF",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-93", "CWE-113"],
        attack=["T1190"],
        evidence=vulnerable,
        replay_steps=[
          f"GET {endpoints[0].path}?{endpoints[0].param}=/x"
          + r"\r\nX-Injected: pwned",
          "Observe the X-Injected response header set with the "
          "attacker-supplied value.",
        ],
        remediation="Strip ``\\r`` and ``\\n`` from values before they "
                    "land in response headers. Validate redirect "
                    "targets against an allowlist of paths.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-12",
        title="Header injection — CRLF stripped or not reflected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))

  def _test_json_type_confusion(self):
    """PT-A03-15: detect lax JSON body parsing on typed fields.

    Sends ``{"<field>": [1]}`` and ``{"<field>": {"$gt": 0}}`` to
    endpoints expecting an integer; vulnerable when a non-int payload
    is accepted (HTTP 2xx) or the response distinguishes the variant
    from a clean rejection.
    """
    endpoints = self.target_config.injection.json_type_endpoints
    if not endpoints:
      return

    import json as _json

    vulnerable = []
    tested = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      headers = {"Content-Type": "application/json"}

      # Baseline: clean integer
      self.safety.throttle()
      try:
        baseline = self.auth.official_session.post(
          url, data=_json.dumps({ep.field: 1}),
          headers=headers, timeout=10,
        )
      except Exception:
        continue
      if baseline.status_code >= 500:
        continue

      # Variant: list
      payloads_to_try = [[1], {"$gt": 0}]
      for variant in payloads_to_try:
        self.safety.throttle()
        try:
          resp = self.auth.official_session.post(
            url, data=_json.dumps({ep.field: variant}),
            headers=headers, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        if resp.status_code < 400:
          vulnerable.append(
            f"endpoint={ep.path}; field={ep.field}; "
            f"variant={variant!r}; status={resp.status_code}"
          )
          break
      if vulnerable:
        break

    if vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-15",
        title="JSON body type confusion — non-integer accepted",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A03:2021",
        cwe=["CWE-843", "CWE-704"],
        attack=["T1190"],
        evidence=vulnerable,
        replay_steps=[
          f"POST {endpoints[0].path} with body "
          f'``{{"{endpoints[0].field}": [1]}}`` or '
          f'``{{"{endpoints[0].field}": {{"$gt": 0}}}}``',
          "Observe the server processes the request without rejecting "
          "the type mismatch.",
        ],
        remediation="Validate JSON body fields against a typed schema "
                    "(pydantic, marshmallow, JSON Schema). Reject "
                    "lists, dicts, or operator-keys when an integer "
                    "is expected.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-15",
        title="JSON type confusion — typed validation in place",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
