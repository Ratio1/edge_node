"""
Injection probes — A03 + A05 + API7.
"""

import re
from urllib.parse import urlparse

from .base import ProbeBase
from ... import cvss_vectors as V
from ..findings import GrayboxFinding
from ..models.target_config import ReflectiveEndpoint
from ..scenario_catalog import graybox_scenario


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
    if self.auth.primary_session:
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
    self.run_safe_scenario("PT-API7-01", "ssrf", self._test_ssrf)
    # OWASP API Top 10 — Subphase 2.7: extend PT-API7-01 to scan JSON
    # body fields configured via target_config.api_security.ssrf_body_fields.
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is not None and getattr(api_security, "ssrf_body_fields", None):
      self.run_safe_scenario(
        "PT-API7-01", "ssrf_body_field", self._test_ssrf_body_field,
      )
    self.run_safe("open_redirect", self._test_open_redirect)
    if self.auth.primary_session:
      self.run_safe("path_traversal", self._test_path_traversal)
      self.run_safe("reflected_xss", self._test_reflected_xss)
      self.run_safe("template_injection", self._test_template_injection)
      self.run_safe("command_injection", self._test_command_injection)
      self.run_safe("header_injection", self._test_header_injection)
      self.run_safe("json_type_confusion", self._test_json_type_confusion)
    return self.findings

  def _emit_no_endpoint(self, scenario_id, kind):
    """Inconclusive coverage row for a family with no configured endpoint.

    Without it the family returns silently and the coverage view cannot tell
    "not tested" from "tested and clean".
    """
    entry = graybox_scenario(scenario_id) or {}
    self.emit_inconclusive(
      scenario_id,
      entry.get("title") or scenario_id,
      entry.get("owasp") or "",
      f"no_configured_{kind}_endpoints",
    )

  def _reflective_endpoints(self, configured):
    """The one boundary where discovered candidates join configured endpoints.

    - precedence: configured entries come first, are never capped, and win a
      (path, param) tie;
    - base path: discovery paths are origin-absolute and probes prefix
      ``target_url``, so the target's base path is stripped here and
      candidates outside it are dropped;
    - cap: at most ``max_candidates_per_family`` (clamped to the ceiling);
    - tag: discovered entries carry ``source="discovered"`` into evidence.
    A family with discovered candidates is not "no endpoint".
    """
    merged = list(configured)
    seen = {(ep.path, ep.param) for ep in merged}
    cap = self.target_config.discovery.max_candidates_per_family
    base = urlparse(self.target_url).path.rstrip("/")
    added = 0
    for cand in self.discovered_candidates:
      if cand.method != "GET" or added >= cap:
        continue
      path = cand.path
      if base:
        if not (path == base or path.startswith(base + "/")):
          continue  # outside the target's base path: not ours to request
        path = path[len(base):] or "/"
      key = (path, cand.param)
      if key in seen:
        continue
      seen.add(key)
      added += 1
      merged.append(ReflectiveEndpoint(
        path=path, param=cand.param, source=cand.source))
    return merged

  @staticmethod
  def _source_tag(ep):
    return "; source=discovered" if ep.source == "discovered" else ""

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
        if label == "sqli":
          # Reflection alone proves echo, not SQL injection.
          self.findings.append(GrayboxFinding(
            scenario_id="PT-A05-01",
            title="SQL injection payload reflected in login form: not confirmed",
            status="inconclusive",
            severity="LOW",
            owasp="A03:2021",
            cwe=[cwe],
            evidence=[
              f"endpoint={login_url}",
              f"field={self.target_config.username_field}",
              f"payload={payload}",
              "payload_reflected=True",
              "reason=sqli_reflection_only",
            ],
          ))
          continue
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A05-01",
          title=f"Reflected {label.upper()} in login form",
          status="vulnerable",
          severity="MEDIUM",
          cvss_vector=V.XSS_UNAUTHENTICATED,
          owasp="A03:2021",
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
        owasp="A03:2021",
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
    denied = 0
    vulnerable_forms = []

    for form_action in self.discovered_forms:
      if form_action == login_path:
        continue
      self.safety.throttle()
      url = self.target_url + form_action

      try:
        page = self.auth.primary_session.get(url, timeout=10)
      except Exception:
        continue
      # 405: a POST-only action. The GET baseline does not apply and there is
      # no form to read, so the payload POST with common field names decides.
      # Such actions often create or delete records, so only with allow_stateful.
      post_only = page.status_code == 405
      if post_only and not self._allow_stateful:
        continue
      if not post_only and not self.response_reached(page):
        denied += 1
        continue
      page_text = "" if post_only else page.text

      # Extract input field names
      input_names = re.findall(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']?text',
        page_text, re.IGNORECASE,
      )
      textarea_names = re.findall(
        r'<textarea[^>]+name=["\']([^"\']+)["\']',
        page_text, re.IGNORECASE,
      )
      all_inputs = input_names + textarea_names
      if post_only:
        all_inputs = ["title", "name", "comment", "message", "description"]
      if not all_inputs:
        continue

      # Include CSRF token
      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page_text, csrf_field)

      for label, payload, cwe in payloads:
        self.safety.throttle()
        form_data = {name: payload for name in all_inputs}
        if csrf_token and csrf_field:
          form_data[csrf_field] = csrf_token

        try:
          resp = self.auth.primary_session.post(url, data=form_data, timeout=10)
        except Exception:
          continue
        if not self.response_reached(resp):
          denied += 1
          continue
        tested += 1

        if payload in resp.text:
          vulnerable_forms.append((form_action, label, cwe, all_inputs[0]))

    for form_action, label, cwe, field in vulnerable_forms:
      if label == "sqli":
        # Reflection alone proves echo, not SQL injection.
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A03-01",
          title="SQL injection payload reflected in authenticated form: not confirmed",
          status="inconclusive",
          severity="LOW",
          owasp="A03:2021",
          cwe=[cwe],
          evidence=[
            f"endpoint={self.target_url + form_action}",
            f"field={field}",
            "payload_reflected=True",
            "reason=sqli_reflection_only",
          ],
        ))
        continue
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-01",
        title=f"Reflected {label.upper()} in authenticated form",
        status="vulnerable",
        severity="MEDIUM",
        cvss_vector=V.XSS_AUTHENTICATED,
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
    elif denied > 0 and not vulnerable_forms and tested == 0:
      self.emit_endpoint_denied("PT-A03-01")

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
    denied = 0
    for form_action in self.discovered_forms[:3]:
      if form_action in skip_paths:
        continue
      self.safety.throttle()
      url = self.target_url + form_action

      try:
        page = self.auth.primary_session.get(url, timeout=10)
      except Exception:
        continue
      if not self.response_reached(page):
        denied += 1
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
        resp = self.auth.primary_session.post(url, data=form_data, timeout=10)
      except Exception:
        continue
      if not self.response_reached(resp):
        denied += 1
        continue

      self.safety.throttle()
      try:
        readback = self.auth.primary_session.get(url, timeout=10)
      except Exception:
        continue
      if not self.response_reached(readback):
        denied += 1
        continue
      tested += 1

      if canary in readback.text and payload in readback.text:
        self.findings.append(GrayboxFinding(
          scenario_id="PT-A03-02",
          title="Stored cross-site scripting (XSS)",
          status="vulnerable",
          severity="MEDIUM",
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
    elif denied > 0:
      self.emit_endpoint_denied("PT-A03-02")

  def _test_ssrf(self):
    """
    PT-API7-01: SSRF checks on URL-fetch endpoints.

    Tests configured endpoints for server-side URL fetching.
    Detects reflected SSRF and timing-based hints for blind SSRF.
    """
    ssrf_endpoints = self.target_config.injection.ssrf_endpoints
    if not ssrf_endpoints:
      self._emit_no_endpoint("PT-API7-01", "ssrf")
      return

    import time as _time
    payload_url = "http://127.0.0.1:1/internal-probe"
    baseline_url = "http://example.invalid/nonexistent"

    for ep in ssrf_endpoints:
      self.safety.throttle()
      url = self.target_url + "/" + ep.path.lstrip("/")
      session = self.auth.primary_session or self.auth.anon_session

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
          severity="HIGH",
          owasp="API7:2023",
          cwe=["CWE-918"],
          attack=["T1190"],
          # The injected parameter is what separates this from the JSON
          # body-field variant below: same scenario, same endpoint, same CWE,
          # and neither severity nor title is part of a finding's identity.
          url=url,
          parameter=ep.param,
          method="GET",
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

  def _test_ssrf_body_field(self):
    """PT-API7-01 extension (Subphase 2.7): scan JSON request body fields.

    For each SSRF endpoint configured under `injection.ssrf_endpoints`,
    iterates the configured `api_security.ssrf_body_fields` names and
    POSTs JSON bodies that embed an internal-probe URL under each field.
    Vulnerable iff the response 200s and reflects the probe marker.
    """
    api_security = self.target_config.api_security
    body_fields = api_security.ssrf_body_fields
    ssrf_endpoints = self.target_config.injection.ssrf_endpoints
    if not ssrf_endpoints or not body_fields:
      return

    payload_url = "http://127.0.0.1:1/internal-probe"
    session = self.auth.primary_session or getattr(self.auth, "anon_session", None)
    if session is None:
      return

    import requests as _rq
    for ep in ssrf_endpoints:
      url = self.target_url + "/" + ep.path.lstrip("/")
      for body_field in body_fields:
        self.safety.throttle()
        try:
          resp = session.post(url, json={body_field: payload_url}, timeout=10)
        except _rq.RequestException:
          continue
        if resp.status_code == 200 and "internal-probe" in (resp.text or ""):
          self.findings.append(GrayboxFinding(
            scenario_id="PT-API7-01",
            title="Server-side request forgery (JSON body field)",
            status="vulnerable",
            severity="HIGH",
            owasp="API7:2023",
            cwe=["CWE-918"],
            attack=["T1190"],
            # The body field, for the same reason the query variant records its
            # parameter: one endpoint can be vulnerable through both.
            url=url,
            parameter=body_field,
            method="POST",
            evidence=[f"endpoint={url}", f"body_field={body_field}",
                       f"payload_url={payload_url}",
                       "response_status=200",
                       "reflected_marker=internal-probe"],
            replay_steps=[
              f"Authenticate as {self.principal_label()}.",
              f"POST {url} with JSON body `{{\"{body_field}\": \"{payload_url}\"}}`.",
              "Observe the response reflects the internal-probe marker, "
              "confirming the server fetched the user-controlled URL.",
            ],
            remediation=(
              "Validate URL fields against an allowlist of schemes/hosts. "
              "Reject loopback / link-local / private ranges before issuing "
              "the outbound request."
            ),
          ))
          return  # one body-field demo per scan is sufficient

  def _test_open_redirect(self):
    """
    PT-A01-04: test URL parameters for open redirect vulnerabilities.

    Tests common redirect parameter names (next, url, redirect, return_to,
    continue, dest, goto, forward) with an external domain payload.
    Checks if the response issues a redirect to the attacker-controlled domain.

    Read-only: only sends GET requests with modified query parameters.
    """
    session = self.auth.primary_session or self.auth.anon_session
    if not session:
      return

    redirect_params = [
      "next", "url", "redirect", "redirect_url", "return_to", "return",
      "continue", "dest", "destination", "goto", "forward", "redir",
      "returnUrl", "redirect_uri", "callback",
    ]
    payload = "//evil.example.com"
    payload_alt = "https://evil.example.com"

    # Test against: login page (common redirect after login), discovered routes.
    # Never the logout path: a GET there ends the scan session.
    test_paths = [self.target_config.login_path]
    for route in self.discovered_routes:
      if not self.is_logout_path(route):
        test_paths.append(route)
    # Deduplicate
    seen = set()
    unique_paths = []
    for p in test_paths:
      if p and p not in seen:
        seen.add(p)
        unique_paths.append(p)

    tested = 0
    denied = 0
    vulnerable_evidence = []
    login_path = self.target_config.login_path

    def _evil_redirect(resp):
      # Parsed host, not substring: a login redirect that echoes ?next=//evil
      # carries the payload in its query, not as the redirect target.
      from urllib.parse import urlparse
      if resp.status_code not in (301, 302, 303, 307, 308):
        return ""
      location = resp.headers.get("Location", "")
      try:
        host = urlparse(location).hostname or ""
      except ValueError:
        return ""
      return location if host.lower() == "evil.example.com" else ""

    def _counts(path, resp):
      # The login page is reachable without a session: any non-error answer
      # counts. Other paths must reach their handler.
      if path == login_path:
        return resp.status_code < 400
      return self.response_reached(resp)

    for path in unique_paths[:10]:  # cap to avoid excessive requests
      if path != login_path:
        # Baseline: plain GET of the same URL. The login page is exempt, it is
        # the classic ?next= target and is reachable without a session.
        reached = self.baseline_reached(session, self.target_url + path, allow_redirects=False)
        if reached is None:
          continue
        if not reached:
          denied += 1
          continue
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
        if not _counts(path, resp):
          denied += 1
          continue
        tested += 1

        # Check for redirect to evil domain
        location = _evil_redirect(resp)
        if location:
          vulnerable_evidence.append((
            path, param, f"endpoint={path}; param={param}; location={location}",
          ))
          break  # one redirect per path is enough

        # Also test the alternate payload (full URL)
        if not vulnerable_evidence or vulnerable_evidence[-1][0] != path:
          self.safety.throttle()
          try:
            resp2 = session.get(
              url, params={param: payload_alt},
              timeout=10, allow_redirects=False,
            )
          except Exception:
            continue
          if not _counts(path, resp2):
            denied += 1
            continue
          tested += 1

          location2 = _evil_redirect(resp2)
          if location2:
            vulnerable_evidence.append((
              path, param, f"endpoint={path}; param={param}; location={location2}",
            ))
            break

      if len(vulnerable_evidence) >= 3:
        break  # enough evidence

    for path, param, item in vulnerable_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-04",
        title="Open redirect via URL parameter",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A01:2021",
        cwe=["CWE-601"],
        attack=["T1566"],
        evidence=[item],
        replay_steps=[
          f"GET {path}?{param}={payload} (or {payload_alt}).",
          "Observe 3xx redirect to attacker-controlled domain.",
        ],
        remediation="Validate redirect targets against a server-side allowlist. "
                    "Use relative paths only, or verify the destination host "
                    "matches your domain. Never pass user input directly to "
                    "Location headers.",
      ))
    if not vulnerable_evidence and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-04",
        title="Open redirect — no vulnerability detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"parameters_tested={tested}"],
      ))
    elif not vulnerable_evidence and denied > 0:
      self.emit_endpoint_denied("PT-A01-04")

  def _test_path_traversal(self):
    """
    PT-A03-03: test parameters for directory traversal vulnerabilities.

    Tests query parameters and path segments in discovered routes with
    path traversal payloads. Checks response body for OS file content
    markers (e.g. root:x: from /etc/passwd).

    Read-only: only sends GET requests with modified parameters.
    """
    session = self.auth.primary_session
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
    denied = 0
    vulnerable_evidence = []

    for route in test_routes[:10]:  # cap to avoid excessive requests
      url = self.target_url + route
      route_hit = False

      # Baseline: a plain GET must reach the handler before the route counts.
      reached = self.baseline_reached(session, url)
      if reached is None:
        continue
      if not reached:
        denied += 1
        continue

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
          if not self.response_reached(resp):
            denied += 1
            continue
          tested += 1

          if resp.status_code == 200:
            body = resp.text
            if any(m in body for m in markers):
              vulnerable_evidence.append((
                route, param, payload,
                f"endpoint={route}; param={param}; payload={payload}",
              ))
              route_hit = True
              break  # one hit per route+param is enough
        if route_hit:
          break  # found a hit on this route, move on

      if len(vulnerable_evidence) >= 3:
        break

    for route, param, payload, item in vulnerable_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-03",
        title="Path traversal — file content disclosed",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A03:2021",
        cwe=["CWE-22"],
        attack=["T1083"],
        evidence=[item],
        replay_steps=[
          "Log in as authenticated user.",
          f"Request GET {route}?{param}={payload}.",
          "Observe OS file contents (e.g. /etc/passwd) in response body.",
        ],
        remediation="Validate and sanitize all file path inputs server-side. "
                    "Use a whitelist of allowed files, canonicalize paths, "
                    "and ensure they stay within the application's base directory. "
                    "Never pass user input directly to file system operations.",
      ))
    if not vulnerable_evidence and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-03",
        title="Path traversal — no vulnerability detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
    elif not vulnerable_evidence and denied > 0:
      self.emit_endpoint_denied("PT-A03-03")

  # ── Batch 2 — A03 family expansion ──────────────────────────────────────

  def _test_reflected_xss(self):
    """PT-A03-04: detect reflected XSS behind authentication.

    Sends a script payload to each configured xss_endpoint and looks
    for unescaped reflection in the response body.
    """
    endpoints = self._reflective_endpoints(
      self.target_config.injection.xss_endpoints)
    if not endpoints:
      self._emit_no_endpoint("PT-A03-04", "xss")
      return

    payload = "<script>alert(1)</script>"
    sentinel = "<script>alert(1)</script>"

    vulnerable = []
    tested = 0
    denied = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      reached = self.baseline_reached(self.auth.primary_session, url)
      if reached is None:
        continue
      if not reached:
        denied += 1
        continue
      self.safety.throttle()
      try:
        resp = self.auth.primary_session.get(
          url, params={ep.param: payload}, timeout=10,
        )
      except Exception:
        continue
      if not self.response_reached(resp):
        denied += 1
        continue
      tested += 1
      if resp.status_code == 200 and sentinel in resp.text:
        vulnerable.append((ep,
          f"endpoint={ep.path}; param={ep.param}; payload_reflected_unescaped=True"
          + self._source_tag(ep)))

    for ep, item in vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-04",
        title="Reflected XSS — payload echoed unescaped",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A03:2021",
        cwe=["CWE-79"],
        attack=["T1059.007"],
        parameter=ep.param,
        evidence=[item],
        replay_steps=[
          f"GET {ep.path}?{ep.param}=<script>alert(1)</script>",
          "Observe payload returned in body without HTML escaping.",
        ],
        remediation="Escape user input on output (Django ``|escape``, "
                    "Jinja autoescape, etc.). Apply a Content Security "
                    "Policy that disallows inline scripts.",
      ))
    if not vulnerable and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-04",
        title="Reflected XSS — payload escaped or not reflected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))
    elif not vulnerable and denied > 0:
      self.emit_endpoint_denied("PT-A03-04")

  def _test_template_injection(self):
    """PT-A03-06: detect server-side template injection.

    Sends ``${7*7}`` and ``{{7*7}}`` to each ssti_endpoint; vulnerable
    if the response body contains ``49``.
    """
    endpoints = self._reflective_endpoints(
      self.target_config.injection.ssti_endpoints)
    if not endpoints:
      self._emit_no_endpoint("PT-A03-06", "ssti")
      return

    payloads = ["${7*7}", "{{7*7}}", "{{ 7*7 }}"]
    sentinel = "49"

    vulnerable = []
    tested = 0
    denied = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      reached = self.baseline_reached(self.auth.primary_session, url)
      if reached is None:
        continue
      if not reached:
        denied += 1
        continue
      for payload in payloads:
        self.safety.throttle()
        try:
          resp = self.auth.primary_session.get(
            url, params={ep.param: payload}, timeout=10,
          )
        except Exception:
          continue
        if not self.response_reached(resp):
          denied += 1
          continue
        tested += 1
        # Avoid false positives on echo-only sinks: require the body to
        # contain ``49`` BUT NOT contain the literal ``7*7`` (an echo
        # would reflect both the payload and the sentinel).
        if (resp.status_code == 200 and sentinel in resp.text
            and "7*7" not in resp.text):
          vulnerable.append((ep,
            f"endpoint={ep.path}; param={ep.param}; "
            f"payload={payload}; sentinel_in_body=True"
            + self._source_tag(ep)
          ))
          break

    for ep, item in vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-06",
        title="Server-side template injection — expression evaluated",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-94", "CWE-1336"],
        attack=["T1059"],
        parameter=ep.param,
        evidence=[item],
        replay_steps=[
          f"GET {ep.path}?{ep.param}=" + r"${7*7}",
          "Observe the response body contains 49 (the evaluated result).",
        ],
        remediation="Never render user-controlled data through a template "
                    "engine. If templates must be dynamic, use a sandbox "
                    "or precompiled templates only.",
      ))
    if not vulnerable and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-06",
        title="Template injection — no expression evaluation observed",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
    elif not vulnerable and denied > 0:
      self.emit_endpoint_denied("PT-A03-06")

  def _test_command_injection(self):
    """PT-A03-07: detect OS command injection via shell metacharacters.

    Sends payloads ``;id`` and ``$(id)``; vulnerable if the response
    body shows the canonical ``uid=`` prefix from ``id(1)``.
    """
    endpoints = self._reflective_endpoints(
      self.target_config.injection.cmd_endpoints)
    if not endpoints:
      self._emit_no_endpoint("PT-A03-07", "cmd")
      return

    payloads = [";id", "$(id)", "`id`", "|id"]
    import re as _re
    sentinel = _re.compile(r"uid=\d+\(")

    vulnerable = []
    tested = 0
    denied = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      reached = self.baseline_reached(self.auth.primary_session, url)
      if reached is None:
        continue
      if not reached:
        denied += 1
        continue
      for payload in payloads:
        self.safety.throttle()
        try:
          resp = self.auth.primary_session.get(
            url, params={ep.param: payload}, timeout=10,
          )
        except Exception:
          continue
        if not self.response_reached(resp):
          denied += 1
          continue
        tested += 1
        if resp.status_code == 200 and sentinel.search(resp.text):
          vulnerable.append((ep,
            f"endpoint={ep.path}; param={ep.param}; "
            f"payload={payload}; uid_marker_in_body=True"
            + self._source_tag(ep)
          ))
          break

    for ep, item in vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-07",
        title="OS command injection — shell metacharacters honored",
        status="vulnerable",
        severity="HIGH",
        owasp="A03:2021",
        cwe=["CWE-78"],
        attack=["T1059.004"],
        parameter=ep.param,
        evidence=[item],
        replay_steps=[
          f"GET {ep.path}?{ep.param}=;id",
          "Observe ``uid=...`` from id(1) in the response body.",
        ],
        remediation="Never invoke a shell with user-controlled input. "
                    "Use parameterised process invocation "
                    "(``subprocess.run([...], shell=False)``) and pass "
                    "the input as an argv element, never a substring of "
                    "the command line.",
      ))
    if not vulnerable and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-07",
        title="Command injection — shell metacharacters had no effect",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
    elif not vulnerable and denied > 0:
      self.emit_endpoint_denied("PT-A03-07")

  def _test_header_injection(self):
    """PT-A03-12: detect HTTP header injection via CRLF.

    Sends a value with a CRLF + injected header; vulnerable if the
    response carries the injected header (or splits/loses the
    location header in a way that proves CRLF was honored).
    """
    endpoints = self._reflective_endpoints(
      self.target_config.injection.header_endpoints)
    if not endpoints:
      self._emit_no_endpoint("PT-A03-12", "header")
      return

    inject_name = "X-Injected"
    inject_value = "pwned"
    payload = f"/safe-target\r\n{inject_name}: {inject_value}"

    vulnerable = []
    tested = 0
    denied = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      reached = self.baseline_reached(self.auth.primary_session, url, allow_redirects=False)
      if reached is None:
        continue
      if not reached:
        denied += 1
        continue
      self.safety.throttle()
      try:
        resp = self.auth.primary_session.get(
          url, params={ep.param: payload},
          allow_redirects=False, timeout=10,
        )
      except Exception:
        continue
      if not self.response_reached(resp):
        denied += 1
        continue
      tested += 1
      if resp.headers.get(inject_name) == inject_value:
        vulnerable.append((ep,
          f"endpoint={ep.path}; param={ep.param}; "
          f"injected_header={inject_name}: {inject_value}"
          + self._source_tag(ep)
        ))

    for ep, item in vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-12",
        title="HTTP header injection via CRLF",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A03:2021",
        cwe=["CWE-93", "CWE-113"],
        attack=["T1190"],
        parameter=ep.param,
        evidence=[item],
        replay_steps=[
          f"GET {ep.path}?{ep.param}=/x"
          + r"\r\nX-Injected: pwned",
          "Observe the X-Injected response header set with the "
          "attacker-supplied value.",
        ],
        remediation="Strip ``\\r`` and ``\\n`` from values before they "
                    "land in response headers. Validate redirect "
                    "targets against an allowlist of paths.",
      ))
    if not vulnerable and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-12",
        title="Header injection — CRLF stripped or not reflected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
    elif not vulnerable and denied > 0:
      self.emit_endpoint_denied("PT-A03-12")

  def _test_json_type_confusion(self):
    """PT-A03-15: detect lax JSON body parsing on typed fields.

    Sends ``{"<field>": [1]}`` and ``{"<field>": {"$gt": 0}}`` to
    endpoints expecting an integer; vulnerable when a non-int payload
    is accepted (HTTP 2xx) or the response distinguishes the variant
    from a clean rejection.
    """
    endpoints = self.target_config.injection.json_type_endpoints
    if not endpoints:
      self._emit_no_endpoint("PT-A03-15", "json_type")
      return

    import json as _json

    vulnerable = []
    tested = 0
    denied = 0
    for ep in endpoints:
      url = self.target_url + ep.path
      headers = {"Content-Type": "application/json"}

      # Baseline: clean integer
      self.safety.throttle()
      try:
        baseline = self.auth.primary_session.post(
          url, data=_json.dumps({ep.field: 1}),
          headers=headers, timeout=10,
        )
      except Exception:
        continue
      if baseline.status_code >= 500:
        continue
      if not self.response_reached(baseline, validation_ok=True):
        denied += 1
        continue

      # Variant: list
      payloads_to_try = [[1], {"$gt": 0}]
      for variant in payloads_to_try:
        self.safety.throttle()
        try:
          resp = self.auth.primary_session.post(
            url, data=_json.dumps({ep.field: variant}),
            headers=headers, timeout=10,
          )
        except Exception:
          continue
        if not self.response_reached(resp, validation_ok=True):
          denied += 1
          continue
        tested += 1
        if resp.status_code < 400:
          vulnerable.append((ep,
            f"endpoint={ep.path}; field={ep.field}; "
            f"variant={variant!r}; status={resp.status_code}"
          ))
          break

    for ep, item in vulnerable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-15",
        title="JSON body type confusion — non-integer accepted",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A03:2021",
        cwe=["CWE-843", "CWE-704"],
        attack=["T1190"],
        evidence=[item],
        replay_steps=[
          f"POST {ep.path} with body "
          f'``{{"{ep.field}": [1]}}`` or '
          f'``{{"{ep.field}": {{"$gt": 0}}}}``',
          "Observe the server processes the request without rejecting "
          "the type mismatch.",
        ],
        remediation="Validate JSON body fields against a typed schema "
                    "(pydantic, marshmallow, JSON Schema). Reject "
                    "lists, dicts, or operator-keys when an integer "
                    "is expected.",
      ))
    if not vulnerable and tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A03-15",
        title="JSON type confusion — typed validation in place",
        status="not_vulnerable",
        severity="INFO",
        owasp="A03:2021",
        evidence=[f"requests_tested={tested}"],
      ))
    elif not vulnerable and denied > 0:
      self.emit_endpoint_denied("PT-A03-15")
