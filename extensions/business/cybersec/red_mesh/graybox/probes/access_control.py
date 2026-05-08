"""
Access control probes — A01 IDOR + privilege escalation + verb tampering + mass assignment.
"""

import re

from .base import ProbeBase
from ..findings import GrayboxFinding


class AccessControlProbes(ProbeBase):
  """
  PT-A01-01 IDOR/BOLA, PT-A01-02 function-level authorization bypass,
  PT-A01-03 HTTP verb tampering, PT-A04-01 mass assignment.
  """

  requires_auth = True
  requires_regular_session = True
  is_stateful = False

  def run(self):
    if self.auth.regular_session:
      self.run_safe("idor", self._test_idor)
    if self.auth.regular_session:
      self.run_safe("privilege_escalation", self._test_privilege_esc)
    if self.auth.regular_session:
      self.run_safe("verb_tampering", self._test_verb_tampering)
    if self.auth.regular_session and self._allow_stateful:
      self.run_safe("mass_assignment", self._test_mass_assignment)
    elif self.auth.regular_session:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-01",
        title="Mass assignment probe skipped: stateful probes disabled",
        status="inconclusive",
        severity="INFO",
        owasp="A04:2021",
        evidence=["stateful_probes_disabled=True",
                  "reason=mass_assignment_modifies_target_data"],
      ))
    return self.findings

  def _test_idor(self):
    """
    Test IDOR on configured or auto-detected endpoints.

    Emits exactly ONE finding per scenario. Accumulates results across
    all endpoints, then emits vulnerable (worst-case wins) or not_vulnerable.
    """
    endpoints = self.target_config.access_control.idor_endpoints
    if not endpoints:
      endpoints = self._infer_idor_endpoints()
    if not endpoints:
      return

    if not self.regular_username:
      return

    vulnerable_evidence = None
    endpoints_tested = 0

    for ep in endpoints:
      self.safety.throttle()
      result = self._test_single_idor(ep)
      endpoints_tested += 1
      if result:
        vulnerable_evidence = result
        break

    if vulnerable_evidence:
      owner, url, path = vulnerable_evidence
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-01",
        title="Object-level authorization bypass",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-639", "CWE-862"],
        attack=["T1078"],
        evidence=[
          f"endpoint={url}",
          "response_status=200",
          f"owner_field={owner}",
          f"authenticated_user={self.regular_username}",
        ],
        replay_steps=[
          "Log in as regular user.",
          f"Request GET {path}.",
          "Observe owner field not matching logged-in user.",
        ],
        remediation="Authorize object access using both role and ownership checks server-side.",
      ))
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-01",
        title="Object-level authorization — no bypass detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"endpoints_tested={endpoints_tested}"],
      ))

  def _test_single_idor(self, ep):
    """Test one IDOR endpoint. Returns (owner, url, path) on hit, None on miss."""
    path_tpl = ep.path
    for test_id in ep.test_ids:
      path = path_tpl.replace("{id}", str(test_id))
      url = self.target_url + path
      resp = self.auth.regular_session.get(url, timeout=10)
      if resp.status_code != 200:
        continue
      ct = resp.headers.get("content-type", "")
      if not ct.startswith("application/json"):
        continue
      try:
        body = resp.json()
      except ValueError:
        continue
      owner = body.get(ep.owner_field, "")
      if owner and owner != self.regular_username:
        return (owner, url, path)
    return None

  def _infer_idor_endpoints(self):
    """Auto-detect potential IDOR endpoints from discovered routes."""
    from ..models.target_config import IdorEndpoint
    pattern = re.compile(r"^(/(?:api/)?[\w-]+/)\d+/?$")
    endpoints = []
    for route in self.discovered_routes:
      m = pattern.match(route)
      if m:
        endpoints.append(IdorEndpoint(
          path=m.group(1) + "{id}/",
          test_ids=[1, 2],
          owner_field="owner",
        ))
    return endpoints

  def _test_privilege_esc(self):
    """Test admin endpoints accessible as regular user."""
    endpoints = self.target_config.access_control.admin_endpoints
    if not endpoints:
      return
    for ep in endpoints:
      self.safety.throttle()
      method = ep.method.upper()
      url = self.target_url + ep.path
      if method == "GET":
        resp = self.auth.regular_session.get(url, timeout=10)
      else:
        continue  # only GET for read-only probes

      if resp.status_code == 200:
        body_lower = resp.text.lower()
        denial_markers = ["access denied", "permission denied", "forbidden",
                          "not authorized", "unauthorized", "403"]
        has_denial = any(m in body_lower for m in denial_markers)

        has_content = any(m in resp.text for m in ep.content_markers) if ep.content_markers else False

        if has_denial:
          continue

        if has_content:
          finding_status = "vulnerable"
          finding_severity = "HIGH"
        else:
          finding_status = "inconclusive"
          finding_severity = "LOW"

        self.findings.append(GrayboxFinding(
          scenario_id="PT-A01-02",
          title="Function-level authorization bypass",
          status=finding_status,
          severity=finding_severity,
          owasp="A01:2021",
          cwe=["CWE-862"],
          attack=["T1078"],
          evidence=[
            f"endpoint={url}",
            "response_status=200",
            f"content_verified={has_content}",
          ],
          replay_steps=[
            "Log in as regular user.",
            f"Request {method} {ep.path}.",
            "Confirm privileged data is returned.",
          ],
          remediation="Require admin role and deny by default for all privileged functions.",
        ))

  def _test_verb_tampering(self):
    """
    PT-A01-03: test if access controls can be bypassed by changing HTTP method.

    Takes admin endpoints that should deny regular users and retries with
    alternative HTTP methods (PUT, PATCH, DELETE). Some frameworks only
    enforce authorization on GET/POST but pass through other verbs.
    """
    endpoints = self.target_config.access_control.admin_endpoints
    if not endpoints:
      return

    alternative_methods = ["PUT", "PATCH", "DELETE", "OPTIONS"]
    denial_markers = ["access denied", "permission denied", "forbidden",
                      "not authorized", "unauthorized", "403"]

    tested = 0
    bypass_evidence = []
    baseline_reachable = 0

    for ep in endpoints:
      # First, confirm the endpoint denies regular user via its normal method.
      self.safety.throttle()
      url = self.target_url + ep.path
      try:
        baseline = self.auth.regular_session.request(
          ep.method.upper(), url, timeout=10,
        )
      except Exception:
        continue
      baseline_reachable += 1

      # Only test verb tampering if the baseline is denied (403/401/302-to-login)
      baseline_denied = baseline.status_code in (401, 403)
      if not baseline_denied and baseline.status_code == 200:
        body_lower = baseline.text.lower()
        baseline_denied = any(m in body_lower for m in denial_markers)
      if not baseline_denied and baseline.status_code in (301, 302):
        location = baseline.headers.get("Location", "").lower()
        baseline_denied = "login" in location
      if not baseline_denied:
        continue  # endpoint already accessible — not a verb tampering target

      # Try alternative methods
      for method in alternative_methods:
        self.safety.throttle()
        try:
          resp = self.auth.regular_session.request(method, url, timeout=10)
        except Exception:
          continue
        tested += 1

        if resp.status_code < 400 and resp.status_code not in (301, 302):
          body_lower = resp.text.lower()
          if not any(m in body_lower for m in denial_markers):
            bypass_evidence.append(
              f"endpoint={ep.path}; denied_method={ep.method}; "
              f"accepted_method={method}; status={resp.status_code}"
            )
            break  # one bypass per endpoint is enough

    if bypass_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-03",
        title="HTTP verb tampering bypass",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-650"],
        attack=["T1190"],
        evidence=bypass_evidence,
        replay_steps=[
          "Log in as regular user.",
          "Send request to admin endpoint using alternative HTTP method.",
          "Observe access granted despite method-based restriction.",
        ],
        remediation="Enforce authorization checks regardless of HTTP method. "
                    "Deny all methods by default and explicitly allow required ones.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-03",
        title="HTTP verb tampering — no bypass detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"endpoints_tested={len(endpoints)}", f"methods_tested={tested}"],
      ))
    elif baseline_reachable > 0:
      # The probe ran every configured admin endpoint but none returned
      # a baseline-denied response, so verb-tampering had nothing to test.
      # Record the inconclusive outcome so coverage accounting reflects it.
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-03",
        title="HTTP verb tampering — no baseline-denied admin endpoint found",
        status="inconclusive",
        severity="INFO",
        owasp="A01:2021",
        evidence=[
          f"endpoints_reached={baseline_reachable}",
          "reason=baseline_responses_were_not_denied_for_regular_user",
        ],
      ))

  def _test_mass_assignment(self):
    """
    PT-A04-01: test if the server binds unauthorized privilege fields.

    Submits forms as regular user with injected privilege fields
    (is_admin, role, is_staff, etc.) and checks if the server accepts
    and persists them. Stateful — gated behind allow_stateful.
    """
    # Collect testable endpoints: discovered forms + configured record endpoints
    skip_paths = {self.target_config.login_path, self.target_config.logout_path}
    form_paths = [f for f in self.discovered_forms if f not in skip_paths]

    # Also add configured record endpoints (these accept form POSTs)
    for ep in self.target_config.business_logic.record_endpoints:
      path = ep.path
      if "{id}" in path:
        idor_ids = [1, 2]
        for iep in self.target_config.access_control.idor_endpoints:
          if iep.test_ids:
            idor_ids = iep.test_ids
            break
        path = path.replace("{id}", str(idor_ids[0]))
      if path not in skip_paths:
        form_paths.append(path)

    if not form_paths:
      return

    # Privilege escalation fields to inject
    priv_fields = {
      "is_admin": "true",
      "is_staff": "true",
      "is_superuser": "true",
      "role": "admin",
      "admin": "true",
      "user_type": "admin",
      "privilege_level": "10",
      "group": "administrators",
    }

    tested = 0
    accepted_evidence = []

    for form_path in form_paths[:5]:  # cap at 5 forms
      self.safety.throttle()
      url = self.target_url + form_path

      # GET the form to extract existing fields + CSRF token
      try:
        page = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue
      if page.status_code != 200:
        continue

      # Extract form fields
      form_fields = {}
      for tag in re.finditer(r'<input\b([^>]*)>', page.text, re.I):
        attrs = tag.group(1)
        name_m = re.search(r'name=["\']([^"\']+)', attrs)
        val_m = re.search(r'value=["\']([^"\']*)', attrs)
        if name_m:
          form_fields[name_m.group(1)] = val_m.group(1) if val_m else ""
      for m in re.finditer(
        r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
        page.text, re.I | re.DOTALL,
      ):
        form_fields[m.group(1)] = m.group(2).strip()
      for sel in re.finditer(
        r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
        page.text, re.I | re.DOTALL,
      ):
        sel_name = sel.group(1)
        sel_body = sel.group(2)
        opt = re.search(r'<option[^>]*selected[^>]*value=["\']([^"\']+)', sel_body, re.I)
        if not opt:
          opt = re.search(r'<option[^>]*value=["\']([^"\']+)["\'][^>]*selected', sel_body, re.I)
        if opt:
          form_fields[sel_name] = opt.group(1)

      if not form_fields:
        continue

      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

      # Build payload: existing fields + injected privilege fields
      payload = dict(form_fields)
      # Remove CSRF field from form_fields (will add fresh one)
      if csrf_field and csrf_field in payload:
        del payload[csrf_field]
      payload.update(priv_fields)
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token

      headers = {"Referer": url}
      if csrf_token:
        headers["X-CSRFToken"] = csrf_token

      self.safety.throttle()
      try:
        resp = self.auth.regular_session.post(
          url, data=payload, headers=headers,
          timeout=10, allow_redirects=False,
        )
      except Exception:
        continue
      tested += 1

      # Check if server accepted the request
      accepted = resp.status_code in (200, 301, 302)
      if accepted and resp.status_code == 200:
        body_lower = resp.text.lower()
        error_markers = ["error", "invalid", "not allowed", "forbidden",
                         "unknown field", "unexpected"]
        if any(m in body_lower for m in error_markers):
          accepted = False

      if not accepted:
        continue

      # Verify: GET the page again and check if privilege fields are reflected
      self.safety.throttle()
      try:
        verify = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue

      persisted_fields = []
      verify_lower = verify.text.lower()
      for field_name, field_value in priv_fields.items():
        # Check for field=value in response (JSON or HTML attribute)
        if (f'"{field_name}": "{field_value}"' in verify_lower or
            f'"{field_name}":"{field_value}"' in verify_lower or
            f"value=\"{field_value}\"" in verify.text and field_name in verify.text or
            f'name="{field_name}"' in verify.text and f'value="{field_value}"' in verify.text):
          persisted_fields.append(field_name)

      if persisted_fields:
        accepted_evidence.append(
          f"endpoint={form_path}; persisted_fields={','.join(persisted_fields)}"
        )

    if accepted_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-01",
        title="Mass assignment — privilege field accepted",
        status="vulnerable",
        severity="HIGH",
        owasp="A04:2021",
        cwe=["CWE-915"],
        attack=["T1078"],
        evidence=accepted_evidence,
        replay_steps=[
          "Log in as regular user.",
          "Submit form with additional privilege fields (is_admin, role, etc.).",
          "Observe server persists the injected privilege fields.",
        ],
        remediation="Use explicit field allowlists in form/API binding. "
                    "Never bind user input directly to model attributes. "
                    "Django: use ModelForm.Meta.fields. Rails: use strong_parameters.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-01",
        title="Mass assignment — no privilege escalation detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A04:2021",
        evidence=[f"forms_tested={tested}"],
      ))
