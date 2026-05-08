"""
Business logic probes — A06 workflow bypass + A07 weak auth.
"""

from .base import ProbeBase
from ..findings import GrayboxFinding


class BusinessLogicProbes(ProbeBase):
  """
  PT-A06-01: workflow bypass (STATEFUL — requires allow_stateful_probes).
  PT-A07-01: weak auth simulation (read-only).
  """

  requires_auth = True
  requires_regular_session = True
  is_stateful = True

  def run(self):
    if self._allow_stateful:
      self.run_safe("workflow_bypass", self._test_workflow_bypass)
      self.run_safe("validation_bypass", self._test_validation_bypass)
    else:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-01",
        title="Business logic probes skipped",
        status="inconclusive",
        severity="INFO",
        owasp="A06:2021",
        evidence=["stateful_probes_disabled=True"],
      ))
    return self.findings

  def run_weak_auth(self, candidates, max_attempts):
    """
    PT-A07-01 bounded weak-credential simulation.

    Read-only: only tests login, never modifies application state.
    Includes lockout detection to abort if target starts blocking.
    """
    budget = self.safety.clamp_attempts(max_attempts)
    if not candidates:
      return self.findings

    lockout_markers = [
      "account locked", "too many attempts", "temporarily blocked",
      "account suspended", "try again later", "rate limit",
    ]

    attempts = 0
    successes = []
    for cred in candidates[:budget]:
      if ":" not in cred:
        continue
      username, password = cred.split(":", 1)
      self.safety.throttle_auth()
      session = self.auth.try_credentials(username, password)
      attempts += 1
      if session:
        successes.append(username)
        session.close()
      else:
        check_session = self.auth.make_anonymous_session()
        try:
          login_url = self.auth.target_url + self.auth.target_config.login_path
          resp = check_session.get(login_url, timeout=10)
          body_lower = resp.text.lower()
          if resp.status_code == 429 or any(m in body_lower for m in lockout_markers):
            self.findings.append(GrayboxFinding(
              scenario_id="PT-A07-01",
              title="Account lockout detected — weak auth aborted",
              status="inconclusive",
              severity="INFO",
              owasp="A07:2021",
              cwe=["CWE-307"],
              evidence=[
                f"attempt_count={attempts}",
                f"status={resp.status_code}",
              ],
            ))
            return self.findings
        except Exception:
          pass
        finally:
          check_session.close()
      if attempts >= budget:
        break

    if successes:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A07-01",
        title="Bounded weak-auth simulation",
        status="vulnerable",
        severity="HIGH",
        owasp="A07:2021",
        cwe=["CWE-307"],
        attack=["T1110"],
        evidence=[
          f"attempt_count={attempts}",
          f"success_count={len(successes)}",
          f"first_success={successes[0]}",
        ],
        replay_steps=[
          "Run weak-auth simulation with bounded candidate list.",
          "Observe successful login using guessed credentials.",
        ],
        remediation="Enforce strong credential policy, lockout, and throttling controls.",
      ))

    return self.findings

  def _test_workflow_bypass(self):
    """
    PT-A06-01: test insecure workflow transitions.

    Tests if regular user can access workflow endpoints that should
    require elevated permissions or specific state transitions.

    For POST endpoints, includes the CSRF token so that CSRF rejection
    doesn't mask a real authorization gap.
    """
    if not self.auth.regular_session:
      return

    endpoints = self.target_config.business_logic.workflow_endpoints
    if not endpoints:
      return
    endpoints_tested = 0
    bypass_emitted = False

    # Resolve {id} placeholders using IDOR test_ids (default: try 1 and 2)
    idor_ids = [1, 2]
    for iep in self.target_config.access_control.idor_endpoints:
      if iep.test_ids:
        idor_ids = iep.test_ids
        break

    for ep in endpoints:
      path = ep.path
      if "{id}" in path:
        path = path.replace("{id}", str(idor_ids[0]))
      self.safety.throttle()
      url = self.target_url + path
      method = ep.method.upper()

      try:
        if method == "POST":
          # Fetch the endpoint (or a page that carries CSRF tokens) to get
          # a fresh CSRF token — otherwise Django/Rails may return 403 for
          # missing CSRF, masking the real authorization check.
          csrf_token = None
          csrf_field = self.auth.detected_csrf_field
          if csrf_field:
            csrf_token = self.auth.regular_session.cookies.get("csrftoken") or \
                         self.auth.regular_session.cookies.get("csrf_token")
          if not csrf_token and csrf_field:
            try:
              page_resp = self.auth.regular_session.get(
                self.target_url + "/", timeout=10,
              )
              csrf_token = self.auth.extract_csrf_value(
                page_resp.text, csrf_field,
              )
            except Exception:
              pass

          payload = {}
          headers = {"Referer": self.target_url + path}
          if csrf_token and csrf_field:
            payload[csrf_field] = csrf_token
            headers["X-CSRFToken"] = csrf_token
          resp = self.auth.regular_session.post(
            url, data=payload, headers=headers, timeout=10,
          )
        else:
          resp = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue

      endpoints_tested += 1
      if resp.status_code < 400:
        body_lower = resp.text.lower()
        denial_markers = ["access denied", "permission denied", "forbidden",
                          "not authorized", "unauthorized"]
        if any(m in body_lower for m in denial_markers):
          continue

        expected = ep.expected_guard
        if expected and str(resp.status_code) != expected:
          self.findings.append(GrayboxFinding(
            scenario_id="PT-A06-01",
            title="Workflow bypass — missing authorization guard",
            status="vulnerable",
            severity="HIGH",
            owasp="A06:2021",
            cwe=["CWE-841"],
            attack=["T1078"],
            evidence=[
              f"endpoint={url}",
              f"method={method}",
              f"expected_guard={expected}",
              f"actual_status={resp.status_code}",
            ],
            replay_steps=[
              "Log in as regular user.",
              f"Send {method} to {path}.",
              f"Observe status {resp.status_code} instead of expected guard {expected}.",
            ],
            remediation="Enforce workflow state guards and role checks on all state-changing endpoints.",
          ))
          bypass_emitted = True

    # If we reached at least one endpoint and didn't fire vulnerable, record
    # a not_vulnerable INFO so the inventory shows the probe ran.
    if endpoints_tested > 0 and not bypass_emitted:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-01",
        title="Workflow bypass — guards held",
        status="not_vulnerable",
        severity="INFO",
        owasp="A06:2021",
        evidence=[f"endpoints_tested={endpoints_tested}"],
      ))

  def _test_validation_bypass(self):
    """
    PT-A06-02: test business logic validation (negative amounts, invalid state transitions).

    Submits boundary-violating values to record endpoints and checks if the
    server accepts them. Tests negative monetary amounts and forbidden state
    transitions.
    """
    if not self.auth.official_session:
      return

    endpoints = self.target_config.business_logic.record_endpoints
    if not endpoints:
      return

    import re

    idor_ids = [1, 2]
    for iep in self.target_config.access_control.idor_endpoints:
      if iep.test_ids:
        idor_ids = iep.test_ids
        break

    bypass_evidence = []

    for ep in endpoints:
      path = ep.path
      if "{id}" in path:
        path = path.replace("{id}", str(idor_ids[0]))
      url = self.target_url + path

      # Step 1: GET the form to extract current state and CSRF token
      self.safety.throttle()
      try:
        page = self.auth.official_session.get(url, timeout=10)
      except Exception:
        continue
      if page.status_code != 200:
        continue

      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

      # Extract all form fields with current values.
      # Parse <input> (any type), <textarea>, and <select> elements.
      form_fields = {}
      for tag in re.finditer(r'<input\b([^>]*)>', page.text, re.I):
        attrs = tag.group(1)
        name_m = re.search(r'name=["\']([^"\']+)', attrs)
        val_m = re.search(r'value=["\']([^"\']*)', attrs)
        if name_m:
          name = name_m.group(1)
          if name != csrf_field:
            form_fields[name] = val_m.group(1) if val_m else ""
      for m in re.finditer(
        r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
        page.text, re.I | re.DOTALL,
      ):
        form_fields[m.group(1)] = m.group(2).strip()
      # Extract <select> current values via selected option
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

      current_status = form_fields.get(ep.status_field)

      # Test A: Negative amount
      self.safety.throttle()
      payload = dict(form_fields)
      payload[ep.amount_field] = "-9999.99"
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token
      headers = {"Referer": url}
      if csrf_token:
        headers["X-CSRFToken"] = csrf_token

      try:
        resp = self.auth.official_session.post(
          url, data=payload, headers=headers,
          timeout=10, allow_redirects=False,
        )
      except Exception:
        resp = None

      if resp is not None:
        # Success indicators: 302 redirect (form accepted) or 200 without error
        accepted = resp.status_code in (301, 302)
        if not accepted and resp.status_code == 200:
          body_lower = resp.text.lower()
          error_markers = ["must be", "invalid", "error", "cannot", "negative"]
          accepted = not any(m in body_lower for m in error_markers)
        if accepted:
          bypass_evidence.append(f"negative_amount_accepted=True; endpoint={path}")

      # Test B: Invalid state transition (if transitions are configured)
      if ep.valid_transitions and current_status:
        valid_next = set(ep.valid_transitions.get(current_status, []))
        # Find an invalid target state
        all_states = set()
        for targets in ep.valid_transitions.values():
          all_states.update(targets)
        all_states.update(ep.valid_transitions.keys())
        invalid_states = all_states - valid_next - {current_status}

        if invalid_states:
          invalid_target = sorted(invalid_states)[0]
          self.safety.throttle()

          # Re-fetch CSRF token (may have been consumed)
          if csrf_field:
            try:
              page2 = self.auth.official_session.get(url, timeout=10)
              csrf_token = self.auth.extract_csrf_value(page2.text, csrf_field)
            except Exception:
              pass

          payload2 = dict(form_fields)
          payload2[ep.status_field] = invalid_target
          payload2[ep.amount_field] = form_fields.get(ep.amount_field, "100.00")
          if csrf_token and csrf_field:
            payload2[csrf_field] = csrf_token
          headers2 = {"Referer": url}
          if csrf_token:
            headers2["X-CSRFToken"] = csrf_token

          try:
            resp2 = self.auth.official_session.post(
              url, data=payload2, headers=headers2,
              timeout=10, allow_redirects=False,
            )
          except Exception:
            resp2 = None

          if resp2 is not None:
            accepted2 = resp2.status_code in (301, 302)
            if not accepted2 and resp2.status_code == 200:
              body_lower = resp2.text.lower()
              error_markers = ["must be", "invalid", "error", "cannot", "blocked", "transition"]
              accepted2 = not any(m in body_lower for m in error_markers)
            if accepted2:
              bypass_evidence.append(
                f"invalid_transition_accepted=True; "
                f"from={current_status}; to={invalid_target}; endpoint={path}"
              )

    if bypass_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-02",
        title="Business logic validation bypass",
        status="vulnerable",
        severity="HIGH",
        owasp="A06:2021",
        cwe=["CWE-20", "CWE-840"],
        attack=["T1190"],
        evidence=bypass_evidence,
        replay_steps=[
          "Log in as authenticated user.",
          "Submit form with negative amount or invalid state transition.",
          "Observe server accepts the invalid input.",
        ],
        remediation="Enforce server-side validation for monetary amounts (>= 0) "
                    "and business state machine transitions. "
                    "Never rely on client-side validation alone.",
      ))
    elif endpoints:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-02",
        title="Business logic validation — no bypass detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A06:2021",
        evidence=[f"endpoints_tested={len(endpoints)}"],
      ))
