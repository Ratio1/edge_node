"""
Business logic probes — A06 workflow bypass + A07 weak auth.
"""

from .access_control import MAX_EVIDENCE_VALUE, parse_form_fields
from .base import ProbeBase
from ..budget import RequestRefused
from ..safety import GrayboxAbort
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
        owasp="A04:2021",
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
    refused = ""
    for cred in candidates[:budget]:
      if ":" not in cred:
        continue
      username, password = cred.split(":", 1)
      self.safety.throttle_auth()
      try:
        session = self.auth.try_credentials(username, password)
      except RequestRefused as exc:
        refused = exc.reason  # keep the successes already found; the rest is unproven
        break
      attempts += 1
      if session:
        successes.append(username)
        session.close()
      else:
        check_session = self.auth.make_anonymous_session()
        try:
          login_url = self.auth.target_url + self.auth.target_config.login_path
          resp = check_session.get(login_url, timeout=10, throttle_retry=False)
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
        except GrayboxAbort:
          raise
        except Exception:
          pass
        finally:
          check_session.close()
      if attempts >= budget:
        break

    if refused:
      self.emit_inconclusive(
        "PT-A07-01", "Weak credential check incomplete", "A07:2021", refused)
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
      url = self.target_url + path
      method = ep.method.upper()
      # The verb this loop really issues (see below); the finding reports this one.
      sent = "POST" if method == "POST" else "GET"

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

      # A denial (401/403, login redirect, or a 404 the admin reached) is the
      # secure result. A bare 404 is skipped: it may be a mistyped path.
      if self.exempt_denial(resp, url):
        endpoints_tested += 1
        continue
      if resp.status_code == 404:
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
            severity="MEDIUM",
            owasp="A04:2021",
            cwe=["CWE-841"],
            attack=["T1078"],
            # No typed `method=` here, deliberately. Two configured endpoints on
            # one path with different verbs do share a finding_id, and stamping
            # `ep.method` would split them — but the split would be a lie: this
            # loop issues POST only for POST and a plain GET for everything else
            # (see the request above), so a `DELETE` entry is probed with GET.
            # Evidence and replay therefore name the verb actually sent, and keep
            # the configured one beside it when they differ. The probe has to
            # issue the configured verb before an identity split is real.
            url=url,
            evidence=[
              f"endpoint={url}",
              f"method={sent}",
              *([f"configured_method={method}"] if sent != method else []),
              f"expected_guard={expected}",
              f"actual_status={resp.status_code}",
            ],
            replay_steps=[
              "Log in as regular user.",
              f"Send {sent} to {path}.",
              f"Observe status {resp.status_code} instead of expected guard {expected}.",
            ],
            remediation="Enforce workflow state guards and role checks on all state-changing endpoints.",
            evidence_artifacts=self.evidence_from(resp),
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
        owasp="A04:2021",
        evidence=[f"endpoints_tested={endpoints_tested}"],
      ))

  def _read_back_field(self, url, field, csrf_field):
    """GET the record again and return the stored value of ``field``, or None.
    The page read is kept in ``_read_back_page``: it, not the POST answer (often
    a bodiless redirect), shows the stored value, so it is the evidence."""
    self._read_back_page = None
    try:
      page = self.auth.primary_session.get(url, timeout=10)
    except Exception:
      return None
    if page.status_code != 200 or not self.response_reached(page):
      return None
    self._read_back_page = page
    return parse_form_fields(page.text, csrf_field).get(field)

  @staticmethod
  def _is_number(value):
    try:
      float(value)
      return True
    except (TypeError, ValueError):
      return False

  @staticmethod
  def _same_amount(stored, submitted):
    try:
      return abs(float(stored) - float(submitted)) < 0.005
    except (TypeError, ValueError):
      return str(stored) == str(submitted)

  def _test_validation_bypass(self):
    """
    PT-A06-02: test business logic validation (negative amounts, invalid state transitions).

    Submits boundary-violating values to record endpoints and checks if the
    server accepts them. Tests negative monetary amounts and forbidden state
    transitions.
    """
    if not self.auth.primary_session:
      return

    endpoints = self.target_config.business_logic.record_endpoints
    if not endpoints:
      return

    idor_ids = [1, 2]
    for iep in self.target_config.access_control.idor_endpoints:
      if iep.test_ids:
        idor_ids = iep.test_ids
        break

    bypass_evidence = []
    bypass_response = None
    tested = 0
    denied = 0
    # PT-A06-04 (Negative amount accepted) is a strict subset of PT-A06-02
    # — track separately so the catalog row fires when negative amount is
    # accepted, even if the invalid-state branch also triggers PT-A06-02.
    negative_amount_evidence = []
    negative_amount_response = None
    amount_unconfirmed = []      # (path, reason)
    transition_unconfirmed = []

    for ep in endpoints:
      path = ep.path
      if "{id}" in path:
        path = path.replace("{id}", str(idor_ids[0]))
      url = self.target_url + path

      # Step 1: GET the form to extract current state and CSRF token
      try:
        page = self.auth.primary_session.get(url, timeout=10)
      except Exception:
        continue
      # 405: a POST-only action. No GET baseline and no form to read, so the
      # payload POST (configured amount and status fields) decides.
      post_only = page.status_code == 405
      if not post_only and not self.response_reached(page):
        denied += 1
        continue
      if not post_only and page.status_code != 200:
        continue
      page_text = "" if post_only else page.text

      csrf_field = self.auth.detected_csrf_field
      csrf_token = None
      if csrf_field:
        csrf_token = self.auth.extract_csrf_value(page_text, csrf_field)

      form_fields = parse_form_fields(page_text, csrf_field)

      current_status = form_fields.get(ep.status_field)

      # Test A: Negative amount
      payload = dict(form_fields)
      payload[ep.amount_field] = "-9999.99"
      if csrf_token and csrf_field:
        payload[csrf_field] = csrf_token
      headers = {"Referer": url}
      if csrf_token:
        headers["X-CSRFToken"] = csrf_token

      try:
        resp = self.auth.primary_session.post(
          url, data=payload, headers=headers,
          timeout=10, allow_redirects=False,
        )
      except Exception:
        resp = None

      if resp is not None and not self.response_reached(resp):
        # Payload denied or redirected to login: the handler never saw it.
        denied += 1
      elif resp is not None:
        tested += 1
        # The POST response (status, error words) proves nothing either way:
        # the read-back alone decides. Stored payload = vulnerable, another
        # stored value = guard held, no read-back = inconclusive.
        before = form_fields.get(ep.amount_field)
        if before is not None and self._same_amount(before, "-9999.99"):
          # The record already held the payload value (residue of an earlier
          # run): reading it back proves nothing.
          amount_unconfirmed.append((path, "value_present_before_probe"))
        else:
          stored = self._read_back_field(url, ep.amount_field, csrf_field)
          if stored is None:
            amount_unconfirmed.append((path, "accepted_value_not_read_back"))
          elif self._same_amount(stored, "-9999.99"):
            bypass_evidence.append(f"negative_amount_accepted=True; endpoint={path}")
            if bypass_response is None:
              bypass_response = self._read_back_page
            if negative_amount_response is None:
              negative_amount_response = self._read_back_page
            negative_amount_evidence.append(
              f"endpoint={path}; submitted_amount=-9999.99; "
              f"stored_amount={stored[:MAX_EVIDENCE_VALUE]}; status={resp.status_code}"
            )
          elif not (stored == before or self._is_number(stored)):
            # A display format the probe cannot compare ("-9,999.99", "$-9999.99"):
            # neither the payload nor a different amount is proven.
            amount_unconfirmed.append((path, "accepted_value_not_read_back"))

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

          # Re-fetch CSRF token (may have been consumed)
          if csrf_field:
            try:
              page2 = self.auth.primary_session.get(url, timeout=10)
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
            resp2 = self.auth.primary_session.post(
              url, data=payload2, headers=headers2,
              timeout=10, allow_redirects=False,
            )
          except Exception:
            resp2 = None

          if resp2 is not None and self.response_reached(resp2):
            # Same rule as Test A: the read-back alone decides.
            stored2 = self._read_back_field(url, ep.status_field, csrf_field)
            if stored2 is None:
              transition_unconfirmed.append((path, "accepted_value_not_read_back"))
            elif stored2 == invalid_target:
              bypass_evidence.append(
                f"invalid_transition_accepted=True; "
                f"from={current_status}; to={invalid_target}; "
                f"stored_status={stored2[:MAX_EVIDENCE_VALUE]}; endpoint={path}"
              )
              if bypass_response is None:
                bypass_response = self._read_back_page

    if bypass_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-02",
        title="Business logic validation bypass",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A04:2021",
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
        evidence_artifacts=self.evidence_from(bypass_response),
      ))
    elif transition_unconfirmed or amount_unconfirmed:
      path, reason = (transition_unconfirmed or amount_unconfirmed)[0]
      self.emit_inconclusive(
        "PT-A06-02", "Business logic validation bypass", "A04:2021", reason,
      )
      self.findings[-1].evidence.append(f"endpoint={path}")
    elif tested:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-02",
        title="Business logic validation — no bypass detected",
        status="not_vulnerable",
        severity="INFO",
        owasp="A04:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))
    elif denied:
      self.emit_endpoint_denied("PT-A06-02")
    else:
      self.emit_inconclusive(
        "PT-A06-02", "Business logic validation bypass", "A04:2021",
        "no_evaluable_responses",
      )

    # PT-A06-04 — Negative amount accepted (strict subset of PT-A06-02).
    # Always emit one finding so coverage accounting shows the probe ran.
    if negative_amount_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-04",
        title="Negative monetary amount accepted",
        status="vulnerable",
        severity="MEDIUM",
        owasp="A04:2021",
        cwe=["CWE-20", "CWE-840"],
        attack=["T1190"],
        evidence=negative_amount_evidence,
        replay_steps=[
          "Log in as authenticated user.",
          "Submit a record-update form with amount=-9999.99.",
          "Observe the server accepts the negative value.",
        ],
        remediation="Enforce a server-side `amount >= 0` invariant on every "
                    "endpoint that mutates monetary fields. Form-level "
                    "validation alone is insufficient — always re-validate at "
                    "the model or service boundary.",
        evidence_artifacts=self.evidence_from(negative_amount_response),
      ))
    elif amount_unconfirmed:
      path, reason = amount_unconfirmed[0]
      self.emit_inconclusive(
        "PT-A06-04", "Negative amount accepted", "A04:2021", reason,
      )
      self.findings[-1].evidence.append(f"endpoint={path}")
    elif tested:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A06-04",
        title="Negative amount — guard held",
        status="not_vulnerable",
        severity="INFO",
        owasp="A04:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))
    elif denied:
      self.emit_endpoint_denied("PT-A06-04")
    else:
      self.emit_inconclusive(
        "PT-A06-04", "Negative amount accepted", "A04:2021",
        "no_evaluable_responses",
      )
