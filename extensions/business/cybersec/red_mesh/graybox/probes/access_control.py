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
    if self.auth.regular_session:
      self.run_safe("admin_path_discovery", self._test_admin_path_discovery)
      self.run_safe("query_role_override", self._test_query_role_override)
      self.run_safe("hidden_field_tampering", self._test_hidden_field_tampering)
    if self.auth.regular_session and self._allow_stateful:
      self.run_safe("mass_assignment", self._test_mass_assignment)
      self.run_safe("mass_assignment_ownership", self._test_mass_assignment_ownership)
      self.run_safe("ownership_update", self._test_ownership_update)
      self.run_safe("ownership_delete", self._test_ownership_delete)
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
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-02",
        title="Mass-assignment ownership probe skipped: stateful probes disabled",
        status="inconclusive",
        severity="INFO",
        owasp="A04:2021",
        evidence=["stateful_probes_disabled=True",
                  "reason=ownership_transfer_mutates_target_data"],
      ))
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05",
        title="Ownership update probe skipped: stateful probes disabled",
        status="inconclusive",
        severity="INFO",
        owasp="A01:2021",
        evidence=["stateful_probes_disabled=True",
                  "reason=write_mutates_target_data"],
      ))
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-06",
        title="Ownership delete probe skipped: stateful probes disabled",
        status="inconclusive",
        severity="INFO",
        owasp="A01:2021",
        evidence=["stateful_probes_disabled=True",
                  "reason=delete_mutates_target_data"],
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

  def _test_mass_assignment_ownership(self):
    """
    PT-A04-02: detect ownership transfer via mass-assignable field.

    Distinct from PT-A04-01 (privilege fields like is_admin): some APIs
    accept the row's owning-user id as a writable field, letting any
    authenticated caller transfer records they own to themselves OR
    transfer records they don't own. Both are catastrophic for
    multi-tenant systems.

    Strategy (stateful):
      1. As regular user, PATCH each configured IDOR endpoint with a
         JSON body containing common ownership-field aliases pointing
         to a fabricated user id (1000).
      2. GET the same endpoint and check the returned ``owner`` /
         ``owner_id`` / ``owner_user_id`` field. If it changed, ownership
         was mass-assigned.
      3. If accepted, attempt to revert by PATCHing the original owner
         back. Best-effort cleanup — the test is destructive by nature.
    """
    endpoints = self.target_config.access_control.idor_endpoints
    if not endpoints:
      return

    transfer_targets = ["owner_user_id", "owner_id", "owner",
                        "user_id", "user", "owned_by"]
    # Try real low-numbered ids first (most apps seed admin=1, regular user=2),
    # then a synthetic one. If any of these IDs exist on the target, the
    # transfer can succeed; otherwise the probe gracefully reports
    # not_vulnerable on the most-recent attempt.
    candidate_owner_ids = [1, 2, 3, 1000]

    transferred_evidence = []
    tested = 0

    import json as _json

    for ep in endpoints:
      for record_id in (ep.test_ids or [1, 2]):
        path = ep.path.replace("{id}", str(record_id))
        url = self.target_url + path
        self.safety.throttle()

        try:
          before = self.auth.regular_session.get(url, timeout=10)
        except Exception:
          continue
        if before.status_code != 200:
          continue
        try:
          before_owner = before.json().get(ep.owner_field)
        except Exception:
          continue
        if before_owner is None:
          continue

        csrf_token = self.auth.regular_session.cookies.get("csrftoken")
        headers = {"Content-Type": "application/json", "Referer": url}
        if csrf_token:
          headers["X-CSRFToken"] = csrf_token

        # Try each candidate owner id until one transfer takes effect.
        success = False
        for owner_id in candidate_owner_ids:
          patch_body = {field: owner_id for field in transfer_targets}
          self.safety.throttle()
          try:
            patch_resp = self.auth.regular_session.patch(
              url, data=_json.dumps(patch_body), headers=headers, timeout=10,
            )
          except Exception:
            continue
          tested += 1
          if patch_resp.status_code >= 400:
            continue

          self.safety.throttle()
          try:
            after = self.auth.regular_session.get(url, timeout=10)
            after_owner = after.json().get(ep.owner_field)
          except Exception:
            continue
          if after_owner != before_owner:
            transferred_evidence.append(
              f"endpoint={path}; field={ep.owner_field}; "
              f"injected_id={owner_id}; "
              f"before={before_owner!r}; after={after_owner!r}"
            )
            # Best-effort restore — PATCH owner back to original by name.
            try:
              restore_body = {field: before_owner for field in transfer_targets}
              self.auth.regular_session.patch(
                url, data=_json.dumps(restore_body), headers=headers, timeout=10,
              )
            except Exception:
              pass
            success = True
            break

        if success:
          break

      if transferred_evidence:
        break

    if transferred_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-02",
        title="Mass assignment — ownership field transferable",
        status="vulnerable",
        severity="HIGH",
        owasp="A04:2021",
        cwe=["CWE-915", "CWE-639"],
        attack=["T1078"],
        evidence=transferred_evidence,
        replay_steps=[
          "Log in as regular user.",
          "PATCH a record with body {\"owner_user_id\": <other-id>}.",
          "GET the same record — observe ``owner`` field reflects "
          "the attacker-supplied value.",
        ],
        remediation="Treat ownership/tenant-id as server-assigned only. "
                    "Reject or strip ``owner_user_id`` (and aliases) on "
                    "every write boundary. Use explicit field allowlists "
                    "in serializers / form binding.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A04-02",
        title="Mass-assignment ownership — guard held",
        status="not_vulnerable",
        severity="INFO",
        owasp="A04:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))

  # ── Batch 3 — A01 access-control variants ──────────────────────────────

  def _test_ownership_update(self):
    """PT-A01-05: regular user updates a record they don't own.

    For each configured IDOR endpoint, probe iterates ``test_ids`` and
    PATCHes a sentinel field as the regular user. If the response is
    2xx and a follow-up GET shows the field changed, the server
    accepted a cross-tenant write.
    """
    endpoints = self.target_config.access_control.idor_endpoints
    if not endpoints:
      return

    import json as _json
    sentinel_title = "redmesh-pt-a01-05-probe-marker"
    transferred_evidence = []
    tested = 0

    for ep in endpoints:
      for record_id in (ep.test_ids or [1, 2]):
        path = ep.path.replace("{id}", str(record_id))
        url = self.target_url + path
        self.safety.throttle()
        try:
          before = self.auth.regular_session.get(url, timeout=10)
        except Exception:
          continue
        if before.status_code != 200:
          continue
        try:
          before_owner = before.json().get(ep.owner_field)
          before_title = before.json().get("title")
        except Exception:
          continue
        # Only attempt cross-tenant write — skip records this user owns.
        if before_owner == self.regular_username:
          continue

        csrf_token = self.auth.regular_session.cookies.get("csrftoken")
        headers = {"Content-Type": "application/json", "Referer": url}
        if csrf_token:
          headers["X-CSRFToken"] = csrf_token
        self.safety.throttle()
        try:
          patch_resp = self.auth.regular_session.patch(
            url, data=_json.dumps({"title": sentinel_title}),
            headers=headers, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        if patch_resp.status_code >= 400:
          continue

        self.safety.throttle()
        try:
          after = self.auth.regular_session.get(url, timeout=10)
          after_title = after.json().get("title")
        except Exception:
          continue

        if after_title == sentinel_title:
          transferred_evidence.append(
            f"endpoint={path}; before_owner={before_owner!r}; "
            f"sentinel_title_persisted=True"
          )
          # Best-effort restore.
          try:
            self.auth.regular_session.patch(
              url, data=_json.dumps({"title": before_title}),
              headers=headers, timeout=10,
            )
          except Exception:
            pass
          break
      if transferred_evidence:
        break

    if transferred_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05",
        title="Ownership update bypass — regular user wrote to non-owned record",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-639", "CWE-862"],
        attack=["T1078"],
        evidence=transferred_evidence,
        replay_steps=[
          "Log in as the regular user.",
          "PATCH a record whose owner is a different user with a "
          "sentinel field value.",
          "GET the record and confirm the sentinel was persisted.",
        ],
        remediation="Enforce ownership / tenant checks on all write "
                    "endpoints. Reject mutating requests where the "
                    "record's owner does not match the authenticated "
                    "principal (or an explicit admin role).",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05",
        title="Ownership update — guard held",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))

  def _test_ownership_delete(self):
    """PT-A01-06: regular user deletes a record they don't own.

    For each IDOR endpoint, the probe sends DELETE as the regular user
    against ids it doesn't own. Vulnerable when the server returns
    2xx and a follow-up GET returns 404 (or an explicit "deleted"
    payload).

    DESTRUCTIVE — gated behind allow_stateful at the run() level.
    """
    endpoints = self.target_config.access_control.idor_endpoints
    if not endpoints:
      return

    deleted_evidence = []
    tested = 0
    for ep in endpoints:
      for record_id in (ep.test_ids or [1, 2]):
        path = ep.path.replace("{id}", str(record_id))
        url = self.target_url + path
        self.safety.throttle()
        try:
          before = self.auth.regular_session.get(url, timeout=10)
        except Exception:
          continue
        if before.status_code != 200:
          continue
        try:
          before_owner = before.json().get(ep.owner_field)
        except Exception:
          continue
        if before_owner == self.regular_username:
          continue  # only test cross-tenant

        csrf_token = self.auth.regular_session.cookies.get("csrftoken")
        headers = {"Referer": url}
        if csrf_token:
          headers["X-CSRFToken"] = csrf_token
        self.safety.throttle()
        try:
          del_resp = self.auth.regular_session.delete(
            url, headers=headers, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        if del_resp.status_code >= 400:
          continue
        # Confirm the record is actually gone — defends against a server
        # that returns 200 but ignores the verb.
        self.safety.throttle()
        try:
          after = self.auth.regular_session.get(url, timeout=10)
        except Exception:
          continue
        if after.status_code in (404, 410) or (
          after.status_code == 200 and (after.json() or {}).get("deleted")
        ):
          deleted_evidence.append(
            f"endpoint={path}; before_owner={before_owner!r}; "
            f"delete_status={del_resp.status_code}; "
            f"followup_status={after.status_code}"
          )
          break
      if deleted_evidence:
        break

    if deleted_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-06",
        title="Ownership delete bypass — regular user deleted non-owned record",
        status="vulnerable",
        severity="CRITICAL",
        owasp="A01:2021",
        cwe=["CWE-639", "CWE-862"],
        attack=["T1078"],
        evidence=deleted_evidence,
        replay_steps=[
          "Log in as the regular user.",
          "DELETE a record whose owner is a different user.",
          "GET the same id and confirm the record is no longer present.",
        ],
        remediation="Apply ownership / role checks on all DELETE "
                    "endpoints. Soft-delete with audit trail is "
                    "preferable when destructive behavior is expected.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-06",
        title="Ownership delete — guard held",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"endpoints_tested={tested}"],
      ))

  def _test_admin_path_discovery(self):
    """PT-A01-09: walk app_routes / discovered_routes for admin-pattern
    paths and check whether the regular user can hit them.

    Distinct from PT-A01-02 (configured admin endpoints): this scenario
    fires on auto-discovered routes that *look* admin-y but weren't
    explicitly configured for testing.
    """
    import re
    admin_pattern = re.compile(
      r"(?:^|/)(?:admin|administrator|management|manage|backoffice|sysop)(?:$|/|-|\?)",
      re.IGNORECASE,
    )
    candidates = []
    seen = set()
    for path in (self.discovered_routes or []):
      if path in seen:
        continue
      seen.add(path)
      if admin_pattern.search(path):
        candidates.append(path)
    # Don't double-emit on configured admin_endpoints — those are PT-A01-02.
    configured_admin = {ep.path for ep in self.target_config.access_control.admin_endpoints}
    candidates = [p for p in candidates if p not in configured_admin]
    if not candidates:
      return

    denial_markers = ["access denied", "permission denied", "forbidden",
                      "not authorized", "unauthorized", "403"]
    reachable = []
    tested = 0
    for path in candidates:
      url = self.target_url + path
      self.safety.throttle()
      try:
        resp = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue
      tested += 1
      if resp.status_code != 200:
        continue
      body_lower = resp.text.lower()
      if any(m in body_lower for m in denial_markers):
        continue
      reachable.append(f"path={path}; status={resp.status_code}")

    if reachable:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-09",
        title="Admin-pattern endpoint reachable by regular user",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-285", "CWE-862"],
        attack=["T1078"],
        evidence=reachable,
        replay_steps=[
          "Discover app routes; identify any with admin-like prefixes.",
          "Request each as a regular user.",
          "Observe routes returning 200 OK without denial markers.",
        ],
        remediation="Apply role-gated middleware to every administrative "
                    "URL prefix. Default-deny on path-based admin "
                    "namespaces (``/admin/``, ``/manage/``, etc.).",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-09",
        title="Admin-pattern endpoints — discovered routes are guarded",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"discovered_admin_paths={len(candidates)}",
                  f"tested={tested}"],
      ))

  def _test_query_role_override(self):
    """PT-A01-10: probe whether a query parameter can flip role state.

    Compares the response on a baseline request vs. one with
    ``?role=admin`` / ``?is_admin=true``. A meaningful body delta
    suggests the server is reading authorization from the URL query
    string rather than the session.
    """
    # Try a small set of authenticated routes where role-gated content
    # is plausible — discovered_routes lets it scale to the target.
    targets = []
    for path in (self.discovered_routes or []):
      if path and not path.startswith(("/static/", "/auth/")):
        targets.append(path)
    if not targets:
      targets = ["/dashboard/"]
    targets = targets[:5]

    overrides = [
      ("role", "admin"), ("is_admin", "true"),
      ("admin", "1"), ("user_type", "admin"),
    ]

    delta_evidence = []
    tested = 0
    for path in targets:
      url = self.target_url + path
      self.safety.throttle()
      try:
        baseline = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue
      if baseline.status_code != 200:
        continue
      base_body = baseline.text
      base_len = len(base_body)
      for key, value in overrides:
        self.safety.throttle()
        try:
          probed = self.auth.regular_session.get(
            url, params={key: value}, timeout=10,
          )
        except Exception:
          continue
        tested += 1
        if probed.status_code != 200:
          continue
        # Detect the appearance of admin-only markers that weren't in
        # the baseline. Length-only deltas are too noisy to flag alone.
        admin_markers = ["admin panel", "/admin-panel", "manage users",
                         "all users", "is_admin"]
        new_markers = [
          m for m in admin_markers
          if m.lower() in probed.text.lower()
          and m.lower() not in base_body.lower()
        ]
        if new_markers:
          delta_evidence.append(
            f"path={path}; param={key}={value}; "
            f"new_markers={new_markers}; "
            f"baseline_len={base_len}; probed_len={len(probed.text)}"
          )
          break
      if delta_evidence:
        break

    if delta_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-10",
        title="Query parameter role override — server honors URL-controlled role",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-639", "CWE-285"],
        attack=["T1078"],
        evidence=delta_evidence,
        replay_steps=[
          "GET a route as a regular user; record body.",
          "GET the same route with ``?role=admin`` (and other "
          "common variants); compare bodies.",
          "Observe admin-only content appearing in the second response.",
        ],
        remediation="Read role state from the authenticated session "
                    "ONLY. Strip / ignore role-related query parameters "
                    "before authorization decisions.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-10",
        title="Query parameter role override — no privilege escalation observed",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"paths_tested={len(targets)}", f"requests={tested}"],
      ))

  def _test_hidden_field_tampering(self):
    """PT-A01-12: scan discovered forms for hidden inputs and try
    submitting a tampered value.

    Inspects each ``form`` action surfaced by discovery for
    ``<input type="hidden" name="..." value="...">`` entries whose
    name suggests an authorization field (role, is_admin, group,
    permission, ...). Submits the form with the value flipped.
    Vulnerable when the server's response indicates the change took
    effect (presence of a privilege-related marker, or a 2xx instead
    of the expected validation rejection).
    """
    forms = self.discovered_forms or []
    if not forms:
      return

    import re
    auth_field_pattern = re.compile(
      r"^(?:role|is_admin|admin|is_staff|is_superuser|"
      r"group|permission|level|priv|access|user_type)$",
      re.IGNORECASE,
    )
    tampered_evidence = []
    tested = 0

    for form_path in forms[:5]:
      url = self.target_url + form_path
      self.safety.throttle()
      try:
        page = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue
      if page.status_code != 200:
        continue

      # Extract hidden inputs and detect any auth-related field.
      hidden_fields = {}
      for tag in re.finditer(
        r'<input\b[^>]*type=["\']hidden["\'][^>]*>', page.text, re.I,
      ):
        attrs = tag.group(0)
        name_m = re.search(r'name=["\']([^"\']+)', attrs)
        val_m = re.search(r'value=["\']([^"\']*)', attrs)
        if name_m:
          hidden_fields[name_m.group(1)] = val_m.group(1) if val_m else ""
      auth_fields = {n: v for n, v in hidden_fields.items()
                     if auth_field_pattern.fullmatch(n)}
      if not auth_fields:
        continue

      # Also extract a CSRF token if needed.
      csrf_field = self.auth.detected_csrf_field or "csrfmiddlewaretoken"
      csrf_token = self.auth.extract_csrf_value(page.text, csrf_field)

      # Build payload: copy all visible fields, override auth fields.
      visible_inputs = {}
      for tag in re.finditer(r'<input\b([^>]*)>', page.text, re.I):
        attrs = tag.group(1)
        if 'type="hidden"' in attrs.lower() or "type='hidden'" in attrs.lower():
          continue
        name_m = re.search(r'name=["\']([^"\']+)', attrs)
        val_m = re.search(r'value=["\']([^"\']*)', attrs)
        if name_m:
          visible_inputs[name_m.group(1)] = val_m.group(1) if val_m else ""

      payload = dict(visible_inputs)
      payload.update(hidden_fields)
      for n in auth_fields:
        # Tamper: assert highest-privilege values.
        payload[n] = "admin"
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

      # Vulnerable signal: 2xx/3xx without an "invalid"/"error" body,
      # AND the server didn't reject the tampered value.
      if resp.status_code in (200, 301, 302):
        body_lower = resp.text.lower()
        if not any(m in body_lower for m in
                   ("invalid", "error", "not allowed", "forbidden")):
          tampered_evidence.append(
            f"form={form_path}; hidden_auth_fields="
            f"{sorted(auth_fields.keys())}; submit_status={resp.status_code}"
          )
          break

    if tampered_evidence:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-12",
        title="Hidden field authorization tampering — server accepted tampered value",
        status="vulnerable",
        severity="HIGH",
        owasp="A01:2021",
        cwe=["CWE-472", "CWE-863"],
        attack=["T1190"],
        evidence=tampered_evidence,
        replay_steps=[
          "GET a form page; observe hidden inputs with auth-related "
          "names (role / is_admin / group / etc.).",
          "Submit the form with that hidden field's value modified.",
          "Observe server accepts the tampered value.",
        ],
        remediation="Never trust client-submitted authorization fields. "
                    "Strip hidden auth-like fields server-side or use a "
                    "session-bound state token. ModelForms should not "
                    "include role / is_staff in their bound fields.",
      ))
    elif tested > 0:
      self.findings.append(GrayboxFinding(
        scenario_id="PT-A01-12",
        title="Hidden field tampering — no privilege escalation observed",
        status="not_vulnerable",
        severity="INFO",
        owasp="A01:2021",
        evidence=[f"forms_with_hidden_auth_fields={tested}"],
      ))
