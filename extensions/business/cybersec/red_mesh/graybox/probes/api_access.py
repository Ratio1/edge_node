"""API access-control probes — OWASP API1 (BOLA) and API5 (BFLA)."""

import re

import requests

from .base import ProbeBase


# Sensitive-field-name patterns that escalate a BOLA finding to CRITICAL
# when present in the leaked response (Subphase 2.1 design § FP guards +
# severity). Field NAMES only — values never inspected here; the
# centralised scrubber strips secret values at the storage boundary.
_BOLA_PII_FIELD_PATTERNS = (
  re.compile(r"(?i)\b(email|e_mail)\b"),
  re.compile(r"(?i)\b(ssn|social_security)\b"),
  re.compile(r"(?i)\b(token|api_key|password|secret)\b"),
  re.compile(r"(?i)\b(credit_?card|cc_number|cc_num|card_number)\b"),
  re.compile(r"(?i)\b(phone|mobile|telephone)\b"),
)


class ApiAccessProbes(ProbeBase):
  """OWASP API1 (BOLA) + API5 (BFLA) graybox probes.

  Scenarios:
    PT-OAPI1-01 — API object-level authorization bypass (BOLA, read)
                  — implemented in Subphase 2.1.
    PT-OAPI5-01 — Function-level authorization bypass (regular as admin,
                  read) — Subphase 2.3.
    PT-OAPI5-02 — Function-level authorization bypass (anonymous as user,
                  read) — Subphase 2.3.
    PT-OAPI5-03 — Method-override authorization bypass — Subphase 3.4.
    PT-OAPI5-04 — Function-level authorization bypass (regular as admin,
                  mutating; stateful, requires revert plan) — Subphase 3.4.
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings

    if getattr(api_security, "object_endpoints", None):
      self.run_safe("api_bola", self._test_api_bola)

    if getattr(api_security, "function_endpoints", None):
      self.run_safe("api_bfla_regular", self._test_bfla_regular_as_admin)
      self.run_safe("api_bfla_anon", self._test_bfla_anon_as_user)
      self.run_safe("api_bfla_method_override", self._test_bfla_method_override)
      self.run_safe("api_bfla_mutating", self._test_bfla_regular_as_admin_mutating)

    return self.findings

  # ── PT-OAPI1-01 — API object-level authorization bypass (BOLA) ──────

  def _test_api_bola(self):
    """For each configured ApiObjectEndpoint, iterate ``test_ids`` against
    ``path`` (template) using the regular_session (or official_session if
    no regular configured). Vulnerable iff response is 200 + JSON +
    ``owner_field`` mismatches the authenticated username (or
    ``tenant_field`` mismatches the expected tenant).

    Severity:
      HIGH by default.
      CRITICAL when leaked response contains PII-ish field NAMES.
    """
    api_security = self.target_config.api_security
    endpoints = api_security.object_endpoints
    session = self.auth.regular_session or self.auth.official_session
    if session is None:
      self.emit_inconclusive(
        "PT-OAPI1-01",
        "API object-level authorization bypass (BOLA)",
        "API1:2023",
        "no_authenticated_session",
      )
      return

    found_any = False
    for ep in endpoints:
      for test_id in ep.test_ids:
        if not self.budget():
          self.emit_inconclusive(
            "PT-OAPI1-01",
            "API object-level authorization bypass (BOLA)",
            "API1:2023",
            "budget_exhausted",
          )
          return
        url = self._render_object_url(ep, test_id)
        self.safety.throttle()
        try:
          resp = session.get(url, timeout=10, allow_redirects=False)
        except requests.RequestException as exc:
          # Single-endpoint transport error → continue with next id.
          # _record_error would also work but inflates noise.
          continue

        outcome = self._evaluate_bola_response(ep, test_id, url, resp)
        if outcome == "vulnerable" or outcome == "clean":
          found_any = True

    if not found_any:
      # Every iteration was inconclusive (HTML, 4xx, etc.) OR the config
      # listed zero test_ids. Surface a single inconclusive so the
      # operator knows the probe attempted but couldn't draw a conclusion.
      self.emit_inconclusive(
        "PT-OAPI1-01",
        "API object-level authorization bypass (BOLA)",
        "API1:2023",
        "no_evaluable_responses",
      )

  def _render_object_url(self, ep, test_id):
    """Substitute {id_param} into ep.path. Falls back to {id} for
    backward compatibility with the typical Django/Flask convention."""
    path = ep.path
    if "{" + ep.id_param + "}" in path:
      path = path.replace("{" + ep.id_param + "}", str(test_id))
    elif "{id}" in path:
      path = path.replace("{id}", str(test_id))
    else:
      path = path.rstrip("/") + "/" + str(test_id)
    return self.target_url + path

  def _evaluate_bola_response(self, ep, test_id, url, resp):
    """Return ``"vulnerable"`` / ``"clean"`` / ``"skip"`` and emit the
    appropriate finding for the single-id evaluation."""
    title = "API object-level authorization bypass (BOLA)"
    owasp = "API1:2023"
    cwe = ["CWE-639", "CWE-284"]

    # FP guard 1: skip non-API responses (web IDOR is AccessControlProbes' job).
    content_type = (resp.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
      return "skip"
    # FP guard 2: skip 4xx/5xx — endpoint forbade us, that's correct.
    if resp.status_code >= 400:
      return "skip"
    # FP guard 3: must parse as JSON.
    try:
      data = resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
      return "skip"
    if not isinstance(data, dict):
      return "skip"
    # FP guard 4: owner_field must be present (otherwise nothing to compare).
    if ep.owner_field not in data:
      return "skip"

    expected_principal = self.regular_username or "<unknown>"
    owner_value = str(data.get(ep.owner_field))
    tenant_field = (ep.tenant_field or "").strip()

    owner_mismatch = owner_value and owner_value != expected_principal
    tenant_mismatch = bool(
      tenant_field and tenant_field in data
      and data[tenant_field] is not None
    )

    if owner_mismatch or tenant_mismatch:
      sensitive_fields = self._collect_sensitive_field_names(data)
      severity = "CRITICAL" if sensitive_fields else "HIGH"
      evidence = [
        f"endpoint={url}",
        "response_status=200",
        "content_type=application/json",
        f"owner_field={ep.owner_field}",
        f"owner_value={owner_value}",
        f"authenticated_user={expected_principal}",
        f"test_id={test_id}",
      ]
      if tenant_mismatch:
        evidence.append(f"tenant_field={tenant_field}")
      if sensitive_fields:
        evidence.append("pii_fields=" + ",".join(sorted(sensitive_fields)))
      replay = [
        "Authenticate as the regular (low-privileged) user.",
        f"GET {url}",
        f"Observe the response carries {ep.owner_field}={owner_value!r} "
        "even though the requester is not the owner.",
      ]
      self.emit_vulnerable(
        "PT-OAPI1-01", title, severity, owasp, cwe, evidence,
        replay_steps=replay,
        remediation=(
          "Enforce per-object authorization on the endpoint: verify that "
          "the requester owns the object (or shares its tenant) before "
          "returning it. A path/query parameter is not an authorization "
          "claim."
        ),
      )
      return "vulnerable"

    self.emit_clean(
      "PT-OAPI1-01", title, owasp,
      [f"endpoint={url}", "response_status=200",
       f"owner_field={ep.owner_field}",
       f"owner_value={owner_value}",
       f"authenticated_user={expected_principal}"],
    )
    return "clean"

  # ── PT-OAPI5-01 — BFLA: regular user reaches admin function ─────────

  def _test_bfla_regular_as_admin(self):
    """For each ApiFunctionEndpoint with method == GET (read-only),
    GET it as the regular_session and expect ≥401/403.

    Vulnerable iff status < 400 (no auth gate). Mutating endpoints
    (method != GET) are deferred to PT-OAPI5-04 in Subphase 3.4 — they
    require the stateful contract + a configured revert plan.
    """
    api_security = self.target_config.api_security
    endpoints = api_security.function_endpoints
    session = self.auth.regular_session
    if session is None:
      self.emit_inconclusive(
        "PT-OAPI5-01",
        "API function-level authorization bypass (regular as admin, read)",
        "API5:2023",
        "no_regular_session",
      )
      return

    found_any = self._run_function_endpoints(
      endpoints, session, "regular",
      scenario_id="PT-OAPI5-01",
      title="API function-level authorization bypass (regular as admin, read)",
    )
    if not found_any:
      self.emit_inconclusive(
        "PT-OAPI5-01",
        "API function-level authorization bypass (regular as admin, read)",
        "API5:2023",
        "no_evaluable_function_endpoints",
      )

  # ── PT-OAPI5-02 — BFLA: anonymous user reaches user function ────────

  def _test_bfla_anon_as_user(self):
    """Anonymous (unauthenticated) GET against each function endpoint.

    Same mechanics as PT-OAPI5-01 but uses
    `auth.make_anonymous_session()` so caller cookies / Bearer headers
    are not present.
    """
    api_security = self.target_config.api_security
    endpoints = api_security.function_endpoints
    if not hasattr(self.auth, "make_anonymous_session"):
      self.emit_inconclusive(
        "PT-OAPI5-02",
        "API function-level authorization bypass (anonymous as user, read)",
        "API5:2023",
        "auth_manager_missing_anonymous_session",
      )
      return
    session = self.auth.make_anonymous_session()
    found_any = self._run_function_endpoints(
      endpoints, session, "anonymous",
      scenario_id="PT-OAPI5-02",
      title="API function-level authorization bypass (anonymous as user, read)",
    )
    try:
      session.close()
    except Exception:
      pass
    if not found_any:
      self.emit_inconclusive(
        "PT-OAPI5-02",
        "API function-level authorization bypass (anonymous as user, read)",
        "API5:2023",
        "no_evaluable_function_endpoints",
      )

  # ── Shared BFLA evaluator ────────────────────────────────────────────

  def _run_function_endpoints(self, endpoints, session, principal, *,
                                scenario_id, title):
    """Iterate function endpoints in read-only mode; emit per-endpoint
    finding. Returns True iff at least one endpoint yielded a definitive
    (vulnerable or clean) result."""
    cwe = ["CWE-285", "CWE-862"]
    owasp = "API5:2023"
    found_any = False

    for ep in endpoints:
      # Phase 2.3 covers read-only (method=GET) only. Mutating methods
      # are deferred to PT-OAPI5-03 / PT-OAPI5-04 (stateful, Phase 3.4).
      if (ep.method or "GET").upper() not in ("GET", "HEAD"):
        continue

      if not self.budget():
        self.emit_inconclusive(
          scenario_id, title, owasp, "budget_exhausted",
        )
        return found_any

      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue

      status = resp.status_code
      # Auth gate working as intended.
      if status in (401, 403):
        self.emit_clean(
          scenario_id, title, owasp,
          [f"endpoint={url}", f"principal={principal}",
           f"response_status={status}",
           "marker=auth_gate_returned_4xx"],
        )
        found_any = True
        continue
      # Other 4xx/5xx — endpoint refused for other reasons; skip.
      if status >= 400:
        continue

      # 2xx/3xx without an auth-required marker = vulnerable.
      body_lower = (resp.text or "").lower()[:2000]
      marker = (ep.auth_required_marker or "").lower().strip()
      marker_present = bool(marker and marker in body_lower)
      if marker_present:
        self.emit_clean(
          scenario_id, title, owasp,
          [f"endpoint={url}", f"principal={principal}",
           f"response_status={status}",
           "marker=configured_auth_required_marker_present"],
        )
        found_any = True
        continue

      # Severity: HIGH baseline; CRITICAL when path matches /admin or
      # function_endpoint is explicitly tagged privilege=admin.
      privilege = (ep.privilege or "").lower()
      severity = "CRITICAL" if (privilege == "admin"
                                  or "/admin" in ep.path.lower()) else "HIGH"
      evidence = [
        f"endpoint={url}", f"principal={principal}",
        f"response_status={status}",
        f"method={(ep.method or 'GET').upper()}",
        "marker_absent=true",
      ]
      replay = [
        f"Authenticate as the {principal} user (or none for anonymous).",
        f"GET {url}",
        "Observe a 2xx response — the endpoint did not enforce its "
        "intended authorization.",
      ]
      self.emit_vulnerable(
        scenario_id, title, severity, owasp, cwe, evidence,
        replay_steps=replay,
        remediation=(
          "Add the appropriate authorization decorator/middleware on the "
          "endpoint. For administrative functions verify that the caller "
          "has the required role; for user-only functions require an "
          "authenticated session. Returning 2xx to the wrong principal "
          "leaks data or exposes side effects."
        ),
      )
      found_any = True

    return found_any

  # ── PT-OAPI5-03 — Method-override bypass (STATEFUL) ────────────────

  def _test_bfla_method_override(self):
    title = "API method-override authorization bypass"
    owasp = "API5:2023"
    api_security = self.target_config.api_security
    session = self.auth.regular_session
    if session is None:
      self.emit_inconclusive("PT-OAPI5-03", title, owasp, "no_regular_session")
      return

    for ep in api_security.function_endpoints:
      method = (ep.method or "GET").upper()
      if method == "GET":
        # Method-override target should be a method-restricted endpoint
        # — GET-only endpoints have nothing to override.
        continue
      if not ep.revert_path:
        self.emit_inconclusive(
          "PT-OAPI5-03", title, owasp, "no_revert_path_configured",
        )
        continue

      url = self.target_url + ep.path
      revert_url = self.target_url + ep.revert_path

      def baseline(_ep=ep, _url=url):
        # Control case: GET (without override) should be rejected.
        if not self.budget():
          raise RuntimeError("budget_exhausted")
        self.safety.throttle()
        try:
          resp = session.get(_url, timeout=10, allow_redirects=False)
        except requests.RequestException as exc:
          raise RuntimeError(str(exc))
        return {"control_status": resp.status_code}

      def mutate(base, _ep=ep, _url=url):
        if base.get("control_status", 0) < 400:
          # Control case was already accessible — no override needed.
          return False
        if not self.budget():
          return False
        self.safety.throttle()
        try:
          resp = session.post(
            _url, headers={"X-HTTP-Method-Override": "GET"},
            timeout=10, allow_redirects=False,
          )
        except requests.RequestException:
          return False
        base["override_status"] = resp.status_code
        return resp.status_code < 400

      def verify(base):
        return base.get("override_status", 999) < 400

      def revert(base, _revert_url=revert_url, _ep=ep):
        if not self.budget():
          return False
        try:
          session.post(_revert_url, json=ep.revert_body or {}, timeout=10)
        except requests.RequestException:
          return False
        return True

      self.run_stateful(
        "PT-OAPI5-03",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=revert,
        finding_kwargs={
          "title": title, "owasp": owasp, "severity": "HIGH",
          "cwe": ["CWE-285", "CWE-862"],
          "evidence": [f"endpoint={url}", "override_header=X-HTTP-Method-Override: GET"],
          "remediation": (
            "Disable HTTP method override entirely or restrict it to "
            "internal services. Authorization must be enforced on the "
            "effective method used."
          ),
        },
      )

  # ── PT-OAPI5-04 — Regular user reaches admin function (MUTATING) ───

  def _test_bfla_regular_as_admin_mutating(self):
    title = "API function-level authorization bypass (regular as admin, mutating)"
    owasp = "API5:2023"
    api_security = self.target_config.api_security
    session = self.auth.regular_session
    if session is None:
      self.emit_inconclusive("PT-OAPI5-04", title, owasp, "no_regular_session")
      return

    for ep in api_security.function_endpoints:
      method = (ep.method or "GET").upper()
      if method == "GET":
        continue
      if not ep.revert_path:
        self.emit_inconclusive(
          "PT-OAPI5-04", title, owasp, "no_revert_path_configured",
        )
        continue

      url = self.target_url + ep.path
      revert_url = self.target_url + ep.revert_path
      method_fn = getattr(session, method.lower(), session.post)

      def baseline(_ep=ep):
        return {"method": method, "ep_path": _ep.path}

      def mutate(base, _url=url, _method_fn=method_fn):
        if not self.budget():
          return False
        self.safety.throttle()
        try:
          resp = _method_fn(_url, timeout=10)
        except requests.RequestException:
          return False
        base["mutate_status"] = resp.status_code
        return resp.status_code < 400

      def verify(base):
        return base.get("mutate_status", 999) < 400

      def revert(base, _revert_url=revert_url, _ep=ep):
        if not self.budget():
          return False
        try:
          session.post(_revert_url, json=ep.revert_body or {}, timeout=10)
        except requests.RequestException:
          return False
        return True

      privilege = (ep.privilege or "").lower()
      severity = ("CRITICAL"
                  if privilege == "admin" or "/admin" in ep.path.lower()
                  else "HIGH")
      self.run_stateful(
        "PT-OAPI5-04",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=revert,
        finding_kwargs={
          "title": title, "owasp": owasp, "severity": severity,
          "cwe": ["CWE-285", "CWE-862"],
          "evidence": [f"endpoint={url}", f"method={method}",
                       "principal=regular"],
          "remediation": (
            "Verify the caller's role on every mutating endpoint. The "
            "URL alone is not an authorization claim — admin actions "
            "must check the session/JWT role on the server."
          ),
        },
      )

  @staticmethod
  def _collect_sensitive_field_names(payload):
    """Return the subset of top-level keys in ``payload`` whose names
    match a PII pattern. Values are never inspected."""
    found = set()
    for key in (payload.keys() if isinstance(payload, dict) else ()):
      if not isinstance(key, str):
        continue
      for pat in _BOLA_PII_FIELD_PATTERNS:
        if pat.search(key):
          found.add(key)
          break
    return found
