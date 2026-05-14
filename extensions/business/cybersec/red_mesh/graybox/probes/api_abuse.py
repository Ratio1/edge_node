"""API abuse probes — OWASP API4 (Resource Consumption) and API6 (Business Flows)."""

import re

import requests

from .base import ProbeBase


MAX_HIGH_LIMIT_PROBE_LIMIT = 1_000
_EXACT_TEMPLATE_RE = re.compile(r"^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$")
_ALLOWED_TEMPLATE_KEYS = ("test_account", "run_id", "job_id")


class ApiAbuseProbes(ProbeBase):
  """OWASP API4 + API6 graybox probes.

  Scenarios implemented (Subphases 3.2 + 3.3):
    PT-OAPI4-01 — pagination cap missing (bounded; non-stateful)
    PT-OAPI4-02 — oversized payload accepted (bounded; non-stateful)
    PT-OAPI4-03 — rate limit absent (bounded; requires `rate_limit_expected=True`)
    PT-OAPI6-01 — business flow lacks rate limit (STATEFUL)
    PT-OAPI6-02 — business flow lacks uniqueness check (STATEFUL)
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False
  probe_key = "_graybox_api_abuse"

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings
    return self.run_runtime_scenarios(self.probe_key)

  def _session(self):
    return self.auth.official_session or self.auth.regular_session

  def _low_priv_session(self):
    return self.auth.regular_session

  @staticmethod
  def _bounded_int(value, *, default: int, minimum: int = 1,
                   maximum: int = MAX_HIGH_LIMIT_PROBE_LIMIT) -> int:
    try:
      parsed = int(value)
    except (TypeError, ValueError):
      parsed = default
    return max(minimum, min(parsed, maximum))

  def _flow_request(self, session, method, url, body, timeout=10):
    req = getattr(session, (method or "POST").lower(), session.post)
    if (method or "POST").upper() in ("GET", "DELETE"):
      return req(url, params=dict(body or {}), timeout=timeout)
    return req(url, json=dict(body or {}), timeout=timeout)

  def _flow_template_context(self, flow):
    job_id = self.job_id or "local"
    run_id = f"{job_id}:{self.assignment_revision or 0}"
    return {
      "test_account": flow.test_account,
      "run_id": run_id,
      "job_id": job_id,
    }

  def _render_template_value(self, value, context):
    if isinstance(value, str):
      match = _EXACT_TEMPLATE_RE.match(value)
      if match:
        key = match.group(1)
        if key not in _ALLOWED_TEMPLATE_KEYS:
          raise ValueError(f"unsupported_template_key:{key}")
        return context[key], key == "test_account"
      if "{" in value or "}" in value:
        raise ValueError("unsupported_template_expression")
      return value, False
    if isinstance(value, dict):
      out = {}
      used_test_account = False
      for key, item in value.items():
        rendered, used = self._render_template_value(item, context)
        out[key] = rendered
        used_test_account = used_test_account or used
      return out, used_test_account
    if isinstance(value, list):
      out = []
      used_test_account = False
      for item in value:
        rendered, used = self._render_template_value(item, context)
        out.append(rendered)
        used_test_account = used_test_account or used
      return out, used_test_account
    return value, False

  def _render_flow_payloads(self, flow):
    context = self._flow_template_context(flow)
    try:
      body, body_uses_test_account = self._render_template_value(
        flow.body_template or {}, context,
      )
      revert_body, revert_uses_test_account = self._render_template_value(
        flow.revert_body or {}, context,
      )
    except ValueError as exc:
      return None, None, str(exc)
    unsafe_static_body = bool(
      getattr(flow, "allow_static_test_account_body", False)
    )
    if not body_uses_test_account and not unsafe_static_body:
      return None, None, "test_account_placeholder_required"
    if flow.revert_body and not revert_uses_test_account and not unsafe_static_body:
      return None, None, "revert_test_account_placeholder_required"
    return body, revert_body, ""

  def _flow_verify(self, session, flow):
    if not flow.verify_path:
      return True
    if not self.budget():
      raise RuntimeError("budget_exhausted")
    self.safety.throttle()
    resp = self._flow_request(
      session,
      flow.verify_method,
      self.target_url + flow.verify_path,
      {},
      timeout=10,
    )
    return resp.status_code < 400

  def _flow_revert(self, session, flow, revert_body):
    if not flow.revert_path:
      return False
    if not self.cleanup_budget():
      return False
    self.safety.throttle()
    resp = self._flow_request(
      session,
      flow.revert_method,
      self.target_url + flow.revert_path,
      revert_body,
      timeout=10,
    )
    return resp.status_code < 400

  def _flow_revert_fn(self, session, flow, revert_body):
    if not flow.revert_path:
      return None

    def revert(_baseline, _flow=flow, _revert_body=revert_body):
      return self._flow_revert(session, _flow, _revert_body)

    return revert

  def _flow_replay_steps(self, flow, url, action):
    steps = [
      f"{action}: {(flow.method or 'POST').upper()} {url}",
    ]
    if flow.revert_path:
      steps.append(
        "rollback: "
        f"{(flow.revert_method or 'POST').upper()} "
        f"{self.target_url + flow.revert_path}"
      )
    return steps

  # ── PT-OAPI4-01 — no pagination cap ────────────────────────────────

  def _test_no_pagination_cap(self):
    if not self.scenario_enabled("PT-OAPI4-01"):
      return
    title = "API endpoint lacks pagination cap"
    owasp = "API4:2023"
    if not self.target_config.api_security.resource_endpoints:
      self.emit_inconclusive(
        "PT-OAPI4-01", title, owasp, "no_configured_resource_endpoints",
      )
      return
    session = self._session()
    if session is None:
      self.emit_inconclusive("PT-OAPI4-01", title, owasp, "no_authenticated_session")
      return
    for ep in self.target_config.api_security.resource_endpoints:
      if not getattr(ep, "allow_high_limit_probe", False):
        self.emit_inconclusive(
          "PT-OAPI4-01", title, owasp, "high_limit_probe_not_authorized",
        )
        continue
      if not self.budget(2):
        self.emit_inconclusive("PT-OAPI4-01", title, owasp, "budget_exhausted")
        return
      url = self.target_url + ep.path
      baseline_limit = self._bounded_int(ep.baseline_limit, default=10)
      abuse_limit = self._bounded_int(ep.abuse_limit, default=MAX_HIGH_LIMIT_PROBE_LIMIT)
      if abuse_limit <= baseline_limit:
        self.emit_inconclusive(
          "PT-OAPI4-01", title, owasp, "invalid_limit_bounds",
        )
        continue
      self.safety.throttle()
      try:
        baseline = session.get(
          url, params={ep.limit_param: baseline_limit}, timeout=10,
        )
      except requests.RequestException:
        continue
      self.safety.throttle()
      try:
        abuse = session.get(
          url, params={ep.limit_param: abuse_limit}, timeout=10,
        )
      except requests.RequestException:
        continue
      if baseline.status_code >= 400 or abuse.status_code >= 400:
        continue
      base_size = len((baseline.text or "").encode())
      abuse_size = len((abuse.text or "").encode())
      if abuse_size > 5 * max(1, base_size):
        self.emit_vulnerable(
          "PT-OAPI4-01", title, "MEDIUM", owasp, ["CWE-770"],
          [f"endpoint={url}", f"requested_limit={ep.abuse_limit}",
           f"effective_limit={abuse_limit}",
           f"baseline_size_bytes={base_size}",
           f"abuse_size_bytes={abuse_size}"],
          remediation=(
            "Cap pagination server-side. Reject limit values above a "
            "configured maximum (typically 100–1000)."
          ),
        )
      else:
        self.emit_clean(
          "PT-OAPI4-01", title, owasp,
          [f"endpoint={url}", "size_growth_within_cap"],
        )

  # ── PT-OAPI4-02 — oversized payload ────────────────────────────────

  def _test_oversized_payload(self):
    if not self.scenario_enabled("PT-OAPI4-02"):
      return
    title = "API endpoint accepts oversized payload"
    owasp = "API4:2023"
    if not self.target_config.api_security.resource_endpoints:
      self.emit_inconclusive(
        "PT-OAPI4-02", title, owasp, "no_configured_resource_endpoints",
      )
      return
    session = self._session()
    if session is None:
      self.emit_inconclusive("PT-OAPI4-02", title, owasp, "no_authenticated_session")
      return
    for ep in self.target_config.api_security.resource_endpoints:
      if not getattr(ep, "allow_oversized_payload_probe", False):
        self.emit_inconclusive(
          "PT-OAPI4-02", title, owasp, "oversized_payload_probe_not_authorized",
        )
        continue
      if not self.budget():
        self.emit_inconclusive("PT-OAPI4-02", title, owasp, "budget_exhausted")
        return
      body_bytes = max(1, min(int(getattr(ep, "oversized_payload_bytes", 65_536) or 65_536), 262_144))
      big = "A" * body_bytes
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        resp = session.post(url, json={"x": big}, timeout=15)
      except requests.RequestException:
        continue
      if resp.status_code == 429:
        return
      if resp.status_code < 400:
        self.emit_vulnerable(
          "PT-OAPI4-02", title, "MEDIUM", owasp, ["CWE-770"],
          [f"endpoint={url}", f"body_bytes={body_bytes}",
           f"response_status={resp.status_code}"],
          remediation=(
            "Enforce a request-body size limit at the reverse-proxy or "
            "framework layer."
          ),
        )

  # ── PT-OAPI4-03 — no rate limit ────────────────────────────────────

  def _test_no_rate_limit(self):
    if not self.scenario_enabled("PT-OAPI4-03"):
      return
    title = "API endpoint lacks rate limit"
    owasp = "API4:2023"
    if not self.target_config.api_security.resource_endpoints:
      self.emit_inconclusive(
        "PT-OAPI4-03", title, owasp, "no_configured_resource_endpoints",
      )
      return
    session = self._session()
    if session is None:
      self.emit_inconclusive("PT-OAPI4-03", title, owasp, "no_authenticated_session")
      return
    for ep in self.target_config.api_security.resource_endpoints:
      if not ep.rate_limit_expected:
        continue  # FP guard — only fire when operator marked endpoint
      n = 0
      saw_429 = False
      saw_retry_after = False
      saw_ratelimit_header = False
      for _ in range(10):
        if not self.budget():
          self.emit_inconclusive("PT-OAPI4-03", title, owasp, "budget_exhausted")
          break
        self.safety.throttle()
        try:
          resp = session.get(self.target_url + ep.path, timeout=10)
        except requests.RequestException:
          break
        n += 1
        if resp.status_code == 429:
          saw_429 = True
          break
        if resp.headers.get("Retry-After"):
          saw_retry_after = True
        if any(h.lower().startswith("x-ratelimit") for h in resp.headers):
          saw_ratelimit_header = True
      if n >= 5 and not (saw_429 or saw_retry_after or saw_ratelimit_header):
        self.emit_vulnerable(
          "PT-OAPI4-03", title, "LOW", owasp, ["CWE-770"],
          [f"endpoint={self.target_url + ep.path}",
           f"requests_sent={n}",
           "rate_limit_signals=absent"],
          remediation=(
            "Apply rate limiting (token bucket / leaky bucket / sliding "
            "window) at the gateway. Return 429 + Retry-After when the "
            "limit is reached."
          ),
        )

  # ── PT-OAPI6-01 — flow no rate limit (STATEFUL) ────────────────────

  def _test_flow_no_rate_limit(self):
    if not self.scenario_enabled("PT-OAPI6-01"):
      return
    title = "API business flow lacks rate limit / abuse controls"
    owasp = "API6:2023"
    if not self.target_config.api_security.business_flows:
      self.emit_inconclusive(
        "PT-OAPI6-01", title, owasp, "no_configured_business_flows",
      )
      return
    session = self._low_priv_session()
    if session is None:
      self.emit_inconclusive("PT-OAPI6-01", title, owasp, "no_low_privileged_session")
      return
    for flow in self.target_config.api_security.business_flows:
      if not flow.test_account:
        self.emit_inconclusive("PT-OAPI6-01", title, owasp, "no_test_account_configured")
        continue
      body, revert_body, template_error = self._render_flow_payloads(flow)
      if template_error:
        self.emit_inconclusive("PT-OAPI6-01", title, owasp, template_error)
        continue
      url = self.target_url + flow.path
      probe_state = {}

      def baseline(_flow=flow):
        return {"flow_name": _flow.flow_name}

      def mutate(_baseline, _flow=flow, _url=url, _body=body,
                 _probe_state=probe_state):
        attempts = 0
        captcha = False
        mfa = False
        for _ in range(5):
          if not self.budget():
            raise RuntimeError("budget_exhausted")
          self.safety.throttle()
          try:
            resp = self._flow_request(
              session, _flow.method, _url, _body, timeout=10,
            )
          except requests.RequestException:
            return self.MUTATION_ATTEMPTED_UNKNOWN
          attempts += 1
          if resp.status_code == 429:
            break
          body = (resp.text or "")[:2000].lower()
          if _flow.captcha_marker and _flow.captcha_marker.lower() in body:
            captcha = True
          if _flow.mfa_marker and _flow.mfa_marker.lower() in body:
            mfa = True
        _probe_state["attempts"] = attempts
        _probe_state["captcha"] = captcha
        _probe_state["mfa"] = mfa
        return attempts >= 5 and not (captcha or mfa)

      def verify(baseline_, _flow=flow, _probe_state=probe_state):
        state = _probe_state
        signals_confirmed = state.get("attempts", 0) >= 5 and not (
          state.get("captcha") or state.get("mfa")
        )
        if not signals_confirmed:
          return False
        try:
          return self._flow_verify(session, _flow)
        except requests.RequestException:
          return self.MUTATION_ATTEMPTED_UNKNOWN

      self.run_stateful(
        "PT-OAPI6-01",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=self._flow_revert_fn(session, flow, revert_body),
        finding_kwargs={
          "title": title, "owasp": owasp, "severity": "MEDIUM",
          "cwe": ["CWE-799", "CWE-840"],
          "evidence": [f"flow={flow.flow_name}", f"endpoint={url}",
                       "attempts=5"],
          "replay_steps": self._flow_replay_steps(flow, url, "repeat 5 times"),
          "remediation": (
            "Add an abuse-prevention layer to sensitive flows: per-account "
            "quota, CAPTCHA challenge after N attempts, or MFA when the "
            "operation impacts billing / identity. Pure rate-limit at the "
            "IP layer is insufficient."
          ),
        },
        no_mutation_reason_fn=lambda base: "abuse_signals_not_confirmed",
      )

  # ── PT-OAPI6-02 — flow no uniqueness check (STATEFUL) ──────────────

  def _test_flow_no_uniqueness(self):
    if not self.scenario_enabled("PT-OAPI6-02"):
      return
    title = "API business flow lacks uniqueness check"
    owasp = "API6:2023"
    if not self.target_config.api_security.business_flows:
      self.emit_inconclusive(
        "PT-OAPI6-02", title, owasp, "no_configured_business_flows",
      )
      return
    session = self._low_priv_session()
    if session is None:
      self.emit_inconclusive("PT-OAPI6-02", title, owasp, "no_low_privileged_session")
      return
    for flow in self.target_config.api_security.business_flows:
      if not flow.test_account:
        self.emit_inconclusive("PT-OAPI6-02", title, owasp, "no_test_account_configured")
        continue
      body, revert_body, template_error = self._render_flow_payloads(flow)
      if template_error:
        self.emit_inconclusive("PT-OAPI6-02", title, owasp, template_error)
        continue
      url = self.target_url + flow.path
      probe_state = {}

      def baseline(_flow=flow):
        return {"flow_name": _flow.flow_name}

      def mutate(_b, _flow=flow, _url=url, _body=body,
                 _probe_state=probe_state):
        if not self.budget(2):
          raise RuntimeError("budget_exhausted")
        try:
          self.safety.throttle()
          r1 = self._flow_request(
            session, _flow.method, _url, _body, timeout=10,
          )
          self.safety.throttle()
          r2 = self._flow_request(
            session, _flow.method, _url, _body, timeout=10,
          )
        except requests.RequestException:
          return False
        _probe_state["both_2xx"] = (
          r1.status_code < 400 and r2.status_code < 400
        )
        return _probe_state["both_2xx"]

      def verify(_b, _flow=flow, _probe_state=probe_state):
        if not _probe_state.get("both_2xx", False):
          return False
        try:
          return self._flow_verify(session, _flow)
        except requests.RequestException:
          return False

      self.run_stateful(
        "PT-OAPI6-02",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=self._flow_revert_fn(session, flow, revert_body),
        finding_kwargs={
          "title": title, "owasp": owasp, "severity": "MEDIUM",
          "cwe": ["CWE-840"],
          "evidence": [f"flow={flow.flow_name}", f"endpoint={url}",
                       "duplicate_accepted=true"],
          "replay_steps": self._flow_replay_steps(flow, url, "submit twice"),
          "remediation": (
            "Enforce uniqueness server-side (e.g., unique constraint on "
            "username/email/voucher-code). Return 409 Conflict on duplicate."
          ),
        },
        no_mutation_reason_fn=lambda base: "duplicate_submission_not_accepted",
      )
