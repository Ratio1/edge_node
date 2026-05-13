"""API abuse probes — OWASP API4 (Resource Consumption) and API6 (Business Flows)."""

import requests

from .base import ProbeBase


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

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings
    if getattr(api_security, "resource_endpoints", None):
      self.run_safe("api_no_pagination_cap", self._test_no_pagination_cap)
      self.run_safe("api_oversized_payload", self._test_oversized_payload)
      self.run_safe("api_no_rate_limit", self._test_no_rate_limit)
    if getattr(api_security, "business_flows", None):
      self.run_safe("api_flow_no_rate_limit", self._test_flow_no_rate_limit)
      self.run_safe("api_flow_no_uniqueness", self._test_flow_no_uniqueness)
    return self.findings

  def _session(self):
    return self.auth.official_session or self.auth.regular_session

  def _flow_request(self, session, method, url, body, timeout=10):
    req = getattr(session, (method or "POST").lower(), session.post)
    if (method or "POST").upper() in ("GET", "DELETE"):
      return req(url, params=dict(body or {}), timeout=timeout)
    return req(url, json=dict(body or {}), timeout=timeout)

  def _flow_verify(self, session, flow):
    if not flow.verify_path:
      return True
    if not self.budget():
      return False
    self.safety.throttle()
    resp = self._flow_request(
      session,
      flow.verify_method,
      self.target_url + flow.verify_path,
      {},
      timeout=10,
    )
    return resp.status_code < 400

  def _flow_revert(self, session, flow):
    if not flow.revert_path:
      return False
    if not self.budget():
      return False
    self.safety.throttle()
    resp = self._flow_request(
      session,
      flow.revert_method,
      self.target_url + flow.revert_path,
      flow.revert_body,
      timeout=10,
    )
    return resp.status_code < 400

  def _flow_revert_fn(self, session, flow):
    if not flow.revert_path:
      return None

    def revert(_baseline, _flow=flow):
      return self._flow_revert(session, _flow)

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
    title = "API endpoint lacks pagination cap"
    owasp = "API4:2023"
    session = self._session()
    if session is None:
      return
    for ep in self.target_config.api_security.resource_endpoints:
      if not (self.budget() and self.budget()):
        return
      url = self.target_url + ep.path
      self.safety.throttle()
      try:
        baseline = session.get(
          url, params={ep.limit_param: ep.baseline_limit}, timeout=10,
        )
      except requests.RequestException:
        continue
      self.safety.throttle()
      try:
        abuse = session.get(
          url, params={ep.limit_param: ep.abuse_limit}, timeout=10,
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
    title = "API endpoint accepts oversized payload"
    owasp = "API4:2023"
    session = self._session()
    if session is None:
      return
    big = "A" * 1_000_000  # 1 MB
    for ep in self.target_config.api_security.resource_endpoints:
      if not self.budget():
        return
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
          [f"endpoint={url}", "body_bytes=1000000",
           f"response_status={resp.status_code}"],
          remediation=(
            "Enforce a request-body size limit at the reverse-proxy or "
            "framework layer."
          ),
        )

  # ── PT-OAPI4-03 — no rate limit ────────────────────────────────────

  def _test_no_rate_limit(self):
    title = "API endpoint lacks rate limit"
    owasp = "API4:2023"
    session = self._session()
    if session is None:
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
    title = "API business flow lacks rate limit / abuse controls"
    owasp = "API6:2023"
    session = self._session()
    if session is None:
      return
    for flow in self.target_config.api_security.business_flows:
      url = self.target_url + flow.path

      def baseline(_flow=flow):
        return {"flow_name": _flow.flow_name}

      def mutate(_baseline, _flow=flow, _url=url):
        attempts = 0
        captcha = False
        mfa = False
        for _ in range(5):
          if not self.budget():
            break
          self.safety.throttle()
          try:
            resp = self._flow_request(
              session, _flow.method, _url, _flow.body_template, timeout=10,
            )
          except requests.RequestException:
            break
          attempts += 1
          if resp.status_code == 429:
            break
          body = (resp.text or "")[:2000].lower()
          if _flow.captcha_marker and _flow.captcha_marker.lower() in body:
            captcha = True
          if _flow.mfa_marker and _flow.mfa_marker.lower() in body:
            mfa = True
        _flow.__dict__.setdefault("_probe_state", {})
        _flow._probe_state["attempts"] = attempts
        _flow._probe_state["captcha"] = captcha
        _flow._probe_state["mfa"] = mfa
        return attempts >= 5 and not (captcha or mfa)

      def verify(baseline_, _flow=flow):
        state = getattr(_flow, "_probe_state", {}) or {}
        signals_confirmed = state.get("attempts", 0) >= 5 and not (
          state.get("captcha") or state.get("mfa")
        )
        if not signals_confirmed:
          return False
        try:
          return self._flow_verify(session, _flow)
        except requests.RequestException:
          return False

      self.run_stateful(
        "PT-OAPI6-01",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=self._flow_revert_fn(session, flow),
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
      )

  # ── PT-OAPI6-02 — flow no uniqueness check (STATEFUL) ──────────────

  def _test_flow_no_uniqueness(self):
    title = "API business flow lacks uniqueness check"
    owasp = "API6:2023"
    session = self._session()
    if session is None:
      return
    for flow in self.target_config.api_security.business_flows:
      url = self.target_url + flow.path

      def baseline(_flow=flow):
        return {"flow_name": _flow.flow_name}

      def mutate(_b, _flow=flow, _url=url):
        if not (self.budget() and self.budget()):
          return False
        try:
          self.safety.throttle()
          r1 = self._flow_request(
            session, _flow.method, _url, _flow.body_template, timeout=10,
          )
          self.safety.throttle()
          r2 = self._flow_request(
            session, _flow.method, _url, _flow.body_template, timeout=10,
          )
        except requests.RequestException:
          return False
        _flow.__dict__.setdefault("_probe_state2", {})
        _flow._probe_state2["both_2xx"] = (
          r1.status_code < 400 and r2.status_code < 400
        )
        return _flow._probe_state2["both_2xx"]

      def verify(_b, _flow=flow):
        if not (getattr(_flow, "_probe_state2", {}) or {}).get("both_2xx", False):
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
        revert_fn=self._flow_revert_fn(session, flow),
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
      )
