"""API data-exposure probes — OWASP API3 (BOPLA)."""

import re

import requests

from .base import ProbeBase


# Built-in sensitive property-name regexes for PT-OAPI3-01. Operators
# can extend via `target_config.api_security.sensitive_field_patterns`.
_DEFAULT_SENSITIVE_PATTERNS = (
  re.compile(r"(?i)\bpassword"),
  re.compile(r"(?i)_hash\b"),
  re.compile(r"(?i)\btoken\b"),
  re.compile(r"(?i)\bsecret\b"),
  re.compile(r"(?i)\bapi[_-]?key\b"),
  re.compile(r"(?i)\bprivate[_-]?key\b"),
  re.compile(r"(?i)\bmfa[_-]?secret\b"),
  re.compile(r"(?i)\brecovery[_-]?code"),
  re.compile(r"(?i)_ssn\b"),
  re.compile(r"(?i)_cc[_-]?number\b"),
  re.compile(r"(?i)\bis[_-]?admin\b"),
  re.compile(r"(?i)\bis[_-]?superuser\b"),
)


class ApiDataProbes(ProbeBase):
  """OWASP API3 (Broken Object Property Level Authorization) probes.

  Scenarios:
    PT-OAPI3-01 — API response leaks sensitive properties (Subphase 2.2).
    PT-OAPI3-02 — API accepts mass assignment of privileged properties
                  (stateful; Subphase 3.1; uses ProbeBase.run_stateful).
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return self.findings

    if getattr(api_security, "property_endpoints", None):
      self.run_safe("api_property_exposure", self._test_api_property_exposure)
      self.run_safe("api_property_tampering", self._test_api_property_tampering)

    return self.findings

  # ── PT-OAPI3-01 — Excessive property exposure ─────────────────────

  def _test_api_property_exposure(self):
    api_security = self.target_config.api_security
    endpoints = api_security.property_endpoints
    session = self.auth.regular_session or self.auth.official_session
    if session is None:
      self.emit_inconclusive(
        "PT-OAPI3-01", "API response leaks sensitive properties",
        "API3:2023", "no_authenticated_session",
      )
      return

    patterns = list(_DEFAULT_SENSITIVE_PATTERNS)
    for raw in getattr(api_security, "sensitive_field_patterns", []) or []:
      try:
        patterns.append(re.compile(raw, re.IGNORECASE))
      except re.error:
        continue

    found_any = False
    for ep in endpoints:
      if not self.budget():
        self.emit_inconclusive(
          "PT-OAPI3-01", "API response leaks sensitive properties",
          "API3:2023", "budget_exhausted",
        )
        return
      url = self._render_url(ep.path, ep.id_param, ep.test_id)
      self.safety.throttle()
      try:
        resp = session.get(url, timeout=10, allow_redirects=False)
      except requests.RequestException:
        continue

      if resp.status_code >= 400:
        continue
      ct = (resp.headers.get("content-type") or "").lower()
      if "application/json" not in ct:
        continue
      try:
        data = resp.json()
      except (ValueError, requests.exceptions.JSONDecodeError):
        continue
      if not isinstance(data, dict):
        continue

      leaks = self._find_sensitive_keys(data, patterns)
      if leaks:
        self.emit_vulnerable(
          "PT-OAPI3-01", "API response leaks sensitive properties",
          "HIGH", "API3:2023", ["CWE-213", "CWE-915"],
          [f"endpoint={url}", "response_status=200",
           "sensitive_fields_present=" + ",".join(sorted(leaks))],
          replay_steps=[
            "Authenticate as the regular user.",
            f"GET {url}",
            "Observe response carries sensitive property names: "
            + ",".join(sorted(leaks)),
          ],
          remediation=(
            "Strip sensitive properties (password hashes, MFA secrets, "
            "API keys, role flags) from response serialisers. Use an "
            "explicit allowlist of fields per role rather than excluding "
            "individual sensitive ones."
          ),
        )
      else:
        self.emit_clean(
          "PT-OAPI3-01", "API response leaks sensitive properties",
          "API3:2023",
          [f"endpoint={url}", "response_status=200",
           "no_sensitive_fields_present"],
        )
      found_any = True

    if not found_any:
      self.emit_inconclusive(
        "PT-OAPI3-01", "API response leaks sensitive properties",
        "API3:2023", "no_evaluable_responses",
      )

  # ── PT-OAPI3-02 — Mass-assignment write (Subphase 3.1, STATEFUL) ──

  def _test_api_property_tampering(self):
    api_security = self.target_config.api_security
    title = "API accepts mass assignment of privileged properties"
    owasp = "API3:2023"

    session = self.auth.regular_session or self.auth.official_session
    if session is None:
      self.emit_inconclusive(
        "PT-OAPI3-02", title, owasp, "no_authenticated_session",
      )
      return

    tampering_fields = list(
      getattr(api_security, "tampering_fields", []) or []
    )
    if not tampering_fields:
      self.emit_inconclusive(
        "PT-OAPI3-02", title, owasp, "no_tampering_fields_configured",
      )
      return

    for ep in api_security.property_endpoints:
      target_field = tampering_fields[0]  # one field per endpoint
      read_url = self._render_url(ep.path, ep.id_param, ep.test_id)
      method = (ep.method_write or "PATCH").upper()

      def baseline(_ep=ep, _url=read_url):
        if not self.budget():
          raise RuntimeError("budget_exhausted")
        self.safety.throttle()
        resp = session.get(_url, timeout=10, allow_redirects=False)
        try:
          return resp.json() if resp.status_code < 400 else None
        except (ValueError, requests.exceptions.JSONDecodeError):
          return None

      def mutate(base, _ep=ep, _url=read_url, _method=method,
                  _field=target_field):
        if base is None:
          return False
        if not self.budget():
          return False
        self.safety.throttle()
        payload = {_field: True}
        try:
          if _method == "PATCH":
            resp = session.patch(_url, json=payload, timeout=10)
          elif _method == "PUT":
            resp = session.put(_url, json=payload, timeout=10)
          else:
            resp = session.post(_url, json=payload, timeout=10)
        except requests.RequestException:
          return False
        return resp.status_code < 400

      def verify(base, _ep=ep, _url=read_url, _field=target_field):
        if not self.budget():
          return False
        self.safety.throttle()
        try:
          resp = session.get(_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
          return False
        if resp.status_code >= 400:
          return False
        try:
          data = resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
          return False
        if not isinstance(data, dict):
          return False
        before = (base or {}).get(_field)
        after = data.get(_field)
        return after is True and after != before

      def revert(base, _ep=ep, _url=read_url, _method=method,
                  _field=target_field):
        if base is None:
          return False
        if not self.budget():
          return False
        before = base.get(_field, False)
        try:
          if _method == "PATCH":
            resp = session.patch(_url, json={_field: before}, timeout=10)
          elif _method == "PUT":
            resp = session.put(_url, json={_field: before}, timeout=10)
          else:
            resp = session.post(_url, json={_field: before}, timeout=10)
        except requests.RequestException:
          return False
        return resp.status_code < 400

      self.run_stateful(
        "PT-OAPI3-02",
        baseline_fn=baseline,
        mutate_fn=mutate,
        verify_fn=verify,
        revert_fn=revert,
        finding_kwargs={
          "title": title, "owasp": owasp, "severity": "HIGH",
          "cwe": ["CWE-915"],
          "evidence": [f"endpoint={read_url}", f"tampered_field={target_field}"],
          "replay_steps": [
            "Authenticate as a non-privileged user.",
            f"{method} {read_url}",
            f'Body includes `{{"{target_field}": true}}` along with the '
            "field the operator is allowed to change.",
            f"GET {read_url} and confirm `{target_field}` flipped to True.",
          ],
          "remediation": (
            "Use an explicit allowlist of writable fields per role. Never "
            "pass user input through to ORM .update(**request.data); "
            "deserialise into a typed schema first and reject unknown fields."
          ),
        },
      )

  # ── helpers ────────────────────────────────────────────────────────

  @staticmethod
  def _render_url(path, id_param, test_id):
    if "{" + id_param + "}" in path:
      path = path.replace("{" + id_param + "}", str(test_id))
    elif "{id}" in path:
      path = path.replace("{id}", str(test_id))
    return path

  @staticmethod
  def _find_sensitive_keys(payload, patterns):
    found = set()
    if not isinstance(payload, dict):
      return found
    for key in payload.keys():
      if not isinstance(key, str):
        continue
      for pat in patterns:
        if pat.search(key):
          found.add(key)
          break
    return found
