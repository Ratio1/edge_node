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
