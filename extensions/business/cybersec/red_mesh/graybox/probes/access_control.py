"""
Access control probes — A01 IDOR + privilege escalation.
"""

import re

from .base import ProbeBase
from ..findings import GrayboxFinding


class AccessControlProbes(ProbeBase):
  """PT-A01-01 IDOR/BOLA, PT-A01-02 function-level authorization bypass."""

  requires_auth = True
  requires_regular_session = True
  is_stateful = False

  def run(self):
    if self.auth.regular_session:
      self.run_safe("idor", self._test_idor)
    if self.auth.regular_session:
      self.run_safe("privilege_escalation", self._test_privilege_esc)
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
