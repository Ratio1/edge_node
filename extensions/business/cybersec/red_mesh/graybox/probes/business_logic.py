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
    """
    if not self.auth.regular_session:
      return

    endpoints = self.target_config.business_logic.workflow_endpoints
    if not endpoints:
      return

    for ep in endpoints:
      self.safety.throttle()
      url = self.target_url + ep.path
      method = ep.method.upper()

      try:
        if method == "POST":
          resp = self.auth.regular_session.post(url, data={}, timeout=10)
        else:
          resp = self.auth.regular_session.get(url, timeout=10)
      except Exception:
        continue

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
              f"Send {method} to {ep.path}.",
              f"Observe status {resp.status_code} instead of expected guard {expected}.",
            ],
            remediation="Enforce workflow state guards and role checks on all state-changing endpoints.",
          ))
