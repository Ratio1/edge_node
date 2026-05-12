"""API abuse probes — OWASP API4 (Resource Consumption) and API6 (Business Flows).

Scaffold introduced in Subphase 1.3. Concrete probe methods land in
Phase 3.2 (API4 bounded resource consumption) and Phase 3.3 (API6
stateful business-flow abuse).
"""

from .base import ProbeBase


class ApiAbuseProbes(ProbeBase):
  """OWASP API4 (Unrestricted Resource Consumption) + API6 (Sensitive Business
  Flows) graybox probes.

  Scenarios:
    PT-OAPI4-01 — API endpoint lacks pagination cap.
    PT-OAPI4-02 — API endpoint accepts oversized payload.
    PT-OAPI4-03 — API endpoint lacks rate limit
                  (requires `rate_limit_expected=True` per endpoint to fire).
    PT-OAPI6-01 — API business flow lacks rate limit / abuse controls (stateful).
    PT-OAPI6-02 — API business flow lacks uniqueness check (stateful).

  Bounded by construction — never stress-tests. Per-probe request budget
  consumed via `ProbeBase.budget` once `RequestBudget` lands in Subphase 1.7.
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    """Run all configured API4/API6 abuse scenarios.

    No-op until probe methods are implemented in Phase 3.2 / 3.3.
    """
    return self.findings
