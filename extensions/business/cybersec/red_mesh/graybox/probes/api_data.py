"""API data-exposure probes — OWASP API3 (BOPLA).

Scaffold introduced in Subphase 1.3. Concrete probe methods land in
Phase 2.2 (PT-OAPI3-01 read-side excessive property exposure) and
Phase 3.1 (PT-OAPI3-02 write-side property tampering, stateful).
"""

from .base import ProbeBase


class ApiDataProbes(ProbeBase):
  """OWASP API3 (Broken Object Property Level Authorization) probes.

  Scenarios:
    PT-OAPI3-01 — API response leaks sensitive properties.
    PT-OAPI3-02 — API accepts mass assignment of privileged properties
                  (stateful; baseline GET → tampering PATCH → re-GET +
                  revert step under StatefulProbeMixin in Subphase 1.8).
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    """Run all configured API data-exposure scenarios.

    No-op until probe methods are implemented in Phase 2.2 / 3.1.
    """
    return self.findings
