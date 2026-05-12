"""API access-control probes — OWASP API1 (BOLA) and API5 (BFLA).

Scaffold introduced in Subphase 1.3 of the API Top 10 plan. Concrete
probe methods land in Phases 2.1 (PT-OAPI1-01), 2.3 (PT-OAPI5-01/02
read-only) and 3.4 (PT-OAPI5-03/04 stateful).
"""

from .base import ProbeBase


class ApiAccessProbes(ProbeBase):
  """OWASP API1 (BOLA) + API5 (BFLA) graybox probes.

  Scenarios:
    PT-OAPI1-01 — API object-level authorization bypass (BOLA, read).
    PT-OAPI5-01 — Function-level authorization bypass (regular as admin, read).
    PT-OAPI5-02 — Function-level authorization bypass (anonymous as user, read).
    PT-OAPI5-03 — Method-override authorization bypass (stateful).
    PT-OAPI5-04 — Function-level authorization bypass (regular as admin,
                  mutating; stateful, requires revert plan).

  Per-method stateful gating mirrors AccessControlProbes (the worker-level
  `is_stateful` flag stays False so the read-only scenarios always dispatch).
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    """Run all configured API access-control scenarios.

    No-op until the probe methods are implemented in Phases 2.1/2.3/3.4.
    The skeleton exists so the worker registry can dispatch the family
    today (Subphase 1.3 acceptance) without conditional registration.
    """
    return self.findings
