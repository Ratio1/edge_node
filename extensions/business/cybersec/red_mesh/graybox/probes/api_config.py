"""API misconfiguration + inventory probes — OWASP API8 and API9.

Scaffold introduced in Subphase 1.3. Concrete probe methods land in
Phase 2.4 (API8 misconfig) and Phase 2.5 (API9 inventory).
"""

from .base import ProbeBase


class ApiConfigProbes(ProbeBase):
  """OWASP API8 (Security Misconfiguration) + API9 (Improper Inventory) probes.

  Scenarios:
    PT-OAPI8-01 — API permissive CORS configuration.
    PT-OAPI8-02 — API response missing security headers.
    PT-OAPI8-03 — API debug endpoint exposed.
    PT-OAPI8-04 — API verbose error response leaks internals.
    PT-OAPI8-05 — API advertises unexpected HTTP methods.
    PT-OAPI9-01 — API OpenAPI/Swagger specification publicly exposed.
    PT-OAPI9-02 — API legacy version still live (version sprawl).
    PT-OAPI9-03 — API deprecated path still serving requests.
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    """Run all configured API config/inventory scenarios.

    No-op until probe methods are implemented in Phase 2.4 / 2.5.
    """
    return self.findings
