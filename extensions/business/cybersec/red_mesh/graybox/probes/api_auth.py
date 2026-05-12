"""API authentication probes — OWASP API2 (Broken Authentication).

Scaffold introduced in Subphase 1.3. Concrete probe methods land in
Phase 2.6 (PT-OAPI2-01 missing-signature, PT-OAPI2-02 weak HMAC) and use
the stateful contract for PT-OAPI2-03 (logout-doesn't-invalidate; revert
is re-authentication).
"""

from .base import ProbeBase


class ApiAuthProbes(ProbeBase):
  """OWASP API2 (Broken Authentication) graybox probes.

  Scenarios:
    PT-OAPI2-01 — JWT missing-signature (alg=none) accepted.
    PT-OAPI2-02 — JWT signed with weak HMAC secret.
    PT-OAPI2-03 — Token not invalidated on logout (stateful, re-auth revert).

  All scenarios require `target_config.api_security.token_endpoints` —
  emit `inconclusive` when absent.
  """

  requires_auth = True
  requires_regular_session = False
  is_stateful = False

  def run(self):
    """Run all configured API auth scenarios.

    No-op until probe methods are implemented in Phase 2.6 / 3.x.
    """
    return self.findings
