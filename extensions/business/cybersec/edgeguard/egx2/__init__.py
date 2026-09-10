"""EGX/2 explanation profile: deterministic insight layer + typed analyst brief.

Modules ported from the A/B-validated EGM-047/EGM-049 harness
(`project-red-mesh:workbooks/egm-047-notation-bakeoff/harness/`); the runtime
binding lives in `insight_brief.py`. Decision authority:
`docs/resources/edgeguard-models/evals/egm-049-analyst-brief-ab-decision.md`;
spec: `docs/resources/edgeguard-models/specs/edgeguard-explain-v2-egx2.md`.
"""

from .field_catalog import CATALOG_SHA256
from .insight_brief import (
  CASE_EXPLANATION_VERSION,
  MAX_TOKENS,
  PROFILE_ID,
  PROFILE_SHA256,
  STRATEGY,
  TRACE_VERSION,
  run_insight_brief,
)

__all__ = [
  "CASE_EXPLANATION_VERSION",
  "CATALOG_SHA256",
  "MAX_TOKENS",
  "PROFILE_ID",
  "PROFILE_SHA256",
  "STRATEGY",
  "TRACE_VERSION",
  "run_insight_brief",
]
