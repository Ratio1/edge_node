"""OWASP API Top 10 — Subphase 1.8 commits #3 + #4.

End-to-end coverage of `ProbeBase.run_stateful` (the baseline → mutate
→ verify → revert contract) plus a lint test asserting that no probe
in the new API families bypasses `run_stateful` for direct mutating
HTTP calls.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase


class _StatefulProbe(ProbeBase):
  def run(self):
    return self.findings


def _make_probe(*, allow_stateful=False):
  return _StatefulProbe(
    target_url="http://x", auth_manager=MagicMock(),
    target_config=MagicMock(), safety=MagicMock(spec=["sanitize_error"]),
    allow_stateful=allow_stateful,
  )


class TestRunStatefulGating(unittest.TestCase):

  def test_skipped_when_stateful_disabled(self):
    p = _make_probe(allow_stateful=False)
    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: None,
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=lambda b: True,
      finding_kwargs={"title": "T", "owasp": "API3:2023"},
    )
    self.assertEqual(len(p.findings), 1)
    f = p.findings[0]
    self.assertEqual(f.status, "inconclusive")
    self.assertIn("stateful_probes_disabled", f.evidence[0])

  def test_skipped_when_no_revert_fn(self):
    p = _make_probe(allow_stateful=True)
    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: None,
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=None,
      finding_kwargs={"title": "T", "owasp": "API3:2023"},
    )
    self.assertEqual(p.findings[0].status, "inconclusive")
    self.assertIn("no_revert_path_configured", p.findings[0].evidence[0])


class TestRunStatefulHappyPath(unittest.TestCase):

  def test_vulnerable_with_successful_revert(self):
    p = _make_probe(allow_stateful=True)
    revert_called = [False]

    def revert(_b):
      revert_called[0] = True
      return True

    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: {"is_admin": False},
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=revert,
      finding_kwargs={"title": "Mass assignment", "owasp": "API3:2023",
                       "severity": "HIGH", "cwe": ["CWE-915"]},
    )
    self.assertTrue(revert_called[0])
    f = p.findings[0]
    self.assertEqual(f.status, "vulnerable")
    self.assertEqual(f.severity, "HIGH")
    self.assertEqual(f.rollback_status, "reverted")

  def test_not_vulnerable_when_verify_fails(self):
    p = _make_probe(allow_stateful=True)
    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: {"is_admin": False},
      mutate_fn=lambda b: True,
      verify_fn=lambda b: False,  # mutation didn't take
      revert_fn=lambda b: True,
      finding_kwargs={"title": "Mass assignment", "owasp": "API3:2023"},
    )
    f = p.findings[0]
    self.assertEqual(f.status, "not_vulnerable")
    self.assertEqual(f.rollback_status, "reverted")


class TestRunStatefulRevertFailureBumpsSeverity(unittest.TestCase):

  def test_revert_failure_escalates_high_to_critical(self):
    p = _make_probe(allow_stateful=True)
    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: None,
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=lambda b: False,  # revert refused / failed
      finding_kwargs={"title": "Mass assignment", "owasp": "API3:2023",
                       "severity": "HIGH"},
    )
    f = p.findings[0]
    self.assertEqual(f.status, "vulnerable")
    self.assertEqual(f.severity, "CRITICAL")
    self.assertEqual(f.rollback_status, "revert_failed")
    self.assertIn("Manual cleanup required", f.remediation)

  def test_revert_exception_treated_as_failure(self):
    p = _make_probe(allow_stateful=True)

    def revert(_b):
      raise RuntimeError("revert HTTP exploded")

    p.run_stateful(
      "PT-OAPI5-02-mut",
      baseline_fn=lambda: None,
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=revert,
      finding_kwargs={"title": "BFLA mut", "owasp": "API5:2023",
                       "severity": "MEDIUM"},
    )
    f = p.findings[0]
    self.assertEqual(f.severity, "HIGH")  # MEDIUM bumped
    self.assertEqual(f.rollback_status, "revert_failed")


class TestRunStatefulErrorPaths(unittest.TestCase):

  def test_baseline_failure_inconclusive(self):
    p = _make_probe(allow_stateful=True)
    p.safety.sanitize_error = MagicMock(side_effect=lambda s: s)

    def baseline():
      raise ConnectionError("target unreachable")

    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=baseline,
      mutate_fn=lambda b: True,
      verify_fn=lambda b: True,
      revert_fn=lambda b: True,
      finding_kwargs={"title": "T", "owasp": "API3:2023"},
    )
    f = p.findings[0]
    self.assertEqual(f.status, "inconclusive")
    self.assertIn("baseline_failed", f.evidence[0])

  def test_mutate_failure_inconclusive(self):
    p = _make_probe(allow_stateful=True)
    p.safety.sanitize_error = MagicMock(side_effect=lambda s: s)

    def mutate(_b):
      raise RuntimeError("write failed")

    p.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: None,
      mutate_fn=mutate,
      verify_fn=lambda b: True,
      revert_fn=lambda b: True,
      finding_kwargs={"title": "T", "owasp": "API3:2023"},
    )
    self.assertIn("mutate_failed", p.findings[0].evidence[0])


class TestStatefulContractLint(unittest.TestCase):
  """Lint guard: no PT-OAPI* family probe issues a mutating HTTP call
  outside of `run_stateful`. The check greps each api_* probe file for
  direct ``session.post/put/patch/delete`` calls and asserts they all
  appear inside a function whose source path contains ``run_stateful``.

  Skeleton probe files (Subphase 1.3) have no HTTP calls yet, so the
  check is currently vacuous; it becomes meaningful once Phase 3
  stateful probe methods land. Failing this lint then requires either
  routing the call through run_stateful or moving it into a non-mutating
  family file.
  """

  def test_mutating_calls_in_api_probe_families_use_run_stateful(self):
    """Every api_*.py file that issues mutating HTTP calls MUST also
    invoke `run_stateful` somewhere — those calls belong inside
    baseline/mutate/verify/revert callbacks per the Subphase 1.8 contract.

    This is a heuristic lint (not full AST analysis): it checks the
    same source file co-locates both patterns. False positives are
    possible if a file legitimately uses POST for non-mutating actions
    AND happens not to call run_stateful — when that case arises,
    revisit this lint.
    """
    pkg_dir = Path(__file__).resolve().parents[1] / "graybox" / "probes"
    api_files = sorted(pkg_dir.glob("api_*.py"))
    self.assertTrue(api_files, "no API probe files found — check pkg layout")

    # POST is overloaded (e.g., PT-OAPI8-04 POSTs malformed JSON to
    # trigger a verbose-error response — non-mutating). PATCH / PUT /
    # DELETE are unambiguously state-changing in REST conventions, so
    # the lint targets those only.
    mut_pat = re.compile(
      r"\bsession\.(put|patch|delete)\(",
      re.IGNORECASE,
    )
    offenders = []
    for f in api_files:
      src = f.read_text()
      if mut_pat.search(src) and "run_stateful" not in src:
        offenders.append(f.name)
    self.assertEqual(
      offenders, [],
      f"Files with mutating HTTP calls but no run_stateful: {offenders}",
    )

  def test_run_stateful_marker_present_on_probebase(self):
    """ProbeBase advertises the lint marker so probe authors can grep
    for it / future mypy plugins can key off it."""
    self.assertTrue(hasattr(ProbeBase, "STATEFUL_PROBE_LINT_MARKER"))


if __name__ == "__main__":
  unittest.main()
