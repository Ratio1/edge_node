"""Vulnerable graybox findings carry their request/response snapshot (RM-060 Phase G).

Phase F stores a snapshot blob only for findings with `evidence_artifacts`, so a
probe that builds `GrayboxFinding(status="vulnerable")` without them leaves the
finding with no retrievable evidence.
"""

import ast
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.graybox import probes as _probes_pkg
from extensions.business.cybersec.red_mesh.tests.test_probes_misconfig import (
  _make_probe, _mock_response,
)

# (file, enclosing function) -> reason no HTTP response proves the finding.
_ALLOWED = {
  ("business_logic.py", "run_weak_auth"):
    "proof is a successful login session, not an HTTP response",
  ("misconfig.py", "_test_session_token"):
    "judged from the cookie jar and token shape; no response is retained",
  ("misconfig.py", "_test_cookie_attributes"):
    "judged from the cookie jar attributes; no response is retained",
  ("misconfig.py", "_test_account_enumeration_timing"):
    "statistical median over 12 requests; no single response proves it",
}


def _enclosing(tree):
  owner = {}
  for fn in ast.walk(tree):
    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
      for node in ast.walk(fn):
        owner[id(node)] = fn.name
  return owner


def _vulnerable_without_artifacts():
  out = []
  for path in sorted(Path(_probes_pkg.__file__).parent.glob("*.py")):
    tree = ast.parse(path.read_text())
    owner = _enclosing(tree)
    for node in ast.walk(tree):
      if not (isinstance(node, ast.Call)
              and getattr(node.func, "id", "") == "GrayboxFinding"):
        continue
      kw = {k.arg: k.value for k in node.keywords if k.arg}
      status = kw.get("status")
      # A non-literal status (a variable that may be "vulnerable") counts too.
      if isinstance(status, ast.Constant) and status.value != "vulnerable":
        continue
      if "evidence_artifacts" in kw:
        continue
      key = (path.name, owner.get(id(node), "<module>"))
      if key in _ALLOWED:
        continue
      out.append(f"{path.name}:{node.lineno} in {key[1]}")
  return out


class TestVulnerableFindingsCarryEvidence(unittest.TestCase):
  def test_direct_vulnerable_findings_pass_evidence_artifacts(self):
    self.assertEqual(_vulnerable_without_artifacts(), [])

  def test_converted_finding_snapshot_holds_the_triggering_response(self):
    probe = _make_probe(debug_paths=["/debug/config/"])
    probe.auth.anon_session.get.return_value = _mock_response(
      status=200, text="DEBUG_MODE=True " + "x" * 60)

    probe._test_debug_exposure()

    finding = next(f for f in probe.findings if f.status == "vulnerable")
    self.assertEqual(len(finding.evidence_artifacts), 1)
    self.assertIn("DEBUG_MODE=True", finding.evidence_artifacts[0].response_snapshot)
