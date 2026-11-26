"""Probe-emitted OWASP tag must equal the scenario catalog tag (RM-060 P3.3)."""

import ast
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.graybox import probes as _probes_pkg
from extensions.business.cybersec.red_mesh.graybox.scenario_catalog import (
  graybox_scenario,
)

# Positional index of `owasp` for the emit_* helpers (after `self`).
_EMIT_OWASP_POS = {"emit_vulnerable": 3, "emit_clean": 2, "emit_inconclusive": 2}


def _const(node):
  """Literal string, or the first literal inside a conditional expression."""
  if isinstance(node, ast.IfExp):
    return _const(node.body)
  return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _emitted_pairs():
  """Yield (file, line, scenario_id, owasp) for every literal emission."""
  for path in sorted(Path(_probes_pkg.__file__).parent.glob("*.py")):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
      if not isinstance(node, ast.Call):
        continue
      name = getattr(node.func, "attr", getattr(node.func, "id", ""))
      kw = {k.arg: k.value for k in node.keywords if k.arg}
      if name == "GrayboxFinding":
        sid, owasp = _const(kw.get("scenario_id")), _const(kw.get("owasp"))
      elif name in _EMIT_OWASP_POS:
        pos = _EMIT_OWASP_POS[name]
        sid = _const(node.args[0]) if node.args else _const(kw.get("scenario_id"))
        owasp = (_const(node.args[pos]) if len(node.args) > pos
                 else _const(kw.get("owasp")))
      else:
        continue
      if sid and owasp:
        yield path.name, node.lineno, sid, owasp


class TestProbeOwaspMatchesCatalog(unittest.TestCase):
  maxDiff = None

  def test_every_literal_emission_uses_catalog_tag(self):
    pairs = list(_emitted_pairs())
    self.assertGreater(len(pairs), 50)
    wrong = []
    for fname, line, sid, owasp in pairs:
      entry = graybox_scenario(sid)
      if entry is not None and entry["owasp"] != owasp:
        wrong.append(f"{fname}:{line} {sid} emits {owasp}, catalog {entry['owasp']}")
    self.assertEqual(wrong, [])
