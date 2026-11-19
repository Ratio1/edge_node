"""RM-169: a probe finding whose title names a CVE is a CVE finding.

The 2026-11-17 vulhub canary found probe-confirmed CVE-2012-2122 and CVE-2023-23752 findings with an empty `cve`:
the per-CVE dedup (title match) kept them over the version-matched row, so the CVE id, KEV and build left the
structured output. Every such `Finding(...)` must set `cve` and take KEV and build from `probe_cve_fields`.
"""
import ast
import re
import unittest
from pathlib import Path

WORKER = Path(__file__).resolve().parents[1] / "worker"
CVE = re.compile(r"CVE-\d{4}-\d+")


def _title_text(node):
  if isinstance(node, ast.Constant) and isinstance(node.value, str):
    return node.value
  if isinstance(node, ast.JoinedStr):
    return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
  return ""


class ProbeCveFieldTests(unittest.TestCase):
  def test_every_finding_naming_a_cve_sets_cve_and_probe_fields(self):
    missing = []
    for path in sorted(WORKER.rglob("*.py")):
      for node in ast.walk(ast.parse(path.read_text())):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding"):
          continue
        kw = {k.arg: k.value for k in node.keywords}
        named = CVE.findall(_title_text(kw.get("title")))
        if not named:
          continue
        where = "%s:%d" % (path.relative_to(WORKER), node.lineno)
        cve = kw.get("cve")
        listed = [e.value for e in getattr(cve, "elts", []) if isinstance(e, ast.Constant)]
        spread = [k.value for k in node.keywords if k.arg is None]
        lookup = [c.args[0].value for c in spread if isinstance(c, ast.Call)
                  and getattr(c.func, "id", None) == "probe_cve_fields" and c.args and isinstance(c.args[0], ast.Constant)]
        if listed != named[:1] or lookup != named[:1]:
          missing.append((where, named[0], listed, lookup))
    self.assertEqual(missing, [])


if __name__ == "__main__":
  unittest.main()
