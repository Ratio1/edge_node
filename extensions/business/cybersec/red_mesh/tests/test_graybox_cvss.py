"""Every vulnerable graybox finding carries a CVSS vector that agrees with its label.

Graybox findings reached the report with no vector and no `severity_source`
(RM-087). Each scenario a probe can report as vulnerable now names the vector
of its weakness in `graybox/scenario_catalog.py`, and `to_flat_finding`
attaches it when its band is the label, as `enrich_finding_for_probe` does for
blackbox findings.

The first half reads `graybox/probes/**` statically, like
`test_cvss_coverage.py` reads `worker/**`:

- a vulnerable finding with a literal label gets the catalog vector of its
  scenario, or passes `cvss_vector=V.<NAME>`, and that vector's band is the label;
- a label chosen by a conditional passes a vector chosen by the same condition;
- a label computed any other way passes `cvss_vector=` explicitly (its branches
  are checked in review, and live).

The second half pins what `to_flat_finding` emits.
"""

import ast
import pathlib
import unittest

from extensions.business.cybersec.red_mesh import cvss_vectors as V
from extensions.business.cybersec.red_mesh.cvss import cvss31_base_score, severity_band
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.scenario_catalog import (
  GRAYBOX_SCENARIO_CATALOG,
  graybox_scenario,
)

_PROBES = pathlib.Path(__file__).resolve().parent.parent / "graybox" / "probes"

# (file, enclosing function): sites that forward a label they did not choose.
# `run_stateful` emits with the `severity` its caller put in `finding_kwargs`,
# and each caller is checked below as a stateful site.
_FORWARDING = {
  ("base.py", "run_stateful"),
}

_CONSTANT_VALUES = {getattr(V, n) for n in dir(V) if n.isupper()}


def _band(vector):
  return severity_band(cvss31_base_score(vector))


def _call_name(node):
  return getattr(node.func, "attr", getattr(node.func, "id", ""))


def _literal(node):
  return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _constant(node):
  """The vector a `V.<NAME>` node names, else None."""
  if isinstance(node, ast.Attribute) and getattr(node.value, "id", "") == "V":
    return getattr(V, node.attr, None)
  return None


def emission_sites():
  """Every place a probe reports a finding that may be vulnerable."""
  sites = []
  for path in sorted(_PROBES.glob("*.py")):
    tree = ast.parse(path.read_text())
    owner = {}
    for fn in ast.walk(tree):
      if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for node in ast.walk(fn):
          owner[node] = fn.name  # inner functions are walked later and win
    for node in ast.walk(tree):
      if not isinstance(node, ast.Call):
        continue
      name = _call_name(node)
      kw = {k.arg: k.value for k in node.keywords if k.arg}
      if name == "emit_vulnerable":
        scenario = node.args[0] if node.args else kw.get("scenario_id")
        severity = node.args[2] if len(node.args) > 2 else kw.get("severity")
      elif name == "GrayboxFinding":
        status = _literal(kw.get("status"))
        if status is not None and status != "vulnerable":
          continue
        scenario, severity = kw.get("scenario_id"), kw.get("severity")
      elif name == "run_stateful" and isinstance(kw.get("finding_kwargs"), ast.Dict):
        fields = kw["finding_kwargs"]
        fields = {_literal(k): v for k, v in zip(fields.keys, fields.values)}
        scenario = node.args[0] if node.args else kw.get("scenario_id")
        severity = fields.get("severity")
        kw = {"cvss_vector": fields["cvss_vector"]} if "cvss_vector" in fields else {}
      else:
        continue
      sites.append({
        "file": path.name, "line": node.lineno, "function": owner.get(node, ""),
        "scenario": _literal(scenario), "severity": severity,
        "vector": kw.get("cvss_vector"),
      })
  return sites


def _problem(site):
  """Why this site breaks the rule, or None."""
  severity, vector = site["severity"], site["vector"]
  label = _literal(severity)
  if label is not None:
    if vector is not None:
      chosen = _constant(vector)
      if chosen is None:
        return "cvss_vector is not a cvss_vectors constant"
    else:
      entry = graybox_scenario(site["scenario"] or "") or {}
      chosen = entry.get("cvss_vector")
      if not chosen:
        return f"scenario {site['scenario']} has no cvss_vector in the catalog"
    band = _band(chosen)
    return None if band == label else f"vector is {band}, label is {label}"
  if isinstance(severity, ast.IfExp) and _literal(severity.body) and _literal(severity.orelse):
    if not isinstance(vector, ast.IfExp) or ast.dump(vector.test) != ast.dump(severity.test):
      return "conditional label without a vector chosen by the same condition"
    for label_node, vector_node in ((severity.body, vector.body), (severity.orelse, vector.orelse)):
      chosen = _constant(vector_node)
      if chosen is None or _band(chosen) != _literal(label_node):
        return f"branch {_literal(label_node)} has no agreeing vector"
    return None
  if (site["file"], site["function"]) in _FORWARDING:
    return None
  return None if vector is not None else "computed label without an explicit cvss_vector"


class TestGrayboxCatalogVectors(unittest.TestCase):

  def test_every_catalog_vector_is_a_named_constant(self):
    for entry in GRAYBOX_SCENARIO_CATALOG:
      if "cvss_vector" in entry:
        with self.subTest(scenario=entry["id"]):
          self.assertIn(entry["cvss_vector"], _CONSTANT_VALUES)
          self.assertIsNotNone(_band(entry["cvss_vector"]))

  def test_every_scenario_reported_vulnerable_has_a_vector(self):
    reported = {s["scenario"] for s in emission_sites() if s["scenario"]}
    missing = sorted(sid for sid in reported
                     if not (graybox_scenario(sid) or {}).get("cvss_vector"))
    self.assertEqual(missing, [])


class TestGrayboxEmissionCvssCoverage(unittest.TestCase):

  def test_the_scan_sees_the_probe_tree(self):
    sites = emission_sites()
    self.assertGreater(len(sites), 50)
    self.assertTrue(any(isinstance(s["severity"], ast.IfExp) for s in sites))
    self.assertTrue(any(s["function"] == "run_stateful" for s in sites))

  def test_every_vulnerable_emission_has_an_agreeing_vector(self):
    offenders = [
      f"graybox/probes/{s['file']}:{s['line']} {s['function']}: {problem}"
      for s in emission_sites()
      if (problem := _problem(s))
    ]
    self.assertEqual(
      offenders, [],
      "a vulnerable graybox finding has no CVSS vector that agrees with its "
      "label. Name the weakness's vector on the scenario in scenario_catalog.py, "
      "pass cvss_vector=V.<NAME> where the label varies, or change the label if "
      "it is wrong (RM-087).",
    )

  def test_the_forwarding_list_only_shrinks(self):
    sites = {(s["file"], s["function"]) for s in emission_sites()}
    self.assertEqual(sorted(_FORWARDING - sites), [])


def _flat(**overrides):
  fields = dict(scenario_id="PT-A01-09", title="Admin endpoint reachable",
                status="vulnerable", severity="HIGH", owasp="A01:2021")
  fields.update(overrides)
  return GrayboxFinding(**fields).to_flat_finding(443, "https", "_graybox_access_control")


class TestGrayboxFlatFindingCvss(unittest.TestCase):

  def test_vulnerable_finding_gets_its_scenario_vector(self):
    flat = _flat()
    self.assertEqual(flat["cvss_vector"], V.AUTHZ_BYPASS_AUTHENTICATED)
    self.assertEqual(flat["cvss_score"], 8.1)
    self.assertEqual(flat["severity_source"], "cvss")

  def test_every_catalog_scenario_scores_at_its_band(self):
    for entry in GRAYBOX_SCENARIO_CATALOG:
      if "cvss_vector" not in entry:
        continue
      with self.subTest(scenario=entry["id"]):
        flat = _flat(scenario_id=entry["id"], severity=_band(entry["cvss_vector"]))
        self.assertEqual(flat["severity_source"], "cvss")
        self.assertEqual(flat["cvss_vector"], entry["cvss_vector"])

  def test_probe_vector_wins_over_the_catalog(self):
    flat = _flat(scenario_id="PT-A02-02", severity="LOW", cvss_vector=V.CORS_UNCREDENTIALED)
    self.assertEqual(flat["cvss_vector"], V.CORS_UNCREDENTIALED)
    self.assertEqual(flat["cvss_score"], 3.1)
    self.assertEqual(flat["severity_source"], "cvss")

  def test_disagreeing_vector_is_withheld_and_label_is_policy(self):
    # run_stateful raises a failed revert from HIGH to CRITICAL.
    flat = _flat(severity="CRITICAL", rollback_status="revert_failed")
    self.assertEqual(flat["cvss_vector"], "")
    self.assertIsNone(flat["cvss_score"])
    self.assertEqual(flat["severity_source"], "probe_policy")

  def test_scenario_without_a_vector_is_policy(self):
    flat = _flat(scenario_id="PT-A01-07")
    self.assertEqual(flat["cvss_vector"], "")
    self.assertEqual(flat["severity_source"], "probe_policy")

  def test_passed_and_inconclusive_checks_carry_no_vector(self):
    for status, severity in (("not_vulnerable", "INFO"), ("inconclusive", "INFO"),
                             ("inconclusive", "LOW")):
      with self.subTest(status=status, severity=severity):
        flat = _flat(status=status, severity=severity, cvss_vector=V.AUTHZ_BYPASS_AUTHENTICATED)
        self.assertEqual(flat["cvss_vector"], "")
        self.assertIsNone(flat["cvss_score"])
        self.assertNotIn("severity_source", flat)


if __name__ == "__main__":
  unittest.main()
