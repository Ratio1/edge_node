"""RM-162: the word-start evidence matcher against the substring matcher it replaced.

Every probe `Finding(...)` / `GrayboxFinding(...)` in the RedMesh package is read from source (string
literals only; an f-string keeps its literal parts) and run through the old matcher, copied below as
the reference, and the new one. The matches that changed are pinned: a change to either keyword set
or to the matcher shows up here and has to be accepted by name.
"""
import ast
import re
import unittest
from collections import Counter
from pathlib import Path

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.services import evidence_engine as engine

PACKAGE = Path(__file__).resolve().parent.parent
POSITIONAL = {
  "Finding": ("severity", "title", "description", "evidence", "remediation", "owasp_id", "cwe_id"),
  "GrayboxFinding": ("scenario_id", "title", "status", "severity", "owasp", "cwe"),
}

# Accepted changes: (signal, title, old match, new match) -> number of findings.
ACCEPTED_CHANGES = {
  # `login` inside `prelogin`: a TDS version disclosure, not an access finding.
  ("auth_access_findings", "MSSQL prelogin handshake succeeded", True, False): 1,
  # `ssl` inside `classloader`: Spring4Shell binding indicators are not transport findings.
  ("crypto_transport_findings", "Spring4Shell (CVE-2022-22965) parameter binding indicator", True, False): 3,
  # The same `classloader`, in the CVE catalog's run-time title (two catalog rows).
  ("crypto_transport_findings", "CVE-2022-22965: Spring4Shell: ClassLoader manipulation RCE (spring_framework 1.0)", True, False): 2,
}


def _old_matches(text, keywords):
  return any(keyword in text for keyword in keywords)


def _literal(node):
  if isinstance(node, ast.Constant):
    return node.value if isinstance(node.value, str) else ""
  if isinstance(node, ast.JoinedStr):
    return "".join(part.value for part in node.values if isinstance(part, ast.Constant))
  if isinstance(node, (ast.List, ast.Tuple)):
    return " ".join(_literal(item) for item in node.elts)
  if isinstance(node, ast.BinOp):
    return _literal(node.left) + _literal(node.right)
  return ""


def _enclosing_functions(tree):
  """Map each Call node to the name of the function it sits in: the probe id the finding is emitted under."""
  owner = {}
  for func in ast.walk(tree):
    if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
      for node in ast.walk(func):
        owner[node] = func.name  # inner functions are visited after outer ones and overwrite
  return owner


def _registered_probes():
  """Probe id -> category from the probe registry, once the probe modules are imported."""
  from extensions.business.cybersec.red_mesh.worker import probe_registry
  return {probe_id: meta.category for probe_id, meta in probe_registry.list_registered_probes().items()}


def _build_corpus():
  categories = _registered_probes()
  found = []
  for path in sorted(PACKAGE.rglob("*.py")):
    if "tests" in path.relative_to(PACKAGE).parts:
      continue
    tree = ast.parse(path.read_text())
    owner = _enclosing_functions(tree)
    for node in ast.walk(tree):
      if not isinstance(node, ast.Call):
        continue
      func = node.func
      name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
      if name not in POSITIONAL:
        continue
      fields = dict(zip(POSITIONAL[name], node.args))
      fields.update({kw.arg: kw.value for kw in node.keywords if kw.arg})
      text = lambda *keys: " ".join(_literal(fields[key]) for key in keys if key in fields)
      title = text("title")
      probe = owner.get(node, "")
      parts = [title, text("description"), probe, categories.get(probe, ""), text("cwe_id", "cwe"), text("owasp_id", "owasp")]
      found.append((title.strip(), " ".join(part.lower() for part in parts if part)))
  # The CVE catalog builds its findings at run time (`cve_db._build_finding`): title and description
  # carry the product name, so every catalog entry is a finding here too.
  for entry in cve_db.CVE_DATABASE:
    title = f"{entry.cve_id}: {entry.title} ({entry.product} 1.0)"
    description = f"{entry.product} 1.0 is vulnerable to {entry.cve_id}."
    found.append((title, " ".join(part.lower() for part in (title, description, entry.cwe_id) if part)))
  return found


_CORPUS = None


def _corpus():
  global _CORPUS
  if _CORPUS is None:
    _CORPUS = _build_corpus()
  return _CORPUS


class TestEvidenceMatcherCorpus(unittest.TestCase):
  def test_the_corpus_is_read_from_the_probes(self):
    self.assertGreater(len(_corpus()), 300)

  def test_the_changed_matches_are_exactly_the_accepted_ones(self):
    changed = Counter()
    for title, text in _corpus():
      for signal, keywords in (("auth_access_findings", engine._ACCESS_KEYWORDS),
                               ("crypto_transport_findings", engine._CRYPTO_KEYWORDS)):
        old, new = _old_matches(text, keywords), engine._matches_keywords({"title": text}, keywords)
        if old != new:
          changed[(signal, title, old, new)] += 1
    self.assertEqual(dict(changed), ACCEPTED_CHANGES)

  def test_a_new_match_never_appears_where_the_old_matcher_found_none(self):
    # A word-start match is a substring match: the new matcher can only lose matches.
    for _title, text in _corpus():
      for keywords in (engine._ACCESS_KEYWORDS, engine._CRYPTO_KEYWORDS):
        if engine._matches_keywords({"title": text}, keywords):
          self.assertTrue(_old_matches(text, keywords), text)

  def test_the_soc_statuses_the_writers_produce_are_in_the_exact_set(self):
    writers = {"services/log_export.py": r"""["']status["']\s*[:=]\s*["']sent["']""",
               "services/suricata_correlation.py": r"""status\s*[:=]\s*["']completed["']"""}
    for relative, pattern in writers.items():
      self.assertIsNotNone(re.search(pattern, (PACKAGE / relative).read_text()), relative)
    self.assertLessEqual({"sent", "completed"}, engine._SOC_COMPLETED_STATUSES)
    self.assertIsNone(re.search(r"\s", "".join(engine._SOC_COMPLETED_STATUSES)))

  def test_the_corpus_reaches_probe_names_and_registered_categories(self):
    self.assertTrue(any("_service_info_" in text for _title, text in _corpus()))
    self.assertTrue(_registered_probes(), "probe registry is empty: categories are not in the corpus")

  def test_an_empty_keyword_set_matches_nothing(self):
    self.assertFalse(engine._matches_keywords({"title": "authentication ssl"}, set()))
    self.assertFalse(engine._matches_keywords({"title": "authentication ssl"}, frozenset()))

  def test_probe_names_match_across_underscores(self):
    self.assertTrue(engine._matches_keywords({"probe": "_service_info_ssl_check"}, engine._CRYPTO_KEYWORDS))
    self.assertTrue(engine._matches_keywords({"probe": "_web_test_auth_bypass"}, engine._ACCESS_KEYWORDS))
    self.assertFalse(engine._matches_keywords({"probe": "_web_test_classloader"}, engine._CRYPTO_KEYWORDS))

  def test_openssl_in_a_runtime_cve_title_stays_a_transport_finding(self):
    finding = {"title": "CVE-2022-0778: Infinite loop in BN_mod_sqrt (openssl 1.0)"}
    self.assertTrue(engine._matches_keywords(finding, engine._CRYPTO_KEYWORDS))


if __name__ == "__main__":
  unittest.main()
