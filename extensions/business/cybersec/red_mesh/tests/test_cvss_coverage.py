"""Every non-INFO probe finding carries a CVSS vector that agrees with its label.

RM-064 withheld a probe's `cvss_template` wherever its band contradicted the
finding's severity, and RM-086 labelled what was left "probe policy". A probe
template is one vector for everything the probe reports, so most findings
ended up with no vector at all (RM-087). The fix is per finding: a `Finding(`
that the template does not cover passes a constant from `cvss_vectors.py`.

This test reads `worker/**` statically and holds that line:

- a static non-INFO `Finding(` either passes `cvss_vector=V.<NAME>` whose band
  equals its label, or sits directly in a registered probe whose template's
  band equals its label (a helper cannot rely on the template: which probe
  calls it is only known at run time, from the stack);
- a `Finding(` whose severity is computed must pass `cvss_vector=` explicitly
  (its branches are checked in review, and live);
- the few findings that are not weaknesses of the target (honeypot and ICS
  scan-safety signals) are listed below, and the list may only shrink.
"""

import ast
import pathlib
import unittest

from extensions.business.cybersec.red_mesh import cvss_vectors as V
from extensions.business.cybersec.red_mesh.cvss import cvss31_base_score, severity_band

_PKG = pathlib.Path(__file__).resolve().parent.parent
_WORKER = _PKG / "worker"

# Band of every constant, stated here rather than recomputed: a vector edited
# into another band must fail loudly, not quietly relabel what uses it.
_CONSTANT_BANDS = {
  "UNAUTHENTICATED_FULL_CONTROL": "CRITICAL",
  "UNAUTHENTICATED_READ_WRITE": "CRITICAL",
  "SSRF_TO_INTERNAL": "CRITICAL",
  "SENSITIVE_DATA_EXPOSED": "HIGH",
  "UNAUTHENTICATED_WRITE": "HIGH",
  "ADMIN_INTERFACE_EXPOSED": "HIGH",
  "INJECTION_DATA_ACCESS": "HIGH",
  "XSS_REFLECTED": "HIGH",
  "RCE_UNCONFIRMED": "HIGH",
  "WEAK_CRYPTO_BREAKABLE": "HIGH",
  "CORS_CREDENTIALED": "HIGH",
  "MIXED_CONTENT_ACTIVE": "HIGH",
  "AUTHZ_BYPASS_AUTHENTICATED": "HIGH",
  "OBJECT_DELETE_AUTHENTICATED": "HIGH",
  "OBJECT_TAMPER_AUTHENTICATED": "HIGH",
  "INJECTION_DATA_ACCESS_AUTHENTICATED": "HIGH",
  "RCE_AUTHENTICATED": "HIGH",
  "RCE_UNCONFIRMED_AUTHENTICATED": "HIGH",
  "SSRF_AUTHENTICATED": "HIGH",
  "CSRF": "HIGH",
  "AUTH_DEFEATABLE": "HIGH",
  "INFO_DISCLOSURE_MEDIUM": "MEDIUM",
  "WEAK_TRANSPORT": "MEDIUM",
  "CERT_UNTRUSTED": "MEDIUM",
  "BRUTE_FORCE_UNTHROTTLED": "MEDIUM",
  "NTLM_RELAY": "MEDIUM",
  "OPEN_RESOLVER": "MEDIUM",
  "OPEN_REDIRECT": "MEDIUM",
  "UNSUPPORTED_SOFTWARE": "MEDIUM",
  "SRI_SCRIPT_MISSING": "MEDIUM",
  "DATA_EXPOSED_AUTHENTICATED": "MEDIUM",
  "BUSINESS_LOGIC_BYPASS": "MEDIUM",
  "BUSINESS_FLOW_ABUSE": "MEDIUM",
  "INPUT_VALIDATION_BYPASS": "MEDIUM",
  "XSS_AUTHENTICATED": "MEDIUM",
  "XSS_UNAUTHENTICATED": "MEDIUM",
  "SESSION_FIXATION": "MEDIUM",
  "SESSION_NOT_REVOKED": "MEDIUM",
  "RESOURCE_UNBOUNDED": "MEDIUM",
  "INFO_DISCLOSURE_LOW": "LOW",
  "WEAK_CRYPTO_MARGINAL": "LOW",
  "CERT_HYGIENE": "LOW",
  "MISSING_HEADER_LOW": "LOW",
  "SRI_STYLESHEET_MISSING": "LOW",
  "DATA_DURABILITY": "LOW",
  "SSLV3_POODLE": "LOW",
  "CORS_UNCREDENTIALED": "LOW",
  "RATE_LIMIT_MISSING": "LOW",
}

# (file under worker/, enclosing function, title prefix). Signals about the
# scan or the target's nature, not weaknesses a CVSS vector could score; they
# keep their label and read as probe policy.
_NOT_A_WEAKNESS = {
  ("correlation.py", "_correlate_port_ratio", "Honeypot indicator"),
  ("correlation.py", "_correlate_os_consistency", "Honeypot indicator"),
  ("correlation.py", "_correlate_timezone_drift", "Timezone inconsistency"),
  ("pentest_worker.py", "_active_fingerprint_ports", "ICS device detected"),
  ("pentest_worker.py", "_gather_service_info", "ICS device detected"),
  ("service/database.py", "_redis_check_auth", "Redis unusual PING response"),
}


def _call_name(node):
  return getattr(node.func, "id", getattr(node.func, "attr", ""))


def _template(fn):
  """The `cvss_template` of a registered probe, "" when it has none, None when
  `fn` is not a registered probe."""
  for dec in fn.decorator_list:
    if isinstance(dec, ast.Call) and _call_name(dec) == "register_probe":
      for kw in dec.keywords:
        if kw.arg == "cvss_template" and isinstance(kw.value, ast.Constant):
          return kw.value.value
      return ""
  return None


def _severity(call):
  """"CRITICAL".."INFO" for a literal `Severity.X`, None when computed."""
  node = next((kw.value for kw in call.keywords if kw.arg == "severity"), None)
  if node is None and call.args:
    node = call.args[0]
  if isinstance(node, ast.Attribute) and getattr(node.value, "id", "") == "Severity":
    return node.attr
  return None


def _title(call):
  node = next((kw.value for kw in call.keywords if kw.arg == "title"), None)
  if node is None and len(call.args) > 1:
    node = call.args[1]
  if isinstance(node, ast.Constant):
    return str(node.value)
  if isinstance(node, ast.JoinedStr):
    return "".join(p.value if isinstance(p, ast.Constant) else "{}" for p in node.values)
  return ""


def finding_sites():
  """One dict per `Finding(` call under worker/."""
  sites = []
  for path in sorted(_WORKER.rglob("*.py")):
    rel = str(path.relative_to(_WORKER))
    tree = ast.parse(path.read_text())
    for fn in ast.walk(tree):
      if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue
      template = _template(fn)
      for call in ast.walk(fn):
        if not (isinstance(call, ast.Call) and _call_name(call) == "Finding"):
          continue
        vector = next((kw.value for kw in call.keywords if kw.arg == "cvss_vector"), None)
        sites.append({
          "file": rel, "line": call.lineno, "function": fn.name,
          "severity": _severity(call), "title": _title(call),
          "template": template, "vector": vector,
        })
  # A nested def is walked from both functions; keep the innermost owner.
  unique = {}
  for site in sites:
    unique[(site["file"], site["line"])] = site
  return list(unique.values())


def _allowlisted(site):
  return any(site["file"] == f and site["function"] == fn and site["title"].startswith(prefix)
             for f, fn, prefix in _NOT_A_WEAKNESS)


def _problem(site):
  """Why this site breaks the rule, or None."""
  severity, vector = site["severity"], site["vector"]
  if severity == "INFO":
    return None
  if severity is None:
    return None if vector is not None else "computed severity without an explicit cvss_vector"
  if vector is not None:
    if not (isinstance(vector, ast.Attribute) and getattr(vector.value, "id", "") == "V"):
      return "cvss_vector is not a cvss_vectors constant"
    band = severity_band(cvss31_base_score(getattr(V, vector.attr, "")))
    return None if band == severity else f"V.{vector.attr} is {band}, label is {severity}"
  if site["template"] is None:
    return "helper function: pass cvss_vector explicitly"
  band = severity_band(cvss31_base_score(site["template"])) if site["template"] else None
  return None if band == severity else f"probe template is {band}, label is {severity}"


class TestCvssVectorConstants(unittest.TestCase):

  def test_every_constant_is_listed_with_its_band(self):
    names = {n for n in dir(V) if n.isupper()}
    self.assertEqual(names, set(_CONSTANT_BANDS))

  def test_every_constant_scores_in_its_stated_band(self):
    for name, band in _CONSTANT_BANDS.items():
      with self.subTest(name=name):
        vector = getattr(V, name)
        self.assertTrue(vector.startswith("CVSS:3.1/"))
        self.assertEqual(severity_band(cvss31_base_score(vector)), band)


class TestProbeFindingCvssCoverage(unittest.TestCase):

  def test_the_scan_sees_the_worker_tree(self):
    sites = finding_sites()
    self.assertGreater(len(sites), 200)
    self.assertTrue(any(s["vector"] is not None for s in sites))

  def test_every_non_info_finding_has_an_agreeing_vector(self):
    offenders = []
    for site in finding_sites():
      problem = _problem(site)
      if problem and not _allowlisted(site):
        offenders.append(f"worker/{site['file']}:{site['line']} {site['function']}: {problem}")
    self.assertEqual(
      offenders, [],
      "a non-INFO finding has no CVSS vector that agrees with its label. Pass "
      "cvss_vector=V.<NAME> from cvss_vectors.py for the weakness this finding "
      "reports, or change the label if it is wrong (RM-087).",
    )

  def test_the_not_a_weakness_list_only_shrinks(self):
    """Each entry must still match a site the rule would otherwise flag."""
    sites = finding_sites()
    stale = []
    for entry in _NOT_A_WEAKNESS:
      f, fn, prefix = entry
      matching = [s for s in sites
                  if s["file"] == f and s["function"] == fn and s["title"].startswith(prefix)]
      if not matching or not any(_problem(s) for s in matching):
        stale.append(entry)
    self.assertEqual(stale, [], "entries that no longer exempt anything")


class TestExplicitVectorThroughEnrichment(unittest.TestCase):
  """A call-site vector is what the report shows: scored, and the label marked
  as CVSS-backed. The seam already did this for any supplied vector
  (`findings.py`); pinned here for the constants the probes now pass."""

  def test_a_low_finding_with_its_constant_is_cvss_sourced(self):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, enrich_finding_for_probe,
    )
    f = enrich_finding_for_probe(
      Finding(severity=Severity.LOW, title="MySQL version disclosed: 8.0.1",
              description="MySQL greeting packet carries its version.",
              cvss_vector=V.INFO_DISCLOSURE_LOW),
      "_service_info_mysql",
    )
    self.assertEqual(f.cvss_vector, V.INFO_DISCLOSURE_LOW)
    self.assertEqual(f.cvss_score, 3.7)
    self.assertEqual(f.severity_source, "cvss")


if __name__ == "__main__":
  unittest.main()
