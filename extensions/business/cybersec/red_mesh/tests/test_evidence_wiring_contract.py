"""Lint gate: a probe that has the triggering response must hand it over.

`GrayboxEvidenceArtifact` was dead schema for its whole life — zero
constructions outside tests — because `emit_vulnerable` accepted evidence
nobody passed. Making the parameter exist does not make the evidence exist,
so this test asserts the wiring rather than the capability.

Modelled on test_stateful_contract.py: the failure mode is a *new* probe
shipping without the wiring, which no behavioural test would catch because
an absent artifact looks exactly like a probe that legitimately has no
response to attach.

Two things the first version of this gate got wrong, both of the same kind — a
gate reporting zero because it cannot see, not because there is nothing there:

  1. It scanned only `self.emit_vulnerable(` sites. Four probe modules build
     `GrayboxFinding(...)` inline and append it, so 38 `status="vulnerable"`
     findings sat outside its field of view entirely. It reported the wiring
     complete while covering roughly a quarter of the vulnerable findings the
     scanner produces.
  2. Its self-test planted an offender matching the detector's narrowest
     assumptions — four-space indent, `session.get` — so three separate ways of
     blinding the detector all left the suite green.

The self-test is now a set of mutations rather than one happy-path plant, and
the inline constructions are counted and pinned rather than invisible.
"""

import re
import unittest
from pathlib import Path

_PROBES = Path(__file__).resolve().parent.parent / "graybox" / "probes"

# Every verb the probes actually use, not the handful the first draft assumed.
# Adding `options` is what surfaced a real unwired site in api_config.py that
# had been invisible since this gate was written.
_RESPONSE_ASSIGNMENT = re.compile(
  r"^\s*([a-z_][a-z0-9_]*)\s*=\s*"
  r"(?:session\.(?:get|post|put|delete|patch|head|options|request)"
  r"|self\.(?:request|stateful_request))\("
)
# Any indentation. The first version required exactly four spaces, which is not
# what a method body inside a class uses here.
_EMIT = re.compile(r"^(\s*)self\.emit_vulnerable\($")
_DIRECT = re.compile(r"^\s*(?:self\.findings\.append\()?GrayboxFinding\($")
_DEF = re.compile(r"^\s*def\s+([a-z_][a-z0-9_]*)")


def _probe_sources():
  """(name, lines) for each probe module, excluding the base class."""
  for path in sorted(_PROBES.glob("*.py")):
    if path.name in ("base.py", "__init__.py"):
      continue
    yield path.name, path.read_text().split("\n")


def _block_end(lines, start):
  depth, end = 0, start
  while end < len(lines):
    depth += lines[end].count("(") - lines[end].count(")")
    if depth == 0 and end > start:
      break
    end += 1
  return end


def _unwired_call_sites(sources=None):
  """Return (file, line, variable) for each emit that drops evidence."""
  offenders = []
  for name, lines in (sources if sources is not None else _probe_sources()):
    index, in_scope = 0, {}
    while index < len(lines):
      line = lines[index]
      if _DEF.match(line):
        in_scope = {}
      assignment = _RESPONSE_ASSIGNMENT.match(line)
      if assignment:
        in_scope[assignment.group(1)] = index
      emit = _EMIT.match(line)
      if emit and in_scope:
        end = _block_end(lines, index)
        block = "\n".join(lines[index:end + 1])
        # `response=` as a keyword argument, not the substring anywhere: a
        # remediation string mentioning "response=" would otherwise satisfy it.
        if not re.search(r"(?m)^\s*response\s*=", block):
          variable = max(in_scope.items(), key=lambda kv: kv[1])[0]
          offenders.append((name, index + 1, variable))
        index = end + 1
        continue
      index += 1
  return offenders


def _direct_vulnerable_constructions(sources=None):
  """Return (file, line) for each `GrayboxFinding(status="vulnerable")` built inline.

  These bypass `emit_vulnerable` entirely, so they get no evidence artifact, no
  curl reproduction and no location derived from their evidence — whether or not
  the triggering response was in scope.
  """
  sites = []
  for name, lines in (sources if sources is not None else _probe_sources()):
    index = 0
    while index < len(lines):
      if _DIRECT.match(lines[index]):
        end = _block_end(lines, index)
        if 'status="vulnerable"' in "\n".join(lines[index:end + 1]):
          sites.append((name, index + 1))
        index = end + 1
        continue
      index += 1
  return sites


# The four modules that build findings inline, with their vulnerable-construction
# counts as of 2026-09-01. A ratchet, not an endorsement: converting them to
# `emit_vulnerable` needs a per-site judgement about which response triggered
# which finding, so it is tracked as RM-062 work rather than done blind here.
# Pinning the numbers means the gap cannot grow, and a new probe written this way
# fails here instead of shipping unnoticed.
_INLINE_BASELINE = {
  "access_control.py": 9,
  "business_logic.py": 4,
  "injection.py": 12,
  "misconfig.py": 11,
}


class TestEvidenceWiringContract(unittest.TestCase):

  def test_every_emit_with_a_response_in_scope_passes_it(self):
    offenders = _unwired_call_sites()
    self.assertEqual(
      offenders, [],
      "these emit_vulnerable calls have the triggering response in scope but "
      "do not pass it, so the finding is archived without request/response "
      "evidence and the LLM narrative is written without any:\n  "
      + "\n  ".join(f"{name}:{line} (response is `{var}`)"
                    for name, line, var in offenders),
    )

  def test_the_inline_construction_gap_does_not_grow(self):
    counts = {}
    for name, _line in _direct_vulnerable_constructions():
      counts[name] = counts.get(name, 0) + 1
    self.assertEqual(
      counts, _INLINE_BASELINE,
      "a vulnerable GrayboxFinding built inline gets no evidence artifact, no "
      "curl reproduction and no derived location. Either route it through "
      "emit_vulnerable, or change the baseline deliberately and say why.",
    )


class TestTheDetectorActuallyDetects(unittest.TestCase):
  """The self-test, as mutations rather than one happy-path plant.

  Each case is a source the detector *must* flag. The original plant matched the
  detector's narrowest assumptions, so pinning the detector to four-space
  indent, to `session.get` alone, or to a glob matching only the planted file
  all left the suite green.

  Sources are passed in rather than written into the real `graybox/probes/`
  package: the previous version wrote a temporary module inside a shipped
  package and removed it in a `finally`, so a crash in between left a stray file
  in the distribution.
  """

  UNWIRED = (
    ("four-space indent, session.get", [
      "  def _probe(self):",
      "    resp = session.get(url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "    )",
    ]),
    ("six-space indent, as a real probe body is", [
      "  def _probe(self):",
      "    if True:",
      "      resp = session.post(url)",
      "      self.emit_vulnerable(",
      '        "S", "t", "HIGH", "O", [],',
      '        ["endpoint=/x"],',
      "      )",
    ]),
    ("a verb other than get/post", [
      "  def _probe(self):",
      "    resp = session.options(url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "    )",
    ]),
    ("the probe helper rather than the session", [
      "  def _probe(self):",
      "    resp = self.request(session, 'GET', url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "    )",
    ]),
    ("response= only as a substring inside a string", [
      "  def _probe(self):",
      "    resp = session.get(url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"], remediation="check response=headers",',
      "    )",
    ]),
  )

  WIRED = (
    ("passes the response", [
      "  def _probe(self):",
      "    resp = session.options(url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "      response=resp,",
      "    )",
    ]),
    ("has no response in scope to pass", [
      "  def _probe(self):",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "    )",
    ]),
  )

  def test_each_unwired_shape_is_flagged(self):
    for label, lines in self.UNWIRED:
      with self.subTest(label):
        self.assertTrue(
          _unwired_call_sites([("planted.py", lines)]),
          "the detector did not flag a deliberately unwired call site",
        )

  def test_a_wired_or_responseless_site_is_not_flagged(self):
    for label, lines in self.WIRED:
      with self.subTest(label):
        self.assertEqual(_unwired_call_sites([("planted.py", lines)]), [])

  def test_the_inline_detector_flags_a_vulnerable_construction(self):
    lines = [
      "  def _probe(self):",
      "    self.findings.append(GrayboxFinding(",
      '      scenario_id="PT-A01-01",',
      '      title="t",',
      '      status="vulnerable",',
      '      severity="HIGH",',
      "    ))",
    ]
    self.assertEqual(
      _direct_vulnerable_constructions([("planted.py", lines)]),
      [("planted.py", 2)],
    )

  def test_the_inline_detector_ignores_a_non_vulnerable_construction(self):
    lines = [
      "  def _probe(self):",
      "    self.findings.append(GrayboxFinding(",
      '      scenario_id="PT-A01-01",',
      '      title="t",',
      '      status="inconclusive",',
      "    ))",
    ]
    self.assertEqual(_direct_vulnerable_constructions([("planted.py", lines)]), [])

  def test_the_scan_covers_every_probe_module(self):
    """A glob narrowed to nothing reports zero offenders and looks like success."""
    scanned = {name for name, _lines in _probe_sources()}
    for required in ("access_control.py", "misconfig.py", "injection.py",
                     "business_logic.py", "api_config.py"):
      self.assertIn(required, scanned)
    self.assertGreaterEqual(len(scanned), 9)


if __name__ == "__main__":
  unittest.main()
