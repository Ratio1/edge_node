"""Lint gate: a probe that has the triggering response must hand it over.

`GrayboxEvidenceArtifact` was dead schema for its whole life — zero
constructions outside tests — because `emit_vulnerable` accepted evidence
nobody passed. Making the parameter exist does not make the evidence exist,
so this test asserts the wiring rather than the capability.

Modelled on test_stateful_contract.py: the failure mode is a *new* probe
shipping without the wiring, which no behavioural test would catch because
an absent artifact looks exactly like a probe that legitimately has no
response to attach.
"""

import re
import unittest
from pathlib import Path

_PROBES = Path(__file__).resolve().parent.parent / "graybox" / "probes"

_RESPONSE_ASSIGNMENT = re.compile(
  r"^\s*([a-z_][a-z0-9_]*)\s*=\s*"
  r"(?:session\.(?:get|post|put|delete|patch|head|request)"
  r"|self\.(?:request|stateful_request))\("
)
_EMIT = re.compile(r"^(\s*)self\.emit_vulnerable\($")
_DEF = re.compile(r"^\s*def\s+([a-z_][a-z0-9_]*)")


def _unwired_call_sites():
  """Return (file, line, function, variable) for each emit that drops evidence."""
  offenders = []
  for path in sorted(_PROBES.glob("*.py")):
    if path.name == "base.py":
      continue
    lines = path.read_text().split("\n")
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
        depth, end = 0, index
        while end < len(lines):
          depth += lines[end].count("(") - lines[end].count(")")
          if depth == 0 and end > index:
            break
          end += 1
        block = "\n".join(lines[index:end + 1])
        if "response=" not in block:
          variable = max(in_scope.items(), key=lambda kv: kv[1])[0]
          offenders.append((path.name, index + 1, variable))
        index = end + 1
        continue
      index += 1
  return offenders


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

  def test_the_detector_itself_finds_a_planted_offender(self):
    # Guards against the gate passing because the scan is broken rather than
    # because the code is clean - the failure mode this whole file exists for.
    source = "\n".join([
      "  def _probe(self):",
      "    resp = session.get(url)",
      "    self.emit_vulnerable(",
      '      "S", "t", "HIGH", "O", [],',
      '      ["endpoint=/x"],',
      "    )",
    ])
    planted = _PROBES / "_lint_selftest_tmp.py"
    planted.write_text(source)
    try:
      offenders = _unwired_call_sites()
      self.assertTrue(
        any(name == "_lint_selftest_tmp.py" for name, _line, _var in offenders),
        "the detector did not flag a deliberately unwired call site",
      )
    finally:
      planted.unlink()


if __name__ == "__main__":
  unittest.main()
