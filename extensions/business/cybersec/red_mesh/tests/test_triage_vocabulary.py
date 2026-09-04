"""RM-062 B7: one triage vocabulary.

Two coexisted and neither knew about the other:

  * `models/triage.py` — `open`, `accepted_risk`, `false_positive`,
    `remediated`, `reopened`. This is the live one: `services/triage.py`
    validates against it and the repository stores it.
  * `findings.py` — `new`, `confirmed`, `false_positive`, `wont_fix`, `fixed`,
    the default value of `Finding.triage_state`, which `services/triage.py`
    never reads.

They overlap on exactly one value, `false_positive`. `rulebook_assessment.py`
falls back to `finding["triage_state"]` and compares it against
`_CLOSED_TRIAGE_STATUSES = {"false_positive", "remediated"}` — the *live* names.
So a finding remediated and marked `fixed` matched nothing, stayed "actionable",
and kept appearing in the compliance gap list after it had been dealt with. The
one value the vocabularies share is the one that worked, which is why this
looked fine.

Not every legacy name changes an outcome: `wont_fix` maps to `accepted_risk`,
which does not close a finding either, because accepting a risk is a decision
about a finding rather than evidence it is gone.
"""

import unittest

from extensions.business.cybersec.red_mesh.models.triage import (
  VALID_TRIAGE_STATUSES,
  normalize_triage_status,
)
from extensions.business.cybersec.red_mesh.services.rulebook_assessment import (
  _is_actionable_finding,
)


class TestOneVocabulary(unittest.TestCase):

  def test_every_live_status_maps_to_itself(self):
    for status in VALID_TRIAGE_STATUSES:
      self.assertEqual(normalize_triage_status(status), status)

  def test_each_legacy_name_maps_onto_a_live_one(self):
    self.assertEqual(normalize_triage_status("new"), "open")
    self.assertEqual(normalize_triage_status("confirmed"), "open")
    self.assertEqual(normalize_triage_status("wont_fix"), "accepted_risk")
    self.assertEqual(normalize_triage_status("fixed"), "remediated")
    self.assertEqual(normalize_triage_status("false_positive"), "false_positive")

  def test_case_and_padding_are_tolerated(self):
    self.assertEqual(normalize_triage_status("  Wont_Fix "), "accepted_risk")

  def test_an_unknown_value_is_not_invented_into_a_closed_state(self):
    """Fail open, not closed. Guessing a closed status would silently drop a
    finding out of the report; leaving it unmapped keeps it visible."""
    self.assertEqual(normalize_triage_status("gibberish"), "")
    self.assertEqual(normalize_triage_status(None), "")


class TestAClosedFindingStopsBeingActionable(unittest.TestCase):

  def _finding(self, triage_state):
    return {
      "finding_id": "0123456789abcdef",
      "title": "Weak TLS",
      "severity": "HIGH",
      "triage_state": triage_state,
    }

  def test_a_finding_marked_fixed_is_closed(self):
    self.assertFalse(_is_actionable_finding(self._finding("fixed"), {}))

  def test_a_finding_marked_wont_fix_stays_visible(self):
    """`wont_fix` maps to `accepted_risk`, which does *not* close a finding.

    Accepting a risk is a decision about a finding, not evidence it is gone, so
    it stays in the compliance report. The mapping still matters: before it,
    `wont_fix` matched no live status at all, so the value carried no meaning
    anywhere rather than carrying this one.
    """
    self.assertTrue(_is_actionable_finding(self._finding("wont_fix"), {}))

  def test_a_finding_marked_false_positive_is_closed(self):
    # The one value the two vocabularies shared — it always worked.
    self.assertFalse(_is_actionable_finding(self._finding("false_positive"), {}))

  def test_a_finding_marked_remediated_is_closed(self):
    self.assertFalse(_is_actionable_finding(self._finding("remediated"), {}))

  def test_an_open_finding_is_still_actionable(self):
    self.assertTrue(_is_actionable_finding(self._finding("open"), {}))
    self.assertTrue(_is_actionable_finding(self._finding("new"), {}))
    self.assertTrue(_is_actionable_finding(self._finding("confirmed"), {}))

  def test_an_accepted_risk_finding_stays_visible(self):
    """Accepting a risk is a decision about it, not evidence it is gone — it
    stays in the report. Only `false_positive` and `remediated` close a finding.
    """
    self.assertTrue(_is_actionable_finding(self._finding("accepted_risk"), {}))

  def test_the_explicit_triage_map_still_wins(self):
    finding = self._finding("open")
    triage_map = {"0123456789abcdef": {"status": "remediated"}}
    self.assertFalse(_is_actionable_finding(finding, triage_map))


if __name__ == "__main__":
  unittest.main()
