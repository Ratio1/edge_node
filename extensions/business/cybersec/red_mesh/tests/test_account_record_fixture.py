"""Both parsers, one fixture (RM-084 P6).

`account-record.v1.json` is the canonical statement of which stored values are accounts and which are
not. The Navigator writes records and this repo reads them, so a case either side gets wrong is an
account that exists for authentication and not for authorization, or the reverse -- and neither side
would notice on its own. Running the same cases here and in the Navigator's
`__tests__/account-record-fixture.test.ts` is what makes disagreement a failing test rather than a
production surprise.

The copy in this repo is checked against the hub's canonical file by the P9 review checklist; there
is no cross-repo CI to do it automatically.
"""
import json
import pathlib
import unittest

from extensions.business.cybersec.red_mesh.tenancy.account_record import (
  is_tombstone,
  parse_account_record,
)

FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tenancy" / "fixtures" / "account-record.v1.json"


def load():
  with FIXTURE.open() as handle:
    return json.load(handle)


class TestAccountRecordFixture(unittest.TestCase):
  def setUp(self):
    self.fixture = load()

  def test_the_fixture_is_the_version_this_parser_reads(self):
    self.assertEqual(self.fixture["schemaVersion"], 1)
    self.assertGreater(len(self.fixture["cases"]), 20)

  def test_every_case_lands_where_the_contract_says(self):
    for case in self.fixture["cases"]:
      with self.subTest(case=case["name"], expect=case["expect"]):
        parsed = parse_account_record(case["value"], case["field"])
        if case["expect"] == "valid":
          self.assertIsNotNone(parsed, "a valid record must parse")
          state, generation, memberships = parsed
          view = case["view"]
          self.assertEqual(state, view["state"])
          self.assertEqual(state == "active", view["active"])
          self.assertEqual(generation, view["generation"])
          self.assertEqual(
            [{"role": role, "tenant_id": tenant_id} for role, tenant_id in memberships],
            view["memberships"])
        elif case["expect"] == "tombstone":
          self.assertTrue(is_tombstone(case["value"]))
          self.assertIsNone(parsed)
        else:
          # Invalid and tombstoned both answer `None`; only a tombstone is a *removal*.
          self.assertIsNone(parsed, "an invalid record must not parse")
          self.assertFalse(is_tombstone(case["value"]))

  def test_the_fixture_exercises_both_outcomes(self):
    outcomes = {case["expect"] for case in self.fixture["cases"]}
    self.assertEqual(outcomes, {"valid", "invalid", "tombstone"})


if __name__ == "__main__":
  unittest.main()
