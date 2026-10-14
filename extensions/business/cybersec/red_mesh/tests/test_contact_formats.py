"""RM-132: the contact formats, every row of `fixtures/contact_formats.json` through every write path.

The table is the contract (`onboarding-drafts.md` §Contact formats). Each entry point is exercised
on its own pure function: the draft party block (`drafts.normalize_legal`), the one-step
`prepare_tenant` input (`administration._legal_input`), the super-tenant profile
(`super_tenant_profile.apply_changes`) and the engagement contacts (`engagements.normalize_context`,
which keeps `context_invalid`). The plugin-level refusals are in the suites of those paths.
"""
import json
import pathlib
import unittest

from extensions.business.cybersec.red_mesh.tenancy import drafts, super_tenant_profile
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, _legal_input
from extensions.business.cybersec.red_mesh.tenancy.contacts import valid_email, valid_phone
from extensions.business.cybersec.red_mesh.tenancy.engagements import EngagementInvalid, normalize_context

FIXTURE_PATH = pathlib.Path(__file__).parent / "fixtures" / "contact_formats.json"
TABLE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
LEGAL = {"name": "Example Holdings SRL", "registration_id": "RO12345678", "signer_name": "Ana Pop",
         "signer_role": "Director"}
PROFILE = super_tenant_profile.empty_profile()
_FIELD = {"email": "contact_email", "phone": "contact_phone"}
_CODE = {"email": "contact_email_invalid", "phone": "contact_phone_invalid"}
_PREDICATE = {"email": valid_email, "phone": valid_phone}
_TEXT = {"email": drafts.email_text, "phone": drafts.phone_text}


class TestContactFormats(unittest.TestCase):

  def rows(self, verdict):
    for kind in ("email", "phone"):
      for value in TABLE[kind][verdict]:
        yield kind, value

  def test_the_table_is_non_trivial(self):
    for kind in ("email", "phone"):
      self.assertGreaterEqual(len(TABLE[kind]["accept"]), 5, kind)
      self.assertGreaterEqual(len(TABLE[kind]["refuse"]), 10, kind)

  def test_predicates_and_text_functions(self):
    for kind, value in self.rows("accept"):
      with self.subTest(kind=kind, value=value):
        self.assertTrue(_PREDICATE[kind](value))
        self.assertEqual(_TEXT[kind](" " + value + " "), value)
    for kind, value in self.rows("refuse"):
      with self.subTest(kind=kind, value=value):
        self.assertFalse(_PREDICATE[kind](value))
        with self.assertRaises(drafts.DraftInvalid) as caught:
          _TEXT[kind](value)
        self.assertEqual(caught.exception.code, _CODE[kind])
    for kind in ("email", "phone"):
      self.assertEqual(_TEXT[kind](""), "")
      self.assertEqual(_TEXT[kind]("   "), "")
      # A non-string is a malformed request, not a bad format.
      with self.assertRaises(drafts.DraftInvalid) as caught:
        _TEXT[kind](7)
      self.assertEqual(caught.exception.code, "invalid_request")

  def test_the_draft_party_block(self):
    for kind, value in self.rows("accept"):
      with self.subTest(kind=kind, value=value):
        self.assertEqual(drafts.normalize_legal({_FIELD[kind]: value}, dict(LEGAL))[_FIELD[kind]], value)
    for kind, value in self.rows("refuse"):
      with self.subTest(kind=kind, value=value):
        with self.assertRaises(drafts.DraftInvalid) as caught:
          drafts.normalize_legal({_FIELD[kind]: value}, dict(LEGAL))
        self.assertEqual(caught.exception.code, _CODE[kind])
    self.assertEqual(drafts.normalize_legal({"contact_email": "", "contact_phone": ""}, dict(LEGAL)),
                     {**LEGAL, "contact_email": "", "contact_phone": ""})

  def test_the_one_step_prepare_tenant_input(self):
    for kind, value in self.rows("accept"):
      with self.subTest(kind=kind, value=value):
        self.assertEqual(_legal_input({**LEGAL, _FIELD[kind]: value}), {**LEGAL, _FIELD[kind]: value})
    for kind, value in self.rows("refuse"):
      with self.subTest(kind=kind, value=value):
        with self.assertRaises(AdministrationDenied) as caught:
          _legal_input({**LEGAL, _FIELD[kind]: value})
        self.assertEqual((caught.exception.status_code, caught.exception.error), (400, _CODE[kind]))
    self.assertEqual(_legal_input({**LEGAL, "contact_email": " ", "contact_phone": ""}),
                     {**LEGAL, "contact_email": "", "contact_phone": ""})
    # A four-key block has no contact field and is accepted as it is.
    self.assertEqual(_legal_input(dict(LEGAL)), LEGAL)

  def test_the_super_tenant_profile(self):
    for kind, value in self.rows("accept"):
      with self.subTest(kind=kind, value=value):
        row, changed = super_tenant_profile.apply_changes(PROFILE, {_FIELD[kind]: value})
        self.assertEqual((row[_FIELD[kind]], changed), (value, [_FIELD[kind]]))
    for kind, value in self.rows("refuse"):
      with self.subTest(kind=kind, value=value):
        with self.assertRaises(drafts.DraftInvalid) as caught:
          super_tenant_profile.apply_changes(PROFILE, {_FIELD[kind]: value})
        self.assertEqual(caught.exception.code, _CODE[kind])
    self.assertEqual(super_tenant_profile.apply_changes(PROFILE, {"contact_email": "", "contact_phone": ""})[1], [])

  def test_the_engagement_contacts_keep_context_invalid(self):
    for contact in ("point_of_contact", "emergency_contact"):
      for kind, value in self.rows("accept"):
        with self.subTest(contact=contact, kind=kind, value=value):
          context = normalize_context({contact: {"name": "Ana", kind: value}})
          self.assertEqual(context[contact][kind], value)
      for kind, value in self.rows("refuse"):
        with self.subTest(contact=contact, kind=kind, value=value):
          with self.assertRaises(EngagementInvalid) as caught:
            normalize_context({contact: {"name": "Ana", kind: value}})
          self.assertEqual(caught.exception.code, "context_invalid")
    self.assertIsNone(normalize_context({"point_of_contact": {"email": "", "phone": ""}})["point_of_contact"])


if __name__ == "__main__":
  unittest.main()
