"""RM-155 phase 1: the account profile, the reviewer designation, the certificates and the review snapshot.

The profile endpoints run through the real plugin, service and adapters on the in-memory CStore double
the other tenancy suites use. The policy matrix for `reports:review` (role x designation x Allow
Pentester) is asserted at the policy (`test_tenant_effect_authority_rm078`) and through real tenant
admission here and in `test_tenant_rulebook_scope`.
"""
import base64
import copy
import json
import unittest
from datetime import date
from unittest.mock import patch
from uuid import uuid4

from .contract_fixture import CONTRACT_PDF, FakeDocumentStore, contract_terms
from .test_tenant_administration import FakeAdministrationStore
from .test_tenant_drafts import TENANCY_HKEY, ok, refused
from extensions.business.cybersec.red_mesh.services import tenant_contract
from extensions.business.cybersec.red_mesh.tenancy import account_profile

KEY = lambda account: (TENANCY_HKEY, json.dumps([account_profile.KIND, "deployment", account], separators=(",", ":")))
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
TODAY = date(2026, 11, 3)
FULL = {"full_name": "Rita Reader", "position": "Lead Penetration Tester", "organization": "Acme Security",
        "contact_email": "rita@acme.example"}


def b64(raw):
  return base64.b64encode(raw).decode("ascii")


class _ProfileCase(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.documents = FakeDocumentStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_chainstore_peers = []
    self.plugin.P = lambda *args, **kwargs: None
    self.plugin._document_store = lambda: self.documents
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.service = self.plugin._execution_service()
    self.service.clock = lambda: _Clock(TODAY)
    self.plugin._execution_service = lambda: self.service  # one service, so the test clock holds
    # A tenant with a member, its admin and a second tenant's member.
    self.tenant_id = self.make_tenant("Acme Tenant", "acme-tenant")
    self.other_tenant_id = self.make_tenant("Other Tenant", "other-tenant")
    self.store.account("tadmin", memberships=[{"role": "tenant_admin", "tenant_id": self.tenant_id}])
    self.store.account("tuser", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}])
    self.store.account("tpent", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant_id}])
    self.store.account("other-admin2", memberships=[{"role": "tenant_admin", "tenant_id": self.other_tenant_id}])
    self.store.account("other-user", memberships=[{"role": "tenant_user", "tenant_id": self.other_tenant_id}])
    self.store.account("sta2", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.store.account("spent", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.store.writes.clear()
    self.events.clear()

  def make_tenant(self, name, domain):
    admin = self.service
    request_id = str(uuid4())
    initial = domain + "-init"
    self.store.account(initial)
    prepared = admin.prepare_tenant({"account_id": "creator"}, request_id, name, domain, initial, **contract_terms())
    assert prepared["success"], prepared
    tenant_id = prepared["data"]["tenantId"]
    self.store.grant(initial, tenant_id)
    assert admin.activate_tenant({"account_id": "creator"}, request_id)["success"]
    return tenant_id

  @staticmethod
  def actor(name):
    return {"account_id": name}

  def get(self, actor, account_id=None):
    return self.plugin.get_account_profile(self.actor(actor), account_id)

  def update(self, actor, account_id, changes):
    return self.plugin.update_account_profile(self.actor(actor), account_id, changes)

  def row(self, account):
    return self.store.data.get(KEY(account))


class _Clock:
  def __init__(self, day):
    self.day = day

  def date(self):
    return self.day


class TestProfileRecord(_ProfileCase):
  def test_an_account_without_a_row_reads_an_empty_profile_and_a_read_writes_nothing(self):
    profile = ok(self, self.get("tuser"))
    self.assertEqual((profile["account_id"], profile["full_name"], profile["profile_complete"],
                      profile["report_reviewer"], profile["qualifications"]), ("tuser", "", False, False, []))
    self.assertEqual((self.store.writes, self.events), ([], []))
    self.assertIsNone(self.row("tuser"))

  def test_the_signature_defaults_to_name_and_position_and_can_be_chosen(self):
    profile = ok(self, self.update("tuser", None, FULL))
    self.assertEqual(profile["signature"], "Rita Reader, Lead Penetration Tester")
    self.assertTrue(profile["profile_complete"])
    self.assertEqual(self.row("tuser")["signature"], "")  # the default is derived, not stored
    custom = ok(self, self.update("tuser", None, {"signature": "R. Reader, OSCP"}))
    self.assertEqual(custom["signature"], "R. Reader, OSCP")
    self.assertEqual(ok(self, self.update("tuser", None, {"signature": ""}))["signature"],
                     "Rita Reader, Lead Penetration Tester")
    self.assertEqual(ok(self, self.update("tuser", None, {"position": ""}))["signature"], "Rita Reader")

  def test_the_organization_is_prefilled_from_the_company_and_stays_editable(self):
    # A tenant account: the tenant record's legal.name; a platform account: the super-tenant company.
    self.assertEqual(ok(self, self.get("tuser"))["organization"], "Example Holdings SRL")
    self.assertEqual(ok(self, self.get("tuser"))["organization_default"], "Example Holdings SRL")
    self.assertEqual(ok(self, self.get("sta2"))["organization"], "")
    ok(self, self.plugin.update_super_tenant_profile(self.actor("creator"), {"legal_name": "RedMesh SRL"}))
    self.assertEqual(ok(self, self.get("sta2"))["organization"], "RedMesh SRL")
    own = ok(self, self.update("tuser", None, {"organization": "Freelance"}))
    self.assertEqual((own["organization"], own["organization_default"]), ("Freelance", "Example Holdings SRL"))

  def test_an_edit_is_attributed_stamped_and_audited_by_key_never_by_value(self):
    profile = ok(self, self.update("tuser", None, FULL))
    self.assertEqual(profile["updated_by"], "tuser")
    self.assertTrue(profile["updated_at"])
    row = self.row("tuser")
    self.assertEqual((row["kind"], row["ids"]), (account_profile.KIND, ["tuser"]))
    self.assertEqual(self.events, [("account_profile_updated", {
      "actor": "tuser", "account_id": "tuser", "changed": ["contact_email", "full_name", "organization", "position"]})])
    self.assertFalse(any("Rita" in json.dumps(details) for _, details in self.events))
    # An unchanged value writes and audits nothing.
    writes, events = len(self.store.writes), len(self.events)
    ok(self, self.update("tuser", None, {"full_name": "Rita Reader"}))
    ok(self, self.update("tuser", None, {}))
    self.assertEqual((len(self.store.writes), len(self.events)), (writes, events))

  def test_malformed_changes_are_refused_without_a_write(self):
    cases = {"not a dict": None, "unknown key": {"reviewer": True}, "reviewer flag": {"report_reviewer": True},
             "type": {"full_name": 7}, "long": {"position": "x" * 201}, "control": {"full_name": "A\x00B"},
             "qualifications type": {"qualifications": "OSCP"}, "entry type": {"qualifications": ["OSCP"]},
             "entry key": {"qualifications": [{"name": "OSCP", "certificate": {}}]},
             "no name": {"qualifications": [{"issuer": "OffSec"}]},
             "bad date": {"qualifications": [{"name": "OSCP", "expires_on": "2026-13-45"}]},
             "date form": {"qualifications": [{"name": "OSCP", "expires_on": "3/11/2026"}]},
             "unknown id": {"qualifications": [{"qualification_id": "q9", "name": "OSCP"}]},
             "too many": {"qualifications": [{"name": f"Q{i}"} for i in range(21)]}}
    codes = {"no name": "qualification_name_required", "bad date": "invalid_date", "date form": "invalid_date"}
    for label, changes in cases.items():
      with self.subTest(label):
        refused(self, self.update("tuser", None, changes), 400, codes.get(label, "invalid_request"))
    refused(self, self.update("tuser", None, {"contact_email": "nope"}), 400, "contact_email_invalid")
    refused(self, self.update("tuser", None, {"qualifications": [
      {"name": "OSCP", "issued_on": "2026-05-01", "expires_on": "2026-04-01"}]}), 400, "invalid_date")
    self.assertEqual((self.store.writes, self.events), ([], []))

  def test_the_validator_refuses_what_the_operations_could_not_have_written(self):
    good = {**account_profile.new_row("2026-01-01T00:00:00.000Z"), "updated_by": "tuser", "updated_at": "now",
            "full_name": "Rita"}
    self.assertIs(account_profile.validate_account_profile(good, ["tuser"]), good)
    bad = {"ids": ({}, []), "id case": ({}, ["Tuser"]), "no created_at": ({"account_created_at": ""}, ["tuser"]),
           "flag type": ({"report_reviewer": 1}, ["tuser"]), "text": ({"full_name": " x"}, ["tuser"]),
           "email": ({"contact_email": "x"}, ["tuser"]), "no stamp": ({"updated_by": None}, ["tuser"]),
           "qualifications": ({"qualifications": [{"qualification_id": "q1"}]}, ["tuser"]),
           "duplicate ids": ({"qualifications": [self._q("q1"), self._q("q1")]}, ["tuser"]),
           "certificate": ({"qualifications": [{**self._q("q1"), "certificate": {"ref": "x"}}]}, ["tuser"])}
    for label, (change, ids) in bad.items():
      with self.subTest(label):
        with self.assertRaises(ValueError):
          account_profile.validate_account_profile({**good, **change}, ids)

  @staticmethod
  def _q(qualification_id):
    return {"qualification_id": qualification_id, "name": "OSCP", "issuer": "", "credential_id": "",
            "issued_on": "", "expires_on": "", "certificate": None}

  def test_a_stored_profile_the_validator_refuses_fails_closed(self):
    ok(self, self.update("tuser", None, FULL))
    self.store.data[KEY("tuser")]["report_reviewer"] = "yes"
    self.assertEqual(self.get("tuser")["status_code"], 503)


class TestEditPermissions(_ProfileCase):
  def test_who_may_read_and_edit_whose_profile(self):
    # (actor, target, allowed). The holder, their Tenant Admin and a Super-Tenant Admin only.
    cases = (
      ("tuser", "tuser", True), ("tpent", "tpent", True), ("spent", "spent", True),
      ("tadmin", "tadmin", True),
      ("creator", "tuser", True), ("sta2", "tadmin", True), ("creator", "spent", True),
      ("tadmin", "tuser", True), ("tadmin", "tpent", True),
      ("tuser", "tpent", False), ("tpent", "tuser", False), ("tuser", "tadmin", False),
      ("tadmin", "other-user", False), ("tadmin", "creator", False), ("tadmin", "spent", False),
      ("other-admin2", "tuser", False), ("spent", "tuser", False), ("spent", "creator", False),
      ("tadmin", "nobody-here", False), ("tuser", "creator", False),
    )
    for number, (actor, target, allowed) in enumerate(cases):
      with self.subTest(actor=actor, target=target):
        events = len(self.events)
        updated = self.update(actor, target, {"position": f"Tester {number}"})
        read = self.get(actor, target)
        if allowed:
          self.assertEqual(ok(self, updated)["position"], f"Tester {number}")
          self.assertEqual(ok(self, read)["account_id"], target)
          self.assertEqual(self.events[-1][0], "account_profile_updated")
          self.assertEqual(self.events[-1][1]["actor"], actor)
          self.assertEqual(self.events[-1][1]["account_id"], target)
          self.assertEqual(ok(self, read)["updated_by"], actor)
        else:
          refused(self, updated, 404, "not_found")
          refused(self, read, 404, "not_found")
          self.assertEqual(len(self.events), events)
    # An inactive or unknown caller is refused.
    self.store.account("tuser", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}], state="deactivated")
    refused(self, self.get("tuser"), 404, "not_found")
    refused(self, self.plugin.get_account_profile(None), 404, "not_found")
    refused(self, self.get("tuser", "Bad Id!"), 404, "not_found")

  def test_a_tenant_admin_of_a_tenant_with_pentesting_off_still_edits_members(self):
    # Editing a profile is user management, not an operator action: Allow Pentester does not bind it.
    tenant = self.service.store.get("tenant", self.tenant_id)
    self.assertFalse(tenant["allow_pentester"])
    self.assertEqual(ok(self, self.update("tadmin", "tuser", {"position": "Analyst"}))["position"], "Analyst")

  def test_an_admin_can_save_the_full_name_before_the_holder_ever_signs_in(self):
    profile = ok(self, self.update("tadmin", "tuser", {"full_name": "Una User"}))
    self.assertTrue(profile["profile_complete"])
    self.assertTrue(ok(self, self.get("tuser"))["profile_complete"])

  def test_only_the_holder_sets_their_signature_line(self):
    # Owner 2026-11-09: each user signs for themself. An admin may fill in everything else.
    for admin in ("tadmin", "creator"):
      with self.subTest(admin=admin):
        events = len(self.events)
        refused(self, self.update(admin, "tuser", {"signature": "Una User, Forged"}), 403, "signature_holder_only")
        refused(self, self.update(admin, "tuser", {"full_name": "Una User", "signature": "X"}), 403,
                "signature_holder_only")
        self.assertEqual(len(self.events), events)
        self.assertEqual(ok(self, self.get("tuser"))["full_name"], "")
    ok(self, self.update("tuser", None, {"full_name": "Una User", "signature": "Una User, Analyst"}))
    # An admin's form that sends the stored value back unchanged is not a change.
    ok(self, self.update("tadmin", "tuser", {"position": "Analyst", "signature": "Una User, Analyst"}))
    self.assertEqual(ok(self, self.get("tuser"))["signature"], "Una User, Analyst")
    refused(self, self.update("creator", "tuser", {"signature": ""}), 403, "signature_holder_only")

  def test_a_deactivated_account_can_still_be_filled_in_by_its_admin_but_a_deleting_one_is_gone(self):
    self.store.account("tuser", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}], state="deactivated")
    ok(self, self.update("tadmin", "tuser", {"position": "Analyst"}))
    self.store.account("tuser", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}], state="deleting")
    refused(self, self.update("tadmin", "tuser", {"position": "Analyst"}), 404, "not_found")


class TestReviewerDesignation(_ProfileCase):
  def set(self, actor, account_id, enabled):
    return self.plugin.set_report_reviewer(self.actor(actor), account_id, enabled)

  def test_only_a_super_tenant_admin_sets_it_on_any_account_and_it_is_audited(self):
    for target in ("tuser", "tadmin", "spent", "creator"):
      with self.subTest(target=target):
        self.assertTrue(ok(self, self.set("creator", target, True))["report_reviewer"])
        self.assertEqual(self.events[-1], ("report_reviewer_set", {"actor": "creator", "account_id": target,
                                                                  "enabled": True}))
        self.assertTrue(ok(self, self.get("creator", target))["report_reviewer"])
    # A second STA unticks it, attributed to them.
    self.assertFalse(ok(self, self.set("sta2", "tuser", False))["report_reviewer"])
    self.assertEqual(self.events[-1][1]["actor"], "sta2")
    # Setting it creates a row on an account with no profile; no full name is needed for the flag.
    self.assertEqual(self.row("tuser")["full_name"], "")

  def test_nobody_else_sets_it_not_even_on_themselves(self):
    scoped = "tn_" + str(uuid4())
    self.store.account("scoped-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": scoped}])
    before = (copy.deepcopy(self.store.data), list(self.events))
    for actor in ("tadmin", "tpent", "tuser", "spent", "other-admin2"):
      for target in ("tuser", actor):
        with self.subTest(actor=actor, target=target):
          refused(self, self.set(actor, target, True), 403, "forbidden")
    refused(self, self.set("scoped-sta", "tuser", True), 404, "not_found")
    self.assertEqual((before[0], before[1]), (self.store.data, self.events))

  def test_an_unknown_account_or_a_bad_value_is_refused_and_a_repeat_writes_nothing(self):
    refused(self, self.set("creator", "nobody-here", True), 404, "not_found")
    refused(self, self.set("creator", "tuser", "yes"), 400, "invalid_request")
    refused(self, self.set("creator", "tuser", None), 400, "invalid_request")
    refused(self, self.set("creator", None, True), 400, "invalid_request")
    self.assertEqual((self.store.writes, self.events), ([], []))
    ok(self, self.set("creator", "tuser", True))
    writes, events = len(self.store.writes), len(self.events)
    ok(self, self.set("creator", "tuser", True))
    ok(self, self.set("creator", "other-user", False))  # already not designated
    self.assertEqual((len(self.store.writes), len(self.events)), (writes, events))

  def test_an_ordinary_profile_edit_cannot_change_it(self):
    ok(self, self.set("creator", "tuser", True))
    ok(self, self.update("tuser", None, FULL))
    self.assertTrue(self.row("tuser")["report_reviewer"])
    refused(self, self.update("tuser", None, {"report_reviewer": False}), 400, "invalid_request")
    self.assertTrue(ok(self, self.get("tuser"))["report_reviewer"])

  def test_the_designation_starts_unticked_for_every_account(self):
    for name in ("creator", "tadmin", "tpent", "tuser", "spent"):
      self.assertFalse(ok(self, self.get("creator", name))["report_reviewer"])
    self.assertEqual(self.store.writes, [])


class TestQualificationState(unittest.TestCase):
  def test_the_state_comes_from_the_expiry_date(self):
    state = account_profile.qualification_state
    self.assertEqual(state("", TODAY), "valid")
    self.assertEqual(state("2026-11-02", TODAY), "expired")
    self.assertEqual(state("2026-11-03", TODAY), "expiring")  # expires today: still held, not for long
    self.assertEqual(state("2026-12-03", TODAY), "expiring")  # exactly 30 days
    self.assertEqual(state("2026-12-04", TODAY), "valid")
    self.assertEqual(state("2030-01-01", TODAY), "valid")

  def test_the_dto_carries_the_state_and_the_service_clock_decides(self):
    case = _ProfileCase("setUp")
    case.setUpClass()
    case.setUp()
    try:
      qualifications = [{"name": "OSCP", "expires_on": "2026-10-01"}, {"name": "CISSP", "expires_on": "2026-11-20"},
                        {"name": "ISO 27001 LA", "expires_on": "2029-01-01"}, {"name": "CEH"}]
      profile = ok(case, case.update("tuser", None, {"qualifications": qualifications}))
      self.assertEqual([q["state"] for q in profile["qualifications"]], ["expired", "expiring", "valid", "valid"])
      self.assertEqual([q["qualification_id"] for q in profile["qualifications"]], ["q1", "q2", "q3", "q4"])
      case.service.clock = lambda: _Clock(date(2026, 12, 25))
      profile = ok(case, case.get("tuser"))
      self.assertEqual([q["state"] for q in profile["qualifications"]], ["expired", "expired", "valid", "valid"])
    finally:
      case.doCleanups()


class TestQualifications(_ProfileCase):
  def test_entries_keep_their_ids_and_edit_in_place_and_removal_drops_the_certificate_file(self):
    profile = ok(self, self.update("tuser", None, {"qualifications": [
      {"name": "OSCP", "issuer": "OffSec", "credential_id": "OS-1", "issued_on": "2024-01-01",
       "expires_on": "2027-01-01"}, {"name": "CISSP"}]}))
    self.assertEqual([q["qualification_id"] for q in profile["qualifications"]], ["q1", "q2"])
    ok(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q1", "oscp.png", b64(PNG)))
    ref = self.row("tuser")["qualifications"][0]["certificate"]["ref"]
    renamed = ok(self, self.update("tuser", None, {"qualifications": [
      {"qualification_id": "q1", "name": "OSCP+", "expires_on": "2027-01-01"}, {"qualification_id": "q2", "name": "CISSP"}]}))
    self.assertEqual(renamed["qualifications"][0]["certificate"]["filename"], "oscp.png")  # kept
    self.assertEqual(self.documents.deleted, [])
    ok(self, self.update("tuser", None, {"qualifications": [{"qualification_id": "q2", "name": "CISSP"}]}))
    self.assertEqual(self.documents.deleted, [ref])
    # A new entry takes a fresh id, never a removed one's certificate.
    added = ok(self, self.update("tuser", None, {"qualifications": [
      {"qualification_id": "q2", "name": "CISSP"}, {"name": "CEH"}]}))
    self.assertEqual([q["qualification_id"] for q in added["qualifications"]], ["q2", "q3"])
    self.assertEqual([q["certificate"] for q in added["qualifications"]], [None, None])

  def test_an_unhashable_or_non_text_qualification_id_is_invalid_request(self):
    ok(self, self.update("tuser", None, {"qualifications": [{"name": "OSCP"}]}))
    for bad in (["q1"], {"q1": 1}, 1):
      with self.subTest(bad=bad):
        refused(self, self.update("tuser", None, {"qualifications": [{"qualification_id": bad, "name": "OSCP"}]}),
                400, "invalid_request")

  def test_text_with_unicode_format_characters_is_refused(self):
    for bad in ("Rita\u202eReader", "Rita\u200bReader", "\ufeffRita"):
      for key in ("full_name", "signature", "position", "organization"):
        with self.subTest(bad=bad, key=key):
          refused(self, self.update("tuser", None, {key: bad}), 400, "invalid_request")
      refused(self, self.update("tuser", None, {"qualifications": [{"name": bad}]}), 400, "invalid_request")
    self.assertIsNone(self.row("tuser"))

  def test_zero_width_joiners_used_in_names_are_kept(self):
    # ZWNJ is part of Persian and some Indic spellings; ZWJ joins conjuncts.
    for name in ("می‌خواهم", "क्‍ष"):
      with self.subTest(name=name):
        ok(self, self.update("tuser", None, {"full_name": name}))

  def test_a_certificate_cannot_come_from_the_request(self):
    ok(self, self.update("tuser", None, {"qualifications": [{"name": "OSCP"}]}))
    refused(self, self.update("tuser", None, {"qualifications": [
      {"qualification_id": "q1", "name": "OSCP",
       "certificate": {"ref": "doc-1", "document_id": "x"}}]}), 400, "invalid_request")


class TestCertificates(_ProfileCase):
  def setUp(self):
    super().setUp()
    ok(self, self.update("tuser", None, {**FULL, "qualifications": [{"name": "OSCP", "expires_on": "2027-01-01"}]}))

  def upload(self, actor="tuser", account_id=None, qualification_id="q1", filename="oscp.png", raw=PNG):
    return self.plugin.upload_account_certificate(self.actor(actor), account_id, qualification_id, filename, b64(raw))

  def test_upload_names_the_file_never_its_reference_and_is_audited(self):
    profile = ok(self, self.upload())
    certificate = profile["qualifications"][0]["certificate"]
    self.assertEqual(set(certificate), {"document_id", "filename", "sha256", "mime", "size_bytes"})
    self.assertEqual((certificate["filename"], certificate["mime"]), ("oscp.png", "image/png"))
    self.assertNotIn("doc-1", json.dumps(profile))
    envelope = self.documents.envelopes["doc-1"]
    self.assertEqual((envelope["kind"], envelope["account_id"], envelope["qualification_id"]),
                     ("redmesh_account_certificate", "tuser", "q1"))
    self.assertEqual(self.events[-1][0], "account_certificate_uploaded")
    self.assertEqual(self.events[-1][1]["document_id"], certificate["document_id"])

  def test_a_second_upload_replaces_and_deletes_the_first(self):
    ok(self, self.upload())
    ok(self, self.upload(filename="new.pdf", raw=CONTRACT_PDF))
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(ok(self, self.get("tuser"))["qualifications"][0]["certificate"]["filename"], "new.pdf")

  def test_only_pdf_png_and_jpeg_within_the_size_cap_are_stored(self):
    for raw, code in ((b"MZ\x90\x00 executable", "bad_mime"), (b"", "empty")):
      refused(self, self.upload(raw=raw), 400, code)
    refused(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q1", "x.png", "!!"), 400,
            "invalid_base64")
    with patch.object(tenant_contract, "CERTIFICATE_MAX_BYTES", 10):
      refused(self, self.upload(), 400, "too_large")
      # Over-long text is refused before it is decoded.
      refused(self, self.upload(raw=b"x" * 100), 400, "too_large")
    self.assertEqual(self.documents.puts, [])

  def test_upload_needs_the_edit_right_and_an_existing_qualification_and_leaves_no_orphan_file(self):
    refused(self, self.upload(actor="tpent", account_id="tuser"), 404, "not_found")
    refused(self, self.upload(qualification_id="q9"), 404, "not_found")
    refused(self, self.upload(account_id="nobody-here"), 404, "not_found")
    self.assertEqual(self.documents.puts, [])
    self.documents.fail = True
    refused(self, self.upload(), 503, "unavailable")
    self.documents.fail = False
    self.assertIsNone(self.row("tuser")["qualifications"][0]["certificate"])

  def test_the_file_is_downloadable_by_the_holder_their_tenant_admin_and_a_sta_only(self):
    document_id = ok(self, self.upload())["qualifications"][0]["certificate"]["document_id"]
    for actor, allowed in (("tuser", True), ("tadmin", True), ("creator", True), ("sta2", True),
                           ("tpent", False), ("spent", False), ("other-admin2", False), ("other-user", False)):
      with self.subTest(actor=actor):
        result = self.plugin.download_account_certificate(self.actor(actor), "tuser", document_id)
        if allowed:
          data = ok(self, result)
          self.assertEqual(base64.b64decode(data["content_b64"]), PNG)
          self.assertEqual((data["filename"], data["mime"]), ("oscp.png", "image/png"))
        else:
          refused(self, result, 404, "not_found")
    refused(self, self.plugin.download_account_certificate(self.actor("tuser"), None, "cd_nope"), 404, "not_found")
    # A document id of another account's profile is not served through this one.
    ok(self, self.update("tpent", None, {"qualifications": [{"name": "CEH"}]}))
    refused(self, self.plugin.download_account_certificate(self.actor("tpent"), None, document_id), 404, "not_found")

  def test_a_missing_store_file_is_not_found_not_an_integrity_failure(self):
    document_id = ok(self, self.upload())["qualifications"][0]["certificate"]["document_id"]
    del self.documents.envelopes["doc-1"]
    refused(self, self.plugin.download_account_certificate(self.actor("tuser"), None, document_id), 404, "not_found")

  def test_the_download_is_refused_when_the_stored_bytes_changed(self):
    document_id = ok(self, self.upload())["qualifications"][0]["certificate"]["document_id"]
    self.documents.envelopes["doc-1"]["content_b64"] = b64(PNG + b"tampered")
    refused(self, self.plugin.download_account_certificate(self.actor("tuser"), None, document_id), 409,
            "document_integrity")

  def test_delete_detaches_removes_the_file_and_is_audited(self):
    document_id = ok(self, self.upload())["qualifications"][0]["certificate"]["document_id"]
    refused(self, self.plugin.delete_account_certificate(self.actor("tpent"), "tuser", document_id), 404, "not_found")
    profile = ok(self, self.plugin.delete_account_certificate(self.actor("tadmin"), "tuser", document_id))
    self.assertIsNone(profile["qualifications"][0]["certificate"])
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(self.events[-1], ("account_certificate_deleted",
                                       {"actor": "tadmin", "account_id": "tuser", "document_id": document_id}))
    refused(self, self.plugin.delete_account_certificate(self.actor("tadmin"), "tuser", document_id), 404, "not_found")


class TestCreatedAtGuard(_ProfileCase):
  def test_a_re_created_account_id_starts_with_no_profile_and_no_designation(self):
    ok(self, self.update("tuser", None, {**FULL, "qualifications": [{"name": "OSCP"}]}))
    ok(self, self.plugin.set_report_reviewer(self.actor("creator"), "tuser", True))
    ok(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q1", "a.png", b64(PNG)))
    # The account is deleted and created again under the same id: another `createdAt`.
    self.store.data[("auth", "tuser")]["createdAt"] = "2026-06-01T00:00:00.000Z"
    profile = ok(self, self.get("tuser"))
    self.assertEqual((profile["full_name"], profile["report_reviewer"], profile["qualifications"]), ("", False, []))
    self.assertFalse(self.service.reviewer_snapshot("tuser")["full_name"])
    self.assertFalse(self.service._report_reviewer(self.service.accounts.get_account("tuser")))
    # The new holder's first save replaces the stale row and takes its certificate file with it.
    updated = ok(self, self.update("tuser", None, {"full_name": "New Person"}))
    self.assertEqual((updated["full_name"], updated["report_reviewer"]), ("New Person", False))
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(self.row("tuser")["account_created_at"], "2026-06-01T00:00:00.000Z")

  def test_designating_a_re_created_account_also_deletes_the_stale_certificate_files(self):
    ok(self, self.update("tuser", None, {"qualifications": [{"name": "OSCP"}]}))
    ok(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q1", "a.png", b64(PNG)))
    self.store.data[("auth", "tuser")]["createdAt"] = "2026-06-01T00:00:00.000Z"
    ok(self, self.plugin.set_report_reviewer(self.actor("creator"), "tuser", True))
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(self.row("tuser")["qualifications"], [])
    # Designating the re-created account is its own act and is not inherited either.
    self.store.data[("auth", "tpent")]["createdAt"] = "2026-06-01T00:00:00.000Z"
    self.assertFalse(ok(self, self.get("creator", "tpent"))["report_reviewer"])


class TestPurge(_ProfileCase):
  def purge(self, actor="creator", account_id="tuser"):
    return self.plugin.purge_account_profile(self.actor(actor), account_id)

  def deleting(self, name="tuser"):
    self.store.account(name, memberships=self.store.data[("auth", name)]["memberships"], state="deleting")

  def setUp(self):
    super().setUp()
    ok(self, self.update("tuser", None, {**FULL, "qualifications": [{"name": "OSCP"}, {"name": "CISSP"}]}))
    ok(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q1", "a.png", b64(PNG)))
    ok(self, self.plugin.upload_account_certificate(self.actor("tuser"), None, "q2", "b.pdf", b64(CONTRACT_PDF)))

  def test_only_an_account_being_deleted_can_be_purged(self):
    refused(self, self.purge(), 409, "account_not_deleting")
    self.assertIsNotNone(self.row("tuser"))
    self.assertEqual(self.documents.deleted, [])

  def test_purge_removes_the_row_and_every_certificate_with_a_confirmed_unpin(self):
    self.deleting()
    data = ok(self, self.purge())
    self.assertEqual(data, {"account_id": "tuser", "purged": True, "files_deleted": 2})
    self.assertEqual(sorted(self.documents.deleted), ["doc-1", "doc-2"])
    self.assertEqual(self.documents.envelopes, {})
    self.assertIsNone(self.row("tuser"))
    self.assertEqual(self.events[-1], ("account_profile_purged", {"actor": "creator", "account_id": "tuser",
                                                                  "files_deleted": 2}))

  def test_purge_is_idempotent(self):
    self.deleting()
    ok(self, self.purge())
    events = len(self.events)
    again = ok(self, self.purge())
    self.assertEqual(again, {"account_id": "tuser", "purged": True, "files_deleted": 0})
    self.assertEqual(len(self.events), events)  # nothing left to purge, nothing to audit
    # An account that never had a profile purges cleanly too.
    self.deleting("tpent")
    self.assertEqual(ok(self, self.purge(account_id="tpent"))["files_deleted"], 0)

  def test_an_unconfirmed_unpin_keeps_the_row_so_the_purge_can_be_repeated(self):
    self.deleting()
    self.documents.fail_delete = {"doc-2"}
    result = self.purge()
    refused(self, result, 503, "unavailable")
    self.assertIsNotNone(self.row("tuser"))
    self.assertEqual(self.events[-1][0], "account_certificate_uploaded")  # no purge audit yet
    self.documents.fail_delete = set()
    # doc-1 went on the first try; a file already gone is skipped, not a failure.
    self.assertEqual(ok(self, self.purge())["purged"], True)
    self.assertIsNone(self.row("tuser"))
    self.assertEqual(self.documents.envelopes, {})

  def test_who_may_purge(self):
    self.deleting()
    for actor in ("tpent", "spent", "other-admin2", "other-user"):
      refused(self, self.purge(actor), 404, "not_found")
    self.assertIsNotNone(self.row("tuser"))
    ok(self, self.purge("tadmin"))  # the member's Tenant Admin deletes the account
    self.assertIsNone(self.row("tuser"))

  def test_after_the_tombstone_only_a_super_tenant_admin_can_still_purge(self):
    self.store.data[("auth", "tuser")] = "null"  # tombstoned
    refused(self, self.purge("tadmin"), 404, "not_found")
    ok(self, self.purge("creator"))
    self.assertIsNone(self.row("tuser"))
    self.assertEqual(sorted(self.documents.deleted), ["doc-1", "doc-2"])

  def test_a_re_created_account_with_the_same_id_starts_with_no_profile_after_a_purge(self):
    self.deleting()
    ok(self, self.purge())
    self.store.account("tuser", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}])
    profile = ok(self, self.get("tuser"))
    self.assertEqual((profile["full_name"], profile["qualifications"], profile["report_reviewer"]), ("", [], False))


class TestReviewPolicyThroughTenantAdmission(_ProfileCase):
  """`authorize_tenant_for_account` for `reports:review`: role x designation x Allow Pentester."""

  def set_allow(self, enabled):
    tenant = self.service.store.get("tenant", self.tenant_id)
    self.service.store.put("tenant", self.tenant_id, record={**tenant, "allow_pentester": enabled})

  def decide(self, name):
    from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
    account = self.service.accounts.get_account(name)
    try:
      self.service.authorize_tenant_for_account(account, self.tenant_id, "reports:review")
      return None
    except AdministrationDenied as exc:
      return exc.status_code, exc.error

  def test_role_by_designation_by_allow_pentester(self):
    for name, bound in (("creator", False), ("spent", False), ("tadmin", True), ("tpent", True), ("tuser", None)):
      for flag in (False, True):
        for allow in (False, True):
          with self.subTest(account=name, designated=flag, allow_pentester=allow):
            self.set_allow(allow)
            ok(self, self.plugin.set_report_reviewer(self.actor("creator"), name, flag))
            if bound is None:
              expected = (403, "forbidden")
            elif bound and not allow:
              expected = (403, "pentesting_disabled")
            elif not flag:
              expected = (403, "reviewer_not_designated")
            else:
              expected = None
            self.assertEqual(self.decide(name), expected)

  def test_nobody_is_a_reviewer_after_deploy_until_a_super_tenant_admin_ticks_someone(self):
    self.set_allow(True)
    for name in ("creator", "spent", "tadmin", "tpent"):
      self.assertEqual(self.decide(name), (403, "reviewer_not_designated"), name)
    self.assertIsNone(self.row("creator"))

  def test_the_designation_of_a_re_created_account_id_is_not_inherited(self):
    self.set_allow(True)
    ok(self, self.plugin.set_report_reviewer(self.actor("creator"), "tpent", True))
    self.assertIsNone(self.decide("tpent"))
    self.store.data[("auth", "tpent")]["createdAt"] = "2026-06-01T00:00:00.000Z"
    self.assertEqual(self.decide("tpent"), (403, "reviewer_not_designated"))

  def test_other_operations_do_not_read_the_designation(self):
    account = self.service.accounts.get_account("tpent")
    self.service.authorize_tenant_for_account(account, self.tenant_id, "reports:view")
    self.assertEqual(self.store.writes, [])


class TestReviewSnapshot(unittest.TestCase):
  """`_decide` with the reviewer profile the plugin reads: the gate, the snapshot, self-approval."""

  REVIEWER = {"full_name": "Rita Reader", "signature": "Rita Reader, Lead Penetration Tester",
              "organization": "Acme Security"}

  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()

  def owner(self):
    from .test_rulebook_assessment import _Owner
    return _Owner()

  def test_approve_without_a_full_name_is_refused_and_writes_nothing(self):
    from extensions.business.cybersec.red_mesh.services.report_review import approve_report, get_report_review, reject_report
    owner = self.owner()
    empty = {"full_name": "", "signature": "", "organization": ""}
    for call in (lambda: approve_report(owner, "job-1", expected_review_revision=0, actor="alice", reviewer=empty),
                 lambda: reject_report(owner, "job-1", expected_review_revision=0, note="no", actor="alice",
                                       reviewer=empty)):
      result = call()
      self.assertEqual((result["status"], result["error"]), ("error", "reviewer_profile_incomplete"))
    self.assertEqual(get_report_review(owner, "job-1")["review_status"], "pending")
    self.assertEqual(owner.audit_events, [])

  def test_the_row_stores_the_snapshot(self):
    from extensions.business.cybersec.red_mesh.services.report_review import approve_report
    owner = self.owner()
    review = approve_report(owner, "job-1", expected_review_revision=0, actor="alice",
                            reviewer=self.REVIEWER)["review"]
    self.assertEqual((review["reviewer"], review["reviewer_name"], review["reviewer_signature"],
                      review["reviewer_org"], review["self_approved"]),
                     ("alice", "Rita Reader", "Rita Reader, Lead Penetration Tester", "Acme Security", False))
    self.assertEqual(review["contract_version"], "2.0.0")

  def test_a_reject_stores_the_snapshot_too(self):
    from extensions.business.cybersec.red_mesh.services.report_review import reject_report
    view = reject_report(self.owner(), "job-1", expected_review_revision=0, note="dup", actor="alice",
                         reviewer=self.REVIEWER)
    self.assertEqual(view["review"]["reviewer_name"], "Rita Reader")
    self.assertFalse(view["review"]["self_approved"])

  def test_approving_ones_own_scan_is_allowed_and_recorded(self):
    from extensions.business.cybersec.red_mesh.services.report_review import approve_report
    owner = self.owner()
    owner.job_specs["execution_binding"] = {"actor_id": "alice"}
    view = approve_report(owner, "job-1", expected_review_revision=0, actor="alice", reviewer=self.REVIEWER)
    self.assertEqual(view["review_status"], "approved", view)
    self.assertTrue(view["review"]["self_approved"])
    other = self.owner()
    other.job_specs["execution_binding"] = {"actor_id": "bob"}
    self.assertFalse(approve_report(other, "job-1", expected_review_revision=0, actor="alice",
                                    reviewer=self.REVIEWER)["review"]["self_approved"])

  def test_a_row_stored_before_the_snapshot_still_reads(self):
    from extensions.business.cybersec.red_mesh.models.report_review import ReportReviewState
    from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
    from extensions.business.cybersec.red_mesh.services.report_review import (
      approve_report, get_report_review, review_summaries)
    owner = self.owner()
    legacy = {"job_id": "job-1", "pass_nr": 1, "state": "approved", "review_revision": 1, "reviewer": "alice",
              "note": "", "decided_at": "2026-10-01T10:00:00Z", "nis2_submission_ref": "",
              "contract_version": "2.0.0"}
    state = ReportReviewState.from_dict(legacy)
    self.assertEqual((state.reviewer_name, state.reviewer_signature, state.reviewer_org, state.self_approved),
                     (None, None, None, None))
    self.assertEqual(state.to_dict(), legacy)  # no snapshot keys appear
    JobStateRepository(owner).put_report_review(state)
    view = get_report_review(owner, "job-1")
    self.assertEqual(view["review"], legacy)
    self.assertEqual(view["review_status"], "approved")
    self.assertEqual(review_summaries(owner, {"job-1": owner.job_specs})["job-1"]["reviewer"], "alice")
    # A replay of the approval keeps the old row as it is, with no snapshot added.
    replay = approve_report(owner, "job-1", expected_review_revision=1, actor="bob", reviewer=self.REVIEWER)
    self.assertTrue(replay["idempotent_replay"])
    self.assertEqual(replay["review"], legacy)

  def test_a_snapshot_row_round_trips_and_ignores_malformed_optional_fields(self):
    from extensions.business.cybersec.red_mesh.models.report_review import ReportReviewState
    row = {"job_id": "job-1", "pass_nr": 1, "state": "approved", "reviewer": "alice",
           "reviewer_name": "Rita", "reviewer_signature": "Rita, Tester", "reviewer_org": "Acme",
           "self_approved": True}
    self.assertEqual(ReportReviewState.from_dict(row).to_dict()["self_approved"], True)
    state = ReportReviewState.from_dict({**row, "reviewer_name": 7, "self_approved": "yes"})
    self.assertEqual((state.reviewer_name, state.self_approved), (None, None))


class TestEndToEndRoutes(_ProfileCase):
  """The plugin's approve and reject read the actor's profile themselves; nothing reaches them from the request."""

  def test_the_snapshot_is_read_from_the_service_for_the_admitted_signer(self):
    ok(self, self.update("tpent", None, FULL))
    snapshot = self.service.reviewer_snapshot("tpent")
    self.assertEqual(snapshot, {"full_name": "Rita Reader", "signature": "Rita Reader, Lead Penetration Tester",
                                "organization": "Acme Security"})
    self.assertEqual(self.service.reviewer_snapshot("tuser")["full_name"], "")
    self.assertEqual(self.service.reviewer_snapshot("nobody-here")["full_name"], "")
    # The organization falls back to the prefill when none is saved.
    ok(self, self.update("tuser", None, {"full_name": "Una"}))
    self.assertEqual(self.service.reviewer_snapshot("tuser")["organization"], "Example Holdings SRL")

  def test_a_later_profile_edit_does_not_change_the_stored_review_row(self):
    from extensions.business.cybersec.red_mesh.services.report_review import approve_report, get_report_review
    from .test_rulebook_assessment import _Owner
    ok(self, self.update("tpent", None, FULL))
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="tpent",
                   reviewer=self.service.reviewer_snapshot("tpent"))
    ok(self, self.update("tpent", None, {"full_name": "Someone Else", "organization": "Other", "signature": "SE, CEO"}))
    self.assertEqual(self.service.reviewer_snapshot("tpent")["full_name"], "Someone Else")
    row = get_report_review(owner, "job-1")["review"]
    self.assertEqual((row["reviewer_name"], row["reviewer_signature"], row["reviewer_org"]),
                     ("Rita Reader", "Rita Reader, Lead Penetration Tester", "Acme Security"))


if __name__ == "__main__":
  unittest.main()
