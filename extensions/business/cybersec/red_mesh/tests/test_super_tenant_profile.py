"""RM-110 phase 1: the super-tenant profile through the real plugin endpoints, service and adapters."""
import copy
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from .test_tenant_drafts import TENANCY_HKEY, ok, refused

PROFILE_KEY = (TENANCY_HKEY, '["super_tenant_profile","deployment","deployment"]')
FIELDS = ("legal_name", "registration_id", "vat_id", "address", "signer_name", "signer_role", "contact_email",
          "contact_phone")
EMPTY = {**{key: "" for key in FIELDS}, "updated_by": None, "updated_at": None}
PROVIDER = {"legal_name": "RedMesh Security SRL", "registration_id": "RO98765432", "vat_id": "RO98765432",
            "address": "Bd. Exemplu 10, Bucuresti", "signer_name": "Maria Ionescu", "signer_role": "CEO",
            "contact_email": "legal@redmesh.example", "contact_phone": "+40 700 100 100"}


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
    self.store.account("other-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.store.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.store.account("scoped-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": "tn_" + str(uuid4())}])
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}

  def get(self, actor=None):
    return self.plugin.get_super_tenant_profile(actor or self.actor)

  def update(self, changes, actor=None):
    return self.plugin.update_super_tenant_profile(actor or self.actor, changes)


class TestProfileRecord(_ProfileCase):
  def test_the_empty_profile_is_answered_without_a_write(self):
    self.assertEqual(ok(self, self.get()), EMPTY)
    self.assertEqual(self.store.writes, [])
    self.assertNotIn(PROFILE_KEY, self.store.data)
    self.assertEqual(self.events, [])

  def test_a_partial_update_writes_the_row_with_its_attribution_and_is_audited_by_key(self):
    profile = ok(self, self.update({"legal_name": " RedMesh Security SRL ", "contact_email": PROVIDER["contact_email"]}))
    self.assertEqual(profile, {**EMPTY, "legal_name": PROVIDER["legal_name"], "contact_email": PROVIDER["contact_email"],
                               "updated_by": "creator", "updated_at": profile["updated_at"]})
    self.assertTrue(profile["updated_at"])
    row = self.store.data[PROFILE_KEY]
    self.assertEqual((row["kind"], row["ids"], row["namespace"]), ("super_tenant_profile", ["deployment"], "deployment"))
    # The keys that changed, never their values.
    self.assertEqual(self.events, [("super_tenant_profile_updated",
                                    {"actor": "creator", "changed": ["contact_email", "legal_name"]})])
    self.assertEqual(ok(self, self.get()), profile)
    # The other fields are kept; another Super-Tenant Admin's update is attributed to them.
    again = ok(self, self.update({"signer_name": PROVIDER["signer_name"]}, actor={"account_id": "other-sta"}))
    self.assertEqual((again["legal_name"], again["signer_name"], again["updated_by"]),
                     (PROVIDER["legal_name"], PROVIDER["signer_name"], "other-sta"))
    self.assertEqual(self.events[-1], ("super_tenant_profile_updated", {"actor": "other-sta", "changed": ["signer_name"]}))
    # Unchanged values write nothing and audit nothing.
    writes, events = len(self.store.writes), len(self.events)
    self.assertEqual(ok(self, self.update({"signer_name": PROVIDER["signer_name"]})), again)
    self.assertEqual(ok(self, self.update({})), again)
    self.assertEqual((len(self.store.writes), len(self.events)), (writes, events))
    # Emptiness is allowed; the full block round-trips.
    cleared = ok(self, self.update({"legal_name": ""}))
    self.assertEqual((cleared["legal_name"], cleared["updated_by"]), ("", "creator"))
    full = ok(self, self.update(dict(PROVIDER)))
    self.assertEqual({key: full[key] for key in FIELDS}, PROVIDER)
    self.assertEqual(ok(self, self.get()), full)
    self.assertFalse(any(PROVIDER["legal_name"] in json.dumps(details) for _, details in self.events))

  def test_malformed_changes_are_refused_without_a_write(self):
    cases = {"not a dict": None, "list": [], "unknown key": {"name": "x"}, "nested": {"legal_name": {"x": 1}},
             "type": {"vat_id": 7}, "long": {"address": "x" * 201}, "control character": {"legal_name": "A\x00B"}}
    for label, changes in cases.items():
      with self.subTest(label):
        refused(self, self.update(changes), 400, "invalid_request")
    self.assertEqual(self.store.writes, [])
    self.assertEqual(self.events, [])
    # A refused change leaves a stored profile as it was.
    ok(self, self.update({"legal_name": "X"}))
    before = copy.deepcopy(self.store.data[PROFILE_KEY])
    refused(self, self.update({"legal_name": "Y", "nope": "1"}), 400, "invalid_request")
    self.assertEqual(self.store.data[PROFILE_KEY], before)
    self.assertEqual(len(self.events), 1)


class TestProfileRoles(_ProfileCase):
  def test_only_a_full_portfolio_super_tenant_admin_reads_or_writes(self):
    ok(self, self.update({"legal_name": "X"}))
    data, events = copy.deepcopy(self.store.data), list(self.events)
    calls = {"get": lambda actor: self.plugin.get_super_tenant_profile(actor),
             "update": lambda actor: self.plugin.update_super_tenant_profile(actor, {"legal_name": "Y"})}
    actors = {"tenant account": {"account_id": "initial"}, "super pentester": {"account_id": "pentester"},
              "tenant-scoped STA": {"account_id": "scoped-sta"}, "unknown": {"account_id": "nobody"},
              "no actor": None}
    for label, actor in actors.items():
      for name, call in calls.items():
        with self.subTest(actor=label, operation=name):
          result = call(actor)
          self.assertFalse(result["success"], result)
          if label in ("tenant account", "super pentester"):
            self.assertEqual((result["status_code"], result["error"]), (403, "forbidden"))
          else:
            self.assertEqual(result["status_code"], 404)
          self.assertNotIn("data", result)
    self.assertEqual(self.store.data, data)
    self.assertEqual(self.events, events)

  def test_no_namespace_means_unavailable_before_any_storage_access(self):
    self.plugin.cfg_tenancy_namespace = None
    for name in ("get_super_tenant_profile", "update_super_tenant_profile"):
      with self.subTest(name):
        self.assertEqual(getattr(self.Plugin, name).__http_method__, "post")
        self.assertEqual(getattr(self.plugin, name)(actor=self.actor)["status_code"], 503)
    self.assertEqual(self.store.writes, [])


if __name__ == "__main__":
  unittest.main()
