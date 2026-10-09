"""RM-125 phase 1: tenant assets on a live tenant and on a tenant draft, through the real plugin endpoints."""
import json
import unittest
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from .test_engagement_drafts import _EngagementDraftCase
from .test_tenant_drafts import TENANCY_HKEY, ok, refused

NETWORK = {"kind": "network", "address": "192.0.2.10"}
WEBAPP = {"kind": "webapp", "url": "https://app.example.com/", "allowedPathPrefix": "/"}
MODEL = {"kind": "model", "adapter": "openai_compatible",
         "endpointUrl": "https://llm.example.com/v1/chat/completions", "model": "gpt-test"}
DTO_KEYS = {"asset_id", "parent", "display_name", "kind", "target", "target_digest", "notes", "archived_at",
            "archived_by", "created_by", "created_at", "updated_by", "updated_at", "links", "status"}


class _AssetCase(_EngagementDraftCase):
  def register(self, parent, display_name="Edge gateway", target=None, notes="", request_id=None, actor=None):
    return self.plugin.create_tenant_asset(actor or self.actor, parent, request_id or str(uuid4()), display_name,
                                           NETWORK if target is None else target, notes)

  def asset(self, parent, **kwargs):
    return ok(self, self.register(parent, **kwargs))

  def listed(self, parent, actor=None, include_archived=False):
    return ok(self, self.plugin.list_tenant_assets(actor or self.actor, parent, include_archived))

  def asset_rows(self):
    return [value for (hkey, key), value in self.store.data.items()
            if hkey == TENANCY_HKEY and value is not None and json.loads(key)[0] == "tenant_asset"]

  def tenant(self):
    _, tenant_id = self.active_tenant()
    return tenant_id


class TestTenantAssetRecord(_AssetCase):
  def test_an_asset_is_registered_on_a_live_tenant_read_back_and_audited(self):
    tenant_id, request_id = self.tenant(), str(uuid4())
    self.events.clear()
    asset = self.asset(tenant_id, display_name=" Edge gateway ", notes=" owner: ops\nrack 4 ", request_id=request_id)
    self.assertEqual(set(asset), DTO_KEYS)
    self.assertEqual(asset["asset_id"], "ta_" + request_id)
    self.assertEqual(asset["parent"], {"tenant_id": tenant_id})
    self.assertEqual((asset["display_name"], asset["notes"]), ("Edge gateway", "owner: ops\nrack 4"))
    self.assertEqual((asset["kind"], asset["target"]), ("network", NETWORK))
    self.assertEqual(asset["target_digest"], canonical_digest(NETWORK))
    self.assertEqual((asset["archived_at"], asset["archived_by"]), (None, None))
    self.assertEqual((asset["links"], asset["status"]), ([], "unlinked"))
    self.assertEqual(self.events, [("tenant_asset_created", {
      "asset_id": asset["asset_id"], "parent": {"tenant_id": tenant_id}, "actor": "creator"})])
    self.assertEqual(ok(self, self.plugin.get_tenant_asset(self.actor, asset["asset_id"])),
                     {"asset": asset, "can_manage": True})
    self.assertEqual(self.listed(tenant_id), {"assets": [asset], "can_manage": True})
    # A replay answers the stored row without a write; under another parent it is a conflict.
    writes = len(self.store.writes)
    self.assertEqual(ok(self, self.register(tenant_id, display_name="Other", request_id=request_id)), asset)
    self.assertEqual(len(self.store.writes), writes)
    refused(self, self.register(self.create()["draft_id"], request_id=request_id), 409, "conflict")

  def test_every_kind_is_registered_and_the_list_is_by_name(self):
    tenant_id = self.tenant()
    for name, target in (("zeta model", MODEL), ("Alpha portal", WEBAPP), ("beta host", NETWORK)):
      self.asset(tenant_id, display_name=name, target=target)
    assets = self.listed(tenant_id)["assets"]
    self.assertEqual([(asset["display_name"], asset["kind"]) for asset in assets],
                     [("Alpha portal", "webapp"), ("beta host", "network"), ("zeta model", "model")])

  def test_an_asset_is_registered_on_a_tenant_draft(self):
    draft_id = self.create()["draft_id"]
    asset = self.asset(draft_id)
    self.assertEqual(asset["parent"], {"draft_id": draft_id})
    self.assertEqual(self.listed(draft_id), {"assets": [asset], "can_manage": True})
    # A well-formed draft that does not exist has none; a write to it is not found.
    missing = "td_" + str(uuid4())
    self.assertEqual(self.listed(missing), {"assets": [], "can_manage": True})
    refused(self, self.register(missing), 404, "not_found")

  def test_a_draft_being_activated_refuses_writes_but_is_read(self):
    draft_id = self.create()["draft_id"]
    asset = self.asset(draft_id)
    self.set_activation(draft_id)
    writes = len(self.store.writes)
    refused(self, self.register(draft_id, target=WEBAPP), 409, "draft_locked")
    refused(self, self.plugin.update_tenant_asset(self.actor, asset["asset_id"], {"notes": "x"}), 409, "draft_locked")
    refused(self, self.plugin.archive_tenant_asset(self.actor, asset["asset_id"], True), 409, "draft_locked")
    refused(self, self.plugin.delete_tenant_asset(self.actor, asset["asset_id"]), 409, "draft_locked")
    self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.listed(draft_id)["assets"], [asset])


class TestTenantAssetRoles(_AssetCase):
  def test_only_the_super_tenant_admin_writes_and_every_tenant_role_reads(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    self.store.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    self.store.account("outsider", memberships=[{"role": "tenant_admin", "tenant_id": "tn_" + str(uuid4())}])
    for name, read in (("acme.admin", True), ("viewer", True), ("pentester", True), ("outsider", False)):
      actor = {"account_id": name}
      with self.subTest(actor=name):
        writes = len(self.store.writes)
        if read:
          self.assertEqual(self.listed(tenant_id, actor=actor), {"assets": [asset], "can_manage": False})
          self.assertEqual(ok(self, self.plugin.get_tenant_asset(actor, asset["asset_id"]))["can_manage"], False)
          status, error = 403, "forbidden"
        else:
          refused(self, self.plugin.list_tenant_assets(actor, tenant_id), 404, "not_found")
          refused(self, self.plugin.get_tenant_asset(actor, asset["asset_id"]), 404, "not_found")
          status, error = 404, "not_found"
        refused(self, self.register(tenant_id, target=WEBAPP, actor=actor), status, error)
        refused(self, self.plugin.update_tenant_asset(actor, asset["asset_id"], {"notes": "x"}), status, error)
        refused(self, self.plugin.archive_tenant_asset(actor, asset["asset_id"], True), status, error)
        refused(self, self.plugin.delete_tenant_asset(actor, asset["asset_id"]), status, error)
        self.assertEqual(len(self.store.writes), writes)

  def test_a_tenant_draft_is_the_super_tenant_admins_alone(self):
    draft_id = self.create()["draft_id"]
    asset = self.asset(draft_id)
    self.assertEqual(self.listed(draft_id, actor={"account_id": "other-sta"})["assets"], [asset])
    for name in ("pentester", "scoped-sta"):
      actor = {"account_id": name}
      with self.subTest(actor=name):
        failure = self.plugin.list_tenant_assets(actor, draft_id)
        self.assertFalse(failure["success"])
        self.assertEqual(self.register(draft_id, target=WEBAPP, actor=actor)["status_code"], failure["status_code"])
        self.assertEqual(self.plugin.get_tenant_asset(actor, asset["asset_id"])["status_code"], failure["status_code"])

  def test_ids_and_parents_are_checked_before_any_read(self):
    for parent in ("", None, "tenant", {"tenant_id": "tn_x"}, "ted_" + str(uuid4())):
      refused(self, self.plugin.list_tenant_assets(self.actor, parent), 400, "invalid_request")
      refused(self, self.register(parent), 400, "invalid_request")
    for asset_id in ("", None, "ta_x", "ted_" + str(uuid4())):
      refused(self, self.plugin.get_tenant_asset(self.actor, asset_id), 400, "invalid_request")
      refused(self, self.plugin.delete_tenant_asset(self.actor, asset_id), 400, "invalid_request")
    refused(self, self.plugin.get_tenant_asset(self.actor, "ta_" + str(uuid4())), 404, "asset_not_found")
    refused(self, self.plugin.list_tenant_assets(self.actor, self.create()["draft_id"], "yes"), 400, "invalid_request")


class TestTenantAssetValidation(_AssetCase):
  def test_create_refuses_malformed_input_without_writes(self):
    tenant_id = self.tenant()
    writes = len(self.store.writes)
    for target in (None, {}, {"kind": "network", "address": "192.0.2.10", "authorized_ports": "22"},
                   {"kind": "network", "address": "192.0.2.0/24"}, {"kind": "webapp", "url": "ftp://x"},
                   {"kind": "model", "adapter": "other", "endpointUrl": MODEL["endpointUrl"], "model": "m"}):
      with self.subTest(target=target):
        refused(self, self.plugin.create_tenant_asset(self.actor, tenant_id, str(uuid4()), "Name", target),
                400, "asset_target_invalid")
    for name in ("", "  ", None, "x" * 201):
      refused(self, self.register(tenant_id, display_name=name), 400, "invalid_request")
    for notes in (3, "x" * 2001, "bell\x07"):
      refused(self, self.register(tenant_id, notes=notes), 400, "invalid_request")
    refused(self, self.plugin.create_tenant_asset(self.actor, tenant_id, "not-a-uuid", "Name", NETWORK),
            400, "invalid_request")
    self.assertEqual(len(self.store.writes), writes)

  def test_a_target_is_registered_once_per_parent_archived_included(self):
    tenant_id = self.tenant()
    first = self.asset(tenant_id)
    ok(self, self.plugin.archive_tenant_asset(self.actor, first["asset_id"], True))
    refused(self, self.register(tenant_id, display_name="Again"), 409, "asset_duplicate")
    # Another parent may register the same target.
    self.asset(self.create()["draft_id"])


class TestTenantAssetChanges(_AssetCase):
  def test_name_notes_and_an_unlinked_target_change_and_are_audited(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    self.events.clear()
    changed = ok(self, self.plugin.update_tenant_asset(
      self.actor, asset["asset_id"], {"display_name": "Gateway", "notes": "new", "target": WEBAPP}))
    self.assertEqual((changed["display_name"], changed["notes"], changed["kind"], changed["target"]),
                     ("Gateway", "new", "webapp", WEBAPP))
    self.assertEqual(changed["target_digest"], canonical_digest(WEBAPP))
    self.assertEqual(changed["created_at"], asset["created_at"])
    self.assertEqual(self.events, [("tenant_asset_updated", {
      "asset_id": asset["asset_id"], "parent": {"tenant_id": tenant_id}, "actor": "creator",
      "fields": ["display_name", "notes", "target"]})])
    # An unchanged update does not write.
    writes = len(self.store.writes)
    self.assertEqual(ok(self, self.plugin.update_tenant_asset(self.actor, asset["asset_id"], {"notes": "new"})),
                     changed)
    self.assertEqual(len(self.store.writes), writes)

  def test_update_refuses_bad_changes_and_a_duplicate_target(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    self.asset(tenant_id, display_name="Portal", target=WEBAPP)
    for changes in (None, {}, {"kind": "webapp"}, {"display_name": ""}, {"notes": 3}):
      refused(self, self.plugin.update_tenant_asset(self.actor, asset["asset_id"], changes), 400, "invalid_request")
    refused(self, self.plugin.update_tenant_asset(self.actor, asset["asset_id"], {"target": {"kind": "network"}}),
            400, "asset_target_invalid")
    refused(self, self.plugin.update_tenant_asset(self.actor, asset["asset_id"], {"target": WEBAPP}),
            409, "asset_duplicate")

  def test_archive_hides_the_asset_until_unarchived(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    self.events.clear()
    archived = ok(self, self.plugin.archive_tenant_asset(self.actor, asset["asset_id"], True))
    self.assertEqual(archived["archived_by"], "creator")
    self.assertIsNotNone(archived["archived_at"])
    self.assertEqual(self.listed(tenant_id)["assets"], [])
    self.assertEqual(self.listed(tenant_id, include_archived=True)["assets"], [archived])
    # Archiving twice does not write.
    writes = len(self.store.writes)
    self.assertEqual(ok(self, self.plugin.archive_tenant_asset(self.actor, asset["asset_id"], True)), archived)
    self.assertEqual(len(self.store.writes), writes)
    restored = ok(self, self.plugin.archive_tenant_asset(self.actor, asset["asset_id"], False))
    self.assertEqual((restored["archived_at"], restored["archived_by"]), (None, None))
    self.assertEqual([event for event, _ in self.events], ["tenant_asset_archived", "tenant_asset_unarchived"])
    refused(self, self.plugin.archive_tenant_asset(self.actor, asset["asset_id"], "yes"), 400, "invalid_request")

  def test_an_unlinked_asset_is_deleted(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    self.events.clear()
    self.assertEqual(ok(self, self.plugin.delete_tenant_asset(self.actor, asset["asset_id"])),
                     {"asset_id": asset["asset_id"], "parent": {"tenant_id": tenant_id}, "deleted": True,
                      "deleted_by": "creator"})
    self.assertEqual(self.events, [("tenant_asset_deleted", {
      "asset_id": asset["asset_id"], "parent": {"tenant_id": tenant_id}, "actor": "creator"})])
    refused(self, self.plugin.get_tenant_asset(self.actor, asset["asset_id"]), 404, "asset_not_found")
    self.assertEqual(self.asset_rows(), [])


class TestTenantAssetLifecycle(_AssetCase):
  def test_assets_of_a_closed_draft_belong_to_the_tenant(self):
    draft_id, request_id = self.ready(), str(uuid4())
    asset = self.asset(draft_id)
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    self.assertEqual(ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))["tenant_id"], tenant_id)
    moved = self.listed(tenant_id)["assets"]
    self.assertEqual([(row["asset_id"], row["parent"]) for row in moved], [(asset["asset_id"], {"tenant_id": tenant_id})])
    self.assertEqual(self.listed(draft_id)["assets"], [])

  def test_deleting_a_tenant_draft_deletes_its_assets(self):
    draft_id = self.create()["draft_id"]
    self.asset(draft_id)
    self.asset(draft_id, target=WEBAPP)
    kept = self.asset(self.create()["draft_id"])
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data["assets_deleted"], 2)
    self.assertEqual([row["asset_id"] for row in self.asset_rows()], [kept["asset_id"]])

  def test_a_malformed_asset_row_fails_the_parents_list_closed(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    field = json.dumps(["tenant_asset", "deployment", asset["asset_id"]], separators=(",", ":"))
    self.store.data[(TENANCY_HKEY, field)]["target_digest"] = "0" * 64
    refused(self, self.plugin.list_tenant_assets(self.actor, tenant_id), 503, "unavailable")


if __name__ == "__main__":
  unittest.main()
