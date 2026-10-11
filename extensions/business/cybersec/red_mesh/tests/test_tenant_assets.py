"""RM-125 phase 1: tenant assets on a live tenant and on a tenant draft, through the real plugin endpoints."""
from datetime import datetime, timedelta, timezone
import json
import unittest
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from .asset_fixture import pick
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


class TestTenantAssetLinks(_AssetCase):
  """RM-125 phase 2b: engagements and engagement drafts pick registered assets; links, status and lock."""

  def engage(self, tenant_id, asset_id, start=-10, end=10, ports="443"):
    """An engagement over `asset_id`, its window `start`..`end` days from now (no documents)."""
    now = datetime.now(timezone.utc)
    window = [(now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ") for days in (start, end)]
    created = self.plugin.create_engagement(self.actor, tenant_id, str(uuid4()), "Q4", *window,
                                            {"client_name": "Example"}, [pick(asset_id, ports)], [])
    return ok(self, created)

  def draft_over(self, parent, asset_id):
    draft = self.child(parent)
    ok(self, self.update_child(draft["engagement_draft_id"], {"assets": [pick(asset_id, "443")]}))
    return draft["engagement_draft_id"]

  def linked(self, asset_id):
    return ok(self, self.plugin.get_tenant_asset(self.actor, asset_id))["asset"]

  def test_the_status_follows_the_links(self):
    tenant_id = self.tenant()
    expectations = {}
    for label, window in (("testable", (-10, 10)), ("scheduled", (5, 10)), ("expired", (-10, -5))):
      asset = self.asset(tenant_id, target={"kind": "network", "address": "192.0.2.%d" % (40 + len(expectations))})
      engagement = self.engage(tenant_id, asset["asset_id"], *window)
      expectations[label] = (asset["asset_id"], engagement["engagementId"])
    unlinked = self.asset(tenant_id, target=WEBAPP)
    self.assertEqual((unlinked["status"], unlinked["links"]), ("unlinked", []))
    states = {"testable": "active", "scheduled": "scheduled", "expired": "ended"}
    for label, (asset_id, engagement_id) in expectations.items():
      with self.subTest(label):
        asset = self.linked(asset_id)
        self.assertEqual(asset["status"], label)
        self.assertEqual(asset["links"], [{"source": "engagement", "id": engagement_id, "display_name": "Q4",
                                           "state": states[label]}])
    # A revoked engagement is a link, and the asset is no longer testable through it.
    asset_id, engagement_id = expectations["testable"]
    ok(self, self.plugin.revoke_engagement(self.actor, tenant_id, engagement_id, "done"))
    asset = self.linked(asset_id)
    self.assertEqual((asset["status"], [link["state"] for link in asset["links"]]), ("expired", ["revoked"]))
    # The list carries the same links.
    self.assertEqual({row["asset_id"]: row["status"] for row in self.listed(tenant_id)["assets"]},
                     {expectations["testable"][0]: "expired", expectations["scheduled"][0]: "scheduled",
                      expectations["expired"][0]: "expired", unlinked["asset_id"]: "unlinked"})

  def test_a_draft_link_alone_is_unlinked_but_locks_the_asset(self):
    tenant_id = self.tenant()
    asset = self.asset(tenant_id)
    draft_id = self.draft_over(tenant_id, asset["asset_id"])
    linked = self.linked(asset["asset_id"])
    self.assertEqual((linked["status"], linked["links"]), ("unlinked", [{
      "source": "engagement_draft", "id": draft_id, "display_name": "Pack", "state": "draft"}]))
    self.assert_locked(asset["asset_id"])

  def assert_locked(self, asset_id):
    writes = len(self.store.writes)
    refused(self, self.plugin.update_tenant_asset(self.actor, asset_id, {"target": WEBAPP}), 409, "asset_linked")
    refused(self, self.plugin.delete_tenant_asset(self.actor, asset_id), 409, "asset_linked")
    self.assertEqual(len(self.store.writes), writes)
    # The name and notes stay editable; archiving is not a delete.
    ok(self, self.plugin.update_tenant_asset(self.actor, asset_id, {"display_name": "Renamed " + str(uuid4())[:4]}))

  def test_a_revoked_or_ended_engagement_still_locks_the_asset(self):
    tenant_id = self.tenant()
    revoked = self.asset(tenant_id)
    ok(self, self.plugin.revoke_engagement(self.actor, tenant_id,
                                           self.engage(tenant_id, revoked["asset_id"])["engagementId"], "done"))
    self.assert_locked(revoked["asset_id"])
    ended = self.asset(tenant_id, target=WEBAPP)
    self.engage(tenant_id, ended["asset_id"], -10, -5, ports=None)
    self.assertEqual(self.linked(ended["asset_id"])["links"][0]["state"], "ended")
    refused(self, self.plugin.update_tenant_asset(self.actor, ended["asset_id"], {"target": NETWORK}), 409,
            "asset_linked")
    refused(self, self.plugin.delete_tenant_asset(self.actor, ended["asset_id"]), 409, "asset_linked")

  def test_an_engagement_draft_picks_the_assets_of_its_own_parent_only(self):
    first, second = self.create()["draft_id"], self.create()["draft_id"]
    own, other = self.asset(first), self.asset(second)
    draft_id = self.draft_over(first, own["asset_id"])
    stored = self.stored_child(draft_id)["assets"]
    self.assertEqual(stored, [{"engagement_asset_id": "ea_1", "asset_id": own["asset_id"],
                               "display_name": own["display_name"], "kind": "network", "target": NETWORK,
                               "target_digest": own["target_digest"]}])
    tenant_id = self.tenant()
    live = self.asset(tenant_id, target=WEBAPP)
    under_tenant = self.child(tenant_id)["engagement_draft_id"]
    writes = len(self.store.writes)
    for assets in ([pick(other["asset_id"], "443")], [pick("ta_" + str(uuid4()), "443")]):
      refused(self, self.update_child(draft_id, {"assets": assets}), 404, "asset_not_found")
    # A tenant's asset is not a tenant draft's, nor the reverse.
    refused(self, self.update_child(draft_id, {"assets": [pick(live["asset_id"])]}), 404, "asset_not_found")
    refused(self, self.update_child(under_tenant, {"assets": [pick(own["asset_id"], "443")]}), 404, "asset_not_found")
    self.assertEqual(len(self.store.writes), writes)
    # Archived assets are refused, and the picked entry keeps its copy.
    ok(self, self.plugin.archive_tenant_asset(self.actor, other["asset_id"], True))
    refused(self, self.update_child(self.child(second)["engagement_draft_id"],
                                    {"assets": [pick(other["asset_id"], "443")]}), 409, "asset_archived")

  def test_closing_the_tenant_draft_keeps_the_links(self):
    draft_id, request_id = self.ready(), str(uuid4())
    asset = self.asset(draft_id)
    engagement_draft_id = self.draft_over(draft_id, asset["asset_id"])
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))
    self.assertEqual(self.stored_child(engagement_draft_id)["parent"], {"tenant_id": tenant_id})
    moved = self.linked(asset["asset_id"])
    self.assertEqual(moved["parent"], {"tenant_id": tenant_id})
    self.assertEqual([(link["source"], link["id"]) for link in moved["links"]],
                     [("engagement_draft", engagement_draft_id)])
    self.assert_locked(asset["asset_id"])
    # The draft still resolves its (re-homed) asset under the tenant.
    ok(self, self.update_child(engagement_draft_id, {"assets": [pick(asset["asset_id"], "443")]}))


if __name__ == "__main__":
  unittest.main()
