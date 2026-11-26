"""RM186 profile: public endpoints, durable adapter and declaration boundaries."""
import copy
import json
from uuid import uuid4
from unittest.mock import patch

from .test_framework_assessment import FrameworkAssessmentFixture, COMPLIANCE_HKEY


class TestComplianceProfile(FrameworkAssessmentFixture):
  def write(self, profile=None, revision=0, request=None, actor=None):
    return self.plugin.save_tenant_compliance_profile(actor or self.admin, self.tenant,
      profile if profile is not None else {}, revision, request or str(uuid4()))

  def read(self, actor=None):
    return self.plugin.get_tenant_compliance_profile(actor or self.admin, self.tenant)

  def row(self):
    key = json.dumps(["compliance_profile", "deployment", self.tenant], separators=(",", ":"))
    return self.storage.data[(COMPLIANCE_HKEY, key)]

  def test_absent_partial_explicit_none_and_tenant_unchanged(self):
    before = copy.deepcopy(self.storage.data)
    empty = self.ok(self.read())
    self.assertEqual(empty["revision"], 0)
    self.assertIsNone(empty["profile"]["sectors"])
    self.assertEqual(before, self.storage.data)
    self.assertEqual(self.ok(self.write({"country": "DE"}))["profile"]["country"], "DE")
    self.assertIsNone(self.row()["profile"]["sectors"])
    saved = self.ok(self.write({"sectors": [], "entity_class": "none"}, 1))
    self.assertEqual(saved["profile"]["sectors"], [])
    self.assertEqual(set(saved), {"profile", "revision", "canManage"})
    for key, value in before.items():
      self.assertEqual(self.storage.data[key], value)
    self.assertEqual(len(self.row()["history"]), 2)
    self.assertEqual(self.row()["history"][0]["actor"], "initial")
    self.assertEqual(self.row()["history"][-1]["after"], saved["profile"])

  def test_roles_and_authority_before_replay(self):
    request = str(uuid4())
    self.ok(self.write(request=request))
    self.assertFalse(self.ok(self.read(self.viewer))["canManage"])
    self.refused(self.write(actor=self.viewer), 403, "forbidden")
    self.assertFalse(self.read(self.stranger)["success"])
    self.ok(self.write(revision=1, actor=self.creator))
    self.storage.account("initial", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.assertFalse(self.write(request=request)["success"])

  def test_retry_conflict_and_reload(self):
    request = str(uuid4())
    first = self.ok(self.write({"country": "RO"}, request=request))
    self.assertEqual(self.ok(self.write({"country": "RO"}, request=request)), first)
    self.refused(self.write({"country": "DE"}, request=request), 409, "profile_request_conflict")
    self.refused(self.write({"country": "RO"}, request=request, actor=self.creator), 409, "profile_request_conflict")
    self.refused(self.write(), 409, "profile_stale")
    self.assertEqual(len(self.row()["history"]), 1)
    self.assertEqual(self.ok(self.read())["profile"], first["profile"])

  def test_invalid_input_never_writes(self):
    for profile in ({"dora": True}, {"country": "ZZ"}, {"country": "ro"}, {"sectors": ["unknown"]},
                    {"sectors": ["rm.nis2.energy"] * 2}, {"entity_class": "unknown"},
                    {"size_band": "huge"}, {"sector_taxonomy": {"id": "redmesh.nis2-sectors", "version": 2}}):
      with self.subTest(profile=profile):
        self.refused(self.write(profile), 400, "profile_invalid")
    self.assertEqual(self.ok(self.read())["revision"], 0)

  def test_stored_profile_reads_after_a_manifest_data_update_but_a_stale_save_is_refused(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_profile as cp
    saved = self.ok(self.write({"country": "RO", "sectors": ["rm.nis2.energy", "rm.nis2.health"]}))
    manifest = copy.deepcopy(cp.load_manifest())
    manifest["sector_taxonomy"]["version"] += 1
    manifest["sector_taxonomy"]["sectors"] = [s for s in manifest["sector_taxonomy"]["sectors"]
                                              if s["code"] != "rm.nis2.energy"]
    with patch.object(cp, "load_manifest", return_value=manifest):
      self.assertEqual(self.ok(self.read())["profile"], saved["profile"])  # shape only on read
      self.refused(self.write({"sectors": ["rm.nis2.energy"]}, 1), 400, "profile_invalid")
      self.refused(self.write({"sectors": ["rm.nis2.health"], "sector_taxonomy": saved["profile"]["sector_taxonomy"]}, 1),
                   400, "profile_invalid")
      current = {"id": manifest["sector_taxonomy"]["id"], "version": manifest["sector_taxonomy"]["version"]}
      self.assertEqual(self.ok(self.write({"sectors": ["rm.nis2.health"], "sector_taxonomy": current}, 1))["revision"], 2)
      self.assertEqual(self.ok(self.read())["profile"]["sector_taxonomy"], current)

  def test_stored_assessment_reads_after_its_country_entry_leaves_the_manifest(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance
    self.ok(self.save({}, 1))
    self.assertEqual(self.stored_row()["country"], "RO")
    manifest = {**compliance.manifest_pack(self.pack["pack_id"]), "entries": []}
    with patch.object(compliance, "manifest_pack", return_value=manifest):
      self.assertTrue(self.ok(self.get())["persisted"])  # was 404 once the entry no longer named RO

  def test_actual_persistence_virtual_and_stored_default(self):
    self.assertFalse(self.ok(self.get())["persisted"])
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
    from extensions.business.cybersec.red_mesh.tenancy import compliance
    adapter = CstoreComplianceStore(self.plugin, "deployment")
    row = compliance.new_row(self.tenant, self.pack, actor="initial", now="t")
    adapter.put(compliance.KIND, self.tenant, self.pack["pack_id"], record=row)
    stored = self.ok(self.get())
    self.assertTrue(stored["persisted"])
    self.assertEqual(stored["assessmentRevision"], 1)
    self.ok(self.save({}, 1))
    self.assertTrue(self.ok(self.get())["persisted"])

  def test_verified_write_uncertain_ack_and_readback_retry(self):
    request = str(uuid4())
    self.storage.fail_write = len(self.storage.writes) + 1
    self.storage.fail_after_write = True
    self.assertFalse(self.write({"country": "RO"}, request=request)["success"])
    self.storage.fail_after_write = False
    self.assertEqual(self.ok(self.write({"country": "RO"}, request=request))["revision"], 1)
    self.assertEqual(len(self.row()["history"]), 1)
    self.storage.noop = True
    self.assertFalse(self.write({"country": "DE"}, 1)["success"])
    self.storage.noop = False
    self.assertEqual(self.ok(self.read())["revision"], 1)
    original = self.plugin.chainstore_hget
    reads = []
    def readback(**kwargs):
      if kwargs["hkey"] == COMPLIANCE_HKEY:
        reads.append(kwargs)
        if len(reads) == 2:
          return None
      return original(**kwargs)
    request = str(uuid4())
    with patch.object(self.plugin, "chainstore_hget", side_effect=readback):
      self.assertFalse(self.write({"country": "DE"}, 1, request)["success"])
    self.assertEqual(self.ok(self.write({"country": "DE"}, 1, request))["revision"], 2)
    self.assertEqual(len(self.row()["history"]), 2)

  def test_adapter_reload_and_malformed_row_fail_closed(self):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_profile as profile
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
    self.ok(self.write({"sectors": ["rm.nis2.health", "rm.nis2.energy"]}))
    adapter = CstoreComplianceStore(self.plugin, "deployment")
    stored = adapter.get(profile.KIND, self.tenant)
    self.assertEqual(stored, self.row())
    baseline = copy.deepcopy(self.row())
    malformed = []
    for field, value in (("revision", True), ("profile", {}), ("history", [])):
      row = copy.deepcopy(baseline); row[field] = value; malformed.append(row)
    for field, value in (("actor", "spoof"), ("at", "yesterday"), ("event_id", str(uuid4())),
                         ("before", {}), ("after", {}), ("revision", True), ("request_digest", "a" * 64)):
      row = copy.deepcopy(baseline); row["history"][0][field] = value; malformed.append(row)
    row = copy.deepcopy(baseline); row["profile"]["sector_taxonomy"]["version"] = True; malformed.append(row)
    key = adapter._location(profile.KIND, (self.tenant,))[1]
    for row in malformed:
      self.storage.data[(COMPLIANCE_HKEY, key)] = row
      self.assertFalse(self.read()["success"], row)
      self.assertFalse(self.write(revision=1)["success"], row)
      self.assertEqual(self.row(), row)

  def history_row(self, count, declaration=None):
    from extensions.business.cybersec.red_mesh.tenancy import compliance_profile as p
    after = p.normalize_profile(declaration or {})
    history = []
    for rev in range(1, count + 1):
      request = str(uuid4())
      history.append({"event_id": p.event_id(self.tenant, request), "request_id": request,
        "request_digest": p.request_digest("initial", after, rev - 1), "actor": "initial",
        "at": "2026-11-16T00:00:00+00:00", "revision": rev,
        "before": p.normalize_profile({}) if rev == 1 else after, "after": after})
    return {"schemaVersion": 1, "namespace": "deployment", "kind": p.KIND, "ids": [self.tenant],
            "tenant_id": self.tenant, "profile": after, "revision": count, "history": history}

  def install_history(self, count, declaration=None):
    row = self.history_row(count, declaration)
    key = json.dumps(["compliance_profile", "deployment", self.tenant], separators=(",", ":"))
    self.storage.data[(COMPLIANCE_HKEY, key)] = row
    return row

  def test_real_500_event_boundary_refuses_without_truncation_but_replays(self):
    self.install_history(499)
    request = str(uuid4())
    self.assertEqual(self.ok(self.write(revision=499, request=request))["revision"], 500)
    baseline = copy.deepcopy(self.row())
    self.refused(self.write(revision=500), 409, "profile_capacity")
    self.assertEqual(self.row(), baseline)
    self.assertEqual(self.ok(self.write(revision=499, request=request))["revision"], 500)

  def test_exact_byte_boundary_plus_one_and_historical_replay(self):
    from datetime import datetime, timezone
    from extensions.business.cybersec.red_mesh.tenancy import compliance_profile as p
    self.ok(self.write())
    before = copy.deepcopy(self.row())
    request, stamp = str(uuid4()), datetime(2026,11,16,tzinfo=timezone.utc)
    after = p.normalize_profile({"country": "DE"})
    candidate = copy.deepcopy(before)
    candidate["profile"], candidate["revision"] = after, 2
    candidate["history"].append({"event_id": p.event_id(self.tenant, request), "request_id": request,
      "request_digest": p.request_digest("initial", after, 1), "actor": "initial", "at": stamp.isoformat(),
      "revision": 2, "before": before["profile"], "after": after})
    size = p.row_bytes(candidate)
    with patch.object(p, "datetime") as clock:
      clock.now.return_value = stamp
      # datetime parser remains real during adapter validation.
      clock.fromisoformat = datetime.fromisoformat
      with patch.object(p, "MAX_WRITE_BYTES", size - 1):
        self.refused(self.write({"country": "DE"}, 1, request), 409, "profile_capacity")
        self.assertEqual(self.row(), before)
      with patch.object(p, "MAX_WRITE_BYTES", size):
        self.assertEqual(self.ok(self.write({"country": "DE"}, 1, request))["revision"], 2)
    self.assertEqual(p.row_bytes(self.row()), size)
    # Real operational budget: a larger valid historical row is readable/replayable, never truncated.
    from extensions.business.cybersec.red_mesh.references.framework_packs import load_manifest
    full = {"sectors": [s["code"] for s in load_manifest()["sector_taxonomy"]["sectors"]]}
    row = self.install_history(400, full)
    self.assertGreater(p.row_bytes(row), p.MAX_WRITE_BYTES)
    self.assertLess(p.row_bytes(row), p.MAX_READ_BYTES)
    self.assertEqual(self.ok(self.read())["revision"], 400)
    event = row["history"][-1]
    self.assertEqual(self.ok(self.write(full, 399, event["request_id"]))["revision"], 400)
    self.refused(self.write(full, 400), 409, "profile_capacity")
    self.assertEqual(self.row(), row)

  def test_invalid_request_revision_actor_and_expired_authority(self):
    for revision, request in ((True,str(uuid4())), (-1,str(uuid4())), (0,"bad"), (0,None)):
      result = self.plugin.save_tenant_compliance_profile(self.admin, self.tenant, {}, revision, request)
      self.refused(result, 400, "profile_invalid")
    self.ok(self.write())
    self.storage.account("initial", active=False)
    self.assertFalse(self.read()["success"])
    self.assertFalse(self.write(revision=1)["success"])
    self.assertEqual(self.row()["revision"], 1)

  def test_purge_singleton_including_malformed_raw_values(self):
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
    from extensions.business.cybersec.red_mesh.tenancy import compliance_profile as p
    self.ok(self.write())
    adapter = CstoreComplianceStore(self.plugin, "deployment")
    self.assertEqual(adapter.tenant_record_ids(p.KIND, self.tenant), [[self.tenant]])
    key = adapter._location(p.KIND, (self.tenant,))[1]
    self.storage.data[(COMPLIANCE_HKEY, key)] = "malformed"
    self.storage.account("initial", memberships=[])
    self.storage.account("viewer", memberships=[])
    self.storage.account("pentester", memberships=[])
    self.assertEqual(self.ok(self.plugin.delete_tenant(self.creator, self.tenant))["assessments"], 0)
    self.assertIsNone(self.storage.data[(COMPLIANCE_HKEY, key)])
    self.assertEqual(adapter.tenant_record_ids(p.KIND, self.tenant), [])
