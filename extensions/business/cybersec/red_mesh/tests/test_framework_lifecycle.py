"""RM-182 phase 4: snapshot manifest version and pack hash, the retired-pack lifecycle, the pack list endpoint,
the row-format marker, unavailable rows in a list, the country label, and tenant delete over every row."""
import json
from uuid import uuid4

from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from extensions.business.cybersec.red_mesh.tenancy import compliance

from .test_framework_assessment import COMPLIANCE_HKEY, PACK as DNSC
from .test_framework_generic_packs import CYFUN, STATUS, GenericPackFixture


class LifecycleFixture(GenericPackFixture):
  def raw_row(self, pack_id, aid=None, drop=(), **over):
    """A stored row written straight into the fake CStore, as an older or foreign build would leave it."""
    ids = [self.tenant, pack_id] + ([aid] if aid else [])
    row = {**compliance.new_row(self.tenant, packs.load_framework_pack(DNSC), actor="initial", now="t"),
           "pack_id": pack_id, **({"assessment_id": aid, "name": aid} if aid else {}), **over}
    row = {**{k: v for k, v in row.items() if k not in drop},
           "schemaVersion": 1, "namespace": "deployment", "kind": compliance.KIND, "ids": ids}
    key = json.dumps([compliance.KIND, "deployment", *ids], separators=(",", ":"))
    self.storage.data[(COMPLIANCE_HKEY, key)] = row
    return row

  def retire(self, pack_id):
    manifest = json.loads((self.tmp / "framework-manifest.json").read_text())
    next(p for p in manifest["packs"] if p["pack_id"] == pack_id)["status"] = "retired"
    (self.tmp / "framework-manifest.json").write_text(json.dumps(manifest))
    packs.reset_framework_caches()

  def create_country(self, pack, country, level=None):
    return self.plugin.create_framework_assessment(self.admin, self.tenant, pack, str(uuid4()), str(uuid4())[:8], level,
                                                   None, country)


FA_A, FA_B, FA_C = (f"fa_{n}1111111-1111-4111-8111-111111111111" for n in "abc")


class TestSnapshotAndCountry(LifecycleFixture):
  def test_a_snapshot_records_manifest_version_pack_hash_and_country(self):
    made = self.ok(self.create_country(CYFUN, "DE", "base"))
    scores = {c["ref_id"]: {"documentation": 2, "implementation": 2, "excluded": False}
              for c in packs.controls_for_level(packs.load_framework_pack(CYFUN), "base")}
    saved = self.ok(self.save_to(CYFUN, made["assessmentId"], {"scores": scores, "completion_date": "2026-10-06"},
                                 made["assessmentRevision"]))
    self.ok(self.submit_to(CYFUN, made["assessmentId"], saved["assessmentRevision"]))
    snapshot = self.documents.envelopes["doc-1"]["snapshot"]
    self.assertEqual((snapshot["manifest_version"], snapshot["country"]), (packs.load_manifest()["manifest_version"], "DE"))
    self.assertEqual(snapshot["pack_hash"], packs.manifest_pack(CYFUN)["pack_sha256"])
    self.assertFalse({"dnsc_unique_id", "external_supplier"} & set(snapshot))  # only the fields the pack's rules list

  def test_a_dnsc_snapshot_keeps_its_dnsc_keys_and_the_default_country(self):
    made = self.ok(self.plugin.create_framework_assessment(self.admin, self.tenant, DNSC, str(uuid4()), "D", "basic", None))
    self.assertEqual(self.stored_row()["country"], "RO")  # the pack's one entry fixes it
    scores = {c["ref_id"]: {"documentation": 3, "implementation": 2, "excluded": False,
                            "justification": {"documentation": "a", "implementation": "b"}}
              for c in packs.controls_for_level(packs.load_framework_pack(DNSC), "basic")}
    saved = self.ok(self.save_to(DNSC, made["assessmentId"], {
      "scores": scores, "completion_date": "2026-10-06",
      "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}}, made["assessmentRevision"]))
    self.ok(self.submit_to(DNSC, made["assessmentId"], saved["assessmentRevision"]))
    snapshot = self.documents.envelopes["doc-1"]["snapshot"]
    self.assertEqual((snapshot["dnsc_unique_id"], snapshot["external_supplier"], snapshot["country"]), ("", "", "RO"))
    self.assertEqual(snapshot["pack_hash"], packs.manifest_pack(DNSC)["pack_sha256"])

  def test_country_is_validated_against_the_packs_entries(self):
    self.assertEqual(self.ok(self.create_country(STATUS, None))["assessmentId"][:3], "fa_")
    self.assertEqual(self.stored_row()["country"], "RO")
    for pack, bad in ((DNSC, "DE"), (DNSC, "ro"), (STATUS, "DE"), (CYFUN, "Germany"), (CYFUN, 5), (CYFUN, "US"), (CYFUN, "ZZ")):
      self.refused(self.create_country(pack, bad, "basic" if pack == DNSC else "base" if pack == CYFUN else None),
                   400, "assessment_invalid")
    self.ok(self.create_country(CYFUN, "DE", "base"))  # an EU entry covers the member states
    made = self.ok(self.create_country(CYFUN, None, "base"))  # an EU entry names no single country
    self.assertEqual(self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, CYFUN, made["assessmentId"]))["packId"], CYFUN)
    rows = [r for r in self.storage.data.values() if r and r.get("pack_id") == CYFUN]
    self.assertEqual(sorted(str(r["country"]) for r in rows), ["DE", "None"])
    self.assertEqual(compliance.new_row(self.tenant, packs.load_framework_pack(DNSC), actor="a", now="t")["country"], "RO")  # the lazy default row too


class TestPackList(LifecycleFixture):
  def packs(self, actor=None):
    return self.ok(self.plugin.list_framework_packs(actor or self.admin, self.tenant))

  def test_the_list_carries_the_active_packs_with_levels_rules_licence_and_capabilities(self):
    data = self.packs()
    self.assertEqual((data["schema"], data["manifestVersion"]), ("redmesh.framework_pack_list.v1", 1))
    by_id = {p["packId"]: p for p in data["packs"]}
    self.assertEqual(set(by_id), set(packs.list_framework_pack_ids()))
    dnsc = by_id[DNSC]
    self.assertEqual((dnsc["scoring"], dnsc["levels"], dnsc["status"], dnsc["languages"]),
                     ("maturity_two_axis.v1", ["basic", "important", "essential"], "active", ["ro"]))
    for pack_id, listed in by_id.items():  # the hash a draft export prints as its pack hash
      self.assertEqual(listed["packSha256"], packs.manifest_pack(pack_id)["pack_sha256"])
    self.assertEqual((dnsc["exports"], dnsc["licence"]["shipText"], dnsc["title"]),
                     (["json", "csv", "pdf", "eval_mms"], True, "DNSC Order 1/2026"))
    for listed in data["packs"]:  # the display name is the manifest title; the catalogue string names the source framework
      self.assertEqual(listed["title"], packs.manifest_pack(listed["packId"])["title"])
      self.assertNotRegex(listed["title"], r"CyFun|Anexa 1")
    self.assertEqual((dnsc["rules"]["entity_fields"], dnsc["rules"]["signoff_required"], "exports" in dnsc["rules"]),
                     (["dnsc_unique_id", "external_supplier"], True, False))
    self.assertEqual((dnsc["capabilities"]["has_levels"], dnsc["capabilities"]["axes"]), (True, ["documentation", "implementation"]))
    self.assertEqual((dnsc["entries"][0]["country"], "verified_by" in dnsc["entries"][0], "exports" in dnsc["capabilities"]),
                     ("RO", False, False))
    self.assertEqual((by_id[STATUS]["levels"], by_id[STATUS]["capabilities"]["has_levels"]), ([], False))

  def test_it_needs_the_view_permission_and_a_member_tenant(self):
    self.assertEqual(self.packs(self.viewer)["manifestVersion"], 1)
    self.assertFalse(self.plugin.list_framework_packs(self.stranger, self.tenant)["success"])
    result = self.plugin.list_framework_packs(self.pentester, self.tenant)
    self.assertFalse(result["success"], result)
    self.assertEqual(self.events[-1][0], "framework_assessment_refused")


class TestRetiredPackLifecycle(LifecycleFixture):
  def test_a_retired_pack_keeps_its_rows_and_is_neither_listed_nor_creatable(self):
    made = self.ok(self.create(STATUS))
    self.retire(STATUS)
    self.assertNotIn(STATUS, [p["packId"] for p in self.ok(self.plugin.list_framework_packs(self.admin, self.tenant))["packs"]])
    self.assertEqual(self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, STATUS, made["assessmentId"]))["packId"], STATUS)
    self.ok(self.save_to(STATUS, made["assessmentId"], {"sectoral_requirements": "still editable"}, made["assessmentRevision"]))
    self.assertEqual([r["assessmentId"] for r in self.listing(STATUS)], [made["assessmentId"]])
    self.refused(self.create(STATUS), 404, "assessment_not_found")
    self.refused(self.plugin.get_framework_assessment(self.admin, self.tenant, STATUS, ""), 404, "assessment_not_found")


class TestUnavailableRows(LifecycleFixture):
  def test_the_marker_is_required_and_a_bad_country_is_refused(self):
    row = self.raw_row(DNSC, FA_A)
    ids = [self.tenant, DNSC, FA_A]
    compliance.validate_framework_assessment(row, ids)
    for bad in ({"row_format": 1}, {"row_format": True}, {"row_format": "2"}, {"country": "ro"}, {"country": 7}):
      with self.assertRaises(ValueError, msg=bad):
        compliance.validate_framework_assessment({**row, **bad}, ids)
    with self.assertRaises(ValueError):
      compliance.validate_framework_assessment({k: v for k, v in row.items() if k != "row_format"}, ids)

  def test_a_list_marks_unavailable_rows_and_returns_the_others(self):
    good = self.ok(self.create(STATUS))
    self.raw_row("cyfun.2025", FA_A)
    self.raw_row(DNSC, FA_B, drop=("row_format",))
    self.raw_row(DNSC, FA_C, state="lost")
    self.raw_row(DNSC, None, drop=("row_format",))
    rows = self.ok(self.plugin.list_framework_assessments(self.admin, self.tenant, "", True))
    self.assertEqual([r["assessmentId"] for r in rows if not r.get("unavailable")], [good["assessmentId"]])
    marked = {(r["assessmentId"], r["packId"]): r for r in rows if r.get("unavailable")}
    self.assertEqual({k: v["unavailable_reason"] for k, v in marked.items()}, {
      (FA_A, "cyfun.2025"): "pack_unknown", (FA_B, DNSC): "row_format_old",
      (FA_C, DNSC): "row_invalid", ("default", DNSC): "row_format_old"})
    self.assertEqual(set(marked[(FA_A, "cyfun.2025")]), {"assessmentId", "packId", "unavailable", "unavailable_reason"})
    filtered = self.ok(self.plugin.list_framework_assessments(self.admin, self.tenant, DNSC, False))
    self.assertEqual({r["assessmentId"] for r in filtered}, {FA_B, FA_C, "default"})
    self.ok(self.create(STATUS, name="Another"))  # an unreadable row does not stop a new assessment

  def test_opening_an_unavailable_row_is_not_found(self):
    self.raw_row(DNSC, FA_B, drop=("row_format",))
    self.raw_row("cyfun.2025", FA_A)
    for pack, aid in ((DNSC, FA_B), ("cyfun.2025", FA_A)):
      self.refused(self.plugin.get_framework_assessment(self.admin, self.tenant, pack, aid), 404, "assessment_not_found")
    self.refused(self.save_to(DNSC, FA_B, {"sectoral_requirements": "x"}, 1), 404, "assessment_not_found")

  def test_a_failed_read_is_not_an_unavailable_row(self):
    self.raw_row(DNSC, FA_B)
    reader, calls = self.plugin.chainstore_hget, []

    def down(*, hkey, key):  # the key enumeration and its presence read pass; the row read fails
      if hkey == COMPLIANCE_HKEY:
        calls.append(key)
        if len(calls) > 1:
          raise RuntimeError("store down")
      return reader(hkey=hkey, key=key)
    self.plugin.chainstore_hget = down
    result = self.plugin.list_framework_assessments(self.admin, self.tenant, "", True)
    self.assertFalse(result["success"], result)
    self.assertEqual(len(calls), 2)  # it got as far as `read_row`

  def test_tenant_delete_removes_every_compliance_row_including_unavailable_ones(self):
    self.ok(self.create(STATUS))
    self.raw_row("cyfun.2025", FA_A)
    self.raw_row(DNSC, FA_B, drop=("row_format",))
    self.storage.account("initial", memberships=[])
    self.storage.account("viewer", memberships=[])
    self.storage.account("pentester", memberships=[])
    result = self.plugin.delete_tenant(self.creator, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["assessments"], 3)
    self.assertEqual([v for (hkey, _), v in self.storage.data.items() if hkey == COMPLIANCE_HKEY and v is not None], [])
