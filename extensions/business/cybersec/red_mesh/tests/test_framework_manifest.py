"""RM-182 phase 3: the applicability manifest, its schema check, the file-hash guard and the pack and
text schema checks. Synthetic packs come from `fixtures/framework_packs/` and are injected, never shipped.
"""
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from extensions.business.cybersec.red_mesh.references.framework_packs import FrameworkPackError
from extensions.business.cybersec.red_mesh.services.framework_scoring import SCORERS

SHIPPED = Path(packs.__file__).parent / "static"
FIXTURES = Path(__file__).parent / "fixtures" / "framework_packs"
DNSC = "ro.dnsc.o1-2026"


def sha(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def hash_mismatches(directory, manifest):
  """Pack and text files whose SHA-256 differs from the manifest (a text file per language)."""
  bad = []
  for pack in manifest["packs"]:
    pid = pack["pack_id"]
    if sha(directory / f"framework-pack.{pid}.json") != pack["pack_sha256"]:
      bad.append(f"pack:{pid}")
    for language, digest in pack["text_sha256"].items():
      path = next((p for p in (directory / f"framework-text.{pid}.{language}.json",
                               directory / f"framework-text.{pid}.json") if p.is_file()), None)
      if path is None or sha(path) != digest:
        bad.append(f"text:{pid}:{language}")  # a missing file counts as a mismatch
  return bad


def static_dir(testcase, *, with_fixtures=True, edit=None):
  """A temp static dir with the shipped DNSC pack, and the fixture packs when asked; `edit(manifest)`
  may change the merged manifest. Patches the loader onto it and clears the caches on cleanup."""
  tmp = Path(tempfile.mkdtemp())
  testcase.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
  for source in (SHIPPED, FIXTURES) if with_fixtures else (SHIPPED,):
    for path in source.glob("framework-*.json"):
      if path.name != "framework-manifest.json":
        shutil.copy(path, tmp / path.name)
  manifest = json.loads((SHIPPED / "framework-manifest.json").read_text())
  if with_fixtures:
    manifest["packs"] += json.loads((FIXTURES / "framework-manifest.json").read_text())["packs"]
  if edit:
    edit(manifest)
  (tmp / "framework-manifest.json").write_text(json.dumps(manifest))
  patcher = patch.object(packs, "_STATIC_DIR", tmp)
  patcher.start()
  testcase.addCleanup(patcher.stop)
  testcase.addCleanup(packs.reset_framework_caches)
  packs.reset_framework_caches()
  return tmp


class TestShippedManifest(unittest.TestCase):
  def setUp(self):
    packs.reset_framework_caches()

  def test_pack_ids_and_the_dnsc_entry_come_from_the_manifest(self):
    manifest = packs.load_manifest()
    self.assertEqual((manifest["schema"], manifest["manifest_version"]), ("redmesh.framework_manifest.v1", 4))
    self.assertEqual(packs.list_framework_pack_ids(), (DNSC, "eu.ec.ir-2024-2690", "us.nist.csf-2.0"))
    dnsc = packs.manifest_pack(DNSC)
    self.assertEqual((dnsc["version"], dnsc["status"], dnsc["scoring"], dnsc["languages"]), (2, "active", "maturity_two_axis.v1", ["ro"]))
    self.assertEqual(dnsc["rules"]["entity_fields"], ["dnsc_unique_id", "external_supplier"])
    self.assertEqual(dnsc["entries"][0]["country"], "RO")
    self.assertIs(dnsc["licence"]["ship_text"], True)
    self.assertIs(packs.pack_rules(packs.load_framework_pack(DNSC)), dnsc["rules"])

  def test_shipped_files_match_the_manifest_hashes(self):
    self.assertEqual(hash_mismatches(SHIPPED, packs.load_manifest()), [])

  def test_a_changed_pack_or_text_file_without_a_new_id_fails_the_hash_check(self):
    tmp = static_dir(self, with_fixtures=False)
    manifest = packs.load_manifest()
    self.assertEqual(hash_mismatches(tmp, manifest), [])
    for name, expected in ((f"framework-pack.{DNSC}.json", f"pack:{DNSC}"), (f"framework-text.{DNSC}.json", f"text:{DNSC}:ro")):
      with self.subTest(name):
        path = tmp / name
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        self.assertEqual(hash_mismatches(tmp, manifest), [expected])
        path.write_bytes(original)

  def test_shipped_pack_and_text_hashes_match_an_independent_pin(self):
    # A literal table, kept apart from the manifest: editing a pack or text file and its manifest hash
    # together (same id and version) fails here until the pin is changed on purpose, with a version bump.
    pinned = {
      "pack:ro.dnsc.o1-2026@2": "0b9e8c60011be5fbc447f5a89933586db750273f6752771df0fafb94d88e6a62",
      "text:ro.dnsc.o1-2026@2": "92fe6d9ed20ef5dfd63a32ad4dab375bcf3e991a749f4383d27bc74bbaeff8ec",
      "pack:eu.ec.ir-2024-2690@2": "3ff9e6a1bf2790e74dd597710a0091654f31212707c3046f7e5a7bfbd8849e05",
      "text:eu.ec.ir-2024-2690@2": "25c2012253fa19dde2495c1bea396876fec9fb03ff3bf852d760b1402254b9da",
      "pack:us.nist.csf-2.0@2": "c8649acc218f1cc1ffdc5176c08bca96775112bea9eea54c235da793f4c10e92",
      "text:us.nist.csf-2.0@2": "9d40c0cf5a3c849c97b41666d65d82f835555f8e3ae3068d23f0017f4a57e71d"}
    actual = {}
    for pack in packs.load_manifest()["packs"]:
      pid, version = pack["pack_id"], pack["version"]
      actual[f"pack:{pid}@{version}"] = sha(SHIPPED / f"framework-pack.{pid}.json")
      actual[f"text:{pid}@{version}"] = sha(SHIPPED / f"framework-text.{pid}.json")
    self.assertEqual(actual, pinned)

  def test_fixture_packs_match_their_manifest_hashes(self):
    self.assertEqual(hash_mismatches(FIXTURES, json.loads((FIXTURES / "framework-manifest.json").read_text())), [])


class TestManifestSchema(unittest.TestCase):
  def test_bad_manifest_edits_are_refused_and_each_error_names_the_offending_key(self):
    entry = lambda m: m["packs"][0]["entries"][0]
    cases = [  # (edit, key the error names; None when only the refusal is asserted)
      (lambda m: m.update(schema="redmesh.framework_manifest.v2"), None),
      (lambda m: m.update(manifest_version="1"), None),
      (lambda m: m["packs"].append(dict(m["packs"][0])), None),
      (lambda m: m["packs"][0].update(status="draft"), None),
      (lambda m: m["packs"][0].update(version="1"), None),
      (lambda m: m["packs"][0].pop("supersedes"), None),
      (lambda m: m["packs"][0].pop("title"), None),
      (lambda m: m["packs"][0]["licence"].pop("ship_text"), None),
      (lambda m: m["packs"][0]["rules"].pop("entity_fields"), None),
      (lambda m: m["packs"][0]["rules"].update(signoff_required="yes"), None),
      (lambda m: entry(m).update(jurisdiction="EU"), None),  # an entry naming both country and jurisdiction
      (lambda m: entry(m).update(country=None), None),  # neither
      (lambda m: entry(m).update(country=None, jurisdiction="US"), None),
      (lambda m: entry(m).pop("verified_by"), None),
      (lambda m: m["packs"][0].update(pack_schema="x.v9"), "pack_schema"),
      (lambda m: m["packs"][0].update(text_schema="x.v9"), "text_schema"),
      (lambda m: m["packs"][0]["rules"].update(exports="json"), "rules.exports"),
      (lambda m: m["packs"][0]["rules"].pop("signoff_required"), "rules.signoff_required"),
      (lambda m: m["packs"][0]["rules"].update(entity_fields=["made_up"]), "rules.entity_fields"),
      (lambda m: m["packs"][0]["licence"].pop("id"), "licence.id"),
    ]
    for bad_title in (None, "", 5, "x" * 121):  # a display title of 1..120 characters
      cases.append((lambda m, t=bad_title: m["packs"][0].update(title=t), None))
    for number, (edit, key) in enumerate(cases):
      with self.subTest(case=number, key=key):
        static_dir(self, with_fixtures=False, edit=edit)
        with self.assertRaisesRegex(FrameworkPackError, f"bad or missing {key}" if key else ""):
          packs.load_manifest()
        packs.reset_framework_caches()

  def test_an_unknown_pack_is_refused(self):
    static_dir(self, with_fixtures=False)
    for call in (packs.manifest_pack, packs.load_framework_pack, packs.load_framework_text):
      with self.assertRaises(FrameworkPackError):
        call("nope")


class TestPackAndTextChecks(unittest.TestCase):
  def setUp(self):
    self.tmp = static_dir(self)

  def rewrite(self, name, change):
    path = self.tmp / name  # a pack, text or manifest file
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data))
    packs.reset_framework_caches()

  def test_an_unknown_scorer_fails_at_pack_load(self):
    self.rewrite("framework-pack.test.cyfun-like.v1.json", lambda d: d.update(scoring="nope.v1"))
    self.rewrite("framework-manifest.json", lambda d: d["packs"][-1].update(scoring="nope.v1"))
    with self.assertRaisesRegex(FrameworkPackError, "unknown scoring"):
      packs.load_framework_pack("test.cyfun-like.v1")

  def test_a_pack_file_scoring_that_differs_from_the_manifest_is_refused(self):
    self.rewrite("framework-pack.test.cyfun-like.v1.json", lambda d: d.update(scoring="test_status.v1"))
    with self.assertRaisesRegex(FrameworkPackError, "!= manifest"):
      packs.load_framework_pack("test.cyfun-like.v1")

  def test_the_loader_checks_the_generic_keys_and_the_scorer_checks_the_rest(self):
    with patch.dict(SCORERS, {"test_status.v1": SimpleNamespace(check_pack=lambda pack, text: None)}):
      self.assertEqual(packs.pack_levels(packs.load_framework_pack("test.status-ids.v1")), ())
    self.rewrite("framework-pack.test.cyfun-like.v1.json", lambda d: d.pop("catalogue"))
    with self.assertRaisesRegex(FrameworkPackError, "missing keys"):
      packs.load_framework_pack("test.cyfun-like.v1")
    self.rewrite("framework-pack.test.cyfun-like.v1.json", lambda d: d.update(catalogue="x", thresholds={}))
    with self.assertRaisesRegex(FrameworkPackError, "thresholds"):
      packs.load_framework_pack("test.cyfun-like.v1")

  def test_a_pack_with_levels_needs_every_entry_level_in_them(self):
    self.rewrite("framework-pack.test.cyfun-like.v1.json", lambda d: d["controls"][0].update(entry_level="basic"))
    with self.assertRaisesRegex(FrameworkPackError, "entry level"):
      packs.load_framework_pack("test.cyfun-like.v1")

  def test_generic_text_hierarchy_of_any_depth_and_optional_per_control_text(self):
    text = packs.load_framework_text("test.cyfun-like.v1")
    self.assertEqual([n["id"] for n in text["hierarchy"]], ["TC", "TC.A", "TC.A-01", "TC.B"])
    self.assertEqual(set(text["controls"]), {"TC.A-01.1", "TC.B-01.1"})  # three controls carry no text

  def test_text_ids_must_be_pack_ids_and_the_hierarchy_must_be_a_tree(self):
    name = "framework-text.test.cyfun-like.v1.json"
    for change, pattern in ((lambda d: d["controls"].update(ZZ={"requirement": "x"}), "not all pack ids"),
                            (lambda d: d["hierarchy"].append({"id": "TC", "parent": None, "label": "dup"}), "unique"),
                            (lambda d: d["hierarchy"][0].update(parent="TC.A"), "cycle"),
                            (lambda d: d["hierarchy"][1].update(parent="GONE"), "unknown parent")):
      with self.subTest(pattern):
        self.rewrite(name, change)
        with self.assertRaisesRegex(FrameworkPackError, pattern):
          packs.load_framework_text("test.cyfun-like.v1")
        shutil.copy(FIXTURES / name, self.tmp / name)

  def test_the_scorer_checks_the_maturity_scale_when_a_text_file_carries_it(self):
    self.rewrite("framework-text.test.cyfun-like.v1.json", lambda d: d.update(maturity_levels=[{"value": 1}]))
    with self.assertRaisesRegex(FrameworkPackError, "maturity_levels"):
      packs.load_framework_text("test.cyfun-like.v1")

  def test_no_text_file_is_accepted_only_when_the_licence_ships_no_text(self):
    with patch.dict(SCORERS, {"test_status.v1": SimpleNamespace(check_pack=lambda pack, text: None)}):
      self.assertIsNone(packs.load_framework_text("test.status-ids.v1"))
    (self.tmp / "framework-text.test.cyfun-like.v1.json").unlink()
    packs.reset_framework_caches()
    with self.assertRaisesRegex(FrameworkPackError, "missing pack file"):
      packs.load_framework_text("test.cyfun-like.v1")


if __name__ == "__main__":
  unittest.main()
