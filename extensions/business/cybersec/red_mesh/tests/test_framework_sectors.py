"""Reviewed taxonomy and entry coverage: unknown is never a positive sector match."""
import unittest
from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from .test_framework_manifest import static_dir, FrameworkPackError


class TestFrameworkSectors(unittest.TestCase):
  def test_reviewed_taxonomy_and_mappings(self):
    taxonomy = packs.load_manifest()["sector_taxonomy"]
    self.assertEqual((taxonomy["id"], taxonomy["version"]), ("redmesh.nis2-sectors", 1))
    sectors = taxonomy["sectors"]
    self.assertEqual(len({s["code"] for s in sectors}), 18)
    self.assertEqual([s["source_location"] for s in sectors],
      ["I." + str(i) for i in range(1,12)] + ["II." + str(i) for i in range(1,8)])
    for sector in sectors:
      self.assertTrue(sector["label"] and sector["title"])
    for pid in ("ro.dnsc.o1-2026", "us.nist.csf-2.0"):
      self.assertEqual(packs.manifest_pack(pid)["entries"][0]["sector_coverage"], "cross_sector")
    ir = packs.manifest_pack("eu.ec.ir-2024-2690")["entries"][0]
    self.assertEqual(ir["sector_coverage"], "listed")
    self.assertEqual(ir["sectors"], ["rm.nis2.digital-infrastructure", "rm.nis2.ict-service-management", "rm.nis2.digital-providers"])
    self.assertIn("provider", ir["sector_scope_note"])

  def test_legacy_empty_sectors_normalize_unknown(self):
    def edit(m):
      e=m["packs"][0]["entries"][0]
      e.pop("sector_coverage")
      e.pop("sector_taxonomy")
    static_dir(self, edit=edit)
    self.assertEqual(packs.load_manifest()["packs"][0]["entries"][0]["sector_coverage"], "unknown")

  def test_bad_coverage_and_taxonomy_refused(self):
    for changes in ({"sectors": ["bad"]}, {"sector_coverage": "listed", "sectors": []},
                    {"sector_coverage": "all"}, {"sectors": ["rm.nis2.energy"]},
                    {"sector_taxonomy": {"id": "redmesh.nis2-sectors", "version": True}}):
      with self.subTest(changes=changes):
        with self.assertRaises(FrameworkPackError):
          static_dir(self, edit=lambda m: m["packs"][0]["entries"][0].update(changes))
          packs.load_manifest()

  def test_malformed_taxonomy_and_duplicate_listed_codes_refused(self):
    for update in (lambda t: t.update(version=True), lambda t: t["sectors"].pop(),
                   lambda t: t["sectors"][0].update(label=""),
                   lambda t: t["sectors"][0].update(code="official-code"),
                   lambda t: t["sectors"][1].update(code=t["sectors"][0]["code"])):
      with self.subTest(update=update):
        with self.assertRaises(FrameworkPackError):
          static_dir(self, edit=lambda m: update(m["sector_taxonomy"]))
          packs.load_manifest()
    with self.assertRaises(FrameworkPackError):
      static_dir(self, edit=lambda m: m["packs"][1]["entries"][0].update(sectors=["rm.nis2.energy"] * 2))
      packs.load_manifest()
