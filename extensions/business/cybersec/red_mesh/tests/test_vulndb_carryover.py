"""RM-168 carry-overs kept honest (RM-169 step 2d): the probe range, the probe-key list, the frozen catalog."""

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, _matches_constraint, entry_applicability
from extensions.business.cybersec.red_mesh.detection_inventory import PRODUCTS_WITHOUT_PROBE
from extensions.business.cybersec.red_mesh.tools import fill_cve_vectors
from extensions.business.cybersec.red_mesh.worker.service.database import _ServiceDatabaseMixin

RED_MESH = Path(__file__).resolve().parents[1]

# sha256 over the sorted catalog rows. The static catalog is frozen (RM-169): `redmesh-vulndb/overlay/curated.json` is its
# master. A change here means the overlay must change with it, then update this pin in the same step.
FROZEN_CATALOG_ROWS = 374
FROZEN_CATALOG_SHA256 = "f42755a9c016c635471163b1957932144eeba561f9c906115add91215db7ee8b"


class TestMysqlProbeRange(unittest.TestCase):

  def test_probe_range_equals_the_catalog_rows(self):
    rows = [e.constraint for e in CVE_DATABASE if e.cve_id == "CVE-2012-2122" and e.product == "mysql"]
    self.assertEqual(len(rows), 3)
    for version in ("5.0.99", "5.1.0", "5.1.62", "5.1.63", "5.5.0", "5.5.23", "5.5.24", "5.5.25", "5.6.0", "5.6.5", "5.6.6", "5.7.0"):
      numbers = tuple(int(x) for x in version.split("."))
      probed = any(low <= numbers < high for low, high in _ServiceDatabaseMixin._MYSQL_CVE_2012_2122_RANGES)
      catalog = any(_matches_constraint(version, c, "mysql") for c in rows)
      self.assertEqual(probed, catalog, version)


class TestProbeKeys(unittest.TestCase):

  def test_products_without_probe_is_what_no_probe_names(self):
    text = "".join(p.read_text() for p in (RED_MESH / "worker").rglob("*.py"))
    unnamed = {e.product for e in CVE_DATABASE if not re.search(r"""['"]%s['"]""" % re.escape(e.product), text)}
    self.assertEqual(set(PRODUCTS_WITHOUT_PROBE), unnamed)


class TestFrozenCatalog(unittest.TestCase):

  def test_static_catalog_is_unchanged(self):
    rows = sorted([e.product, e.constraint, e.cve_id, e.severity.value, e.title, e.cwe_id,
                   int(entry_applicability(e) == "client")] for e in CVE_DATABASE)
    self.assertEqual(len(rows), FROZEN_CATALOG_ROWS)
    digest = hashlib.sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    self.assertEqual(digest, FROZEN_CATALOG_SHA256, "static catalog changed: update redmesh-vulndb overlay, then this pin")


class TestFillCveVectors(unittest.TestCase):

  def test_vector_shape(self):
    ok = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    self.assertTrue(fill_cve_vectors.valid_vector(ok))
    for bad in ("", None, ok + '"\nimport os', 'CVSS:3.1/AV:N"; x="', "CVSS:3.1/AV:N/AC:L", ok + "/" + "A:B/" * 40):
      self.assertFalse(fill_cve_vectors.valid_vector(bad), bad)

  def test_existing_module_is_read_as_data(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = Path(tmp) / "m.py"
      marker = Path(tmp) / "ran"
      path.write_text(
        f"open({str(marker)!r}, 'w').write('x')\n"
        'CVE_CVSS_VECTORS = {"CVE-2020-0001": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "bad": "x"}\n'
        'CVE_WITHOUT_V3 = frozenset({"CVE-2020-0002"})\n')
      vectors, without = fill_cve_vectors.read_module(path)
      self.assertFalse(marker.exists())
    self.assertEqual(list(vectors), ["CVE-2020-0001"])
    self.assertEqual(without, {"CVE-2020-0002"})

  def test_tool_has_no_exec(self):
    self.assertNotIn("exec(", (RED_MESH / "tools" / "fill_cve_vectors.py").read_text())


if __name__ == "__main__":
  unittest.main()
