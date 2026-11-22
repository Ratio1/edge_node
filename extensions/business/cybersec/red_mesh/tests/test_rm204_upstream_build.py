"""RM-204 phase 1: the upstream-build signal (`Apache/x (Unix)`) and the `upstream_build` reason."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.vulndb.reader import load_vulndb
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.service import common

from .test_probes import DummyOwner
from .test_vulndb_reader import make_db

# (cve, product, constraint, source, confidence, reason, platform_dependent, client_side)
ROWS = [
  ("CVE-2030-1001", "apache", "<2.5", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-1002", "apache", "<2.5", "nvd", "firm", "nvd_range", 1, 0),
  ("CVE-2030-1003", "apache", "<2.5", "nvd", "tentative", "nvd_exact", 0, 0),
  ("CVE-2030-1004", "apache", "<2.5", "nvd", "tentative", "inferred_version", 0, 0),
  ("CVE-2030-1005", "openssl", "<9", "nvd", "firm", "nvd_range", 0, 0),
  ("CVE-2030-1006", "mysql", "<9", "nvd", "firm", "nvd_range", 0, 0),
]
UP = "Apache/2.4.49 (Unix)"


class MarkerTests(unittest.TestCase):
  def test_positive_forms(self):
    for server in (UP, "Apache/2.4.49 (Unix) OpenSSL/1.1.1d PHP/7.4.3-4ubuntu2.19 mod_perl/2.0", " Apache/2.4.49 (Unix) "):
      self.assertTrue(common._APACHE_UPSTREAM_RE.match(server), server)

  def test_negative_forms(self):
    for server in (
      "Apache/2.4.49 (Debian)", "Apache/2.4.49 (Ubuntu)", "Apache/2.4.49 (CentOS)", "Apache/2.4.49 (Red Hat)",
      "Apache/2.4.49 (Fedora)", "Apache/2.4.49 (Win64)", "Apache/2.4.49 (Unix) HP-UX_Apache-based_Web_Server",
      "Apache/2.4.49 (Unix) Debian", "Apache/2.4.49", "Apache", "nginx/1.18.0 (Unix)",
      "Apache/2.4.49 (Unix) (Ubuntu)", "HP-UX_Apache/2.4.49 (Unix)",
      "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix)", "Oracle HTTP Server Powered by Apache/1.3.12 (Unix)",
      "Apache/2.2.22 (Debian) Apache/2.4.49 (Unix)", "Apache/2.4.29 (Ubuntu), Apache/2.4.29 (Unix)",
      "Apache/2.4.49 (Unix) mod_x/(Debian)",
    ):
      self.assertIsNone(common._APACHE_UPSTREAM_RE.match(server), server)


def use_generated_reader(case):
  """Load the ROWS build as the `generated` reader for one test; both are undone on cleanup."""
  case.addCleanup(cve_db.set_vulndb_reader, None)
  tmp = tempfile.TemporaryDirectory()
  case.addCleanup(tmp.cleanup)
  db, pin = Path(tmp.name) / "vulndb-aaaaaaaaaaaa.sqlite", Path(tmp.name) / "vulndb-aaaaaaaaaaaa.json"
  make_db(db, rows=ROWS, build_id="vulndb-aaaaaaaaaaaa")
  pin.write_text(json.dumps({"build_id": "vulndb-aaaaaaaaaaaa", "built_at": "2026-11-14",
                             "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}))
  reader, keys = load_vulndb("generated", db, pin)
  case.assertIsNone(keys["vulndb_load_error"])
  cve_db.set_vulndb_reader(reader)


class ReasonTests(unittest.TestCase):
  def use(self):
    use_generated_reader(self)

  def found(self, product, version, **kw):
    return {f.cve[0]: f for f in cve_db.check_cves(product, version, **kw) if f.cve}

  def pairs(self, found):
    return {k: (f.confidence, f.confidence_reason) for k, f in found.items()}

  def test_upstream_build_is_firm_and_keeps_other_tentative_reasons(self):
    self.use()
    found = self.found("apache", "2.4.49", upstream_build=True)
    self.assertEqual(self.pairs(found), {
      "CVE-2030-1001": ("firm", "upstream_build"),
      "CVE-2030-1002": ("tentative", "platform_dependent"),
      "CVE-2030-1003": ("tentative", "nvd_exact"),
      "CVE-2030-1004": ("tentative", "inferred_version"),
    })
    firm = found["CVE-2030-1001"]
    self.assertEqual(firm.backport_status, cve_db.BACKPORT_UPSTREAM_BUILD)
    self.assertIn("upstream build with no distribution package", firm.description)
    self.assertNotIn("false positive", firm.description)

  def test_local_vector_still_wins(self):
    match = type("M", (), {"confidence": "firm", "reason": "nvd_range", "platform_dependent": 0, "cvss": (
      {"version": "3.1", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 7.0, "source": "nvd"},)})()
    self.assertEqual(cve_db._confidence_reason(cve_db.BACKPORT_UPSTREAM_BUILD, match, "apache"),
                     ("tentative", "local_vector"))

  def test_banner_unverified_still_wins(self):
    self.assertEqual(cve_db._confidence_reason(cve_db.BACKPORT_UPSTREAM_BUILD, None, "apache", False),
                     ("tentative", "banner_unverified"))

  def test_without_the_marker_rows_stay_banner_only(self):
    self.use()
    found = self.found("apache", "2.4.49")
    self.assertEqual(self.pairs(found)["CVE-2030-1001"], ("tentative", "banner_only"))
    self.assertIn("may be a false positive", found["CVE-2030-1001"].description)

  def test_a_bare_mysql_version_is_unchanged(self):
    self.use()
    self.assertEqual(self.pairs(self.found("mysql", "5.1.73")), {"CVE-2030-1006": ("tentative", "banner_only")})

  def test_a_distro_package_ignores_the_marker(self):
    self.use()
    package = cve_db.DistroPackage("debian", "2.4.49", "1")
    found = self.found("apache", "2.4.49", package=package, upstream_build=True)
    self.assertEqual(found["CVE-2030-1001"].backport_status, cve_db.BACKPORT_UNKNOWN)
    self.assertEqual(self.pairs(found)["CVE-2030-1001"], ("tentative", "backport_unknown"))

  def test_static_is_unchanged(self):
    for f in cve_db.check_cves("apache", "2.4.49", upstream_build=True):
      self.assertEqual((f.confidence, f.confidence_reason), ("tentative", "banner_only"))
      self.assertEqual(f.backport_status, cve_db.BACKPORT_UNKNOWN_NO_PACKAGE)


class CallSiteTests(unittest.TestCase):
  def setUp(self):
    use_generated_reader(self)

  def reasons(self, probe, server, port):
    worker = PentestLocalWorker(owner=DummyOwner(), target="example.com", job_id="j", initiator="i",
                                local_id_prefix="1", worker_target_ports=[port])
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    resp = MagicMock(status_code=200, reason="OK", headers={"Server": server}, text="<html></html>")
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "requests.get", return_value=resp), patch(base + "requests.request", side_effect=Exception("skip")):
      result = getattr(worker, probe)("example.com", port)
    return {f["cve"][0]: (f["confidence"], f["confidence_reason"]) for f in result["findings"] if f.get("cve")}

  def check(self, probe, port):
    up = self.reasons(probe, UP + " OpenSSL/1.1.1", port)
    self.assertEqual(up["CVE-2030-1001"], ("firm", "upstream_build"))
    self.assertEqual(up["CVE-2030-1002"], ("tentative", "platform_dependent"))
    self.assertEqual(up["CVE-2030-1005"], ("tentative", "banner_only"))  # co-disclosed OpenSSL unchanged
    down = self.reasons(probe, "Apache/2.4.49 (Debian)", port)
    self.assertEqual(down["CVE-2030-1001"], ("tentative", "banner_only"))

  def test_http_call_site(self):
    self.check("_service_info_http", 80)

  def test_https_call_site(self):
    self.check("_service_info_https", 443)


if __name__ == "__main__":
  unittest.main()
