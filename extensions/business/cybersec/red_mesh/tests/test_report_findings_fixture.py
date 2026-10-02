"""The report-findings contract fixture (RM-118).

One fixture, generated from real probe output in production order, committed
byte-identical here, in Navigator (`__tests__/fixtures/report-findings.v1.json`)
and in the hub (`docs/resources/redmesh/contracts/fixtures/`). This test makes a
backend change that alters what the report receives fail until the fixture is
regenerated — and, with the review rule in the hub's contract note, until all
three copies move together — and pins the backend promises the client checks:
one `finding_id` per finding, credentials masked at source, and the CVSS band
equal to the label unless the label is probe policy.

Regenerate: `REGENERATE=1 .venv/bin/python -m pytest -q <this file>`, then copy
the file to Navigator and the hub.
"""

import json
import os
import re
import unittest

from extensions.business.cybersec.red_mesh.cvss import cvss31_base_score, severity_band
from extensions.business.cybersec.red_mesh.tests.fixtures import report_findings

# Every pair the fixture's fake services accept, in plain text. None may appear.
_PLAINTEXT_PAIRS = ("root:toor", "root:root", "root:password", "admin:admin", "admin:password",
                    "user:user", "test:test", "ftp:ftp", "root:(empty)")


class TestReportFindingsFixture(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.generated = report_findings.render()
    if os.environ.get("REGENERATE") == "1":
      report_findings.FIXTURE_PATH.write_text(cls.generated)
    cls.fixture = json.loads(report_findings.FIXTURE_PATH.read_text())
    cls.findings = cls.fixture["findings"]
    # The promises are checked on what the backend produces now as well as on
    # the committed copy, so a regression fails under its own name rather than
    # only as "regenerate".
    cls.sources = {"committed": cls.fixture, "generated": json.loads(cls.generated)}

  def test_the_committed_fixture_is_what_the_backend_produces(self):
    self.assertEqual(
      report_findings.FIXTURE_PATH.read_text(), self.generated,
      "backend output changed: regenerate with REGENERATE=1 and update the Navigator and hub copies",
    )

  def test_one_finding_id_per_finding(self):
    for source, fixture in self.sources.items():
      ids = [f["finding_id"] for f in fixture["findings"]]
      with self.subTest(source=source):
        self.assertEqual(len(ids), len(set(ids)))

  def test_credentials_are_masked_at_source(self):
    for source, fixture in self.sources.items():
      text = json.dumps(fixture)
      with self.subTest(source=source):
        for pair in _PLAINTEXT_PAIRS:
          self.assertNotIn(pair, text)
        logins = [f for f in fixture["findings"] if "default credential accepted" in f["title"]]
        self.assertTrue(logins)
        for finding in logins:
          self.assertRegex(finding["title"], r"default credential accepted: [\w.-]+:\*\*\*")

  def test_the_cvss_band_matches_the_label_unless_it_is_probe_policy(self):
    for source, fixture in self.sources.items():
      for finding in fixture["findings"]:
        vector = finding.get("cvss_vector") or ""
        if finding.get("severity_source") == "probe_policy" or not vector.startswith("CVSS:3.1/"):
          continue
        with self.subTest(source=source, title=finding["title"]):
          band = severity_band(cvss31_base_score(vector))
          self.assertEqual("INFO" if band == "NONE" else band, finding["severity"])

  def test_it_covers_every_case_the_report_reads(self):
    actions = {f.get("authenticated_action") for f in self.findings}
    self.assertTrue({"performed", "attempted", "not_permitted", "not_applicable"} <= actions)
    self.assertTrue(any("inconclusive" in f["title"] for f in self.findings))
    csrf = [f for f in self.findings if f["probe"] == "_web_test_csrf"]
    self.assertEqual(len(csrf), 2)
    self.assertEqual({f["affected_assets"][0]["parameter"] for f in csrf}, {"/users/sign_in", "/users"})
    self.assertTrue(any(f.get("backport_status") for f in self.findings))
    self.assertTrue(all(f.get("probe_display_name") for f in self.findings))
    self.assertEqual(self.fixture["catch_all_withheld"],
                     {"http://198.51.100.20": [{"path": "/admin", "probe": "_web_test_common"}]})
    self.assertTrue(re.fullmatch(r"198\.51\.100\.\d+", self.fixture["target"]))


if __name__ == "__main__":
  unittest.main()
