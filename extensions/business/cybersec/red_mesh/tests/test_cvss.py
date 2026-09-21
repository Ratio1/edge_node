"""CVSS v3.1 base-score derivation (RM-064 item 3)."""

import unittest

from extensions.business.cybersec.red_mesh.cvss import (
  cvss31_base_score,
  parse_vector,
  severity_band,
)


class TestBaseScore(unittest.TestCase):

  # Published scores: the CVSS v3.1 specification's worked examples plus NVD
  # records, so the arithmetic is checked against numbers this repo did not
  # produce.
  KNOWN = (
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # CVE-2021-41773
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),   # info disclosure
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),   # reflected XSS-ish
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # spec example: XSS
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local privesc
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),   # CVE-2024-6387
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # DoS
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # 3.0 prefix accepted
  )

  def test_matches_published_scores(self):
    for vector, expected in self.KNOWN:
      with self.subTest(vector=vector):
        self.assertEqual(cvss31_base_score(vector), expected)

  def test_temporal_metrics_are_ignored(self):
    base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    self.assertEqual(cvss31_base_score(base + "/E:P/RL:O/RC:C"), 9.8)

  def test_unscorable_inputs_return_none(self):
    for vector in (None, "", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H",
                   "CVSS:3.1/AV:N/AC:L", "not a vector", 7.5):
      with self.subTest(vector=vector):
        self.assertIsNone(cvss31_base_score(vector))
        self.assertIsNone(parse_vector(vector))
    # Well-formed but with an unknown metric value: parses, does not score.
    self.assertIsNone(cvss31_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))


class TestSeverityBand(unittest.TestCase):

  def test_bands_follow_the_specification_table(self):
    for score, band in ((0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"),
                        (6.9, "MEDIUM"), (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"),
                        (10.0, "CRITICAL")):
      with self.subTest(score=score):
        self.assertEqual(severity_band(score), band)
    self.assertIsNone(severity_band(None))


if __name__ == "__main__":
  unittest.main()
