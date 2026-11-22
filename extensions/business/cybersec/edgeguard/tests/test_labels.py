import unittest

from extensions.business.cybersec.edgeguard import explain_notation, explain_selection
from extensions.business.cybersec.edgeguard.edgeguard_api import _node_caption
from extensions.business.cybersec.edgeguard.egx2 import field_catalog
from extensions.business.cybersec.edgeguard.labels import primary_label

# Sector nodes carry the sector label first: the node type is the schema label.
SECTOR_FIRST = {"labels": ["Energy", "ThreatActor"], "properties": {}}


class PrimaryLabelTests(unittest.TestCase):
  def test_schema_label_beats_a_leading_sector_label(self):
    self.assertEqual(primary_label(["Energy", "Finance", "ThreatActor"]), "ThreatActor")

  def test_unknown_labels_fall_back_to_the_first_and_empty_to_none(self):
    self.assertEqual(primary_label(["Sector"]), "Sector")
    self.assertIsNone(primary_label([]))
    self.assertIsNone(primary_label(None))


class CallSiteTests(unittest.TestCase):
  def test_every_label_call_site_uses_the_schema_label(self):
    self.assertEqual(field_catalog.label_of(SECTOR_FIRST), "ThreatActor")
    self.assertEqual(explain_notation._label_of(SECTOR_FIRST), "ThreatActor")
    self.assertEqual(explain_selection._label_of(SECTOR_FIRST), "ThreatActor")
    self.assertEqual(_node_caption(SECTOR_FIRST["labels"], {}), "ThreatActor")

  def test_no_labels_keep_the_old_placeholders(self):
    self.assertEqual(field_catalog.label_of({}), "?")
    self.assertEqual(_node_caption([], {}), "Entity")
