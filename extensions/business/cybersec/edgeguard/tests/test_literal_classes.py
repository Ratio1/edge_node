import json
import unittest
from pathlib import Path

from extensions.business.cybersec.edgeguard import literal_classes
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (
  EDGEGUARD_SCHEMA_V0_11,
)

FIXTURES = Path(__file__).parent / "fixtures"
VECTORS_PATH = FIXTURES / "literal_class_vectors.json"


def _load_vectors() -> dict:
  with open(VECTORS_PATH, "r", encoding="utf-8") as handle:
    return json.load(handle)


class LiteralClassesVectorTests(unittest.TestCase):
  """Contract §3.3: guard and validator share one test-vector file with at
  least 40 vectors (20 accept, 20 reject)."""

  @classmethod
  def setUpClass(cls):
    cls.vectors = _load_vectors()

  def test_vector_file_has_at_least_twenty_of_each(self):
    self.assertGreaterEqual(len(self.vectors["accept"]), 20)
    self.assertGreaterEqual(len(self.vectors["reject"]), 20)
    self.assertGreaterEqual(len(self.vectors["accept"]) + len(self.vectors["reject"]), 40)

  def test_every_accept_vector_is_grounded(self):
    for vector in self.vectors["accept"]:
      with self.subTest(literal=vector["literal"], request=vector["request"]):
        result = literal_classes.literal_is_grounded(
          vector["literal"], vector["request"], EDGEGUARD_SCHEMA_V0_11,
        )
        self.assertTrue(result["grounded"], f"{vector}: {result}")
        self.assertEqual(result["class"], vector["class"], f"{vector}: {result}")

  def test_every_reject_vector_is_not_grounded(self):
    for vector in self.vectors["reject"]:
      with self.subTest(literal=vector["literal"], request=vector["request"]):
        result = literal_classes.literal_is_grounded(
          vector["literal"], vector["request"], EDGEGUARD_SCHEMA_V0_11,
        )
        self.assertFalse(result["grounded"], f"{vector}: {result}")
        self.assertEqual(result["class"], vector["class"], f"{vector}: {result}")
        feedback = literal_classes.format_literal_rejection(vector["literal"], result["class"])
        self.assertIn(vector["literal"], feedback)
        self.assertIn(result["class"], feedback)
        self.assertIn("is not in the request", feedback)


class LiteralClassesUnitTests(unittest.TestCase):
  def test_classify_literal_closed_vocabulary(self):
    classification = literal_classes.classify_literal("ipv4", EDGEGUARD_SCHEMA_V0_11)

    self.assertEqual(classification["class"], literal_classes.CLOSED_VOCABULARY)
    self.assertIn(
      {"property": "Indicator.indicator_type", "value": "ipv4"},
      classification["candidates"],
    )

  def test_classify_literal_free_when_not_in_any_vocabulary(self):
    classification = literal_classes.classify_literal("CVE-2024-99999", EDGEGUARD_SCHEMA_V0_11)

    self.assertEqual(classification["class"], literal_classes.FREE)
    self.assertEqual(classification["candidates"], [])

  def test_ip_synonym_is_grounded_without_being_a_substring(self):
    result = literal_classes.literal_is_grounded(
      "ipv4", "Which IP addresses are indicators of compromise?", EDGEGUARD_SCHEMA_V0_11,
    )

    self.assertTrue(result["grounded"])
    self.assertEqual(result["class"], literal_classes.CLOSED_VOCABULARY)
    self.assertIn(result["matched_wording"], ("ip", "ips", "ip address", "ip addresses"))

  def test_free_literal_absent_from_request_is_rejected_and_named(self):
    result = literal_classes.literal_is_grounded(
      "CISA Vuls", "Show me CVE details for this vulnerability.", EDGEGUARD_SCHEMA_V0_11,
    )

    self.assertFalse(result["grounded"])
    self.assertEqual(result["class"], literal_classes.FREE)
    feedback = literal_classes.format_literal_rejection("CISA Vuls", result["class"])
    self.assertEqual(feedback, "Literal 'CISA Vuls' (free) is not in the request.")

  def test_campaign_literal_matches_with_and_without_trailing_suffix(self):
    with_suffix = literal_classes.literal_is_grounded(
      "Operation Sample Campaign", "Tell me about Operation Sample.", EDGEGUARD_SCHEMA_V0_11,
    )
    without_suffix = literal_classes.literal_is_grounded(
      "Operation Sample", "Tell me about Operation Sample Campaign.", EDGEGUARD_SCHEMA_V0_11,
    )

    self.assertTrue(with_suffix["grounded"])
    self.assertTrue(without_suffix["grounded"])

  def test_severity_without_synonym_wording_is_not_grounded(self):
    result = literal_classes.literal_is_grounded(
      "MEDIUM", "Show me every campaign this year.", EDGEGUARD_SCHEMA_V0_11,
    )

    self.assertFalse(result["grounded"])
    self.assertEqual(result["class"], literal_classes.CLOSED_VOCABULARY)

  def test_synonym_wording_does_not_match_a_substring_of_a_longer_word(self):
    """Review finding 3 (S7/Q2): 'relationship'/'shipped' contain the 'ip'
    wording, 'linked' contains 'link', but neither asks about IP addresses
    or URLs; token-boundary matching, not substring, is required."""
    for request in ("Show me every relationship between these campaigns.", "shipped"):
      with self.subTest(request=request):
        result = literal_classes.literal_is_grounded("ipv4", request, EDGEGUARD_SCHEMA_V0_11)
        self.assertFalse(result["grounded"])
    result = literal_classes.literal_is_grounded(
      "url", "Which malware is linked to this campaign?", EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertFalse(result["grounded"])

  def test_closed_vocabulary_literal_itself_does_not_match_inside_a_longer_word(self):
    """'allow' contains 'low', 'highest' contains 'high', 'impacted'
    contains 'impact': the literal-value direct match must also be
    token-boundary, not substring."""
    self.assertFalse(
      literal_classes.literal_is_grounded("LOW", "Would you allow this?", EDGEGUARD_SCHEMA_V0_11)["grounded"],
    )
    self.assertFalse(
      literal_classes.literal_is_grounded(
        "HIGH", "Which CVE has the highest score?", EDGEGUARD_SCHEMA_V0_11,
      )["grounded"],
    )
    self.assertFalse(
      literal_classes.literal_is_grounded(
        "TA0040", "Which sectors were impacted?", EDGEGUARD_SCHEMA_V0_11,
      )["grounded"],
    )

  def test_execution_tactic_wording_is_not_grounded_when_it_names_code_execution(self):
    """'remote code execution' is a CWE/CVE concept, not an ATT&CK Execution
    tactic request; a bare 'Execution tactic' request is unaffected."""
    result = literal_classes.literal_is_grounded(
      "TA0002", "Which CVEs enable remote code execution?", EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertFalse(result["grounded"])

    result = literal_classes.literal_is_grounded(
      "TA0002", "Which techniques belong to the Execution tactic?", EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertTrue(result["grounded"])

  def test_grounded_properties_names_the_specific_property_for_a_synonym_match(self):
    result = literal_classes.literal_is_grounded(
      "ipv4", "Which IP addresses are indicators of compromise?", EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertEqual(result["grounded_properties"], ["Indicator.indicator_type"])

    result = literal_classes.literal_is_grounded(
      "CISA Vuls", "Show me CVE details for this vulnerability.", EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertEqual(result["grounded_properties"], [])

  def test_index_builders_are_cached_by_artifact_identity(self):
    # Review finding Q8: repeat calls with the same (process-lifetime)
    # artifact object must not rescan it every time.
    first = literal_classes.build_closed_vocabulary_index(EDGEGUARD_SCHEMA_V0_11)
    second = literal_classes.build_closed_vocabulary_index(EDGEGUARD_SCHEMA_V0_11)
    self.assertIs(first, second)
    first_synonyms = literal_classes.build_synonym_index(EDGEGUARD_SCHEMA_V0_11)
    second_synonyms = literal_classes.build_synonym_index(EDGEGUARD_SCHEMA_V0_11)
    self.assertIs(first_synonyms, second_synonyms)
    # A different artifact object is never served the other's cached result.
    other_artifact = {"vocabularies": {"kind": ["fixture"]}}
    other = literal_classes.build_closed_vocabulary_index(other_artifact)
    self.assertIsNot(other, first)
    self.assertEqual(other, {"fixture": [{"property": "kind", "value": "fixture"}]})

  def test_module_has_no_edge_node_imports(self):
    """Contract: `literal_classes.py` is stdlib-only, no edge_node imports,
    so the hub validator can vendor it by sha (EGM-059 phase 5)."""
    source = Path(literal_classes.__file__).read_text(encoding="utf-8")
    for line in source.splitlines():
      stripped = line.strip()
      if stripped.startswith("import ") or stripped.startswith("from "):
        self.assertNotIn("edgeguard", stripped, stripped)
        self.assertFalse(stripped.startswith("from ."), stripped)


if __name__ == "__main__":
  unittest.main()
