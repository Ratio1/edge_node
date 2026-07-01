import unittest

from extensions.business.cybersec.red_mesh.edgeguard_cypher_guard import (
  SCHEMA_VERSION,
  analyze_generated_cypher,
  build_empty_result_broadening_cypher,
  build_direct_cypher_system_prompt,
  build_schema_prompt_context,
  build_schema_correction_prompt,
  extract_schema_tokens,
  normalize_user_literal_text,
  unsupported_temporal_behavior,
)


class EdgeGuardCypherGuardTests(unittest.TestCase):
  def test_accepts_valid_read_only_schema_query(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10"
    )

    self.assertTrue(analysis["accepted"])
    self.assertEqual(
      analysis["accepted_cypher"],
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
    )

  def test_rejects_invented_schema_tokens(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:InternetFacing) WHERE i.cve IS NOT NULL RETURN i.hostname AS hostname"
    )

    self.assertFalse(analysis["accepted"])
    self.assertEqual(analysis["schema_unknown"]["labels"], ["InternetFacing"])
    self.assertEqual(analysis["schema_unknown"]["properties"], ["cve"])
    self.assertIn("Unknown labels: InternetFacing", analysis["validation_feedback"])

  def test_rejects_write_cypher_and_semicolon(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator) SET i.value = 'x'; RETURN i"
    )

    self.assertFalse(analysis["accepted"])
    self.assertFalse(analysis["read_only_static"])
    self.assertIn("semicolon", analysis["validation_feedback"])

  def test_rejects_parameter_placeholders(self):
    analysis = analyze_generated_cypher(
      "MATCH (d:Device) WHERE d.device_id = $device_id RETURN d.device_id AS device_id"
    )

    self.assertFalse(analysis["accepted"])
    self.assertTrue(analysis["forbidden"]["parameter_ref"])
    self.assertIn("Inline the concrete user value", analysis["validation_feedback"])

  def test_schema_extractor_ignores_labels_function_property(self):
    tokens = extract_schema_tokens("MATCH (n) RETURN labels(n) AS labels, count(n) AS count")

    self.assertEqual(tokens["properties"], set())

  def test_empty_result_broadening_uses_first_allowed_label_and_relationship(self):
    broadened = build_empty_result_broadening_cypher(
      "MATCH (i:Indicator)-[:INDICATES]->(a:Alert) WHERE i.value = 'x' RETURN i.value AS value"
    )

    self.assertEqual(
      broadened,
      {
        "cypher": "MATCH p=(n:Indicator)-[:INDICATES]-() RETURN p LIMIT 5",
        "strategy": "first_allowed_label_first_allowed_relationship_type",
      },
    )

  def test_empty_result_broadening_requires_label_and_relationship_pair(self):
    self.assertIsNone(
      build_empty_result_broadening_cypher("MATCH (i:Indicator) RETURN i.value AS value")
    )

  def test_prompts_include_schema_and_output_contract(self):
    prompt = build_direct_cypher_system_prompt()

    self.assertIn("Return exactly one Cypher query and nothing else.", prompt)
    self.assertIn("Indicator", prompt)
    self.assertIn("EXPLOITS", prompt)
    self.assertIn("confidence_score", prompt)

  def test_v09_schema_prompt_includes_temporal_and_graph_guidance(self):
    prompt = build_schema_prompt_context()

    self.assertEqual(SCHEMA_VERSION, "edgeguard-cypher-schema-v0.9")
    self.assertIn("CVSSv30", prompt)
    self.assertIn("CVSSv40", prompt)
    self.assertIn("(i:Indicator)-[:TARGETS]->(s:Sector)", prompt)
    self.assertIn("(c:CVE)-[:AFFECTS]->(s:Sector)", prompt)
    self.assertIn("Sector guidance: use `Sector.name`", prompt)
    self.assertIn("Temporal predicates: supported only on whitelisted properties", prompt)
    self.assertIn("last_updated", prompt)
    self.assertIn("recently=P30D", prompt)
    self.assertNotIn("Unsupported temporal predicates", prompt)

  def test_temporal_behavior_uses_whitelisted_windows(self):
    behavior = unsupported_temporal_behavior()

    self.assertIn("supported_for_whitelisted_properties", behavior)
    self.assertIn("last_week=P7D", behavior)
    self.assertIn("whitelisted temporal property", behavior)

  def test_accepts_whitelisted_temporal_property(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator) WHERE datetime(i.last_updated) >= datetime() - duration('P7D') RETURN i LIMIT 10"
    )

    self.assertTrue(analysis["accepted"])

  def test_rejects_hallucinated_temporal_property(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator) WHERE i.timestamp >= datetime() - duration('P7D') RETURN i LIMIT 10"
    )

    self.assertFalse(analysis["accepted"])
    self.assertEqual(analysis["invented_temporal_properties"], ["timestamp"])

  def test_normalizes_common_user_literals(self):
    normalized = normalize_user_literal_text("  hxxps://evil[.]example/path and cve-2024-12345. ")

    self.assertEqual(normalized, "https://evil.example/path and CVE-2024-12345")

  def test_correction_prompt_includes_feedback(self):
    prompt = build_schema_correction_prompt(
      original_user_prompt="Show recent indicators",
      rejected_cypher="MATCH (i:Indicator) WHERE i.timestamp IS NOT NULL RETURN i.value AS value",
      validation_feedback="Unknown properties: timestamp",
      retry_index=1,
      retry_limit=2,
    )

    self.assertIn("Schema correction attempt 1 of 2", prompt)
    self.assertIn("Unknown properties: timestamp", prompt)
    self.assertIn("Return only the corrected read-only Cypher query", prompt)
