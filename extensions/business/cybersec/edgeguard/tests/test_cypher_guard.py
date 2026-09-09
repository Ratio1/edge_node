import unittest

from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (
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

  def test_schema_extractor_ignores_dot_tokens_inside_string_literals(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator) WHERE i.value = 'gait.com' RETURN i LIMIT 10"
    )

    self.assertTrue(analysis["accepted"])
    self.assertNotIn("com", analysis["schema_unknown"].get("properties", []))

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
    self.assertIn("Never add a literal value or WHERE filter", prompt)
    self.assertIn("Indicator", prompt)
    self.assertIn("EXPLOITS", prompt)
    self.assertIn("confidence_score", prompt)

  def test_v010_schema_prompt_includes_temporal_and_graph_guidance(self):
    prompt = build_schema_prompt_context()

    self.assertEqual(SCHEMA_VERSION, "edgeguard-cypher-schema-v0.10")
    self.assertIn("CVSSv30", prompt)
    self.assertIn("CVSSv40", prompt)
    self.assertIn("(i:Indicator)-[:TARGETS]->(s:Sector)", prompt)
    self.assertIn("(c:CVE)-[:AFFECTS]->(s:Sector)", prompt)
    self.assertIn("Sector guidance: use `Sector.name`", prompt)
    self.assertIn("Temporal predicates: supported only on whitelisted properties", prompt)
    self.assertIn("last_updated", prompt)
    self.assertIn("published", prompt)
    self.assertIn("active", prompt)
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

  def test_accepts_v010_graph_intent_properties(self):
    analysis = analyze_generated_cypher(
      "MATCH (i:Indicator)-[:EXPLOITS]->(c:CVE) "
      "WHERE i.active = true AND c.published >= '2025-01-01' RETURN i, c LIMIT 10"
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


class EdgeGuardExecutionSafetyTests(unittest.TestCase):
  """EG-013 execution-safety denial classes and their positive regressions."""

  def _analysis(self, cypher, **kwargs):
    return analyze_generated_cypher(cypher, **kwargs)

  def assert_rejected(self, cypher, fragment, **kwargs):
    analysis = self._analysis(cypher, **kwargs)
    self.assertFalse(analysis["accepted"], cypher)
    feedback = (analysis.get("execution_safety_error") or "") + (analysis.get("read_only_error") or "")
    self.assertIn(fragment, feedback, cypher)

  def test_rejects_every_call_form(self):
    cases = [
      "MATCH (n:Indicator) CALL custom.write(n) RETURN n LIMIT 5",
      "MATCH (n:Indicator) OPTIONAL CALL custom.read(n) RETURN n LIMIT 5",
      "MATCH (n:Indicator) CALL { WITH n RETURN n AS m } RETURN m LIMIT 5",
      "MATCH (n:Indicator) call dbms.components() YIELD name RETURN n LIMIT 5",
      "WITH 1 AS x CALL apoc.load.json('x') YIELD value RETURN value LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "CALL")

  def test_rejects_catalog_procedure_start(self):
    analysis = self._analysis("CALL db.labels() YIELD label RETURN label")
    self.assertFalse(analysis["accepted"])
    self.assertIn("read-only Cypher clause", analysis["read_only_error"])

  def test_call_inside_string_literal_is_not_a_call(self):
    analysis = self._analysis(
      "MATCH (i:Indicator) WHERE i.value = 'CALL me maybe' RETURN i.value AS value LIMIT 5"
    )
    self.assertTrue(analysis["accepted"], analysis)

  def test_rejects_properties_projection(self):
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN properties(i) AS all_properties LIMIT 5",
      "properties() projection",
    )

  def test_rejects_wildcard_map_projection(self):
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i{.*} AS mapping LIMIT 5",
      "wildcard map projection",
    )

  def test_rejects_bracket_property_access(self):
    cases = [
      'MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS v LIMIT 5',
      "MATCH (n:Indicator) RETURN n['value'] AS v LIMIT 5",
      "MATCH p=(n:Indicator)-[:INDICATES]->() RETURN nodes(p)[0] AS head LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "bracket property access")

  def test_pattern_brackets_and_in_lists_are_not_bracket_access(self):
    cases = [
      "MATCH p=(i:Indicator)-[:INDICATES]->(m:Malware) RETURN p LIMIT 5",
      "MATCH (i:Indicator)-[r:INDICATES]->(m:Malware) RETURN i.value AS value LIMIT 5",
      "MATCH (i:Indicator) WHERE i.indicator_type IN ['hash', 'domain'] RETURN i LIMIT 5",
      "MATCH (i:Indicator) WHERE i.value = 'foo[bar]' RETURN i LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher)
        self.assertTrue(analysis["accepted"], f"{cypher!r}: {analysis['validation_feedback']}")

  def test_rejects_schema_free_scans(self):
    cases = [
      "MATCH (n) RETURN n LIMIT 5",
      "MATCH ()-[r]->() RETURN r LIMIT 5",
      "WITH 1 AS x RETURN x LIMIT 1",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "not anchored")

  def test_rejects_materializing_collect(self):
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN collect(i.value) AS values LIMIT 5",
      "collect()",
    )

  def test_limit_rules(self):
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i.value AS value",
      "explicit positive LIMIT",
    )
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 0",
      "explicit positive LIMIT",
    )
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 500",
      "server row cap of 100",
      max_limit=100,
    )
    accepted = self._analysis(
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 100", max_limit=100,
    )
    self.assertTrue(accepted["accepted"], accepted["validation_feedback"])
    uncapped = self._analysis("MATCH (i:Indicator) RETURN i.value AS value LIMIT 500")
    self.assertTrue(uncapped["accepted"], "max_limit=None skips only the cap comparison")

  def test_scalar_aggregate_only_queries_may_omit_limit(self):
    cases = [
      "MATCH (i:Indicator) RETURN count(i) AS total",
      "MATCH (i:Indicator) RETURN count(i) AS total, max(i.confidence_score) AS best",
      "MATCH (i:Indicator) RETURN DISTINCT count(i) AS total",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher)
        self.assertTrue(analysis["accepted"], f"{cypher!r}: {analysis['validation_feedback']}")
    mixed = self._analysis("MATCH (i:Indicator) RETURN count(i) AS total, i.value AS value")
    self.assertFalse(mixed["accepted"], "mixed aggregate and scalar projection still needs LIMIT")

  def test_broadening_template_survives_execution_safety(self):
    analysis = self._analysis("MATCH p=(n:Indicator)-[:INDICATES]-() RETURN p LIMIT 5", max_limit=100)
    self.assertTrue(analysis["accepted"], analysis["validation_feedback"])

  def test_accepted_cypher_is_never_rewritten(self):
    for cypher in (
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
      "MATCH (i:`Indicator`) RETURN i.value AS value LIMIT 10",
    ):
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertEqual(analysis["accepted_cypher"], cypher)

  def test_rejects_parenthesized_and_backticked_property_access(self):
    cases = [
      "MATCH (i:Indicator) RETURN (i).private AS v LIMIT 5",
      "MATCH (i:Indicator) RETURN `i`.private AS v LIMIT 5",
      "MATCH (i:Indicator) RETURN i.`private` AS v LIMIT 5",
      "MATCH (i:Indicator) WHERE (i).private IS NOT NULL RETURN i.value AS v LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertFalse(analysis["accepted"], cypher)
        self.assertIn("private", analysis["schema_unknown"]["properties"], cypher)

  def test_extracts_every_label_in_a_chain(self):
    cases = [
      "MATCH (i:Indicator:Nope) RETURN i.value AS v LIMIT 5",
      "MATCH (:Indicator:Nope) RETURN 1 AS v LIMIT 5",
      "MATCH (i:Nope:Indicator) RETURN i.value AS v LIMIT 5",
      "MATCH (i :Indicator :Nope) RETURN i.value AS v LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertFalse(analysis["accepted"], cypher)
        self.assertEqual(analysis["schema_unknown"]["labels"], ["Nope"], cypher)
    tokens = extract_schema_tokens("MATCH (:Indicator:Malware)-[:INDICATES]->() RETURN 1")
    self.assertEqual(tokens["labels"], {"Indicator", "Malware"})
    self.assertEqual(tokens["relationship_types"], {"INDICATES"})

  def test_anonymous_labelled_node_anchors_query(self):
    analysis = self._analysis("MATCH (:Indicator) RETURN count(*) AS total")
    self.assertTrue(analysis["accepted"], analysis["validation_feedback"])

  def test_rejects_comments(self):
    cases = [
      "MATCH (i:Indicator) RETURN i.value AS v // LIMIT 1",
      "MATCH (i:Indicator) RETURN i.value AS v /* LIMIT 1 */",
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 // done",
      "MATCH (i:Indicator) /* hidden */ RETURN i.value AS v LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "comments are not allowed", max_limit=100)

  def test_limit_must_be_final_integer_literal(self):
    cases = [
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 1 + 1000",
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 1000 + 1",
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT toInteger('5')",
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 ORDER BY i.value",
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 SKIP 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "single integer literal", max_limit=100)

  def test_quoted_identifiers_cannot_read_as_clauses(self):
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i AS `rows LIMIT 1`",
      "explicit positive LIMIT",
      max_limit=100,
    )
    self.assert_rejected(
      "MATCH (i:Indicator) RETURN i AS `x` LIMIT 1000 AS `LIMIT 1`",
      "single integer literal",
      max_limit=100,
    )
    accepted = self._analysis("MATCH (i:Indicator) RETURN i.value AS `my value` LIMIT 5", max_limit=100)
    self.assertTrue(accepted["accepted"], accepted["validation_feedback"])
    quoted_label = self._analysis("MATCH (i:`Not Allowed`) RETURN i.value AS v LIMIT 5", max_limit=100)
    self.assertFalse(quoted_label["accepted"])

  def test_label_expressions_check_every_identifier(self):
    cases = [
      "MATCH (i:Indicator|ReviewPrivate) RETURN i LIMIT 5",
      "MATCH (i:Indicator&ReviewPrivate) RETURN i LIMIT 5",
      "MATCH (i:Indicator|ReviewPrivate:Malware) RETURN i LIMIT 5",
      "MATCH (i:Indicator)-[:INDICATES&ReviewPrivate]->(m:Malware) RETURN i LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertFalse(analysis["accepted"], cypher)
        unknown = analysis["schema_unknown"]
        self.assertIn("ReviewPrivate", unknown.get("labels", []) + unknown.get("relationship_types", []), cypher)
    for cypher in (
      "MATCH (i:Indicator|Malware) RETURN i.value AS v LIMIT 5",
      "MATCH (i:Indicator)-[:INDICATES|SOURCED_FROM]->(m:Malware) RETURN i.value AS v LIMIT 5",
    ):
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertTrue(analysis["accepted"], f"{cypher!r}: {analysis['validation_feedback']}")

  def test_rejects_negated_wildcard_and_grouped_label_expressions(self):
    cases = [
      "MATCH (i:!Indicator) RETURN i LIMIT 5",
      "MATCH (i:%) RETURN i LIMIT 5",
      "MATCH (i:(Indicator|Malware)) RETURN i LIMIT 5",
      "MATCH (i:Indicator|!Malware) RETURN i LIMIT 5",
      "MATCH (i:Indicator)-[:!INDICATES]->(m:Malware) RETURN i LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        self.assert_rejected(cypher, "negation, wildcard or grouping", max_limit=100)

  def test_negative_controls_stay_accepted(self):
    cases = [
      "MATCH (i:Indicator) RETURN i.name AS name LIMIT 5",
      "MATCH (i:Indicator) RETURN count(i) AS total",
      "MATCH p=(i:Indicator)-[:INDICATES]->(m:Malware) RETURN p LIMIT 5",
      "MATCH (i:Indicator) WHERE i.indicator_type IN ['hash', 'domain'] RETURN i LIMIT 5",
      "MATCH (i:Indicator) WHERE i.value = 'http://x' RETURN i LIMIT 5",
      "MATCH (i:Indicator) WHERE i.value = 'a /* b' RETURN i LIMIT 5",
      "MATCH (i:Indicator)-[r :INDICATES]->(m:Malware) RETURN i.value AS value LIMIT 5",
      "MATCH (i:`Indicator`) RETURN i.value AS value LIMIT 5",
      "MATCH (i:Indicator) RETURN i.value AS value ORDER BY i.value LIMIT 5",
      "MATCH (i:Indicator) RETURN i.value AS value SKIP 5 LIMIT 5",
    ]
    for cypher in cases:
      with self.subTest(cypher=cypher):
        analysis = self._analysis(cypher, max_limit=100)
        self.assertTrue(analysis["accepted"], f"{cypher!r}: {analysis['validation_feedback']}")

  def test_execution_safety_feedback_reaches_validation_feedback(self):
    analysis = self._analysis("MATCH (i:Indicator) RETURN i.value AS value")
    self.assertIn("Execution safety error", analysis["validation_feedback"])
