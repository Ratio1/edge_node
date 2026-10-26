"""EGM-068 contract v0.13: guard allowlist, served prompt profile and the default Neo4j `method`."""

import hashlib
import re
import unittest
from unittest.mock import MagicMock, patch

# test_api installs the naeural_core stubs at import time, so it comes first.
from extensions.business.cybersec.edgeguard.tests.test_api import (
  TEST_GENERATION_WORKERS,
  _Result,
  _graph_first_payload,
  _make_api,
)
from extensions.business.cybersec.edgeguard.edgeguard_api import (
  PROMPT_PROFILE_V0_13_PATTERN_SCHEMA,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (
  EDGEGUARD_SCHEMA_V0_11,
  EXECUTION_SAFETY_ERROR_CODE,
  PATTERN_ENDPOINT_MISMATCH_CODE,
  analyze_generated_cypher,
  build_v0_11_pattern_schema_system_prompt,
  schema_sets,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard_v0_13 import (
  EDGEGUARD_SCHEMA_V0_13,
  SCHEMA_ARTIFACT_V0_13_SHA256,
  PROMPT_SIZE_FACTOR,
  SCHEMA_VERSION_V0_13,
  build_v0_13_pattern_schema_system_prompt,
  load_schema_artifact_v0_13,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import EdgeGuardCypherGuardError

# Hub `configs/edgeguard_v0_13_runtime_pin.json` served_system_prompt_sha256.
HUB_V0_13_PROMPT_SHA256 = "62bc5b281bec851aac8da6e6603a53a559f1da332b59898955246f2a0afca0aa"
V0_13_MODEL_KEY = "v0-13-fixture-model"
V0_13_WORKERS = {
  V0_13_MODEL_KEY: {
    "SEMAPHORE": "edgeguard_llm_v0_13",
    "PATH": "/create_chat_completion",
    "PROMPT_PROFILE": PROMPT_PROFILE_V0_13_PATTERN_SCHEMA,
    "DISPLAY_NAME": "v0.13 fixture model",
    "MODEL_REPO": "example-org/v0-13-fixture-gguf",
    "MODEL_FILE": "v0-13-fixture.Q4_K_M.gguf",
  },
  **TEST_GENERATION_WORKERS,
}


def _analyze(cypher):
  return analyze_generated_cypher(
    cypher,
    allowed=schema_sets(EDGEGUARD_SCHEMA_V0_13),
    max_limit=100,
    allow_limit_optional_graph=True,
    enforce_hop_bounds=True,
    enforce_pattern_endpoints=True,
    schema_artifact=EDGEGUARD_SCHEMA_V0_13,
  )


class V0_13ArtifactAndPromptTests(unittest.TestCase):
  def test_artifact_is_pinned_and_versioned(self):
    self.assertEqual(EDGEGUARD_SCHEMA_V0_13["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(EDGEGUARD_SCHEMA_V0_13["checksums"]["artifact_sha256"], SCHEMA_ARTIFACT_V0_13_SHA256)
    self.assertEqual(load_schema_artifact_v0_13()["checksums"], EDGEGUARD_SCHEMA_V0_13["checksums"])

  def test_tampered_artifact_fails_loudly(self):
    import json
    import os
    import tempfile
    artifact = json.loads(json.dumps(EDGEGUARD_SCHEMA_V0_13))
    artifact["schema"]["labels"].append("Injected")
    with tempfile.TemporaryDirectory() as tmp:
      path = os.path.join(tmp, "a.json")
      with open(path, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle)
      with self.assertRaises(EdgeGuardCypherGuardError):
        load_schema_artifact_v0_13(__import__("pathlib").Path(path))

  def test_served_prompt_matches_the_hub_builder_sha(self):
    prompt = build_v0_13_pattern_schema_system_prompt()
    self.assertEqual(hashlib.sha256(prompt.encode("utf-8")).hexdigest(), HUB_V0_13_PROMPT_SHA256)

  def test_served_prompt_size_bound_against_v0_11(self):
    v0_11 = len(build_v0_11_pattern_schema_system_prompt().encode("utf-8"))
    v0_13 = len(build_v0_13_pattern_schema_system_prompt().encode("utf-8"))
    self.assertEqual(v0_11, 3289)
    self.assertLessEqual(v0_13, int(v0_11 * PROMPT_SIZE_FACTOR))

  def test_served_prompt_has_no_removed_graph_shapes(self):
    prompt = build_v0_13_pattern_schema_system_prompt()
    pattern_lines = [line for line in prompt.splitlines() if re.match(r"^[A-Z_a-z0-9]+ [A-Za-z0-9]+: ", line)]
    self.assertTrue(pattern_lines)
    for line in pattern_lines:
      if line.startswith("PART_OF "):
        self.assertNotIn("Campaign", line)
      if line.startswith("EXPLOITS "):
        self.assertEqual(line, "EXPLOITS CVE: ThreatActor")
    self.assertNotIn("r.source_id", prompt)
    self.assertNotIn("source_ids", prompt)

  def test_v0_11_prompt_is_unchanged(self):
    self.assertNotEqual(
      build_v0_11_pattern_schema_system_prompt(), build_v0_13_pattern_schema_system_prompt(),
    )
    self.assertNotIn("PART_OF_CAMPAIGN", build_v0_11_pattern_schema_system_prompt())


class V0_13GuardTests(unittest.TestCase):
  def test_each_new_relationship_type_is_accepted(self):
    for cypher in (
      "MATCH (a:ThreatActor)-[:USES_MALWARE]->(m:Malware) RETURN a.name LIMIT 5",
      "MATCH (a:ThreatActor)-[:USES_TOOL]->(t:Tool) RETURN a.name LIMIT 5",
      "MATCH (t:Technique)-[:SUBTECHNIQUE_OF]->(p:Technique) RETURN t.name LIMIT 5",
      "MATCH (c:CVE)-[:HAS_CVSS_v2]->(v:CVSSv2) RETURN c.cve_id LIMIT 5",
      "MATCH (m:Malware)-[:PART_OF_CAMPAIGN]->(c:Campaign) RETURN m.name LIMIT 5",
      "MATCH (i:Indicator)-[:INDICATES]->(c:CVE) RETURN i.value LIMIT 5",
      "MATCH (a:ThreatActor)-[:EXPLOITS]->(c:CVE) RETURN a.name LIMIT 5",
    ):
      with self.subTest(cypher=cypher):
        result = _analyze(cypher)
        self.assertTrue(result["accepted"], result["execution_safety_error"] or result["schema_unknown"])

  def test_part_of_to_campaign_is_refused(self):
    result = _analyze("MATCH (m:Malware)-[:PART_OF]->(c:Campaign) RETURN m.name LIMIT 5")
    self.assertFalse(result["accepted"])
    self.assertEqual(result["execution_safety_error_code"], PATTERN_ENDPOINT_MISMATCH_CODE)
    self.assertIn("PART_OF_CAMPAIGN", result["execution_safety_error"])

  def test_indicator_exploits_cve_is_refused(self):
    result = _analyze("MATCH (i:Indicator)-[:EXPLOITS]->(c:CVE) RETURN i.value LIMIT 5")
    self.assertFalse(result["accepted"])
    self.assertEqual(result["execution_safety_error_code"], PATTERN_ENDPOINT_MISMATCH_CODE)
    self.assertIn("INDICATES", result["execution_safety_error"])

  def test_unknown_relationship_type_is_refused(self):
    result = _analyze("MATCH (m:Malware)-[:MENTIONS]->(c:Campaign) RETURN m.name LIMIT 5")
    self.assertFalse(result["accepted"])
    self.assertEqual(result["schema_unknown"], {"relationship_types": ["MENTIONS"]})

  def test_relationship_variable_source_id_is_refused_by_the_owner_rule(self):
    result = _analyze(
      "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) WHERE r.source_id = 'nvd' RETURN i.value LIMIT 5"
    )
    self.assertFalse(result["accepted"])
    self.assertEqual(result["execution_safety_error_code"], EXECUTION_SAFETY_ERROR_CODE)
    self.assertIn("r.source_id", result["execution_safety_error"])

  def test_aliased_relationship_source_id_is_refused(self):
    result = _analyze(
      "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) WITH r AS x RETURN x.source_id AS s LIMIT 5"
    )
    self.assertFalse(result["accepted"])
    self.assertEqual(result["execution_safety_error_code"], EXECUTION_SAFETY_ERROR_CODE)
    self.assertIn("x.source_id", result["execution_safety_error"])

  def test_source_id_on_a_parenthesised_expression_is_refused(self):
    result = _analyze(
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN head(collect(s)).source_id AS s LIMIT 5"
    )
    self.assertFalse(result["accepted"])

  def test_source_ids_is_refused_by_the_flat_schema(self):
    result = _analyze(
      "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) WHERE r.source_ids = 'nvd' RETURN i.value LIMIT 5"
    )
    self.assertFalse(result["accepted"])
    self.assertEqual(result["schema_unknown"], {"properties": ["source_ids"]})

  def test_map_projection_of_source_id_is_refused_off_a_relationship(self):
    for projection in ("r{.source_id}", "r{.sources, .source_id}", "r{.*, .source_id}",
                       "r{description: {cve_id: 1}, .source_id}"):
      with self.subTest(projection=projection):
        result = _analyze(
          f"MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) RETURN {projection} AS m LIMIT 5"
        )
        self.assertFalse(result["accepted"])

  def test_map_projection_of_source_id_is_allowed_on_a_source_node(self):
    result = _analyze(
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN s{.source_id} AS m LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_source_label_test_in_where_does_not_bind_the_owner(self):
    # Documented fail-closed behaviour (contract v0.13 §3.1): bind `(s:Source)` inline.
    result = _analyze(
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s) WHERE s:Source RETURN s.source_id AS v LIMIT 5"
    )
    self.assertFalse(result["accepted"])

  def test_source_id_alias_of_a_source_node_is_refused_conservatively(self):
    result = _analyze(
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) WITH s AS x RETURN x.source_id AS s LIMIT 5"
    )
    self.assertFalse(result["accepted"])

  def test_source_id_owner_is_scoped_per_union_branch(self):
    result = _analyze(
      "MATCH (s:Source) RETURN s.source_id AS v LIMIT 5 UNION "
      "MATCH (i:Indicator)-[s:INDICATES]->(c:CVE) RETURN s.source_id AS v LIMIT 5"
    )
    self.assertFalse(result["accepted"])

  def test_source_node_source_id_stays_allowed(self):
    result = _analyze(
      "MATCH (i:Indicator)-[r:SOURCED_FROM]->(s:Source) WHERE s.source_id = 'nvd' RETURN i.value LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_relationship_variable_without_the_removed_property_is_allowed(self):
    result = _analyze(
      "MATCH (i:Indicator)-[r:INDICATES]->(c:CVE) WHERE 'nvd' IN r.sources RETURN i.value LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_v0_11_artifact_still_allows_the_old_shapes(self):
    allowed = schema_sets(EDGEGUARD_SCHEMA_V0_11)
    result = analyze_generated_cypher(
      "MATCH (i:Indicator)-[r:EXPLOITS]->(c:CVE) WHERE r.source_id = 'x' RETURN i.value LIMIT 5",
      allowed=allowed, max_limit=100, allow_limit_optional_graph=True, enforce_hop_bounds=True,
      enforce_pattern_endpoints=True, schema_artifact=EDGEGUARD_SCHEMA_V0_11,
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])


class V0_13ThreadingTests(unittest.TestCase):
  """The v0.13 artifact reaches every route that validates a Cypher candidate."""

  CAMPAIGN = "MATCH (m:Malware)-[:PART_OF_CAMPAIGN]->(c:Campaign) RETURN m.name AS name LIMIT 5"
  REMOVED = "MATCH (i:Indicator)-[:EXPLOITS]->(c:CVE) RETURN i.value AS value LIMIT 5"

  def _plugin(self):
    return _make_api(edgeguard_generation_workers=V0_13_WORKERS)

  def test_neo4j_query_validates_against_v0_13(self):
    plugin = self._plugin()
    refused = plugin.neo4j_query(
      uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
      cypher=self.REMOVED, model_key=V0_13_MODEL_KEY,
    )
    payload = _graph_first_payload(refused)
    self.assertEqual(payload["validation"]["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(payload["validation"]["execution_safety_error_code"], PATTERN_ENDPOINT_MISMATCH_CODE)

    record = MagicMock()
    record.data.return_value = {"name": "x"}
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.return_value = _Result([record])
    driver = MagicMock()
    driver.session.return_value = session
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=driver):
        accepted = plugin.neo4j_query(
          uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
          cypher=self.CAMPAIGN, model_key=V0_13_MODEL_KEY,
        )
    self.assertTrue(accepted["executed"])
    self.assertEqual(accepted["validation"]["schema_version"], SCHEMA_VERSION_V0_13)

  def test_explain_graph_validates_against_v0_13(self):
    plugin = self._plugin()
    result = plugin.explain_graph(
      cypher=self.REMOVED, request="Explain this.", model_key=V0_13_MODEL_KEY,
      uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
    )
    payload = _graph_first_payload(result)
    self.assertEqual(payload["validation"]["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(payload["validation"]["execution_safety_error_code"], PATTERN_ENDPOINT_MISMATCH_CODE)

  def test_prepare_graph_explanation_validates_against_v0_13(self):
    plugin = self._plugin()
    result = plugin.prepare_graph_explanation(
      cypher=self.REMOVED, model_key=V0_13_MODEL_KEY,
    )
    payload = _graph_first_payload(result)
    self.assertEqual(payload["validation"]["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(payload["validation"]["execution_safety_error_code"], PATTERN_ENDPOINT_MISMATCH_CODE)

  def test_the_same_candidate_is_accepted_for_a_v0_11_key(self):
    plugin = _make_api(edgeguard_generation_workers={
      **V0_13_WORKERS, "v0-11-key": {**V0_13_WORKERS[V0_13_MODEL_KEY], "PROMPT_PROFILE": "v0_11_pattern_schema"},
    })
    self.assertTrue(plugin.check_cypher(cypher=self.REMOVED, model_key="v0-11-key")["accepted"])
    self.assertFalse(plugin.check_cypher(cypher=self.REMOVED, model_key=V0_13_MODEL_KEY)["accepted"])


class V0_13ProfileTests(unittest.TestCase):
  def test_profile_resolves_prompt_and_validation_from_the_v0_13_artifact(self):
    plugin = _make_api(edgeguard_generation_workers=V0_13_WORKERS)

    messages = plugin._generation_messages(V0_13_MODEL_KEY, "Show indicators")
    profile = plugin._cypher_validation_profile(V0_13_MODEL_KEY)

    self.assertEqual(messages[0]["content"], build_v0_13_pattern_schema_system_prompt())
    self.assertTrue(profile["use_v0_11"])
    self.assertIs(profile["schema_artifact"], EDGEGUARD_SCHEMA_V0_13)
    self.assertEqual(profile["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(profile["schema_allowed"], schema_sets(EDGEGUARD_SCHEMA_V0_13))
    self.assertIn("PART_OF_CAMPAIGN", profile["schema_allowed"]["relationship_types"])
    self.assertNotIn("PART_OF_CAMPAIGN", schema_sets(EDGEGUARD_SCHEMA_V0_11)["relationship_types"])

  def test_check_cypher_uses_the_v0_13_allowlist_for_a_v0_13_model_key(self):
    plugin = _make_api(edgeguard_generation_workers=V0_13_WORKERS)
    cypher = "MATCH (m:Malware)-[:PART_OF_CAMPAIGN]->(c:Campaign) RETURN m.name LIMIT 5"
    bad = "MATCH (m:Malware)-[:PART_OF]->(c:Campaign) RETURN m.name LIMIT 5"

    ok = plugin.check_cypher(cypher=cypher, model_key=V0_13_MODEL_KEY)
    refused = plugin.check_cypher(cypher=bad, model_key=V0_13_MODEL_KEY)

    self.assertTrue(ok["accepted"], ok["validation_feedback"])
    self.assertEqual(ok["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertFalse(refused["accepted"])

  def test_prompt_contract_reports_the_v0_13_profile(self):
    plugin = _make_api(edgeguard_generation_workers=V0_13_WORKERS)

    profiles = {item["model_key"]: item for item in plugin.prompt_contract()["profiles"]}

    entry = profiles[V0_13_MODEL_KEY]
    self.assertEqual(entry["system_prompt_sha256"], HUB_V0_13_PROMPT_SHA256)
    self.assertEqual(entry["cypher_schema_version"], SCHEMA_VERSION_V0_13)
    self.assertIn("USES_TOOL", entry["schema_surface"]["relationship_types"])

  def test_correction_turn_keeps_the_v0_11_conversation_shape(self):
    plugin = _make_api(edgeguard_generation_workers=V0_13_WORKERS)

    messages = plugin._generation_messages(
      V0_13_MODEL_KEY, "Show indicators", rejected_cypher="MATCH (n) RETURN n",
      validation_feedback="bad", retry_index=1, retry_limit=2,
    )

    self.assertEqual([m["role"] for m in messages], ["system", "user", "assistant", "user"])


class Neo4jDefaultMethodTests(unittest.TestCase):
  DEFAULT = {"uri": "db.example:7687", "username": "u", "password": "p", "scheme": "bolt+s"}

  def _plugin(self, **extra):
    return _make_api(neo4j_default_connection={**self.DEFAULT, **extra})

  def _run(self, plugin, **kwargs):
    record = MagicMock()
    record.data.return_value = {"value": "1.2.3.4"}
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.return_value = _Result([record])
    driver = MagicMock()
    driver.session.return_value = session
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=driver) as mocked:
        result = plugin.neo4j_query(cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 10", **kwargs)
    return result, mocked

  def test_no_method_anywhere_keeps_bolt_over_wss(self):
    result, mocked = self._run(self._plugin())
    self.assertEqual(mocked.call_args.args[3], None)
    self.assertEqual(result["method"], "bolt_over_wss")

  def test_default_method_applies_when_the_request_has_none(self):
    result, mocked = self._run(self._plugin(method="native_driver"))
    self.assertEqual(mocked.call_args.args[3], "native_driver")
    self.assertEqual(result["method"], "native_driver")

  def test_request_method_wins_over_the_default(self):
    result, mocked = self._run(self._plugin(method="native_driver"), method="bolt_over_wss")
    self.assertEqual(mocked.call_args.args[3], "bolt_over_wss")
    self.assertEqual(result["method"], "bolt_over_wss")

  def test_default_method_is_not_applied_to_a_request_override_connection(self):
    result, mocked = self._run(
      self._plugin(method="native_driver"),
      uri="other.example:7687", username="x", password="y", scheme="bolt+s",
    )
    self.assertIsNone(mocked.call_args.args[3])
    self.assertEqual(result["method"], "bolt_over_wss")

  def test_invalid_default_method_is_a_configuration_error(self):
    plugin = self._plugin(method="carrier_pigeon")
    connection, error = plugin._resolve_neo4j_connection(None, None, None, None)
    self.assertIsNone(connection)
    self.assertIn("method", error)
    result, mocked = self._run(plugin)
    mocked.assert_not_called()
    self.assertNotEqual(result.get("status"), "accepted")

  def test_native_driver_default_with_a_plaintext_scheme_needs_allow_plaintext(self):
    for scheme in ("bolt", "neo4j"):
      plugin = self._plugin(method="native_driver", scheme=scheme)
      connection, error = plugin._resolve_neo4j_connection(None, None, None, None)
      self.assertIsNone(connection, scheme)
      self.assertIn("allow_plaintext", error)
    allowed = self._plugin(method="native_driver", scheme="bolt", allow_plaintext=True)
    connection, error = allowed._resolve_neo4j_connection(None, None, None, None)
    self.assertIsNone(error)
    self.assertEqual(connection["method"], "native_driver")
    self.assertEqual(connection["scheme"], "bolt")

  def test_allow_plaintext_must_be_the_boolean_true(self):
    plugin = self._plugin(method="native_driver", scheme="bolt", allow_plaintext="true")
    self.assertIsNone(plugin._resolve_neo4j_connection(None, None, None, None)[0])

  def test_native_driver_default_with_an_encrypted_scheme_needs_no_opt_in(self):
    for scheme in ("bolt+s", "neo4j+s", "bolt+ssc"):
      connection, error = self._plugin(method="native_driver", scheme=scheme)._resolve_neo4j_connection(
        None, None, None, None,
      )
      self.assertIsNone(error, scheme)

  def test_plaintext_scheme_without_a_default_method_is_unchanged(self):
    connection, error = self._plugin(scheme="bolt")._resolve_neo4j_connection(None, None, None, None)
    self.assertIsNone(error)
    self.assertNotIn("method", connection)

  def test_health_reports_the_default_method(self):
    self.assertEqual(
      self._plugin(method="native_driver").health()["neo4j"]["default_connection"]["method"], "native_driver",
    )
    self.assertEqual(self._plugin().health()["neo4j"]["default_connection"]["method"], "bolt_over_wss")


class ArtifactCacheTests(unittest.TestCase):
  def test_two_artifacts_do_not_evict_each_other(self):
    from extensions.business.cybersec.edgeguard import edgeguard_cypher_guard as guard
    from extensions.business.cybersec.edgeguard import literal_classes
    for build in (
      guard._pattern_endpoint_pairs_by_type, guard._topology_surface_labels,
      guard._topology_surface_relationship_types,
      literal_classes.build_closed_vocabulary_index, literal_classes.build_synonym_index,
    ):
      first_11 = build(EDGEGUARD_SCHEMA_V0_11)
      first_13 = build(EDGEGUARD_SCHEMA_V0_13)
      self.assertIs(build(EDGEGUARD_SCHEMA_V0_11), first_11, build.__name__)
      self.assertIs(build(EDGEGUARD_SCHEMA_V0_13), first_13, build.__name__)

  def test_effective_method_prefers_the_request(self):
    from extensions.business.cybersec.edgeguard.edgeguard_api import EdgeguardApiPlugin
    self.assertEqual(EdgeguardApiPlugin._effective_neo4j_method(None, {"method": "native_driver"}), "native_driver")
    self.assertEqual(
      EdgeguardApiPlugin._effective_neo4j_method("bolt_over_wss", {"method": "native_driver"}), "bolt_over_wss",
    )
    self.assertIsNone(EdgeguardApiPlugin._effective_neo4j_method(None, {}))


if __name__ == "__main__":
  unittest.main()
