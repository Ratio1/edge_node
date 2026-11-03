"""EG-019 phase 3: multi-statement guard (I-079) and /explain_graph error
labels (I-076)."""
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (
  EDGEGUARD_SCHEMA_V0_11,
  MULTI_STATEMENT_CODE,
  _multi_statement_error,
  analyze_generated_cypher,
  format_schema_validation_feedback,
  schema_sets,
)
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError
from extensions.business.cybersec.edgeguard.tests.test_api import (
  _graph_first_payload,
  _make_api,
)

from extensions.business.cybersec.edgeguard.edgeguard_api import (
  Neo4jDatabaseUnavailable as DatabaseUnavailable,
  Neo4jServiceUnavailable as ServiceUnavailable,
  Neo4jSessionExpired as SessionExpired,
)


def _analyze(cypher):
  return analyze_generated_cypher(cypher, max_limit=100)


class MultiStatementGuardTests(unittest.TestCase):
  def assertMulti(self, cypher):
    result = _analyze(cypher)
    self.assertFalse(result["accepted"], cypher)
    self.assertIsNone(result["accepted_cypher"])
    self.assertEqual(result["execution_safety_error_code"], MULTI_STATEMENT_CODE)
    self.assertIn("return exactly one Cypher statement", result["execution_safety_error"])
    self.assertIn("one final `RETURN`", result["validation_feedback"])

  def test_two_statements_rejected(self):
    self.assertMulti(
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 "
      "MATCH (c:CVE) RETURN c.cve_id AS id LIMIT 5"
    )

  def test_three_statements_rejected(self):
    self.assertMulti(
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 "
      "MATCH (c:CVE) RETURN c.cve_id AS id LIMIT 5 "
      "MATCH (m:Malware) RETURN m.name AS n LIMIT 5"
    )

  def test_clause_after_final_return_rejected(self):
    self.assertMulti(
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 MATCH (c:CVE) WITH c LIMIT 5"
    )

  def test_with_statement_accepted(self):
    result = _analyze(
      "MATCH (i:Indicator) WITH i LIMIT 10 MATCH (i)-[:INDICATES]->(m:Malware) "
      "RETURN i.value AS v, m.name AS n ORDER BY n SKIP 1 LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_starts_with_after_return_accepted(self):
    result = _analyze(
      "MATCH (i:Indicator) RETURN i.value AS v ORDER BY v LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])
    result = _analyze(
      "MATCH (i:Indicator) WHERE i.value STARTS WITH '203.' RETURN i.value AS v LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_starts_ends_with_after_return_accepted(self):
    for expr in ("i.value STARTS WITH '2'", "i.value ENDS WITH '9'"):
      result = _analyze(f"MATCH (i:Indicator) RETURN {expr} AS f LIMIT 5")
      self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_clause_word_alias_or_map_key_accepted(self):
    result = _analyze("MATCH (c:CVE) RETURN c.cve_id AS `match` LIMIT 5")
    self.assertTrue(result["accepted"], result["execution_safety_error"])
    result = _analyze("MATCH (c:CVE) RETURN c.cve_id AS with, c.cve_id AS unwind LIMIT 5")
    self.assertTrue(result["accepted"], result["execution_safety_error"])
    self.assertIsNone(_multi_statement_error("MATCH (c:CVE) RETURN {match: c.cve_id, with: 1} AS m LIMIT 5"))

  def test_collect_subquery_with_return_accepted(self):
    result = _analyze(
      "MATCH (c:CVE) RETURN COLLECT { MATCH (c)-[:EXPLOITS]->(i:Indicator) RETURN i.value } "
      "AS v LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_collect_where_pattern_predicates_stay_rejected(self):
    # COLLECT masking is private to the multi-statement check: the WHERE
    # pattern-predicate checks behave as at base.
    head = "MATCH (c:CVE) RETURN COLLECT { MATCH (z:Indicator)-[:EXPLOITS]->(c) WHERE %s RETURN z.value } AS v LIMIT 5"
    v0_11 = dict(
      allowed=schema_sets(EDGEGUARD_SCHEMA_V0_11), max_limit=100,
      allow_limit_optional_graph=True, enforce_hop_bounds=True, enforce_pattern_endpoints=True,
    )
    result = analyze_generated_cypher(head % "(z)-[:EXPLOITS]->(:Sector)", **v0_11)
    self.assertFalse(result["accepted"])
    self.assertEqual(result["execution_safety_error_code"], "pattern_endpoint_mismatch")
    result = _analyze(head % "(z)-[:EXPLOITS]->(q:CVE)")
    self.assertFalse(result["accepted"])
    self.assertIn("introduces variable", result["execution_safety_error"])

  def test_union_accepted(self):
    result = _analyze(
      "MATCH (i:Indicator) RETURN i.value AS v LIMIT 5 UNION "
      "MATCH (c:CVE) RETURN c.cve_id AS v LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_exists_subquery_with_return_accepted(self):
    result = _analyze(
      "MATCH (c:CVE) WHERE EXISTS { MATCH (c)-[:EXPLOITS]->(i:Indicator) RETURN i } "
      "RETURN c.cve_id AS id LIMIT 5"
    )
    self.assertTrue(result["accepted"], result["execution_safety_error"])

  def test_existing_violation_message_wins(self):
    # No LIMIT: the pre-existing first-violation message is unchanged.
    result = _analyze(
      "MATCH (i:Indicator) RETURN i.value AS v MATCH (c:CVE) RETURN c.cve_id AS id"
    )
    self.assertEqual(result["execution_safety_error_code"], "execution_safety_violation")

  def test_feedback_carries_guidance(self):
    feedback = format_schema_validation_feedback(
      {}, None, execution_safety_error="return exactly one Cypher statement; x",
    )
    self.assertIn("return exactly one Cypher statement", feedback)


class ExplainGraphErrorLabelTests(unittest.TestCase):
  def _call(self, exc):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    driver = MagicMock()
    driver.session.side_effect = exc
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=driver):
        return plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the returned graph.",
          cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 5",
        )

  def _check(self, exc, status, code):
    result = self._call(exc)
    self.assertEqual(result["status_code"], status)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["error_code"], code)
    self.assertNotIn("secret", payload["error"])

  def test_escaped_graph_first_runtime_error_is_500_with_own_code(self):
    self._check(
      GraphFirstRuntimeError("explanation_response_size", "internal", "too big secret"),
      500, "explanation_response_size",
    )

  def test_service_unavailable_is_503_connection_error(self):
    self._check(ServiceUnavailable("down secret"), 503, "neo4j_connection_error")

  def test_database_unavailable_is_503_connection_error(self):
    self._check(DatabaseUnavailable("starting"), 503, "neo4j_connection_error")

  def test_session_expired_is_503_connection_error(self):
    self._check(SessionExpired("expired"), 503, "neo4j_connection_error")

  def test_oserror_is_503_connection_error(self):
    self._check(TimeoutError("timeout"), 503, "neo4j_connection_error")

  def test_other_exception_is_500_internal_error(self):
    self._check(RuntimeError("boom secret"), 500, "explain_internal_error")


if __name__ == "__main__":
  unittest.main()
