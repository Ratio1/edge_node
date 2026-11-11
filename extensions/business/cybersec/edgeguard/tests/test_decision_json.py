"""Decision-JSON prompt profile (EdgeGuard Cypher 2026-11-08, IICT-BAS adapter).

The model replies with one JSON line whose first key is `decision`; only
`answer` and `partial` carry a Cypher query.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# test_api installs the naeural_core stubs at import time, so it comes first.
from extensions.business.cybersec.edgeguard.tests.test_api import (
  TEST_GENERATION_WORKERS,
  _Response,
  _make_api,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_decision_json import (
  SYSTEM_PROMPT_PATH,
  load_system_prompt,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import EdgeGuardCypherGuardError

DECISION_KEY = "decision-fixture-model"
DECISION_SEMAPHORE = "edgeguard_llm_decision_fixture"
DECISION_WORKERS = {
  DECISION_KEY: {
    "SEMAPHORE": DECISION_SEMAPHORE,
    "PATH": "/create_chat_completion",
    "PROMPT_PROFILE": "decision_json_v2026_11_08",
    "DISPLAY_NAME": "decision fixture model",
  },
  **TEST_GENERATION_WORKERS,
}


def _completion(content, finish_reason="stop"):
  return _Response(payload={
    "result": {
      "TEXT_RESPONSE": content,
      "FULL_OUTPUT": {
        "choices": [{"message": {"content": content}, "finish_reason": finish_reason}],
        "usage": {"completion_tokens": 20},
      },
    },
  })


def _generate(*replies, question="Which techniques does the group use?"):
  """Run `generate` for the decision fixture model; the worker returns `replies` in order."""
  plugin = _make_api(
    edgeguard_generation_workers=DECISION_WORKERS,
    worker_semaphore_env={DECISION_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53009"}},
  )
  session = MagicMock()
  session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
  session.post.side_effect = [_completion(r if isinstance(r, str) else json.dumps(r)) for r in replies]
  with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
    result = plugin.generate(request=question, model_key=DECISION_KEY)
  return result, session


class DecisionReplyTests(unittest.TestCase):
  def test_clarify_reply_is_declined_with_the_models_question(self):
    result, session = _generate({"decision": "clarify", "question": "Which group do you mean?"})

    self.assertEqual(result["status"], "declined")
    self.assertFalse(result["accepted"])
    self.assertIsNone(result["accepted_cypher"])
    self.assertEqual(result["decision"], "clarify")
    self.assertEqual(result["decision_message"], "Which group do you mean?")
    self.assertEqual(session.post.call_count, 1)

  def test_answer_reply_is_accepted_with_the_query_from_the_json(self):
    cypher = ("MATCH p=(ta:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
              "WHERE toLower(ta.name) = 'apt28' RETURN p LIMIT 25")
    result, _ = _generate({"decision": "answer", "cypher": cypher},
                          question="Which techniques does APT28 employ?")

    self.assertEqual(result["status"], "accepted", result.get("validation_feedback"))
    self.assertEqual(result["accepted_cypher"], cypher)
    self.assertEqual(result["decision"], "answer")

  def test_malformed_reply_is_rejected_without_a_correction_turn(self):
    result, session = _generate("MATCH (n) RETURN n LIMIT 5")

    self.assertEqual(result["status"], "rejected")
    self.assertIn("JSON", result["validation_feedback"])
    self.assertEqual(session.post.call_count, 1)

  def test_answer_without_cypher_is_rejected(self):
    result, _ = _generate({"decision": "answer"})

    self.assertEqual(result["status"], "rejected")
    self.assertIn("without a Cypher query", result["validation_feedback"])

  def test_partial_reply_is_accepted_with_its_note(self):
    cypher = "MATCH p=(c:CVE)-[:AFFECTS]->(s:Sector) WHERE s.name = 'energy' RETURN p LIMIT 25"
    note = "Which of these run on your hosts lives in ResilMesh ISIM, not here."
    result, _ = _generate({"decision": "partial", "cypher": cypher, "note": note},
                          question="Which energy CVEs affect our hosts?")

    self.assertEqual(result["status"], "accepted", result.get("validation_feedback"))
    self.assertEqual(result["decision"], "partial")
    self.assertEqual(result["decision_note"], note)


class DecisionPromptTests(unittest.TestCase):
  # Adapter bundle EdgeGuard-cypher-LoRA-2026-11-08, SHA256SUMS entry for system_prompt.txt.
  BUNDLE_PROMPT_SHA256 = "da06f1e43e6102b9c04adaa4b361ef1d81e2a4e3ac3d3759525689a7cf47a2eb"

  def test_model_gets_the_adapter_prompt_unchanged_and_the_question_alone(self):
    _, session = _generate({"decision": "out_of_scope", "reason": "General knowledge."},
                           question="What is the capital of France?")

    messages = session.post.call_args.kwargs["json"]["messages"]
    self.assertEqual([m["role"] for m in messages], ["system", "user"])
    self.assertEqual(hashlib.sha256(messages[0]["content"].encode("utf-8")).hexdigest(), self.BUNDLE_PROMPT_SHA256)
    self.assertEqual(messages[1]["content"], "What is the capital of France?")

  def test_decoding_matches_the_adapter_training(self):
    _, session = _generate({"decision": "refuse", "reason": "Write request."}, question="Drop the database")

    body = session.post.call_args.kwargs["json"]
    self.assertEqual(body["temperature"], 0.0)
    self.assertEqual(body["max_tokens"], 512)

  def test_a_modified_prompt_file_is_refused(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = Path(tmp) / "prompt.txt"
      path.write_bytes(SYSTEM_PROMPT_PATH.read_bytes() + b" ")
      with self.assertRaises(EdgeGuardCypherGuardError):
        load_system_prompt(path)


class DecisionSchemaTests(unittest.TestCase):
  """The guard allowlist is the schema the adapter's system prompt describes (graph v2026.11.6)."""

  def test_queries_on_the_prompt_schema_are_accepted(self):
    cases = {
      "How many campaigns does Sandworm run?":
        "MATCH (ta:ThreatActor)-[:RUNS]->(c:Campaign) WHERE toLower(ta.name) = 'sandworm' "
        "RETURN count(c) AS total ORDER BY total DESC LIMIT 1",
      "Which malware does APT28 use, corroborated by two sources?":
        "MATCH p=(ta:ThreatActor)-[r:USES_MALWARE]->(m:Malware) WHERE toLower(ta.name) = 'apt28' "
        "AND size(r.sources) >= 2 AND r.match_type IS NOT NULL RETURN p LIMIT 25",
      "Which CVEs have a CVSS v2 record?":
        "MATCH p=(c:CVE)-[:HAS_CVSS_v2]->(v:CVSSv2) RETURN p LIMIT 25",
      "Which indicators were reported in the last 30 days?":
        "MATCH (i:Indicator) WHERE i.last_reported_at >= datetime() - duration({days: 30}) "
        "RETURN i.value AS value ORDER BY value LIMIT 25",
      "Top 10 KEV CVEs by EPSS score":
        "MATCH (c:CVE) WHERE c.cisa_exploit_add IS NOT NULL RETURN c.cve_id AS cve, c.epss_score AS epss "
        "ORDER BY epss DESC LIMIT 10",
    }
    for question, cypher in cases.items():
      with self.subTest(question=question):
        result, _ = _generate({"decision": "answer", "cypher": cypher}, question=question)
        self.assertEqual(result["status"], "accepted", result.get("validation_feedback"))

  def test_stored_values_the_prompt_teaches_are_not_refused_as_ungrounded_literals(self):
    # Real adapter replies (sealed set q040, q051); both are exactly right on the prod graph.
    cases = {
      "How many TLS certificate fingerprints are on the blocklist?":
        "MATCH (i:Indicator) WHERE i.indicator_type = 'x509-fingerprint-sha1' "
        "RETURN count(i) AS total ORDER BY total DESC LIMIT 1",
      "How many CVEs in the graph does CISA flag as used by ransomware?":
        "MATCH (c:CVE) WHERE c.known_ransomware_use = 'Known' RETURN count(c) AS total ORDER BY total DESC LIMIT 1",
    }
    for question, cypher in cases.items():
      with self.subTest(question=question):
        result, _ = _generate({"decision": "answer", "cypher": cypher}, question=question)
        self.assertEqual(result["status"], "accepted", result.get("validation_feedback"))

  def test_labels_outside_the_prompt_schema_are_rejected(self):
    cypher = "MATCH (h:Host)-[:HAS_VULNERABILITY]->(c:CVE) RETURN h LIMIT 25"
    result, _ = _generate({"decision": "answer", "cypher": cypher}, question="Which hosts have CVEs?")

    self.assertEqual(result["status"], "rejected")
    self.assertIn("Host", result["validation_feedback"])

  def test_write_queries_are_rejected(self):
    result, _ = _generate({"decision": "answer", "cypher": "MATCH (m:Malware) DETACH DELETE m"},
                          question="Delete all malware")

    self.assertEqual(result["status"], "rejected")


if __name__ == "__main__":
  unittest.main()
