"""Parity capture for the decision-JSON model path.

`capture(workers, model_key)` runs fixed cases against one worker entry and
returns the worker payloads and response bodies, normalised (timings dropped,
identity fields removed). The fixture `fixtures/decision_json_parity.json` is
frozen from the pre-pack code at edge_node commit 71d0be45 (worker entry
`PROMPT_PROFILE: decision_json_v2026_11_08`). Do not regenerate it from current
code: that would make the test compare the code with itself. To regenerate,
check out 71d0be45 in a scratch worktree, copy this file in, and run there

  python -m extensions.business.cybersec.edgeguard.tests.decision_json_parity --write

The pack path must reproduce it exactly.
"""

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# test_api installs the naeural_core stubs at import time, so it comes first.
from extensions.business.cybersec.edgeguard.tests.test_api import (
  TEST_GENERATION_WORKERS,
  _Response,
  _make_api,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "decision_json_parity.json"
MODEL_KEY = "decision-fixture-model"
SEMAPHORE = "edgeguard_llm_decision_fixture"
# Fields that name the profile mechanism, not its behaviour: allowed to differ.
IDENTITY_FIELDS = {"prompt_profile", "prompt_profile_id", "template_version"}
# Wall-clock fields.
VOLATILE_FIELDS = {"timing_ms", "metrics", "timeout", "logged"}

_CYPHER_OK = ("MATCH p=(ta:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) "
              "WHERE toLower(ta.name) = 'apt28' RETURN p LIMIT 25")
GENERATE_CASES = {
  "clarify": ({"decision": "clarify", "question": "Which group do you mean?"}, "stop"),
  "out_of_scope": ({"decision": "out_of_scope", "reason": "General knowledge."}, "stop"),
  "refuse": ({"decision": "refuse", "reason": "Write request."}, "stop"),
  "answer": ({"decision": "answer", "cypher": _CYPHER_OK}, "stop"),
  "partial": ({"decision": "partial", "note": "Hosts live in ISIM.",
               "cypher": "MATCH p=(c:CVE)-[:AFFECTS]->(s:Sector) WHERE s.name = 'energy' RETURN p LIMIT 25"}, "stop"),
  "answer_stored_value": ({"decision": "answer", "cypher":
                           "MATCH (c:CVE) WHERE c.known_ransomware_use = 'Known' "
                           "RETURN count(c) AS total ORDER BY total DESC LIMIT 1"}, "stop"),
  "malformed": ("MATCH (n) RETURN n LIMIT 5", "stop"),
  "answer_without_cypher": ({"decision": "answer"}, "stop"),
  "unknown_label": ({"decision": "answer", "cypher": "MATCH (h:Host)-[:HAS_VULNERABILITY]->(c:CVE) RETURN h LIMIT 25"}, "stop"),
  "write_query": ({"decision": "answer", "cypher": "MATCH (m:Malware) DETACH DELETE m"}, "stop"),
  "truncated": ('{"decision":"answer","cypher":"MATCH (', "length"),
}
CHECK_CASES = {
  "accepted": _CYPHER_OK,
  "unknown_label": "MATCH (h:Host) RETURN h LIMIT 5",
  "no_limit": "MATCH (i:Indicator) RETURN i.value AS value",
}


def _completion(content, finish_reason):
  return _Response(payload={"result": {
    "TEXT_RESPONSE": content,
    "FULL_OUTPUT": {"choices": [{"message": {"content": content}, "finish_reason": finish_reason}],
                    "usage": {"completion_tokens": 20}},
  }})


def normalise(value):
  if isinstance(value, dict):
    if value.get("role") == "system":  # the long system prompt is pinned by hash
      return {"role": "system", "content_sha256": hashlib.sha256(value["content"].encode()).hexdigest()}
    # The surface is long and repeated per route: pin it by hash.
    return {
      k: (hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest() if k == "schema_surface" else normalise(v))
      for k, v in sorted(value.items()) if k not in IDENTITY_FIELDS | VOLATILE_FIELDS
    }
  if isinstance(value, (list, tuple)):
    return [normalise(v) for v in value]
  return value


def dumps_by_case(data):
  """JSON with one line per case, so the fixture stays reviewable."""
  tops = []
  for top, value in sorted(data.items()):
    if top in ("generate", "check_cypher", "neo4j_query", "explain_graph"):
      cases = ",\n".join(f"  {json.dumps(k)}: {json.dumps(v, sort_keys=True)}" for k, v in sorted(value.items()))
      tops.append(f"{json.dumps(top)}: {{\n{cases}\n}}")
    else:
      tops.append(f"{json.dumps(top)}: {json.dumps(value, sort_keys=True)}")
  return "{\n" + ",\n".join(tops) + "\n}\n"


def _api(worker):
  return _make_api(
    edgeguard_generation_workers={MODEL_KEY: worker, **TEST_GENERATION_WORKERS},
    worker_semaphore_env={SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53009"}},
  )


def _body(result):
  return result["result"] if isinstance(result, dict) and set(result) == {"status_code", "result", "logged"} else result


def capture(worker):
  """Run every case against `worker` (the decision-JSON entry); return a JSON-safe dict."""
  out = {"generate": {}, "check_cypher": {}, "neo4j_query": {}, "explain_graph": {}}
  for name, (reply, finish) in GENERATE_CASES.items():
    plugin = _api(worker)
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = _completion(reply if isinstance(reply, str) else json.dumps(reply), finish)
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
      result = plugin.generate(request="Which techniques does the group use?", model_key=MODEL_KEY)
    out["generate"][name] = {
      "worker_payload": normalise(session.post.call_args.kwargs["json"]),
      "response": normalise(_body(result)),
      "worker_calls": session.post.call_count,
    }
  plugin = _api(worker)
  for name, cypher in CHECK_CASES.items():
    out["check_cypher"][name] = normalise(_body(plugin.check_cypher(cypher=cypher, model_key=MODEL_KEY)))
  rejected = CHECK_CASES["unknown_label"]
  out["neo4j_query"]["rejected"] = normalise(_body(plugin.neo4j_query(
    uri="example.com:7687", scheme="bolt+s", username="neo4j", password="x", cypher=rejected, model_key=MODEL_KEY)))
  record = MagicMock()
  record.data.return_value = {"value": "1.2.3.4"}
  result = MagicMock()
  result.__iter__.return_value = iter([record])
  session = MagicMock()
  session.__enter__.return_value = session
  session.run.return_value = [record]
  driver = MagicMock()
  driver.session.return_value = session
  with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
    with patch.object(plugin, "_neo4j_driver", return_value=driver):
      for name, cypher in {"accepted": _CYPHER_OK, "no_limit": CHECK_CASES["no_limit"]}.items():
        out["neo4j_query"][name] = normalise(_body(plugin.neo4j_query(
          uri="example.com:7687", scheme="bolt+s", username="neo4j", password="x",
          cypher=cypher, model_key=MODEL_KEY)))
  out["explain_graph"]["rejected"] = normalise(_body(plugin.explain_graph(
    request="Show hosts", cypher=rejected, explanation_mode="fast", model_key=MODEL_KEY)))
  entry = {p["model_key"]: p for p in plugin.prompt_contract()["profiles"]}[MODEL_KEY]
  out["prompt_contract"] = normalise(entry)
  model = {m["model_key"]: m for m in plugin.models()["models"]}[MODEL_KEY]
  out["models"] = normalise(model)
  return json.loads(json.dumps(out, default=str))


if __name__ == "__main__":
  if "--write" not in sys.argv:
    sys.exit("pass --write to regenerate the fixture from the profile-name worker entry")
  legacy = {"SEMAPHORE": SEMAPHORE, "PATH": "/create_chat_completion",
            "PROMPT_PROFILE": "decision_json_v2026_11_08", "DISPLAY_NAME": "decision fixture model"}
  FIXTURE_PATH.write_text(dumps_by_case(capture(legacy)))
  print("wrote", FIXTURE_PATH)
