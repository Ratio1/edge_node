"""Offline replay of stored model replies through `generate` (no model, no Neo4j).

Each stored reply is returned by a mocked worker, so the run measures the parser
and guard only. No data lives in the repo: paths come from argv.

  python -m extensions.business.cybersec.edgeguard.tests.replay_stored_replies \
      REPLIES.jsonl OUT.json [--grounding on|off|pack] [--profile NAME]

REPLIES.jsonl rows hold `id`, `raw` and `finish_reason`; the question text is not
needed because the worker is mocked (a fixed stand-in question is sent).
OUT.json maps id to `{status, decision, cypher, candidate, feedback, unknown}`
(`candidate` is the query the guard saw, `unknown` the names it refused).
"""

import argparse
import dataclasses
import json
from collections import Counter
from unittest.mock import MagicMock, patch

# test_api installs the naeural_core stubs at import time, so it comes first.
from extensions.business.cybersec.edgeguard.tests.test_api import _Response, _make_api

KEY = "replay-model"
SEMAPHORE = "edgeguard_llm_replay"


def _completion(raw, finish_reason):
  return _Response(payload={"result": {
    "TEXT_RESPONSE": raw,
    "FULL_OUTPUT": {"choices": [{"message": {"content": raw}, "finish_reason": finish_reason}],
                    "usage": {"completion_tokens": 20}},
  }})


def replay(rows, profile="decision_json_v2026_11_08", grounding="pack"):
  workers = {KEY: {"SEMAPHORE": SEMAPHORE, "PATH": "/create_chat_completion", "PROMPT_PROFILE": profile,
                   "DISPLAY_NAME": "replay"}}
  out = {}
  for row in rows:
    plugin = _make_api(edgeguard_generation_workers=workers,
                       worker_semaphore_env={SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53009"}})
    if grounding != "pack":
      pack = plugin._prompt_pack(KEY)
      forced = dataclasses.replace(pack, grounding=(grounding == "on"))
      plugin._prompt_pack = lambda _key, forced=forced: forced
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = _completion(row["raw"], row.get("finish_reason", "stop"))
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
      result = plugin.generate(request="replayed question", model_key=KEY)
    attempt = (result.get("attempts") or [{}])[-1]
    out[row["id"]] = {
      "status": result.get("status"),
      "decision": result.get("decision"),
      "cypher": result.get("accepted_cypher"),
      "candidate": attempt.get("candidate_cypher"),
      "feedback": result.get("validation_feedback") or "",
      "unknown": attempt.get("schema_unknown") or {},
    }
  return out


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("replies")
  parser.add_argument("out")
  parser.add_argument("--grounding", choices=["on", "off", "pack"], default="pack")
  parser.add_argument("--profile", default="decision_json_v2026_11_08")
  args = parser.parse_args()
  with open(args.replies, encoding="utf-8") as handle:
    rows = [json.loads(line) for line in handle if line.strip()]
  out = replay(rows, profile=args.profile, grounding=args.grounding)
  with open(args.out, "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=1)
  print(dict(Counter(item["status"] for item in out.values())))


if __name__ == "__main__":
  main()
