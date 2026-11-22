"""Decision-JSON reply parser (EdgeGuard Cypher 2026-11-08, IICT-BAS adapter).

The adapter was trained on one system prompt (vendored in its prompt pack,
`prompts/packs/cypher_2026_11_08/`) and the question alone. It replies with one
line of JSON whose first key is `decision`:

  answer        {"decision":"answer","cypher":"..."}
  partial       {"decision":"partial","cypher":"...","note":"..."}
  clarify       {"decision":"clarify","question":"..."}
  out_of_scope  {"decision":"out_of_scope","reason":"..."}
  refuse        {"decision":"refuse","reason":"..."}

The pack's `field_map` names the JSON field behind each role (`cypher`, `note`,
`message`) per decision. A reply that does not parse is a failed generation.
"""

import json
import re
from typing import Any, Dict


def parse_decision_reply(raw: Any, field_map: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
  """Parse one model reply.

  Returns `{"ok": True, "decision", "cypher", "note", "message"}` or
  `{"ok": False, "error"}`. `message` is the clarifying question or the reason
  of a declining decision; `note` is the `partial` note.
  """
  text = str(raw or "").strip()
  fenced = re.match(r"^```[a-zA-Z]*\s*(.*?)\s*```$", text, re.S)
  if fenced:
    text = fenced.group(1).strip()
  try:
    obj = json.loads(text.splitlines()[0] if text else "")
  except (json.JSONDecodeError, IndexError):
    return {"ok": False, "error": "The reply is not one line of JSON."}
  decision = obj.get("decision") if isinstance(obj, dict) else None
  fields = field_map.get(decision) if isinstance(decision, str) else None
  if fields is None:
    return {"ok": False, "error": "The reply has no valid decision."}
  if "cypher" in fields:
    cypher = obj.get(fields["cypher"])
    if not isinstance(cypher, str) or not cypher.strip():
      return {"ok": False, "error": f"Decision '{decision}' without a Cypher query."}
    note = obj.get(fields["note"]) if "note" in fields else None
    return {"ok": True, "decision": decision, "cypher": cypher.strip(),
            "note": note if isinstance(note, str) else None, "message": None}
  message = obj.get(fields["message"])
  return {"ok": True, "decision": decision, "cypher": None, "note": None,
          "message": message if isinstance(message, str) else None}
