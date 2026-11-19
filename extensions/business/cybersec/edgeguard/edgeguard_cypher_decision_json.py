"""Decision-JSON prompt profile: EdgeGuard Cypher 2026-11-08 (IICT-BAS Qwen3-4B adapter).

The adapter was trained on one system prompt (vendored byte-for-byte in
`prompts/`, version `5e12777d5a`) and the question alone. It replies with one
line of JSON whose first key is `decision`:

  answer        {"decision":"answer","cypher":"..."}
  partial       {"decision":"partial","cypher":"...","note":"..."}
  clarify       {"decision":"clarify","question":"..."}
  out_of_scope  {"decision":"out_of_scope","reason":"..."}
  refuse        {"decision":"refuse","reason":"..."}

A reply that does not parse as one of these is a failed generation.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .edgeguard_cypher_guard import EdgeGuardCypherGuardError

PROMPT_PROFILE_DECISION_JSON_2026_11_08 = "decision_json_v2026_11_08"
SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "edgeguard_cypher_2026_11_08_system_prompt.txt"
# Adapter bundle `SHA256SUMS`, entry `system_prompt.txt` (version 5e12777d5a).
SYSTEM_PROMPT_SHA256 = "da06f1e43e6102b9c04adaa4b361ef1d81e2a4e3ac3d3759525689a7cf47a2eb"
SYSTEM_PROMPT_VERSION = "5e12777d5a"

SCHEMA_VERSION_DECISION_JSON = "edgeguard-v2026.11.6-prompt-5e12777d5a"
# Guard allowlist: the graph schema the system prompt describes ("Nodes",
# "Relationships", the relationship evidence properties, and the duration()
# map keys of its relative-time rule). The adapter was trained on exactly this.
_NODE_PROPERTIES = {
  "ThreatActor": "name mitre_id aliases description zone source",
  "Malware": "name mitre_id aliases description zone source",
  "Tool": "mitre_id name aliases description",
  "Technique": "mitre_id name tactic_phases attack_domain is_subtechnique detection",
  "Tactic": "mitre_id name shortname attack_domain",
  "CVE": ("cve_id description cvss_score cvss_version severity attack_vector published cisa_exploit_add "
          "cisa_action_due cisa_vulnerability_name known_ransomware_use epss_score epss_percentile "
          "ssvc_exploitation ssvc_automatable ssvc_technical_impact cwe affected_products zone"),
  "CVSSv31": "cve_id base_score base_severity vector_string attack_vector attack_complexity "
             "privileges_required user_interaction scope",
  "Indicator": ("indicator_type value confidence_score active last_reported_at first_imported_at aging_tier "
                "malware_family url_status zone"),
  "Campaign": "name actor_name indicator_count malware_count first_seen last_seen zone",
  "Sector": "name",
  "Source": "source_id name type reliability",
}
_NODE_PROPERTIES.update({label: _NODE_PROPERTIES["CVSSv31"] for label in ("CVSSv30", "CVSSv2", "CVSSv40")})
_RELATIONSHIP_PROPERTIES = (
  "confidence imported_at source_reported_first_at source_reported_last_at misp_event_ids "  # SOURCED_FROM
  "match_type confidence_score sources"  # evidence on the other relationships
)
_DURATION_KEYS = "years months weeks days hours minutes seconds"
DECISION_JSON_SCHEMA = {
  "labels": set(_NODE_PROPERTIES),
  "relationship_types": {
    "EMPLOYS_TECHNIQUE", "IMPLEMENTS_TECHNIQUE", "USES_TECHNIQUE", "ATTRIBUTED_TO", "USES_MALWARE",
    "USES_TOOL", "INDICATES", "EXPLOITS", "TARGETS", "AFFECTS", "IN_TACTIC", "SUBTECHNIQUE_OF", "RUNS",
    "PART_OF_CAMPAIGN", "HAS_CVSS_v31", "HAS_CVSS_v30", "HAS_CVSS_v2", "HAS_CVSS_v40", "SOURCED_FROM",
  },
  "properties": (
    {p for props in _NODE_PROPERTIES.values() for p in props.split()}
    | set(_RELATIONSHIP_PROPERTIES.split()) | set(_DURATION_KEYS.split())
  ),
}

DECISION_ANSWER = "answer"
DECISION_PARTIAL = "partial"
QUERY_DECISIONS = (DECISION_ANSWER, DECISION_PARTIAL)
# The field each declining decision carries as its message for the analyst.
DECLINE_MESSAGE_FIELDS = {"clarify": "question", "out_of_scope": "reason", "refuse": "reason"}


def load_system_prompt(path: Optional[Path] = None) -> str:
  """The vendored system prompt, unchanged (final newline included); refuses a modified file."""
  data = (path or SYSTEM_PROMPT_PATH).read_bytes()
  digest = hashlib.sha256(data).hexdigest()
  if digest != SYSTEM_PROMPT_SHA256:
    raise EdgeGuardCypherGuardError(
      f"decision-JSON system prompt sha256 {digest} does not match the pinned {SYSTEM_PROMPT_SHA256}"
    )
  return data.decode("utf-8")


def parse_decision_reply(raw: Any) -> Dict[str, Any]:
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
  if decision in QUERY_DECISIONS:
    cypher = obj.get("cypher")
    if not isinstance(cypher, str) or not cypher.strip():
      return {"ok": False, "error": f"Decision '{decision}' without a Cypher query."}
    note = obj.get("note") if decision == DECISION_PARTIAL else None
    return {"ok": True, "decision": decision, "cypher": cypher.strip(),
            "note": note if isinstance(note, str) else None, "message": None}
  if decision in DECLINE_MESSAGE_FIELDS:
    message = obj.get(DECLINE_MESSAGE_FIELDS[decision])
    return {"ok": True, "decision": decision, "cypher": None, "note": None,
            "message": message if isinstance(message, str) else None}
  return {"ok": False, "error": "The reply has no valid decision."}
