"""EGX/2 insight-brief runtime: deterministic insight sheet plus a typed model brief.

The insight layer computes a typed sheet from the full redacted packet graph in
deterministic code; the model only narrates it. Hard gate failure triggers one
validated retry naming the failed checks; a second failure (or any provider
failure) degrades to a deterministic rendering of the insight sheet, never a
bare "unavailable". A thin sheet (< 1 substantive insight) is answered
deterministically without a model call.

Deviation from the EGX/2 spec recorded here: digest-strategy responses carry no
`neo4j_trace`, so `entity_ids` reference `packet.graph` node ids and the client
renders its IOC inventory from `packet.graph` instead of a trace catalog.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Mapping, Optional

from . import brief_gates
from . import brief_profile
from . import field_catalog as fc
from . import insights
from ..graph_first_runtime import GraphFirstRuntimeError

PROFILE_ID = "EGX/2"
STRATEGY = "insight_brief"
CASE_EXPLANATION_VERSION = "edgeguard.case_explanation.v2"
TRACE_VERSION = "edgeguard.explanation_trace.v2"
MAX_TOKENS = 768
TEMPERATURE = 0.7
TOP_P = 0.8
MAX_OBSERVATIONS = 4
MAX_NEXT_CHECKS = 3
TEXT_LIMIT = 1_000
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

RETRY_NOTE_TEMPLATE = (
  "\n\nRETRY: your previous brief failed these deterministic checks: {failures}. "
  "Fix only those problems. Cite only I# ids that appear in the sheet, name "
  "entities only from an insight's [examples: ...] list, and state only counts "
  "the sheet itself states."
)

PROFILE_MANIFEST = {
  "profile_id": PROFILE_ID,
  "strategy": STRATEGY,
  # Bumped with deterministic insight-layer changes (primitives, sheet
  # rendering, gate set) so the profile hash reflects notation changes even
  # when the prompt text is unchanged.
  "insights_version": 2,
  "case_explanation_schema_version": CASE_EXPLANATION_VERSION,
  "trace_schema_version": TRACE_VERSION,
  "catalog_sha256": fc.CATALOG_SHA256,
  "system_prompt": brief_profile.SYSTEM,
  "user_template": brief_profile.USER_TEMPLATE,
  "retry_note_template": RETRY_NOTE_TEMPLATE,
  "sampling": {"temperature": TEMPERATURE, "top_p": TOP_P, "top_k": 20},
  "max_tokens": MAX_TOKENS,
  "hard_gates": sorted(brief_gates.HARD_GATES),
  "advisory_gates": sorted(brief_gates.ADVISORY_GATES),
}
PROFILE_SHA256 = hashlib.sha256(
  json.dumps(PROFILE_MANIFEST, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
).hexdigest()


def _entity_id_map(graph: Mapping[str, Any]) -> dict[str, str]:
  mapping: dict[str, str] = {}
  for node in graph.get("nodes", []) or []:
    view = fc.project(node)
    for key in ("name", "value", "cve_id", "mitre_id"):
      value = view.get(key)
      if isinstance(value, str) and value:
        mapping.setdefault(value.lower(), str(node.get("id")))
  return mapping


def _entity_ids_for(names: list[str], id_map: Mapping[str, str]) -> list[str]:
  ids = []
  for name in names:
    node_id = id_map.get(str(name).lower())
    if node_id is not None and node_id not in ids:
      ids.append(node_id)
  return ids


def _insight_index(sheet: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
  return [{"id": ins["id"], "kind": ins["kind"], "count": ins["count"]} for ins in sheet]


def _confidence_from_sheet(sheet: list[Mapping[str, Any]]) -> dict[str, str]:
  for ins in sheet:
    if ins.get("kind") == "confidence":
      return {"tier": str(ins.get("tier") or "low"), "basis": str(ins.get("text_hint") or "")[:TEXT_LIMIT]}
  return {"tier": "low", "basis": "no source-data confidence insight available"}


def _deterministic_case(
  sheet: list[Mapping[str, Any]],
  graph: Mapping[str, Any],
  mode: str,
  assessment_text: str,
) -> dict[str, Any]:
  """Render the insight sheet itself as the explanation, verbatim, no model."""
  id_map = _entity_id_map(graph)
  substantive = [ins for ins in sheet if ins.get("kind") != "confidence"]
  observations = []
  for ins in substantive[:MAX_OBSERVATIONS]:
    named = [e for e in (ins.get("exemplars") or []) if fc.is_nameable_value(e)]
    observations.append({
      "text": str(ins.get("text_hint") or "")[:TEXT_LIMIT],
      "insight_ids": [ins["id"]],
      "entity_ids": _entity_ids_for(named, id_map),
    })
  why = (
    "Deterministic summary: the listed observations restate every substantive "
    "precomputed insight for this result without model interpretation."
  )
  return {
    "schema_version": CASE_EXPLANATION_VERSION,
    "assessment": {"text": assessment_text[:TEXT_LIMIT], "insight_ids": [i["id"] for i in substantive[:2]]},
    "observations": observations,
    "why_it_matters": {"text": why, "insight_ids": []},
    "next_checks": [],
    "confidence": _confidence_from_sheet(sheet),
    "insight_index": _insight_index(sheet),
    "provenance": {"mode": mode, "profile_id": PROFILE_ID, "profile_sha256": PROFILE_SHA256},
  }


def _validated_text(value: Any, code: str, trace: Optional[Mapping[str, Any]]) -> str:
  if not isinstance(value, str) or not value.strip() or len(value) > TEXT_LIMIT or CONTROL_RE.search(value):
    raise GraphFirstRuntimeError(code, "validation", "brief text field is invalid", trace)
  return value.strip()


def _parse_brief(content: str, trace: Optional[Mapping[str, Any]]) -> dict[str, Any]:
  try:
    parsed = json.loads(content)
  except json.JSONDecodeError as exc:
    raise GraphFirstRuntimeError("invalid_brief_json", "response_parse", "brief is not valid JSON", trace) from exc
  if not isinstance(parsed, dict) or set(parsed) != {"assessment", "observations", "why_it_matters", "next_checks", "confidence"}:
    raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief has invalid keys", trace)
  brief: dict[str, Any] = {
    "assessment": _validated_text(parsed.get("assessment"), "invalid_brief_text", trace),
    "why_it_matters": _validated_text(parsed.get("why_it_matters"), "invalid_brief_text", trace),
  }
  observations = parsed.get("observations")
  next_checks = parsed.get("next_checks")
  if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_OBSERVATIONS:
    raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief observations are invalid", trace)
  if not isinstance(next_checks, list) or len(next_checks) > MAX_NEXT_CHECKS:
    raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief next_checks are invalid", trace)
  brief["observations"] = []
  for item in observations:
    if not isinstance(item, Mapping):
      raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief observation is invalid", trace)
    ids = item.get("insight_ids")
    entities = item.get("exemplar_entities")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
      raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "observation insight_ids are invalid", trace)
    if entities is not None and (not isinstance(entities, list) or not all(isinstance(x, str) for x in entities)):
      raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "observation exemplar_entities are invalid", trace)
    brief["observations"].append({
      "text": _validated_text(item.get("text"), "invalid_brief_text", trace),
      "insight_ids": list(ids),
      "exemplar_entities": list(entities or []),
    })
  brief["next_checks"] = []
  for item in next_checks:
    if not isinstance(item, Mapping):
      raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief next_check is invalid", trace)
    ids = item.get("insight_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
      raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "next_check insight_ids are invalid", trace)
    brief["next_checks"].append({
      "text": _validated_text(item.get("text"), "invalid_brief_text", trace),
      "insight_ids": list(ids),
    })
  confidence = parsed.get("confidence")
  if not isinstance(confidence, Mapping):
    raise GraphFirstRuntimeError("invalid_brief_shape", "response_parse", "brief confidence is invalid", trace)
  brief["confidence"] = {
    "tier": str(confidence.get("tier") or "")[:32],
    "basis": _validated_text(confidence.get("basis"), "invalid_brief_text", trace),
  }
  return brief


def _model_case(brief: Mapping[str, Any], sheet: list[Mapping[str, Any]], graph: Mapping[str, Any]) -> dict[str, Any]:
  id_map = _entity_id_map(graph)
  observations = []
  for item in brief["observations"]:
    observations.append({
      "text": item["text"],
      "insight_ids": item["insight_ids"],
      "entity_ids": _entity_ids_for(item.get("exemplar_entities") or [], id_map),
    })
  cited = [ids for item in brief["observations"] for ids in item["insight_ids"]]
  return {
    "schema_version": CASE_EXPLANATION_VERSION,
    "assessment": {"text": brief["assessment"], "insight_ids": sorted(set(cited))[:4]},
    "observations": observations,
    "why_it_matters": {"text": brief["why_it_matters"], "insight_ids": []},
    "next_checks": [dict(item) for item in brief["next_checks"]],
    "confidence": dict(brief["confidence"]),
    "insight_index": _insight_index(sheet),
    "provenance": {"mode": "model", "profile_id": PROFILE_ID, "profile_sha256": PROFILE_SHA256},
  }


def _trace(calls: list[Mapping[str, Any]], status: str, safe_code: Optional[str]) -> dict[str, Any]:
  completed = sum(1 for call in calls if call.get("status") in {"completed", "supported"})
  return {
    "schema_version": TRACE_VERSION,
    "profile": {"id": PROFILE_ID, "sha256": PROFILE_SHA256},
    "calls": [dict(call) for call in calls],
    "outcome": {
      "status": status,
      "attempted_calls": len(calls),
      "completed_calls": completed,
      "safe_code": safe_code,
    },
  }


DETERMINISTIC_REASON_TEXTS = {
  "transport_truncated": (
    "Deterministic brief: the transport row cap was reached before result "
    "exhaustion, so the model was not consulted; the precomputed insights "
    "below summarize the transported rows only."
  ),
}


def run_insight_brief(
  *,
  question: str,
  graph: Mapping[str, Any],
  model: Optional[str],
  provider_call: Callable[[Mapping[str, Any]], Mapping[str, Any]],
  allow_model: bool = True,
  deterministic_reason: Optional[str] = None,
) -> dict[str, Any]:
  sheet = insights.build_insight_sheet(graph)
  substantive = [ins for ins in sheet if ins.get("kind") != "confidence"]
  if deterministic_reason is not None:
    text = DETERMINISTIC_REASON_TEXTS.get(
      deterministic_reason,
      "Deterministic brief: the model was not consulted; the precomputed "
      "insights below summarize the result verbatim.",
    )
    case = _deterministic_case(sheet, graph, "deterministic_fallback", text)
    return {"case_explanation": case, "explanation_trace": _trace([], "fallback", deterministic_reason)}
  if not substantive:
    case = _deterministic_case(
      sheet, graph, "deterministic_no_pattern",
      "No notable pattern: the returned result contains no substantive precomputed insight.",
    )
    return {"case_explanation": case, "explanation_trace": _trace([], "deterministic", "no_notable_pattern")}
  if not allow_model:
    case = _deterministic_case(
      sheet, graph, "deterministic_fallback",
      "Deterministic brief: the precomputed insights below summarize the result (model call not admitted).",
    )
    return {"case_explanation": case, "explanation_trace": _trace([], "fallback", "model_not_admitted")}

  prompt = brief_profile.build_brief_prompt(sheet, question)
  calls: list[dict[str, Any]] = []
  failure_code: Optional[str] = None
  retry_note = ""
  for attempt in (1, 2):
    user_content = prompt["user"] + retry_note
    payload: dict[str, Any] = {
      "messages": [
        {"role": "system", "content": prompt["system"]},
        {"role": "user", "content": user_content},
      ],
      "metadata": {"profile_id": PROFILE_ID, "task": "edgeguard_insight_brief"},
      "response_format": {"type": "json_object"},
      "temperature": TEMPERATURE,
      "top_p": TOP_P,
      "max_tokens": MAX_TOKENS,
    }
    if isinstance(model, str) and model:
      payload["model"] = model
    call: dict[str, Any] = {
      "kind": "insight_brief",
      "attempt": attempt,
      "status": "started",
      "request_sha256": hashlib.sha256(user_content.encode("utf-8")).hexdigest(),
      "model": model,
      "max_tokens": MAX_TOKENS,
      "temperature": TEMPERATURE,
      "top_p": TOP_P,
      "finish_reason": None,
      "completion_tokens": None,
    }
    try:
      raw = provider_call(payload)
      if not isinstance(raw, Mapping):
        raise GraphFirstRuntimeError("invalid_provider_response", "completion", "brief provider response is invalid")
      finish_reason = raw.get("finish_reason")
      completion_tokens = raw.get("completion_tokens")
      call.update({
        "status": "completed",
        "finish_reason": finish_reason if finish_reason in {"stop", "length"} else "other" if finish_reason is not None else None,
        "completion_tokens": completion_tokens if isinstance(completion_tokens, int) and not isinstance(completion_tokens, bool) and completion_tokens >= 0 else None,
      })
      if finish_reason != "stop":
        code = "output_truncated" if finish_reason == "length" else "completion_metadata_missing"
        raise GraphFirstRuntimeError(code, "completion", "brief completion metadata is invalid")
      content = raw.get("content")
      if not isinstance(content, str) or not content:
        raise GraphFirstRuntimeError("missing_content", "completion", "brief content is missing")
      brief = _parse_brief(content, None)
      results = brief_gates.grade(brief, sheet)
      hard_failures = {
        name: detail for name, (passed, detail, tier) in results.items()
        if tier == "hard" and not passed
      }
      call["gates"] = {name: passed for name, (passed, _detail, _tier) in results.items()}
      if hard_failures:
        failure_code = "deterministic_validation_failed"
        call["status"] = "failed"
        calls.append(call)
        retry_note = RETRY_NOTE_TEMPLATE.format(failures="; ".join(
          f"{name}: {detail}" for name, detail in sorted(hard_failures.items())
        ))
        continue
      call["status"] = "supported"
      calls.append(call)
      return {
        "case_explanation": _model_case(brief, sheet, graph),
        "explanation_trace": _trace(calls, "supported", None),
      }
    except GraphFirstRuntimeError as exc:
      failure_code = exc.code
      if call.get("status") == "started":
        call["status"] = "failed"
      calls.append(call)
      if exc.code in {"model_not_configured", "model_not_ready"}:
        break
      retry_note = RETRY_NOTE_TEMPLATE.format(failures=exc.code)
      continue

  case = _deterministic_case(
    sheet, graph, "deterministic_fallback",
    "Deterministic brief: the model output did not pass validation, so the "
    "precomputed insights below summarize the result verbatim.",
  )
  return {"case_explanation": case, "explanation_trace": _trace(calls, "fallback", failure_code)}
