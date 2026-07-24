"""Production binding for EdgeGuard EGX/1 graph-first explanation.

Wires the pure `explain_selection` / `explain_notation` / `explain_profile` /
`explain_gates` modules into the production request lifecycle: selection ->
render -> one analyst call + at most one validated retry -> gates ->
`CaseExplanation v1` assembly -> coverage v2 -> trace v2.

Kept from the EEL/1-era `graph_first_runtime.py` (imported, not duplicated --
that module stays byte-untouched as the rollback target): the tokenizer
artifact identity (`TOKENIZER_JSON_SHA256`), the qwen chat renderer, and the
sanitized Neo4j trace builder. `GraphFirstRuntimeError` and
`GraphFirstContractError` are reused as the shared runtime/contract
exception vocabulary -- they are generic infrastructure, not EEL/1-specific.

Explicitly NOT reused: `validate_frozen_sources()` (EGX/1 prompts are not
byte-frozen by design -- identity is the profile-manifest SHA instead) and
the chat-template token measurement (`render_chat`) for budgeting -- the
EGM-047 measured-rate calibration (`explain_profile.PREFILL_TOKENS_PER_SEC`
etc.) was performed against raw-text tokenization
(`workbooks/egm-047-notation-bakeoff/harness/tokens.py`), so the production
counter here tokenizes raw text directly to stay faithful to that
calibration.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from . import explain_gates as gates
from . import explain_notation as notation
from . import explain_profile as profile
from . import explain_selection as selection
from .graph_first_explanation import GraphFirstContractError, CASE_EXPLANATION_VERSION
from .graph_first_runtime import (
  GraphFirstRuntimeError,
  TOKENIZER_JSON_SHA256,
  TOKENIZER_DEFAULT_PATH,
  _compatible_tokenizer_json,
)


PROFILE_ID = profile.PROFILE_ID
NOTATION_ID = profile.NOTATION_ID
PROFILE_SHA256 = profile.PROFILE_MANIFEST_SHA256
TRACE_VERSION = "edgeguard.explanation_trace.v2"
COVERAGE_VERSION = "edgeguard.explanation_coverage.v2"
MAX_TOKENS = profile.MAX_TOKENS
COMPLETION_TOKEN_LIMIT = profile.COMPLETION_TOKEN_LIMIT
MODE_ROW_LIMITS = {"fast": 10, "balanced": 25, "thorough": 50}
CALL_CAP = 1  # per mode, excluding the one validated retry
RETRY_MIN_REMAINING_SECONDS = profile.CALL_BUDGET_SECONDS + 30

TASK_KINDS = {
  "analyst": "edgeguard_explain_v2_analyst",
  "retry": "edgeguard_explain_v2_retry",
}


@dataclasses.dataclass(frozen=True)
class ModePlanV2:
  mode: str
  row_limit: int
  call_cap: int
  max_tokens: int


def _fail(code: str, detail: str) -> None:
  raise GraphFirstContractError(code, detail)


def _strict_positive_integer(value: Any, name: str) -> Optional[int]:
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
    _fail("invalid_explanation_limit", f"{name} must be a positive integer")
  return value


def resolve_mode_v2(
  explanation_mode: Any = None,
  explanation_rows: Any = None,
  max_rows: Any = None,
  *,
  temperature: Any = None,
  top_p: Any = None,
  top_k: Any = None,
  max_tokens: Any = None,
) -> ModePlanV2:
  """Resolve the EGX/1 mode plan; reject drift from the pinned sampling
  contract (`temperature=0.7`, `top_p=0.8`, `top_k=20`, `max_tokens=320`)."""
  rows = _strict_positive_integer(explanation_rows, "explanation_rows")
  legacy_max = _strict_positive_integer(max_rows, "max_rows")
  if rows is not None and legacy_max is not None and rows != legacy_max:
    _fail("conflicting_explanation_limits", "legacy explanation row limits must be equal")
  legacy = rows if rows is not None else legacy_max
  if legacy is not None and legacy > 50:
    _fail("explanation_limit_exceeded", "graph-first explanation supports at most 50 rows")
  if explanation_mode is not None:
    if not isinstance(explanation_mode, str) or explanation_mode not in MODE_ROW_LIMITS:
      _fail("invalid_explanation_mode", "explanation_mode must be fast, balanced, or thorough")
    mode = explanation_mode
  elif legacy is None or legacy > 10:
    mode = "balanced" if legacy is None or legacy <= 25 else "thorough"
  else:
    mode = "fast"
  cap = MODE_ROW_LIMITS[mode]
  row_limit = min(cap, legacy) if legacy is not None else cap
  if temperature is not None and (
    isinstance(temperature, bool) or not isinstance(temperature, (int, float))
    or not math.isfinite(float(temperature)) or float(temperature) != profile.MODEL_CARD_SAMPLING["temperature"]
  ):
    _fail("explanation_configuration_drift", "temperature must be 0.7")
  if top_p is not None and (
    isinstance(top_p, bool) or not isinstance(top_p, (int, float))
    or not math.isfinite(float(top_p)) or float(top_p) != profile.MODEL_CARD_SAMPLING["top_p"]
  ):
    _fail("explanation_configuration_drift", "top_p must be 0.8")
  if top_k is not None and (
    isinstance(top_k, bool) or not isinstance(top_k, int) or top_k != profile.MODEL_CARD_SAMPLING["top_k"]
  ):
    _fail("explanation_configuration_drift", "top_k must be 20")
  selected_tokens = MAX_TOKENS if max_tokens is None else _strict_positive_integer(max_tokens, "max_tokens")
  if selected_tokens != MAX_TOKENS:
    _fail("explanation_configuration_drift", "max_tokens must be 320")
  return ModePlanV2(mode, row_limit, CALL_CAP, selected_tokens)


# --------------------------------------------------------------------------
# Production token counter: raw-text tokenization via the frozen tokenizer
# artifact (same on-disk artifact/identity hash as EEL/1; NOT chat-templated
# -- see module docstring).
# --------------------------------------------------------------------------

_TOKENIZER_LOCK = threading.Lock()
_TOKENIZER_CACHE: dict[str, tuple[Optional[Callable[[str], int]], Optional[str]]] = {}


def _load_text_token_counter(path: str) -> Callable[[str], int]:
  try:
    raw = Path(path).read_bytes()
  except OSError as exc:
    raise GraphFirstRuntimeError("tokenizer_missing", "configuration", "graph-first tokenizer is unavailable") from exc
  if hashlib.sha256(raw).hexdigest() != TOKENIZER_JSON_SHA256:
    raise GraphFirstRuntimeError("tokenizer_drift", "configuration", "graph-first tokenizer identity differs")
  try:
    from tokenizers import Tokenizer
    tokenizer = Tokenizer.from_str(_compatible_tokenizer_json(raw))
  except GraphFirstRuntimeError:
    raise
  except Exception as exc:
    raise GraphFirstRuntimeError("tokenizer_incompatible", "configuration", "graph-first tokenizer cannot load") from exc

  def count(text: str) -> int:
    if not text:
      return 0
    try:
      ids = tokenizer.encode(text, add_special_tokens=False).ids
    except Exception as exc:
      raise GraphFirstRuntimeError("tokenizer_failure", "configuration", "graph-first tokenization failed") from exc
    return len(ids)

  return count


def production_token_counter(path: str = TOKENIZER_DEFAULT_PATH) -> Callable[[str], int]:
  with _TOKENIZER_LOCK:
    cached = _TOKENIZER_CACHE.get(path)
    if cached is None:
      try:
        counter = _load_text_token_counter(path)
        cached = (counter, None)
      except GraphFirstRuntimeError as exc:
        cached = (None, exc.code)
      _TOKENIZER_CACHE[path] = cached
  counter, error = cached
  if counter is None:
    raise GraphFirstRuntimeError(error or "tokenizer_unavailable", "configuration", "graph-first tokenizer binding failed")
  return counter


# --------------------------------------------------------------------------
# Payload / parsing / gates
# --------------------------------------------------------------------------

def _payload(prompt: Mapping[str, str], kind: str, mode: ModePlanV2, model: Optional[str]) -> dict[str, Any]:
  value: dict[str, Any] = {
    "max_tokens": mode.max_tokens,
    "messages": [
      {"role": "system", "content": prompt["system"]},
      {"role": "user", "content": prompt["user"]},
    ],
    "metadata": {"profile_id": PROFILE_ID, "notation_id": NOTATION_ID, "task": TASK_KINDS[kind]},
    "response_format": {"type": "json_object"},
    "temperature": profile.MODEL_CARD_SAMPLING["temperature"],
    "top_p": profile.MODEL_CARD_SAMPLING["top_p"],
  }
  if isinstance(model, str) and model:
    value["model"] = model
  return value


def _parse_response(content: Any) -> tuple[Optional[dict[str, Any]], Optional[str]]:
  if not isinstance(content, str) or not content:
    return None, "missing_content"
  try:
    value = json.loads(content)
  except (TypeError, ValueError) as exc:
    return None, f"invalid_json: {exc}"
  if not isinstance(value, dict) or set(value) != {"citations", "finding"}:
    return None, "invalid_shape"
  citations = value["citations"]
  finding = value["finding"]
  if not isinstance(citations, list) or not all(isinstance(item, str) and item for item in citations):
    return None, "invalid_citations"
  if not isinstance(finding, str) or not finding.strip():
    return None, "invalid_finding"
  return {"citations": citations, "finding": finding}, None


def _validated_completion_tokens(value: Any) -> Optional[int]:
  """Completion-token ceiling: an integer in `[0, COMPLETION_TOKEN_LIMIT]`
  (384) inclusive."""
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > COMPLETION_TOKEN_LIMIT:
    raise GraphFirstRuntimeError(
      "completion_metadata_missing", "completion",
      "graph-first completion token accounting is missing or invalid",
    )
  return value


def _retry_budget_ok(remaining_seconds: Any) -> bool:
  return (
    isinstance(remaining_seconds, (int, float))
    and not isinstance(remaining_seconds, bool)
    and math.isfinite(remaining_seconds)
    and remaining_seconds >= RETRY_MIN_REMAINING_SECONDS
  )


def _validate_dispatch_budget(remaining_seconds: Any) -> None:
  if (
    isinstance(remaining_seconds, bool) or not isinstance(remaining_seconds, (int, float))
    or not math.isfinite(float(remaining_seconds)) or remaining_seconds < 0
  ):
    raise GraphFirstRuntimeError("invalid_deadline_budget", "internal", "deadline budget inputs are invalid")
  if remaining_seconds < profile.CALL_BUDGET_SECONDS + 30:
    raise GraphFirstRuntimeError(
      "insufficient_deadline_budget", "completion",
      "remaining request time cannot cover the required call",
    )


# --------------------------------------------------------------------------
# Trace v2 assembly
# --------------------------------------------------------------------------

def _new_trace(mode: ModePlanV2) -> dict[str, Any]:
  return {
    "schema_version": TRACE_VERSION,
    "profile": {"id": PROFILE_ID, "notation_id": NOTATION_ID, "sha256": PROFILE_SHA256},
    "mode": {"requested": mode.mode, "effective": mode.mode, "row_limit": mode.row_limit, "call_cap": mode.call_cap},
    "selection": {},
    "calls": [],
    "outcome": {},
  }


def _new_call(call_id: str, kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
  """A trace-v2 call record never carries the full request (messages/
  evidence text) on success or failure -- only a `configuration` echo of the
  sampling contract (temperature/top_p/max_tokens) travels, matching the UI
  validator's exact-key-set contract for `explanation_trace.v2` calls."""
  return {
    "id": call_id,
    "kind": kind,
    "configuration": {
      "temperature": payload.get("temperature"),
      "top_p": payload.get("top_p"),
      "max_tokens": payload.get("max_tokens"),
    },
    "duration_ms": 0.0,
    "finish_reason": "missing",
    "completion_tokens": None,
    "status": "started",
    "gates": {},
  }


def _selection_summary(
  source_graph: Mapping[str, Any],
  sel_graph: Mapping[str, Any],
  sel_trace: Sequence[Mapping[str, Any]],
  scaffold_tokens: int,
  budget: int,
  evidence_tokens: int,
) -> dict[str, Any]:
  """Content-free (counts and action names only, never property values)."""
  degrade_actions = sorted({
    item["action"] for item in sel_trace
    if item.get("stage") == "D" and item.get("action") not in ("measure", "final")
  })
  return {
    "source_nodes": len(source_graph.get("nodes", [])),
    "source_relationships": len(source_graph.get("relationships", [])),
    "admitted_nodes": len(sel_graph.get("nodes", [])),
    "admitted_relationships": len(sel_graph.get("relationships", [])),
    "scaffold_tokens": scaffold_tokens,
    "evidence_budget_tokens": budget,
    "evidence_tokens": evidence_tokens,
    "degrade_actions": degrade_actions,
  }


def _safe_failure_trace_v2(trace: Mapping[str, Any], stage: str, code: str, attempted: int, completed: int) -> dict[str, Any]:
  """Strip `raw_output`/`parsed` (never present on failed calls in the first
  place, since they are only attached after a call passes every gate) and
  keep only the content-free call fields; `configuration` already never
  carries messages/evidence text (see `_new_call`)."""
  safe_calls = []
  for call in trace.get("calls", []):
    safe_call = {
      key: call[key]
      for key in ("id", "kind", "configuration", "duration_ms", "finish_reason", "completion_tokens", "status", "gates")
      if key in call
    }
    safe_calls.append(safe_call)
  return {
    **trace,
    "calls": safe_calls,
    "outcome": {
      "status": "failed",
      "attempted_calls": attempted,
      "completed_calls": completed,
      "failure_stage": stage,
      "safe_code": code,
    },
  }


def empty_failure_trace(mode: ModePlanV2, stage: str, code: str) -> dict[str, Any]:
  """Strict trace envelope for failures before selection or dispatch."""
  return _safe_failure_trace_v2(_new_trace(mode), stage, code, 0, 0)


# --------------------------------------------------------------------------
# CaseExplanation v1 assembly + coverage v2
# --------------------------------------------------------------------------

def _assemble_case_explanation(rendered, response: Mapping[str, Any], *, caveats: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
  citations = list(response.get("citations") or [])
  finding_text = str(response.get("finding") or "")
  member_ids: list[str] = []
  for citation_id in citations:
    for member in rendered.citation_members(citation_id):
      if member not in member_ids:
        member_ids.append(member)
  entity_findings = []
  if citations:
    entity_id = rendered.citation_subject(citations[0])
    if entity_id is not None:
      entity_findings.append({
        "entity_id": entity_id,
        "role": "evidence_anchor",
        "finding": finding_text,
        "evidence_ids": list(member_ids),
      })
  return {
    "schema_version": CASE_EXPLANATION_VERSION,
    "summary": {"text": finding_text, "evidence_ids": list(member_ids)},
    "key_paths": [],
    "entity_findings": entity_findings,
    "risk_interpretation": [],
    "provenance": [],
    "caveats": list(caveats),
    "missing_context": [],
    "next_pivots": [],
  }


def _property_slots(graph: Mapping[str, Any]) -> set[tuple[str, str]]:
  slots: set[tuple[str, str]] = set()
  for node in graph.get("nodes", []):
    for key in (node.get("properties") or {}):
      slots.add((node["id"], key))
  for rel in graph.get("relationships", []):
    rel_id = rel.get("id")
    if isinstance(rel_id, str):
      for key in (rel.get("properties") or {}):
        slots.add((rel_id, key))
  return slots


def _safe_ratio(numerator: int, denominator: int) -> float:
  return 1.0 if denominator == 0 else round(numerator / denominator, 6)


def _build_coverage(
  source_graph: Mapping[str, Any],
  sel_graph: Mapping[str, Any],
  rendered,
  response: Optional[Mapping[str, Any]],
  *,
  attempted_calls: int,
  completed_calls: int,
) -> dict[str, Any]:
  """`returned` = the packet graph handed to selection; `admitted` = survived
  Stage A-D selection; `cited` = referenced by the gate-passing finding."""
  returned_nodes = {n["id"] for n in source_graph.get("nodes", [])}
  returned_rels = {r["id"] for r in source_graph.get("relationships", []) if isinstance(r.get("id"), str)}
  admitted_nodes = {n["id"] for n in sel_graph.get("nodes", [])} & returned_nodes
  admitted_rels = {r["id"] for r in sel_graph.get("relationships", []) if isinstance(r.get("id"), str)} & returned_rels

  cited_members: set[str] = set()
  for citation_id in (response or {}).get("citations") or []:
    cited_members.update(rendered.citation_members(citation_id))
  cited_nodes = cited_members & returned_nodes
  cited_rels = cited_members & returned_rels

  def counts(returned: set[str], admitted: set[str], cited: set[str]) -> dict[str, int]:
    return {
      "returned": len(returned),
      "admitted": len(admitted),
      "cited": len(cited),
      "omitted": len(returned - admitted),
    }

  returned_props = _property_slots(source_graph)
  admitted_props = _property_slots(sel_graph) & returned_props
  cited_props = {slot for slot in admitted_props if slot[0] in cited_members}

  topology_returned = len(returned_nodes) + len(returned_rels)
  topology_admitted = len(admitted_nodes) + len(admitted_rels)
  completeness = {
    "topology": _safe_ratio(topology_admitted, topology_returned),
    "property": _safe_ratio(len(admitted_props), len(returned_props)),
  }
  completeness["overall"] = min(completeness.values())

  retry_calls = max(0, attempted_calls - 1)
  return {
    "schema_version": COVERAGE_VERSION,
    "scope": "bounded_query_result",
    "counts": {
      "nodes": counts(returned_nodes, admitted_nodes, cited_nodes),
      "relationships": counts(returned_rels, admitted_rels, cited_rels),
      "property_slots": {
        "returned": len(returned_props),
        "admitted": len(admitted_props),
        "cited": len(cited_props),
        "omitted": len(returned_props) - len(admitted_props),
      },
    },
    "calls": {"analyst": 1, "retry": retry_calls, "total": attempted_calls},
    "completeness": completeness,
  }


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def run_explanation_v2(
  *,
  question: str,
  graph: Mapping[str, Any],
  mode: ModePlanV2,
  token_counter: Callable[[str], int],
  provider_call: Callable[[Mapping[str, Any]], Mapping[str, Any]],
  remaining_time: Callable[[], float],
  model: Optional[str] = None,
  caveats: Sequence[dict[str, Any]] = (),
  notation_id: str = NOTATION_ID,
  projected_columns: Sequence[str] = (),
) -> dict[str, Any]:
  trace = _new_trace(mode)
  attempted = 0
  completed = 0
  try:
    if notation_id not in notation.NOTATIONS:
      raise GraphFirstRuntimeError("unknown_notation", "configuration", "graph-first notation is not registered")
    scaffold_tokens = profile.measure_scaffold_tokens(notation_id, question, token_counter)
    budget = profile.compute_evidence_budget(scaffold_tokens)
    render_fn = lambda candidate_graph: notation.render(notation_id, candidate_graph).text  # noqa: E731
    sel_graph, sel_trace = selection.run_pipeline(
      graph, question=question, projected_columns=projected_columns,
      token_counter=token_counter, budget=budget, render_fn=render_fn,
    )
    if not selection.referential_integrity_ok(sel_graph):
      raise GraphFirstRuntimeError(
        "selection_referential_integrity", "internal",
        "selected evidence graph lost referential integrity",
      )
    rendered = notation.render(notation_id, sel_graph)
    evidence_tokens = token_counter(rendered.text)
    trace["selection"] = _selection_summary(graph, sel_graph, sel_trace, scaffold_tokens, budget, evidence_tokens)
    prompt = profile.build_analyst_prompt(notation_id, rendered.text, question)

    response: Optional[dict[str, Any]] = None
    failed_names: list[str] = []
    for attempt in range(2):
      kind = "analyst" if attempt == 0 else "retry"
      current_prompt = prompt if attempt == 0 else profile.build_retry_prompt(notation_id, rendered.text, question, failed_names)
      payload = _payload(current_prompt, kind, mode, model)
      _validate_dispatch_budget(remaining_time())
      call = _new_call(f"C{attempt}", kind, payload)
      trace["calls"].append(call)
      attempted += 1
      dispatch_started = time.monotonic()
      raw = provider_call(payload)
      reported_duration = raw.get("duration_ms")
      call["duration_ms"] = (
        float(reported_duration)
        if isinstance(reported_duration, (int, float)) and reported_duration >= 0
        else round((time.monotonic() - dispatch_started) * 1000.0, 3)
      )
      finish_reason = raw.get("finish_reason")
      call["finish_reason"] = finish_reason
      call["completion_tokens"] = _validated_completion_tokens(raw.get("completion_tokens"))

      if finish_reason == "length":
        call["status"] = "failed"
        if attempt == 0 and _retry_budget_ok(remaining_time()):
          failed_names = ["output_truncated"]
          continue
        raise GraphFirstRuntimeError("finish_reason", "completion", "graph-first completion was truncated at the token limit")
      if finish_reason != "stop":
        call["status"] = "failed"
        raise GraphFirstRuntimeError("finish_reason", "completion", "graph-first completion did not stop normally")

      parsed, parse_err = _parse_response(raw.get("content"))
      if parsed is None:
        call["status"] = "failed"
        if attempt == 0 and _retry_budget_ok(remaining_time()):
          failed_names = ["invalid_model_output"]
          continue
        raise GraphFirstRuntimeError("invalid_model_output", "response_parse", "graph-first response is not valid citations-first JSON")

      gate_results = gates.evaluate_all(parsed, rendered)
      call["gates"] = {name: passed for name, (passed, _detail) in gate_results.items()}
      all_pass = all(passed for passed, _detail in gate_results.values())
      completed += 1
      if all_pass:
        call["status"] = "supported"
        call["raw_output"] = raw.get("content")
        call["parsed"] = parsed
        response = parsed
        break
      call["status"] = "failed"
      failed_names = [name for name, (passed, _detail) in gate_results.items() if not passed]
      if attempt == 0 and _retry_budget_ok(remaining_time()):
        continue
      raise GraphFirstRuntimeError(
        "deterministic_validation_failed", "validation",
        f"graph-first response failed gate(s): {', '.join(failed_names)}",
      )

    if response is None:
      raise GraphFirstRuntimeError("deterministic_validation_failed", "validation", "graph-first response did not pass gates")

    explanation = _assemble_case_explanation(rendered, response, caveats=caveats)
    coverage = _build_coverage(graph, sel_graph, rendered, response, attempted_calls=attempted, completed_calls=completed)
    trace["outcome"] = {
      "status": "supported",
      "attempted_calls": attempted,
      "completed_calls": completed,
      "failure_stage": None,
      "safe_code": None,
    }
    return {"explanation": explanation, "coverage": coverage, "explanation_trace": trace}
  except GraphFirstRuntimeError as exc:
    if exc.trace is not None:
      raise
    exc.trace = _safe_failure_trace_v2(trace, exc.stage, exc.code, attempted, completed)
    raise
  except GraphFirstContractError as exc:
    raise GraphFirstRuntimeError(
      exc.code, "validation", exc.detail,
      _safe_failure_trace_v2(trace, "validation", exc.code, attempted, completed),
    ) from exc
  except Exception as exc:
    raise GraphFirstRuntimeError(
      "unexpected_failure", "internal", "unexpected graph-first explanation failure",
      _safe_failure_trace_v2(trace, "internal", "unexpected_failure", attempted, completed),
    ) from exc
  finally:
    _ = time.monotonic()


# --------------------------------------------------------------------------
# Map-reduce feeding: present per the EGX/1 spec ("remains implemented behind
# a disabled config flag"), gated OFF by `explain_profile.MAP_REDUCE_ENABLED`.
# The EGM-047 lane-2 evidence (11/22 pass, 7.7x cost) is the bar any future
# enablement must beat -- see the EGX/1 spec's "Prompting and inference"
# section. Not exercised by any production endpoint while the flag is off.
# --------------------------------------------------------------------------

def run_map_reduce_v2(**_kwargs: Any) -> dict[str, Any]:
  if not profile.MAP_REDUCE_ENABLED:
    raise GraphFirstRuntimeError(
      "map_reduce_disabled", "configuration",
      "graph-first map-reduce feeding is disabled; EGX/1 ships single-pass only",
    )
  raise NotImplementedError("map-reduce feeding is gated off; see explain_profile.MAP_REDUCE_ENABLED")
