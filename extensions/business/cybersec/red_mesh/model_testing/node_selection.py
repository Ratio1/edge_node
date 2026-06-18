"""Single-node execution selection for Model Testing."""

from __future__ import annotations

import random
from math import isfinite


MODEL_TEST_SELECTION_MANUAL = "manual"
MODEL_TEST_SELECTION_AUTO_ALL = "auto_all"
MODEL_TEST_SELECTION_AUTO_SUBSET = "auto_subset"

MODEL_TEST_REASON_MANUAL = "manual_single_peer"
MODEL_TEST_REASON_RESOURCE = "highest_resource_score"
MODEL_TEST_REASON_RANDOM = "random_no_usable_telemetry"


def _validation_error(message: str):
  return {"error": "validation_error", "message": message}


def normalize_peer_ids(peer_ids, *, field_path):
  """Trim, reject empty/non-string values, and deduplicate peer ids."""
  if peer_ids is None:
    peer_ids = []
  if not isinstance(peer_ids, list):
    return None, _validation_error(f"{field_path} must be a list")
  normalized = []
  seen = set()
  for idx, peer_id in enumerate(peer_ids):
    if not isinstance(peer_id, str):
      return None, _validation_error(f"{field_path}[{idx}] must be a string")
    peer_id = peer_id.strip()
    if not peer_id:
      return None, _validation_error(f"{field_path}[{idx}] must not be empty")
    if peer_id not in seen:
      normalized.append(peer_id)
      seen.add(peer_id)
  return normalized, None


def _configured_peers(owner):
  peers, err = normalize_peer_ids(
    list(getattr(owner, "cfg_chainstore_peers", []) or []),
    field_path="cfg_chainstore_peers",
  )
  if err:
    return None, err
  if not peers:
    return None, _validation_error("No workers found in chainstore peers configuration.")
  return peers, None


def _extract_score(value):
  if isinstance(value, dict):
    for key in (
      "resource_score",
      "available_resource_score",
      "available_resources",
      "score",
      "available",
    ):
      if key in value:
        return _extract_score(value.get(key))
    cpu = value.get("cpu_available")
    memory = value.get("memory_available")
    if cpu is not None and memory is not None:
      try:
        score = float(cpu) + float(memory)
      except (TypeError, ValueError):
        return None
      return score if isfinite(score) else None
    return None
  try:
    score = float(value)
  except (TypeError, ValueError):
    return None
  return score if isfinite(score) else None


def _maybe_call(callable_obj, *args):
  try:
    return callable_obj(*args)
  except TypeError:
    return callable_obj()


def get_candidate_resource_scores(owner, candidate_peer_ids):
  """Return usable resource scores for candidates from netmon-like telemetry."""
  explicit = getattr(owner, "get_model_test_resource_scores", None)
  if callable(explicit):
    raw_scores = _maybe_call(explicit, candidate_peer_ids)
    return _normalize_scores(raw_scores, candidate_peer_ids)

  netmon = getattr(owner, "netmon", None)
  if netmon is None:
    return {}
  for method_name in (
    "get_model_test_resource_scores",
    "get_peer_resource_scores",
    "get_available_resource_scores",
    "get_peer_resources",
  ):
    method = getattr(netmon, method_name, None)
    if callable(method):
      raw_scores = _maybe_call(method, candidate_peer_ids)
      scores = _normalize_scores(raw_scores, candidate_peer_ids)
      if scores:
        return scores
  for attr_name in (
    "model_test_resource_scores",
    "peer_resource_scores",
    "available_resource_scores",
    "peer_resources",
    "resource_status",
  ):
    raw_scores = getattr(netmon, attr_name, None)
    scores = _normalize_scores(raw_scores, candidate_peer_ids)
    if scores:
      return scores
  return {}


def _normalize_scores(raw_scores, candidate_peer_ids):
  if not isinstance(raw_scores, dict):
    return {}
  candidates = set(candidate_peer_ids or [])
  normalized = {}
  for peer_id, value in raw_scores.items():
    if peer_id not in candidates:
      continue
    score = _extract_score(value)
    if score is not None:
      normalized[peer_id] = score
  return normalized


def _choose_random(candidate_peer_ids, random_source=None):
  if random_source is None:
    return random.SystemRandom().choice(candidate_peer_ids)
  choice = getattr(random_source, "choice", None)
  if callable(choice):
    return choice(candidate_peer_ids)
  if callable(random_source):
    return random_source(candidate_peer_ids)
  return random.SystemRandom().choice(candidate_peer_ids)


def select_model_test_execution_node(
  owner,
  selected_peers=None,
  *,
  resource_scores_getter=None,
  random_source=None,
):
  """Resolve peer context into exactly one Model Test Execution Node."""
  requested_input = [] if selected_peers is None else selected_peers
  requested_peers, err = normalize_peer_ids(requested_input, field_path="selected_peers")
  if err:
    return None, err
  configured_peers, err = _configured_peers(owner)
  if err:
    return None, err

  configured_set = set(configured_peers)
  invalid_peers = [peer_id for peer_id in requested_peers if peer_id not in configured_set]
  if invalid_peers:
    return None, _validation_error(
      f"Invalid peer addresses not found in chainstore_peers: {invalid_peers}. "
      f"Available peers: {configured_peers}"
    )

  if len(requested_peers) == 1:
    candidate_peer_ids = list(requested_peers)
    selection_mode = MODEL_TEST_SELECTION_MANUAL
  elif requested_peers:
    candidate_peer_ids = list(requested_peers)
    selection_mode = MODEL_TEST_SELECTION_AUTO_SUBSET
  else:
    candidate_peer_ids = list(configured_peers)
    selection_mode = MODEL_TEST_SELECTION_AUTO_ALL

  if selection_mode == MODEL_TEST_SELECTION_MANUAL:
    selected = candidate_peer_ids[0]
    return {
      "selection_mode": selection_mode,
      "requested_peer_ids": requested_peers,
      "candidate_count": 1,
      "candidate_peer_ids": candidate_peer_ids,
      "candidate_peer_ids_omitted_reason": None,
      "selected_execution_node": selected,
      "selection_reason": MODEL_TEST_REASON_MANUAL,
      "telemetry_used": False,
      "telemetry_available_count": 0,
      "random_fallback": False,
    }, None

  if resource_scores_getter is None:
    resource_scores_getter = get_candidate_resource_scores
  resource_scores = resource_scores_getter(owner, candidate_peer_ids)
  usable_scores = _normalize_scores(resource_scores, candidate_peer_ids)
  if usable_scores:
    selected = sorted(
      usable_scores,
      key=lambda peer_id: (-usable_scores[peer_id], peer_id),
    )[0]
    return {
      "selection_mode": selection_mode,
      "requested_peer_ids": requested_peers,
      "candidate_count": len(candidate_peer_ids),
      "candidate_peer_ids": candidate_peer_ids,
      "candidate_peer_ids_omitted_reason": None,
      "selected_execution_node": selected,
      "selection_reason": MODEL_TEST_REASON_RESOURCE,
      "telemetry_used": True,
      "telemetry_available_count": len(usable_scores),
      "random_fallback": False,
    }, None

  selected = _choose_random(candidate_peer_ids, random_source=random_source)
  return {
    "selection_mode": selection_mode,
    "requested_peer_ids": requested_peers,
    "candidate_count": len(candidate_peer_ids),
    "candidate_peer_ids": candidate_peer_ids,
    "candidate_peer_ids_omitted_reason": None,
    "selected_execution_node": selected,
    "selection_reason": MODEL_TEST_REASON_RANDOM,
    "telemetry_used": False,
    "telemetry_available_count": 0,
    "random_fallback": True,
  }, None
