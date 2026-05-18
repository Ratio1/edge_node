"""LLM fixture cache for development workflow (Phase 4 PR-4.4).

During PDF / prompt-template iteration the developer wants:

  - Deterministic LLM output for reliable snapshot tests.
  - Zero API cost / zero network for the typical inner loop.
  - An explicit opt-in for occasional real-LLM smoke tests (to
    catch prompt-engineering regressions against the actual model).

This module wraps a real ``llm_call`` callable with a content-hash-
keyed cache. On every invocation:

  - Compute a stable hash over (messages, max_tokens, temperature).
  - If the env var ``LIVE_LLM=1`` is set, call the real LLM and
    persist the response to ``cache_dir / {hash}.json``.
  - Otherwise, load the cached response from disk and return it.
    Missing fixture under non-live mode is an error — fail loudly
    so the developer knows to run with LIVE_LLM=1 once to populate.

Cache files are checked into the repo under
``__tests__/fixtures/llm_cache/`` so CI runs deterministically
without network access.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable


# Default cache location relative to the repo root.
_DEFAULT_CACHE_DIR = (
  Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "llm_cache"
)


class LlmFixtureCacheMiss(Exception):
  """Raised when a cache lookup misses and LIVE_LLM is not enabled.

  The error message includes the cache key + a copy/paste-able
  command to populate the fixture from a real-LLM run.
  """


def cached_llm_call(
  inner_llm_call: Callable[[list[dict], int, float], str],
  *,
  cache_dir: str | Path | None = None,
  live_env_var: str = "LIVE_LLM",
) -> Callable[[list[dict], int, float], str]:
  """Wrap a real LLM-call callable with a fixture cache.

  Returns a callable with the same signature.

  Behavior:
    - LIVE_LLM=1 in env: forward to inner_llm_call, persist
      response to cache_dir / {hash}.json, return response.
    - Any other value, including unset, 0, false, and empty: load
      cached response from disk; raise
      LlmFixtureCacheMiss if not found.
  """
  cache_path = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
  cache_path.mkdir(parents=True, exist_ok=True)
  is_live = os.environ.get(live_env_var, "").strip() == "1"

  def call(messages: list[dict], max_tokens: int, temperature: float) -> str:
    key = _cache_key(messages, max_tokens, temperature)
    fixture_file = cache_path / f"{key}.json"

    if is_live:
      response = inner_llm_call(messages, max_tokens, temperature)
      _save_fixture(fixture_file, key, messages, max_tokens, temperature, response)
      return response

    if not fixture_file.exists():
      raise LlmFixtureCacheMiss(
        f"no LLM fixture for cache key {key!r} at {fixture_file}\n"
        f"To populate, run the test once with {live_env_var}=1 — "
        f"e.g. `{live_env_var}=1 pytest <test path>`."
      )
    with fixture_file.open() as fh:
      data = json.load(fh)
    return str(data.get("response", ""))

  return call


def _cache_key(messages: list[dict], max_tokens: int, temperature: float) -> str:
  """Stable content hash. Same inputs → same key, regardless of
  insertion order in the message list."""
  payload = json.dumps(
    {
      "messages": messages,
      "max_tokens": int(max_tokens),
      "temperature": float(temperature),
    },
    sort_keys=True,
    default=str,
  )
  return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _save_fixture(
  path: Path,
  key: str,
  messages: list[dict],
  max_tokens: int,
  temperature: float,
  response: str,
) -> None:
  """Persist the fixture as JSON. Includes the inputs (for human
  inspection / debugging) plus the response."""
  path.write_text(
    json.dumps(
      {
        "cache_key": key,
        "messages": messages,
        "max_tokens": int(max_tokens),
        "temperature": float(temperature),
        "response": response,
      },
      indent=2,
      default=str,
    ),
    encoding="utf-8",
  )
