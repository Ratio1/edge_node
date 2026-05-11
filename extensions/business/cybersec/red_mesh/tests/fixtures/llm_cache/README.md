# LLM fixture cache

Cached LLM responses keyed by SHA-256 over (messages, max_tokens, temperature).

## Usage

```python
from extensions.business.cybersec.red_mesh.services import cached_llm_call

cached = cached_llm_call(
  inner_llm_call=my_real_deepseek_caller,
  cache_dir=Path(__file__).parent / "fixtures" / "llm_cache",
)
# cached has the same signature as inner_llm_call
```

- `LIVE_LLM=1` in env → the real LLM is called and the response is
  written to this directory as `{hash}.json`.
- `LIVE_LLM` unset → the cached response is loaded from disk;
  missing fixture raises `LlmFixtureCacheMiss` with an actionable
  message.

## Refreshing fixtures

```bash
LIVE_LLM=1 pytest extensions/business/cybersec/red_mesh/tests/test_llm_structured_service.py
```

After a refresh, audit the new `.json` files (they include the input
prompt for inspection) before committing.

## Why these fixtures are checked in

CI runs without network and must produce identical PDFs across runs.
Determinism comes from these fixtures. When the prompt template
changes (PROMPT_VERSION_EXEC_SUMMARY bump), the developer regenerates
the fixtures, audits them, and commits them in the same PR as the
template change.
