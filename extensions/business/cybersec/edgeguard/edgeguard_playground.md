# EdgeGuard Playground API Notes

## Runtime Shape

The playground uses edge-node runtime pieces plus the Next.js server route as the
generation orchestrator:

- `LLM_INFERENCE_API` finetuned worker for the private Ratio1 EdgeGuard v0.10 GGUF
- `LLM_INFERENCE_API` base worker for the public Qwen3 4B Instruct GGUF
- `EDGEGUARD_API` as the UI-facing safety facade for health, model catalog, prompt contract
  metadata, deterministic `/check_cypher`, Neo4j execution, and graph explanation
- `WORKER_APP_RUNNER` for the Next.js UI repo

There is no `EDGEGUARD_LLM_AGENT_API` layer and no `EDGEGUARD_API /generate` endpoint in this
flow. The authenticated Next.js route `/api/edgeguard/generate` selects an allowlisted
model-specific LLM worker, builds the prompt, calls `POST /predict_async`, polls
`GET /request_status?request_id=...&return_full=true`, validates every attempt through
`EDGEGUARD_API /check_cypher`, and returns the full attempt trail to the browser.

Use request balancing only among replicas of the same model. Do not place the base and finetuned
workers in one balancing group.

Run the finetuned and base workers in separate loopback streams. Do not put both
`LLM_INFERENCE_API` instances in one stream: the edge-node serving aggregator builds model inputs
from stream-captured data, and live smoke showed same-stream LLM workers can see each other's
`JEEVES_CONTENT` request IDs.

## Model Workers

The finetuned worker serves the private EGM-029 v0.10 graph-intent continuation:

```text
MODEL_NAME=ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf
MODEL_FILENAME=edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf
AI_ENGINE=edgeguard_qwen_4b
```

The base comparison worker reuses the existing EdgeGuard llama.cpp AI-engine alias with a distinct
startup model instance id instead of adding a new AI-engine alias:

```text
MODEL_NAME=MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF
MODEL_FILENAME=Qwen3-4B-Instruct-2507.Q4_K_M.gguf
AI_ENGINE=edgeguard_qwen_4b
STARTUP_AI_ENGINE_PARAMS.MODEL_INSTANCE_ID=edgeguard-base-qwen3-4b
```

Do not use a raw serving-process value
(`llama_cpp_edgeguard_qwen_4b?edgeguard-base-qwen3-4b`) or an `AI_ENGINE` suffix
(`edgeguard_qwen_4b?edgeguard-base-qwen3-4b`) for this worker. Live smoke showed both can register
details under a key that does not match the core inference router's reverse lookup. The stable
runtime contract is the plain `edgeguard_qwen_4b` alias plus `MODEL_INSTANCE_ID` in
`STARTUP_AI_ENGINE_PARAMS`, which makes the serving handle
`("llama_cpp_edgeguard_qwen_4b", "edgeguard-base-qwen3-4b")` and routes results back to
`("edgeguard_qwen_4b", "edgeguard-base-qwen3-4b")`.

Set the private Hugging Face token as a runtime secret for the finetuned worker; do not put it in a
pipeline JSON committed to git.

## Guard Contract

`EDGEGUARD_API` owns deterministic safety checks and execution boundaries. It exposes:

- `GET /models` with opaque model keys, display names, repo/file metadata, prompt profile ids, and
  no backend URLs
- `GET /prompt_contract` with schema version, schema surface, temporal policy, retry default, and
  prompt template versions/hashes
- `POST /check_cypher` for deterministic query-only, read-only, schema-compatible validation
- Neo4j query/explanation endpoints that revalidate accepted Cypher before execution

Accepted generated output is still one read-only Cypher query string only:

- no JSON, markdown, prose, `query_id`, `params`, or `$param` placeholders
- no `CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE`, `DROP`, `LOAD CSV`, or dangerous procedure calls
- only the allowed EdgeGuard labels, relationship types, and properties
- at most two schema-correction retries by default

When an accepted generated query executes successfully but returns zero rows, `EDGEGUARD_API` can
apply the empty-result broadening fallback: it derives one bounded graph query from the first
allowed label and relationship type already present in the accepted Cypher, executes that query, and
returns explicit `live_retry` metadata so the UI can show that the returned graph was broadened.

## Minimal Pipeline Sketch

Use one stream per model worker:

```json
{
  "NAME": "edgeguard_llm_finetuned_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LLM_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_llm_finetuned_v0_10",
          "AI_ENGINE": "edgeguard_qwen_4b",
          "PORT": 5090,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_NAME": "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf",
            "MODEL_FILENAME": "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf",
            "MODEL_INSTANCE_ID": "edgeguard-finetuned-v0-10",
            "HF_TOKEN": "$HF_TOKEN"
          }
        }
      ]
    }
  ]
}
```

```json
{
  "NAME": "edgeguard_llm_base_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LLM_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_llm_base_qwen3_4b",
          "AI_ENGINE": "edgeguard_qwen_4b",
          "PORT": 5091,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_NAME": "MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF",
            "MODEL_FILENAME": "Qwen3-4B-Instruct-2507.Q4_K_M.gguf",
            "MODEL_INSTANCE_ID": "edgeguard-base-qwen3-4b"
          }
        }
      ]
    }
  ]
}
```

Keep the safety API and UI runner outside those LLM streams:

```json
{
  "NAME": "edgeguard_playground_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "EDGEGUARD_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_api",
          "SEMAPHORE": "edgeguard_api",
          "PORT": 5055,
          "REQUEST_TIMEOUT": 600,
          "REQUEST_TIMEOUT_SECONDS": 600,
          "NEO4J_MAX_ROWS": 100,
          "LIVE_EMPTY_RESULT_BROADENING": true
        }
      ]
    }
  ]
}
```

```json
{
  "NAME": "edgeguard_playground_ui",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "WORKER_APP_RUNNER",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_playground_ui",
          "SEMAPHORED_KEYS": ["edgeguard_api"],
          "PORT": 3010,
          "DYNAMIC_ENV": {
            "EDGEGUARD_API_BASE_URL": [
              {
                "type": "shmem",
                "path": ["edgeguard_api", "API_URL"]
              }
            ]
          },
          "ENV": {
            "EDGEGUARD_LLM_FINETUNED_URLS": "http://127.0.0.1:5090",
            "EDGEGUARD_LLM_BASE_URLS": "http://127.0.0.1:5091"
          }
        }
      ]
    }
  ]
}
```

The `WORKER_APP_RUNNER` stream injects the two model-specific URLs above as server-only environment
variables. The deployment-specific repository, build, tunnel, and secret settings are intentionally
omitted from this minimal contract sketch.

The UI must not hardcode `EDGEGUARD_API_BASE_URL` when deployed in edge-node. `EDGEGUARD_API`
publishes `API_URL` through semaphore key `edgeguard_api`; `WORKER_APP_RUNNER` waits for that
semaphore and injects the resolved value through `DYNAMIC_ENV` before starting the Next.js app.

The LLM worker URLs are server-only Worker App Runner environment variables. They are not returned
by `EDGEGUARD_API`, not exposed to the browser, and not written to local query history.

Neo4j execution requires the `neo4j` Python driver in the runtime image. If the driver is missing,
`EDGEGUARD_API` reports Neo4j execution as unavailable and does not attempt to connect.

## Required Secrets

- `HF_TOKEN` for the private Hugging Face model artifact.
- `EDGEGUARD_PLAYGROUND_PASSWORD` for the shared UI password gate.
- `EDGEGUARD_SESSION_SECRET` for the UI session cookie signature.
- `EDGEGUARD_PLAYGROUND_UI_GH_TOKEN` for Worker App Runner access to the private UI repo.
- `EDGEGUARD_PLAYGROUND_UI_CF_TOKEN` for the Worker App Runner Cloudflare tunnel on UI port `3010`.
- `EDGEGUARD_API_TOKEN` only if an API bearer-token boundary is enabled.
- `EDGEGUARD_LLM_API_TOKEN` only if the local LLM workers enforce bearer-token auth.
