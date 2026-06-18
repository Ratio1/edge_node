# EdgeGuard Playground API Notes

## Runtime Shape

The playground uses three edge-node runtime pieces:

- `LLM_INFERENCE_API` with `AI_ENGINE=edgeguard_qwen_4b`
- `EDGEGUARD_LLM_AGENT_API` for guarded text-to-Cypher generation
- `EDGEGUARD_API` as the UI-facing facade for health, model metadata, generation, validation, and
  request-scoped Neo4j test/query calls
- `WORKER_APP_RUNNER` for the Next.js UI repo

The model artifact is private in Hugging Face:

```text
MODEL_NAME=ratio1/edgeguard-cypher-qwen3-4b-v0.5-preview-gguf
MODEL_FILENAME=edgeguard-cypher-qwen3-4b-v0.5-preview.Q4_K_M.gguf
AI_ENGINE=edgeguard_qwen_4b
```

This is the private v0.5 preview continuation of the v0.4 GGUF artifact. The published GGUF contains
the merged EGM-013 v0.5.3 weights. The backend runtime now applies the EGM-019 v0.5.10 live-retry
and empty-result broadening harness around those weights. The generated-live extractable-graph gate
improved to `34/38 = 89.47%` with planner failures `0` and scalar-projection regressions `0`. The
runtime harness is not baked into the GGUF weights; it is backend behavior around inference and
Neo4j execution. Deterministic broadening improves graph extractability but can return a wider graph
than the original request, so semantic-fidelity review remains required before production promotion.

Set the private Hugging Face token as a runtime secret for `LLM_INFERENCE_API`; do not put it in a
pipeline JSON committed to git.

## Guard Contract

`EDGEGUARD_LLM_AGENT_API` sends every user request with the committed EdgeGuard schema prompt, then
validates each model output before returning it. The accepted output contract is one read-only Cypher
query string only:

- no JSON, markdown, prose, `query_id`, `params`, or `$param` placeholders
- no `CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE`, `DROP`, `LOAD CSV`, or dangerous procedure calls
- only the allowed EdgeGuard labels, relationship types, and properties
- at most two schema-correction retries by default

`EDGEGUARD_API` revalidates accepted agent output before returning it to the UI and revalidates Cypher
again before Neo4j execution. When an accepted generated query executes successfully but returns zero
rows, `EDGEGUARD_API` can apply the v0.5.10 empty-result broadening fallback: it derives one bounded
graph query from the first allowed label and relationship type already present in the accepted Cypher,
executes that query, and returns explicit `live_retry` metadata so the UI can show that the returned
graph was broadened.

## Minimal Pipeline Sketch

```json
{
  "NAME": "edgeguard_playground_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LLM_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_llm_runtime",
          "AI_ENGINE": "edgeguard_qwen_4b",
          "PORT": 5090,
          "STARTUP_AI_ENGINE_PARAMS": {
            "HF_TOKEN": "$HF_TOKEN"
          }
        }
      ]
    },
    {
      "SIGNATURE": "EDGEGUARD_LLM_AGENT_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_llm_agent",
          "PORT": 5060,
          "LOCAL_LLM_API_PORT": 5090,
          "SCHEMA_RETRY_LIMIT": 2
        }
      ]
    },
    {
      "SIGNATURE": "EDGEGUARD_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_api",
          "SEMAPHORE": "edgeguard_api",
          "PORT": 5055,
          "EDGEGUARD_LLM_AGENT_PORT": 5060,
          "NEO4J_MAX_ROWS": 100,
          "LIVE_EMPTY_RESULT_BROADENING": true
        }
      ]
    },
    {
      "SIGNATURE": "WORKER_APP_RUNNER",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_playground_ui",
          "SEMAPHORED_KEYS": ["edgeguard_api"],
          "PORT": 3010,
          "BUILD_AND_RUN_COMMANDS": [
            "npm install",
            "npm run build",
            "npm run start -- --hostname 0.0.0.0 --port 3010"
          ],
          "VCS_DATA": {
            "PROVIDER": "github",
            "USERNAME": "toderian",
            "TOKEN": "$EDGEGUARD_PLAYGROUND_UI_GH_TOKEN",
            "REPO_URL": "git@github.com:Ratio1/edgeguard-playground-ui.git",
            "BRANCH": "main",
            "POLL_INTERVAL": 60
          },
          "AUTOUPDATE": true,
          "EXPOSED_PORTS": {
            "3010": {
              "is_main_port": true,
              "host_port": null,
              "tunnel": {
                "enabled": true,
                "engine": "cloudflare",
                "token": "$EDGEGUARD_PLAYGROUND_UI_CF_TOKEN",
                "protocol": "http"
              }
            }
          },
          "TUNNEL_ENGINE_ENABLED": true,
          "DYNAMIC_ENV": {
            "EDGEGUARD_API_BASE_URL": [
              {
                "type": "shmem",
                "path": ["edgeguard_api", "API_URL"]
              }
            ]
          },
          "ENV": {
            "EDGEGUARD_PLAYGROUND_PASSWORD": "$EDGEGUARD_PLAYGROUND_PASSWORD",
            "EDGEGUARD_SESSION_SECRET": "$EDGEGUARD_SESSION_SECRET",
            "EDGEGUARD_API_TOKEN": "$EDGEGUARD_API_TOKEN"
          },
          "HEALTH_CHECK": {
            "PATH": "/api/health"
          }
        }
      ]
    }
  ]
}
```

The UI must not hardcode `EDGEGUARD_API_BASE_URL` when deployed in edge-node. `EDGEGUARD_API`
publishes `API_URL` through semaphore key `edgeguard_api`; `WORKER_APP_RUNNER` waits for that
semaphore and injects the resolved value through `DYNAMIC_ENV` before starting the Next.js app.

Neo4j execution requires the `neo4j` Python driver in the runtime image. If the driver is missing,
`EDGEGUARD_API` reports Neo4j execution as unavailable and does not attempt to connect.

## Required Secrets

- `HF_TOKEN` for the private Hugging Face model artifact.
- `EDGEGUARD_PLAYGROUND_PASSWORD` for the shared UI password gate.
- `EDGEGUARD_SESSION_SECRET` for the UI session cookie signature.
- `EDGEGUARD_PLAYGROUND_UI_GH_TOKEN` for Worker App Runner access to the private UI repo.
- `EDGEGUARD_PLAYGROUND_UI_CF_TOKEN` for the Worker App Runner Cloudflare tunnel on UI port `3010`.
- `EDGEGUARD_API_TOKEN` only if an API bearer-token boundary is enabled.
