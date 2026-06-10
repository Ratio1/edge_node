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
MODEL_NAME=ratio1/edgeguard-cypher-qwen3-4b-v0.4-gguf
MODEL_FILENAME=edgeguard-cypher-qwen3-4b-v0.4.Q4_K_M.gguf
AI_ENGINE=edgeguard_qwen_4b
```

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
again before Neo4j execution.

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
          "PORT": 5055,
          "EDGEGUARD_LLM_AGENT_PORT": 5060,
          "NEO4J_MAX_ROWS": 100
        }
      ]
    },
    {
      "SIGNATURE": "WORKER_APP_RUNNER",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_playground_ui",
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
          "ENV": {
            "EDGEGUARD_PLAYGROUND_PASSWORD": "$EDGEGUARD_PLAYGROUND_PASSWORD",
            "EDGEGUARD_SESSION_SECRET": "$EDGEGUARD_SESSION_SECRET",
            "EDGEGUARD_API_BASE_URL": "http://127.0.0.1:5055",
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

Neo4j execution requires the `neo4j` Python driver in the runtime image. If the driver is missing,
`EDGEGUARD_API` reports Neo4j execution as unavailable and does not attempt to connect.

## Required Secrets

- `HF_TOKEN` for the private Hugging Face model artifact.
- `EDGEGUARD_PLAYGROUND_PASSWORD` for the shared UI password gate.
- `EDGEGUARD_SESSION_SECRET` for the UI session cookie signature.
- `EDGEGUARD_PLAYGROUND_UI_GH_TOKEN` for Worker App Runner access to the private UI repo.
- `EDGEGUARD_PLAYGROUND_UI_CF_TOKEN` for the Worker App Runner Cloudflare tunnel on UI port `3010`.
- `EDGEGUARD_API_TOKEN` only if an API bearer-token boundary is enabled.
