# EdgeGuard Playground API Notes

## Runtime Shape

The playground uses three edge-node runtime pieces:

- `LLM_INFERENCE_API` with `AI_ENGINE=edgeguard_qwen_4b`
- `EDGEGUARD_LLM_AGENT_API` for guarded text-to-Cypher generation
- `EDGEGUARD_API` as the UI-facing facade for health, model metadata, generation, validation, and
  request-scoped Neo4j test/query calls

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
    }
  ]
}
```

Neo4j execution requires the `neo4j` Python driver in the runtime image. If the driver is missing,
`EDGEGUARD_API` reports Neo4j execution as unavailable and does not attempt to connect.
