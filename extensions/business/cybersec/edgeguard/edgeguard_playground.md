# EdgeGuard Playground API Notes

## Runtime ownership

`EDGEGUARD_API` is the complete EdgeGuard workflow boundary. It owns model selection and dispatch,
prompt construction, Cypher validation and correction attempts, Neo4j connection selection and
bounded execution, graph/evidence construction, explanation inference, deterministic validation,
coverage, and sanitized diagnostics.

The authenticated Next.js application owns only authentication, input collection, local presentation
state/history, API transport, and rendering. It must not connect to Neo4j, address model workers,
construct prompts, poll inference workers, or rebuild/validate graph explanation evidence.

A playground deployment uses one `edgeguard_playground_api` Loopback pipeline containing one
`LLM_INFERENCE_API` instance per model and one `EDGEGUARD_API` instance. Only the API has a stable
published port (`5055`). Each model worker receives a runtime-selected port and publishes `API_HOST`
and `API_PORT` through a unique semaphore.

This repository ships two public models. The model a deployment actually wants to evaluate, for
example a private fine-tuned GGUF, is added by the pipeline alone: its public model key, Hub
repository, filename, pinned revision and semaphore live in the deployment configuration and are
never committed here. The placeholders below mark those deployment-supplied values.

| Public model key | AI engine | Semaphore | Source |
| --- | --- | --- | --- |
| `<public-model-key>` | `llama_cpp_gguf` + `MODEL_INSTANCE_ID` | `edgeguard_llm_private` | pipeline |
| `base_qwen3_4b` | `base_qwen3_4b` | `edgeguard_llm_base` | shipped |
| `cybersec_qwen_4b` | `cybersec_qwen_4b` | `edgeguard_llm_cybersec` | shipped |

`EDGEGUARD_API` resolves the selected worker address from its semaphore for every request. Port
publication proves only that the worker facade is reachable: worker `/health` also reports whether
its configured serving process reached READY. Aggregate API health remains `starting` until every
model is ready. A missing facade fails with `worker_not_ready`; a loading model fails immediately
and retryably with `model_not_ready`, before Neo4j or model work. Graph explanations use
`edgeguard_llm_base` with public model key `base_qwen3_4b`; generation routing remains selected by
the user-facing model key.

Every generation or explanation request carries its public model key to its `LLM_INFERENCE_API`
worker. The worker resolves that key to the serving process that owns it (the AI engine name, an id
from `STARTUP_AI_ENGINE_PARAMS`, or a `SERVED_MODELS` alias) and tags the bus request with that
serving name; a request whose key resolves to no local serving is rejected before dispatch instead of
waiting for the request timeout. Matching is exact and case-sensitive on both the local and the peer
path. `SERVED_MODELS` is either a plain list of aliases, which belongs to the instance's single
engine, or a mapping `{"engine_name": ["alias", ...]}` that names the engine explicitly. An
instance running several engines must use the mapping form; a plain list there is ignored with a
warning that says so. Each LLM serving accepts a tagged packet only when the tag is its own serving
name. Untagged legacy packets retain the historical broadcast behavior, but a targeted
completion can never be overwritten by another model in the shared pipeline.

## Hub-backed model contract

Runtime configuration contains no `MODEL_PATH`. Generic llama.cpp serving resolves the configured
file with `hf_hub_download`, forwarding `MODEL_REVISION`, the runtime cache directory, and
`$EE_HF_TOKEN`, then opens the returned cached file with `Llama`. The Hugging Face repository and
pinned revision are the artifact source of truth; the normal persistent Hub cache is permitted.

| Worker | Repository | Revision | File |
| --- | --- | --- | --- |
| Deployment model | `<hub-org>/<private-gguf-repo>` | `<pinned-commit-sha>` | `<model>.Q4_K_M.gguf` |
| Base | `MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF` | `aec29f0e8c31130ba811bec2c774c2ef44888f55` | `Qwen3-4B-Instruct-2507.Q4_K_M.gguf` |
| CyberSec | `mradermacher/CyberSecQwen-4B-GGUF` | `4b369711d408b9fde0efcca155409c072b19a1f6` | `CyberSecQwen-4B.Q4_K_M.gguf` |

The deployment model row is filled in by the operator's pipeline record, which is kept with the
deployment, not in this repository.

Keep the base engine identity pinned to Qwen3 4B. A future generation receives a separate engine,
profile, public key, artifact, instance, and semaphore instead of repointing `base_qwen3_4b`.

## API contract

- `GET /health` reports API status plus per-model serving readiness without returning worker
  addresses, credentials, paths, or tokens.
- `GET /models`, `GET /model`, and `GET /prompt_contract` expose safe model/schema metadata.
- `POST /generate` accepts the user request and public model key, calls the selected worker at
  temperature `0`, validates every candidate, applies literal grounding, and performs at most two
  correction attempts.
- `POST /check_cypher` remains available as a standalone deterministic validator.
- `POST /neo4j_test` and `POST /neo4j_query` use either the complete API default connection or a
  complete request override. Fields are never merged between those sources.
- `POST /neo4j_query` returns the operator's complete `rows` by design, including properties such
  as `raw_data` or credential-shaped keys that the graph packet drops. Forbidden-key redaction
  applies to the `graph` packet and to every model-bound evidence path, never to the analyst's table.
- `POST /prepare_graph_explanation` remains a credential-free planning/diagnostic endpoint.
- `POST /explain_graph` owns Neo4j execution when no execution evidence is supplied, then runs the
  restored EEL/1 + JSON-CB/1 map/reduce explanation contract. Compatibility evidence mode remains supported
  for direct API clients but is not used by the playground UI.

Sampling and safety remain frozen: text-to-Cypher temperature `0`; explanation temperature `0.1`,
top-p `1.0`, and `max_tokens=127`; Fast/Balanced/Thorough row caps `10/25/50` with map caps `1/2/3`
and at most one synthesis; one attempt per call with no repair retry; read-only/schema guard;
complete bounded evidence; server-owned citations, coverage, caveats, and safe diagnostics.

EEL/1 maps complete `RowPathClosure` batches. Every supported map becomes an entity finding,
summary evidence is the union of cited rows, and synthesis must cite all supported maps in canonical
order. Provider, timeout, context, completion-metadata, parser, or citation failure remains
fail-closed without exposing raw content.

## Unified pipeline sketch

```json
{
  "NAME": "edgeguard_playground_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LLM_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_llm_private",
          "AI_ENGINE": "llama_cpp_gguf",
          "SEMAPHORE": "edgeguard_llm_private",
          "SERVED_MODELS": ["<public-model-key>"],
          "PORT": null,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_INSTANCE_ID": "private-model",
            "MODEL_NAME": "<hub-org>/<private-gguf-repo>",
            "MODEL_FILENAME": "<model>.Q4_K_M.gguf",
            "MODEL_REVISION": "<pinned-commit-sha>"
          }
        },
        {
          "INSTANCE_ID": "edgeguard_llm_base_qwen3_4b",
          "AI_ENGINE": "base_qwen3_4b",
          "SEMAPHORE": "edgeguard_llm_base",
          "PORT": null,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_NAME": "MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF",
            "MODEL_FILENAME": "Qwen3-4B-Instruct-2507.Q4_K_M.gguf",
            "MODEL_REVISION": "aec29f0e8c31130ba811bec2c774c2ef44888f55"
          }
        },
        {
          "INSTANCE_ID": "edgeguard_llm_cybersec_qwen_4b",
          "AI_ENGINE": "cybersec_qwen_4b",
          "SEMAPHORE": "edgeguard_llm_cybersec",
          "PORT": null,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF",
            "MODEL_FILENAME": "CyberSecQwen-4B.Q4_K_M.gguf",
            "MODEL_REVISION": "4b369711d408b9fde0efcca155409c072b19a1f6"
          }
        }
      ]
    },
    {
      "SIGNATURE": "EDGEGUARD_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "edgeguard_api",
          "SEMAPHORE": "edgeguard_api",
          "SEMAPHORED_KEYS": [
            "edgeguard_llm_private",
            "edgeguard_llm_base",
            "edgeguard_llm_cybersec"
          ],
          "PORT": 5055,
          "EDGEGUARD_GENERATION_WORKERS": {
            "<public-model-key>": {
              "SEMAPHORE": "edgeguard_llm_private",
              "PROMPT_PROFILE": "direct_cypher",
              "DISPLAY_NAME": "<display name>",
              "MODEL_REPO": "<hub-org>/<private-gguf-repo>",
              "MODEL_FILE": "<model>.Q4_K_M.gguf",
              "SOURCE": "private_deployment"
            },
            "base_qwen3_4b": {"SEMAPHORE": "edgeguard_llm_base"},
            "cybersec_qwen_4b": {"SEMAPHORE": "edgeguard_llm_cybersec"}
          },
          "EDGEGUARD_DEFAULT_MODEL": "<public-model-key>",
          "EDGEGUARD_EXPLANATION_WORKER": {"SEMAPHORE": "edgeguard_llm_base"},
          "EDGEGUARD_EXPLANATION_MODEL": "base_qwen3_4b",
          "NEO4J_DEFAULT_CONNECTION": {
            "uri": "$EE_NEO4J_URI",
            "scheme": "bolt+s",
            "username": "$EE_NEO4J_USERNAME",
            "password": "$EE_NEO4J_PASSWORD"
          }
        }
      ]
    }
  ]
}
```

Shipped public keys (`base_qwen3_4b`, `cybersec_qwen_4b`) equal their AI engine names, so they need
no `SERVED_MODELS` alias, and a shorthand `{"SEMAPHORE": ...}` entry keeps the shipped catalog
metadata. A deployment model runs on the generic `llama_cpp_gguf` engine, needs `MODEL_INSTANCE_ID`
so it can coexist with other generic instances on the node, and declares its public key through
`SERVED_MODELS` on its worker and as the key of its `EDGEGUARD_GENERATION_WORKERS` entry. Set
`EDGEGUARD_DEFAULT_MODEL` explicitly when the deployment model should answer requests that name none.

## Secrets and deployment

edg3 receives an ignored, mode-`0600` runtime env file containing `EE_HF_TOKEN` and the four
`EE_NEO4J_*` values. The tracked devcontainer configuration contains no secret and injects that file
only into edg3 through the generated local devcontainer config. The generic loader reads the Hub
token from the process environment while the stream pins only repository, filename, and revision.
The stream itself, with the real model identity, is deployment state and stays out of this repository.
Never place literal credentials in tracked files, logs, task records, prompts, or responses.

The Next.js Worker App Runner needs only the semaphored `EDGEGUARD_API_BASE_URL` plus its own
authentication/deployment secrets. It no longer receives model URLs or Neo4j transport dependencies.
