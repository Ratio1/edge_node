# EdgeGuard Playground API Notes

## Runtime ownership

`EDGEGUARD_API` is the complete EdgeGuard workflow boundary. It owns model selection and dispatch,
prompt construction, Cypher validation and correction attempts, Neo4j connection selection and
bounded execution, graph/evidence construction, explanation inference, deterministic validation,
coverage, and sanitized diagnostics.

The authenticated Next.js application owns only authentication, input collection, local presentation
state/history, API transport, and rendering. It must not connect to Neo4j, address model workers,
construct prompts, poll inference workers, or rebuild/validate graph explanation evidence.

The edg3 deployment uses one `edgeguard_playground_api` Loopback pipeline containing three
`LLM_INFERENCE_API` instances and one `EDGEGUARD_API` instance. Only the API has a stable published
port (`5055`). Each model worker receives a runtime-selected port and publishes `API_HOST` and
`API_PORT` through a unique semaphore:

| Public model key | AI engine | Semaphore |
| --- | --- | --- |
| `finetuned_v0_10` | `edgeguard_qwen_4b` | `edgeguard_llm_finetuned` |
| `base_qwen3_4b` | `base_qwen3_4b` | `edgeguard_llm_base` |
| `cybersec_qwen_4b` | `cybersec_qwen_4b` | `edgeguard_llm_cybersec` |

`EDGEGUARD_API` resolves the selected worker address from its semaphore for every request. Port
publication proves only that the worker facade is reachable: worker `/health` also reports whether
its configured serving process reached READY. Aggregate API health remains `starting` until every
model is ready. A missing facade fails with `worker_not_ready`; a loading model fails immediately
and retryably with `model_not_ready`, before Neo4j or model work. Graph explanations use
`edgeguard_llm_base` with public model key `base_qwen3_4b`; generation routing remains selected by
the user-facing model key.

Every generation or explanation request carries its public model key through `LLM_INFERENCE_API` to
the generic llama.cpp engine. A targeted packet is relevant only to the engine whose
`MODEL_API_KEY` matches exactly. Untargeted legacy packets retain the historical broadcast behavior,
but a targeted completion can never be overwritten by another model in the shared pipeline.

## Hub-backed model contract

Runtime configuration contains no `MODEL_PATH`. Generic llama.cpp serving resolves the configured
file with `hf_hub_download`, forwarding `MODEL_REVISION`, the runtime cache directory, and
`$EE_HF_TOKEN`, then opens the returned cached file with `Llama`. The Hugging Face repository and
pinned revision are the artifact source of truth; the normal persistent Hub cache is permitted.

| Worker | Repository | Revision | File |
| --- | --- | --- | --- |
| Fine-tuned | `ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf` | `369066092b5eef41c9093474ff7142cc530a853f` | `edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf` |
| Base | `MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF` | `aec29f0e8c31130ba811bec2c774c2ef44888f55` | `Qwen3-4B-Instruct-2507.Q4_K_M.gguf` |
| CyberSec | `mradermacher/CyberSecQwen-4B-GGUF` | `4b369711d408b9fde0efcca155409c072b19a1f6` | `CyberSecQwen-4B.Q4_K_M.gguf` |

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
          "INSTANCE_ID": "edgeguard_llm_finetuned_v0_10",
          "AI_ENGINE": "edgeguard_qwen_4b",
          "SEMAPHORE": "edgeguard_llm_finetuned",
          "PORT": null,
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_NAME": "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf",
            "MODEL_FILENAME": "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf",
            "MODEL_REVISION": "369066092b5eef41c9093474ff7142cc530a853f"
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
            "edgeguard_llm_finetuned",
            "edgeguard_llm_base",
            "edgeguard_llm_cybersec"
          ],
          "PORT": 5055,
          "EDGEGUARD_GENERATION_WORKERS": {
            "finetuned_v0_10": {"SEMAPHORE": "edgeguard_llm_finetuned"},
            "base_qwen3_4b": {"SEMAPHORE": "edgeguard_llm_base"},
            "cybersec_qwen_4b": {"SEMAPHORE": "edgeguard_llm_cybersec"}
          },
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

## Secrets and deployment

edg3 receives an ignored, mode-`0600` runtime env file containing `EE_HF_TOKEN` and the four
`EE_NEO4J_*` values. The tracked devcontainer configuration contains no secret and injects that file
only into edg3 through the generated local devcontainer config. The generic loader reads the Hub
token from the process environment while the stream pins only repository, filename, and revision.
Never place literal credentials in tracked files, logs, task records, prompts, or responses.

The Next.js Worker App Runner needs only the semaphored `EDGEGUARD_API_BASE_URL` plus its own
authentication/deployment secrets. It no longer receives model URLs or Neo4j transport dependencies.
