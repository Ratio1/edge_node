# Per-Node LLM Deeploy E2E

This testbed starts exactly two edge nodes and a private Mosquitto broker in a
dedicated Compose network. Each node has an independent cache volume and mounts
only its assigned GGUF model.

The validator sends the same Deeploy-marked `LLM_INFERENCE_API` pipeline to both
nodes. `PER_NODE_CONFIG.byNode` selects a different `AI_ENGINE`, model path, and
public model alias before serving startup. It then checks local and cross-node
model-aware requests through the real HTTP API and ChainStore balancing path.

Run from the `edge_node` worktree root:

```bash
export PER_NODE_LLM_MODEL_A=/absolute/path/to/llama-3.2-1b-instruct-q8_0.gguf
export PER_NODE_LLM_MODEL_B=/absolute/path/to/Qwen3.5-0.8B-Q8_0.gguf
docker compose -f docker-compose/per-node-llm-e2e.yaml up -d --build
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=../naeural_core:. \
python3 \
  docker-compose/per-node-llm-e2e/validate_per_node_llm.py
docker compose -f docker-compose/per-node-llm-e2e.yaml down -v
```

`PER_NODE_LLM_MODEL_A` and `PER_NODE_LLM_MODEL_B` are required absolute paths.
The validated pairing is Llama 3.2 1B Instruct Q8_0 from `hugging-quants` and
Qwen3.5 0.8B Q8_0 from `unsloth`; equivalent local GGUF artifacts can be used
when recreating the testbed elsewhere.

Expected scenarios:

1. Node 1 serves `llama-1b` locally.
2. Node 2 serves `qwen-0.8b` locally.
3. A `qwen-0.8b` request sent to node 1 executes on node 2.
4. A `llama-1b` request sent to node 2 executes on node 1.

The validator writes a sanitized JSON result under
`docker-compose/per-node-llm-e2e/results/`. Compose teardown removes all node
state and the private broker network.
