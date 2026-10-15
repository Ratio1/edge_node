# RedMesh pipeline configuration

How a node's RedMesh pipeline is laid out, which keys matter, and how to fill it in. The source of
truth for every default is `_CONFIG` in `pentester_api_01.py` and the `DEFAULT_*` blocks in
`services/config.py`; a key left out of the pipeline takes that default.

## Where it lives

A pipeline is one JSON file per node under the node's data volume:

```text
<node data>/_data/box_configuration/streams/<PIPELINE_NAME>.json
```

The node reads it at start. After any edit, restart the node so the plugins pick it up. The file holds
secrets (wallet keys, integration credentials): keep it out of git, back it up before editing, and never
print it whole.

## Shape

```json
{
  "NAME": "<PIPELINE_NAME>",
  "TYPE": "Loopback",
  "DEFAULT_PLUGIN": false,
  "VALIDATED": true,
  "SESSION_ID": "<set by the node>",
  "INITIATOR_ADDR": "<set by the node>",
  "INITIATOR_ID": "<set by the node>",
  "MODIFIED_BY_ADDR": "<set by the node>",
  "MODIFIED_BY_ID": "<set by the node>",
  "LAST_UPDATE_TIME": "<set by the node>",
  "PLUGINS": [
    { "SIGNATURE": "PENTESTER_API_01", "INSTANCES": [ { "INSTANCE_ID": "<id>", "...": "..." } ] },
    { "SIGNATURE": "REDMESH_LLM_AGENT_API", "INSTANCES": [ { "INSTANCE_ID": "llm_agent", "PORT": 5083, "LLM_PROVIDER": "local" } ] },
    { "SIGNATURE": "LLM_INFERENCE_API", "INSTANCES": [ { "INSTANCE_ID": "<id>", "PORT": 5090, "AI_ENGINE": "<engine>" } ] }
  ]
}
```

- `PENTESTER_API_01` is the RedMesh API: scans, jobs, tenancy, reports, integrations, attestation.
  Exactly one instance per node.
- `REDMESH_LLM_AGENT_API` and `LLM_INFERENCE_API` serve the AI analysis; they are needed only when
  `LLM_AGENT.ENABLED` is true. `PENTESTER_API_01.LLM_AGENT_API_PORT` points at the agent's `PORT`.
- The `INITIATOR_*`, `MODIFIED_*`, `SESSION_ID` and `LAST_UPDATE_TIME` fields are written by the node;
  copy them from an existing pipeline rather than inventing them.

## `PENTESTER_API_01` instance

### Required

| Key | What | Example |
|---|---|---|
| `INSTANCE_ID` | Instance name | `"redmesh_api"` |
| `PORT` | API port the Navigator calls | `5082` |
| `TENANCY_NAMESPACE` | CStore partition for every tenant record. Unset means every scoped read, launch and administration call answers `unavailable` | `"dev"` |
| `CHAINSTORE_PEERS` | Node addresses that share job state | `["<node address>", "..."]` |
| `ENV.R1EN_CSTORE_AUTH_HKEY` | CStore hash of the Navigator account store (identity reads) | `"<pipeline name>:auth-v1"` |

### Common

| Key | Default | Notes |
|---|---|---|
| `NR_LOCAL_WORKERS` | code default | Local scan workers |
| `CHECK_JOBS_EACH` | `15` | Seconds between job checks |
| `WARMUP_DELAY` | `30` | Seconds before the first check |
| `DISTRIBUTION_STRATEGY` / `PORT_ORDER` | slice / shuffle | How ports are split and ordered |
| `LLM_AGENT` | disabled | `ENABLED`, `TIMEOUT`, `MODEL`, `STRUCTURED_MAX_FINDINGS`, `STRUCTURED_MAX_TOKENS`, ... |
| `LLM_AGENT_API_HOST` / `LLM_AGENT_API_PORT` | `127.0.0.1` / none | Required when `LLM_AGENT.ENABLED` |
| `GRAYBOX_BUDGETS` | 10 / 100 / 1 | Web app probe budgets |
| `SCAN_TARGET_ALLOWLIST` | `[]` | Extra allowed targets |
| `REDMESH_DEMO_ONLY` | `false` | Demo-only deployment: every real launch is refused |
| `SUPER_TENANT_PERMISSIONS` | all `true` | What the super-tenant may edit about itself |

### Attestation (live jobs)

```json
"ATTESTATION": {
  "ENABLED": true,
  "PRIVATE_KEY": "<live attestation wallet key>",
  "MIN_SECONDS_BETWEEN_SUBMITS": 86400,
  "RETRIES": 2
}
```

Live jobs attest on the node's own network (`EE_EVM_NET`). An empty key skips live attestation.

### `DEMO`: what the edge does for the Navigator Demo

One root block, one sub-block per capability. Today it has `ATTESTATION`; later Demo capabilities sit
beside it.

```json
"DEMO": {
  "ATTESTATION": {
    "ENABLED": true,
    "PRIVATE_KEY": "<demo wallet key>",
    "NETWORK": "testnet",
    "RETRIES": 2,
    "SETTLE_SECONDS": 5
  }
}
```

`DEMO.ATTESTATION` makes Navigator Demo jobs produce real Base Sepolia transactions: one when a job
starts, one when it completes or is stopped. The node signs, the Demo wallet pays.

| Key | Default | Notes |
|---|---|---|
| `ENABLED` | `false` | Off means the Navigator keeps simulated receipts |
| `PRIVATE_KEY` | `""` | The Demo wallet. Must not be the live `ATTESTATION.PRIVATE_KEY`: a shared key is refused (`demo_wallet_shared`) because two senders would race its nonce |
| `NETWORK` | `testnet` | `testnet` or `devnet`, both Base Sepolia. Anything else falls back to `testnet`; mainnet is impossible. Independent of the node's `EE_EVM_NET` |
| `RETRIES` | `2` | Send attempts per event |
| `SETTLE_SECONDS` | `5` | Gap between two Demo sends (the SDK does not wait for mining) |

To fill it in:

1. Create a Base Sepolia wallet for the Demo (a new one, not the live attestation wallet) and fund it
   with a little Base Sepolia ETH. One Demo transaction cost about 0.0000007 ETH in October 2026, so
   0.0003 ETH covers hundreds of jobs.
2. Put its key in `DEMO.ATTESTATION.PRIVATE_KEY` and set `ENABLED: true`, on every node the Navigator
   may call.
3. Restart the node.
4. Check: `POST /get_demo_attestation_status` answers `{"configured": true, "network": "base-sepolia",
   "evm_network": "testnet"}`. `configured` is false when the block is off, the key is empty, or the
   key equals the live key.
5. Launch a Demo job in the Navigator: its timeline shows "Job-start attestation submitted" with a
   `sepolia.basescan.org` link and the execution id. Jobs launched before the block was configured keep
   simulated receipts.

The endpoints `submit_demo_attestation` and `get_demo_attestation_status` accept only `demo-` job ids
and never return the key. They do not check `REDMESH_BACKEND_TOKEN` yet; like most plugin endpoints
they rely on the private network boundary (ADR 0001 in the operations hub).

### Integrations

All disabled by default; each block's keys and defaults are in `services/config.py`.

| Block | Purpose | Secrets |
|---|---|---|
| `MISP_EXPORT` | Push findings to MISP | `MISP_API_KEY` |
| `EVENT_EXPORT` | SOC event envelope, redaction, signing | HMAC via `HMAC_SECRET_ENV` |
| `WAZUH_EXPORT` | Syslog / HTTP delivery to Wazuh | `PASSWORD` |
| `SURICATA_CORRELATION` | Match scans against Suricata alerts | none |
| `STIX_EXPORT` / `OPENCTI_EXPORT` / `TAXII_EXPORT` | CTI exports | `TOKEN`, `PASSWORD` |
| `MODEL_TESTING` | AI model red-teaming; evaluator models by env-var key | `api_key_env` names an env var |

## Environment, not pipeline

Some settings are process environment variables on the node, not pipeline keys:

- `REDMESH_BACKEND_TOKEN`: shared with the Navigator; required by `launch_model_test` and
  `preflight_model_test_provider`.
- `EE_EVM_NET`: the node's own network (live attestation).
- MinIO and MQTT settings (`EE_MINIO_*`, `EE_MQTT_*`) the node needs to start.

## Keys you may find that the plugin ignores

`PORT_DISTRIBUTION` and `TENANT_ADMINISTRATION_ENABLED` appear in older pipelines; the plugin reads
neither (port splitting is `DISTRIBUTION_STRATEGY`). `DEMO_ATTESTATION` at the instance root is not
read: the block is `DEMO.ATTESTATION`.

## Editing safely

1. Copy the file next to itself with a timestamped `.bak` suffix.
2. Change only the keys you mean to, with a JSON-aware tool so the rest stays byte-identical.
3. Validate the JSON, then restart the node.
4. Never paste keys into tickets, chats or commits; read them from where they are kept when writing the
   file.
