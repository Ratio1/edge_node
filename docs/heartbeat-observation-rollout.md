# Heartbeat Observation Rollout

The SDK supports three immutable heartbeat observation modes:

- `full_network` keeps the existing global `CTRL` subscription and is the default.
- `selected_nodes` subscribes only to exact `CTRL/<node_address>` topics.
- `summary_discovery` does not subscribe to `CTRL`; it discovers network state from trusted, signed `NET_MON_01` payloads.

## Runtime Configuration

The edge runtime needs this communication shape before any selected-node SDK is enabled:

```json
{
  "CTRL_CHANNEL": {
    "TOPIC": "naeural/ctrl",
    "TARGETED_TOPIC": "naeural/ctrl/{}",
    "SUBSCRIBE_TARGETED": false
  },
  "HEARTBEAT_TARGETED_MIRROR_ENABLED": false
}
```

Use the deployment's actual topic root. `SUBSCRIBE_TARGETED` remains `false` for edge communicators because the targeted route is for SDK consumers; subscribing the edge CommandControl receiver to its own route would duplicate heartbeat processing.

When `HEARTBEAT_TARGETED_MIRROR_ENABLED` is enabled, a node publishes the same serialized, signed heartbeat once to the global topic and once to its own addressed topic. The flag can also be supplied as `EE_HEARTBEAT_TARGETED_MIRROR_ENABLED=true`. The default remains global-only.

## Existing Nodes And `config_app.txt`

Yes, existing nodes need their persisted application configuration updated. The tracked `.config_app*.json` files seed new or reset installations. In the communication testbed that seed is `.config_app_comms.json`, but a running node normally loads:

```text
/edge_node/_local_cache/_data/box_configuration/config_app.txt
```

Update that persisted configuration through the normal configuration distribution or deployment mechanism so `CTRL_CHANNEL.TARGETED_TOPIC` and `CTRL_CHANNEL.SUBSCRIBE_TARGETED` are present. Do not add a generated `config_app.txt` to source control. Rollback tests must update both `.config_app_comms.json` and the persisted file so startup seeding cannot undo the rollback. After update and restart or configuration reload, verify the effective persisted file before enabling the mirror.

If the mirror flag is enabled while `TARGETED_TOPIC` is absent, the runtime warns once and continues publishing globally. It does not invent a topic. A `selected_nodes` SDK will therefore remain degraded instead of silently subscribing to the full network.

## Safe Sequence

1. Deploy the runtime and SDK code while all clients remain in the default `full_network` mode.
2. Add the targeted topic with the mirror disabled to templates and existing nodes' persisted configuration.
3. Verify the effective config and the unchanged global heartbeat path.
4. Enable the heartbeat mirror on a small node cohort.
5. Start `selected_nodes` SDK sessions for those nodes and require `state == "ready"` from `get_heartbeat_observation_status()`.
6. Start `summary_discovery` only with explicitly trusted NetMon publisher addresses and require a fresh accepted summary.
7. Expand only while broker delivery counters, SDK queue counters, and observation freshness remain healthy.

Rollback is configuration-only: recreate reduced-mode SDK sessions as `full_network`, then disable the mirror. Leaving `TARGETED_TOPIC` configured while the mirror is disabled is harmless.

## Durability Boundary

This change does not add a write-ahead log. Messages already admitted to an in-memory SDK or node queue survive a broker disconnect while the process remains alive, but a process crash can lose them. Queue conservation and freshness metrics make that risk visible; they do not provide durable replay.
