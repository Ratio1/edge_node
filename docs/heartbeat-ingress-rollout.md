# Heartbeat Ingress Rollout

The runtime now admits raw CTRL heartbeats into a bounded in-memory FIFO,
authenticates signed envelopes on a small worker set, and commits formatter,
deduplication, NetMon, and Epoch state on one ordered owner thread.

## Runtime Configuration

The recommended initial settings are:

```json
{
  "HEARTBEAT_INGRESS_WORKER_ENABLED": true,
  "HEARTBEAT_INGRESS_QUEUE_SIZE": 10000,
  "HEARTBEAT_AUTH_WORKERS": 4,
  "HEARTBEAT_AUTH_MAX_IN_FLIGHT": 32,
  "HEARTBEAT_AUTH_MODE": "shadow"
}
```

`HEARTBEAT_AUTH_WORKERS` performs only raw JSON parsing and signature
verification concurrently. `HEARTBEAT_AUTH_MAX_IN_FLIGHT` bounds the work that
has left the main FIFO but is waiting for its ordered turn. Formatter decoding,
deduplication, NetMon, and Epoch mutation remain serial and preserve FIFO order.
Signing-canonicalization counters remain in memory during heartbeat processing;
their best-effort JSON snapshot is flushed after the heartbeat worker drains on
clean shutdown, so metric persistence does not compete with authentication. If
the worker exceeds its shutdown timeout, runtime status and logs report an
incomplete drain and the snapshot is not flushed; shutdown persistence is
best-effort rather than absolute.

The regrouped communication roles are:

```json
{
  "COMMANDCONTROL": {
    "RECV_FROM": "CONFIG_CHANNEL",
    "SEND_TO": "CONFIG_CHANNEL"
  },
  "HEARTBEATS": {
    "RECV_FROM": "CTRL_CHANNEL",
    "SEND_TO": "CTRL_CHANNEL"
  }
}
```

The old crossed roles remain supported for rollback. Receive behavior is
derived from the configured channel, not the communicator name.

## Existing Nodes And `config_app.txt`

Existing nodes must receive the new settings and regrouped roles in their
effective persisted configuration. The tracked `.config_app*.json` files seed
new or reset installations. In the communication testbed that seed is
`.config_app_comms.json`, while a running node normally loads:

```text
/edge_node/_local_cache/_data/box_configuration/config_app.txt
```

Update that file through the normal configuration distribution mechanism; do
not commit a generated `config_app.txt`. A rollback test must update both the
startup seed, such as `.config_app_comms.json`, and the persisted
`config_app.txt`; otherwise startup can immediately restore the seeded values.
Verify the effective persisted file after restart or configuration reload.

## Safe Sequence

1. Deploy the compatible code and keep the legacy topology with
   `HEARTBEAT_AUTH_MODE=shadow`.
2. Confirm conservation, rejected-full, oldest-age, authentication, and commit
   counters remain healthy for at least one full Epoch boundary.
3. Change the persisted communication roles to the regrouped topology and
   verify broker subscriptions and command delivery.
4. Move authentication to `enforce` only after shadow evidence accounts for
   legacy senders and present identity mismatches.

Rollback is configuration-only: restore the legacy role mapping or set
`HEARTBEAT_INGRESS_WORKER_ENABLED=false`. With the worker disabled, whichever
communicator owns CTRL continues consuming one heartbeat at a time on its own
loop through the same authentication and identity checks. This fallback works
with both legacy and regrouped roles, but it restores the old throughput
coupling, so use it as an emergency rollback rather than a steady-state tuning
choice. Do not change both topology and auth enforcement in the same rollout
step.

## Capacity And Durability

When the queue is full, the new message is rejected and counted; already
accepted FIFO entries are not evicted. Queue depth is the number waiting in the
FIFO. Oldest age reads the timestamp on the head entry in constant time.

This release has no write-ahead log. A broker disconnect does not erase the
process-local queue while the process remains alive, but a process crash can
lose admitted messages. The counters make that loss boundary visible; they do
not provide durable replay or exactly-once delivery.
