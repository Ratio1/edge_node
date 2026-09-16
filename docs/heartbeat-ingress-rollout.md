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

Use the crossed communication roles:

```json
{
  "COMMANDCONTROL": {
    "RECV_FROM": "CTRL_CHANNEL",
    "SEND_TO": "CONFIG_CHANNEL"
  },
  "HEARTBEATS": {
    "RECV_FROM": "CONFIG_CHANNEL",
    "SEND_TO": "CTRL_CHANNEL"
  }
}
```

Heartbeat publishing and subscription must use distinct MQTT clients when EMQX
has `mqtt.ignore_loop_deliver=true`. Putting both on HEARTBEATS suppresses the
node's self echo: peers remain visible, but supervisor self-availability stops
advancing. A broker with this setting disabled can hide the regression.

Receive behavior is derived from the configured channel, not the communicator
name. The dedicated ingress worker, parallel authentication, bounded queues and
ordered NetMon/Epoch commits remain active on COMMANDCONTROL. Command receive
and its queue safeguards move to HEARTBEATS. Keep SEND_TO, QoS, auth, worker and
mirror settings unchanged; DEFAULT remains send-only. Ingress status therefore
appears under `COMM_STATS.COMMANDCONTROL.HEARTBEAT_INGRESS`.

This retains processing isolation, but not full transport isolation: heartbeat
receive and command send share one MQTT connection/network loop. Monitor command
latency under load; a config-only fix is not a guarantee of unchanged peak capacity.

## Existing Nodes And `config_app.txt`

Existing nodes must receive the new settings and crossed roles in their
effective configuration. The tracked `.config_app*.json` files seed
new or reset installations. In the communication testbed that seed is
`.config_app_comms.json`, while a running node normally loads:

```text
/edge_node/_local_cache/_data/box_configuration/config_app.txt
```

Inspect `CONFIG_RETRIEVE` and the deployment's selected application config first.
Correct the authoritative source through the normal distribution mechanism;
an independently managed custom source must not be silently replaced. Where
startup refreshes `config_app.txt` from a seed, such as `.config_app_comms.json`,
changing only the cache is insufficient. Where the persisted file is the source,
update it with a backup. Do not commit generated `config_app.txt` files. Restart
the node and verify effective roles and broker subscriptions, not only file contents.

## Safe Sequence

1. Deploy the compatible code and keep the crossed topology with
   `HEARTBEAT_AUTH_MODE=shadow`.
2. Verify fresh self and peer heartbeat timestamps in NetMon and Epoch state,
   including reconnect and persisted restart, against both broker loopback policies.
3. Verify command delivery and confirm conservation, rejected-full, oldest-age,
   authentication and commit counters through at least one full Epoch boundary.
4. Move authentication to `enforce` only after shadow evidence accounts for
   legacy senders and present identity mismatches.

The loopback regression fix is configuration-only: restore the crossed receive
mapping while keeping the worker enabled. Setting
`HEARTBEAT_INGRESS_WORKER_ENABLED=false` does not fix suppressed self delivery.
As a separate emergency worker rollback, disable the worker. Then whichever
communicator owns CTRL continues consuming one heartbeat at a time on its own
loop through the same authentication and identity checks. This fallback works
with both legacy and regrouped roles, but it restores the old throughput
coupling, so use it as an emergency rollback rather than a steady-state tuning
choice. Do not change both topology and auth enforcement in the same rollout
step. Restoring fresh observations does not repair already faulty historical
epochs; verify eligibility and the next consensus round separately.

## Capacity And Durability

When the queue is full, the new message is rejected and counted; already
accepted FIFO entries are not evicted. Queue depth is the number waiting in the
FIFO. Oldest age reads the timestamp on the head entry in constant time.

This release has no write-ahead log. A broker disconnect does not erase the
process-local queue while the process remains alive, but a process crash can
lose admitted messages. The counters make that loss boundary visible; they do
not provide durable replay or exactly-once delivery.
