# Inference API Request Balancing V1

## Goal

Implement a minimally invasive V1 request delegation protocol for `edge_inference_api` using CStore for:

- peer capacity publication
- delegated request transport
- delegated result transport

V1 is a protocol tracer bullet:

- small payloads only
- `predict` / `predict_async` only
- all peered inference API instances can contribute
- no sharding
- no immediate rerouting to alternate peers
- local request lifecycle remains authoritative on the origin instance

## Scope

In scope:

- `BaseInferenceApiPlugin` orchestration changes
- CStore-backed peer capacity publication
- CStore-backed delegated request and result mailboxes
- bounded local pending queue
- balanced-endpoint eligibility metadata
- compressed request/result transport bodies
- executor-side forced-local handler execution

Out of scope for V1:

- large-payload support via manifests or sharding
- alternate-peer rerouting after timeout or reject
- generic FastAPI framework changes in parent web-app classes
- full endpoint-specific request-model refactor
- balancing for light/status endpoints

## Key Decisions

### Instance participation

All peered instances that run the inference API should contribute to balancing.

This means:

- all publish capacity to CStore
- all can accept delegated requests
- only selected heavy endpoints are balance-eligible

### Endpoint eligibility

V1 balances only:

- `predict`
- `predict_async`

All light/control endpoints remain local-only, including:

- `health`
- `status`
- `metrics`
- `request_status`
- subtype-specific result listing endpoints

Use a thin metadata decorator such as `@balanced_endpoint` to mark balanced endpoints.

The decorator only marks eligibility. It does not implement balancing behavior.

### Capacity model

- `REQUEST_BALANCING_CAPACITY` is configurable and defaults to `1`
- `capacity_used` counts only actively executing requests
- pending requests do not consume capacity
- local-origin and delegated-in executions share the same active capacity pool

Capacity fields:

- `capacity_total`
- `capacity_used`
- `capacity_free`
- `updated_at`

Optional convenience field:

- `accepting_requests`

`updated_at` is mandatory and is used for stale-peer filtering. Peer selection must ignore capacity records older than the configured stale threshold.

### Pending queue

Add a bounded local pending queue for requests that cannot immediately execute locally or be delegated.

Recommended default:

- `pending_limit = max(8, 4 * capacity_total)`

Policy:

- if pending queue has room, keep request pending
- if pending queue is full, reject with overload
- pending requests are retried by the normal process-loop scheduler

### CStore layout

Keep peer capacity separate from delegated work mailboxes.

Namespaces:

- `inference_api:capacity:<group>`
- `inference_api:req:<group>`
- `inference_api:res:<group>`

`capacity` contains peer capacity records only.

`req` contains active delegated work records.

`res` contains final completion/failure records for origin pickup.

Write scope:

- `capacity` records are shared with balancing participants
- `req` records are written only to the selected executor peer
- `res` records are written only to the origin/delegator peer

### Request/result cleanup

Normal cleanup:

- executor deletes request entry after writing final result
- origin deletes result entry after consuming it

Fallback cleanup:

- TTL-based cleanup removes stale orphaned request/result entries

Local request history remains in the origin plugin's persistence, not in CStore.

### Retry policy

V1 retries only the same selected peer on later scheduler passes.

We intentionally do not reroute to another peer immediately in V1.

Reason:

- lower duplicate-execution risk
- simpler protocol
- smaller implementation scope

Add explicit TODO comments for V2 alternate-peer rerouting.

### Transport codec

Use the same fixed codec for both requests and results:

- `zlib+base64+json`

Include explicit version fields in the envelope.

V1 delegates only when the final encoded envelope is below a conservative configured size threshold.

### Executor behavior

The executor should call the actual handler locally.

Balancing wraps before and after handler execution.

Executor-side execution must be forced-local to prevent recursive delegation.

### Validation

V1 origin-side validation before delegation is generic transport-safety validation only:

- endpoint is marked balanced
- request is serializable
- encoded envelope fits the V1 transport size budget
- required protocol metadata is valid

Endpoint-specific validation may still happen inside the existing handler path on the executor.

Executor validation failures must return a normal failed result back to the origin request.

## Protocol Model

### Origin-owned request lifecycle

The origin instance is the only owner of the client-visible request lifecycle.

Origin request states may include:

- `pending`
- `queued`
- `delegated`
- `running_local`
- `completed`
- `failed`
- `timeout`

The origin always owns:

- HTTP response semantics
- sync postponed resolution
- async polling status
- local persistence/history

### Executor-owned work lifecycle

The executor only owns remote execution of delegated work.

Executor-side delegated work states may include:

- `submitted`
- `accepted`
- `running`
- `failed`
- `expired`

### CStore result states

Result records may include:

- `completed`
- `failed`
- `rejected`
- `timeout`

## CStore Record Shapes

### Capacity record

Stored in `inference_api:capacity:<group>`.

Key:

- `<ee_addr>:<pipeline>:<signature>:<instance_id>`

Suggested value:

```json
{
  "protocol_version": 1,
  "balancer_group": "group-name",
  "ee_addr": "0x...",
  "pipeline": "pipeline_name",
  "signature": "SD_INFERENCE_API",
  "instance_id": "instance_1",
  "capacity_total": 1,
  "capacity_used": 0,
  "capacity_free": 1,
  "max_cstore_bytes": 524288,
  "updated_at": 0.0,
  "accepting_requests": true
}
```

### Delegated request record

Stored in `inference_api:req:<group>`.

Key:

- `delegation_id`

Suggested value:

```json
{
  "protocol_version": 1,
  "delegation_id": "uuid",
  "origin_request_id": "uuid",
  "endpoint_name": "predict",
  "status": "submitted",
  "origin_addr": "0xorigin",
  "origin_instance_id": "origin_inst",
  "target_addr": "0xtarget",
  "target_instance_id": "target_inst",
  "created_at": 0.0,
  "updated_at": 0.0,
  "expires_at": 0.0,
  "body_codec": "zlib+base64+json",
  "body_format_version": 1,
  "compressed_request_body": "..."
}
```

### Result record

Stored in `inference_api:res:<group>`.

Key:

- `delegation_id`

Suggested value:

```json
{
  "protocol_version": 1,
  "delegation_id": "uuid",
  "origin_request_id": "uuid",
  "status": "completed",
  "origin_addr": "0xorigin",
  "origin_instance_id": "origin_inst",
  "target_addr": "0xtarget",
  "target_instance_id": "target_inst",
  "created_at": 0.0,
  "updated_at": 0.0,
  "expires_at": 0.0,
  "body_codec": "zlib+base64+json",
  "body_format_version": 1,
  "compressed_result_body": "..."
}
```

## Scheduling and Polling

### Capacity publication

Publish capacity:

- once on startup
- once when an execution starts
- once when an execution ends
- once when `REQUEST_BALANCING_ANNOUNCE_PERIOD` elapsed since last publish

Recommended default:

- `REQUEST_BALANCING_ANNOUNCE_PERIOD = 60`

### Mailbox polling

Use the same style as the current incoming/postponed request scheduling:

- bounded work per loop
- fair enough to avoid starving existing flows
- integrated into the plugin `process()` path

Per loop, do bounded work for:

- local pending scheduling
- delegated request mailbox polling
- delegated result mailbox polling

V1 does not use `hsync`.

Peer selection uses only the locally replicated capacity view plus `updated_at` freshness filtering.

## Peer Selection

Peer selection should be capacity-aware and deterministic enough for debugging.

Algorithm:

1. read `inference_api:capacity:<group>`
2. filter peers:
   - same group
   - same signature / compatible subtype
   - fresh `updated_at`
   - if `accepting_requests` is present, it must be `true`
   - `capacity_free > 0`
   - not self
3. compute `best_free = max(capacity_free)`
4. select randomly among peers with `capacity_free == best_free`

This gives:

- for capacity `1`: random among all free peers
- for capacity `>1`: preference toward peers with more available slots

If the selected executor resolves to the origin instance itself, bypass CStore request/result transport and execute through the normal local handler path while still updating local capacity state.

V2 TODO:

- add latency/failure scoring
- add weighted least-loaded policy
- add alternate-peer rerouting

## Execution Flow

### Local request flow

1. HTTP request arrives at origin.
2. Origin runs existing auth/rate-limit/basic validation path.
3. Origin registers the local request in `_requests`.
4. If endpoint is not balanced, execute locally.
5. If local capacity is free, execute locally.
6. Otherwise, enqueue as pending and allow scheduler to attempt delegation.

### Delegation flow

1. Scheduler picks a pending request.
2. If local capacity has become free, execute locally.
3. Else choose a peer via capacity records.
4. If the selected peer is self, execute locally and bypass CStore request/result transport.
5. Otherwise build encoded delegation envelope.
6. If envelope exceeds configured max bytes, do not delegate; keep local or fail by policy.
7. Write delegated request to `inference_api:req:<group>` targeting only the selected executor peer.
8. Mark origin request as delegated/pending.

### Executor flow

1. Executor polls `inference_api:req:<group>`.
2. It finds records targeting itself.
3. It ignores stale, expired, or already-seen records.
4. If active capacity is full, leave request pending for later poll pass.
5. If capacity is free:
   - reserve execution slot
   - execute the actual handler locally in forced-local mode
   - build encoded result record
   - write result to `inference_api:res:<group>` targeting only the origin peer
   - delete request record from `req`
   - release execution slot

### Origin result flow

1. Origin polls `inference_api:res:<group>`.
2. It finds results targeting itself.
3. It matches by `delegation_id`.
4. It decodes the result body.
5. It updates the original `_requests[origin_request_id]`.
6. It deletes the result record from `res`.

## Code Structure

### Base class ownership

`BaseInferenceApiPlugin` should own:

- balanced-endpoint orchestration
- pending queue management
- capacity tracking
- capacity publication
- peer selection
- CStore request/result mailbox writing and polling
- generic transport validation
- result application back to local `_requests`
- TTL cleanup

### Handler ownership

Handlers remain the request solvers.

The executor should call the actual handler locally.

Balancing logic wraps before and after handler execution.

This keeps V1 minimally invasive.

### Prevent recursion

Delegated execution on the executor must force local execution and must not re-enter the delegation decision path.

## Config Additions

Suggested additions to `BaseInferenceApiPlugin.CONFIG`:

- `REQUEST_BALANCING_ENABLED`
- `REQUEST_BALANCING_GROUP`
- `REQUEST_BALANCING_CAPACITY`
- `REQUEST_BALANCING_PENDING_LIMIT`
- `REQUEST_BALANCING_ANNOUNCE_PERIOD`
- `REQUEST_BALANCING_PEER_STALE_SECONDS`
- `REQUEST_BALANCING_MAILBOX_POLL_PERIOD`
- `REQUEST_BALANCING_MAX_CSTORE_BYTES`
- `REQUEST_BALANCING_REQUEST_TTL_SECONDS`
- `REQUEST_BALANCING_RESULT_TTL_SECONDS`

## Implementation Steps

1. Add `@balanced_endpoint` metadata support in `base_inference_api.py`.
2. Mark `predict` and `predict_async` as balanced.
3. Add capacity tracking helpers and active-slot reservation/release.
4. Add bounded local pending queue and timeout handling.
5. Add capacity publication helpers and periodic publication logic.
6. Add CStore request/result body codec helpers.
7. Add peer selection based on highest free capacity with randomized tie-break.
8. Extend the main request path to:
   - keep local behavior for non-balanced endpoints
   - queue/delegate when local capacity is full
9. Add request mailbox writer.
10. Add executor mailbox poller and forced-local handler execution path.
11. Add result mailbox writer and origin result poller.
12. Add cleanup and TTL pruning.
13. Add focused tests for V1 flow.

## Verification

Minimum tests:

- balancing disabled preserves current behavior
- balanced endpoints delegate only when local capacity is full
- light endpoints stay local
- capacity publication happens at startup/start/end/periodic intervals
- peer selection chooses the highest `capacity_free` peer and randomizes ties
- oversized encoded request does not delegate
- executor consumes delegated request and writes result
- origin consumes result and resolves original request
- executor failure is returned as normal request failure
- CStore request/result entries are deleted after normal consumption
- stale/orphaned entries are cleaned up
- pending queue limit rejects overload

Suggested command:

```bash
python3 -m unittest extensions.business.edge_inference_api.test_sd_inference_api
```

If a dedicated module is added:

```bash
python3 -m unittest extensions.business.edge_inference_api.test_request_balancing
```

## V2 TODOs

- reroute to alternate peers after timeout or repeated failure
- manifest/sharding for large request/result bodies
- endpoint-specific normalized request-model hooks
- smarter peer scoring with latency/failure history
- configurable priorities for pending queue scheduling
- stronger claim/lease semantics if needed
