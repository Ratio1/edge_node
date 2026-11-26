# Deeploy deployment lifecycle specification and implementation plan

Date: 2026-10-14. Status: implemented on coordinated review branches; final validation and PR references are recorded below.

Deeploy will accept deployment requests asynchronously, persist their execution independently of HTTP connections, and expose one polling endpoint that reports progress across all target nodes. Node-owned reporting will expose explicit failures even when a plugin cannot initialize. Generic worker and container apps follow their configured source by default. Workload failures leave these jobs deployed. Pinned apps, catalogue services and infrastructure failures use the stop and restoration rules below.

This is the durable reference for implementation across independent Ratio1 repositories and for resuming work after chat compaction. The confirmed decisions below supersede earlier proposals in the conversation, particularly proposals to keep partially successful deployments running or to preserve legacy API behavior.

## Upgrade notice for app owners

On the first node restart after this upgrade, existing generic worker apps rebuild from the current head of their branch. Generic container apps pull the current image of their tag. A branch or tag may have moved since deployment. An app whose current source fails stays deployed and may be unavailable until a working version arrives. During an update the previous revision stops before the new one starts.

Notify app owners before rollout. Upgrade nodes (Core and runners), then coordinators, then the web app, with no active operation at the switch. An older node that omits the source mode retains its existing failure handling. Catalogue services keep their current version and recovery policy.

## Confirmed product decisions

1. Use existing CStore and R1FS infrastructure for durable operation state and revision payloads. Do not introduce an external database or workflow service.
2. Polling must work from any Deeploy oracle, including an oracle other than the one that accepted the request and an oracle that has restarted.
3. Make both `create_pipeline` and `update_pipeline` asynchronous at the HTTP contract level. Acceptance is separate from deployment completion.
4. Add exactly one public polling endpoint. It returns progress, per-node and per-plugin state, errors, recent events, and recovery status together. Do not add separate status, history, event-stream, or discovery endpoints.
5. Show deployment progress across every target node in Deeploy, including errors, cleanup, and restoration progress. Polling is sufficient; SSE and WebSockets are outside this scope.
6. A create succeeds only when every required instance on every planned target node is ready. If a source-following workload is kept, commit the revision with outcome `waiting_for_source`. On a terminal failure, stop its pipeline on nodes where it started and prevent pending starts from completing afterward.
7. A failed update stops the rollout and restores the previous configuration after every required stop is confirmed. A kept workload failure commits the new revision and releases the previous revision's secrets.
8. All affected components will be deployed together. No legacy deployment response handling, opt-in asynchronous flags, dual deployment protocols, or migration scripts are required. Decision 14 defines the narrow exception for existing pipelines resolving secrets after restart.
9. Implementation and pull requests are authorized from current `develop` (Edge/frontend) and `main` (Core). Live deployments, chain writes, remote configuration changes, and production data changes remain outside scope.
10. **2026-10-14 implementation clarification:** the coordinator is the oracle receiving each create/update request. Do not implement distributed locking, consensus, stable coordinator assignment, or automatic failover. Polling remains available through any oracle. Concurrent submissions through different oracles are not globally serialized; the client must reuse a request ID and discover an existing operation before deliberate retries.

11. **2026-10-14 certificate recovery:** include CockroachDB certificate-regeneration recovery in this release. Preserve the prior credentials and data, stop every failed-generation node before restoring, and require authenticated TLS SQL readiness using the planned certificates. See [certificate recovery](deeploy-certificate-recovery.md).
12. **2026-10-14 mutation scope:** scale-up and whole-job deletion are asynchronous and use the same polling endpoint. Scale-up is a full placement revision with rollback. Delete waits for confirmed stops before removing secrets and metadata. Partial node deletion is rejected; no compatibility mode. Deleted paid job IDs may be reused through a higher revision (user confirmed).

13. **2026-10-14 completion clarification:** coordinator completion is the final deployment outcome. The UI must not wait for blockchain consensus: report deployment success and stop automatic polling once execution and required recovery are complete. Do not track, display, or gate deployment completion or subsequent operations on blockchain transactions. The existing ChainDistMonitor remains separate; authentication and paid-job admission validation are unchanged. The SDK examples use the same completion boundary.

14. **2026-10-15 existing-pipeline exception (user confirmed):** existing pipelines must continue working after restart without `secret_revision`. Retain unversioned secret resolution only for pre-lifecycle pipelines, authorized against current raw-CID metadata and runner placement. Reject versioned/deleted jobs on that path. New deployments and the first update's target/restoration configurations use immutable secret revisions. This exception does not restore the old deployment API or require operator migration.

15. **2026-10-15 local admission concurrency (user confirmed):** remove `_serialize_job_mutation` and the global admission lock, including the create/update and coordinator-worker lock scopes. Leave HTTP request handling as it was; do not add background preparation workers or postponed responses. The caller assumes no concurrent requests for the same job. Preserve observed-operation/revision conflicts and the handoff from live preparation to recovery without blocking other jobs. Core's sequential HTTP dispatch remains unchanged.

16. **2026-10-20 review corrections (user approved):** release runtime plugin references only after confirmed stop evidence is persisted, retaining the journal and unconfirmed runtimes. Isolate per-job observation/cleanup exceptions so unrelated node reports continue. SDK deletion accepts revision `0` for existing pipelines with no revision metadata. Deployment-status authentication maps nonce/signature rejection to HTTP 401 without changing shared authentication helpers. Edit forms retain the revision loaded with their saved configuration; polling validates that revision and must not replace it with a newer one or automatically reload configuration. Stale edits are rejected before payment, allocation or submission. Capture abort fencing and the dApp session-refresh interceptor are explicitly unchanged. The SDK's fixed-name signer cache remains a separate investigation: it can reuse wallet A when a later helper explicitly requests wallet B.

## Repository orientation and inspected baseline

The reference inspection used `edge_node` commit `7ba2adbf`, `naeural_core` commit `a4b2ad0`, and `deeploy-dapp` commit `56a90f4`. Recheck the relevant code before implementation; these commits describe the inspected baseline, not a required checkout state.

| Repository and source | Baseline responsibility and implementation relevance |
| --- | --- |
| [Deeploy manager](../extensions/business/deeploy/deeploy_manager_api.py) | API admission, dispatch orchestration, in-memory pending requests, timeout handling, finalization, and blockchain confirmation. Internal async mode still postpones the response; it is not the required durable operation API. |
| [Deeploy mixin](../extensions/business/deeploy/deeploy_mixin.py) | Request validation, materialized node configurations, dispatch, response collection, runtime discovery, and pipeline lookup. The collector currently counts any non-null response as confirmation. |
| [Job persistence mixin](../extensions/business/deeploy/deeploy_job_mixin.py) | R1FS pipeline persistence, CStore registry pointers, dAuth bundles, and staging/rollback. Existing metadata rollback does not restore running node configuration. |
| [Response routing mixin](../extensions/business/deeploy/deeploy_chainstore_response_mixin.py) | Response key setup and routing helpers. Revisit replication scope for any-oracle reads. |
| [Deeploy constants](../extensions/business/deeploy/deeploy_const.py) | Request fields, status vocabulary, and examples. |
| [Container runner](../extensions/business/container_apps/container_app_runner.py) | Container lifecycle, readiness, local errors, restarts, and cleanup. Application health and container-start acknowledgment must be distinguished. |
| [Core BusinessManager](../../naeural_core/naeural_core/business/business_manager.py) | Loads and instantiates plugins; already detects missing plugin code and initialization exceptions. |
| [Core plugin execution wrapper](../../naeural_core/naeural_core/business/base/base_plugin_biz.py) | Currently invokes ChainStore response publication from the plugin processing loop. |
| [Core response mixin](../../naeural_core/naeural_core/business/mixins_base/deeploy_chainstore_response_mixin.py) | Publishes a readiness response once per cycle and routes it to selected peers. |
| [Core readiness mixin](../../naeural_core/naeural_core/business/mixins_base/plugin_readiness_mixin.py) | Existing readiness interface; also used by semaphores. Preserve correct dependency signaling while separating deployment publication. |
| [Core CStore contract](../../naeural_core/docs/CSTORE.md) | Local reads, push replication, cache persistence, and explicit namespace repair. Contains important consistency limits. |
| [Frontend payment flow](../../deeploy-dapp/src/shared/projects/Payment.tsx) | Pays jobs, signs requests, calls create, classifies results, and removes successful drafts. Must hand off to durable tracking after acceptance. |
| [Frontend API wrappers](../../deeploy-dapp/src/lib/api/deeploy.ts) and [API types](../../deeploy-dapp/src/typedefs/deeployApi.ts) | Submission and polling contracts. |
| [Deployment provider](../../deeploy-dapp/src/lib/contexts/deployment/deployment-provider.tsx), [flow modal](../../deeploy-dapp/src/components/draft/DeeployFlowModal.tsx), and [job instances](../../deeploy-dapp/src/components/job/JobInstances.tsx) | Shared tracking state and deployment presentation. |

The inspected baseline timeout handling dropped pending tracking without stopping deployed nodes. First-time create staging can retain secrets; update and scale-up timeout paths can restore stored metadata while nodes continue running changed configurations. The implementation checkpoints describe the replacement for both tracking loss and this runtime/metadata mismatch.

Use existing command dispatch, validation, R1FS persistence, dAuth protection, node notifications, readiness, and frontend query conventions as the implementation quality bar. Replace lifecycle ownership rather than duplicating existing builders or authorization logic.

## Scope and invariants

The required end-to-end feature is create/update admission, durable execution, node reporting, one polling API, all-target readiness, automatic failure recovery, and the Deeploy UI. Shared scale-up, stop, and delete paths must participate in operation coordination so they cannot race an active deployment or invalidate secrets during recovery. Scale-up and whole-job deletion also return durable operation acceptance; partial node deletion is rejected by the confirmed scope decision.

The following invariants are release requirements:

- No deployment command is sent before its intent, exact execution plan, and required revision data are durably recoverable.
- An HTTP disconnect or polling error does not fail, cancel, or duplicate deployment.
- Retries reuse a discoverable existing operation by request ID. There is no atomic cross-oracle admission guarantee for simultaneous submissions before replication, per the confirmed receiving-oracle coordinator design.
- Only the recorded receiving oracle executes a given operation. A different oracle never takes it over. Detect known active operations and conflicting revisions; do not claim distributed serialization of simultaneous admissions.
- Reserve `succeeded` for a rollout with every required instance ready. Both `succeeded` and `waiting_for_source` make the target revision current. No silent substitution of nodes or reduction of the target count.
- A received command, running plugin object, or non-null CStore entry is not sufficient evidence of application readiness.
- Once an attempt is aborted, late success reports cannot revive its operation. Nodes that have enforced the abort must reject delayed starts; nodes that have not yet learned/enforced it remain unresolved cleanup obligations.
- Cleanup completion requires positive evidence that the scoped workloads stopped. A missing heartbeat is not that evidence.
- Recovery requires restoration of the previous configuration and placement. A previous source-following workload may be waiting for its source when restoration completes.
- Keep every secret/configuration revision that may still be needed by a live, unreachable, or restoring instance.
- Never roll back application data or delete persistent volumes as an implicit deployment cleanup action.
- Runtime execution, recovery and metadata determine the deployment outcome. Blockchain transactions are outside this lifecycle.

## Deployment and operation records

Use a deployment identity scoped by network, escrow/owner authorization domain, and job ID. Existing `app_id` is the stable pipeline identity; do not generate a different app identity when retrying an accepted request.

| Record | Required information |
| --- | --- |
| Deployment index | Stable identity; active operation; desired and last successful revisions; exact previous placement; coordination ownership/version; bounded recent-operation references. |
| Immutable revision | Redacted canonical configuration; canonical hash; exact materialized configuration references per node; required plugin identities; secret revision references; readiness requirements; image/content identifiers where available. |
| Operation intent | Operation ID; signed client request ID; semantic request hash; create/update kind; expected prior revision; target revision; frozen node/instance plan; timestamps; deadlines; recovery policy. |
| Operation progress | Execution phase; outcome; retry schedule; error details; abort decision; cleanup/restoration evidence; metadata progress; monotonically ordered changes. |
| Node observation | Authenticated node; operation/revision/attempt; plugin identity; local phase; readiness; structured error; sequence/incarnation; emitted and received times. |
| Action record | Dispatch/stop/restore action ID, scope, precondition, attempt history, acknowledgment, and completion evidence. |

Large immutable redacted definitions and bounded historical snapshots belong in R1FS. Frequently read operation indexes, small progress records, node observations, and recovery decisions belong in CStore. Store protected secret material through dAuth, not in public progress records or ordinary revision payloads.

Avoid a single shared read-modify-write node-status blob: independent nodes must not overwrite one another's observations. Use separately owned records and aggregate them for polling.

Namespace names, serialization types, and internal helper names are implementation choices. They must not require new public endpoints or an external store.

## CStore durability and coordination requirements

The current CStore contract documents local reads and explicit `hsync` repair. `hsync` accepts the first valid allowed-peer response, overwrites overlapping fields, preserves local-only fields, and does not arbitrate freshness or prune deletions. It is not proof of distributed locking, compare-and-set, transactional admission, or globally fresh reads.

Before building the worker, establish an executable storage/coordination contract within CStore/R1FS:

1. **Acceptance durability:** specify the required peer acknowledgments, persistence boundary, and R1FS payload availability. A local in-memory write or an unexplained fixed number of network acknowledgments is not a sufficient durability claim. Verify cache flush/restart behavior and explicitly define tolerated failures.
2. **Admission and idempotency:** persist request identity and an admission record before dispatch; retries consult replicated records. An interrupted local admission is recoverable. The receiving oracle coordinates its own operation; cross-oracle simultaneous requests are not made atomic.
3. **Receiving oracle ownership:** record the receiving oracle's authenticated identity. Only it advances execution or recovery, including after restart. Other oracles read replicated progress. There is no distributed lock, leader election, stable routing assignment, or automatic takeover. If the coordinator is unavailable, execution/recovery pauses and polling reports freshness honestly.
4. **Versioned observations:** reject stale state per operation, coordinator identity, node incarnation, and sequence. Use immutable/versioned records or strengthen the relevant merge behavior; do not rely on wall-clock last-write-wins ordering.
5. **Peer discovery and replication:** explicitly define the authorized oracle/registry peers for intents, indexes, observations, and abort records. Existing initiating-oracle-plus-one-seed response routing alone is insufficient for any-oracle polling and restart recovery.
6. **Local replica reads:** deployment admission, polling, and coordinator recovery read locally persisted or pushed operation snapshots and node reports without namespace repair. Missing operation replicas return synchronizing/unavailable. Missed terminal node reports are not automatically pulled later; remote state becomes visible when it reaches the local replica.
7. **Retention and tombstones:** preserve abort/fencing decisions and revision references long enough to reject delayed commands and repair restarted peers. Prevent stale snapshot merges from resurrecting removed operations or references.
8. **Recovery:** rebuild active work from durable intents and action records; reconcile node evidence before repeating a side effect whose previous acknowledgment was lost.
9. **Start versus abort ordering:** define start-authorization validity and synchronization on reconnect/restart. A disconnected node may execute an already authorized start before it learns of an abort; a coordinator-local abort write cannot retroactively prevent that. Require renewed authority where the protocol needs it, and distinguish `abort requested` from `abort enforced everywhere`. Any late execution remains subject to stop/fencing and blocks cleanup completion.

Any Deeploy oracle must serve the polling API without relying on another oracle's Python dictionary. Under a partition, it may return an explicitly stale/unknown view or a retryable availability error; it must not invent fresh state, declare a missing local record nonexistent, or take over another oracle’s operation.

The coordination decision is resolved: receiving-oracle ownership with no takeover and no distributed locking/consensus. Persistence, signed/versioned records, and replay are implemented and covered by the verification below. The deployment coordinator no longer repairs operation/report namespaces. Do not expand this into a consensus project. No external database fallback is authorized.

## Submission API contract

Keep `POST /create_pipeline` and `POST /update_pipeline` and replace their response behavior unconditionally. Do not retain the old postponed-response path behind a flag.

The signed payload must include a stable client-generated `request_id`; updates additionally identify the expected current revision. Bind the request ID, operation kind, job/app identity, target configuration, and preconditions into the signature/hash contract. Authentication envelope refreshes must not change the semantic request hash.

The frontend persists the request ID before its first submission. Scope idempotency by deployment/authorization domain and operation kind. The same key and semantic request return the original operation, including after completion; a changed payload with the same key is a conflict. A deliberate new attempt uses a new request ID after prior cleanup/recovery is resolved.

Admission checks identity, authority, ownership/payment eligibility, schema, and known active-operation/revision preconditions. These checks do not constitute a distributed lock. Expensive plan preparation may occur in the worker, but the resulting exact plan must be durably committed before any dispatch. Invalid requests that can be rejected before admission should be rejected immediately.

Successful first acceptance returns HTTP 202 with the existing response envelope conventions, for example:

```json
{
  "result": {
    "operation_id": "op_123",
    "request_id": "request_abc",
    "job_id": 42,
    "app_id": "app_456",
    "revision": 3,
    "status": "accepted"
  }
}
```

A duplicate can return the same operation with its current status. Transport success is not rollout success. Map pre-admission validation/auth/conflict errors to appropriate HTTP errors with a stable error code. Storage admission failure must not dispatch work; if acceptance is uncertain, return a retryable error and require same-key retry rather than a new operation.

Rejected admissions create no accepted deployment and trigger no workload commands. After admission, preparation and execution failures are recorded on the operation and visible through polling.

### Same-host recovery of a blocked legacy relink

The escrow owner or an active delegate who can edit the job uses **Edit → Review → Update job** on the original coordinator. Version 1 covers a legacy untracked Git worker with one instance, common previous settings and no persistent volumes, sync, per-node overrides or pending one-shot command. The prior worker must configure its Git checkout so rollback can select the verified commit. A signed partially retired relink, confirmed license links, a paid slot for each placement, at least one surviving worker and a verifiable prior stop are required. Each historical address remains visible separately from its paid successor.

| Entry point | Contract |
| --- | --- |
| `POST /get_job_repair_preview` | A v3 wallet signature in the **get job repair preview** domain covers the positive integer `job_id`, original `coordinator` and hexadecimal epoch-milliseconds `nonce`. The normal 12-hour wallet nonce expiry applies. An authorized editor receives `status=reviewable` and a proposal, or `status=blocked` and a reason. Preview reads local worker observations, the canonical CID and current chain registrations. It sends no worker command. |
| `POST /repair_update_pipeline` | A v3 wallet-signed **repair update pipeline** request with the ordinary edit fields, stable request ID, expected revision, and `repair={proposal,same_host:true,rotate_main_tunnel:boolean}`. The signed proposal includes version, network, job, coordinator, parent identity/sequence/plan CID, published pipeline CID, instance ID, ordered old/current pairs and index permutations for commands, peers and targets. Reordering moves only the reviewed elements. The receiver rechecks the signer's escrow access and the entire proposal and runs normal payment, resource and request validation. The escrow owner scopes the operation and its retries. |
| `POST /get_deployment_status` | The existing poll returns the linked operation. During the handoff the parent shows `holding_for_repair` and its `repair_child_operation_id`. After the child finishes, the parent shows `completed/superseded`. The child's `relinked_nodes` lists the previous/current pairs. Existing ready counts refer to its paid workers. Retry an uncertain signed submission on the original endpoint. |

Both repair endpoints support the shared Deeploy API. If another oracle receives the request, it checks the signed wallet request against the verified CStore operation and forwards the original envelope over encrypted peer messaging. The coordinator rechecks authorization, evaluates the repair and signs its ordinary response. The relay keeps only pending reply information in memory. A missing reply blocks the preview or returns retryable `ADMISSION_UNAVAILABLE` for the update. Retry the same signed update and `request_id` so the coordinator can return an operation it already accepted.

The reviewed target permutation also applies to `PER_NODE_TARGET_NODES` if it exactly mirrors the corresponding target order in the saved config and every surviving worker report. This uses the existing signed target order and the exact worker fingerprint. The same-host repair continues to require a single Git worker with no per-node overrides. Legacy `DEEPLOY_SPECS.spare_nodes` and the response-key list for each node under `DEEPLOY_SPECS.chainstore_response_keys` may match the reported order only when every entry and its multiplicity agree. The ordinary legacy edit guard uses this metadata rule in a comparison copy and retains the saved order for rollback. Managed-service order fields require their exact allocation and per-node plan.

Admission sends one targeted inspection per current worker. A survivor must sign its actual Git HEAD and the reviewed full configuration, including the three ordered lists. The coordinator encrypts the expected fingerprint to that worker. An already stopped worker confirms its own journaled stop, matching Git commit and empty local workload. An unavailable worker, incompatible version or changed configuration stops admission before the survivor is retired. The coordinator also checks that every previous Git commit is retrievable from the configured public repository.

The signed child reserves the original operation before secret preparation. The coordinator stages independent deployment and restoration grants with dAuth. Explicit rotation of the existing main tunnel uses the new credential at its connector paths for both outcomes. The receiver rechecks license ownership, paid placement and the canonical pointer before a conditional retirement, start or publication. The worker verifies the original instance again before retiring it. The old addresses receive no grant. Restarts reuse the signed reservation and receipts. A failed rollout stops the new attempt on both hosts before restoring each original Git pin and the approved command order.

ChainDist reloads confirmed relinks from its persisted event scan after startup and offers ordinary relinks to Deeploy one at a time. Ordinary relink requires an observation of the previous workload at every address that will receive a retirement command. An empty replacement machine cannot supply that evidence. If several addresses already changed and each workload reports only under its successor, the first ordinary relink is held because the retained address lacks an observation. Recoveries in this profile require a publicly verifiable GitHub source for each previous commit. Admission waits up to 12 seconds for worker observations before checking GitHub with bounded unauthenticated requests. A retry on the same coordinator for the same verified proposal can use a late report while its challenge is still valid. The coordinator requests fresh observations after expiry, a scope change, or restart.

If a repair expires before recording any retirement challenge, the coordinator revokes its staged grants and releases the original reservation. After a retirement command might have been sent, the coordinator retains the operation and its grants until it has exact stop evidence. An operator must resolve contradictory or missing evidence before work can resume. dAuth checks the current job and license registration on each repair revision grant read. An ordinary committed update replaces the repair grant with the normal revision format.

The repaired deployment or restoration completes after every worker reports ready. A failed repair rollout restores each worker's verified Git commit from its stop report. The coordinator checks those commits against the signed ready reports before finalizing. If placement or the reviewed source changes, the existing progress endpoint exposes a blocked reason. The hold remains in place until the coordinator can verify that proceeding is safe.

Publish the repair-capable Core package (candidate 7.7.362) before building the Edge image (candidate 2.10.744), which requires that Core version or later. Upgrade the serving dAuth instances, the original coordinator and both workers before enabling the frontend route. For the shared Deeploy API, upgrade every serving oracle to the repair relay and verify encrypted connectivity between them. A trusted HTTPS coordinator URL in `NEXT_PUBLIC_DEEPLOY_REPAIR_COORDINATORS` can also route requests directly. Keep the worker lifecycle journals and coordinator operation data across the upgrade. Verify a signed preview and worker reachability, then observe both app responses and the existing hostname through the rotated tunnel during the canary. Keep the recovery-capable coordinator and custodians available until the operation finishes.

## Single polling endpoint

Add `POST /get_deployment_status`, using the existing authenticated Deeploy request envelope conventions. POST keeps signed/scoped lookups consistent with the current API style. This replaces the earlier proposal for multiple GET endpoints.

The request accepts exactly one primary selector:

- `operation_id`: a specific operation, including a completed one.
- `job_id` with its existing deployment scope: current operation, or the latest completed operation when none is active.
- `request_id` with deployment scope and operation kind: recover an operation whose acceptance response was lost.

Optional parameters: bounded `events_limit` and `after_event_cursor`. Recent events, continuation cursor, and truncation indication are part of the same response. Existing job listing can discover jobs; this endpoint resolves their active/latest operation. Do not add a separate operation-list endpoint.

Authorize every read using existing job/escrow access rules and the durable operation identity. IDs are locators, not access tokens. Sanitize errors and events so configuration values, secrets, credentials, and raw tracebacks are not exposed.

A response must contain:

- Operation identity, kind, target/previous revisions, phase, outcome, and recovery state.
- Planned node and required-instance counts, ready counts, and per-node/per-plugin observations.
- Last known workload health separately from operation outcome.
- Observation timestamps, stale flags, source/authority version, and a suggested poll interval.
- Structured errors with code, safe message, scope, failed phase, retryability, attempt count, and next retry time where applicable.
- An ended blocked operation reports `phase: completed`, `outcome: failed`, `recovery: blocked`, and the non-retryable error `BLOCKED_OPERATION_ENDED`. `blocked_phase` identifies the expired retirement, failed-rollout stop, or restoration phase. `unconfirmed_nodes` lists every worker address whose stop or readiness made that phase incomplete.
- Cleanup/restoration state for each affected node; metadata state.
- Bounded recent events and continuation information.

During an update in `retiring_previous`, the coordinator returns a per-node `action` of
`awaiting_stop_report`, `stop_reported`, or `waiting_to_start`. A previous worker is marked `stop_reported`
when the responding oracle has its signed `stopped` report for the retirement attempt.
A replica missing that report returns `stop_report_unavailable`.
A desired-only worker owes no retirement report. These observations describe the operation.
Paid capacity comes from the job contract.

Illustrative result body during failure recovery:

```json
{
  "operation_id": "op_123",
  "job_id": 42,
  "kind": "update",
  "target_revision": 3,
  "previous_revision": 2,
  "phase": "stopping_failed_rollout",
  "outcome": null,
  "recovery": "in_progress",
  "ready_nodes": 2,
  "target_nodes": 3,
  "observation_stale": false,
  "poll_after_ms": 2000,
  "nodes": [
    {"node_id": "A", "ready": true, "observed_revision": 3, "workload_state": "ready", "action": "stop_requested"},
    {"node_id": "B", "ready": true, "observed_revision": 3, "workload_state": "ready", "action": "stop_requested"},
    {"node_id": "C", "ready": false, "observed_revision": null, "workload_state": "failed", "action": "abort_requested",
     "error": {"code": "IMAGE_PULL_DENIED", "message": "Registry authentication rejected", "retryable": false}}
  ],
  "events": [],
  "next_event_cursor": null
}
```

The example omits the instance detail and additional freshness fields for brevity; those are required by the implemented schema. The response should be a coherent aggregation with provenance, not an assertion that asynchronously observed nodes were sampled at one instant.

Each node's `ready` is true when it belongs to the placement for the displayed attempt, is online, and its signed report confirms readiness for every required instance. For each pinned runner, the report must also declare pinned mode and identify the configured Git commit or the registry digest in the configured image repository. `ready_nodes` counts the nodes whose `ready` flag is true. A node shown only for its prior placement has `ready: false`.

Polling reads local replicas without namespace repair and has no deployment side effects. Opening or closing the UI must not start, stop, or advance an operation. A local miss returns synchronizing/unavailable until the service can establish absence under the coordination contract. Return an explicit no-operation result for an authorized existing job with no tracked operation; do not manufacture migration history.

## Node reporting and readiness

Register operation and instance identity in Core's command/config admission path before plugin construction. The runtime then owns publication independently of the affected plugin's processing loop.

| Source | Status responsibilities |
| --- | --- |
| Command/config manager | Authenticated command acceptance/rejection; stale revision/fence rejection; persisted desired action. |
| BusinessManager and execution supervision | Missing plugin code, constructor/init exceptions, lifecycle transitions, execution errors, and stopped/removed confirmation. |
| Plugin through a local interface | Workload-specific preparation/progress, explicit failures, and application readiness. |
| Independent node reporter | Durable pending observations, bounded publication retries, replay after restart, and authorized routing. |
| Deeploy controller | Multi-node aggregation, deadlines, abort decisions, cleanup and restoration. |

Extend the existing readiness interface only as needed to carry phase/error information. Preserve semaphore semantics used by dependent plugins. A running plugin must not default to application-ready if the workload requires health checks; container and worker runners must report their actual readiness contract.

Use states such as `accepted`, `initializing`, `preparing`, `starting`, `ready`, `failed`, `stopping`, and `stopped`. Rich phases such as image pull or dependency wait may refine those states. Reporting continues through readiness changes and recovery; it is not a one-shot startup response.

Node reports must carry operation/revision/attempt/plugin identity and authenticated node provenance. A node may report only its own instances. Scope writes to the authorized operation; arbitrary plugin fields cannot impersonate another node or override controller recovery decisions.

A stuck plugin cannot be relied upon to call its own error hook. Runtime supervision detects what it can; lack of progress beyond a policy deadline is recorded as an unconfirmed/unresponsive instance, not a fabricated application error. A dead/disconnected node remains unknown until external observation or reconnection supplies evidence.

## Execution and recovery state machine

Keep execution phase, outcome, recovery state, and current workload health separate. This avoids a single overloaded `failed` field.

| Path | Required progression |
| --- | --- |
| Normal create/update | accepted → preparing → dispatching → waiting_for_readiness → finalizing → completed; outcome `succeeded`. |
| Kept create/update | Every planned instance is ready or kept. Commit the target revision and complete with outcome `waiting_for_source` and no recovery. |
| Terminal create failure | failure detected → aborting → stopping_failed_rollout → finalizing_cleanup → completed; outcome `failed`, recovery `completed`, workloads confirmed stopped. |
| Terminal update failure | failure detected → aborting → stopping_failed_rollout → restoring_previous → verifying_previous → finalizing_recovery → completed; outcome `failed`, recovery `completed`, previous configuration in effect. |
| Incomplete cleanup/restoration | While recovery is active, report `recovery=blocked` or `in_progress`. On expiry, stop sending workload commands and finish with `BLOCKED_OPERATION_ENDED`, preserving unresolved nodes. |

An operation can have an explicit failure reason while recovery is still active. Restoring the old revision does not turn the requested update into a success. A later runtime crash after an already completed successful operation changes current health; it does not rewrite historical rollout success or automatically trigger a new rollout policy.

### Failure detection and deadlines

Distinguish HTTP request timeout, node observation freshness, rollout readiness deadline, and recovery retry/deadline budgets. These are different controls.

- A transient failure may be retried within a bounded startup budget before declaring the attempt failed.
- A definitive failure of any required instance triggers abort immediately; do not wait for other nodes to time out.
- A source-following instance that reports a workload start, health, image pull or source-access failure stays deployed. At the deadline a reporting source-following instance can also be kept while it is starting. Use the stored plan to determine eligibility and require a matching mode from the node. Infrastructure and bound-instance failures abort the whole operation.
- If a required node never reports before the rollout deadline, abort with a reason such as `READINESS_DEADLINE_EXCEEDED`. This proves policy failure, not that the node never started.
- Once aborted, no further forward-deployment retries are allowed for that attempt. Recovery commands take precedence over delayed readiness success.
- After the ordinary phase deadline, allow 24 readiness timeouts for missing previous-retirement stops, failed-rollout stops, or restored readiness. This is six additional hours at the default timeout. During a blocked phase a coordinator resends the same command or snapshot at most every 600 seconds. A restart may resend once before the next interval. An ended automatic relink does not retry the same move. An already-authorized repair or replacement follows its own signed handoff and publication rules.
- Whole-job delete allows one additional hour after its retirement deadline, or 75 minutes from phase start at defaults. Admission returns `202`. A conflicting mutation to the same job returns `409` while the operation is active. Every planned worker must confirm shutdown for deletion to succeed. On failure the coordinator preserves the job metadata and published credentials, and names the workers whose shutdown remained unconfirmed.

Implemented defaults: preparation deadline 120 seconds; deployment/restoration readiness deadline 900 seconds (15 minutes; `DEPLOYMENT_READINESS_TIMEOUT`); worker wake-up 2 seconds using local operation/report replicas without namespace repair; CStore write timeout 5 seconds with one retry; nodes publish signed reports only on state change (15-second confirmation wait, retried until confirmed) and continue to report source-following status and version changes after readiness. The node replays its latest signed current field to an intended oracle that missed the observation or whose restart NetMon detected, preserving its sequence and timestamp. Bound instances stop reporting after confirmed readiness. Readiness pairs the latest ready report with NetMon command/control liveness instead of report age. Operation events retain 128 entries and each signed record uses eight sequence slots. Abort/history identities have no automatic expiry.

### Terminal create failure cleanup

1. Durably commit the abort decision and invalidate further start authority for the attempt.
2. Send idempotent, scoped stop/abort commands to every node to which work could have been dispatched, including those still starting or unreachable. Do not limit cleanup to nodes that acknowledged success.
3. A node records the abort before acknowledging it and prevents delayed/replayed start commands or its own restart policy from resurrecting the attempt.
4. Confirm the whole attempted pipeline is stopped, including dependencies and instances that never reported ready. Where needed, stop dependents before providers.
5. Preserve persistent application volumes/data. Release only operation-owned transient resources whose lifecycle is understood and whose cleanup is authorized.
6. After all possible running instances are accounted for, release unused configuration/secret references and finish cleanup. Retain audit and abort records under the retention policy.

Example: A/B ready, C fails. Stop A/B and abort C. On reconnect, C synchronizes operation authority before accepting new starts and enforces the abort. If it executed an earlier authorized start before receiving the abort, confirm that workload stopped as part of cleanup. If B cannot be reached, show `cleanup blocked on B`; keep B's needed secrets and continue reconciliation.

### Failed update restoration

Before dispatch, retain the previous successful revision, its exact materialized configurations, secret references, placement, and readiness criteria. Restore that snapshot rather than reconstructing it from partial live discovery.

1. Abort and fence the attempted revision everywhere it may have been applied.
2. Stop workloads from the failed rollout and prevent delayed forward commands. Nodes demonstrably still running the exact previous revision need not be restarted unnecessarily, but must be verified against the restoration plan.
3. Enforce a restoration safety barrier: where coexistence is unsafe, require positive stop evidence or proven workload-level fencing before starting restored instances, especially on another target. An unreachable old writer must block restoration unless fencing proves it cannot continue writing. Controller ownership fencing alone is not proof that an application process has stopped.
4. Restore the prior configuration and original placement; stop newly added targets that did not belong to that placement.
5. Use a new command/control generation for restoration even though the content is the previous revision. A stale-revision guard must not reject an authorized restore or allow delayed failed-update commands to overtake it.
6. Verify each restored instance is ready or qualifies to stay deployed waiting for its source. Restore canonical metadata to the previous revision even when its branch head or image tag has moved.
7. Mark the update failed and recovered only after restoration is confirmed. Show `Previous revision restored` in the UI.

If restoration itself fails or a node is unreachable, show `Update failed; restoration incomplete` with per-node details. Do not recursively roll back the rollback or release secrets needed by either version.

Restoring configuration is not undoing database migrations, external side effects, or changed application data. Freeze resolvable image digests/source identifiers and exact effective configuration where practical. If a managed operation cannot safely restore its previous behavior (for example irreversible credential/data changes), reject that operation before mutation or require an explicit separately agreed service procedure. Do not promise automatic restoration for an inherently irreversible action.

## Secrets and canonical metadata

The existing per-job mutable dAuth bundle is insufficient if both previous and attempted revisions may be active or restoring. Design revision-aware bundle lookup/binding across Deeploy, dAuth, and node materialization as part of this change; do not merely retain two R1FS CIDs while overwriting the only retrievable secret bundle.

- Keep secrets protected and bind each bundle to its configuration revision and authorization scope.
- Stage a new immutable revision without prematurely replacing the authoritative current revision or deleting the previous bundle.
- During a successful update, retain the previous version until the rollback obligation and active-use conditions permit cleanup.
- During active recovery, retain the credentials needed for cleanup or restoration.
- When a blocked ordinary operation ends, revoke its abandoned deploy revision. Preserve the previous and restore credentials that a workload can still need. An update whose failed targets have not all stopped ends without starting restoration.
- Cleanup must be retryable and reference-aware. A deadline alone never establishes that secrets are unused.
- Existing secret-path selection, redaction, owner checks, and reveal rules remain security requirements. No plaintext secrets in operation events, errors, polling responses, logs, or ordinary R1FS definitions.

Keep canonical metadata consistent with desired intent and observed execution. Never restore a registry pointer and label the workload restored without node evidence. Preserve a recovery journal if a multi-record commit is interrupted.

## Blockchain and payment integration

Reuse the paid job identity throughout submission, retry, cleanup, and restoration. A missing deploy response must never trigger another payment.

A deliberate create retry after the latest verified failed create has completed
cleanup uses the existing paid-job reuse validation, even when independent
monitoring already recorded that job as started. Owner and resource validation
still apply. Incomplete cleanup, unrelated jobs/owners, and newer successful
operations do not grant this reuse permission.

After a blocked create ends, the coordinator can still confirm cleanup once it has revoked the abandoned deploy revision and received signed stop evidence for the exact attempt from every planned worker. It checks its local reports once a minute and preserves the final failure and its original `unconfirmed_nodes`. Only the cleanup state changes, and the user can then submit a manual retry. Late reports never trigger more workload commands for an ended operation.

Deployment operations do not prepare, broadcast, reconcile, cancel or track blockchain transactions. Completion and subsequent operation admission depend only on the coordinator's runtime, metadata and recovery state. Polling does not expose settlement fields, and the UI does not show settlement indicators.

The existing ChainDistMonitor continues its independent pending-job confirmation, launch-recovery and closable-job handling. This lifecycle does not promise blockchain reconciliation for arbitrary changes to an already-active job's placement. Payment/ownership/resource validation at admission remains unchanged. Runtime cleanup never implies a refund or payment reversal.

## Frontend behavior

### Submission and recovery

- Persist a stable request ID and paid-job association before submission. Do not persist plaintext secrets merely to support polling.
- Show acceptance immediately and switch to operation tracking. Stop using `Promise.allSettled` submission results as final deployment outcomes.
- On a lost acceptance response, look up by request ID or resubmit the same signed semantic request/key. Do not generate a fresh request ID automatically.
- Reopen active/latest tracking by job ID after refresh, navigation, logout/login where authorized, or oracle change.
- A paid draft becomes a tracked deployment after acceptance. Keep enough identifiers to resume it; do not leave a second actionable create draft for the same accepted operation.
- The dashboard lists failed creates tracked by a paid draft in the browser. Show `Deployment failed · Paid` with cleanup progress and a link to the operation. A failed delete shows `Delete failed` and identifies every worker whose shutdown remained unconfirmed. A create retry requires confirmed cleanup, reopens the saved configuration, and signs a new create under the same paid job ID. A successful retry supersedes the failed draft on the dashboard.
- UI polling failures affect a connection/freshness indicator only. Keep the last observed result and avoid repeated failure toasts.

### Progress presentation

Render one operation panel in both the creation flow and the existing job view. Reuse existing design components and query/state patterns.

Each node row shows its alias/address, observed revision, current phase, last update, and safe error details. Expand into required plugin instances with their own progress. Show counts such as `2 of 3 nodes ready`; do not invent numeric percentages for phases with unknown work size.

Display recovery explicitly:

- `Deployment failed — stopping started nodes`.
- `Deployment failed — all attempted instances stopped`.
- `Update failed — restoring previous revision`.
- `Update failed — previous revision restored`.
- `Recovery incomplete — waiting for node B`.

Show recent timeline events in the same panel using the polling response. Keep detailed logs outside this scope unless already provided through an existing feature. Do not include blockchain transaction state in deployment progress.

Start with approximately two-second polling while active, configurable and jittered. Back off on transport errors and when the tab is hidden; fetch promptly on focus/reconnect. Share polling state so the modal, list, and detail view do not independently flood the API. Stop active operation polling only when execution and required recovery are complete; current-health monitoring remains a separate concern.

No new cancel/retry endpoints are required. A deliberate retry can use the existing create/update endpoint with a new request ID once recovery permits it. Existing stop/delete actions must be serialized with operation ownership and must not race restoration. If manual cancellation is exposed, route it through the existing mutation surface with a defined stop-versus-restore intent; do not add a speculative extra API.

## Release and compatibility boundary

This is one coordinated release across Core, Edge/Deeploy/dAuth, frontend, and affected direct clients/tutorials. Replace the old contracts directly. Delete obsolete pending-request/final-response assumptions when their replacement is integrated.

Do not add migration scripts, legacy operation converters, deployment-response fallbacks, dual publishers, or feature flags whose purpose is old/new API coexistence. The required existing-pipeline secret lookup is the explicit exception: it uses existing CID binding/runner authorization against local registry state and rejects locally observed versioned or deleted jobs. Internal schema identifiers for validation are allowed; they must not become a compatibility framework.

Existing running jobs can supply a canonical current configuration when accepting a new update; this is normal operation, not migration of historical operations. If a recoverable prior snapshot cannot be established, reject the update before dispatch. Jobs with no operation history show that fact through the same polling endpoint.

Test the coordinated release in an isolated environment. Verify that no old in-flight deployment is accepted across the cutover; an operational quiescence check is sufficient and does not require migration code. Live release execution and any destructive action need their own environment/target authorization.

## Implementation work packages

### Work package 1 Contracts and coordination proof

- Finalize record schemas, error vocabulary, endpoint payloads, identity scope, signed idempotency fields, and readiness criteria.
- Inspect Core CStore persistence/merge/replication and establish the coordination mechanism described above.
- Prove same-key retry reuse after replication, coordinator-only execution, local-replica reads, and crash recovery in focused tests; document the simultaneous cross-oracle admission limitation.
- Define timeout/retry/retention configuration and how unavailable coordination is surfaced.
- Map dAuth revision lookup and preserve existing paid-job validation.

Exit: written algorithm and tests demonstrate the required guarantees. Do not start by wrapping today's in-memory pending dictionary in a polling endpoint.

### Work package 2 Persistence and revision lifecycle

- Add operation/index/action storage using CStore and immutable payload persistence using R1FS.
- Add revision-aware secret binding and retain previous snapshots/placements.
- Implement commit/recovery markers, reference-aware cleanup, and abort retention.
- Recover from locally persisted operation state on startup and use pushed replicas for any-oracle lookup.

Exit: accepted intents, secret revisions, and aborted attempts survive process restart and push replication without ambiguous duplication or resurrection.

### Work package 3 Core node reporting and command lifecycle

- Register operation metadata before plugin load and connect command/config and BusinessManager failures to typed observations.
- Add independent publication and restart replay; connect plugin progress/readiness/errors through a small local contract.
- Add scoped idempotent start/stop/restore commands, control generations, and abort enforcement.
- Update container, worker, native, and managed-service runners involved in Deeploy to supply correct readiness/error evidence.
- Preserve semaphore and unrelated plugin behavior; separate deployment transport from readiness consumers.

Exit: missing code, constructor failure, startup error, stalled execution, stop confirmation, and replay are observable without relying on successful plugin processing.

### Work package 4 Controller and recovery

- Execute committed plans independently of API requests and UI polling.
- Interpret typed node observations, enforce all-target readiness, and record side effects before/reconcile after dispatch.
- Implement failed-create cleanup and failed-update restoration exactly as specified.
- Coordinate stop/delete/scale with known active operations; prevent obsolete commands within an operation. Do not add cross-oracle consensus.
- Replace timeout-triggered metadata rollback with evidence-based lifecycle finalization.

Exit: three-node success/failure/deadline scenarios converge to all-ready, deployed and waiting for source, confirmed stopped, confirmed restored, or a stated unresolved recovery.

### Work package 5 API and direct clients

- Replace create/update responses with durable acceptance and add only `POST /get_deployment_status`.
- Apply existing ownership checks to submission, polling, and operation discovery selectors.
- Update signatures, types, direct HTTP clients, examples, and actual Deeploy SDK callers; do not alter unrelated SDK pipeline APIs merely because they share method names.
- Remove legacy `success`/`command_delivered` submission assumptions and obsolete postponed tracking paths.

Exit: submitting through oracle A and polling through B/C works across acceptance-response loss and oracle restart.

### Work package 6 Deeploy UI

- Refactor submission/payment handoff and shared operation queries.
- Add reusable node/instance progress, timeline, recovery, and freshness presentation.
- Recover by job/request ID, prevent duplicate submissions, and wire deliberate retry eligibility.
- Verify desktop/mobile, long error text, empty/loading/stale/error states, modal dismissal/reopen, and reconnect behavior.

Exit: the user can follow the same operation through refresh and oracle changes, including all automatic recovery steps.

### Work package 7 Integration and release readiness

- Run deterministic Core/Edge/frontend checks and multi-node fault-injection tests.
- Exercise CStore/R1FS/dAuth failures and blockchain uncertainty with controlled stubs/test environments.
- Check no compatibility/migration/opt-in paths beyond decision 14, or additional public endpoints, were introduced.
- Record operational limits, retention settings, unresolved recovery procedures, coordinated release steps, and test evidence.

Exit: all acceptance criteria below pass or the feature remains incomplete. An API/UI demo alone is insufficient.

## Acceptance and failure matrix

| Scenario | Required result |
| --- | --- |
| Three nodes become ready | One operation succeeds after all required instances are ready; metadata is committed. |
| Acceptance response lost | Same request ID returns the same operation through another oracle; no duplicate payment or workload. |
| Crash before admission commit | No workload dispatch; same-key retry safely completes or rejects admission. |
| Crash after commit or mid-dispatch | Recover exact plan/actions; reconcile and resume without duplicate effects. |
| Same key submitted after replication to another oracle | Existing operation reused, original coordinator retained. Simultaneous unseen admissions are outside the no-lock guarantee. |
| Two updates conflict with known active state | Reject the conflicting request. Simultaneous admissions before replication have no global exclusion guarantee. |
| Polling oracle restarted or never saw the original write | Use local persisted/pushed replicas; report synchronizing/unavailable for missing operation state without request-time or background namespace repair. |
| Coordinator unavailable | Other oracles continue replicated polling with freshness information; no takeover or new executor for that operation. |
| Stale peer snapshot and reordered observations | No status regression or resurrection; authority/sequence rules decide applicability. |
| Plugin cannot load or initialize | Explicit instance failure before the deployment deadline; recovery begins. |
| Two nodes ready and the third cannot pull its image | A following container stays deployed and the operation completes with `waiting_for_source`. A bound container failure stops the rollout on all targets. |
| Third node never responds | Deadline aborts the attempt; missing node remains unresolved until it acknowledges abort/stop. |
| Start delivered before abort while a node is disconnected | Distinguish requested versus enforced abort; any late execution is stopped/fenced and remains unresolved until confirmed. |
| Delayed startup after node has enforced abort | Node rejects it; late ready report cannot revive the operation. |
| Duplicate stop/restore commands or lost acknowledgments | Safe repeated reconciliation with scoped, idempotent effects. |
| Terminal update failure on one node | Stop the failed revision and restore the previous configuration on its original placement. |
| Prior revision restoration fails | A kept source failure completes recovery with the previous revision in effect. An infrastructure or bound-workload failure keeps recovery pending with its secrets and reason. |
| Unreachable failed-revision writer during restoration | No unsafe overlapping restored writer; wait for confirmed stop or proven workload-level fencing. |
| Node disappears during cleanup | Recovery not marked complete; no speculative secret deletion. |
| Attempted and previous revisions need different secrets | Both remain retrievable under correct authorization until confirmed retirement. |
| CStore publish or R1FS retrieval fails | Retry/availability state exposed; no fabricated readiness or destructive cleanup. |
| Runtime ready but blockchain result unknown | Report coordinator completion immediately; transactions do not participate in deployment status or mutation gates. |
| Frontend refresh/reconnect/oracle switch | Same operation resumes, including cleanup/restoration; transport failure is not deployment failure. |
| Unauthorized operation/node record access | Denied; no secret or cross-owner observation disclosure or forged status acceptance. |
| Stop/delete/scale during update recovery | Defined serialization/conflict; no race that resurrects deleted work or drops required secret revisions. |
| Persistent volumes and irreversible service actions | No implicit data deletion; unsupported automatic-restoration paths rejected before mutation. |

Use existing repository test conventions. Edge's current suite is documented as `PYTHONPATH=../naeural_core:../ratio1_sdk python -m unittest discover -s extensions/business/deeploy/tests -p 'test_*.py'`; confirm the supported Python/container environment before running. Add focused Core tests near the existing response/lifecycle tests. Frontend has script-based tests, `npm run lint`, and `npm run build`; select relevant scripts after implementation. UI work requires actual flow checks and saved desktop/mobile screenshots under the repository's existing preview/test conventions.

This matrix defines required behavior. Concrete executed checks and remaining environment limits are recorded below; it does not imply a live multi-node rollout was performed.

## Resume instructions and implementation status

Completed in this planning task:

- [x] Inspect existing create/update, timeout, metadata/secret handling, node publication, and frontend submission behavior.
- [x] Confirm CStore/R1FS persistence and any-oracle polling requirements.
- [x] Confirm exactly one new polling API; no migration work or compatibility beyond decision 14.
- [x] Confirm failed-create cleanup and failed-update restoration policy with the user.
- [x] Save this durable specification and implementation sequence.

Implementation and final review are recorded in the checkpoints below. Live deployment and remote changes are outside this task.

To resume after compaction:

1. Read this file first; preserve the confirmed product decisions, particularly automatic recovery and the narrow existing-pipeline secret exception in decision 14.
2. Read applicable `AGENTS.md` files in each independent repository and inspect branches/dirty state before edits. Preserve unrelated work.
3. Resume from the implementation checkpoints and PRs, not from work package 1. Preserve receiving-oracle coordination without distributed locking/consensus.
4. Recheck the source map against current code; use exact function behavior over stale prose.
5. Keep this document updated with completed work packages, chosen persistence/reporting settings, exact tests and results, affected commits, remaining blockers, and the next concrete step. Do not mark a package complete on code shape alone.
6. Follow the user's delegation rule for substantial frontend implementation: Claude owns the agreed UI file scope while Codex remains responsible for architecture, integration, and verification. Documentation-only planning does not require UI delegation.
7. Do not create compatibility shims beyond decision 14, a second polling/event endpoint, or a new external storage dependency. Use the terminal and kept failure rules in the state machine above.

## Implementation checkpoints

2026-10-14 implementation:

- Branch `codex/deeploy-deployment-lifecycle` in four isolated worktrees under `/Users/alessandro/programmazione/ratio1/.worktrees/deeploy-lifecycle/`. Edge base `origin/develop` `4b24efcc`, Core base `origin/main` `b19f2e2`, frontend base `origin/develop` `f6d18a84`, SDK base `origin/main` `3c7570b` (SDK has no develop branch).
- Core now owns durable node lifecycle journals, signed per-node observations, explicit plugin failures, scoped start/retire/stop commands, abort tombstones, and verified external-workload cleanup. A local lifecycle lock prevents stop acknowledgment racing plugin construction.
- CStore persists atomically with fsync before acknowledging. Replication requires distinct authenticated remote peers; default threshold is a strict majority of remote eligible peers, explicit `MIN_CONFIRMATIONS` overrides it. Self is excluded and zero remote peers fails closed. Identical-value retries recollect confirmation. This is durability acknowledgment, not distributed consensus or admission locking.
- Operations and node observations use eight sequence slots per identity; signed writer/field bindings and monotonic slot merge reject stale or forged snapshots. Operation events are bounded to 128. Abort journals and operation identities are retained; automatic history expiry is not implemented, because deleting abort history could permit replay.
- Redacted exact execution plans are stored in R1FS. Local plan persistence/pinning and durable coordinator volume are required; independent remote pinning and coordinator failover are not promised.
- Edge `deployment_operations.py` owns admission, worker replay, readiness, stop barriers, restoration, canonical commit, secret revocation, and the single owner-authorized polling projection. HTTP400 validation and HTTP503 uncertain admission are separate from HTTP202 acceptance.
- Admission writes a durable `preparing` intent before any revision secret copies. Complete staged data can resume after restart only before its 120-second preparation deadline. Once expiry is observed, the coordinator persists `cleaning_up_preparation`, outcome `failed`, recovery `in_progress`, and `ADMISSION_PREPARATION_FAILED` before plan reads or dAuth cleanup. A bounded RPC already in flight may delay observing expiry; successful late preparation/status replies cannot accept the rollout. Cleanup retries across restarts without dispatching workloads or changing the current revision. Only confirmed secret revocation/erasure permits `completed` with recovery `completed`; other mutations remain blocked until then. A local per-operation marker keeps the worker from advancing live admission; completed handoffs are cleared before loading fresh snapshots. Other jobs continue without a global admission lock (decision 15).
- dAuth stores immutable per-revision secrets with exact authorized node/instance configurations. Revocation is a separate durable marker followed by plaintext erasure. Previous secrets remain available until stop/restoration evidence allows retirement. Non-dAuth coordinators prepare and publish revisions through the SDK reconciliation API. dAuth retains all prior and merged bundles; coordinators load only redacted plans and sign public pointers. Polling from any oracle remains supported.
- Container readiness reports actual health and build/pull failures. Cleanup verifies Docker absence and preserves volumes. Managed CockroachDB additionally verifies planned certificate fingerprints and authenticated verify-full SQL before readiness. Its isolated real-binary old/new/old certificate recovery test passed with data preservation; see the linked recovery document for the exact offline command and limitations.
- Canonical pointers and current dAuth bundles carry signed monotonic storage generations. A restored runtime retains its previous content revision while its metadata commit advances the storage generation; later creates/updates/deletes advance beyond it. Delete tombstones reject stale repair, and explicit higher generations permit paid job reuse. Every new attempt also advances beyond all verified observed attempts for the job, including failed preparation/create attempts, so clock skew cannot hide a retry in job-only polling. The receiving oracle also coordinates existing CSP owner transfer through the revision lifecycle; rollback preserves the newly authorized owner.
- A generic worker or container app follows its branch or image tag unless its instance has `PINNED_VERSION: true`. A pinned worker takes `VCS_DATA.COMMIT` (40 lowercase hex digits). A pinned container takes `IMAGE_DIGEST` (a registry digest beginning with `sha256:` and 64 lowercase hex digits). Both fields name content in the configured repository. The worker's base image follows its own pull policy. Catalogue services keep their existing runtime bindings.
- A bound container restores its recorded image by local ID or exact saved registry digest. The same digest can have different local IDs across Docker image stores. The configured tag can recover the binding when it resolves to the recorded ID.
- Deployment transaction tracking and consensus gates were removed per the completion clarification. Existing blockchain monitor and SDK transaction submission behavior remain unchanged; no deployment nonce reservation, cancellation or prepared-transaction API is introduced.
- Frontend implementation initially delegated to Claude; Codex completed final retry work after the specialist session limit. Persisted request identity, uncertain acceptance lookup, refresh/account/oracle-scoped polling, node/instance/recovery progress, and create/update/delete integration are implemented. Scale-up uses the update lifecycle. Unknown update acceptance blocks new payments/allocations; an exact signed resend is held in memory only. Missing replica state or elapsed time cannot authorize discarding an unresolved submission. Escrow node count is refreshed before another node-extension payment. These safeguards do not provide cross-tab or cross-oracle consensus.
- Offline verification: Container Apps 484 tests passed; Worker 17 passed; dAuth/reveal 63 passed; SDK direct-client 6 and secret-client 19 passed; transaction-specific additions and their tests were removed. Core focused lifecycle/CStore/secrets checks after transaction removal: 95 passed (lifecycle module now 45 tests). HSync 9 passed. Before removal, Core broad discovery ran 467 tests with eight errors and one skip; an isolated base-HEAD run (415 tests) reproduced the identical eight errors and skip. Failures: five node-oracle fixtures missing `evm_network`, one shutdown fixture missing `config_data`, absent structured training pipeline module, and Torch stub missing `dtype`. These remain outside this change. Final full Deeploy suite after transaction decoupling: 371 tests passed, including retry-generation ordering under clock skew.
- Runtime image: `local_edge_node_dauth471_core219_arm64:1599b7e`, Python3.10.12, network disabled, worktrees mounted read-only. Host supported Python: `/Users/alessandro/.pyenv/versions/3.10.18/bin/python`. No live deployments or production changes performed.

Final integration evidence:

- Real SDK signing passes Edge signature/nonce/escrow validation offline; direct-client tutorials use the new asynchronous contract.
- A three-node Core journal/Edge coordinator regression covers partial startup, stop barriers, restart replay, and restoration.
- Actual Edge canonical commit/delete methods passed Core CStore validators for restoration generation 9, deletion 10, reuse 11, and rejection of stale generation 9.
- CStore acknowledgment/replacement concurrency regressions pass; a superseded write cannot borrow an older value's acknowledgments.
- Container process-loop regression fails before and passes after removal of unconditional readiness publication.
- Frontend: all 48 script suites, TypeScript, ESLint and production build pass. Deterministic preview checks cover 24 states on desktop/mobile (48 screenshots) plus uncertain update on both (50 total). Actual wallet/chain payment and production network flows were not executed.
- Real CockroachDB binary verification is isolated, network-disabled and preserves seeded data through old/new/old certificate activation. Full multi-node R1DB/Cloudflare deployment is not claimed.

Release requires all four repositories together and persistent coordinator/node journal volumes. Do not downgrade one component to the old protocol while operations are active. For release rollback, stop new admissions, resolve or explicitly reconcile active operations, retain journals and revision secrets, and deploy a coordinated compatible revision; reverting code is not a database/application-data rollback. No production rollout has been performed.

## Review handoff

Implementation and offline verification are complete; all four PRs are open and must be released together:

- [edge_node](https://github.com/Ratio1/edge_node/pull/533)
- [naeural_core](https://github.com/Ratio1/naeural_core/pull/226)
- [ratio1_sdk](https://github.com/Ratio1/ratio1_sdk/pull/184)
- [deeploy-dapp](https://github.com/Ratio1/deeploy-dapp/pull/170)

Implementation commits: Edge `f2ddd91`, Core `4f56e71`, SDK `9b47c02`, dApp `59de055`. No live deployment was performed. Follow-up implementation should start by reading this document and inspecting the current PR heads, preserving the confirmed decisions and verification limits above.

2026-10-14 completion update: removed deployment transaction tracking, prepared-transaction APIs, nonce reservations, settlement polling fields/UI and transaction-based admission gates. Coordinator completion alone is final. Latest checks: Deeploy 371, ChainDistMonitor 12, Core focused 95, SDK async/secrets 25 and baseline EVM 11 passed; frontend lifecycle/UI scripts, TypeScript, ESLint, production build, and desktop/mobile completion preview passed. The earlier broad Core and 48-suite frontend runs above describe the initial implementation; final focused checks cover this removal.

### Fresh whole-stack critic review — 2026-10-15

A new read-only critic reviewed Edge PR #533, Core #226, SDK #184, and dApp #170,
including admission, replication, recovery, secrets, certificate restoration,
client retries, and UI finality. Three confirmed issues were fixed:

- Telegram now defers readiness until background polling starts and reports
  startup failures through safe node lifecycle errors. Shutdown wakes its event
  loop thread-safely; a subsequent review caught and fixed concurrent loop closure
  so cleanup still joins the bot thread without hiding unrelated errors.
- Core journals resolved workload classification and interpreter identity before
  plugin construction. Known native workloads can complete an aborted stop after
  their owning process exits. Unknown/external workloads and same-process failures
  still need cleanup evidence. Retirement preserves this private evidence.
- A deliberate retry after the latest verified failed create completes cleanup
  reuses its paid job even if independent monitoring recorded a start timestamp.
  The existing payment, owner, resource, and active-operation checks still apply.

All three original regressions were reproduced against the pre-review production
code and pass with the fixes. Two follow-up critic passes reviewed the fixes and
the loop-close race; the final pass found no remaining P1/P2 issue. No findings
were rejected and no new product decision was needed.

Verification on Python 3.10 in the network-disabled runtime container, with the
three sibling source repositories mounted:

- PASS: `python -m unittest discover -s extensions/business/deeploy/tests -p 'test_*.py'`
  — 376 tests, including four Telegram lifecycle tests and paid-retry admission cases.
- PASS: `python -m unittest test_deployment_lifecycle test_chain_store_hsync test_runtime_secret_resolution test_deeploy_chainstore_response_mixin`
  — 99 tests with Core's test directory on `PYTHONPATH`; lifecycle module 49 tests.
- PASS: changed-file compilation, diff checks, and independent critic reruns of
  Core lifecycle and Telegram tests. SDK/dApp sources were unchanged in this review;
  dApp PR lint/build checks were green.
- FAIL (unchanged baseline): Core broad discovery ran 467 tests with the same eight
  errors and one skip documented above. No additional failure appeared.
- BLOCKED / not performed: live multi-node, wallet, broker, and production service
  validation. Offline evidence does not establish those live-system outcomes.

Local review evidence: `/tmp/deeploy-review-before-regressions.log`,
`/tmp/deeploy-fresh-review-edge-final.log`, `/tmp/deeploy-fresh-review-core-final.log`,
and `/tmp/deeploy-fresh-review-core-broad.log`. These temporary logs are not required
to resume implementation; the regression tests and contract notes are committed.

### Existing pipelines after restart — 2026-10-15

Implemented decision 14 across Edge dAuth, Core runtime secret resolution, and
the SDK. An existing persisted pipeline with no secret revision sends a signed
unversioned request. dAuth reads local registries and requires an
unversioned current CID, matching job identity, current runner placement, and a
CID-bound secret bundle. It rejects locally observed deleted/versioned records and generation
changes. Existing pre-CID bundles retain their structural binding procedure.
No secrets or revision fields are written into the persisted node configuration.

Worker secret requests do not synchronize namespaces, including for warm revision
caches. Missing local records fail without peer repair; remote revocation markers
take effect after reaching the local replica. Existing dAuth maintenance refreshes
current and revision secret namespaces, not all deployment metadata. Lifecycle
actions through `reconcile_job_secrets` also use local persisted/pushed replicas
without namespace repair, including preparation status and cleanup. Local
revocation markers and newer signed operation snapshots remain enforced, but
remote changes take effect only after reaching the receiving custodian. Requests
do not prove globally fresh state; missing required local records fail or report
incomplete preparation. Plan validation, durable publication, write peer
acknowledgments, and confirmed cleanup requirements remain in place.

Tracked pipelines with a missing secret revision fail closed locally. Explicit
revision requests retain signature, nonce, oracle, job, revision, and authorized
runner checks and never retry through the unversioned path. The first update of
an existing pipeline snapshots its old secrets into an immutable `:restore`
revision, so failed-update restoration remains possible.

Verification used the network-disabled
`local_edge_node_dauth471_core219_arm64:1599b7e` runtime (Python 3.10.12), with
Edge/Core/SDK source mounts:

- PASS: Edge Deeploy discovery — 376 tests.
- PASS: `python -m unittest extensions.business.dauth.test_unversioned_secret_resolution extensions.business.dauth.test_dauth_registry_gating extensions.business.dauth.test_dauth_secret_routing`
  — 64 tests. The ten new cross-stack cases exercise two cold secret-cache
  restarts from persisted redacted JSON through the real Core resolver, SDK
  request path, and dAuth handler; first-update restoration; and authorization,
  stale-pointer, deletion, and downgrade rejection. Crypto/network dependencies
  are controlled test doubles. Run this integration suite separately from the
  Deeploy suite, whose lightweight dependency mocks cannot load the full node.
- PASS: Core lifecycle, HSync, runtime secrets, and response tests — 100 tests.
- PASS: SDK async client and job-secret tests — 28 tests; compilation and diff
  checks pass across changed Python files.
- FAIL (unchanged baseline): Core broad discovery — 468 tests, the same eight
  errors and one skip as the isolated baseline; failure details remain above.
- PASS: an independent read-only critic reviewed the cross-repository exception
  and reran restart/auth tests, finding no confirmed P1/P2 issue. No findings
  required fixes. The additional first-update restoration case also passes.

Live multi-node restart/rollback and production release were not performed.
Update the existing Edge #533, Core #226, and SDK #184 PRs together; the frontend
requires no change for this exception. Preserve unrelated local readiness-timeout
edits separately from this change.

### Remove global admission serialization — 2026-10-15

Implemented decision 15 in Edge only. Removed the mutation decorator and all
global admission-lock scopes from create/update, scale/delete, commands, escrow
reconciliation, and the coordinator worker. HTTP request execution and response
shapes remain unchanged; this does not introduce parallel HTTP preparation.

Live admission registers an operation marker before publishing `preparing` and
marks it finished in `finally`. The worker skips marked operations, clears
finished handoffs before reading fresh snapshots, and resumes interrupted
preparation after failure or restart. This prevents competing state writes and
premature secret cleanup without holding up unrelated jobs. The shared plan
cache uses a short bookkeeping lock and retains a local plan reference across
eviction; R1FS downloads remain outside the lock.

Verification: all 380 Edge Deeploy tests passed in the network-disabled Python
3.10 runtime. New regressions cover progress for another job during preparation,
admission finishing during a stale record read, failed-publication/admission
handoff cleanup, and overlapping plan downloads with bounded eviction. The
independent read-only critic reran all 26 admission/operation tests and found no
remaining P1/P2 issue after reviewing both handoff and cache correctness.
No live deployment was performed. This change updates Edge PR #533; other
components require no changes. Preserve the separate local 900-second timeout
edit outside this commit.

### dAuth reconciliation after the non-dAuth update fix (2026-10-20)

The lifecycle uses `BCWrapper.reconcile_dauth_job_secrets` and the SDK-owned
signed HTTP transport for `prepare`, `status`, `commit`, `revoke`, and `delete`.
The signed operation, action, network, job, owner, exact node/instance plan and
plan CID bind each request. Preparation persists immutable target and restoration
secret records only on dAuth, after the existing durable `preparing` operation.
It leaves current metadata and the prior R1FS CID available to existing workers.
Fresh request values are extracted before public plan persistence; neither
prior nor merged bundles enter the coordinator's memory. Scale-up aliases and
per-node placeholder validation are reconciled inside dAuth.

After interrupted admission, `status` confirms and replicates existing copies
before the preparation deadline; it never generates replacement credentials.
Expired preparation enters the durable cleanup phase before contacting dAuth,
then revokes only that operation's staged copies. dAuth permits only `revoke`
in this phase, requires expiry and no active attempt, and rejects stale
preparation snapshots when a newer signed operation is known. Failed or
uncertain cleanup remains nonterminal and is retried rather than reported as
complete. The UI distinguishes this failure from runtime rollback: an update's
previous revision is unchanged, not restored.
Runtime readiness/stop evidence, the coordinator journal and rollback decisions
remain the lifecycle's responsibility. Owner-transfer restoration retains the
new owner. No second journal or cross-oracle arbitration is introduced.

Finalization supplies a coordinator-signed canonical pointer. dAuth validates
its generation and exact plan CID, publishes its signed current secret bundle
and the original public pointer, then cleans up the prior CID. Repeating the
same finalization repairs uncertain writes. Only lifecycle-authorized cleanup
revokes unused revisions; deletion waits for all scoped stop reports. Core
accepts a registered dAuth signature on the current bundle while still requiring
a coordinator signature on public pointers. Equal-generation retries ignore
signature metadata only; altered semantic contents and revoked revisions fail
closed. These changes require SDK 3.5.59 and Core 7.7.334 (7.7.333 was released separately before this stack). Edge ships as 2.10.511.

The original lifecycle release shipped SDK, Core, then Edge together with the lifecycle dApp. Retain the
existing journal/secret storage and coordinated rollback requirements above.
This integration was checked offline with physically separated public/protected
stores, the real SDK client and Core wrapper; no live node or wallet was changed.

### Stateless replacement without earlier stop confirmation

An authorized editor signs a read-only `get_job_repair_preview` request with
`job_id`, `nonce`, `network`, and `replace_stateless: true`. The receiver
requires its network in the signed payload before looking up placement. The response binds the
published CID, app ID and revision, previous addresses, paid slot count, and
coordinator. A blocked relink keeps its original coordinator. Otherwise the
registered EVM oracle roster and job ID select the coordinator before resolving
its internal address. An unavailable mapping blocks review until it is
available. Current worker sightings are returned separately in
`observed_previous_nodes` and stay outside the signed proposal.

The signed `repair_update_pipeline` request includes the ordinary complete
update, an explicit target for every paid slot, and
`repair: {replace_stateless: true, accept_unconfirmed_stop: true, proposal}`.
Normal payment, resource, and target checks apply. The escrow owner or an
active delegate with the editor's job-edit permission can sign. Every target
needs a distinct active license at admission. The coordinator binds the exact
licensed address, license ID and license owner, and rechecks the placement
before dispatch and publication. dAuth independently verifies the license
and current paid execution term before releasing replacement credentials. It
verifies the full placement before publication. Preview and admission require a
paid execution epoch. Extensions take effect at the next credential request.
After the revision is published, buying additional slots preserves the exact
licensed recipients of its grant. dAuth verifies the current signed publication
before granting this exception. Staged grants and new placements still require
the reviewed paid count.
Existing app and component IDs are preserved. If the saved per-slot component
IDs differ, replacement preview refuses the plan until there is an explicit
mapping for those identities.
The path supports ordinary native plugins and app runners. Local mounts,
runtime commands, synchronization, and managed services make a job ineligible.
Deeploy uses the normal readiness and shutdown behavior of each component. The
signer attests that the app can run while a previous copy may still be active.

Admission stages only the replacement revision and reserves any blocked
retirement. It sends versioned replacement commands without waiting for old
nodes or using historical license relink records. Only successful readiness
publishes the new runtime placement. Dispatch intent is persisted before each
first start. If the replacement fails before any dispatch intent, only its
grants are revoked and the original relink can resume. A completed cutover or a
failed rollout with a recorded dispatch supersedes the relink and revokes its
prepared grants. Failure requires cleanup only on workers that might have
received the replacement and keeps the previous saved pointer. Status carries
forward `unconfirmed_previous_nodes` and clears a reused address after
successful takeover. This operation updates the Deeploy runtime
placement. On-chain node allocation and rewards follow the existing contract.
The coordinator uploads the redacted R1FS metadata before persisting the signed
publication pointer and sending it to dAuth. A retry uses that exact pointer.
When readiness or placement can no longer be verified after a possible custody
send, a finalizing `status` request can finish the same publication only if
dAuth finds its signed bundle or signed pointer for that exact revision.
Missing or inconclusive evidence leaves the operation blocked.
When the first `commit` opts in with `report_prewrite_refusal: true`, dAuth
can return the signed `publication_refused_before_write: true` with the exact
CID if a successful chain read establishes that the paid term, paid slot count
or verified license binding no longer matches before any write. Only a
confirmed response to that first send allows the coordinator to clean up the
failed rollout. A failed chain read or lost reply leaves the saved intent
ambiguous. ChainDist can close an expired job independently.

If a replica cannot confirm routing for a signed retry, it returns retryable
`503 ADMISSION_UNAVAILABLE`. Keep the original request ID and payload until
the coordinator resolves it. An authoritative refusal of a stale replacement
proposal returns `409 REPLACEMENT_REVIEW_STALE`. The coordinator persists the
refusal to its data volume under the same admission lock and replicates it
through CStore. A delayed exact request cannot be admitted, including after a
restart before the local CStore flush. Its `non_admission` contains the network, decimal-string job ID,
coordinator, request ID, wallet payload hash and a signature. The signature
is EIP-191 over `Ratio1 Deeploy replacement refusal v1\n` followed by the
compact JSON array of those five fields in that order. The browser verifies
the recovered public key against the reviewed coordinator address.

After a reload, the editor sends the optional `replacement_coordinator`
selector alongside `job_id`, `request_id` and `kind: "update"` to
`get_deployment_status`. The authenticated escrow owner's refused request can
return `non_admission` with status `synchronizing` for compatibility. When
the serving oracle lacks the outcome, it can relay the authenticated lookup
to the reviewed coordinator over the existing encrypted relay. The receiver
authenticates the wallet again. A timed-out lookup stays inconclusive.
An exact resend also retries replication of the original signed record. The
browser only retains the non-secret request identity, verifies the same proof
and uses a new request ID for the fresh review.

Publish Core 7.7.363 before building Edge. Upgrade the target workers, the
serving oracles, and dAuth before enabling the updated editor. Stateless
operations use versioned phases so earlier coordinators and custodians cannot
interpret a persisted replacement as an ordinary update.
