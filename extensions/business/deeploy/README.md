# Selected Environment Secrets

`create_pipeline` and `update_pipeline` accept an optional top-level `secret_paths`
list. Selectors address the signed request's flat `plugins` array, before runtime
signature grouping:

```json
{
  "secret_paths": [
    ["plugins", 0, "ENV", "API_KEY"],
    ["plugins", 0, "DYNAMIC_ENV", "DATABASE_URL"],
    ["plugins", 0, "PER_NODE_CONFIG", "byNode", "0xai_address", "ENV", "KEY"],
    ["plugins", 0, "PER_NODE_CONFIG", "byIndex", "0", "ENV", "KEY"]
  ]
}
```

Every selected variable must exist. Plugin indexes are non-negative JSON integers;
`byIndex` map keys are canonical non-negative decimal strings. Per-node `default`
selectors are also supported. Arbitrary config paths, runtime `PLUGINS/INSTANCES`
paths, individual dynamic parts, malformed selections, and client-supplied
`SECRET_PATHS` metadata are rejected before staging or dispatch. A builder may use
transient metadata internally, but must strip it from the final request.

ENV selections protect scalar values, including empty strings. A DYNAMIC_ENV
selection addresses the whole variable and protects every static part's string
`value`, including empty strings. Dynamic `type`, `path`, and other runtime
references remain visible. No objects or lists are stored as secret values.
Existing mandatory secret paths remain protected regardless of this list.

The backend compiles selectors to server-owned per-instance `SECRET_PATHS`, such
as `["ENV", "API_KEY"]` and `["DYNAMIC_ENV", "DATABASE_URL"]`. Per-node selectors
retain their relative `PER_NODE_CONFIG` prefix in canonical pipeline metadata.
The metadata and ordered dynamic paths survive R1FS persistence, recovery,
replacement updates, and scale-up. Node materialization projects selectors to
the effective variables using the same default/index/node precedence as values.
dAuth retains its existing scalar same-path bundle format; no Core protocol change
is required.

## Updates and Hidden Values

- Omitted `secret_paths` preserves existing valid selection metadata for retained
  variables, including accepted legacy per-node aliases. It is not a request to
  publish secrets. Full-request responses preserve the submitted alias spelling.
- An explicit list replaces conditional selections. `[]` removes all conditional
  selections only when retained hidden variables have replacement plaintext.
  Removing a variable entirely is allowed.
- An unchanged placeholder reuses the same relative path owned by the same plugin
  signature and instance ID, even when plugin or instance arrays are reordered.
  Missing prior values fail closed before deployment changes.
- Dynamic placeholder reuse additionally requires the entire expression's
  structure, order, types, sources, and runtime references to match. After any
  structural/reference edit, submit fresh values for all static parts. A swap of
  structurally identical placeholder-only parts is not observable without stable
  part IDs; clients must enforce replacement values for such edits as well.
- Logs mask all ENV and DYNAMIC_ENV values, even for invalid requests and innocuous
  variable names. Successful full-request responses redact only effective selected
  and mandatory secret values.

## Updates Through Non-dAuth Protocol Oracles

`update_pipeline` and `scale_up_job_workers` keep the receiving Deeploy protocol
oracle as coordinator. It sends the unchanged wallet request and its prepared per-node configs to
dAuth's signed `POST /stage_job_update` endpoint. Existing hidden values are
reconstructed only on dAuth; the coordinator receives redacted configs and a
signed receipt, never the previous plaintext bundle or rollback material.
Newly supplied values necessarily arrive in the original wallet request.

This follows the existing signed `add_secrets` trust boundary: the prepared
plan is the responsibility of a trusted protocol oracle. dAuth independently
checks the node signature, current protocol-oracle membership, a transport
nonce no older than 120 seconds, the original Deeploy wallet signature and
nonce policy, active escrow, the operation's permission (bit 1 for configuration
updates, bit 4 / `EXTEND_NODES` for scale-up), persisted app/owner,
on-chain job owner, previous CID, and the plan's deployment identity/targets.
It does not independently regenerate the coordinator's transformed plan.
Neither operation requires view-secrets permission (bit 16). Arbitrary workers
cannot use this endpoint as coordinators.

The `stage`, `commit`, and `rollback` actions share this endpoint. Stage returns
`pipeline_configs` and a `receipt` identifying the coordinator, operation, job,
app, owner, previous/staged CIDs, plan digest and phase. Settlement submits that
receipt in a fresh node-signed body. The allowlisted `request_type` is
`update pipeline` or `scale up workers`, including the wallet wrapper's request
type. Operation IDs bind the coordinator, request type and exact signed wallet
request; changing the prepared envelope under the same operation is rejected.
Endpoint failures intentionally omit exception details
because planning and transport errors can contain credentials.

dAuth retains immutable `DAUTH_JOB_SECRET_GENERATIONS` entries keyed by
`job_id:pipeline_cid`, and a private `DAUTH_JOB_UPDATES` operation journal. Both
replicate exclusively to registered dAuth peers, like `DAUTH_JOB_SECRETS`.
Readers select the generation matching `DEEPLOY_DEPLOYED_JOBS`, with legacy
fallback for jobs not yet versioned. The legacy per-job bundle is maintained
for compatibility. Earlier bundles and their R1FS payloads are retained for
rollback; there is no automatic pruning protocol.

Bookkeeping-only persistence drops `INITIATOR_ADDR`, `INITIATOR_ID`,
`MODIFIED_BY_ADDR`, `MODIFIED_BY_ID`, and `VALIDATED`, in addition to existing
transient fields. Equal canonical configs keep their existing CID. A changed
config containing hidden values, or replacing one that does, must use staging;
the metadata writer refuses to publish a new unbound generation.

### Scale-up Plans

Scale-up stages canonical configs for both new nodes and existing online nodes
before sending new pipelines or instance updates. Every config retains the same
ordered full target list: the previous fleet (including offline nodes), followed
by the additions. Both deferred and immediate on-chain confirmation preserve
that full fleet; multiple plugin responses do not change its node count.

The node-signed envelope includes `new_nodes` and `identity_aliases` triples
`[signature, destination_instance_id, source_instance_id]`. Aliases bind generated
and existing worker identities to unique persisted source instances; several
worker destinations may share one source. Duplicate destinations, unknown or
ambiguous sources, missing destinations, and cross-signature mappings are
rejected. Source lookup follows identity before resolving relative secret paths,
including reordered instances, selected dynamic expressions and per-node values.
All affected configs must resolve to the same complete scalar secret bundle. The request
hash binds aliases and additions; the signed receipt includes request type and
the full target list. Existing signed scale-up requests that omit `app_id` derive
it from the authenticated persisted job; a supplied mismatching ID is rejected.

### Failure and Recovery Contract

The client retries one transport failure with the same prepared envelope and a
fresh transport nonce. Stage resumes an interrupted journaled operation, and
commit/rollback are idempotent, including after a terminal journal write fails.
An old staged operation cannot be replayed once another CID is published.
No worker is dispatched until a valid dAuth receipt is received. Once any
dispatch was attempted, failure retains the staged generation because workers
may already be using it. Inspect those workers before deciding on recovery.

Automatic retry is limited to the exact prepared envelope within that RPC.
A top-level API retry or coordinator restart can generate different timestamps,
credentials or response keys, and is deliberately rejected for the same signed
wallet request. To recover, inspect the published CID, target workers and the
private operation journal on dAuth. If the original prepared envelope/receipt
is available, retry stage/settlement with fresh node transport authentication.
Otherwise, reconcile the running workers and submit a newly signed wallet
update with a fresh nonce; do not infer that a timeout rolled the operation back.
Rollback is appropriate only before dispatch, or after separately ensuring no
worker can use the staged configuration.

Scale-up marks dispatch before each new-node send and existing-worker instance
update. Exceptions, failed responses and pending timeouts retain the generation
and report `dispatch_uncertain` once delivery may have occurred. A failure before
dispatch can roll back safely through the same dAuth settlement flow.

ChainStore has no compare-and-swap or distributed lock. Generation checks avoid
known stale settlements but do not serialize concurrent writers across separate
oracles. Serialize updates and scale-up per job operationally. Autonomous
replication flows are separate from these signed wallet operations and retain
their existing secret-custody requirements.

### Rollout and Rollback

Release the SDK providing `BaseBlockEngine.request_dauth_job_update()`
(`ratio1>=3.5.58`) before building these Edge images. The SDK owns signing,
HTTP retry, and authenticated dAuth response validation; Edge validates the
deployment receipt and plan and coordinates dispatch and settlement.

Deploy the new dAuth endpoint and generation-aware readers to **all dAuth
servers first**, then update Deeploy coordinators. Mixed old dAuth servers fail
closed; there is no fallback that reveals secrets to a non-dAuth coordinator.
Existing wallet request formats and scalar secret paths remain compatible;
no Core runtime change is required.

For rollback, pause updates and drain/reconcile staged operations first. Retain
generation records, journals, legacy bundles and their R1FS payloads. Restore an
older coordinator only where the legacy bundle matches the published CID and
the coordinator has the required dAuth data. Rolling back binaries alone cannot
reconcile an uncertain dispatch or concurrent update.

## Verification

Run the modern suite with the supported Python environment and local Core/SDK:

```sh
PYTHONPATH=../naeural_core:../ratio1_sdk python -m unittest discover -s extensions/business/deeploy/tests -p 'test_*.py'
```

Rollout keeps compatibility with old clients that omit selectors. Do not roll back
to a backend without selection-aware handling while selected-secret jobs are
being updated; retain canonical metadata and dAuth bundles together.

## Uncertain Create Outcomes

For a new `create_pipeline` request, `dispatch_uncertain: true` on a `fail` or
`timeout` response means a node may already have received the configuration.
The job's CID and dAuth bundle remain available so a late worker can resolve
secrets. This is not a cancellation, and the node may still start even though
the request failed. The field is omitted for ordinary failures and successful
responses. It is additive to the existing response shape.

While a job ID has stored pipeline metadata, another `create_pipeline` request
for that ID fails before staging or dispatch. Retrying would replace the only
CID-bound bundle while workers from the first attempt may still run. Inspect
the target nodes and resolve the old attempt before creating a new job; do not
assume that a timeout or a stop command proves all nodes have stopped. There is
no automatic expiry or safe cleanup protocol for this retained bundle yet.
Overlapping creates handled by one manager process are also rejected, but
ChainStore has no atomic cross-manager claim; independent managers must not
accept concurrent creates for the same job ID until a distributed claim or
generation-aware protocol exists.
