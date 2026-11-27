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
- An unchanged placeholder reuses only the same path owned by the same instance.
  Missing prior values fail closed before deployment changes.
- Dynamic placeholder reuse additionally requires the entire expression's
  structure, order, types, sources, and runtime references to match. After any
  structural/reference edit, submit fresh values for all static parts. A swap of
  structurally identical placeholder-only parts is not observable without stable
  part IDs; clients must enforce replacement values for such edits as well.
- Logs mask all ENV and DYNAMIC_ENV values, even for invalid requests and innocuous
  variable names. Successful full-request responses redact only effective selected
  and mandatory secret values.

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

## Reconciliation through dAuth

Updates and scale-up call the SDK's `reconcile_dauth_job_secrets` client. A registered
dAuth server authenticates the protocol oracle, checks the expected pipeline CID,
reuses the existing secret-selection and merge rules, and stores the complete
bundle bound to the redacted pipeline CID. The response contains redacted configs
and their CID; the coordinator does not fetch the previous or merged bundle.
The existing `DAUTH_JOB_SECRETS` and pipeline registry formats remain in use.

Reconciliation publishes before worker dispatch. Deployment failure does not
restore the previous metadata or secrets in this path; deployment restoration is
left to the lifecycle flow. The SDK does not retry a transport failure because the
write may already have succeeded. Inspect the current metadata and workers before
retrying an uncertain request. This change does not introduce distributed locking
or revision history, or fix pre-existing metadata-only CID drift.

Release SDK 3.5.58 and Core 7.7.332 (the plugin blockchain wrapper forwarders),
then deploy the dAuth endpoint before using this update path on coordinators.
An SDK upgrade alone does not expose the client through older Core wrappers.
dAuth performs the existing best-effort cleanup of the previous local R1FS
pipeline object after publishing reconciliation. No deployment restoration is
added. New job creation keeps its existing staging flow.

## Local Replica Reads

Worker secret requests read local CStore metadata and bundles without synchronizing
namespaces over the network. Signature, nonce, job identity, runner placement,
revision, and locally observed revocation checks still apply. A missing local
record cannot be fetched during the request, and a remote revocation is enforced
only after it reaches the local replica. Existing dAuth maintenance still refreshes
current and revision secret namespaces; it does not refresh every deployment
metadata namespace.

Deployment admission, polling, and the coordinator worker also use local persisted
or pushed operation snapshots and node reports. They do not run namespace repair.
An oracle missing an operation returns the existing synchronizing response; a
missed terminal node report is not automatically pulled later.

Lifecycle actions through `reconcile_job_secrets` also read local replicas without
namespace repair, including preparation status and cleanup. Revocation markers and
newer operation snapshots are enforced once they reach the receiving custodian;
the request does not establish globally fresh state. Required local records that
are missing still fail or report incomplete preparation. Plan validation, durable
publication, and peer acknowledgments for writes remain in place; cleanup stays
pending until its writes are confirmed.

The first update of an existing pipeline does not require a current dAuth bundle
when its published configuration contains no secret placeholders. dAuth extracts
the available values into a temporary bundle and stages immutable target and
restoration revisions through the normal custody path. Existing bundles still
require the exact current CID and unversioned state; missing bundles needed to
resolve placeholders remain an error.

### Optional shared delegate aliases

Delegate aliases are optional CSP metadata. Existing delegates require no migration;
addresses and on-chain permission masks remain authoritative. Deploy the backend
before enabling the dApp alias editor. No contract upgrade or blockchain write is
needed to rename a delegate.

Both endpoints are `POST` and use the normal signed Deeploy envelope:
`{"request": {"nonce": "0x...", "EE_ETH_SENDER": "0x...", "EE_ETH_SIGN": "0x...", ...}}`.
The signature covers the complete payload. Existing nonce validation and active
escrow authentication apply. For v3 signatures, the request types are
`get delegate aliases` and `set delegate alias` respectively.

- `/get_delegate_aliases`: add `delegate_addresses`, a list of at most 10 Ethereum
  addresses. An authenticated CSP owner or active delegate can read. Success
  returns `result: {status: "success", aliases: {"0x<lowercase address>": "CI bot"}}`
  in the usual server response envelope. Missing, cleared, owner, unrelated, and
  revoked delegate entries are omitted; an empty request list returns `{}`.
  Corrupt stored labels are skipped without hiding valid entries, with one bounded
  warning per request containing only the count (never the untrusted label).
- `/set_delegate_alias`: add `delegate_address` and string `alias`. Only the
  authenticated escrow owner may write, and the target must currently be an active
  delegate of that escrow. Success returns
  `result: {status: "success", delegate_address: "0x<lowercase address>", alias: "CI bot"}`.
  Leading/trailing whitespace is trimmed; blank clears the alias. Labels have a
  maximum of 80 Unicode code points. Unicode control/format/private-use/unassigned
  characters and surrogates are rejected. Null/missing alias does not mean clear.
- Failures use the existing `result: {status: "fail", error: "..."}` envelope.
  Clients must check `status`, keep addresses usable when metadata reads fail, and
  not report a successful rename when CStore rejects a write.

Each read accepts at most 10 addresses, validates the whole list before per-target
work, and checks membership only for valid, nonempty stored labels. This bounds
one request to 10 target membership RPCs plus the existing signer-authentication
RPC. Missing, cleared, or corrupt labels require no target membership RPC. Clients
with longer lists must request sequential batches; loading all labeled addresses
can still require N target RPCs in total. No membership cache is introduced.

CStore hash `deeploy_delegate_aliases_v1` uses one key per
`<server EVM network>:<lowercase escrow>:<lowercase delegate>`. This avoids overwriting
other addresses during concurrent edits and preserves aliases when the CSP owner
changes. Clearing writes an empty-string tombstone. Removing a delegate on-chain
hides its alias; re-adding the same address to the same escrow restores its old
label. Moving the address to another escrow never carries its old label across.

The feature inherits CStore persistence and replication semantics; a successful
write is not a guarantee of immediate visibility on every oracle. Concurrent edits
to the same address use CStore's existing conflict resolution. This patch does not
change CStore retention or provide archival guarantees.

Aliases deliberately use the same mutable CStore trust model as Preferred Nodes.
CStore `readonly=True` restricts subsequent changes to the **writing node identity**,
not the CSP wallet that signed the API request. Enabling it would prevent another
Deeploy oracle from servicing that CSP's rename or clear. Owner authorization is
therefore enforced at the signed API boundary; this feature does not claim that
CStore independently enforces CSP wallet permissions against trusted node writers.

Focused Docker verification (Python 3.11 with `eth-account` installed):

```bash
docker run --rm --entrypoint python -v "$PWD:/app" -w /app \
  r1-key-rotation-review:20261112 \
  -m unittest extensions.business.deeploy.tests.test_delegate_aliases -v
```

The companion `tests/delegate_aliases_harness.py` exposes HTTP on container port
5000 for isolated browser integration tests. It executes the production endpoint,
request-verification, and nonce-validation method bodies with real EIP-191 signature
recovery. Blockchain membership, CStore, web-server startup, and response signing
are fixtures. Its synthetic keys must never be used for live systems. Fixture
storage is a JSON file (`ALIAS_TEST_STORE`, default `/tmp/delegate-aliases.json`),
allowing independent browser sessions to share metadata. This proves the API/UI
boundary, not live-chain or multi-oracle replication behavior.

### Native per-container limits

The signed create and update endpoints accept CPU and memory in each Native
CAR/WAR plugin's `CONTAINER_RESOURCES`. The purchased worker tier continues to
set the price. On create each container's positive finite CPU and RAM caps
must fit that worker. Two containers may each inherit the entire tier. Native
in-process plugins share the worker. Docker applies CPU and memory limits.

Optional `CONTAINER_RESOURCES.storage` sets a Volume Storage budget that
includes the container's fixed-size volumes. An omitted Native budget accounts
for the existing fixed-volume reservations. Explicit zero is valid with no
reservations. The storage allocation does not resize existing volume files.
