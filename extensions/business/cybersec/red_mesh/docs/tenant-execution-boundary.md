# Tenant execution boundary (RM-026 B2)

Status: locally validated B2 implementation; not a tenant-serving activation guide. The complete
programme, phase gates and operational authority live in the RedMesh hub's
`docs/_plans/2026-09-11-rm-026-complete-execution.md` and RM-026 task. Existing job/read/export APIs
are not made tenant-safe merely by this launch boundary; I1 and later gates remain required.

Review checkpoint (2026-09-11): owner-approved corrections resolve cached-archive identity, strict
counter and commit-own-read findings at both production finalizers. Focused archive/model checks pass
128 tests/267 subtests; full RedMesh regression passes 2,819 tests/1,730 subtests with three existing
skips/four warnings. The separate native semaphore contract passes four tests. Three cross-assigned
reviewers pass their non-authored B2 scopes in resumed round 2. This remains disabled implementation
work, not tenant-serving activation evidence.

## Admission and compatibility

The four launch endpoints and model-provider preflight append `tenant_id`, `asset_id` and
`expected_target_digest`, preserving existing positional arguments. All three selectors are required
together for tenant execution. A saved target is derived server-side; repeated matching target
values are accepted, different protected values are denied. A changed target digest returns 409.
Model preflight now also accepts the trusted forwarded actor. Only the two original model endpoints
retain their existing token requirement; no new shared token or wallet proof is introduced.

Each admission resolves one fresh stored account. Tenant publication, launch role, Allow Pentester,
active asset and configured-peer/active-assignment intersection are checked before target or storage
effects. The binding freezes original actor/incarnation, target/digest, failure policy and **actual**
assigned worker order. Model jobs have one selected worker, not all candidate peers. Bound launch
responses contain only their own job/config and never enumerate `other_jobs`.

Source controls default to `TENANT_EXECUTION_ENABLED=False` and
`TENANT_EXECUTION_STAGE="compatibility"`. The configured namespace and instance must also have
explicit typed `execution_rollout` state in the existing administration store. Runtime never creates
that state or treats missing/unavailable controls as permission. Tenant administration enablement is
not execution enablement. M supplies setup/drain/cutover tools; do not manually activate this slice.

Compatibility admission requires matching flag-false compatibility controls, all selectors omitted,
and proof that the stored membership key is absent. Explicit empty membership, malformed metadata
and unknown provenance are not legacy. A configured restrictive stage cannot be lowered by a stale
stored stage; tenant-stage flag-off never falls back to legacy. Draining blocks new admission and
new passes while current authorized work can settle. Stored JSON `execution_binding: null` is invalid;
the optional typed Python field's `None` means that serialization omits the field entirely.

## Execution and external effects

Workers check current authorization/assignment and config/record binding agreement before secret
reads and launch. Bound workers carry the captured `(job_id, job_pass, worker_addr,
assignment_revision)` through those gates; stale passes/reassignments and missing identities deny
before secret lookup, worker start or provider construction. Model config must name that exact job,
even if another job has an identical binding. Real network and graybox thread entry recheck the captured
identity, so scheduling a worker is not permission to execute after reassignment. The effective
network/web destination is checked before worker construction; model secrets cannot replace the
protected endpoint, adapter or model. Graybox
requests, redirects, authentication and cleanup retain the bound origin/path prefix, including the
final prepared request and Host authority at transport dispatch. Foreign or ambiguous Host headers
cannot redirect a bound URL to a different virtual host. Budget exemption is not scope exemption.

Reannouncement/new-pass boundaries recheck permission. Automatic analysis checks current owner,
binding, pass and job revision at admission, provider calls/retries and completion. Authorization
loss suppresses external provider/event/attestation effects. Local completed-report collection,
aggregation and deterministic rulebook derivation remain separate finalization duties so partial
results can be preserved. Manual analysis of bound jobs stays unavailable until I1 adds independent
requester admission and completion authorization; original launch attribution cannot substitute.

Config, running record, archives and finalized stubs retain the original immutable binding. Missing
or changed current binding/owner and config-redaction binding loss cannot silently produce an archive.
Bound finalizers recheck their observed owner/pass/revision/config snapshot after slow reads and before
archive/raw writes and stub publication. A rejected commit is not success. Bound network cleanup runs
only after confirming its own committed archive and stops on an observed ownership change; legacy
cleanup ordering remains unchanged. These checks do not supply atomic storage transactions or leases.
Bound archive entry, including cached-CID shortcuts, requires requested/supplied/stored job IDs to
match. Present `job_pass` is an exact integer >= 1 and `job_revision` an exact integer >= 0 on both
records; booleans, floats, strings and null are invalid. Finalized stubs legitimately omit these
counters. Same-job cached reuse validates identity without requiring old live counters to equal the
pruned stub; in-progress snapshot checks still compare the raw values without injecting defaults.
The bound stub writer requires the captured archive snapshot and compares it against its own fresh
current read before terminal shortcuts or revision normalization. A later-observed ID, counter, owner,
binding or config/archive-CID change denies publication and cleanup. An archive already written before
that change may remain orphaned; this is not an atomic transaction or a guarantee against a later race.
Fresh reauthorization returns current facts, never a replacement binding or newly saved failure policy.

This is not C/D: launcher heartbeats, HARD-stop semantics, automatic takeover, recovery HSync barriers,
worker rejoin and schedule-gap handling remain separate approved phases. There is no distributed
lease or compare-and-swap guarantee here; shared discovery alone does not authorize execution.

## Actual HTTP runtime guard

The public asset initializer uses the native `basic_server` renderer and adds a fixed guard import
and call to generated `main.py`. It removes only the previous generated `main.py` first, so a skipped
render cannot reuse old output. Unsupported template/communication-argument overrides and failures
inside the initializer set the existing failed state and block native setup/start. Native failures
before entering this override remain outside that containment boundary.

The guard runs in the actual HTTP interpreter at module import, including `-O` and lifespan-off.
It checks all five unique POST routes, endpoint/model/body binding identities, real Pydantic-2
declarations and omission-vs-null/string behavior. Malformed selectors never cross positional IPC.
Unverifiable assembly makes the entire generated HTTP app unavailable, not merely its launch routes.
Supervisor survival is not HTTP health. No core/template fork or added dependency is involved.

## Local checks

From the edge-node checkout, use its existing `.venv/bin/python -m pytest` with
`extensions/business/cybersec/red_mesh/tests/test_tenant_execution*.py`, then the full RedMesh test
directory. Tests use real serializers, production finalizers and the actual native renderer/IPC;
external effects use deterministic fixture transports. Exact commands, results and independent
review evidence are recorded in the hub plan/task, separately from operational verification.
