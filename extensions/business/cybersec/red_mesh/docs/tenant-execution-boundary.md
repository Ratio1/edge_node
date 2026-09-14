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

## Current-reader and artifact construction seams (I1a.1–I1a.3b.1)

`TenantReadAccess` resolves the current stored reader before tenant/job access. Historical reads do
not reuse the launch actor, launch capability or current compute assignment as reader authority.
It captures list membership before processing and returns the exact detached job whose namespace,
tenant binding and storage key were validated. Foreign/unattributed jobs are absent; recognizable
local corruption and surfaced storage failures are unavailable. This is not an atomic CStore snapshot.

The optional internal `checked_job`/`checked_jobs` query inputs consume that operation's checked
snapshots. Explicit invalid inputs never select the separate legacy path. Scoped progress reads
assigned worker keys, validates job/worker identity, and uses existing pass/revision reconciliation.
Scoped triage reads only archive-owned finding state; it does not return finding audit history under
`reports:view`. No global/orphan/local-status fallback is used by these scoped projections.

`TenantJobArtifacts` validates raw archive job/config binding before serializers or descendant reads.
Only explicit pass/aggregate/worker references authorize ordinary reports; archive/config CIDs,
raw evidence, secrets, authorization documents and export/rulebook references are not generic report
downloads. Identity-less scan passes/aggregates inherit their validated parent association. Graybox
fields remain intact; ordinary model-worker payloads retain the existing producer-sanitized format.
Analysis is inline associated-pass content, never an arbitrary or pruned CID recovery path.

Per-operation limits are 128 distinct JSON fetches and 10,000 typed reference occurrences, including
empty typed collection entries. Compatible references share cached validated data; incompatible kinds
or identities fail unavailable. Limits do not truncate into partial success and are not storage-byte
or launch-admission limits. Finding-state reads have a separate 10,000-entry bound. All these bounds
fail as sanitized unavailable errors. Snapshots and artifact helpers are not reusable authorization
leases or new encryption boundaries.

`LegacyReadAccess` admits only a fresh active stored account with the membership key absent and
matching current configured/stored compatibility-disabled rollout. An explicit empty/malformed
membership key is not legacy; audit additionally requires the stored legacy-admin membership.
It captures and detaches unbound rows before production normalization with `migrate=False`, preserving
raw listing aliases while point lookups use logical job IDs only. Duplicate logical IDs and collisions
with recognizable bound/present-null identities fail unavailable. Every present binding is excluded,
including one appearing during copying. This is not an atomic shared-store snapshot or a job-count cap.

The explicit internal `snapshot_mode="legacy_unbound"` consumes these checked snapshots without
fabricated bindings. Unknown modes, missing legacy inputs and present bindings fail before fallback.
Default bound validation is unchanged; omitted default helper inputs retain old unchecked behavior
only until endpoint migration. Legacy archives may contain partial unbound configs, but typed job/report
association still applies. Model worker identity comes from captured workers or the finalized stub's
selected execution node, never the launcher or serving node. This mode is not a client request field.

The ten ordinary native reads now use these checked seams: status, data, archive, triage, progress,
network/local lists, report, audit and analysis. All are POST with a fresh `request_actor` and optional
explicit `tenant_id`; report additionally requires `job_id`. Omitted scope can enter only proven
legacy admission. Report replies wrap the unchanged associated payload in `{job_id,cid,report}` with
the checked execution binding for bound jobs. Associated report and ancestor fetches remain unpinned.
Audit requires separate `audit:view` authority and filters detached entries by permitted job identity
before counting or limiting. Checked absence is 404; broken references/storage are sanitized 503.

The generated HTTP guard rejects malformed/ambiguous body fields, explicit null, query fields and
non-POST methods before IPC. Protected responses are JSON and `no-store`, including errors and native
RAW/WRAPPED responses; startup rejects incompatible route/model/guard installation. The native core
and the two existing model-token dependencies are unchanged. Historical actorless GET collectors are
incompatible and must not be used as a reason to restore an unchecked fallback.

The two list responses use the native supported `on_response` hook plus HTTP-edge restoration so
legal job aliases such as `error` or `status_code` cannot become native error metadata. The private
versioned capsule is transport-only, never a reserved job alias or a new public response shape.
Successful list HTTP replies require a valid capsule before any headers/body are published. RAW lists
return only the checked mapping (including `{}` when empty); WRAPPED lists retain native metadata
outside their restored `result`. Genuine denials remain errors, and missing/malformed capsules fail503.

The deferred correlation-status read is now also a checked POST, with `job_id` and `request_actor`
only. It admits current proven legacy readers, rejects tenant selectors and membership-bearing
accounts, and projects a detached summary without provider, artifact or write effects. Missing jobs
return typed 404; malformed or foreign summaries return 503; model jobs return the allowlisted
`unsupported_job_type` 400 in both RAW and WRAPPED formats. Null summaries remain valid empty status.
This does not change the correlation mutation or activate tenant integrations.

MISP, STIX, OpenCTI and TAXII export-status reads also use requester-only checked legacy POSTs.
They project detached persisted metadata, never build/export/push/publish or fetch the referenced
artifacts. Missing/null/empty metadata is valid nonexported status; other malformed metadata,
foreign job identity or response-control fields fail 503 before projection. MISP preserves its
five-field projection; the other readers preserve nonreserved metadata. Matching embedded job IDs
remain valid. OpenCTI/TAXII dry-run metadata remains visible with `exported:false`; exported becomes
true only for `pushed`/`published` respectively. Model jobs retain typed400 in RAW and WRAPPED.
Their mutation, dry-run, configuration and tenant activation paths are unchanged. Twenty-eight native
endpoints still require admission/shaping work, including `get_misp_export_config_status` and
`llm_health`. The former returns deployment configuration; the latter calls provider health and can
return its host/port/raw response. Neither is an exempt harmless metadata endpoint. Earlier planning
counts of31 deferred endpoints omitted those two: five checked status reads leave28 from33.

Rulebook assessment status and review now use checked legacy POSTs with `job_id`, optional
`profile_id` and server requester; tenant selectors are not accepted. Omitted/empty profile selects
the server's canonical default; explicit wire null remains400. The checked job and exact-key
review/submission/audit records are copied and associated before model coercion. Missing assessment
or review remains a valid empty state, while corrupt/foreign rows fail503. Historical profile versions,
failed attempts, pending submissions and revision-zero legacy reviews remain readable.
Raw audit publication requires explicit state and object-valued answers; it cannot reuse permissive
model-input defaults without normalization. Checked review inputs keep their separate model defaults.

Staleness uses only checked archive/pass-parent traversal when submission references require it;
no global job reread, aggregate/config/worker hydration, assessment/submission CID fetch, generation,
write or provider call occurs. No completed pass means unknown latest-pass information; broken
referenced artifacts fail503. Invalid profile/model produce400; unfinished review409; unsupported
submission contract is a successful assessment marker but a typed review503. These exact errors are
preserved in RAW/WRAPPED without exposing source details. Rulebook mutations are unchanged.
This two-read slice passed paired cumulative spec, quality and security review, leaving26 native
endpoints still requiring admission. Explicit metadata/history `last_error:null` fails unavailable before publication;
absent metadata errors and genuinely nullable pending/submission errors remain supported.
All six tenant/binding key aliases are rejected recursively. Optional error classification and audit
timestamps are validated, as are JSON numbers that would overflow the finite client number range.
Full backend4,270 tests/2,310subtests pass; evidence belongs to the hub rulebook-read plan.

MISP configuration status is verified as an actor-only POST after paired spec/quality/security review. It
requires a current stored legacy account with proven absent membership metadata and matching
configured/stored compatibility controls. Membership-bearing callers and restrictive rollout deny
before configuration access. No job lookup, enumeration, export or provider call is authorized.
The existing producer must return exactly four fields: literal enabled/auto_export/misp_configured
booleans and a known uppercase severity. Extra fields, including credential-bearing additions, fail
unavailable before transport wrapping. Independent flags and INFO remain valid; errors are static,
all responses no-store, old GET denied. This leaves25 native endpoints requiring admission.
Full backend4,530 tests/2,310subtests PASS. This does not make integrations tenant-configurable.

Public `llm_health` is now deny-only POST with an optional `request_actor` object. Every accepted
body returns static `503 unavailable`; malformed bodies/query fields return400 and old GET405,
all no-store. It performs no endpoint/domain diagnostic, configuration, identity, rollout, job,
provider or audit operation. Existing native framing and sanitized status logging remain; internal
health helpers and the separate LLM-agent API health endpoint are unchanged. No Navigator consumer
exists. Diagnostic access requires a future approved permission and safe projection, not an ordinary
read grant. This containment leaves24 native endpoints requiring admission; it is not a working
health feature or permission to activate workspace entry.

Public `update_finding_triage` is also deliberately unavailable. It is actor-only POST returning a
fresh static `503 unavailable` for every accepted body, without resolving identity or touching jobs,
archives, triage state, submission locks, audit or SOC delivery. Old GET returns405; old mutation
fields (job/finding/status/note/actor/review date), selectors and malformed bodies return400. All
responses are JSON/no-store. This withdraws the old mutation input contract, not just its UI button.
Checked `get_job_triage` reads and internal service persistence/submission fences remain unchanged.
Hub task RM-076 owns the future tenant-workspace UI and its prior role, audit-return and SOC-effect
decisions; no legacy-role exception or UI activation is authorized here. With two explicitly contained
surfaces and18 checked reads,23 native endpoints still require admission work.

This is **local wiring, not completed application isolation**. Navigator ordinary-read pairing
I1a.3b.2 is committed; these five status reads require matching Navigator changes. Unmatched
versions fail denied/unavailable, never fall back to actorless GET. I1a.3c remains incomplete. Dormant
unchecked service helpers are not authorized public read paths. I2 still owns browser-wide
provider/cache isolation. Public workspace entry remains closed, and passing local tests does not
authorize activation or deployment.

## Local checks

From the edge-node checkout, use its existing `.venv/bin/python -m pytest` with
`extensions/business/cybersec/red_mesh/tests/test_tenant_execution*.py`, then the full RedMesh test
directory. Tests use real serializers, production finalizers and the actual native renderer/IPC;
external effects use deterministic fixture transports. Exact commands, results and independent
review evidence are recorded in the hub plan/task, separately from operational verification.
