# RedMesh Resume and Checkpoint Boundary

This document records the Phase 6 checkpoint boundary without implementing resumable execution yet.

## Safe to Resume

- Archive read queries can be retried because they are immutable reads.
- Archive verification after write can be retried because it does not mutate job state.
- LLM analysis calls can be retried because the pass report is updated only after a successful response.
- Attestation submission can be retried before the attestation result is persisted into job state.

## Restart From Scratch

- Active worker execution inside a pass must restart from the beginning of the pass.
- Graybox authenticated probe execution must restart from a fresh authentication flow.
- Partial pass aggregation must restart from collected worker reports rather than replaying mid-pass state.

## Checkpoint Candidates

- Immutable `job_config_cid`
- Completed `pass_reports`
- Finalized `job_cid`
- Mutable `job_revision`
- Triage state and triage audit

## Explicit Non-Goals

- No mid-pass resume token
- No worker-side checkpoint serialization
- No replay of partially completed graybox sessions

## Design Rule

RedMesh may resume only from durable, integrity-checked boundaries that are already represented as immutable artifacts or explicit mutable orchestration records. Any state that depends on live sockets, authenticated sessions, or partial aggregation must restart.
