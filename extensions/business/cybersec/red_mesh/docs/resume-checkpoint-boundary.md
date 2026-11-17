# RedMesh Resume and Checkpoint Boundary

This document records the Phase 6 checkpoint boundary. Resumable execution stays out of scope, except the node-local network worker checkpoints described below (RM-201).

## Safe to Resume

- Archive read queries can be retried because they are immutable reads.
- Archive verification after write can be retried because it does not mutate job state.
- LLM analysis calls can be retried because the pass report is updated only after a successful response.
- Attestation submission can be retried before the attestation result is persisted into job state.

## Restart From Scratch

- Active graybox worker execution inside a pass must restart from the beginning of the pass (RM-202 covers graybox resume).
- Graybox authenticated probe execution must restart from a fresh authentication flow.
- Partial pass aggregation must restart from collected worker reports rather than replaying mid-pass state.

## Checkpoint Candidates

- Immutable `job_config_cid`
- Completed `pass_reports`
- Finalized `job_cid`
- Mutable `job_revision`
- Triage state and triage audit

## Network Worker Local Checkpoints (RM-201)

A network (blackbox) worker may resume execution inside a pass from a checkpoint on its own node's disk.

- Files are plain pickle under `plugin_data/redmesh_ckpt/<job_id>/<pass_nr>_<local_id_prefix>.pkl`,
  written only through `diskapi_save_pickle_to_data` (atomic) by `services/checkpoint.py`.
- Resume granularity: per port, and per completed service or web method. A method cut off by the
  restart may run again.
- Validity rules (applied on load, Phase 3). A file is used only when all hold: `version` equals the
  current version; `job_id`, `pass_nr`, `ee_addr`, `scan_type`, `config_cid`, `target_ports` and the
  port range match the current assignment; the file is younger than `MAX_AGE`; the worker is not
  `finished` in CStore; the job is not terminal. A file that fails a rule is deleted.
- Coverage is all-or-nothing: the union of the restored `initial_ports` must equal the worker's
  slice, otherwise the whole pass checkpoint is discarded and the pass restarts.
- Cleanup: on startup, every `WORKER_CHECKPOINT.GC_INTERVAL`, and when a job ends. Files older than
  `MAX_AGE` are dropped.
- Graybox workers still restart from the beginning of the pass.
- The checkpoint is local to the node. It is not a CStore or R1FS record.

## Explicit Non-Goals

- No mid-pass resume token in CStore or R1FS
- No replay of partially completed graybox sessions (graybox workers still restart; RM-202)

## Design Rule

RedMesh may resume only from durable, integrity-checked boundaries that are already represented as immutable artifacts or explicit mutable orchestration records. Any state that depends on live sockets, authenticated sessions, or partial aggregation must restart. The one exception is the node-local network worker checkpoint (RM-201), which is validated on load and never leaves the node.
