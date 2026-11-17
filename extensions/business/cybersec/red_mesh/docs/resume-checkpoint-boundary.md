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
- Finished but not merged: after `_close_job` publishes the terminal `:live` row, the node writes a
  final marker `final_<pass_nr>.pkl` and deletes the pass files. The marker holds plain types only:
  `version`, `job_id`, `pass_nr`, `ee_addr`, `report_cid`, `done`, `saved_at` and the live-row summary
  (`assignment_revision_seen`, port counts, open ports, completed tests, `started_at`,
  `first_seen_live_at`, `live_metrics`, `threads`, `scan_type`, phase counts). It holds no findings and
  no credentials. If the marker cannot be saved, the pass files stay. After a restart, when CStore does
  not yet show this worker `finished` but a marker for the job's current pass exists, the node
  publishes the terminal `:live` row again from it and does not scan. The marker must match the job,
  pass, node and assignment revision; a bad or mismatched marker is deleted and the worker resumes or
  launches as above. If the republish itself fails (for example a CStore error), the marker is kept,
  nothing launches, and the next check tick retries. The marker is read back with a key and type
  check: only the listed keys, `report_cid` a string of at most 256 characters, counts integers; any
  other marker is deleted. The worker then ends `finished` in CStore when the launcher merges the row, as
  after a normal close. Resume ignores the marker; `delete_pass` keeps it.
- Cleanup (`_maybe_cleanup_checkpoints`): once at warmup, then every `WORKER_CHECKPOINT.GC_INTERVAL`
  after `_maybe_close_jobs`. It reads each checkpoint job folder's job record once per tick and
  unpickles nothing. The whole job folder (marker included) is deleted when the job is missing from
  CStore on two consecutive ticks (the count is in memory and resets on restart), the job is terminal,
  the job is not a network job (a graybox or model-test record), or this worker is `finished`. A single
  file is deleted when its pass is below the job's `job_pass` or it is older than `MAX_AGE`. A pass
  above the job's (a CStore replica lagging after a restart) is kept. Stray `*.tmp` files left by
  `save_pickle` (named `<file>.pkl.<random>.tmp`) are removed once older than five minutes. One log line
  gives the files and bytes removed, only when something was removed. A GC error is logged and never
  raised; a malformed job record skips only its own folder. An unreadable worker file is left to the
  resume path, which deletes it. If `plugin_data/redmesh_ckpt` or a job folder is a symlink, no helper
  reads, writes or deletes through it.
- Stop paths: a HARD `stop_monitoring` and `stop_and_delete_job` delete all of the job's checkpoints,
  marker included. A soft stop keeps them, since the pass continues.
- Graybox workers still restart from the beginning of the pass.
- The checkpoint is local to the node. It is not a CStore or R1FS record.
- Accepted limits:
  - Metric counters (`scan_metrics`) may double-count a method that reruns after a restart.
  - The node report keeps the first worker's `resume_events`.
  - A planted checkpoint can stall unpickling. The restricted unpickler refuses unlisted globals and
    the file and node caps bound the work, but a hostile file with allowed types can still cost CPU
    and memory until it is rejected. Files live in the plugin data folder, which needs node access to write.
  - A GC decision rests on the local CStore replica. Right after a restart that replica can lag.
    The two-tick rule covers a missing job, and the pass rule only deletes older passes, so a lagging
    `job_pass` never deletes a resume checkpoint. A lagging status can still delete a file early,
    which costs a rescan of the affected slice, never a wrong result.

## Explicit Non-Goals

- No mid-pass resume token in CStore or R1FS
- No replay of partially completed graybox sessions (graybox workers still restart; RM-202)

## Design Rule

RedMesh may resume only from durable, integrity-checked boundaries that are already represented as immutable artifacts or explicit mutable orchestration records. Any state that depends on live sockets, authenticated sessions, or partial aggregation must restart. The one exception is the node-local network worker checkpoint (RM-201), which is validated on load and never leaves the node.
