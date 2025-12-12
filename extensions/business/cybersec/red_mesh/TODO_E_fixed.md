# RedMesh v2.0 – Minimal, Correct Implementation Plan
Status: ready to implement. Scope is only the features from PROMPT.MD; no extras.

## Principles
- Preserve existing orchestrator/worker/CStore lifecycle (discover → launch → aggregate → publish).
- Keep it simple: minimal new fields, no lineage trees, no extra audit metadata.
- Non-blocking scheduling: never sleep the orchestrator.
- Defaults: single-pass, sliced ports, shuffled order unless configured otherwise.

## Job spec (CStore) additions
- `included_tests: list[str] | None` – whitelist; None means all. Validate against discovered features (same discovery path as workers); reject unknowns.
- `excluded_tests: list[str]` – blacklist; wins over included. Same validation.
- `port_distribution: "SLICE" | "MIRROR"` – SLICE default.
- `port_order: "SEQUENTIAL" | "SHUFFLE"` – default SHUFFLE for stealth; SEQUENTIAL allowed (no compatibility constraint).
- `run_mode: "SINGLEPASS" | "CONTINUOUS"` – SINGLEPASS default.
- `schedule: {"interval": int} | None` – required for CONTINUOUS; interval > 0 else reject; reject malformed/non-dict payloads.
- `pacing: {"pause_interval": int, "pause_duration": float} | None` – pause after ~N actions for ~D seconds with defined jitter; validate pause_interval > 0 and pause_duration >= 0; reject malformed/non-dict payloads.
- `scheduled_at: float | None` – future launch time for non-blocking continuous runs (set only on successors).
- `continuous_stopped: bool` – stop flag for continuous chains; default False; never reset in successors.
- `max_iterations: int | None` – optional safety ceiling; default None (no cap). If provided, must be > 0; job-level value overrides any global default if such config is introduced.

## Architecture by feature
- Monitoring: add a simple `current_stage` string in worker state (INITIALIZED/SCANNING/PROBING/TESTING/PAUSED/COMPLETED) plus clearer logs; surface it in `get_job_status` per worker entry (e.g., status[job_id][worker_id]["current_stage"]); no extra nested telemetry.
- Test selection: filter `_service_info_*` and `_web_test_*` via include/ exclude lists with validation against discovered features.
- Port distribution: in `_launch_job`, choose SLICE (existing chunking) or MIRROR (all workers get full range); aggregation already deduplicates.
- Port order: per job, apply SEQUENTIAL (sorted) or SHUFFLE (random.shuffle once before scan) to each worker’s ports.
- Run modes & scheduling: job chaining. When a CONTINUOUS job finishes, orchestrator **re-reads the latest job spec from CStore** to honor concurrent stop requests, then writes a successor job with a new `job_id`, incremented iteration, and `scheduled_at = now + interval`. `_maybe_launch_jobs` skips jobs until `scheduled_at` is reached. No sleeps in the orchestrator.
- Stop continuous: `stop_and_delete_job(job_id, stop_continuous=True)` sets `continuous_stopped=True` so `_close_job` skips creating successors. Do not reset this flag in successors.
- Pacing (“Dune sand walking”): worker-level `_maybe_pause` that uses `stop_event.wait(duration)` with defined jitter (interval jitter 0.8–1.2x, duration jitter 0.5–1.5x); invoked in port scan, service probes, and web tests; preserves/restores `current_stage`. Each worker gets its own port list copy when shuffling MIRROR batches to avoid shared state; for MIRROR+SEQUENTIAL reuse the shared range to avoid unnecessary memory.

## Implementation steps
1) Data/validation (pentester_api_01.py)
   - Extend `_CONFIG` defaults for new fields (port_order default SHUFFLE).
   - Update `launch_test` signature to accept new params; validate enums, schedule interval > 0 (required for CONTINUOUS), pacing bounds, known test names; reject malformed dicts (missing keys/wrong types) for schedule/pacing; reject or explicitly ignore extra keys (document behavior).
   - Include new fields in job spec; set `scheduled_at=None`, `continuous_stopped=False`, optional `max_iterations` (must be > 0 if set; job-level overrides any global default if present).
   - `_normalize_job_record` to backfill defaults for missing fields; for malformed specs, reject with a clear error (no legacy compatibility/implicit coercion).
2) Worker wiring (redmesh_utils.py)
   - Accept and store include/exclude, port_order, pacing in `PentestLocalWorker`.
   - Add `current_stage` to state.
   - Implement `_should_run(test_name)` and use it in service/web loops.
   - Apply port order before scanning; inject `_maybe_pause` with jitter and stage preservation.
3) Port distribution (pentester_api_01.py)
   - In `_launch_job`, branch on `port_distribution`: existing batch split for SLICE; identical full range per worker for MIRROR. For MIRROR+SEQUENTIAL reuse the same range object; for MIRROR+SHUFFLE, create per-worker list copies (or document the memory cost) so shuffling does not share state.
4) Continuous mode (pentester_api_01.py)
   - In `_close_job`, after aggregation and updating worker entry, **re-read** the job spec from CStore to honor concurrent stop flags; if spec is missing, log and skip successor creation. If `run_mode=="CONTINUOUS"` and not `continuous_stopped` and (max_iterations is None or iteration < max_iterations), create successor with new `job_id`, `scheduled_at=now+interval`, and reset `workers={}`; do not block.
   - In `_maybe_launch_jobs`, skip jobs whose `scheduled_at` is in the future; if a job spec is missing between read and launch, log and skip gracefully.
   - In `stop_and_delete_job`, when `stop_continuous` is true, set `continuous_stopped=True` in CStore before or during stop.
5) Observability polish
   - Update logs to include job_id, stage, and port range/test name.
   - Ensure `get_job_status` surfaces `current_stage` per worker when present.

## Out of scope (to stay KISS)
- No parent_job_id lineage, no tests_run/skipped audit lists, no RBAC/allowlists, no extra pacing knobs beyond interval/duration.

## Acceptance checks
- SINGLEPASS job still works with no new params.
- CONTINUOUS job creates successor after interval without blocking other jobs; stop flag prevents further successors.
- MIRROR launches workers with same port range; aggregation dedupes.
- SHUFFLE changes scan order; SEQUENTIAL remains deterministic.
- Pacing pauses respect stop requests (stop_event.wait), and stage restores correctly after pauses.
