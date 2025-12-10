# RedMesh API/spec quick brief (PentesterApi01)

- **Port distribution:** add `distribution_strategy` (`slice` default, `mirror`). Slice: divide [start_port, end_port] evenly across chainstore peers and store per-worker start/end in `job_specs["workers"]`; Mirror: each worker gets full range. Update `_maybe_launch_jobs` to read worker-specific ranges correctly; keep existing range guards.

- **Port order:** in `_launch_job`, shuffle port lists before assignment (e.g., current order 0,1,2,3 -> randomized 2,1,0,3) so workers scan in non-sequential order.

- **Test selection:** UI sends `excluded_features` (defaults to run-all). Validate against `_get_all_features`, pass through to `_gather_service_info` and `_run_web_tests`, and filter accordingly (exclusions win). Persist allowed/skipped lists in worker/aggregate reports for audit.

- **Run modes:** add `RUN_MODE` (`SINGLEPASS` default, `CONTINUOUS_MONITORING`) plus `MONITOR_INTERVAL` seconds (default 60). `SINGLEPASS`: launcher builds job for all peers (including self), executes once, waits for peers, saves reports. `CONTINUOUS_MONITORING`: repeat the same single-pass flow after MONITOR_INTERVAL; bump `job_pass` counter in `job_specs` and append each pass CID to a list in reports. Keep a small random jitter before relaunch to avoid simultaneous writes.

- **Dune sand walking:** introduce `SCAN_MIN_RND_DELAY` / `SCAN_MAX_RND_DELAY` (config + `launch_test`) and sleep a random interval per worker thread during scans; make sleeps interruptible.

- **Report storage:** workers write full reports to R1FS and store only resulting CID in CStore (no report blobs in CStore).
