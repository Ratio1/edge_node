# RedMesh feature plan (PentesterApi01 / PentestLocalWorker)

## Current state (quick map)
- API plugin `pentester_api_01.py` orchestrates jobs announced via CStore, splits target port ranges evenly across local workers, and aggregates reports when all workers finish.
- `PentestLocalWorker` auto-runs port scan → service probes (all `_service_info_*`) → web probes (all `_web_test_*`), with optional port exclusions but no per-test selection or pacing controls.
- Job spec today: `job_id`, `target`, `start_port`, `end_port`, `exceptions`, `launcher`, `workers{peer->{finished,result}}`. No concept of run mode (single/continuous), jitter, or distribution strategy choices.

## Required feature tracks
- Service/web test selection
  - Extend job spec with `include_tests` / `exclude_tests` (separate lists for `service_info` vs `web_tests`) validated against `_get_all_features()`. Default: run all.
  - Add API params to `launch_test` (and validation rules) to accept comma/space lists; normalize to method names. Reject unknown tests with a helpful error.
  - `PentestLocalWorker` should accept the allowed set and filter the discovered `_service_info_*` / `_web_test_*` before execution. Persist allowed/blocked lists in report metadata for auditability.
  - Reporting: add per-worker fields `tests_run`, `tests_skipped`, and propagate to aggregated report.
  - Tests: add unit coverage for include-only, exclude-only, and conflicting rules (exclude wins).

- Worker port-range distribution modes
  - New job flag `distribution_mode`: `slice` (default, breadth-first coverage) vs `mirror` (every worker gets same range) vs optional `staggered` (all workers same range but randomized start offset/stride to reduce duplication).
  - If `mirror`/`staggered`, mark worker reports with `coverage_strategy` and ensure aggregation dedupes `open_ports` and merges service/web results deterministically.
  - Wire flag into `_launch_job` splitter; keep guardrails when requested workers > ports. In `staggered`, randomize per-worker port order and introduce optional `max_retries_per_port` to bound duplicate effort.
  - Config surface: plugin default (e.g., `CFG_PORT_DISTRIBUTION_MODE`), default `slice`. Default worker count = available CPU cores (plugin runs as sole job); allow override but cap at cores.

- Run mode: singlepass vs continuous monitoring
  - Add `run_mode` in job spec (`singlepass` default, `continuous` for chained jobs). Continuous: after `_close_job`, schedule a successor job with inherited params, new `job_id`, incremented `iteration` counter, and backoff delay.
  - Persist lineage fields (`parent_job_id`, `iteration`, `last_report_at`, `next_launch_at`) to aid observability and cleanup. Add TTL/`max_iterations` or `stop_after` datetime to prevent infinite loops.
  - API responses should surface next scheduled run time; allow `stop_and_delete_job` to cancel the chain (mark lineage as canceled in cstore).
  - Consider a `run_interval_sec` knob; default to a conservative interval to avoid rate-limiting targets.
  - Add optional daily runtime windows (UTC hour-based `window_start`, `window_end`, 0–23) with at least one-hour disallowed window; continuous mode should pause/resume respecting the window. Default can be full-day minus a 1-hour break for safety.

- Steps temporization (“Dune sand walking”)
  - Job-level pacing config: `min_steps`, `max_steps`, `min_wait_sec`, `max_wait_sec`. Optional for `singlepass`; enforced non-zero for `continuous` (fallback defaults if not provided).
  - Implement in `PentestLocalWorker` port scanning loop and optionally between service/web methods: after a random number of actions, sleep random wait while honoring `stop_event`.
  - Record pacing stats in worker status (`jitter_applied`, `total_sleep_sec`) for transparency. Make values configurable via plugin defaults and `launch_test` params.

## Additional logical enhancements (fit with API/framework)
- Target/port randomization: shuffle port order per worker (configurable) to reduce IDS signatures and distribute load.
- Safe-rate controller: per-target max RPS and concurrent sockets; auto-throttle on repeated timeouts/connection resets to mimic human scanning.
- Fingerprinting & preflight: optional light-touch pre-scan (ICMP/TCP SYN-lite) to bail early on dead hosts; enrich reports with ASN/cloud provider to better interpret noise/blocks.
- Credential hygiene: allow injecting bearer/API keys for authenticated tests via secrets manager pointer (never store raw secrets in cstore; expect vaulted reference).
- Health/timeout guardrails: per-stage max duration; force-close jobs that exceed SLAs and flag in report to avoid runaway continuous chains.
- Observability: append `audit_log` entries (timestamps, action, module) to worker status; expose via `get_job_status` for forensic traceability.
- Extensibility hooks: plugin registry for `_service_info_*` / `_web_test_*` from `extensions/.../plugins` so users can add probes without core edits; validate names against allowlist.

## Stealth & red-team best practices (public Ratio1 edge nodes)
- Pacing and jitter: default to non-burst scans with randomized inter-request sleeps; stagger workers across time windows to evade traffic spikes.
- Traffic shaping: rotate User-Agent/Host headers, optionally bind to egress pools or proxies per cloud region to avoid IP reputation clustering.
- Noise reduction: avoid full 1–65535 sweeps by default; prefer common/high-value ports + heuristics from previous runs; honor exclusions strictly.
- Detection-aware retries: back off or skip ports when seeing WAF/IDS fingerprints (e.g., TCP RST storms, HTTP 429/403 patterns).
- Cover traffic & blending: mix benign HEAD/OPTIONS with probes; throttle to stay below typical NIDS thresholds; optionally insert dormant intervals to simulate human behavior.
- Logging hygiene: ensure reports strip sensitive headers/body fragments; store only minimal artifacts needed for findings.
- Authorization compliance: enforce explicit allowlists/attestation per target before running (config flag) to prevent misuse of public nodes.

## Testing & rollout
- Add unit tests covering new job spec validation, distribution modes, pacing counters, continuous chaining lifecycle, and aggregation dedupe paths.
- Provide a dry-run/simulation mode to exercise scheduling without sending network traffic for CI.
- Update documentation/README and FastAPI schema to reflect new params and defaults.

## Open questions for the product/ops team
- What is the acceptable default pacing for continuous mode (sleep floor/ceiling, max daily test hours) given UTC windows and the mandated 1-hour daily break?
- Confirm default distribution stays `slice` and whether any cap below `cpu_count` is desired (thermal/network guardrails).
- Do we need per-target authorization tokens or signed scopes to launch tests from public edge nodes, and are certain probes (SQLi/path traversal/auth bypass) forbidden for specific tenants/environments (e.g., production vs staging, regulated sectors)?
- How should chained jobs be retained (TTL) and how much historical reporting is required for compliance?
