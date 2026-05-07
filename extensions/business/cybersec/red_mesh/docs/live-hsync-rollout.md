# Live Hsync Rollout

Launcher-side live hsync repairs lost worker completion announcements. It is
**enabled by default**. The flag is a per-node kill-switch, not a staged-rollout
gate — disable it via config only if a regression is suspected on a specific
launcher.

Default values from `DEFAULT_DISTRIBUTED_JOB_RECONCILIATION_CONFIG`:

```python
"DISTRIBUTED_JOB_RECONCILIATION": {
  "STARTUP_TIMEOUT": 180.0,                # 2x LIVE_HSYNC_INTERVAL — give hsync 2 windows
  "STALE_TIMEOUT": 120.0,
  "STALE_GRACE": 90.0,                     # 1x LIVE_HSYNC_INTERVAL — 1 window post-stale
  "MAX_REANNOUNCE_ATTEMPTS": 3,
  "LIVE_HSYNC_ENABLED": True,              # default; set False to disable
  "LIVE_HSYNC_INTERVAL_SECONDS": 90.0,
  "LIVE_HSYNC_TIMEOUT": 3.0,
  "LIVE_HSYNC_MAX_PEERS_PER_TICK": 6,
  "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": True,
}
```

`STARTUP_TIMEOUT` and `STALE_GRACE` are intentionally larger than
`LIVE_HSYNC_INTERVAL_SECONDS` so hsync gets at least one full repair window
before reannounce fires. A premature reannounce would bump
`assignment_revision`, which would cause subsequent hsync rescues to be
rejected by the revision filter — wasting the safety net.

Expected behavior:

- The launcher first repairs from already-local `PENTESTER_API_*:live` rows.
- Every configured interval, the launcher hsyncs `PENTESTER_API_*:live` from
  bounded missing worker peers with `include_default_peers=False`.
- Only terminal live rows with matching `job_id`, `job_pass`,
  `assignment_revision_seen`, `finished=True`, and non-empty `report_cid`
  repair the launcher-owned top-level job record.
- Successful repair writes `finished=True`, `report_cid`, and `result=None`,
  allowing the normal launcher-only finalization path to proceed.
- Reannounce path runs the same durable `:live` repair as a defensive guard
  before any `assignment_revision` bump, so a worker whose terminal `:live`
  row has already arrived at the launcher is never clobbered by a stale-replica
  reannounce.

Canary checklist (recommended on first deploy to one launcher before fleet
rollout):

- Run repeated distributed scans for at least one hour on one launcher.
- Confirm stuck workers with terminal live rows repair within the next
  90-second window.
- Watch for one summary log per repair tick:
  `[LIVE-HSYNC] jobs=... missing_workers=... targeted_calls=...`.
- Confirm no long process-loop stalls and no false finalization.
- Per-node kill-switch: set `LIVE_HSYNC_ENABLED=False` to disable on a single
  launcher; existing completion announcement and reannounce paths remain
  unchanged.

Final verification on this implementation branch:

- `python -m pytest extensions/business/cybersec/red_mesh/tests -v`
- `/home/vitalii/remote-dev/.venvs/edge-node-hsync/bin/python -m pytest naeural_core/naeural_core/business/test_framework/test_chain_store_hsync.py -v`

Known baseline caveat:

- The core hsync primitive suite currently has a pre-existing failure in
  `test_chainstore_set_and_hsync_share_peer_selection`: `chainstore_set`
  returns `bool` while the test expects a metadata envelope.
