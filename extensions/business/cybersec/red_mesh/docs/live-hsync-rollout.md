# Live Hsync Rollout

Launcher-side live hsync is a canary feature for repairing lost worker
completion announcements. It is disabled by default.

Enable it on one launcher through the existing RedMesh config block:

```python
"DISTRIBUTED_JOB_RECONCILIATION": {
  "LIVE_HSYNC_ENABLED": True,
  "LIVE_HSYNC_INTERVAL_SECONDS": 90.0,
  "LIVE_HSYNC_TIMEOUT": 3.0,
  "LIVE_HSYNC_MAX_PEERS_PER_TICK": 6,
  "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": True,
}
```

Expected behavior:

- The launcher first repairs from already-local `PENTESTER_API_*:live` rows.
- Every configured interval, the launcher hsyncs `PENTESTER_API_*:live` from
  bounded missing worker peers with `include_default_peers=False`.
- Only terminal live rows with matching `job_id`, `job_pass`,
  `assignment_revision_seen`, `finished=True`, and non-empty `report_cid`
  repair the launcher-owned top-level job record.
- Successful repair writes `finished=True`, `report_cid`, and `result=None`,
  allowing the normal launcher-only finalization path to proceed.

Canary checklist:

- Run repeated distributed scans for at least one hour on one launcher.
- Confirm stuck workers with terminal live rows repair within the next
  90-second window.
- Watch for one summary log per repair tick:
  `[LIVE-HSYNC] jobs=... missing_workers=... targeted_calls=...`.
- Confirm no long process-loop stalls and no false finalization.
- Roll back by setting `LIVE_HSYNC_ENABLED=False`; existing completion
  announcement and reannounce paths remain unchanged.

Final verification on this implementation branch:

- `python -m pytest extensions/business/cybersec/red_mesh/tests -v`
- `/home/vitalii/remote-dev/.venvs/edge-node-hsync/bin/python -m pytest naeural_core/naeural_core/business/test_framework/test_chain_store_hsync.py -v`

Known baseline caveat:

- The core hsync primitive suite currently has a pre-existing failure in
  `test_chainstore_set_and_hsync_share_peer_selection`: `chainstore_set`
  returns `bool` while the test expects a metadata envelope.
