# Suricata Security Onion Correlation Examples

Use RedMesh lifecycle events as an assessment window when correlating
Suricata alerts in Security Onion. The event payload includes a bounded
time window, authorization context, expected egress metadata, and report
references without exposing target IP values when redaction is enabled.

Example Security Onion query:

```text
event.dataset:suricata.eve
AND @timestamp >= window.started_at
AND @timestamp <= window.actual_end_at
AND redmesh.authorization_ref:*
```

Useful fields to preserve in analyst notes:

- `window.started_at`
- `window.actual_end_at`
- `window.grace_seconds`
- `window.clock_skew_seconds`
- `authorization_ref`
- `report_refs.pass_report_cid`

Treat matches as correlation context for the authorized RedMesh
assessment window. Keep rule tuning and alert handling in the normal SOC
workflow.
