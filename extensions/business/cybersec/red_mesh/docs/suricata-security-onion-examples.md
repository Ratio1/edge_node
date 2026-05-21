# RedMesh Suricata And Security Onion Queries

These examples correlate IDS telemetry with RedMesh assessment-window notices. They do not disable, suppress, or alter IDS rules.

## RedMesh Notice Fields

Canonical lifecycle events include:

- `event_type`: `redmesh.job.started`, `redmesh.job.pass_completed`, or `redmesh.job.stopped`
- `job_id` and `pass_nr`
- `window.started_at`, `window.expected_end_at`, and `window.actual_end_at`
- `window.grace_seconds` and `window.clock_skew_seconds`
- `window.source_node_ids`
- `window.expected_egress_ip_pseudonyms`
- `window.target_pseudonym`
- `window.ports.start`, `window.ports.end`, and `window.protocols`
- `authorization_ref` or `authorization_id` when supplied

Raw target and egress IP values are intentionally omitted from exported notices unless a future internal trust profile explicitly allows them.

## Security Onion Hunt Query

Use the RedMesh notice to determine the approved time window, source nodes, target pseudonym, and port range. In Security Onion, query Suricata EVE alerts and flows with the raw values available inside the SOC boundary:

```text
event.dataset:suricata.eve
AND @timestamp:[2026-05-09T12:00:00Z TO 2026-05-09T12:20:00Z]
AND destination.port:[1 TO 1024]
AND network.transport:tcp
AND source.ip:(198.51.100.20 OR 198.51.100.21)
AND destination.ip:10.0.0.5
```

If NAT or cloud egress is used, replace `source.ip` with the approved translated egress addresses before comparing Suricata events.

## Security Onion Alert-Focused Query

```text
event.dataset:suricata.eve
AND event.kind:alert
AND @timestamp:[${window.started_at - clock_skew_seconds} TO ${window.actual_end_at + grace_seconds}]
AND destination.port:(${window.ports.start} TO ${window.ports.end})
AND network.transport:(${window.protocols})
```

## Wazuh RedMesh Notice Query

```text
rule.groups:redmesh
AND data.schema:redmesh.event.v1
AND data.event_type:(redmesh.job.started OR redmesh.job.pass_completed OR redmesh.job.stopped)
AND data.job_id:${job_id}
```

## Correlation Checklist

- Confirm the RedMesh job was authorized by checking `authorization_ref` or `authorization_id`.
- Expand the query window by `clock_skew_seconds` before the start and `grace_seconds` after the end.
- Match source by approved egress IPs or NAT mappings available inside the SOC.
- Match destination by the raw target only inside the SOC boundary; exported RedMesh notices carry only `target_pseudonym`.
- Treat missing IDS telemetry as an absence of observed telemetry, not proof that no detection occurred.
