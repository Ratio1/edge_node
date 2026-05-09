# RedMesh Wazuh / Generic SIEM Examples

Phase 3 emits one canonical `redmesh.event.v1` payload per HTTP POST or syslog JSON message.
All payloads are redacted before delivery and include idempotency fields:

- HTTP: `X-RedMesh-Event-Id`, `X-RedMesh-Dedupe-Key`, and optional `X-RedMesh-Signature`.
- Syslog JSON: top-level `redmesh_idempotency_key` and optional `redmesh_signature`.

## Event Groups

Example rule groups for downstream routing:

- `redmesh.lifecycle` for job start/pass/completion/stop/failure notices.
- `redmesh.service_observation` for normalized port/protocol/service observations.
- `redmesh.finding` for created, updated, or triaged findings.
- `redmesh.export` for SIEM/MISP/STIX/OpenCTI/TAXII export status.
- `redmesh.attestation` for attestation submitted/completed/failed status.
- `redmesh.correlation` for Suricata/Security Onion correlation summaries.

## Decoder Sketch

```xml
<decoder name="redmesh-json">
  <program_name>redmesh</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

## Rule Sketch

```xml
<group name="redmesh,redmesh.lifecycle,">
  <rule id="110100" level="3">
    <decoded_as>redmesh-json</decoded_as>
    <field name="schema">redmesh.event.v1</field>
    <description>RedMesh authorized assessment lifecycle event</description>
  </rule>
</group>

<group name="redmesh,redmesh.finding,">
  <rule id="110102" level="8">
    <decoded_as>redmesh-json</decoded_as>
    <field name="event_type">redmesh.finding.*</field>
    <description>RedMesh finding event</description>
  </rule>
</group>
```

Keep decoder and rule deployment managed by the SOC/SIEM owner. RedMesh does not disable,
suppress, or control IDS/SIEM detection rules.
