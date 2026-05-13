# ADR — Scenario ID convention `PT-OAPI<N>-<NN>` for OWASP API Top 10 2023

**Status**: Accepted
**Date**: 2026-05-12
**Context**: Graybox API Top 10 implementation, Subphase 1.0 (see `_todos/2026-05-12-graybox-api-top10-plan-detailed.md`).

## Decision

New OWASP API Top 10 (2023) graybox scenarios use the prefix **`PT-OAPI<N>-<NN>`** where:

- `<N>` is the OWASP API category number (1–6, 8, 9 for v1; API7 keeps its legacy ID, API10 is reserved for Phase 9).
- `<NN>` is a zero-padded sequence within the category (`01`, `02`, …).

Examples: `PT-OAPI1-01` (BOLA), `PT-OAPI3-02` (mass assignment), `PT-OAPI5-02-mut` (mutating BFLA), `PT-OAPI9-01` (OpenAPI exposure).

**Out of scope of this ADR**: any scenario ID for API7 SSRF stays as the existing **`PT-API7-01`** for backward compatibility. Any scenario ID for API10 will be minted in Phase 9, not in v1.

## Context

The graybox catalog already uses `PT-A<NN>-<NN>` for OWASP Web Top 10 2021 scenarios (`PT-A01-01` … `PT-A07-06`). When adding OWASP API Top 10 (2023) coverage we considered several prefixes:

| Candidate | Pros | Cons |
|---|---|---|
| `PT-API<N>-<NN>` | Short, matches OWASP naming directly | One character away from `PT-A0<N>-<NN>` — pentesters reading reports under time pressure will misread. `PT-API1-01` vs `PT-A01-01` differ by one character in position 5. |
| `PT-API<N>:2023-<NN>` | Year-explicit | Punctuation in ID is hostile to grep, regex, CI test names, JSON keys. |
| `PT-OWASPAPI<N>-<NN>` | Fully unambiguous | Long. Inflates inventory tables and PDF columns. |
| **`PT-OAPI<N>-<NN>`** | Visually distinct from `PT-A` family. Short. OWASP-API mnemonic. | Slight learning curve (one-time). |

We chose `PT-OAPI<N>-<NN>`.

## Consequences

### Affected systems

1. **Backend catalog** — `extensions/business/cybersec/red_mesh/graybox/scenario_catalog.py` adds 23 new entries under the new prefix (see Subphase 1.2 in the plan).
2. **Inventory regex** — `extensions/business/cybersec/red_mesh/tests/test_detection_inventory.py` widens its scenario-ID matcher to accept `PT-OAPI\d{1,2}-\d+` alongside the existing `PT-A\d+-\d+` and `PT-API7-\d+`.
3. **Frontend (RedMesh-Navigator)** — `lib/domain/knowledge.ts::GRAYBOX_SCENARIOS` registers the new IDs; `OWASP_CATEGORIES` extends to include `API1`–`API9`; a shared `owaspCategoryKey()` helper replaces brittle `owasp_id.slice(0, 3)` usage so `API7:2023` resolves correctly.
4. **PDF report** — `lib/pdf/sections/vulnerabilityAssessment.ts` adds §3.3.3 "OWASP API Top 10" with `owaspCategoryKey(f.owasp_id)?.startsWith('API')` as the dispatch predicate. Legacy `PT-API7-01` MUST appear here.
5. **Operator docs** — `docs/guides/api-security-scanning.md` (Phase 8.6) explains how to read the new IDs.

### Backward compatibility

- `PT-A<NN>-<NN>` (Web Top 10 2021) IDs are unchanged.
- `PT-API7-01` (legacy SSRF) is preserved verbatim — never renamed. Frontend must continue to render it correctly.
- Detection-inventory floor counters are bumped by +23 (graybox floor 80 → ≥103) in Subphase 1.2.

### Non-decisions (out of scope of this ADR)

- Whether to deprecate the legacy `PT-A02-12` once `PT-OAPI2-01` is stable. Tracked as Phase 9 F12.
- ATT&CK / CWE / compliance-framework mapping schemes; tracked separately (Subphase 1.2 and Phase 9 F13).
- Whether `PT-API7-01` should eventually be renamed to `PT-OAPI7-01` for consistency. Not in v1; revisit when there is a separate need to migrate the legacy probe.

## References

- Plan: `_todos/2026-05-12-graybox-api-top10-plan-detailed.md` (Subphase 1.0, lines 253–280; Subphase 1.2 ID table, lines 315–329).
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Existing OWASP Web Top 10 2021 scenarios: `extensions/business/cybersec/red_mesh/graybox/scenario_catalog.py`.
