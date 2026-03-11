# Phase 6 Summary

Date: 2026-03-11
Phase: 6
Title: Frontend Normalization, Graybox UX Parity, and Export Completeness

## Scope

This phase focused on RedMesh Navigator only. No backend runtime code changed in this phase.

Primary goals:
- complete graybox/webapp launch-field propagation through the Navigator UI and Next API route
- normalize graybox job fields consistently in the frontend contract layer
- render graybox worker findings as first-class results in the job details experience
- verify that graybox-specific validation and display behavior match the accepted Phase 6 criteria

## What Was Changed

### 1. Frontend normalization and contract handling

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/api/jobs.ts`:
- fixed port-order normalization so backend `SHUFFLE` maps to frontend `random`
- made excluded-method derivation scan-type-aware
- ensured webapp launch requests invert only graybox feature groups
- preserved graybox identity fields already added in Phase 1 while aligning the rest of the launch mapping

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/services/edgeClient.ts`:
- added `graybox_results -> grayboxResults` transformation when worker reports are fetched from R1FS

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/services/redmeshApi.types.ts` and `/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/api/types.ts`:
- extended worker report typing to include graybox result payloads

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/domain/features.ts`:
- kept the graybox fallback catalog available in default feature resolution, which is required for mock/fallback mode exclusion logic

### 2. Job creation UX and validation

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/components/dashboard/JobForm.tsx`:
- added webapp form controls for:
  - `weakCandidates`
  - `maxWeakAttempts`
  - `verifyTls`
- kept `allowStatefulProbes` explicit and improved toggle accessibility with dedicated labels
- added specific client-side validation messages for:
  - missing target URL
  - invalid target URL
  - missing admin username
  - missing admin password
- removed transient submit-path debug logging
- ensured the submit payload now includes:
  - `weakCandidates`
  - `maxWeakAttempts`
  - `verifyTls`
  - `allowStatefulProbes`

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/app/api/jobs/route.ts`:
- retained and verified route-level parsing/validation for webapp fields
- confirmed route forwarding for weak-auth and TLS fields

### 3. Graybox findings UX

Updated `/home/vitalii/remote-dev/repos/RedMesh-Navigator/app/dashboard/jobs/[jobId]/components/DetailedWorkerReports.tsx`:
- graybox findings now appear in a dedicated "Authenticated Findings" section
- per-node result cards now treat `grayboxResults` as findings-bearing data
- added status rollups for vulnerable / clean / inconclusive findings
- reused the existing structured finding renderer so replay steps, scenario IDs, severity, and evidence remain consistent

### 4. Test coverage

Updated or added:
- `/home/vitalii/remote-dev/repos/RedMesh-Navigator/__tests__/jobs-api.test.ts`
- `/home/vitalii/remote-dev/repos/RedMesh-Navigator/__tests__/jobs-route.test.ts`
- `/home/vitalii/remote-dev/repos/RedMesh-Navigator/__tests__/ui-jobform.test.tsx`
- `/home/vitalii/remote-dev/repos/RedMesh-Navigator/__tests__/detailed-worker-reports.test.tsx`

Coverage added for:
- running graybox job normalization
- `SHUFFLE -> random` port-order mapping
- propagation of `weakCandidates`, `maxWeakAttempts`, and `verifyTls`
- route rejection for invalid target URLs
- end-to-end UI payload generation for webapp launches
- dedicated rendering of graybox findings in job details

## Acceptance Criteria Check

### All graybox launch inputs round-trip correctly through UI -> Next route -> backend

Met for the Navigator-managed path:
- UI sends the full graybox field set
- route validates and forwards the graybox field set
- request-builder tests confirm correct API payload shaping

### Job details render graybox results and scenario-oriented findings without network-centric fallbacks

Met:
- worker report fetches now preserve `grayboxResults`
- detailed results UI now renders a dedicated authenticated findings section

### Exported PDF includes graybox-specific content

Met by verification of the current implementation:
- no code change was required here
- existing PDF generation already includes graybox summary and finding sections
- this was re-checked during the phase review

### Error states distinguish validation problems from transport/server failures

Met for the webapp creation flow:
- invalid or missing webapp inputs now surface specific validation errors in the UI and route layer

## Verification

Executed:

`npm test -- --runInBand jobs-api.test.ts jobs-route.test.ts ui-jobform.test.tsx detailed-worker-reports.test.tsx`

Result:
- 4 suites passed
- 12 tests passed

## Notes / Residual Risk

- `lib/config/env.ts` still logs raw environment/config data during tests and runtime. This remains a real security issue, but it is part of the later hardening phase, not Phase 6.
- The Phase 6 PDF requirement was satisfied by re-validating the existing implementation rather than changing it.

## Resulting State

After Phase 6, Navigator treats graybox scans as first-class jobs in all core operator flows:
- launch configuration
- validation
- typed request construction
- report fetching
- detailed findings presentation

The next phase should focus on security hygiene and operational hardening.
