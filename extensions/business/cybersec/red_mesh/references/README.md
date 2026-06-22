# Reference data

Static reference tables used by the PTES-aligned report generator.

## Files

| File | Purpose | Refresh cadence |
|---|---|---|
| `static/cwe_to_owasp.json` | CWE-ID → OWASP Top 10 category mapping | Annual (when OWASP rev'd) |
| `static/owasp_categories.json` | OWASP Top 10 category metadata (code, name, description) | When OWASP publishes a new revision |
| `static/cwe_top25.json` | MITRE CWE Top 25 ranked list | Annual (MITRE typically publishes May/June) |

## Refresh procedure

1. Pull the latest from each source (links in each JSON's `source` field).
2. Update the `last_refreshed` field to today's ISO date (`YYYY-MM-DD`).
3. Update the `version` field if the source has rev'd.
4. Run `pytest extensions/business/cybersec/red_mesh/tests/test_static_references.py` to validate the file shape.
5. Commit the refresh in a single PR with `chore(refs): refresh ...` as the title.

## Staleness CI gate

`tests/test_static_references.py::test_files_are_not_stale` fails the suite when any file's `last_refreshed` is older than 180 days. This forces a refresh roughly every 6 months even if the upstream source hasn't changed (catches us if MITRE/OWASP issue silent-but-meaningful corrections).

## Why static-in-repo (vs. fetched at runtime)

These tables change rarely. Bundling them in the repo:

- Keeps lookups deterministic across environments (no network dependency at scan time).
- Lets CI assert mappings exist for every CWE in `cve_db.py`.
- Survives air-gapped deployments.

CVSS / CISA KEV / FIRST EPSS data does NOT belong here — those change daily and live in `references/dynamic.py` (Phase 2 PR-2.2), fetched fresh per scan and persisted to the scan's R1FS record so the report is reproducible.
