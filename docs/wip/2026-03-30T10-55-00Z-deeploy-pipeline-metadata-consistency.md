# Deeploy Pipeline Metadata Consistency

This note documents the current persistence behavior for Deeploy pipeline create/update flows.

## Summary

Deeploy now treats node deployment confirmation and job metadata persistence as separate phases.

For `create_pipeline` and `update_pipeline`:

1. The oracle dispatches the pipeline command to the target node(s).
2. The oracle waits for chainstore confirmation from the target node(s).
3. After the deployment is confirmed, the oracle persists the new pipeline payload to R1FS and updates the `DEEPLOY_DEPLOYED_JOBS` CSTORE entry in the background.
4. For updates, the previous R1FS CID is deleted only after the new CID is committed.

## Why

This avoids two failure modes in the old update path:

- slow R1FS persistence blocked `update_pipeline` completion even when the target node had already confirmed readiness
- the previous stored job definition could be deleted before the replacement deployment was confirmed

The current behavior favors deployment correctness and API latency over immediate metadata freshness.

## Contract

The live deployment state and the stored job metadata are now eventually consistent for a short period after a successful create/update.

That means:

- `create_pipeline` / `update_pipeline` success means the target node confirmed the deployment
- `get_r1fs_job_pipeline` may briefly return the previous stored pipeline immediately after a successful update
- once background persistence completes, `get_r1fs_job_pipeline` converges to the latest deployed pipeline

## Scope

This applies uniformly to Deeploy-managed pipelines, including:

- generic jobs
- service jobs
- native jobs
- `CONTAINER_APP_RUNNER`
- `WORKER_APP_RUNNER`

No service-catalog or UI payload shape changes are required for this behavior. The change is in persistence timing, not in request structure.

## UI Guidance

Normal create/edit flows do not need special handling if they only depend on the API response status.

Flows that immediately re-read stored pipeline metadata from R1FS after create/update should tolerate a short stale window by:

- polling until the stored payload matches the latest app/job state, or
- deferring the metadata read briefly, or
- treating the R1FS payload as last-known durable state rather than instant post-update truth

## Operational Note

If a deployment succeeds but background R1FS/CSTORE persistence fails, the node can still be running the new config while `get_r1fs_job_pipeline` lags behind. That is intentional for request-path latency, but it should be considered when debugging post-update state.
