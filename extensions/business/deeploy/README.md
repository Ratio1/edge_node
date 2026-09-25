# Selected Environment Secrets

`create_pipeline` and `update_pipeline` accept an optional top-level `secret_paths`
list. Selectors address the signed request's flat `plugins` array, before runtime
signature grouping:

```json
{
  "secret_paths": [
    ["plugins", 0, "ENV", "API_KEY"],
    ["plugins", 0, "DYNAMIC_ENV", "DATABASE_URL"],
    ["plugins", 0, "PER_NODE_CONFIG", "byNode", "0xai_address", "ENV", "KEY"],
    ["plugins", 0, "PER_NODE_CONFIG", "byIndex", "0", "ENV", "KEY"]
  ]
}
```

Every selected variable must exist. Plugin indexes are non-negative JSON integers;
`byIndex` map keys are canonical non-negative decimal strings. Per-node `default`
selectors are also supported. Arbitrary config paths, runtime `PLUGINS/INSTANCES`
paths, individual dynamic parts, malformed selections, and client-supplied
`SECRET_PATHS` metadata are rejected before staging or dispatch. A builder may use
transient metadata internally, but must strip it from the final request.

ENV selections protect scalar values, including empty strings. A DYNAMIC_ENV
selection addresses the whole variable and protects every static part's string
`value`, including empty strings. Dynamic `type`, `path`, and other runtime
references remain visible. No objects or lists are stored as secret values.
Existing mandatory secret paths remain protected regardless of this list.

The backend compiles selectors to server-owned per-instance `SECRET_PATHS`, such
as `["ENV", "API_KEY"]` and `["DYNAMIC_ENV", "DATABASE_URL"]`. Per-node selectors
retain their relative `PER_NODE_CONFIG` prefix in canonical pipeline metadata.
The metadata and ordered dynamic paths survive R1FS persistence, recovery,
replacement updates, and scale-up. Node materialization projects selectors to
the effective variables using the same default/index/node precedence as values.
dAuth retains its existing scalar same-path bundle format; no Core protocol change
is required.

## Updates and Hidden Values

- Omitted `secret_paths` preserves existing valid selection metadata for retained
  variables, including accepted legacy per-node aliases. It is not a request to
  publish secrets. Full-request responses preserve the submitted alias spelling.
- An explicit list replaces conditional selections. `[]` removes all conditional
  selections only when retained hidden variables have replacement plaintext.
  Removing a variable entirely is allowed.
- An unchanged placeholder reuses only the same path owned by the same instance.
  Missing prior values fail closed before deployment changes.
- Dynamic placeholder reuse additionally requires the entire expression's
  structure, order, types, sources, and runtime references to match. After any
  structural/reference edit, submit fresh values for all static parts. A swap of
  structurally identical placeholder-only parts is not observable without stable
  part IDs; clients must enforce replacement values for such edits as well.
- Logs mask all ENV and DYNAMIC_ENV values, even for invalid requests and innocuous
  variable names. Successful full-request responses redact only effective selected
  and mandatory secret values.

## Verification

Run the modern suite with the supported Python environment and local Core/SDK:

```sh
PYTHONPATH=../naeural_core:../ratio1_sdk python -m unittest discover -s extensions/business/deeploy/tests -p 'test_*.py'
```

Rollout keeps compatibility with old clients that omit selectors. Do not roll back
to a backend without selection-aware handling while selected-secret jobs are
being updated; retain canonical metadata and dAuth bundles together.
