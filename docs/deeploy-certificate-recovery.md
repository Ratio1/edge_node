# CockroachDB certificate regeneration and recovery

This supplements [the deployment lifecycle specification](deeploy-deployment-lifecycle-spec.md).
The user explicitly chose to include automatic recovery for certificate regeneration.
Regeneration uses the same asynchronous update operation, receiving-oracle coordinator,
immutable revision storage, node observations, and polling endpoint as other updates.

## Runtime contract verified from source

The managed service image is maintained in `Ratio1/r1db`. Inspected sources:

- [v1.0.7 entrypoint, commit 7b555b82e649749585df6a2aa42ed35067cfa9a8](https://github.com/Ratio1/r1db/blob/7b555b82e649749585df6a2aa42ed35067cfa9a8/entrypoint.sh).
- [main entrypoint, commit 9e488ddbde645b915e65c137c879f1e79551cdac](https://github.com/Ratio1/r1db/blob/9e488ddbde645b915e65c137c879f1e79551cdac/entrypoint.sh).

Both versions read supplied certificate environment values (or their staged secret files),
then unconditionally overwrite `ca.crt`, `node.crt`, and `node.key` under `CRDB_CERTS_DIR`.
Node 1 also overwrites `client.root.crt` and `client.root.key`. These writes happen before
the SQL server starts. The writer strips trailing newlines through shell substitution,
adds one newline, and sets file permissions to 0600. The certificate directory defaults
to `/cockroach/certs`; database data defaults to `/cockroach/cockroach-data`.

Consequently, restoring the previous exact per-node configuration and protected certificate
bundle restores the previous on-disk certificates even when that directory is persistent.
No extra certificate backup inside the volume, CA private key retention, volume deletion,
data restore, or custom overwrite command is needed. The previous client/root certificate
and key are retained with the old revision; a CA private key is never stored.

The image has no Docker HEALTHCHECK, and an open SQL TCP listener can precede completed
bootstrap. Generic TCP, delay, or running-container checks cannot confirm regeneration.

## Execution and recovery

1. Admission persists the new certificate bundle and the exact previous bundle in protected
   dAuth revision records. R1FS plans, accepted responses, node status, and logs contain no
   plaintext certificate private keys or credentials. Preserve per-node identity, endpoints,
   tunnel credentials, volume names/mounts, store paths, and previous certificate metadata.
2. Retire the previous attempt on **every previous node** and wait for positive stop evidence
   before starting the new generation. Every target receives the one admitted new bundle;
   retries never generate a replacement bundle during execution.
3. Every managed Cockroach node must pass the certificate-aware SQL probe below. Only all-node
   readiness permits metadata promotion and successful runtime outcome. Acceptance is not success.
4. On failure, stop/fence the new attempt on **every target**, including targets that did not
   report starting. Unreachable targets block restoration and retain both secret revisions.
5. After every required stop acknowledgment, restart the previous exact node configurations
   using the protected previous certificate bundle. The image rewrites its certificate files
   before SQL startup. Preserve existing database volumes and the original client/internal endpoints.
6. Apply the same certificate-aware SQL readiness to every restored node. Only then record
   completed recovery, promote the previous metadata, and revoke unused certificate revisions.
   The attempted update remains failed even though recovery succeeded.

Certificate regeneration intent excludes HTTP request IDs, expected-revision preconditions,
nonces/signatures, and the retired plugin-response flag. The operation admission layer still
enforces request idempotency and revision preconditions separately. Service configuration or
credential changes change the certificate intent. No opt-in or migration mode is introduced.

## Readiness implementation

`extensions/business/container_apps/cockroachdb_readiness.py` provides
`probe_cockroachdb_readiness(container, env)`. The runner must apply it for managed Cockroach
instances before allowing generic health modes to declare readiness, including restored instances.

The probe verifies SHA-256 of the actual `ca.crt` and `node.crt` against the planned PEM bytes,
then executes an authenticated `SELECT 1` using the image's Cockroach CLI against this node's
`roach<CRDB_NODE_ID>:CRDB_SQL_PORT` address and configured application database/user. Its connection
uses `sslmode=verify-full` and that exact CA file. Each regeneration creates a fresh CA, so a process
still serving the previous certificate generation cannot pass even if new files have been written.
This also exercises SQL authentication and database existence after bootstrap. The CLI's supported
`COCKROACH_URL` environment variable carries the percent-encoded password; secrets do not enter
shell command text, returned probe output, or plugin logs. Docker output streams remain attached
until exec completion; their captured bytes are discarded without logging. No root client credentials are distributed
to additional nodes. The command has an eight-second deadline with a one-second kill grace.

Failure returns false; polling intervals and the deployment readiness deadline remain owned by the
runner/coordinator. A timeout cannot be upgraded to readiness by a generic health fallback.

## Verification and limits

Restoration also pins runtime content. A mutable image tag such as `:stable` is not an
immutable revision. The runner records the resolved Docker image ID in its existing local
persistent state before launching a tracked attempt and starts that exact ID thereafter.
Node-owned observations capture the actual running image ID; worker runners additionally
capture and verify the actual Git HEAD before publishing readiness. Retirement preserves
these safe identifiers in the node journal/report, and restoration supplies them through
the server-owned `DEEPLOY_RUNTIME_ARTIFACTS` instance field. The report getter reads cached
identifiers and performs no Docker, disk, or Git I/O on the reporter thread.

A restored node requires its local image ID to still exist; it never substitutes a tag or
registry result if the old image was removed. Worker restoration checks out the exact prior
commit and does not consult the branch's current head. Tracked attempts disable autonomous
image/Git updates; a change requires a new deployment operation. Database volume names,
paths, and contents remain untouched. These content bindings do not make arbitrary build
commands deterministic: a project installing unpinned external dependencies can still
produce different build outputs from the same source and base image.

- `extensions/business/deeploy/tests/test_cockroachdb_recovery.py`: regeneration creates new CA/node
  keys without changing previous material, storage, or endpoints; missing secrets fail closed;
  probe credentials remain out of command text; three-node partial failure waits for every stop
  before exact restoration and waits for every restored readiness observation.
- Request tests cover asynchronous regeneration acceptance with no immediate dispatch/staging,
  protected certificate material, and changed-intent rejection.
- Container runner tests prove managed SQL cannot bypass certificate readiness through disabled,
  delay, or TCP modes; restoration is subject to the same gate. Runtime-artifact tests cover
  tag movement, restart persistence, missing-image refusal, disabled automatic updates, detached
  Git restoration, and source verification before readiness.
- `docker-compose/deeploy-crdb-verify-full/validate_certificate_recovery.py`: opt-in offline binary
  test using the locally cached `cockroachdb/cockroach:v23.1.28` image. It creates one uniquely named,
  network-disabled container with tmpfs database storage, exercises old/new/old certificate reload,
  rejects a process still using old TLS after new files are written, and verifies a stored row
  survives both transitions. It removes only that exact disposable container and never pulls an
  image or accesses existing volumes, external tunnels, chain state, or live deployments.

The isolated binary test is not a full R1DB entrypoint, Cloudflare, or three-node integration test.
The overwrite behavior is grounded in the pinned image source; the coordinator tests exercise the
three-node barriers independently. Run the existing isolated three-node workflow separately when
validating a release image and tunnel integration.

R1DB's independent corrupt-store recovery records bind their active store to a CA fingerprint.
If a node's stored recovery state is incompatible with a requested certificate generation, its
entrypoint refuses startup. Deeploy must report that failure and attempt the exact old revision;
it must never erase or rewrite database recovery markers to force a certificate rollout. If even
the old revision cannot start (for example, because the underlying data is corrupt), recovery
remains blocked with secrets retained and explicit node errors. Automatic certificate recovery
does not promise to repair unrelated database corruption or reverse application data changes.

### Reproducible offline commands

From the Edge worktree, with the sibling Core/SDK worktrees and the locally cached runtime:

```bash
docker run --rm --network none --entrypoint python3 \
  -v "$PWD/../naeural_core:/workspace/naeural_core:ro" \
  -v "$PWD/../naeural_core:/workspace/edge_node/naeural_core:ro" \
  -v "$PWD/../ratio1_sdk:/workspace/ratio1_sdk:ro" \
  -v "$PWD:/workspace/edge_node:ro" \
  -e PYTHONPATH=/workspace/naeural_core:/workspace/ratio1_sdk \
  -w /workspace/edge_node local_edge_node_dauth471_core219_arm64:1599b7e \
  -m unittest discover -s extensions/business/container_apps/tests -p 'test_*.py'
```

Use the same command with `extensions/business/deeploy/tests` for the Deeploy suite, or
`-m unittest extensions.business.container_apps.test_worker_app_runner` for Worker regressions.

The optional binary validation additionally needs the local Docker socket. It uses only the
cached `cockroachdb/cockroach:v23.1.28` image; the verified local image ID was
`sha256:f049c3d560a4bf568d1466b548d306f76c1c43424f9d0dae2fb3c09d9d49d77c`.

```bash
docker run --rm --network none --entrypoint python3 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/../naeural_core:/workspace/naeural_core:ro" \
  -v "$PWD/../ratio1_sdk:/workspace/ratio1_sdk:ro" \
  -v "$PWD:/workspace/edge_node:ro" \
  -e PYTHONPATH=/workspace/edge_node:/workspace/naeural_core:/workspace/ratio1_sdk \
  -w /workspace/edge_node local_edge_node_dauth471_core219_arm64:1599b7e \
  docker-compose/deeploy-crdb-verify-full/validate_certificate_recovery.py
```

Verified output: `PASS: expected certificates + authenticated TLS SQL; old/new/old reload; data preserved`.
