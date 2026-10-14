"""Certificate-aware SQL readiness for the managed CockroachDB service."""
import hashlib
from urllib.parse import quote, urlencode


# Pass secrets through Docker's exec environment, never the command, output,
# or plugin log. The image includes coreutils timeout and the Cockroach CLI.
_PROBE_COMMAND = r'''
set -eu
ca_hash=$(sha256sum -- "$R1_CERTS_DIR/ca.crt")
node_hash=$(sha256sum -- "$R1_CERTS_DIR/node.crt")
[ "${ca_hash%% *}" = "$R1_CA_SHA256" ]
[ "${node_hash%% *}" = "$R1_NODE_SHA256" ]
exec /cockroach/cockroach sql --execute='SELECT 1' --format=csv
'''


def is_cockroachdb_service(image, env):
  """Match Deeploy's managed-service recognition, including prior configurations."""
  repository = image.strip().lower().split("@", 1)[0] if isinstance(image, str) else ""
  if ":" in repository.rsplit("/", 1)[-1]:
    repository = repository.rsplit(":", 1)[0]
  if isinstance(image, str):
    return repository in (
      "ghcr.io/ratio1/r1db", "ghcr.io/ratio1/deeploy-cockroachdb-service",
    )
  return isinstance(env, dict) and ("CRDB_NODE_COUNT" in env or "CRDB_HOSTNAMES" in env)


def probe_cockroachdb_readiness(container, env):
  """Prove this node uses its planned CA/certificate and accepts authenticated SQL.

  Unlike a TCP probe, this cannot succeed against an old certificate generation.
  R1DB's entrypoint rewrites certificate files before starting SQL. The CLI then
  authenticates to this node using verify-full against that exact planned CA.
  Each generation has a fresh CA, so an old running process fails the TLS check.
  Exceptions and command output are deliberately not exposed: they may contain
  credentials. The caller owns polling intervals and deployment deadlines.
  """
  try:
    required = ("CRDB_NODE_ID", "CRDB_DATABASE", "CRDB_USER", "CRDB_PASSWORD",
                "CRDB_CA_CRT", "CRDB_NODE_CRT")
    if not isinstance(env, dict) or any(not isinstance(env.get(key), str) or not env[key] for key in required):
      return False
    node_id = int(env["CRDB_NODE_ID"])
    port = int(env.get("CRDB_SQL_PORT", "26257"))
    if node_id < 1 or not 1 <= port <= 65535:
      return False
    certs_dir = env.get("CRDB_CERTS_DIR", "/cockroach/certs")
    if not isinstance(certs_dir, str) or not certs_dir.startswith("/"):
      return False
    query = urlencode({"sslmode": "verify-full", "sslrootcert": certs_dir + "/ca.crt", "connect_timeout": "5"})
    url = "postgresql://{}:{}@roach{}:{}/{}?{}".format(
      quote(env["CRDB_USER"], safe=""), quote(env["CRDB_PASSWORD"], safe=""),
      node_id, port, quote(env["CRDB_DATABASE"], safe=""), query,
    )
    # Shell command substitution in the image strips trailing LF from supplied
    # PEM, then write_secret_file adds exactly one LF.
    digest = lambda value: hashlib.sha256((value.rstrip("\n") + "\n").encode("ascii")).hexdigest()
    result = container.exec_run(
      ["timeout", "--signal=TERM", "--kill-after=1s", "8s", "/bin/bash", "-c", _PROBE_COMMAND],
      environment={
        "COCKROACH_URL": url,
        "R1_CERTS_DIR": certs_dir,
        "R1_CA_SHA256": digest(env["CRDB_CA_CRT"]),
        "R1_NODE_SHA256": digest(env["CRDB_NODE_CRT"]),
      },
      # Keep the exec stream attached until the process exits. Disabling both
      # streams allows Docker to return before exec_inspect has an exit code.
      # Captured bytes are intentionally discarded, never returned or logged.
      stdout=True, stderr=True,
    )
    return result.exit_code == 0
  except Exception:
    return False
