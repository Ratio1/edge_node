#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from cryptography import x509

from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


NETWORK = "deeploy-crdb-verify-full"
IMAGE = os.environ.get(
  "CRDB_IMAGE",
  "ghcr.io/ratio1/r1-meshdb@sha256:3be00a63467628d0f5c3382be8ae7a885c5b658762dfd095fba0cb0b5549fab4",
)
CLIENT_IMAGE = os.environ.get("CRDB_CLIENT_IMAGE", "postgres:16-alpine")
SNIFFER_IMAGE = os.environ.get("CRDB_SNIFFER_IMAGE", "nicolaka/netshoot:v0.13")
MAX_OFFSET = os.environ.get("CRDB_MAX_OFFSET", "500ms")
HOSTNAME = "crdb-client.test"
NODES = ["verify_crdb_1", "verify_crdb_2", "verify_crdb_3"]
ALIASES = ["roach1", "roach2", "roach3"]
RELAY = "verify_crdb_relay"
CLIENT = "verify_crdb_client"
PASSWORD = "verify_full_disposable_password"

if "@sha256:" not in IMAGE:
  raise ValueError("CRDB_IMAGE must be an immutable digest reference")
if MAX_OFFSET != "500ms":
  raise ValueError("CRDB_MAX_OFFSET must remain at the production 500ms bound")


def run(args, *, check=True, capture=False, input_text=None, timeout=None):
  result = subprocess.run(
    args,
    check=False,
    text=True,
    input=input_text,
    stdout=subprocess.PIPE if capture else None,
    stderr=subprocess.PIPE if capture else None,
    timeout=timeout,
  )
  if check and result.returncode != 0:
    detail = (result.stderr or result.stdout or "").strip()
    raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(args)}\n{detail}")
  return result


def docker(*args, **kwargs):
  return run(["docker", *args], **kwargs)


def write_bundle(root, bundle):
  for index, node in enumerate(NODES):
    cert_dir = root / f"certs-{index + 1}"
    cert_dir.mkdir(parents=True, exist_ok=True)
    env = bundle[node]
    (cert_dir / "ca.crt").write_text(env["CRDB_CA_CRT"], encoding="ascii")
    (cert_dir / "node.crt").write_text(env["CRDB_NODE_CRT"], encoding="ascii")
    (cert_dir / "node.key").write_text(env["CRDB_NODE_KEY"], encoding="ascii")
    if index == 0:
      (cert_dir / "client.root.crt").write_text(env["CRDB_CLIENT_ROOT_CRT"], encoding="ascii")
      (cert_dir / "client.root.key").write_text(env["CRDB_CLIENT_ROOT_KEY"], encoding="ascii")
      os.chmod(cert_dir / "client.root.key", 0o600)
    os.chmod(cert_dir / "node.key", 0o600)
  (root / "client-ca.crt").write_text(bundle[NODES[0]]["CRDB_CA_CRT"], encoding="ascii")


def generate_bundle(root, regeneration_id=None):
  plugin = make_deeploy_plugin()
  allocation = {
    "version": 1,
    "service": "cockroachdb",
    "status": "allocated",
    "nodeOrder": list(NODES),
    "clientTunnel": {"url": f"{HOSTNAME}:26257"},
    "internalTunnels": [],
  }
  request = {
    "service_kind": "cockroachdb",
    "target_nodes": list(NODES),
    "pipeline_params": {"deeploy_cockroachdb": allocation},
    "plugins": [
      make_plugin_entry(
        "CONTAINER_APP_RUNNER",
        IMAGE=IMAGE,
        ENV={
          "CRDB_DATABASE": "appdb",
          "CRDB_USER": "app_user",
          "CRDB_PASSWORD": PASSWORD,
        },
      )
    ],
  }
  if regeneration_id:
    request["cockroachdb_certificate_regeneration_id"] = regeneration_id
  inputs = make_inputs(**request)
  service_kind = plugin._resolve_deeploy_service_kind(inputs=inputs)
  plugin._prepare_managed_service_secure_config(service_kind, inputs, NODES)
  by_node = inputs["plugins"][0]["PER_NODE_CONFIG"]["byNode"]
  bundle = {node: by_node[node]["ENV"] for node in NODES}
  write_bundle(root, bundle)
  cert = x509.load_pem_x509_certificate(bundle[NODES[0]]["CRDB_NODE_CRT"].encode("ascii"))
  sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
  if HOSTNAME not in sans.get_values_for_type(x509.DNSName):
    raise AssertionError("Generated node certificate is missing the client DNS SAN")
  return hashlib.sha256(bundle[NODES[0]]["CRDB_CA_CRT"].encode("ascii")).hexdigest()


def start_node(root, index):
  name = NODES[index]
  alias = ALIASES[index]
  docker("rm", "-f", name, check=False)
  docker(
    "run", "-d", "--name", name, "--hostname", alias,
    "--network", NETWORK, "--network-alias", alias,
    "-v", f"{root / f'certs-{index + 1}'}:/certs:ro",
    "-v", f"verify_crdb_store_{index + 1}:/cockroach/cockroach-data",
    "--entrypoint", "/cockroach/cockroach", IMAGE,
    "start", "--certs-dir=/certs", "--store=/cockroach/cockroach-data",
    "--listen-addr=0.0.0.0:26257", f"--advertise-addr={alias}:26257",
    "--http-addr=0.0.0.0:8080", "--join=roach1:26257,roach2:26257,roach3:26257",
    f"--max-offset={MAX_OFFSET}", "--cache=.1", "--max-sql-memory=.1",
  )


def root_sql(sql, *, check=True):
  return docker(
    "exec", NODES[0], "/cockroach/cockroach", "sql", "--certs-dir=/certs",
    "--host=roach1:26257", "--execute", sql, check=check, capture=True,
  )


def client_sql(sql, *, hostname=HOSTNAME, ca_path="/ca/client-ca.crt", sslmode="verify-full", password=PASSWORD, check=True):
  uri = f"postgresql://app_user@{hostname}:26257/appdb?sslmode={sslmode}&sslrootcert={ca_path}"
  return docker(
    "exec", "-e", f"PGPASSWORD={password}", CLIENT,
    "psql", "--set", "ON_ERROR_STOP=1", "--dbname", uri, "--command", sql,
    check=check, capture=True,
  )


def wait_for(predicate, label, timeout=150):
  deadline = time.monotonic() + timeout
  last = None
  while time.monotonic() < deadline:
    try:
      if predicate():
        return
    except Exception as exc:
      last = exc
    time.sleep(1)
  raise RuntimeError(f"Timed out waiting for {label}: {last}")


def cleanup(root):
  docker("rm", "-f", CLIENT, RELAY, *NODES, check=False)
  for index in range(1, 4):
    docker("volume", "rm", "-f", f"verify_crdb_store_{index}", check=False)
  shutil.rmtree(root, ignore_errors=True)


def main():
  root = Path(tempfile.mkdtemp(prefix="deeploy-crdb-verify-full-", dir="/tmp"))
  try:
    for service in ("deeploy_verify_node_1", "deeploy_verify_node_2", "deeploy_verify_node_3"):
      state = docker("compose", "-f", "docker-compose/deeploy-crdb-verify-full.yaml", "ps", "-q", service, capture=True)
      if not state.stdout.strip():
        raise RuntimeError(f"Edge runtime {service} is not running")

    first_fingerprint = generate_bundle(root)
    for index in range(3):
      start_node(root, index)

    wait_for(
      lambda: docker(
        "exec", NODES[0], "/cockroach/cockroach", "init", "--certs-dir=/certs",
        "--host=roach1:26257", check=False, capture=True, timeout=10,
      ).returncode == 0 or root_sql("select 1", check=False).returncode == 0,
      "cluster initialization",
    )
    wait_for(lambda: root_sql("select 1", check=False).returncode == 0, "initialized cluster")

    root_sql(
      "CREATE DATABASE IF NOT EXISTS appdb; "
      "CREATE USER IF NOT EXISTS app_user WITH PASSWORD 'verify_full_disposable_password'; "
      "GRANT ALL ON DATABASE appdb TO app_user; "
      "CREATE TABLE IF NOT EXISTS appdb.verify_items (id INT PRIMARY KEY, note STRING); "
      "GRANT ALL ON TABLE appdb.verify_items TO app_user; "
      "UPSERT INTO appdb.verify_items SELECT i, 'persisted-' || i::STRING FROM generate_series(1, 1000) AS g(i);"
    )

    docker("run", "-d", "--name", RELAY, "--network", NETWORK,
           "--network-alias", HOSTNAME, "--network-alias", "wrong-client.test",
           "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "-v", f"{root}:/capture",
           "--entrypoint", "socat", SNIFFER_IMAGE,
           "TCP-LISTEN:26257,fork,reuseaddr", "TCP:roach1:26257")
    docker("run", "-d", "--name", CLIENT, "--network", NETWORK,
           "-v", f"{root}:/ca:ro", "--entrypoint", "sleep", CLIENT_IMAGE, "3600")
    wait_for(lambda: client_sql("select 1", check=False).returncode == 0, "verify-full client")

    if client_sql("select 1", hostname="wrong-client.test", check=False).returncode == 0:
      raise AssertionError("verify-full accepted the wrong hostname")
    if client_sql("select 1", sslmode="disable", check=False).returncode == 0:
      raise AssertionError("server accepted plaintext SQL")
    fake_bundle = make_deeploy_plugin()._generate_cockroachdb_cert_bundle(NODES, HOSTNAME)
    (root / "wrong-ca.crt").write_text(fake_bundle[NODES[0]]["CRDB_CA_CRT"], encoding="ascii")
    if client_sql("select 1", ca_path="/ca/wrong-ca.crt", check=False).returncode == 0:
      raise AssertionError("verify-full accepted an unrelated CA")

    canary = "VERIFY_FULL_SQL_CANARY_7f3e90"
    capture = root / "tls.pcap"
    sniffer = subprocess.Popen(
      [
        "docker", "exec", RELAY, "timeout", "-s", "INT", "8",
        "tcpdump", "-U", "-i", "any", "-s", "0", "-w", "/capture/tls.pcap",
        "tcp port 26257",
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
    )
    time.sleep(2)
    client_sql(f"select '{canary}';")
    _, sniffer_stderr = sniffer.communicate(timeout=15)
    if sniffer.returncode not in (0, 124):
      raise AssertionError(f"TLS packet capture failed: {sniffer_stderr.strip()}")
    if not capture.exists() or capture.stat().st_size <= 24:
      raise AssertionError("TLS packet capture contains no packets")
    if canary.encode("ascii") in capture.read_bytes() or PASSWORD.encode("ascii") in capture.read_bytes():
      raise AssertionError("TLS packet capture exposed SQL or password plaintext")

    old_ca = root / "old-ca.crt"
    shutil.copy2(root / "client-ca.crt", old_ca)
    docker("stop", "--timeout", "20", *NODES)
    second_fingerprint = generate_bundle(
      root,
      regeneration_id="22222222-2222-4222-8222-222222222222",
    )
    if first_fingerprint == second_fingerprint:
      raise AssertionError("Certificate regeneration reused the CA")
    start_node(root, 0)
    start_node(root, 1)
    wait_for(lambda: root_sql("select 1", check=False).returncode == 0, "rotated two-node quorum")
    start_node(root, 2)
    wait_for(lambda: "3" in root_sql("select count(*) from crdb_internal.gossip_nodes", check=False).stdout,
             "delayed third-node convergence")
    wait_for(lambda: client_sql("select count(*) from verify_items", check=False).returncode == 0,
             "new-CA client")
    if client_sql("select 1", ca_path="/ca/old-ca.crt", check=False).returncode == 0:
      raise AssertionError("old CA remained trusted after full regeneration")
    rows = client_sql("select count(*) from verify_items").stdout
    if "1000" not in rows:
      raise AssertionError(f"Expected 1000 persisted rows after rotation, got: {rows}")

    print(
      "verify-full workflow ok "
      f"(nodes=3 rows=1000 max_offset={MAX_OFFSET} ca_before={first_fingerprint[:12]} "
      f"ca_after={second_fingerprint[:12]} capture_bytes={capture.stat().st_size})"
    )
  finally:
    cleanup(root)


if __name__ == "__main__":
  main()
