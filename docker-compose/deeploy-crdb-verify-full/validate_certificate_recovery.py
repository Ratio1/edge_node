#!/usr/bin/env python3
"""Offline certificate reload/restore proof against the cached Cockroach binary.

Creates exactly one disposable, network-disabled container with tmpfs storage.
No image pull, host port, external tunnel, existing volume, or chain operation.
The actual R1DB entrypoint contract is documented separately; this exercises
the SQL probe and unchanged database storage across old/new/old certificates.
"""
import io
import tarfile
import time
import uuid

import docker

from extensions.business.container_apps.cockroachdb_readiness import probe_cockroachdb_readiness
from extensions.business.deeploy.tests.support import make_deeploy_plugin


IMAGE = "cockroachdb/cockroach:v23.1.28"


def main():
  client = docker.from_env()
  # Fail instead of pulling an image: this validation deliberately stays offline.
  image = client.images.get(IMAGE)
  plugin = make_deeploy_plugin()
  bundles = [plugin._generate_cockroachdb_cert_bundle(["A", "B", "C"], "client.test")["A"] for _ in range(2)]
  old, new = [{**bundle, "CRDB_NODE_ID": "1", "CRDB_DATABASE": "appdb", "CRDB_USER": "app_user",
               "CRDB_PASSWORD": "disposable-probe-password", "CRDB_CERTS_DIR": "/probe/certs"} for bundle in bundles]
  container = client.containers.run(
    image.id, name="deeploy-cert-recovery-" + uuid.uuid4().hex[:12],
    entrypoint="/bin/bash", command=["-c", "sleep infinity"], detach=True,
    network_disabled=True, extra_hosts={"roach1": "127.0.0.1"},
    tmpfs={"/probe": "rw,size=512m,mode=700"}, labels={"ratio1.test": "certificate-recovery"},
  )
  try:
    assert container.exec_run(["/bin/bash", "-c", "printf '127.0.0.1 localhost roach1\\n' >> /etc/hosts"]).exit_code == 0

    def write_certificates(env):
      archive = io.BytesIO()
      with tarfile.open(fileobj=archive, mode="w") as tar:
        directory = tarfile.TarInfo("certs")
        directory.type, directory.mode = tarfile.DIRTYPE, 0o700
        tar.addfile(directory)
        for key, filename in {
          "CRDB_CA_CRT": "ca.crt", "CRDB_NODE_CRT": "node.crt", "CRDB_NODE_KEY": "node.key",
          "CRDB_CLIENT_ROOT_CRT": "client.root.crt", "CRDB_CLIENT_ROOT_KEY": "client.root.key",
        }.items():
          # The production entrypoint performs this same unconditional overwrite.
          data = (env[key].rstrip("\n") + "\n").encode("ascii")
          entry = tarfile.TarInfo("certs/" + filename)
          entry.size, entry.mode = len(data), 0o600
          tar.addfile(entry, io.BytesIO(data))
      # Docker archive extraction does not target a running tmpfs mount.
      container.put_archive("/tmp", archive.getvalue())
      assert container.exec_run(["/bin/bash", "-c",
        "mkdir -p /probe/certs; cp /tmp/certs/* /probe/certs/; chmod 600 /probe/certs/*; rm -rf /tmp/certs"]).exit_code == 0

    def start():
      container.exec_run(["/bin/bash", "-c",
        "echo $$ > /probe/pid; exec /cockroach/cockroach start-single-node "
        "--certs-dir=/probe/certs --store=/probe/store --listen-addr=127.0.0.1:26257 "
        "--advertise-addr=roach1:26257 --http-addr=127.0.0.1:8080 "
        "--cache=32MiB --max-sql-memory=32MiB > /probe/database.log 2>&1"], detach=True)

    def stop():
      result = container.exec_run(["/bin/bash", "-c",
        "kill -TERM $(cat /probe/pid); timeout 20s /bin/bash -c "
        "'while kill -0 $(cat /probe/pid) 2>/dev/null; do sleep .1; done'"])
      assert result.exit_code == 0, "database process did not stop"

    def sql(query):
      return container.exec_run(["timeout", "8s", "/cockroach/cockroach", "sql",
        "--certs-dir=/probe/certs", "--host=roach1:26257", "--format=csv", "--execute", query])

    def wait(check):
      deadline = time.monotonic() + 45
      while time.monotonic() < deadline:
        if check():
          return
        time.sleep(.3)
      raise AssertionError("readiness did not converge within 45 seconds")

    write_certificates(old)
    start()
    wait(lambda: sql("SELECT 1").exit_code == 0)
    assert sql("CREATE DATABASE appdb; CREATE USER app_user WITH PASSWORD 'disposable-probe-password'; "
               "GRANT ALL ON DATABASE appdb TO app_user; CREATE TABLE appdb.public.proof (id INT PRIMARY KEY); "
               "INSERT INTO appdb.public.proof VALUES (42)").exit_code == 0
    wait(lambda: probe_cockroachdb_readiness(container, old))
    assert not probe_cockroachdb_readiness(container, new), "wrong planned certificate passed"
    write_certificates(new)
    assert not probe_cockroachdb_readiness(container, new), "new files hid a process still serving old TLS"
    stop()
    start()
    wait(lambda: probe_cockroachdb_readiness(container, new))
    assert not probe_cockroachdb_readiness(container, old), "old generation passed after reload"
    stop()
    write_certificates(old)
    start()
    wait(lambda: probe_cockroachdb_readiness(container, old))
    assert not probe_cockroachdb_readiness(container, new), "failed generation passed after restoration"
    proof = sql("SELECT id FROM appdb.public.proof")
    assert proof.exit_code == 0 and b"42" in proof.output, "persistent data was not preserved"
    print("PASS: expected certificates + authenticated TLS SQL; old/new/old reload; data preserved")
  finally:
    # This handle refers only to the exact disposable container created above.
    container.remove(force=True)
    client.close()


if __name__ == "__main__":
  main()
