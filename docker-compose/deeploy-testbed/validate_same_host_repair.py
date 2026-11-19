"""Exercise same-host recovery with two Docker workloads and disposable tunnel credentials.

The coordinator, custody, SDK config encryption, Git checkouts, configured lists and HTTP servers
are real. Transport, receipt signatures, license events, CStore/R1FS and the connector provider
use local fixture implementations. The host runs Docker CLI. Containers have no
host socket, network or capabilities. Run from the Edge checkout with the matching
Core and SDK on PYTHONPATH and DEEPLOY_TEST_IMAGE set to the local Edge image ID.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from naeural_core import Logger
from naeural_core.business.deployment_lifecycle import repair_config_fingerprint
from naeural_core.utils.plugins_base.bc_wrapper import BCWrapper
from ratio1.bc import DefaultBlockEngine

from extensions.business.deeploy.job_repair import MUTATION, order_fields, worker
from extensions.business.deeploy.tests.lifecycle_custody_support import Engine
from extensions.business.deeploy.tests.test_job_repair import RepairCoordinator, RepairTests
from extensions.business.deeploy.tests.test_same_host_repair_custody import connector


# The setup creates the file served by the next command. Reverse order cannot pass the HTTP assertion.
SETUP = """mkdir site && sed "s/WORKER_HERE/$WORKER/g" page > site/index.html && echo setup >> /tmp/run-order"""
SERVE = "echo serve >> /tmp/run-order && exec python3 -m http.server 8080 --bind 127.0.0.1 --directory site"
EDITED_SERVE = 'test "$INJECT_FAILURE" = no && ' + SERVE
GATEWAY = """
import hashlib, http.server, os, urllib.request
from pathlib import Path

class Connector(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    if hashlib.sha256(os.environ["FIXTURE_CONNECTOR"].encode()).hexdigest() != Path("/bed/provider.sha").read_text():
      self.send_error(403)
      return
    try:
      with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1) as origin:
        body = origin.read()
    except OSError:
      self.send_error(502)
      return
    self.send_response(200)
    self.end_headers()
    self.wfile.write(body)
  def log_message(self, *args):
    pass

http.server.ThreadingHTTPServer(("127.0.0.1", 8081), Connector).serve_forever()
"""


def command(args, *, check=True):
  """Run a test-owned CLI command and capture its output.

  Commands run directly with an upper time bound.

  Parameters
  ----------
  args : list
    Program and its arguments.
  check : bool
    Raise when the program reports failure.

  Returns
  -------
  subprocess.CompletedProcess
    Exit status, stdout and stderr.

  Examples
  --------
  >>> command(["git", "--version"]).returncode
  0
  """
  return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def scenario(folder, key_folder, fail):
  """Drive a local rollout to a committed update or a committed restoration.

  Exercise real Docker/Git/HTTP workloads against the coordinator and custodian;
  fixture infrastructure carries the node reports.

  Parameters
  ----------
  folder, key_folder : str
    Independent temporary directories for mounted workload source and unmounted SDK identities.
  fail : bool
    Force the second worker to exit during deployment.

  Returns
  -------
  None
    Prints a redacted result and tears down both workload containers.

  Examples
  --------
  >>> scenario(source_dir, keys_dir, fail=True)  # doctest: +SKIP
  """
  name = "r1-repair-" + uuid.uuid4().hex[:10]
  cwd = Path(folder)
  repo = cwd / "repo"
  repo.mkdir()
  # The pseudo-addresses used by the fixture map to fresh SDK keypairs outside the worker's mounted source.
  log = Logger("REPAIR", base_folder=key_folder, app_folder="_cache", no_folders_no_save=True, DEBUG=False)
  keys = {peer: BCWrapper(DefaultBlockEngine(name=name + peer, log=log, eth_enabled=False, verbosity=0,
                           config={"PEM_FILE": str(Path(key_folder) / (peer + ".pem"))}), owner=None)
          for peer in ("oracle", "newA")}
  cwd.chmod(0o755)  # Disposable fixtures must be readable by the unprivileged container user.
  (cwd / "gateway.py").write_text(GATEWAY)
  active = cwd / "provider.sha"
  old_token, new_token = connector("a"), connector("b")
  active.write_text(hashlib.sha256(old_token.encode()).hexdigest())
  git = ["git", "-C", str(repo), "-c", "user.email=fixture@localhost", "-c", "user.name=fixture"]
  command(git + ["init", "-q"])
  commits = {}
  for node, content in (("newA", "original-A"), ("newB", "original-B"), ("edited", "updated")):
    (repo / "page").write_text(f"<html>{content} on WORKER_HERE</html>")
    command(git + ["add", "page"])
    command(git + ["commit", "-qm", content])
    commits[node] = command(git + ["rev-parse", "HEAD"]).stdout.strip()

  def container(node):
    if node not in ("newA", "newB"):
      raise AssertionError("The old address received a command")
    return name + "-" + node.lower() + "-app-worker"

  def remove(node):
    command(["docker", "rm", "-f", container(node)], check=False)

  def run_worker(node, pin, commands, token, inject=False):
    # Docker rejects a duplicate host/stream/instance name. The coordinator must retire the old instance first.
    if any(item not in (SETUP, SERVE, EDITED_SERVE) for item in commands):
      raise AssertionError("Unexpected fixture command")
    launch = ("export HOME=/tmp && git config --global --add safe.directory /bed/repo/.git && "
              "git clone -q --no-local /bed/repo /tmp/work && cd /tmp/work && "
              'git -c advice.detachedHead=false checkout -q "$APP_COMMIT" && (python3 /bed/gateway.py &) && '
              + " && ".join(commands))
    args = ["docker", "run", "-d", "--network=none", "--read-only", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--user", "65534:65534", "--cpus=.35", "--memory=128m",
            "--pids-limit=30", "--tmpfs", "/tmp:rw,nosuid,nodev,size=12m", "--name", container(node),
            "--label", "r1-job31-test=" + name, "-v", str(cwd) + ":/bed:ro", "-e", "WORKER=" + node,
            "-e", "APP_COMMIT=" + pin, "-e", "INJECT_FAILURE=" + ("yes" if inject else "no"),
            "-e", "FIXTURE_CONNECTOR", "--entrypoint", "sh", os.environ["DEEPLOY_TEST_IMAGE"], "-ec", launch]
    # Pass the test credential through the child process environment, never in command text or console output.
    subprocess.run(args, check=True, capture_output=True, timeout=30, env={**os.environ, "FIXTURE_CONNECTOR": token})

  def inside(node, *args):
    return command(["docker", "exec", container(node), *args], check=False)

  def fetch(node, port, expected=None):
    url = f"http://127.0.0.1:{port}/"
    code = 'import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=1).read().decode())'
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
      response = inside(node, "python3", "-c", code, url)
      if expected == 403 and "HTTP Error 403" in response.stderr:
        return 403
      if response.returncode == 0:
        return response.stdout.strip()
      state = command(["docker", "inspect", "--format", "{{.State.Status}}", container(node)], check=False)
      if state.returncode or state.stdout.strip() in ("dead", "exited"):
        break
      time.sleep(.12)
    return None

  def commit(node):
    result = inside(node, "git", "-C", "/tmp/work", "rev-parse", "HEAD")
    assert result.returncode == 0
    return result.stdout.strip()

  fixture = RepairTests()
  fixture.setUp()
  c = fixture.c
  initial = fixture.parent
  serial = 1
  observed = []
  prior_rows = {}
  try:
    for node in ("newA", "newB"):
      run_worker(node, commits[node], [SETUP, SERVE], old_token)
      prior_rows[node] = fetch(node, 8081)
      if prior_rows[node] != f"<html>original-{node[-1]} on {node}</html>":
        result = command(["docker", "logs", "--tail", "10", container(node)], check=False)
        raise AssertionError(f"First fixture HTTP check failed on {node}: {result.stderr} {result.stdout}")
    stopped_pin = commit("newB")
    remove("newB")  # Its historical receipt is captured from a real checkout retired before repair.
    fixture.state.public.clear()
    for pipeline in (fixture.stored, fixture.live):
      worker(pipeline).update(PORT=8080, TUNNEL_ENGINE_ENABLED=True, CLOUDFLARE_TOKEN=old_token)
    worker(fixture.stored)["BUILD_AND_RUN_COMMANDS"] = [SERVE, SETUP]
    worker(fixture.live)["BUILD_AND_RUN_COMMANDS"] = [SETUP, SERVE]
    fixture.cid = fixture.state.blobs.add_json(fixture.stored)
    fixture.state.public["DEEPLOY_DEPLOYED_JOBS", "31"] = fixture.cid
    initial.update(previous_pipeline_cid=fixture.cid, sequence=3)
    c._save_operation(initial)
    fixture.receipt(initial, "newB", "retire", "stopped", stopped_pin)
    current_config = {"newA": fixture.live}
    def transport(config, node_address):
      nonlocal serial
      node = node_address
      container(node)  # Refuse every command to an obsolete address.
      op = config["DEEPLOY_OPERATION"]
      action, attempt = op["action"], op["attempt"]
      fields = {}
      pin = ""
      if action == "inspect_worker_v1" and op.get("confirm_prior_stop"):
        assert node == "newB" and command(["docker", "inspect", container(node)], check=False).returncode
        pin = stopped_pin  # The worker is still absent and its historical retire receipt names this commit.
        fields = dict(confirm_prior_stop=True, challenge=op["challenge"], expires_at=op["expires_at"])
        status = "observed"
      elif action in ("inspect_worker_v1", "retire_worker_v1"):
        assert node == "newA"  # The prior stop on B has to be reused.
        pin = commit(node)
        assert keys[node].decrypt_str(op["config_seal"], keys["oracle"].address) == repair_config_fingerprint(current_config[node])
        order = list(order_fields(current_config[node]).values())
        digest = hashlib.sha256(json.dumps(order, separators=(",", ":")).encode()).hexdigest()
        fields = dict(order_digest=digest, challenge=op["challenge"],
                      config_seal_hash=hashlib.sha256(op["config_seal"].encode()).hexdigest())
        if action == "inspect_worker_v1":
          fields["expires_at"] = op["expires_at"]
          status = "observed"
        else:
          assert pin == op["git_commit"] and digest == op["order_digest"]
          fields["parent_operation_id"] = initial["operation_id"]
          remove(node)
          status = "stopped"
      elif action == "start_repaired_worker_v1":
        assert op["parent_operation_id"] == initial["operation_id"]
        token_revision = config["DEEPLOY_SPECS"]["secret_revision"]
        private = fixture.dauth._load_revision_runner_secret_bundle("31", token_revision, node)
        worker_secret = private["job_secrets"]["PLUGINS"][0]["INSTANCES"][0]
        assert worker_secret["CLOUDFLARE_TOKEN"] == new_token
        if attempt == "deploy":
          assert worker_secret["EXPOSED_PORTS"]["8080"]["token"] == new_token
        pin = worker(config).get("DEEPLOY_RUNTIME_ARTIFACTS", {}).get("git_commit", commits["edited"])
        inject = fail and node == "newB" and attempt == "deploy"
        run_worker(node, pin, worker(config)["BUILD_AND_RUN_COMMANDS"], worker_secret["CLOUDFLARE_TOKEN"], inject)
        page = fetch(node, 8081)
        if inject:
          assert page is None
          exit_code = command(["docker", "wait", container(node)]).stdout.strip()
          assert exit_code == "1", exit_code  # Confirm a real command failure, including a container still shutting down.
          status = "failed"
        else:
          assert page and page.endswith(f" on {node}</html>"), (node, attempt, page)
          assert commit(node) == pin, (node, attempt, "checkout differs")
          assert inside(node, "cat", "/tmp/run-order").stdout.splitlines() == ["setup", "serve"]
          status = "ready"
      else:
        assert action == "stop"
        remove(node)
        status = "stopped"
      serial += 1
      item = fixture.receipt(op, node, attempt, status, pin, **fields)
      item.update(sequence=serial, revision=op["revision"])
      Engine(node).sign(item)
      observed.append((node, action, attempt, status))

    def configure(coordinator):
      fixture.configure(coordinator)
      coordinator.bc.encrypt_str = lambda value, node: keys["oracle"].encrypt_str(value, keys[node].address)
      coordinator.known = {"newA": [fixture.live]}
      coordinator.cmdapi_start_pipeline = transport
      def check_repo(config, pins):
        for pin in pins:
          assert command(git + ["cat-file", "-t", pin]).stdout.strip() == "commit"
      coordinator._verify_repair_source = check_repo  # Local Git replaces external GitHub in this offline run.

    configure(c)
    proposal, corrected, *_ = c._assess_job_repair(31, "owner")
    addresses = [row["current"] for row in proposal["placements"]]
    assert len(set(addresses)) == 2 and {"newA","newB"} == set(addresses)
    active.write_text(hashlib.sha256(new_token.encode()).hexdigest())
    assert fetch("newA", 8081, expected=403) == 403 and fetch("newA", 8080) == prior_rows["newA"]
    request = dict(job_id=31, app_id="app", expected_revision=0, request_id="test-edit", target_nodes=addresses,
                   repair=dict(proposal=proposal, same_host=True, rotate_main_tunnel=True))
    repair = c._prepare_job_repair(request, "owner")
    desired = copy.deepcopy(corrected)
    desired["DEEPLOY_SPECS"]["current_target_nodes"] = addresses
    worker(desired).update(BUILD_AND_RUN_COMMANDS=[SETUP, EDITED_SERVE], CHAINSTORE_PEERS=addresses,
                          CLOUDFLARE_TOKEN=new_token, EXPOSED_PORTS={"8080": {"is_main_port": True, "token": new_token}})
    accepted = c._admit_prepared_deployment(request, {"escrow_owner":"owner"}, "app", {n:desired for n in addresses},
                                            fixture.stored, False, mutation=MUTATION, repair=repair)
    child = c._operation_records()[accepted["operation_id"]]
    c._advance_deployment_operation(child)
    c = RepairCoordinator(fixture.state)  # No per-process state survives the coordinator restart.
    configure(c)
    for _ in range(18):
      child = c._operation_records()[accepted["operation_id"]]
      if child["phase"] == "completed":
        break
      fixture.state.now += 1
      c._advance_deployment_operation(child)
    assert (child["phase"], child["outcome"]) == ("completed", "failed" if fail else "succeeded")
    if fail:
      assert child["recovery"] == "completed" and child["error"]["code"] == "INSTANCE_FAILED"
    c._advance_serialized_operation(c._operation_records()[initial["operation_id"]])
    assert c._operation_records()[initial["operation_id"]]["outcome"] == "superseded"
    assert len(command(["docker","ps","-q","--filter","label=r1-job31-test="+name]).stdout.splitlines()) == 2
    rows = {}
    for node in addresses:
      page = fetch(node, 8081)
      assert page == (prior_rows[node] if fail else f"<html>updated on {node}</html>")
      rows[node] = dict(html=page, git_commit=commit(node), commands=inside(node, "cat", "/tmp/run-order").stdout.splitlines())
      assert rows[node]["git_commit"] == commits[node if fail else "edited"]
    print(json.dumps(dict(scenario="forced_failure" if fail else "success", outcome=child["outcome"],
                          recovery=child["recovery"], pinned=rows, requests=observed)), flush=True)
  finally:
    fixture.doCleanups()
    for node in ("newA", "newB"):
      remove(node)


if __name__ == "__main__":
  for inject_failure in (False, True):
    with tempfile.TemporaryDirectory(prefix="same-host-repair-") as disposable, tempfile.TemporaryDirectory() as key_folder:
      scenario(disposable, key_folder, inject_failure)
