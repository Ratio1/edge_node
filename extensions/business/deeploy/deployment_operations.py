"""Durable Deeploy operations coordinated by their receiving oracle.

Operation snapshots and node reports are signed, sequence-ordered CStore records.
There is deliberately no distributed lock, election, or automatic takeover.
The receiving oracle resumes its own unfinished operations after restart;
other oracles only aggregate replicated observations for polling.
"""
import copy
import hashlib
import json
import threading
import uuid

from ratio1.const.base import dAuth
from .selected_secrets import inherit_selections

from extensions.business.dauth.dauth_registry import (
  dauth_registry_write_kwargs, get_dauth_registry_internal_peers,
)
from .deeploy_const import DEEPLOY_KEYS, CONTAINERIZED_APPS_SIGNATURES


OPERATIONS_HKEY = "DEEPLOY_OPERATIONS"
NODE_OPERATIONS_HKEY = "DEEPLOY_NODE_OPERATIONS"
SECRET_REVISIONS_HKEY = "DAUTH_JOB_SECRET_REVISIONS"
class DeploymentAuthenticationError(ValueError):
  """The reusable read authorization is invalid or expired."""


class DeploymentConflictError(ValueError):
  """A request conflicts with observed operation identity or revision."""


SIGNATURE_KEYS = {"EE_SIGN", "EE_SENDER", "EE_HASH", "EE_SIGN_CANON_V"}


def request_digest(request):
  """Hash semantic intent without transport authentication or nonce fields."""
  excluded = SIGNATURE_KEYS | {"EE_ETH_SIGN", "nonce", "address", "signature"}
  semantic = {key: value for key, value in request.items() if key not in excluded}
  return hashlib.sha256(json.dumps(
    semantic, sort_keys=True, separators=(",", ":"), allow_nan=False,
  ).encode()).hexdigest()


def required_instances(config):
  """Return the exact signature/instance identities required by a pipeline."""
  return [
    (plugin["SIGNATURE"], instance["INSTANCE_ID"])
    for plugin in config.get("PLUGINS", [])
    for instance in plugin.get("INSTANCES", [])
  ]


def report_is_ready(report, config, now=None):
  """Require an explicit ready report for every planned plugin instance."""
  if not report or report.get("status") != "ready":
    return False
  if now is not None and not 0 <= now - report.get("updated_at", 0) <= 30:
    return False
  actual = {
    (item.get("signature"), item.get("instance_id")): item.get("status")
    for item in report.get("instances", [])
  }
  expected = required_instances(config)
  return bool(expected) and all(actual.get(identity) == "ready" for identity in expected)


class _DeploymentOperationsMixin:
  """Persist, execute, recover, and present asynchronous deployment operations."""

  def _init_deployment_operations(self):
    """Start the independent execution worker and initialize bounded caches."""
    self._deployment_preparations = {}
    self._deployment_plan_cache_lock = threading.Lock()
    self._deployment_operations_event = threading.Event()
    self._deployment_operations_stop = threading.Event()
    self._deployment_sync_time = 0
    self._deployment_plans = {}
    self._deployment_operations_thread = threading.Thread(
      target=self._deployment_operation_worker,
      name="deeploy-operations", daemon=True,
    )
    self._deployment_operations_thread.start()

  def _operation_peers(self):
    """Resolve replication peers without choosing an execution coordinator."""
    peers = list(get_dauth_registry_internal_peers(self))
    oracles, _ = self.bc.get_oracles(wait_interval=0)
    peers.extend(oracles)
    peers.append(self.bc.address)
    return sorted(set(peer for peer in peers if isinstance(peer, str) and peer))

  def _operation_write_kwargs(self):
    """Keep operation state on the oracle peers used for cross-oracle reads."""
    return dict(extra_peers=self._operation_peers(), include_default_peers=False,
                include_configured_peers=False, timeout=5, max_retries=1)

  def _verify_operation_record(self, record, signer_key):
    """Accept only signed records whose claimed writer matches their signer."""
    if not isinstance(record, dict) or not record.get(signer_key):
      return False
    try:
      verification = self.bc.verify(record, return_full_info=True)
      return bool(verification.valid and record.get("EE_SENDER") == record[signer_key])
    except Exception:
      return False

  def _operation_records(self):
    """Select the newest verified snapshot per operation from local replicas."""
    latest = {}
    trusted = set(self._operation_peers())
    for record in (self.chainstore_hgetall(OPERATIONS_HKEY) or {}).values():
      if not self._verify_operation_record(record, "coordinator"):
        continue
      if record.get("coordinator") not in trusted or record.get("network") != self.evm_network:
        continue
      operation_id = record.get("operation_id")
      sequence = record.get("sequence")
      if not isinstance(operation_id, str) or type(sequence) is not int:
        continue
      writer_prefix = hashlib.sha256(record["coordinator"].encode()).hexdigest()[:16] + "-"
      if not operation_id.startswith(writer_prefix):
        continue
      previous = latest.get(operation_id)
      if previous is None or sequence > previous["sequence"]:
        latest[operation_id] = record
    return latest

  def _repair_deployment_records(self, force=False):
    """Bound replica refresh; Core rejects stale sequence values on slot merges."""
    now = self.time()
    if not force and now - getattr(self, "_deployment_sync_time", 0) < 5:
      return
    self._deployment_sync_time = now
    peers = self._operation_peers()
    for namespace in (OPERATIONS_HKEY, NODE_OPERATIONS_HKEY):
      try:
        self.chainstore_hsync(namespace, extra_peers=peers,
                             include_default_peers=False,
                             include_configured_peers=False, timeout=2)
      except Exception:
        # A failed repair never proves that an operation does not exist.
        continue

  def _save_operation(self, operation, phase=None, message=None):
    """Replicate a signed snapshot in a bounded sequence slot before side effects."""
    if operation["coordinator"] != self.bc.address:
      raise ValueError("Only the accepting oracle can advance this operation.")
    snapshot = copy.deepcopy(operation)
    for key in SIGNATURE_KEYS:
      snapshot.pop(key, None)
    snapshot["sequence"] = operation.get("sequence", 0) + 1
    snapshot["updated_at"] = self.time()
    if phase is not None:
      snapshot["phase"] = phase
    if message:
      events = snapshot.setdefault("events", [])
      events.append(dict(sequence=snapshot["sequence"], time=self.time(),
                         phase=snapshot["phase"], message=message))
      snapshot["events"] = events[-128:]
    self.bc.sign(snapshot, add_data=True, use_digest=True)
    key = "{}|{}".format(snapshot["operation_id"], snapshot["sequence"] % 8)
    if not self.chainstore_hset(OPERATIONS_HKEY, key, snapshot, readonly=True,
                               **self._operation_write_kwargs()):
      raise RuntimeError("Deployment state replication is pending.")
    operation.clear()
    operation.update(snapshot)
    return operation

  def _replicate_operation(self, operation):
    """Retry the exact durable snapshot, including after an uncertain write."""
    key = "{}|{}".format(operation["operation_id"], operation["sequence"] % 8)
    if not self.chainstore_hset(OPERATIONS_HKEY, key, operation, readonly=True,
                               **self._operation_write_kwargs()):
      raise RuntimeError("Deployment state replication is pending.")

  def _assert_no_active_deployment(self, job_id=None, app_id=None):
    """Serialize other job mutations against known deployment/recovery work."""
    self._repair_deployment_records(force=True)
    if any((str(record["job_id"]) == str(job_id) or (app_id and record["app_id"] == app_id))
           and record["phase"] != "completed"
           for record in self._operation_records().values()):
      raise DeploymentConflictError("Deployment or recovery is active; wait before changing this job.")

  def _find_request_operation(self, request, owner, kind):
    """Resolve already observed idempotent requests and known job conflicts."""
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
      raise ValueError("A stable request_id of 1 to 128 characters is required.")
    digest = request_digest(request)
    job_id = str(request.get("job_id"))
    self._repair_deployment_records(force=True)
    records = [record for record in self._operation_records().values()
               if record.get("owner", "").lower() == owner.lower()
               and str(record.get("job_id")) == job_id]
    for record in records:
      if record["request_id"] == request_id and record["kind"] == kind:
        if record["request_hash"] != digest:
          raise DeploymentConflictError("request_id was already used for different deployment input.")
        return record
    if any(record["phase"] != "completed" for record in records):
      raise DeploymentConflictError("A deployment operation or recovery is already active for this job.")
    return None

  def _accepted_operation_response(self, operation):
    """Return durable acceptance without implying workload readiness."""
    # A previous admission may have persisted locally before replication timed
    # out. Reconfirm that exact snapshot before returning acceptance on retry.
    if operation["coordinator"] == self.bc.address:
      self._replicate_operation(operation)
    return self._get_response(dict(
      status_code=202, status="accepted", operation_id=operation["operation_id"],
      request_id=operation["request_id"], job_id=operation["job_id"],
      app_id=operation["app_id"], revision=operation["target_revision"],
    ))

  def _deployment_secret_request(self, action, operation, **payload):
    """Request custody work through the SDK without fetching protected bundles."""
    return self.bc.reconcile_dauth_job_secrets(dict(
      job_id=str(operation["job_id"]), operation=copy.deepcopy(operation),
      action=action, **payload,
    ))

  def _prepare_deployment_secret_configs(self, configs, prior_pipeline=None, identity_aliases=None):
    """Extract only fresh input values; reconciliation remains on dAuth."""
    redacted, fragments = {}, None
    for node, config in configs.items():
      config = copy.deepcopy(config)
      inherit_selections(config, prior_pipeline, dAuth.DAUTH_SECRET_PLACEHOLDER,
                         identity_aliases=identity_aliases)
      redacted[node], values = self._extract_and_redact_deeploy_dauth_secrets(config)
      fragments = self._merge_deeploy_dauth_secret_fragments(fragments, values, reject_conflicts=True)
    return redacted, fragments

  def _previous_deployment_configs(self, pipeline):
    """Load exact previous redacted placement from public plans or node metadata."""
    specs = pipeline["DEEPLOY_SPECS"]
    reference = specs.get("secret_revision")
    if reference:
      previous = self._operation_records().get(reference.split(":", 1)[0])
      if previous is None:
        raise ValueError("The previous deployment operation is unavailable.")
      plan = self._load_operation_plan(previous)
      return copy.deepcopy(plan["previous_configs" if reference.endswith(":restore") else "configs"])
    configs = {}
    known = self.netmon.network_known_pipelines()
    for node in specs.get("current_target_nodes", []):
      matches = [config for config in known.get(node, [])
                 if config.get("NAME") == pipeline["NAME"]
                 and str(config.get("DEEPLOY_SPECS", {}).get("job_id")) == str(specs["job_id"])]
      if len(matches) != 1:
        raise ValueError("The exact previous configuration is unavailable for a target node.")
      configs[node] = copy.deepcopy(matches[0])
    return configs

  def _next_deployment_revision(self, job_id, previous_revision=0):
    """Advance past canonical content and every verified observed job attempt.

    Failed preparation and failed creates leave canonical metadata unchanged,
    but their durable operation generations still order subsequent admissions.
    Read the authenticated operation projection already repaired by admission;
    this does not provide cross-oracle serialization of simultaneous requests.
    """
    pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(job_id))
    generation = pointer.get("revision", 0) if isinstance(pointer, dict) else 0
    observed = [record["target_revision"] for record in self._operation_records().values()
                if str(record["job_id"]) == str(job_id)]
    return max([previous_revision, generation] + observed) + 1

  def _admit_prepared_deployment(self, request, auth_result, app_id, configs,
                                 prior_pipeline, is_create, mutation=None,
                                 restore_owner=None, identity_aliases=None):
    """Save exact redacted plans and secret revisions before accepting work.

    Parameters
    ----------
    request : dict
      Validated signed request including stable request identity.
    auth_result : dict
      Existing escrow authorization result.
    app_id : str
      Stable pipeline identity.
    configs : dict
      Prepared node-specific configurations; fresh values are extracted before
      persisting the redacted plan and sent only to dAuth for reconciliation.
    prior_pipeline : dict or None
      Current canonical redacted configuration for restoration planning.
    is_create : bool
      Whether this operation creates a previously absent deployment.

    Returns
    -------
    dict
      Signed HTTP acceptance response.
    """
    owner = auth_result[DEEPLOY_KEYS.ESCROW_OWNER]
    job_id = request["job_id"]
    previous_revision = 0 if is_create else (prior_pipeline or {}).get(
      "DEEPLOY_SPECS", {}).get("revision", 0)
    if not is_create:
      if not isinstance(prior_pipeline, dict):
        raise ValueError("An update requires a recoverable previous configuration.")
      if type(request.get("expected_revision")) is not int or request["expected_revision"] != previous_revision:
        raise DeploymentConflictError("The deployment revision changed; refresh before updating.")
    operation_id = hashlib.sha256(self.bc.address.encode()).hexdigest()[:16] + "-" + uuid.uuid4().hex
    revision = self._next_deployment_revision(job_id, previous_revision)
    secret_revision = operation_id + ":deploy"
    configs, new_secrets = self._prepare_deployment_secret_configs(configs, prior_pipeline, identity_aliases)
    for config in configs.values():
      config.setdefault("DEEPLOY_SPECS", {}).update(
        revision=revision, secret_revision=secret_revision,
      )
      # Node-owned publication replaces plugin-owned deployment responses.
      for plugin in config.get("PLUGINS", []):
        for instance in plugin.get("INSTANCES", []):
          instance.pop("CHAINSTORE_RESPONSE_KEY", None)
          instance.pop("DEEPLOY_RUNTIME_ARTIFACTS", None)
    previous_configs = {}
    previous_operation_id = None
    previous_secret_revision_to_release = None
    if not is_create:
      previous_nodes = prior_pipeline.get("DEEPLOY_SPECS", {}).get("current_target_nodes", [])
      if not previous_nodes:
        raise ValueError("The previous revision has no recoverable node placement.")
      previous_secret_revision = operation_id + ":restore"
      prior_secret_revision = prior_pipeline.get("DEEPLOY_SPECS", {}).get("secret_revision")
      previous_secret_revision_to_release = prior_secret_revision
      previous_operation_id = prior_secret_revision.split(":", 1)[0] if prior_secret_revision else None
      previous_configs = self._previous_deployment_configs(prior_pipeline)
      previous_configs, previous_new_secrets = self._prepare_deployment_secret_configs(
        previous_configs, prior_pipeline,
      )
      if set(previous_configs) != set(previous_nodes) or any(
        config.get("NAME") != app_id or
        str(config.get("DEEPLOY_SPECS", {}).get("job_id")) != str(job_id) or
        config.get("DEEPLOY_SPECS", {}).get("revision", 0) != previous_revision or
        not required_instances(config)
        for config in previous_configs.values()
      ):
        raise ValueError("The previous revision does not contain the exact complete placement.")
      for old_config in previous_configs.values():
        old_config.pop("DEEPLOY_OPERATION", None)
        if restore_owner is not None:
          old_config["OWNER"] = restore_owner
        old_config.setdefault("DEEPLOY_SPECS", {}).update(
          revision=previous_revision, secret_revision=previous_secret_revision,
        )
    plan = dict(configs=configs, previous_configs=previous_configs)
    plan_cid = self.r1fs.add_json(plan, nonce=42, fn="deployment-plan.json", show_logs=False)
    if not plan_cid:
      raise RuntimeError("Could not persist deployment execution plan.")
    now = self.time()
    operation = dict(
      operation_id=operation_id, request_id=request["request_id"],
      request_hash=request_digest(request), kind="create" if is_create else "update",
      mutation=mutation,
      job_id=job_id, app_id=app_id, owner=owner, network=self.evm_network,
      coordinator=self.bc.address, target_revision=revision,
      previous_revision=None if is_create else previous_revision,
      previous_operation_id=previous_operation_id,
      previous_secret_revision=previous_secret_revision_to_release,
      previous_pipeline_cid=self._get_pipeline_from_cstore(job_id),
      plan_cid=plan_cid, nodes=list(configs), previous_nodes=list(previous_configs),
      instances={node: required_instances(config) for node, config in configs.items()},
      previous_instances={node: required_instances(config) for node, config in previous_configs.items()},
      phase="preparing", outcome=None, recovery=None, created_at=now, updated_at=now,
      preparation_deadline=now + 120,
      deadline=now + self.cfg_deployment_readiness_timeout,
      sequence=0, events=[], sent_at={},
      error=None,
    )
    # The recovery owner must exist before any plaintext revision is staged.
    # If admission stops here, the worker either confirms complete preparation
    # or revokes its staged references without touching the running revision.
    finished = threading.Event()
    self._deployment_preparations[operation_id] = finished
    try:
      self._save_operation(operation, message="Preparing durable deployment data.")
      self._deployment_secret_request(
        "prepare", operation, new_secrets=new_secrets,
        previous_new_secrets=previous_new_secrets if previous_configs else None,
        identity_aliases=[[list(current), list(source)] for current, source in (identity_aliases or {}).items()],
      )
      self._save_operation(operation, "accepted", "Deployment accepted.")
    finally:
      # Keep the marker until the worker discards its old snapshots and reloads
      # durable state. This also hands interrupted admission to recovery.
      finished.set()
    self._deployment_operations_event.set()
    return self._accepted_operation_response(operation)

  def _load_operation_plan(self, operation):
    """Load immutable redacted execution data without exposing it in polling."""
    cid = operation["plan_cid"]
    with self._deployment_plan_cache_lock:
      plan = self._deployment_plans.get(cid)
    if plan is None:
      plan = self.r1fs.get_json(cid, timeout=10, show_logs=False)
      if not isinstance(plan, dict) or not isinstance(plan.get("configs"), dict):
        raise RuntimeError("Deployment plan is temporarily unavailable.")
      # Only cache bookkeeping is locked; storage reads never hold this lock.
      with self._deployment_plan_cache_lock:
        if cid not in self._deployment_plans and len(self._deployment_plans) >= 32:
          self._deployment_plans.pop(next(iter(self._deployment_plans)))
        self._deployment_plans[cid] = plan
    return copy.deepcopy(plan)

  def _node_operation_reports(self, operation, attempt):
    """Read newest signed reports from the planned nodes for this attempt."""
    reports = {}
    nodes = operation["nodes"] if attempt == "deploy" else operation["previous_nodes"]
    revision = operation["target_revision"] if attempt == "deploy" else operation["previous_revision"]
    for report in (self.chainstore_hgetall(NODE_OPERATIONS_HKEY) or {}).values():
      if not isinstance(report, dict) or report.get("operation_id") != operation["operation_id"]:
        continue
      if report.get("app_id") != operation["app_id"]:
        continue
      if report.get("attempt") != attempt or report.get("revision") != revision:
        continue
      node = report.get("node_addr")
      if node not in nodes or report.get("coordinator") != operation["coordinator"]:
        continue
      if not self._verify_operation_record(report, "node_addr"):
        continue
      sequence = report.get("sequence")
      if type(sequence) is not int:
        continue
      if node not in reports or reports[node]["sequence"] < sequence:
        reports[node] = report
    return reports

  def _operation_metadata(self, operation, attempt, action):
    """Bind a node command to its coordinator, attempt, and content revision."""
    return dict(
      operation_id=operation["operation_id"], attempt=attempt, action=action,
      revision=operation["target_revision"] if attempt == "deploy" else operation["previous_revision"],
      coordinator=operation["coordinator"], peers=self._operation_peers(),
      job_id=operation["job_id"],
      expected_previous_operation_id=operation.get("previous_operation_id") if attempt == "retire" else None,
    )

  def _send_operation_commands(self, operation, configs, attempt, action, reports):
    """Retry scoped commands while recording intent before transport dispatch."""
    for node, config in configs.items():
      report = reports.get(node, {})
      if action in ("stop", "retire") and report.get("status") == "stopped":
        continue
      if action == "start" and report_is_ready(report, config, self.time()):
        continue
      key = "{}|{}|{}".format(attempt, action, node)
      if self.time() - operation["sent_at"].get(key, 0) < 10:
        continue
      operation["sent_at"][key] = self.time()
      self._save_operation(operation)
      payload = copy.deepcopy(config) if action == "start" else {"NAME": operation["app_id"]}
      if action == "start" and (attempt == "restore" or operation.get("mutation") == "owner_transfer"):
        bindings = operation.get("retired_runtime", {}).get(node, {})
        for plugin in payload.get("PLUGINS", []):
          if plugin["SIGNATURE"].upper() not in CONTAINERIZED_APPS_SIGNATURES:
            continue
          for instance in plugin.get("INSTANCES", []):
            identity = plugin["SIGNATURE"] + "|" + instance["INSTANCE_ID"]
            artifacts = bindings.get(identity)
            if not artifacts or not artifacts.get("image_id"):
              operation["recovery"] = "blocked"
              self._save_operation(operation, message="Previous runtime image binding is unavailable; restoration is blocked.")
              raise RuntimeError("Previous runtime artifacts are unavailable.")
            instance["DEEPLOY_RUNTIME_ARTIFACTS"] = copy.deepcopy(artifacts)
      payload["DEEPLOY_OPERATION"] = self._operation_metadata(operation, attempt, action)
      if self._deployment_operations_stop.is_set():
        return
      self.cmdapi_start_pipeline(config=payload, node_address=node)

  def _advance_deployment_operation(self, operation):
    """Advance one operation using explicit node evidence and safe recovery."""
    if operation["coordinator"] != self.bc.address or operation["phase"] == "completed":
      return
    if operation["kind"] == "delete":
      return self._advance_delete_operation(operation)
    self._replicate_operation(operation)
    plan = self._load_operation_plan(operation)
    configs = plan["configs"]
    reports = self._node_operation_reports(operation, "deploy")
    phase = operation["phase"]
    if phase == "preparing":
      return self._finish_deployment_preparation(operation, plan)
    if phase == "accepted":
      next_phase = "retiring_previous" if operation["kind"] == "update" else "waiting_for_readiness"
      self._save_operation(operation, next_phase, "Preparing target nodes.")
      phase = operation["phase"]
    if phase == "retiring_previous":
      retired = self._node_operation_reports(operation, "retire")
      if all(retired.get(node, {}).get("status") == "stopped" for node in plan["previous_configs"]):
        operation["retired_runtime"] = {
          node: {item["signature"] + "|" + item["instance_id"]: copy.deepcopy(item["runtime_artifacts"])
                 for item in report.get("instances", []) if item.get("runtime_artifacts")}
          for node, report in retired.items()
        }
        if operation.get("error"):
          operation["restore_deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          self._save_operation(operation, "restoring_previous", "Restoring the previous revision.")
        else:
          operation["deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          self._save_operation(operation, "waiting_for_readiness", "Previous instances stopped; starting target nodes.")
      else:
        if self.time() >= operation["deadline"] or any(r.get("status") == "failed" for r in retired.values()):
          operation["error"] = dict(code="PREVIOUS_STOP_UNCONFIRMED",
                                    message="Waiting for confirmed stop of the previous revision.", retryable=True)
          operation["recovery"] = "blocked"
        self._send_operation_commands(operation, plan["previous_configs"], "retire", "retire", retired)
      return
    if phase == "waiting_for_readiness":
      failed = any(report.get("status") == "failed" or any(
        instance.get("status") == "failed" for instance in report.get("instances", [])
      ) for report in reports.values())
      if failed or self.time() >= operation["deadline"]:
        operation["error"] = dict(
          code="INSTANCE_FAILED" if failed else "READINESS_DEADLINE_EXCEEDED",
          message="A required instance failed." if failed else "Not all target nodes confirmed readiness in time.",
          retryable=False,
        )
        operation["recovery"] = "in_progress"
        operation["recovery_started_at"] = self.time()
        self._save_operation(operation, "stopping_failed_rollout", "Stopping the failed rollout on all targets.")
      elif all(report_is_ready(reports.get(node), config, self.time()) for node, config in configs.items()):
        self._save_operation(operation, "finalizing", "All required instances are ready.")
      else:
        self._send_operation_commands(operation, configs, "deploy", "start", reports)
      return
    if phase == "stopping_failed_rollout":
      # Requiring all stop acknowledgments provides the stateful restoration barrier.
      if all(reports.get(node, {}).get("status") == "stopped" for node in configs):
        if operation["kind"] == "update":
          operation["restore_deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          self._save_operation(operation, "restoring_previous", "Restoring the previous revision.")
        else:
          self._release_unused_secret_revisions(operation, plan, active_attempt=None)
          operation.update(outcome="failed", recovery="completed")
          self._save_operation(operation, "completed", "Failed deployment stopped on all target nodes.")
      else:
        if self.time() - operation["recovery_started_at"] > self.cfg_deployment_readiness_timeout:
          operation["recovery"] = "blocked"
        self._send_operation_commands(operation, configs, "deploy", "stop", reports)
      return
    if phase == "restoring_previous":
      previous_configs = plan["previous_configs"]
      previous_reports = self._node_operation_reports(operation, "restore")
      if all(report_is_ready(previous_reports.get(node), config, self.time()) for node, config in previous_configs.items()):
        self._save_operation(operation, "finalizing_recovery", "Previous revision is ready on all required nodes.")
      else:
        if self.time() >= operation["restore_deadline"] or any(
          report.get("status") == "failed" for report in previous_reports.values()
        ):
          operation["recovery"] = "blocked"
        self._send_operation_commands(operation, previous_configs, "restore", "start", previous_reports)
      return
    if phase in ("finalizing", "finalizing_recovery"):
      restored = phase == "finalizing_recovery"
      active_configs = plan["previous_configs"] if restored else configs
      self._commit_operation_revision(operation, active_configs)
      self._release_unused_secret_revisions(operation, plan, active_attempt="restore" if restored else "deploy")
      operation.update(outcome="failed" if restored else "succeeded",
                       recovery="completed" if restored else None)
      self._save_operation(operation, "completed",
                           "Previous revision restored." if restored else "Deployment completed.")

  def _finish_deployment_preparation(self, operation, plan):
    """Recover interrupted admission without leaving unowned secret copies."""
    result = self._deployment_secret_request("status", operation)
    if not result["prepared"]:
      if self.time() < operation["preparation_deadline"]:
        return
      # Fresh values lost before custody cannot be regenerated after restart.
      # Revoke only this operation's partial copies; leave the active job intact.
      self._release_unused_secret_revisions(operation, plan, active_attempt=None)
      operation.update(outcome="failed", recovery="completed", error=dict(
        code="ADMISSION_PREPARATION_FAILED",
        message="Deployment preparation did not complete; the running revision is unchanged.",
        retryable=False,
      ))
      self._save_operation(operation, "completed", "Incomplete deployment preparation cleaned up.")
      return
    operation["deadline"] = self.time() + self.cfg_deployment_readiness_timeout
    self._save_operation(operation, "accepted", "Deployment preparation recovered.")

  def _commit_operation_revision(self, operation, configs):
    """Commit canonical metadata only after readiness or restoration evidence."""
    representative = next(iter(configs.values()))
    self.commit_deployment_revision(operation, representative)

  def _release_unused_secret_revisions(self, operation, plan, active_attempt):
    """Remove plaintext from unused revisions only after positive stop evidence.

    Keep a revoked record rather than deleting the field: CStore repair is
    additive, and a tombstone must survive to reject a delayed secret request.
    """
    self._deployment_secret_request("revoke", operation, active_attempt=active_attempt)

  def _reconcile_coordinator_operations(self):
    """Advance runtime execution and recovery for this receiving oracle."""
    # Clear completed handoffs BEFORE reading snapshots. Admissions that finish
    # during that read keep their marker until the next pass, avoiding a stale
    # `preparing` snapshot racing the request's final `accepted` write.
    for operation_id, finished in self._deployment_preparations.copy().items():
      if finished.is_set():
        self._deployment_preparations.pop(operation_id)
    own = [copy.deepcopy(operation) for operation in self._operation_records().values()
           if operation["coordinator"] == self.bc.address]
    for operation in own:
      if operation["phase"] == "completed" or operation["operation_id"] in self._deployment_preparations:
        continue
      try:
        self._advance_deployment_operation(operation)
      except Exception:
        self.P("Deployment operation waiting for storage or transport recovery.", color="y")

  def _deployment_operation_worker(self):
    """Resume coordinator-owned work independently of HTTP and UI polling."""
    while not self._deployment_operations_stop.is_set():
      try:
        self._repair_deployment_records()
        self._reconcile_coordinator_operations()
      except Exception:
        self.P("Deployment operation synchronization is temporarily unavailable.", color="y")
      self._deployment_operations_event.wait(2)
      self._deployment_operations_event.clear()

  def _deployment_status(self, request):
    """Authorize a lookup and return a bounded, redacted progress projection."""
    # Reuse the existing nonce-only wallet read envelope. Selectors cannot
    # widen access: every result is filtered by the authenticated escrow owner.
    envelope = {key: request.get(key) for key in ("nonce", "EE_ETH_SIGN", "EE_ETH_SENDER")}
    try:
      _, inputs = self.deeploy_verify_and_get_inputs(envelope, request_type="get deployment status")
      auth = self.deeploy_get_auth_result(inputs)
    except (ValueError, AssertionError) as exc:
      raise DeploymentAuthenticationError("Read authorization is invalid or expired; sign in again.") from exc
    if request.get("job_id") is not None:
      inputs[DEEPLOY_KEYS.JOB_ID] = request["job_id"]
    owner = auth[DEEPLOY_KEYS.ESCROW_OWNER]
    selector = request.get("operation_id") or request.get("request_id")
    if request.get("operation_id") and request.get("request_id"):
      raise ValueError("Choose only one operation selector.")
    if not selector and request.get("job_id") is None:
      raise ValueError("operation_id, request_id, or job_id is required.")
    self._repair_deployment_records()
    matches = []
    for record in self._operation_records().values():
      if record.get("owner", "").lower() != owner.lower():
        continue
      if request.get("operation_id") and record["operation_id"] != request["operation_id"]:
        continue
      if request.get("request_id") and record["request_id"] != request["request_id"]:
        continue
      if request.get("kind") and record["kind"] != request["kind"]:
        continue
      if request.get("job_id") is not None and str(record["job_id"]) != str(request["job_id"]):
        continue
      matches.append(record)
    if not matches:
      if not selector and request.get("job_id") is not None:
        pipeline = self.get_job_pipeline_from_cstore(
          request["job_id"], timeout=5, pin=False, raise_on_error=False, show_logs=False,
        )
        if isinstance(pipeline, dict):
          specs = pipeline.get("DEEPLOY_SPECS", {})
          # A canonical job without operation metadata predates this job's
          # first tracked update. Do not turn absent replicas into absence.
          if not specs.get("secret_revision"):
            job = self.bc.get_job_details(job_id=request["job_id"])
            if job and str(job.get("escrowOwner", "")).lower() == owner.lower():
              return {"status": "not_found", "job_id": request["job_id"], "revision": 0,
                      "observation_stale": False, "poll_after_ms": 2000}
      return {"status": "synchronizing", "job_id": request.get("job_id"),
              "revision": 0, "observation_stale": True, "poll_after_ms": 2000}
    operation = max(matches, key=lambda record: (record["target_revision"], record["created_at"], record["sequence"]))
    restoring = operation["phase"] in ("restoring_previous", "finalizing_recovery") or (
      operation["outcome"] == "failed" and operation["kind"] == "update"
    )
    attempt = "retire" if operation["kind"] == "delete" or operation["phase"] == "retiring_previous" else "restore" if restoring else "deploy"
    reports = self._node_operation_reports(operation, attempt)
    deployed_reports = self._node_operation_reports(operation, "deploy") if restoring else reports
    identities = operation["previous_instances"] if attempt != "deploy" else operation["instances"]
    configs = {node: {"PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": instance}]} for signature, instance in values]}
               for node, values in identities.items()}
    now = self.time()
    nodes = []
    for node in dict.fromkeys(operation["nodes"] + operation["previous_nodes"]):
      report = reports.get(node, {}) if node in identities else deployed_reports.get(node, {})
      updated_at = report.get("updated_at")
      planned = identities.get(node, []) if node in identities else operation["instances"].get(node, [])
      instances = copy.deepcopy(report.get("instances", []))
      if not instances:
        instances = [{"signature": signature, "instance_id": instance_id, "status": "pending"}
                     for signature, instance_id in planned]
      nodes.append(dict(
        node_id=node, observed_revision=report.get("revision"),
        workload_state=report.get("status", "unknown"),
        updated_at=updated_at, stale=report.get("status") != "stopped" and (updated_at is None or now - updated_at > 30),
        instances=instances, error=copy.deepcopy(report.get("error")),
        action=operation["phase"],
      ))
    fields = ("operation_id", "request_id", "job_id", "app_id", "kind", "mutation", "sequence",
              "target_revision", "previous_revision", "phase", "outcome", "recovery",
              "coordinator", "created_at", "updated_at", "error")
    result = {key: copy.deepcopy(operation.get(key)) for key in fields}
    limit = request.get("events_limit", 64)
    if type(limit) is not int or not 1 <= limit <= 128:
      raise ValueError("events_limit must be between 1 and 128.")
    after = request.get("after_event_cursor", 0)
    if type(after) is not int or after < 0:
      raise ValueError("after_event_cursor must be a non-negative integer.")
    events = [event for event in operation["events"] if event["sequence"] > after]
    result.update(
      status=operation["phase"], nodes=nodes, target_nodes=len(configs),
      ready_nodes=sum(report_is_ready(reports.get(node), config, self.time()) for node, config in configs.items()),
      observation_stale=operation["phase"] != "completed" and now - operation["updated_at"] > 30,
      poll_after_ms=2000, events=events[:limit],
      next_event_cursor=events[limit - 1]["sequence"] if len(events) > limit else None,
      revision=operation["target_revision"] if operation["outcome"] == "succeeded" else operation["previous_revision"] or 0,
    )
    return result
