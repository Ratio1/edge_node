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

from ratio1.const.base import BCct, dAuth
from .selected_secrets import inherit_selections

from extensions.business.dauth.dauth_registry import get_dauth_registry_internal_peers
from .deeploy_const import DEEPLOY_KEYS, CONTAINERIZED_APPS_SIGNATURES


OPERATIONS_HKEY = "DEEPLOY_OPERATIONS"
NODE_OPERATIONS_HKEY = "DEEPLOY_NODE_OPERATIONS"
SECRET_REVISIONS_HKEY = "DAUTH_JOB_SECRET_REVISIONS"
class DeploymentAuthenticationError(ValueError):
  """The reusable read authorization is invalid or expired."""


class DeploymentConflictError(ValueError):
  """A request conflicts with observed operation identity or revision."""


SIGNATURE_KEYS = {"EE_SIGN", "EE_SENDER", "EE_HASH", BCct.SIGN_CANON_V}
# Signing and retry bookkeeping: a snapshot that differs only here is not new state.
VOLATILE_OPERATION_FIELDS = SIGNATURE_KEYS | {"EE_ETH_SENDER", "EE_ETH_SIGN", "sequence", "updated_at", "sent_at"}


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


def report_is_ready(report, config):
  """Require an explicit ready report for every planned plugin instance.

  Nodes publish a ready report once per attempt and never refresh it, so its
  age is not a liveness signal; callers pair it with NetMon liveness.
  """
  if not report or report.get("status") != "ready":
    return False
  actual = {
    (item.get("signature"), item.get("instance_id")): item.get("status")
    for item in report.get("instances", [])
  }
  expected = required_instances(config)
  return bool(expected) and all(actual.get(identity) == "ready" for identity in expected)


def replace_nodes(value, node_aliases):
  """Rename node addresses used as dict keys or whole string values.

  A relinked node keeps its job, so everything naming the old address
  (placement, peers, per-node settings and their secret paths) moves to the new one.
  """
  if isinstance(value, dict):
    return {node_aliases.get(key, key): replace_nodes(item, node_aliases) for key, item in value.items()}
  if isinstance(value, list):
    return [replace_nodes(item, node_aliases) for item in value]
  if isinstance(value, str):
    return node_aliases.get(value, value)
  return value


def list_order_differs(stored, running):
  """Whether some list holds the same items in both configs, in another order."""
  if isinstance(stored, dict) and isinstance(running, dict):
    return any(list_order_differs(stored[key], running[key]) for key in stored.keys() & running.keys())
  if isinstance(stored, list) and isinstance(running, list):
    items = lambda values: sorted(json.dumps(value, sort_keys=True) for value in values)
    if stored != running and items(stored) == items(running):
      return True
    return any(list_order_differs(a, b) for a, b in zip(stored, running))
  return False


class _DeploymentOperationsMixin:
  """Persist, execute, recover, and present asynchronous deployment operations."""

  # Coordinator write discipline. Each value has an "off" setting that restores
  # the previous behaviour, noted in brackets.
  # Retry bookkeeping (sent_at, a repeated event) creates no snapshot [False].
  OPERATION_SKIP_UNCHANGED_SAVES = True
  # Re-publish an unchanged, already confirmed snapshot at most this often [0].
  OPERATION_REPUBLISH_SECONDS = 300
  # Back-off of a failed or blocked operation, doubling to the ceiling [0].
  OPERATION_RETRY_MIN_SECONDS = 10
  OPERATION_RETRY_MAX_SECONDS = 600
  # Snapshot writes per rolling hour once an operation has written this many;
  # phase changes (completion, operator release) are exempt [None].
  OPERATION_FREE_WRITES = 100
  OPERATION_HOURLY_WRITES = 30
  # Repeat one operation's identical error or budget log at most this often.
  OPERATION_LOG_SECONDS = 600
  # Signature verdicts kept for unchanged operation records [0].
  OPERATION_VERIFY_CACHE_SIZE = 4096

  def _operation_runtime(self, operation_id):
    """Return this process's non-replicated bookkeeping for one operation.

    Parameters
    ----------
    operation_id : str
      Operation identity.

    Returns
    -------
    dict
      Last confirmed snapshot (``replicated``, ``replicated_at``), command
      throttle (``sent_at``), back-off (``seen``, ``delay``, ``next_attempt``),
      recent snapshot write times (``writes``) and log throttles (``logged``).
      A restart loses it, which repeats at most one replication or command.
    """
    states = vars(self).setdefault("_deployment_operation_runtime", {})
    return states.setdefault(operation_id, dict(
      replicated=None, replicated_at=0, sent_at={}, seen=None, delay=0, next_attempt=0,
      writes=[], logged={},
    ))

  def _init_deployment_operations(self):
    """Start the independent execution worker and initialize bounded caches."""
    self._deployment_preparations = {}
    self._deployment_plan_cache_lock = threading.Lock()
    self._deployment_operations_event = threading.Event()
    self._deployment_operations_stop = threading.Event()
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
    """Select the newest verified snapshot per operation from local replicas.

    A signature verdict is reused while the record under the same storage key
    keeps its sequence, signature and hash. CStore verifies every write to this
    namespace, so changed content cannot keep them. Only records present in
    this read are kept, which bounds the cache by the namespace size.
    """
    latest = {}
    trusted = set(self._operation_peers())
    cache = vars(self).get("_operation_verdicts", {}) if self.OPERATION_VERIFY_CACHE_SIZE else {}
    verdicts = {}
    for key, record in (self.chainstore_hgetall(OPERATIONS_HKEY) or {}).items():
      marker = (key,) + tuple(record.get(field) for field in ("sequence", "EE_SIGN", "EE_HASH")) \
        if isinstance(record, dict) else None
      cacheable = marker is not None and all(isinstance(item, (str, int, type(None))) for item in marker)
      valid = cache.get(marker) if cacheable else None
      if valid is None:
        valid = self._verify_operation_record(record, "coordinator")
      if cacheable and len(verdicts) < self.OPERATION_VERIFY_CACHE_SIZE:
        verdicts[marker] = valid
      if not valid:
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
    self._operation_verdicts = verdicts
    return latest

  def _save_operation(self, operation, phase=None, message=None):
    """Replicate a signed snapshot in a bounded sequence slot before side effects.

    Nothing is written when the phase stays, no new event is added and the
    content equals the confirmed snapshot apart from VOLATILE_OPERATION_FIELDS.
    A write that keeps the phase counts against the operation's write budget.
    """
    if operation["coordinator"] != self.bc.address:
      raise ValueError("Only the accepting oracle can advance this operation.")
    runtime = self._operation_runtime(operation["operation_id"])
    next_phase = operation.get("phase") if phase is None else phase
    last = (operation.get("events") or [{}])[-1]
    repeated = (self.OPERATION_SKIP_UNCHANGED_SAVES and bool(message)
                and last.get("message") == message and last.get("phase") == next_phase)
    if (self.OPERATION_SKIP_UNCHANGED_SAVES and next_phase == operation.get("phase")
        and (not message or repeated) and self._operation_is_confirmed(operation, runtime)):
      return operation
    if next_phase == operation.get("phase"):
      self._check_operation_write_budget(operation, runtime)
    snapshot = copy.deepcopy(operation)
    for key in SIGNATURE_KEYS:
      snapshot.pop(key, None)
    snapshot["sequence"] = operation.get("sequence", 0) + 1
    snapshot["updated_at"] = self.time()
    if phase is not None:
      snapshot["phase"] = phase
    if message and not repeated:
      events = snapshot.setdefault("events", [])
      events.append(dict(sequence=snapshot["sequence"], time=self.time(),
                         phase=snapshot["phase"], message=message))
      snapshot["events"] = events[-128:]
    self.bc.sign(snapshot, add_data=True, use_digest=True)
    key = "{}|{}".format(snapshot["operation_id"], snapshot["sequence"] % 8)
    runtime["writes"].append(self.time())
    if not self.chainstore_hset(OPERATIONS_HKEY, key, snapshot, readonly=True,
                               **self._operation_write_kwargs()):
      raise RuntimeError("Deployment state replication is pending.")
    runtime.update(replicated=(snapshot["sequence"], snapshot.get("EE_SIGN")), replicated_at=self.time())
    operation.clear()
    operation.update(snapshot)
    return operation

  def _operation_is_confirmed(self, operation, runtime):
    """Whether this exact content is the snapshot this process confirmed.

    Parameters
    ----------
    operation : dict
      Working copy, possibly changed in memory since it was loaded.
    runtime : dict
      The operation's bookkeeping from ``_operation_runtime``.

    Returns
    -------
    bool
      True when its sequence was confirmed and the stored snapshot of that
      sequence has the same content apart from VOLATILE_OPERATION_FIELDS.
    """
    sequence, confirmed = operation.get("sequence", 0), runtime["replicated"]
    if not sequence or confirmed is None or confirmed[0] != sequence:
      return False
    stored = self.chainstore_hget(OPERATIONS_HKEY, "{}|{}".format(operation["operation_id"], sequence % 8))
    content = lambda record: {key: value for key, value in record.items() if key not in VOLATILE_OPERATION_FIELDS}
    return isinstance(stored, dict) and stored.get("sequence") == sequence and content(stored) == content(operation)

  def _check_operation_write_budget(self, operation, runtime):
    """Refuse a same-phase snapshot write beyond the operation's hourly budget.

    A safety ceiling independent of why an operation keeps writing. Writes
    that change the phase, including completion or an operator release to
    ``completed``, never reach this check.

    Parameters
    ----------
    operation : dict
      Operation about to be saved; its sequence counts its lifetime writes.
    runtime : dict
      The operation's bookkeeping from ``_operation_runtime``.

    Raises
    ------
    RuntimeError
      When the budget is exhausted; the worker then keeps it in back-off.
    """
    now = self.time()
    runtime["writes"] = [moment for moment in runtime["writes"] if 0 <= now - moment < 3600]
    if (self.OPERATION_HOURLY_WRITES is None or operation.get("sequence", 0) < self.OPERATION_FREE_WRITES
        or len(runtime["writes"]) < self.OPERATION_HOURLY_WRITES):
      return
    logged_at = runtime["logged"].get("budget")
    if logged_at is None or not 0 <= now - logged_at < self.OPERATION_LOG_SECONDS:
      runtime["logged"]["budget"] = now
      self.P("Deployment operation {} in phase {} exceeded its snapshot write budget: {} writes in the "
             "last hour at sequence {}. Same-phase writes are paused; completion and release still apply.".format(
               operation["operation_id"], operation.get("phase"), len(runtime["writes"]),
               operation.get("sequence")), color="r")
    raise RuntimeError("Deployment operation snapshot write budget is exhausted.")

  def _replicate_operation(self, operation):
    """Retry the exact durable snapshot, including after an uncertain write.

    A snapshot this process already confirmed is re-published only every
    OPERATION_REPUBLISH_SECONDS, which still repairs peers that missed it.
    A failed attempt is not remembered, so the next attempt retries it.
    """
    runtime = self._operation_runtime(operation["operation_id"])
    marker = (operation["sequence"], operation.get("EE_SIGN"))
    if runtime["replicated"] == marker and 0 <= self.time() - runtime["replicated_at"] < self.OPERATION_REPUBLISH_SECONDS:
      return
    key = "{}|{}".format(operation["operation_id"], operation["sequence"] % 8)
    if not self.chainstore_hset(OPERATIONS_HKEY, key, operation, readonly=True,
                               **self._operation_write_kwargs()):
      raise RuntimeError("Deployment state replication is pending.")
    runtime.update(replicated=marker, replicated_at=self.time())

  def _assert_no_active_deployment(self, job_id=None, app_id=None):
    """Serialize other job mutations against known deployment/recovery work."""
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
    """Load each target node's exact config of the stored revision from R1FS.

    A revision committed by a deployment operation names its plan in the job's
    stored pointer. The plan holds every node's config, which can differ per
    node (scale-up gives each new node its own instance IDs). A job stored
    before that has only its stored copy, so every node gets that copy; it is
    refused while a node runs the job with other instances or list order.
    Neither the oracle that deployed the job nor what nodes report is used as
    content. Each node owns its response key, so it is dropped.

    Parameters
    ----------
    pipeline : dict
      The job's stored copy in R1FS, with its original node names.
    """
    specs = pipeline["DEEPLOY_SPECS"]
    nodes = specs.get("current_target_nodes", [])
    pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(specs["job_id"]))
    if isinstance(pointer, dict) and pointer.get("plan_cid"):
      plan = self.r1fs.get_json(pointer["plan_cid"], timeout=10, show_logs=False) or {}
      restored = str(specs.get("secret_revision", "")).endswith(":restore")
      configs = plan.get("previous_configs" if restored else "configs")
      if not isinstance(configs, dict) or set(configs) != set(nodes):
        raise ValueError("The stored deployment plan is unavailable.")
    else:
      if any(required_instances(config) != required_instances(pipeline) or list_order_differs(pipeline, config)
             for reports in self._job_reports(pipeline).values() for config in reports):
        raise ValueError("A node runs this job differently from its stored copy; repair the stored job first.")
      configs = {node: pipeline for node in nodes}
    configs = {node: copy.deepcopy(configs[node]) for node in nodes}
    for config in configs.values():
      for plugin in config.get("PLUGINS", []):
        for instance in plugin.get("INSTANCES", []):
          instance.pop("CHAINSTORE_RESPONSE_KEY", None)
    return configs

  def _job_reports(self, pipeline):
    """Configs NetMon reports for this job, by node: used to decide, never as content."""
    job_id = str(pipeline["DEEPLOY_SPECS"]["job_id"])
    return {node: [config for config in configs if config.get("NAME") == pipeline["NAME"]
                   and str(config.get("DEEPLOY_SPECS", {}).get("job_id")) == job_id]
            for node, configs in self.netmon.network_known_pipelines().items()}

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
                                 restore_owner=None, identity_aliases=None, node_aliases=None):
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
      The job's stored copy in R1FS, for restoration planning.
    is_create : bool
      Whether this operation creates a previously absent deployment.
    node_aliases : dict, optional
      Old node -> new node for a relink. ``prior_pipeline`` still names the old
      node; its previous configs and placement are renamed here.

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
    stored_pipeline = prior_pipeline
    prior_pipeline = replace_nodes(prior_pipeline, node_aliases or {})
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
      # A node leaving the placement that no longer reports the job (e.g. offline)
      # is skipped: there is nothing to stop or restore on it.
      reports = self._job_reports(prior_pipeline)
      skipped = {node for node in set(previous_nodes) - set(configs) if not reports.get(node)}
      previous_configs = {
        node: config for node, config in
        replace_nodes(self._previous_deployment_configs(stored_pipeline), node_aliases or {}).items()
        if node not in skipped
      }
      previous_configs, previous_new_secrets = self._prepare_deployment_secret_configs(
        previous_configs, prior_pipeline,
      )
      if set(previous_configs) != set(previous_nodes) - skipped or any(
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
        node_aliases=[[old, new] for old, new in (node_aliases or {}).items()],
      )
      if self.time() >= operation["preparation_deadline"]:
        self._expire_deployment_preparation(operation)
      else:
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

  def _node_is_ready(self, node, report, config):
    """Pair the attempt's one-time ready report with current NetMon liveness."""
    return report_is_ready(report, config) and self._netmon_node_is_online_for_control(node)

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
      if action == "start" and report_is_ready(report, config):
        continue
      key = "{}|{}|{}".format(attempt, action, node)
      # The resend throttle is process memory; the save below journals only a
      # pending state change (such as blocked recovery) before dispatch.
      sent_at = (self._operation_runtime(operation["operation_id"])["sent_at"]
                 if self.OPERATION_SKIP_UNCHANGED_SAVES else operation["sent_at"])
      if self.time() - sent_at.get(key, 0) < 10:
        continue
      sent_at[key] = self.time()
      self._save_operation(operation)
      payload = copy.deepcopy(config) if action == "start" else {
        "NAME": operation["app_id"], "TYPE": config["TYPE"],
      }
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
    if operation["phase"] == "preparing" and self.time() >= operation["preparation_deadline"]:
      self._expire_deployment_preparation(operation)
    self._replicate_operation(operation)
    if operation["phase"] == "cleaning_up_preparation":
      self._deployment_secret_request("revoke", operation, active_attempt=None)
      operation["recovery"] = "completed"
      self._save_operation(operation, "completed", "Incomplete deployment preparation cleaned up.")
      return
    if operation["phase"] == "preparing":
      return self._finish_deployment_preparation(operation)
    plan = self._load_operation_plan(operation)
    configs = plan["configs"]
    reports = self._node_operation_reports(operation, "deploy")
    phase = operation["phase"]
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
      elif all(self._node_is_ready(node, reports.get(node), config) for node, config in configs.items()):
        self._save_operation(operation, "finalizing", "All required instances are ready.")
      else:
        self._send_operation_commands(operation, configs, "deploy", "start", reports)
      return
    if phase == "stopping_failed_rollout":
      # Requiring all stop acknowledgments provides the stateful restoration barrier.
      if all(reports.get(node, {}).get("status") == "stopped" for node in configs):
        if operation["kind"] == "update" and operation["previous_nodes"]:
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
      if all(self._node_is_ready(node, previous_reports.get(node), config) for node, config in previous_configs.items()):
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

  def _expire_deployment_preparation(self, operation):
    """Record deadline failure before waiting for plan or secret cleanup."""
    operation.update(outcome="failed", recovery="in_progress", error=dict(
      code="ADMISSION_PREPARATION_FAILED",
      message="Deployment preparation did not complete; the running revision is unchanged.",
      retryable=False,
    ))
    self._save_operation(operation, "cleaning_up_preparation",
                         "Deployment preparation expired; secret cleanup is pending.")

  def _finish_deployment_preparation(self, operation):
    """Recover complete preparation only while its deadline still permits it."""
    try:
      result = self._deployment_secret_request("status", operation)
    except Exception:
      if self.time() < operation["preparation_deadline"]:
        raise
      self._expire_deployment_preparation(operation)
      return
    if self.time() >= operation["preparation_deadline"]:
      self._expire_deployment_preparation(operation)
      return
    if not result["prepared"]:
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
    """Advance runtime execution and recovery for this receiving oracle.

    An operation whose attempt raised or left recovery blocked waits with an
    exponential back-off; a new snapshot or node report ends the wait.
    """
    # Clear completed handoffs BEFORE reading snapshots. Admissions that finish
    # during that read keep their marker until the next pass, avoiding a stale
    # `preparing` snapshot racing the request's final `accepted` write.
    for operation_id, finished in self._deployment_preparations.copy().items():
      if finished.is_set():
        self._deployment_preparations.pop(operation_id)
    own = [operation for operation in self._operation_records().values()
           if operation["coordinator"] == self.bc.address]
    states = vars(self).setdefault("_deployment_operation_runtime", {})
    active = {operation["operation_id"] for operation in own if operation["phase"] != "completed"}
    for operation_id in set(states) - active - set(self._deployment_preparations):
      states.pop(operation_id, None)
    for record in own:
      if record["phase"] == "completed" or record["operation_id"] in self._deployment_preparations:
        continue
      runtime = self._operation_runtime(record["operation_id"])
      if self.time() < runtime["next_attempt"]:
        # Waiting ends early on progress made elsewhere: a new snapshot or node report.
        if runtime["seen"] == (record["sequence"], self._operation_evidence(record["operation_id"])):
          continue
        runtime["delay"] = 0
      operation = copy.deepcopy(record)
      phase, failure = operation["phase"], None
      try:
        self._advance_deployment_operation(operation)
      except Exception as exc:
        failure = exc
      if failure is None and (operation["phase"] != phase or operation.get("recovery") != "blocked"):
        runtime.update(delay=0, next_attempt=0)
      else:
        self._back_off_operation(operation, runtime, phase, failure)

  def _operation_evidence(self, operation_id):
    """Fingerprint one operation's node reports, to end a back-off early.

    Reports are not verified here: decisions still read verified reports. The
    namespace is scanned at most once per OPERATION_RETRY_MIN_SECONDS.

    Parameters
    ----------
    operation_id : str
      Operation identity.

    Returns
    -------
    frozenset or None
      (storage key, sequence, status) of each report naming the operation.
    """
    now = self.time()
    scanned_at, evidence = vars(self).get("_operation_evidence_scan", (None, {}))
    if scanned_at is None or not 0 <= now - scanned_at < self.OPERATION_RETRY_MIN_SECONDS:
      evidence = {}
      for key, report in (self.chainstore_hgetall(NODE_OPERATIONS_HKEY) or {}).items():
        if isinstance(report, dict) and isinstance(report.get("operation_id"), str):
          evidence.setdefault(report["operation_id"], set()).add(
            (key, str(report.get("sequence")), str(report.get("status"))))
      evidence = {key: frozenset(items) for key, items in evidence.items()}
      self._operation_evidence_scan = (now, evidence)
    return evidence.get(operation_id)

  def _back_off_operation(self, operation, runtime, phase, failure):
    """Delay the next attempt of a failed or blocked operation.

    Parameters
    ----------
    operation : dict
      The operation as the attempt left it.
    runtime : dict
      Its bookkeeping from ``_operation_runtime``.
    phase : str
      Phase at the start of the attempt; a change resets the delay.
    failure : Exception or None
      What the attempt raised. Each distinct message is logged at most once
      per OPERATION_LOG_SECONDS for this operation.
    """
    delay = 0 if operation["phase"] != phase else runtime["delay"]
    delay = min(max(2 * delay, self.OPERATION_RETRY_MIN_SECONDS), self.OPERATION_RETRY_MAX_SECONDS)
    now = self.time()
    runtime.update(delay=delay, next_attempt=now + delay,
                   seen=(operation.get("sequence"), self._operation_evidence(operation["operation_id"])))
    if failure is None:
      return
    text = "{}: {}".format(type(failure).__name__, failure)[:300]
    logged_at = runtime["logged"].get(text)
    if logged_at is not None and 0 <= now - logged_at < self.OPERATION_LOG_SECONDS:
      return
    if len(runtime["logged"]) > 32:
      runtime["logged"].clear()
    runtime["logged"][text] = now
    self.P("Deployment operation waiting for storage or transport recovery: {} in phase {}: {} "
           "Next attempt in {:.0f}s.".format(operation["operation_id"], operation["phase"], text, delay), color="y")

  def _deployment_operation_worker(self):
    """Resume coordinator-owned work independently of HTTP and UI polling."""
    while not self._deployment_operations_stop.is_set():
      try:
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
      and (operation.get("error") or {}).get("code") != "ADMISSION_PREPARATION_FAILED"
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
        updated_at=updated_at, stale=report.get("status") != "stopped" and (
          updated_at is None or not self._netmon_node_is_online_for_control(node)),
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
      ready_nodes=sum(self._node_is_ready(node, reports.get(node), config) for node, config in configs.items()),
      observation_stale=operation["phase"] != "completed" and now - operation["updated_at"] > 30,
      poll_after_ms=2000, events=events[:limit],
      next_event_cursor=events[limit - 1]["sequence"] if len(events) > limit else None,
      revision=operation["target_revision"] if operation["outcome"] == "succeeded" else operation["previous_revision"] or 0,
    )
    return result
