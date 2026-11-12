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
# The worker signature tells the restoration gate which runtime binding an instance needs.
from .deeploy_const import DEEPLOY_KEYS, CONTAINERIZED_APPS_SIGNATURES, WORKER_APP_RUNNER_SIGNATURE


OPERATIONS_HKEY = "DEEPLOY_OPERATIONS"
NODE_OPERATIONS_HKEY = "DEEPLOY_NODE_OPERATIONS"
SECRET_REVISIONS_HKEY = "DAUTH_JOB_SECRET_REVISIONS"
class DeploymentAuthenticationError(ValueError):
  """The reusable read authorization is invalid or expired."""


class DeploymentConflictError(ValueError):
  """A request conflicts with observed operation identity or revision."""


SIGNATURE_KEYS = {"EE_SIGN", "EE_SENDER", "EE_HASH", BCct.SIGN_CANON_V}


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

  def _init_deployment_operations(self):
    """Start the independent execution worker and initialize bounded caches.

    Creates every field the operation mixin needs before the worker thread
    starts: the admission handoff markers, the bounded plan cache (at most 32
    plans) with its lock, the wake-up and stop events, and two in-process
    bookkeeping maps. `_operations_sent_at` holds the command resend times
    that used to be written into the signed operation snapshot, so a command
    retry no longer produces a new CStore write; `_operations_confirmed`
    holds the last confirmed send of each snapshot, so an unchanged snapshot
    is no longer re-sent on every 2 s pass. They are created here, next to
    their sibling fields, so that a plugin missing one fails at once instead
    of creating it on first use. Finally starts the daemon thread that runs
    `_deployment_operation_worker`.

    Returns
    -------
    None
      The fields and the started thread are attached to the plugin instance.

    Notes
    -----
    Called once from the plugin's `on_init`; `on_close` sets the stop event
    and joins the thread. The two bookkeeping maps live only in process
    memory and are not pruned: they hold one small entry per operation and
    per command target. After a restart they start empty, so the current
    snapshot of each own operation the worker still handles (unfinished, or
    completed less than 600 s ago) is sent once more and pending commands are
    sent again; nodes de-duplicate commands by operation id and attempt.

    Examples
    --------
    >>> plugin._init_deployment_operations()
    >>> plugin._deployment_operations_thread.name
    'deeploy-operations'
    >>> plugin._operations_confirmed, plugin._operations_sent_at
    ({}, {})
    """
    self._deployment_preparations = {}
    # Last confirmed send per operation id, as (sequence, signature, time): it lets _replicate_operation
    # skip an unchanged snapshot for 30 s instead of re-sending it to every oracle on each 2 s pass.
    self._operations_confirmed = {}
    # Last command time per "operation id|attempt|action|node": the 10 s resend throttle lives in process
    # memory, so a command retry no longer writes a new signed snapshot that every oracle re-stores.
    self._operations_sent_at = {}
    # Fingerprints of the signed records already checked and found valid. A signed record never changes,
    # so its signature is checked once and not on every 2 s worker pass and every status poll again.
    self._verified_operation_records = set()
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
    """
    Accept only signed records whose claimed writer matches their signer, checking each record once.

    Operation snapshots and node reports are read from the local replica and their signatures are
    checked before use. The readers go over every record on every call: the `deeploy-operations`
    worker every 2 s on every oracle, and every `get_deployment_status` request. One signature check
    costs about 1 ms, so with a few hundred records each pass cost a few hundred milliseconds of CPU,
    all the time, and more with every operation ever created (records are never removed).

    A signed record never changes, and the result of the check depends only on the record's bytes and
    on which field names its writer. So a record that was found valid is remembered by a fingerprint of
    exactly those bytes, and the signature of a remembered record is not checked again. A record that
    differs in any byte has another fingerprint and is checked in full. Records that fail are not
    remembered: they are checked again each time.

    Parameters
    ----------
    record : dict
      A signed operation snapshot or node report as read from the chain store.
    signer_key : str
      Name of the field that holds the address of the record's writer ("coordinator" for an operation
      snapshot, "node_addr" for a node report). The record is accepted only if its signer is that address.

    Returns
    -------
    bool
      True when the signature is valid and the signer is the claimed writer; False otherwise, also when
      the record is not a dict, the writer field is missing or the check raises.

    Notes
    -----
    The remembered set lives in process memory, so after a restart every record is checked once more.
    It is emptied when it reaches 10,000 fingerprints (about 1 MB): records that were replaced leave
    their fingerprints behind, and emptying it costs one full pass of checks, once. It is read and
    written from the worker thread and the plugin thread; each operation on it is a single set call.

    Examples
    --------
    >>> plugin._verify_operation_record(snapshot, "coordinator")   # first time: the signature is checked
    True
    >>> plugin._verify_operation_record(snapshot, "coordinator")   # same bytes: answered from memory
    True
    >>> plugin._verify_operation_record({**snapshot, "phase": "completed"}, "coordinator")   # changed: checked, fails
    False
    """
    if not isinstance(record, dict) or not record.get(signer_key):
      return False
    try:
      # Fingerprint of everything the result depends on: the writer field's name and the whole record,
      # signature fields included. About 30 times cheaper than the signature check it replaces.
      fingerprint = hashlib.sha256((signer_key + json.dumps(record, sort_keys=True)).encode()).digest()
      if fingerprint in self._verified_operation_records:
        # These exact bytes were checked before and were valid: no second signature check.
        return True
      verification = self.bc.verify(record, return_full_info=True)
      # The full check, as before: a valid signature made by the address the record names as its writer.
      valid = bool(verification.valid and record.get("EE_SENDER") == record[signer_key])
      if valid:
        if len(self._verified_operation_records) >= 10000:
          # Bound the memory: fingerprints of replaced records are never looked up again. Emptying the
          # set only means that the current records are checked once more.
          self._verified_operation_records.clear()
        # Remember only records that passed, so a bad record is never accepted from memory.
        self._verified_operation_records.add(fingerprint)
      # The outcome of the full check; a record that failed it was not remembered above.
      return valid
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

  def _save_operation(self, operation, phase=None, message=None):
    """Replicate a signed snapshot in a bounded sequence slot before side effects.

    The coordinator saves the operation on every phase change and again
    before each node command, so that the durable record leads the action it
    describes. A new snapshot copies the operation, drops its old signature,
    increments `sequence`, stamps `updated_at`, applies the optional phase,
    appends the optional event (keeping the last 128), signs it, and writes it
    to the slot `operation_id|sequence % 8` on the oracle peers.

    A write happens only when durable state changed. When the phase is
    unchanged, no new event message is given (or it equals the last event's
    message) and the operation equals the snapshot stored in its current slot
    in the local replica, the call returns without signing or writing.
    Before this check, a stuck operation wrote a new signed snapshot for every
    command retry and for every pass past its deadline, so every oracle
    re-stored and re-pickled CStore for retry bookkeeping only.

    Parameters
    ----------
    operation : dict
      The coordinator's current operation snapshot. It is replaced in place
      by the new signed snapshot after a confirmed write, and left untouched
      when nothing changed. Fields the caller set on it (for example `error`
      or `recovery`) count as changed content.
    phase : str or None, optional
      The phase to record, such as "waiting_for_readiness" or "completed".
      None (the default) keeps the current phase.
    message : str or None, optional
      Text of an event to append, stamped with the new sequence, the time and
      the phase. None (the default) or an empty string appends no event.

    Returns
    -------
    dict
      The same `operation` object: the new signed snapshot after a write, or
      the unchanged operation when nothing durable changed.

    Raises
    ------
    ValueError
      If this oracle is not the operation's coordinator.
    RuntimeError
      If the replicated write is not confirmed; `operation` is then left
      unchanged so the caller retries on a later pass.

    Notes
    -----
    Eight slots bound the record count per operation: older sequences are
    overwritten. A confirmed write also records `(sequence, signature, time)`
    in `_operations_confirmed`, so `_replicate_operation` does not send the
    same snapshot again for 30 s.

    Examples
    --------
    >>> operation = plugin._save_operation(operation, "waiting_for_readiness", "Preparing target nodes.")
    >>> operation["sequence"], operation["events"][-1]["message"]
    (1, 'Preparing target nodes.')
    >>> plugin._save_operation(operation)["sequence"]  # nothing changed: no write
    1
    """
    if operation["coordinator"] != self.bc.address:
      raise ValueError("Only the accepting oracle can advance this operation.")
    # Same phase, no new event, same content as the stored snapshot: nothing durable changed.
    if phase in (None, operation["phase"]) and (not message or message == (operation.get("events") or [{}])[-1].get("message")):
      # Read the snapshot held in this operation's current sequence slot from the local replica (no network
      # round trip), to compare it with the in-memory operation before deciding to write.
      stored = self.chainstore_hget(OPERATIONS_HKEY, "{}|{}".format(operation["operation_id"], operation.get("sequence", 0) % 8))
      if json.dumps(stored, sort_keys=True) == json.dumps(operation, sort_keys=True):
        # Skip signing and writing: an operation with nothing new used to get a new signed snapshot on every
        # command retry and every pass past a deadline, and every oracle re-stored and re-pickled CStore for it.
        return operation
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
    # Remember that this exact snapshot (sequence and signature) was confirmed now, so _replicate_operation
    # waits 30 s before sending it again instead of re-sending the unchanged record on every 2 s pass.
    self._operations_confirmed[snapshot["operation_id"]] = (snapshot["sequence"], snapshot.get("EE_SIGN"), self.time())
    return operation

  def _replicate_operation(self, operation):
    """Retry the exact snapshot until confirmed; once confirmed, re-send it every 30 s as repair.

    A confirmation needs only part of the peers, and nothing else brings an oracle that missed the write
    up to date. The re-sent snapshot is the same record: peers that hold it store nothing.

    The snapshot is identified by its `sequence` and its signature. Until
    that exact snapshot has been confirmed once, every call writes it again
    and raises while the write stays unconfirmed, so the caller does not act
    on state the peers may lack. Once confirmed, a call within 30 s of the
    last send returns without writing; after that the same record is sent
    again as peer repair, and a failed repair send is not an error. Before
    this throttle the unchanged snapshot was re-sent to every oracle peer on
    every 2 s pass of the worker.

    Parameters
    ----------
    operation : dict
      A signed operation snapshot exactly as stored, with `operation_id`,
      `sequence` and `EE_SIGN`. It is written as is and never modified.

    Returns
    -------
    None
      After a send (confirmed, or a failed repair of an already confirmed
      snapshot) its time is recorded in `_operations_confirmed`; a call inside
      the 30 s window returns without sending or recording anything.

    Raises
    ------
    RuntimeError
      If the write is not confirmed and this exact snapshot was never
      confirmed before.

    Notes
    -----
    The 30 s timer is measured with `self.time()`; a negative age (a clock
    step backwards) counts as expired, so the record is sent rather than
    held back. A failed repair send also restarts the 30 s timer.

    Examples
    --------
    >>> plugin._replicate_operation(operation)  # not confirmed yet: writes and records the send
    >>> plugin._replicate_operation(operation)  # within 30 s: returns without writing
    >>> plugin.now += 31
    >>> plugin._replicate_operation(operation)  # repair: the same record is sent once more
    """
    # Read the confirmations kept in process memory since init; the signed snapshot carries no send bookkeeping.
    confirmed = self._operations_confirmed
    # Identify the snapshot by sequence and signature, and look up when it was last sent with confirmation.
    marker, last = (operation["sequence"], operation.get("EE_SIGN")), confirmed.get(operation["operation_id"])
    if last and last[:2] == marker and 0 <= self.time() - last[2] < 30:
      return
    key = "{}|{}".format(operation["operation_id"], operation["sequence"] % 8)
    if not self.chainstore_hset(OPERATIONS_HKEY, key, operation, readonly=True,
                               **self._operation_write_kwargs()):
      if not last or last[:2] != marker:
        # Only a snapshot that was never confirmed blocks the caller; a failed repair of an already
        # confirmed one no longer stops the node commands that follow it.
        raise RuntimeError("Deployment state replication is pending.")
    # Record this send (or failed repair) so the next repair of the same snapshot waits another 30 s.
    confirmed[operation["operation_id"]] = marker + (self.time(),)

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
    """Retry scoped commands while recording intent before transport dispatch.

    For every planned node that has not yet reported the wanted outcome
    (stopped for "stop" and "retire", ready for "start"), sends a pipeline
    command at most once per 10 s. Before each command the operation is saved
    so the durable record leads the side effect; a restore or owner-transfer
    start also binds each container instance to the runtime artifacts the
    retired revision reported. Each command carries the operation metadata
    (`DEEPLOY_OPERATION`) that nodes use to de-duplicate it.

    The 10 s resend throttle is kept in process memory
    (`_operations_sent_at`), not in the signed snapshot. Before, every
    command retry changed the snapshot's `sent_at` field, so the save before
    it wrote a new signed snapshot that every oracle re-stored and
    re-pickled; now that save writes only when the caller changed durable
    state.

    Parameters
    ----------
    operation : dict
      The coordinator's operation snapshot. It may be saved, and on a missing
      runtime image binding it is marked `recovery="blocked"` and saved with
      an event.
    configs : dict
      Node address -> pipeline config planned for that node. For "start" the
      config is sent as the payload; for "stop" and "retire" only its `TYPE`
      is used, with the job's `app_id` as the pipeline name.
    attempt : str
      The attempt the command belongs to: "deploy", "retire" or "restore".
    action : str
      The command: "start", "stop" or "retire".
    reports : dict
      Node address -> the newest signed node report for this attempt, as
      returned by `_node_operation_reports`. Nodes without a report get the
      command.

    Returns
    -------
    None
      Also returns early, without sending the remaining commands, when the
      worker is stopping.

    Raises
    ------
    RuntimeError
      If a restore or owner-transfer start lacks the previous runtime image
      binding for a container instance, or if a save is not confirmed.
    ValueError
      If this oracle is not the operation's coordinator (from
      `_save_operation`).

    Notes
    -----
    The throttle key is "operation id|attempt|action|node", so it is unique
    across operations in the shared map. A negative age (a clock step
    backwards) counts as expired, so the command is sent rather than held
    back. Entries are lost on restart, so pending commands are sent once
    more; nodes de-duplicate by operation id and attempt.

    Examples
    --------
    >>> plugin._send_operation_commands(operation, configs, "deploy", "start", reports={})
    >>> len(plugin._operations_sent_at)  # one command per planned node
    3
    >>> plugin._send_operation_commands(operation, configs, "deploy", "start", reports={})  # within 10 s
    >>> len(plugin.commands)  # nothing was sent again
    3
    """
    for node, config in configs.items():
      report = reports.get(node, {})
      if action in ("stop", "retire") and report.get("status") == "stopped":
        continue
      if action == "start" and report_is_ready(report, config):
        continue
      # Resend throttle in process memory, not in the signed snapshot; nodes de-duplicate by operation_id|attempt.
      sent_at = self._operations_sent_at
      # The map is shared by all operations, so the key starts with the operation id; the old in-snapshot
      # key needed only attempt|action|node.
      key = "{}|{}|{}|{}".format(operation["operation_id"], attempt, action, node)
      if 0 <= self.time() - sent_at.get(key, 0) < 10:
        continue
      # Record the send time in memory only: the save below then finds nothing changed and writes no new
      # snapshot for a mere retry.
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
            # What the instance cannot be restored without: a worker is rebuilt from its Git commit on a
            # base image the node pulls again, a container app is its image. Asking a worker for an image
            # id blocked its restoration over a value it does not need.
            needed = "git_commit" if plugin["SIGNATURE"].upper() == WORKER_APP_RUNNER_SIGNATURE else "image_id"
            if not artifacts or not artifacts.get(needed):
              operation["recovery"] = "blocked"
              # Name what is really missing: for a worker that is its Git commit, not an image.
              missing = "Git commit" if needed == "git_commit" else "image binding"
              # The blocked state and its reason are saved before the error stops the command.
              self._save_operation(operation, message="Previous runtime {} is unavailable; restoration is blocked.".format(missing))
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

    One pass of the operations worker. It clears admission handoffs that
    have finished, reads the newest verified snapshot of every operation this
    oracle coordinates from the local replica, and handles each one that no
    admission still holds: an unfinished operation is advanced, and
    a completed one whose last update is less than 600 s old is handed to
    `_replicate_operation`, which re-sends the final snapshot at most every
    30 s as peer repair.

    The repair of completed operations exists because a write needs only one
    confirmation, so an oracle can miss the final snapshot and nothing else
    sent it again. That oracle kept showing the operation as running and
    refused new changes to the job. Peers that already hold the record store
    nothing when it arrives again.

    Returns
    -------
    None
      A failure on one operation is logged and the pass continues with the
      next one.

    Notes
    -----
    Runs on the `deeploy-operations` thread every 2 s, or sooner when the
    wake-up event is set. Each operation is deep-copied before it is
    advanced, so the replica's records are not mutated in place.

    Examples
    --------
    >>> operation = plugin._save_operation(operation, "completed", "Deployment completed.")
    >>> plugin._reconcile_coordinator_operations()  # just confirmed: nothing is sent
    >>> plugin.now += 31
    >>> plugin._reconcile_coordinator_operations()  # the same final record is sent once more
    >>> plugin.now += 600
    >>> plugin._reconcile_coordinator_operations()  # past the 600 s window: left alone
    """
    # Clear completed handoffs BEFORE reading snapshots. Admissions that finish
    # during that read keep their marker until the next pass, avoiding a stale
    # `preparing` snapshot racing the request's final `accepted` write.
    for operation_id, finished in self._deployment_preparations.copy().items():
      if finished.is_set():
        self._deployment_preparations.pop(operation_id)
    own = [copy.deepcopy(operation) for operation in self._operation_records().values()
           if operation["coordinator"] == self.bc.address]
    for operation in own:
      if operation["operation_id"] in self._deployment_preparations:
        continue
      try:
        if operation["phase"] != "completed":
          # Unfinished operations are advanced as before; completed ones are no longer skipped outright but
          # get the repair re-send below.
          self._advance_deployment_operation(operation)
        # For 600 s after completion, oracles that missed the final snapshot get it too.
        elif self.time() - operation["updated_at"] < 600:
          # Re-send the final snapshot as repair, throttled to once per 30 s; peers that hold it store nothing,
          # and an oracle that missed it stops showing the operation as running and refusing job changes.
          self._replicate_operation(operation)
      except Exception:
        self.P("Deployment operation waiting for storage or transport recovery.", color="y")

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
    """Authorize a lookup and return a bounded, redacted progress projection.

    Verifies the wallet's nonce-signed read envelope, then selects the
    newest operation of the authenticated escrow owner that matches the
    request's selectors, using only this oracle's local replica. The result
    holds the operation's public fields, a per-node view (observed revision,
    workload state, instances, staleness), readiness counts, a page of
    events, and the revision that is in effect. Any oracle can answer; only
    the coordinator advances the operation.

    `observation_stale` tells the caller that the snapshot may be outdated.
    Snapshots now change only when durable state changes and no longer on
    every retry, so their age alone does not mean that: an unfinished
    operation's snapshot is stale only when it is older than 30 s and its
    coordinator is not online for control.

    Parameters
    ----------
    request : dict
      The endpoint's request body:
      - "nonce", "EE_ETH_SIGN", "EE_ETH_SENDER": the reusable read
        authorization; nothing else in the request is part of it.
      - "operation_id" or "request_id" (str): selects one operation; at most
        one of the two may be given.
      - "job_id" (int or str, optional): limits the lookup to one job; it is
        required when neither selector above is given.
      - "kind" (str, optional): limits the lookup to "create", "update" or
        "delete" operations.
      - "events_limit" (int, optional): page size for events, 1 to 128,
        default 64.
      - "after_event_cursor" (int, optional): return only events with a
        higher sequence, default 0.

    Returns
    -------
    dict
      The progress projection: the operation fields ("operation_id",
      "request_id", "job_id", "app_id", "kind", "mutation", "sequence",
      "target_revision", "previous_revision", "phase", "outcome",
      "recovery", "coordinator", "created_at", "updated_at", "error") plus
      "status", "nodes", "target_nodes", "ready_nodes",
      "observation_stale", "poll_after_ms", "events", "next_event_cursor"
      and "revision". When nothing matches, a short answer with "status"
      set to "synchronizing" (replicas may not have the record yet), or to
      "not_found" for a job lookup of the owner's job that has no tracked
      operation yet.

    Raises
    ------
    DeploymentAuthenticationError
      If the read authorization is invalid or expired.
    ValueError
      If both selectors are given, no selector or job_id is given, or
      events_limit or after_event_cursor is out of range.

    Examples
    --------
    >>> result = plugin._deployment_status({"operation_id": operation_id, "nonce": nonce,
    ...                                     "EE_ETH_SIGN": signature, "EE_ETH_SENDER": wallet})
    >>> result["status"], result["ready_nodes"], result["observation_stale"]
    ('waiting_for_readiness', 2, False)
    """
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
      # Snapshots now change only with state: an old one is stale only while its coordinator is away.
      observation_stale=operation["phase"] != "completed" and now - operation["updated_at"] > 30
        # With the coordinator online, an old snapshot only means nothing durable changed during a long
        # wait (snapshots are no longer rewritten per retry), so it is not reported as an outdated view.
        and not self._netmon_node_is_online_for_control(operation["coordinator"]),
      poll_after_ms=2000, events=events[:limit],
      next_event_cursor=events[limit - 1]["sequence"] if len(events) > limit else None,
      revision=operation["target_revision"] if operation["outcome"] == "succeeded" else operation["previous_revision"] or 0,
    )
    return result
