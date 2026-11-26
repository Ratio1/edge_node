"""dAuth custody for the receiving coordinator's existing deployment lifecycle."""
import copy
import hashlib

from .dauth_registry import dauth_registry_write_kwargs
from .repair_tunnel import reconcile_restore_tunnel
from extensions.business.deeploy.deployment_operations import (
  check_replacement_placement, deployment_operation_phase, required_instances, ReplacementPlacementMismatch,
  SIGNATURE_KEYS, STATELESS_REPLACEMENT,
)
from extensions.business.deeploy.relink_placement import relink_configs, relink_pipeline


REVISIONS = "DAUTH_JOB_SECRET_REVISIONS"
CURRENT = "DAUTH_JOB_SECRETS"
POINTERS = "DEEPLOY_DEPLOYED_JOBS"
AUTH_FIELDS = SIGNATURE_KEYS | {"EE_ETH_SENDER", "EE_ETH_SIGN"}


class DeploymentSecretRecordTooLarge(ValueError):
  """
  The chain store refused a deployment's secret record for its size.

  Raised by ``_prepare_deployment_secret_revisions`` when the write of a secret-revision record, the target copy
  or the restoration copy, ends with the chain store's outcome word ``refused_too_large``. It is a
  ``ValueError``, so it is final like the other refusals of a request: the chain store of every oracle of this
  release has the same size cap, and no retry can store the record.

  Notes
  -----
  The type is its own so that the dAuth endpoint can tell this one refusal from every other failure and name
  it to the caller by a fixed reason code (see ``reconcile_job_secrets``). It carries no text: the endpoint
  reads the type only, and the caller's client words the refusal itself.

  Examples
  --------
  >>> issubclass(DeploymentSecretRecordTooLarge, ValueError)
  True
  """


def _revision_ref(operation, attempt):
  """Derive the immutable custody reference for an attempt.

  The repair namespace also prevents an older dAuth from preparing a child with
  legacy rollback semantics.

  Parameters
  ----------
  operation : dict
    Authenticated coordinator operation.
  attempt : str
    Deploy or restore attempt.

  Returns
  -------
  str
    Operation-scoped secret revision.

  Examples
  --------
  >>> _revision_ref({"operation_id": "op", "mutation": "same_host_repair_v1"}, "restore")
  'op:repair_v1:restore'
  """
  scope = ":repair_v1:" if operation.get("mutation") == "same_host_repair_v1" else ":"
  return operation["operation_id"] + scope + attempt


class _DauthDeploymentSecretsMixin:
  """Prepare immutable secrets and publish only at lifecycle finalization."""

  def _deployment_secret_context(self, body, requester):
    """
    Authenticate an operation and its immutable, entirely redacted plan.

    Checks that the deployment operation is signed by the requesting coordinator for
    this network, that its identity (job, operation ID prefix, kind, revisions) is
    well formed, and that the requested action fits the operation's phase and kind.
    It then reads the operation's plan from R1FS and checks that every planned
    configuration matches the operation's placement and identity and carries no
    plaintext secret. Every lifecycle custody action starts here, on the single
    dAuth request thread, so the plan read is bounded: ``pin=False`` keeps
    ``ipfs pin add`` out and makes the 10 s ``timeout`` the real bound.

    Parameters
    ----------
    body : dict
      The verified ``reconcile_job_secrets`` request body. Uses ``operation`` (the
      coordinator-signed operation snapshot), ``job_id`` and ``action`` (one of
      "prepare", "status", "commit", "revoke" or "delete").
    requester : str
      The verified node address that signed the request; it must be the
      operation's coordinator and sender.

    Returns
    -------
    tuple
      ``(job_id, operation, plan)``: the normalized job ID (str), the operation
      dict and the plan dict read from ``operation["plan_cid"]``.

    Raises
    ------
    ValueError
      When the operation is missing, unsigned, not from ``requester`` or for another
      network, its identity is malformed, the action does not match its phase or
      kind, or the plan's placement, identity, redaction or secret references are
      invalid.
    RuntimeError
      When the plan cannot be read from R1FS, or a newer signed snapshot of the
      same operation is already held on this node (both retryable).

    Examples
    --------
    >>> job_id, operation, plan = self._deployment_secret_context(body, requester)
    >>> job_id, operation["phase"], sorted(plan)  # an update in its prepare phase
    ('42', 'preparing', ['configs', 'previous_configs'])
    """
    operation = body.get("operation")
    if not isinstance(operation, dict):
      raise ValueError("A signed deployment operation is required.")
    if (operation.get("coordinator") != requester or operation.get("EE_SENDER") != requester
        or operation.get("network") != self.evm_network
        or not self.bc.verify(operation, return_full_info=True, log_hash_sign_fails=False).valid):
      raise ValueError("Invalid deployment coordinator authentication.")
    job_id = self._normalize_dauth_job_id(body.get("job_id"))
    operation_id = operation.get("operation_id", "")
    prefix = hashlib.sha256(requester.encode()).hexdigest()[:16] + "-"
    if (str(operation.get("job_id")) != job_id or not operation_id.startswith(prefix)
        or not operation.get("request_hash") or not operation.get("owner")
        or operation.get("kind") not in ("create", "update", "delete")
        or type(operation.get("target_revision")) is not int or operation["target_revision"] < 1
        or (operation["kind"] != "create" and (
          type(operation.get("previous_revision")) is not int
          or not 0 <= operation["previous_revision"] < operation["target_revision"]))):
      raise ValueError("Invalid deployment operation identity.")
    if operation.get("mutation") in ("same_host_repair_v1", STATELESS_REPLACEMENT):
      if not isinstance(operation.get("phase"), str):
        raise ValueError("Invalid repair custody phase.")
      phase = deployment_operation_phase(operation)
      if phase == operation["phase"]:
        raise ValueError("Invalid repair custody phase.")
      # Normalize a private view only after authenticating the original signed snapshot above.
      operation = dict(operation, phase=phase)
    action, phase = body.get("action"), operation.get("phase")
    phases = {
      "prepare": {"preparing"}, "status": {"preparing"},
      "commit": {"finalizing", "finalizing_recovery"},
      "revoke": {"preparing", "cleaning_up_preparation", "stopping_failed_rollout", "finalizing", "finalizing_recovery", "retiring_previous"},
      "delete": {"retiring_previous"},
    }
    if operation.get("mutation") == STATELESS_REPLACEMENT:
      phases["status"].add("finalizing")  # Reconcile the exact published attempt if the original reply was lost.
    if action not in phases or phase not in phases[action]:
      raise ValueError("Secret action does not match the deployment phase.")
    if (operation.get("kind") == "delete") != (action == "delete" or (action == "revoke" and phase == "retiring_previous")):
      raise ValueError("Secret action does not match the deployment kind.")
    # Read the plan within the 10 s timeout and without pinning: this node does not need its own
    # pin of the plan, because the writer and the relays keep theirs.
    plan = self.r1fs.get_json(operation["plan_cid"], timeout=10, pin=False, show_logs=False)
    if not isinstance(plan, dict):
      raise RuntimeError("Deployment plan is unavailable.")
    for attempt, key, node_key, instance_key, revision_key in (
      ("deploy", "configs", "nodes", "instances", "target_revision"),
      ("restore", "previous_configs", "previous_nodes", "previous_instances", "previous_revision"),
    ):
      configs = plan.get(key)
      if not isinstance(configs, dict) or set(configs) != set(operation.get(node_key, [])):
        raise ValueError("Deployment plan placement does not match the operation.")
      for node, config in configs.items():
        specs = config.get("DEEPLOY_SPECS", {})
        expected = operation.get(instance_key, {}).get(node, [])
        _, secrets = self._extract_and_redact_deeploy_dauth_secrets(config)
        if (config.get("NAME") != operation.get("app_id") or str(specs.get("job_id")) != job_id
            or str(config.get("OWNER", "")).lower() != operation["owner"].lower()
            or specs.get("revision", 0) != operation.get(revision_key)
            or [list(item) for item in required_instances(config)] != [list(item) for item in expected]
            or secrets is not None):
          raise ValueError("Deployment plan identity or redaction is invalid.")
        if operation["kind"] != "delete" and specs.get("secret_revision") != _revision_ref(operation, attempt):
          raise ValueError("Deployment secret reference is invalid.")
    # Read persisted/pushed replicas; remote revocations and newer snapshots
    # take effect after reaching this custodian, without request-time repair.
    records = (self.chainstore_hgetall(hkey="DEEPLOY_OPERATIONS") or {}).values()
    if operation.get("mutation") == "same_host_repair_v1":
      self._verify_held_repair_parent(operation, body, plan, records)
    elif operation.get("mutation") == STATELESS_REPLACEMENT and "repair_parent" in operation:
      self._require_held_repair_parent(operation, records)
    for record in records:
      if (isinstance(record, dict) and record.get("operation_id") == operation_id
          and record.get("coordinator") == requester and record.get("EE_SENDER") == requester
          and self.bc.verify(record, return_full_info=True, log_hash_sign_fails=False).valid
          and record.get("sequence", 0) > operation.get("sequence", 0)):
        raise RuntimeError("A newer deployment operation snapshot is available.")
    return job_id, operation, plan

  def _require_held_repair_parent(self, operation, records):
    """Resolve the latest authentic retirement hold for this exact child.

    Parameters
    ----------
    operation : dict
      Authenticated child operation.
    records : iterable
      Locally replicated coordinator snapshots.

    Returns
    -------
    tuple
      The signed parent and its reservation for this child.

    Examples
    --------
    >>> parent, hold = plugin._require_held_repair_parent(child, replicas)  # doctest: +SKIP
    """
    parent_ref = operation.get("repair_parent")
    if not isinstance(parent_ref, dict) or type(parent_ref.get("sequence")) is not int:
      raise ValueError("The repair has no valid parent reference.")
    requester = operation["coordinator"]
    parents = [record for record in records if isinstance(record, dict)
               and record.get("operation_id") == parent_ref.get("operation_id")
               and record.get("EE_SENDER") == requester and record.get("coordinator") == requester
               and type(record.get("sequence")) is int
               and self.bc.verify(record, return_full_info=True, log_hash_sign_fails=False).valid]
    if not parents:  # A dAuth with a lagging replica must wait for the authoritative hold.
      raise RuntimeError("The original coordinator's repair hold is unavailable.")
    parent = max(parents, key=lambda record: record["sequence"])
    hold = parent.get("repair_child") or {}
    if (parent.get("phase") != "holding_for_repair" or parent.get("mutation") != "node_relink"
        or parent.get("kind") != "update" or operation["kind"] != "update"
        or parent.get("plan_cid") != parent_ref.get("plan_cid")
        or parent_ref["sequence"] != hold.get("base_sequence") or parent["sequence"] <= parent_ref["sequence"]
        or hold.get("operation_id") != operation["operation_id"] or hold.get("request_hash") != operation["request_hash"]
        or parent["operation_id"] == operation["operation_id"] or parent["target_revision"] >= operation["target_revision"]
        or any(parent.get(key) != operation.get(key) for key in (
          "app_id", "job_id", "network", "owner", "previous_pipeline_cid", "previous_revision",
          "previous_secret_revision"))):
      raise ValueError("The original operation has not authorized this repair.")
    return parent, hold

  def _verify_held_repair_parent(self, operation, body, plan, records):
    """Bind a repair's custody actions to the original coordinator's held operation.

    A signature on the child alone cannot supersede an active parent. Its latest
    signed hold names exactly this child, the approved request and recipient aliases.

    Parameters
    ----------
    operation, body, plan : dict
      Authenticated child, custody request and immutable per-node plans.
    records : iterable
      Locally persisted operation replicas.

    Returns
    -------
    None
      Raises when the signed hold or authorized recipients do not agree.

    Examples
    --------
    >>> plugin._verify_held_repair_parent(child, body, plan, replicas)  # doctest: +SKIP
    """
    parent, hold = self._require_held_repair_parent(operation, records)
    if (parent.get("previous_revision") != 0 or parent.get("previous_operation_id")
        or parent.get("previous_secret_revision") or operation.get("previous_operation_id")):
      raise ValueError("Same-host repair requires the original legacy revision.")
    pairs = hold.get("node_aliases")
    if (not isinstance(pairs, list) or not pairs
        or any(not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(n, str) and n for n in pair)
               for pair in pairs)):
      raise ValueError("The original operation has no authorized relink placement.")
    old, new = zip(*pairs)
    nodes = set(operation["nodes"])
    reviewed = hold.get("licenses")
    if (not isinstance(reviewed, dict) or set(reviewed) != nodes or reviewed != operation.get("repair_licenses")
        or any(not isinstance(pair, list) or len(pair) != 2 or type(pair[0]) is not int
               or not isinstance(pair[1], str) or pair[1] != pair[1].lower() for pair in reviewed.values())
        or len(old) != len(set(old)) or len(new) != len(set(new)) or set(old) & nodes
        or len(nodes) != len(operation["nodes"]) or len(nodes) != len(operation["previous_nodes"])
        or set(operation["previous_nodes"]) != nodes or not set(new) <= nodes
        or type(operation.get("rotate_main_tunnel", False)) is not bool):
      raise ValueError("Invalid repair secret recipients.")
    if body["action"] == "prepare" and (body.get("node_aliases") != pairs or body.get("identity_aliases")):
      raise ValueError("The repair secret recipients changed.")
    if body["action"] in ("prepare", "status"):
      reverse = {current: previous for previous, current in pairs}
      addresses = {node: self.bc.node_address_to_eth_address(node) for node in nodes}
      slots = {eth.lower(): self.bc.node_address_to_eth_address(reverse.get(node, node)) for node, eth in addresses.items()}
      self._check_repair_paid_job(operation["job_id"], operation["owner"], slots)
      # An unversioned writer rejects a legacy placement with an inactive license even on a partitioned replica.
      if any(self.bc.is_node_licensed(node_address=node) is not False for node in old):
        raise ValueError("An earlier repair identity still has an active license.")
      licenses = {eth.lower(): self._current_repair_license(eth) for eth in addresses.values()}  # Keep EIP-55 case for Web3.
      if (any(licenses[eth.lower()] != reviewed[node] for node, eth in addresses.items())
          or len({license_id for license_id, _ in licenses.values()}) != len(nodes)):
        raise ValueError("A repair recipient no longer owns the reviewed license.")
      operation["_repair_grant"] = dict(owner=operation["owner"], slots=slots, licenses=licenses)
    for configs in (plan["configs"], plan["previous_configs"]):
      for config in configs.values():
        placement = config["DEEPLOY_SPECS"].get("current_target_nodes")
        if not isinstance(placement, list) or len(placement) != len(nodes) or set(placement) != nodes:
          raise ValueError("A repair plan contains a different placement.")

  def _check_repair_paid_job(self, job_id, owner, slots):
    """Require each reviewed slot to match exactly one currently paid address.

    During migration a paid slot can still name its old address. Its counterpart
    is restricted to the one recorded at preparation.

    Parameters
    ----------
    job_id, owner : str
      On-chain job and expected escrow owner.
    slots : dict
      Lowercase current ETH address to checksummed original paid address.

    Returns
    -------
    None
      Raises if ownership or any paid slot has changed.

    Examples
    --------
    >>> plugin._check_repair_paid_job("31", owner, current_to_previous)  # doctest: +SKIP
    """
    job = self.bc.get_job_details(job_id=int(job_id))
    active = job.get("activeNodes") if isinstance(job, dict) else None
    if (not isinstance(active, (list, tuple)) or not slots or len(active) != len(slots)
        or str(job.get("escrowOwner", "")).lower() != owner.lower()
        or type(job.get("numberOfNodesRequested")) is not int or job["numberOfNodesRequested"] != len(slots)):
      raise ValueError("The current job owner or paid placement changed.")
    paid = {str(address).lower() for address in active}
    if len(paid) != len(slots) or any(len({node, prior.lower()} & paid) != 1 for node, prior in slots.items()):
      raise ValueError("The current job owner or paid placement changed.")

  def _current_repair_license(self, eth):
    """Read the active license identity of an exact repair worker.

    Parameters
    ----------
    eth : str
      Current worker ETH address, preserving its Web3 checksum.

    Returns
    -------
    list
      License ID and license owner; raises if the address is no longer registered.

    Examples
    --------
    >>> plugin._current_repair_license(worker_eth)  # doctest: +SKIP
    [42, '0xowner']
    """
    info = self.bc.get_node_license_info(node_address_eth=eth, raise_if_error=True)
    if (not isinstance(info, dict) or info.get("isValid") is not True or str(info.get("nodeAddress")).lower() != eth.lower()
        or type(info.get("licenseId")) is not int or not isinstance(info.get("owner"), str) or not info["owner"]):
      raise ValueError("A repair recipient has no active license.")
    return [info["licenseId"], info["owner"].lower()]

  def _deployment_secret_record(self, job_id, revision):
    """Return one exact, unrevoked record; never substitute current secrets."""
    key = job_id + "|" + revision
    if self.chainstore_hget(hkey=REVISIONS, key=key + "|revoked"):
      raise ValueError("Deployment secret revision is revoked.")
    record = self.chainstore_hget(hkey=REVISIONS, key=key)
    if record is not None and (
      not isinstance(record, dict) or record.get("revoked")
      or record.get("job_id") != job_id or record.get("revision") != revision
    ):
      raise ValueError("Invalid deployment secret revision.")
    return record

  def _prepare_deployment_secret_revisions(self, job_id, operation, plan, body):
    """
    Reconcile target and restoration copies without changing the active CID.

    Checks that the job's active pipeline is still the one the operation was built on and collects the secret
    values the previous revision holds. It then builds one secret-revision record per attempt of the plan: the
    restoration copy (``previous_configs``) and the target copy (``configs``). A record holds the job's secret
    values and one pipeline configuration per target node, so it grows with the number of nodes and with the
    size of the configurations. Both records are built and checked before either is written; each is then
    written to the dAuth registry peers and must be confirmed.

    Parameters
    ----------
    job_id : str
      The normalized Deeploy job ID.
    operation : dict
      The authenticated operation from ``_deployment_secret_context``, in its "preparing" phase.
    plan : dict
      The operation's verified plan: ``configs`` and ``previous_configs``, each keyed by node.
    body : dict
      The verified request body. ``new_secrets`` and ``previous_new_secrets`` carry fresh secret values;
      ``identity_aliases`` and ``node_aliases`` carry the renames of a scale-up and of a relink.

    Returns
    -------
    None
      The records are in the chain store, under ``DAUTH_JOB_SECRET_REVISIONS``.

    Raises
    ------
    ValueError
      When the active pipeline or the previous revision changed, a create would replace an active pipeline,
      a staged revision would get other values, or the secret values cannot be completed. All are final: the
      same request fails again.
    DeploymentSecretRecordTooLarge
      When the chain store refuses either record for its size: a ``ValueError`` too, and the one failure the
      dAuth endpoint names to the caller.
    RuntimeError
      When the previous secret revision is not available, or a record's write failed for another reason,
      such as no confirmation in time (retryable).

    Notes
    -----
    The chain store refuses a record over its size cap and reports the outcome word ``refused_too_large``
    through ``result_info``. That refusal is final, for either copy, so it gets its own error type, which
    carries no text (so no value, key or node). ``reconcile_job_secrets`` answers every failure with one fixed
    text and, for this type only, the reason code ``record_too_large``, from which the caller's client makes
    its own text. The restoration copy is written first; when it is the one refused, nothing is stored. Every
    other refusal of the store (``refused_too_deep`` and ``refused_unencodable`` among them) keeps the
    "pending" error and gets no code.

    Examples
    --------
    >>> self._prepare_deployment_secret_revisions("42", operation, plan, body)   # an update of job 42
    >>> staged = self.chainstore_hgetall(hkey="DAUTH_JOB_SECRET_REVISIONS")
    >>> sorted(key for key in staged if key.startswith("42|" + operation["operation_id"]))
    ['42|<operation_id>:deploy', '42|<operation_id>:restore']
    """
    prior_cid, prior_pipeline = self._load_dauth_job_pipeline_record(job_id)
    if prior_cid != operation.get("previous_pipeline_cid"):
      raise ValueError("The active pipeline changed before preparation.")
    prior_bundle = None
    if operation["kind"] == "update":
      if (not isinstance(prior_pipeline, dict)
          or prior_pipeline.get("DEEPLOY_SPECS", {}).get("revision", 0) != operation["previous_revision"]):
        raise ValueError("The previous deployment revision changed.")
      prior_reference = prior_pipeline.get("DEEPLOY_SPECS", {}).get("secret_revision")
      if prior_reference != operation.get("previous_secret_revision"):
        raise ValueError("The previous secret revision changed.")
      if prior_reference:
        prior_bundle = self._deployment_secret_record(job_id, prior_reference)
        if prior_bundle is None:
          raise RuntimeError("The previous secret revision is unavailable.")
        if ":repair_v1:" in prior_reference:
          prior_bundle = dict(prior_bundle, pipelines=prior_bundle["repair_pipelines"])  # Future ordinary edits reuse these values.
      elif (self._load_dauth_job_secret_bundle(job_id) is not None
            or any(self._iter_deeploy_dauth_placeholder_paths(prior_pipeline))):
        prior_bundle = self._load_current_dauth_secret_bundle(job_id, prior_cid, prior_pipeline, require_unversioned=True)
      else:
        # First updates can recover values from the published plaintext
        # configuration without requiring an already-existing dAuth bundle.
        _, prior_secrets = self._extract_and_redact_deeploy_dauth_secrets(prior_pipeline)
        prior_bundle = dict(job_id=job_id, job_secrets=prior_secrets or {})
        if self._load_dauth_pipeline_cid(job_id) != prior_cid:
          raise ValueError("The active pipeline changed before preparation.")
    elif prior_cid:
      raise ValueError("A create cannot replace an active pipeline.")
    # A relinked node takes over the old node's values, including its per-node secret paths.
    node_aliases = dict(body.get("node_aliases") or [])
    is_repair = operation.get("mutation") == "same_host_repair_v1"
    replacing = operation.get("mutation") == STATELESS_REPLACEMENT
    if replacing and set(operation.get("replacement_licenses", ())) != set(plan["configs"]):
      raise ValueError("Replacement custody requires an exact license binding for every target.")
    if prior_bundle and "replacement_pipelines" in prior_bundle:
      # Later edits still inherit protected values from the committed replacement.
      prior_bundle = dict(prior_bundle, pipelines=prior_bundle["replacement_pipelines"])
    if is_repair:
      # A legacy CID may combine plaintext connector fields and separately custodied environment values.
      canonical, inline = self._extract_and_redact_deeploy_dauth_secrets(prior_pipeline)
      prior_bundle = dict(prior_bundle, job_secrets=self._merge_deeploy_dauth_secret_fragments(
        copy.deepcopy(prior_bundle.get("job_secrets") or {}), inline, reject_conflicts=True,
      ))
      if str(prior_pipeline.get("OWNER", "")).lower() != operation["owner"].lower():
        raise ValueError("The stored job has a different owner.")
      old_nodes = prior_pipeline["DEEPLOY_SPECS"].get("current_target_nodes", [])
      targets = set(operation["nodes"])
      old_eth = {self.bc.node_address_to_eth_address(node).lower() for node in node_aliases}
      new_eth = {self.bc.node_address_to_eth_address(node).lower() for node in targets}
      if (not set(node_aliases) <= set(old_nodes) or len(old_eth) != len(node_aliases) or old_eth & new_eth
          or len(old_nodes) != len(targets) or {node_aliases.get(node, node) for node in old_nodes} != targets
          or len(new_eth) != len(targets) or new_eth & self._dauth_revoked_nodes.keys()):
        raise ValueError("The repair cannot grant secrets to this placement.")
    if node_aliases:
      prior_pipeline = relink_pipeline(prior_pipeline, node_aliases)
      # Work on a new bundle; the original revision still owns its immutable recipient map.
      prior_bundle = dict(prior_bundle, job_secrets=relink_pipeline(prior_bundle["job_secrets"], node_aliases))
      if "pipelines" in prior_bundle:
        prior_bundle["pipelines"] = relink_configs(prior_bundle["pipelines"], node_aliases)
    aliases = {tuple(current): tuple(source) for current, source in body.get("identity_aliases", [])}
    records = []
    for attempt, key, fragments in (
      # Only canonical custody can supply the original worker's secrets for a repair.
      ("restore", "previous_configs", None if is_repair else body.get("previous_new_secrets")),
      ("deploy", "configs", body.get("new_secrets")),
    ):
      configs = plan[key]
      if not configs:
        continue
      reference = _revision_ref(operation, attempt)
      bundle = dict(job_id=job_id, job_secrets={})
      prior_configs = (prior_bundle or {}).get("pipelines", {} if is_repair else plan["previous_configs"])
      for node, config in configs.items():
        source = prior_configs.get(node, prior_pipeline)
        if is_repair and required_instances(config) != required_instances(source):
          raise ValueError("The repair would give a different worker instance access to protected values.")
        node_bundle = self._build_complete_dauth_job_secret_bundle(
          job_id, config, fragments,
          prior_bundle=prior_bundle, prior_pipeline=source,
          current_identity_aliases=aliases if attempt == "deploy" else None,
        )
        bundle["job_secrets"] = self._merge_deeploy_dauth_secret_fragments(
          bundle["job_secrets"], node_bundle["job_secrets"], reject_conflicts=True,
        )
      record = dict(bundle, revision=reference, pipelines=copy.deepcopy(configs))
      if is_repair:
        record["repair_plan_cid"] = operation["plan_cid"]  # Recovery status can verify the exact prepared plan.
        record["repair_grant"] = operation["_repair_grant"]  # Each direct fetch must still own the reviewed license.
      if replacing:
        # Earlier dAuth versions require the ordinary "pipelines" field and cannot grant this revision.
        record["replacement_pipelines"] = record.pop("pipelines")
        record["replacement_licenses"] = operation["replacement_licenses"]
        record["replacement_owner"] = operation["owner"]
      records.append((reference, record))
    if is_repair:
      # An unapproved token change must never commit a restore plan that still uses a revoked connector.
      reconcile_restore_tunnel(self, canonical, records[0][1], records[1][1], body.get("new_secrets") or {},
                               operation.get("rotate_main_tunnel", False))
      for _, record in records:
        # An old dAuth requires a "pipelines" grant. It must reject even a fully replicated repair record.
        record["repair_pipelines"] = record.pop("pipelines")
    for reference, record in records:
      existing = self._deployment_secret_record(job_id, reference)
      if existing is not None and existing != record:
        raise ValueError("An immutable secret revision cannot be replaced.")
    # Validate both copies before staging either. A partial replication can still
    # need recovery, but invalid target placeholders must not create an orphan.
    if is_repair:
      # Hold the legacy pointer on this custodian even if the old licenses later become active again.
      if not self.chainstore_hset(hkey=REVISIONS, key=job_id + "|repair_hold|" + prior_cid,
                                  value=operation["repair_parent"], **dauth_registry_write_kwargs(self)):
        raise RuntimeError("The repair's custody hold is pending.")
    for reference, record in records:
      # The dict the chain store fills with its word for how the write ended; read when the write failed.
      info = {}
      # The same write as before, now with the caller's dict, so a failure can be told by its cause.
      if not self.chainstore_hset(hkey=REVISIONS, key=job_id + "|" + reference, value=record,
                                  result_info=info, **dauth_registry_write_kwargs(self)):
        if info["outcome"] == "refused_too_large":
          # The record is over the chain store's size cap, here and on every other oracle: no retry can store
          # it, so it is a final error that says what to change. Before, it ended in the retryable "pending"
          # error below, like a write that was only not confirmed yet. A type of its own (before, a plain
          # ValueError), so that the endpoint can give the caller the reason code of this one refusal. No text:
          # the endpoint reads the type only and the client words the refusal, so a text here had no reader.
          raise DeploymentSecretRecordTooLarge()
        raise RuntimeError("Deployment secret preparation is pending.")

  def _deployment_secrets_prepared(self, job_id, operation, plan):
    """Confirm existing preparation after a crash without regenerating values."""
    records = []
    for key in ("previous_configs", "configs"):
      configs = plan[key]
      if not configs:
        continue
      reference = next(iter(configs.values()))["DEEPLOY_SPECS"]["secret_revision"]
      try:
        record = self._deployment_secret_record(job_id, reference)
      except ValueError:
        # Interrupted cleanup may have replicated its marker before erasure.
        # Report incomplete so the coordinator can finish that same cleanup.
        return False
      placements = "repair_pipelines" if operation.get("mutation") == "same_host_repair_v1" else "pipelines"
      if operation.get("mutation") == STATELESS_REPLACEMENT:
        placements = "replacement_pipelines"
        if (record is None or record.get("replacement_licenses") != operation.get("replacement_licenses")
            or record.get("replacement_owner") != operation["owner"]):
          return False  # Recovery must not treat an ordinary grant as a scoped replacement grant.
      if (record is None or record.get(placements) != configs or
          (operation.get("mutation") == "same_host_repair_v1" and (
            record.get("repair_plan_cid") != operation["plan_cid"] or record.get("repair_grant") != operation["_repair_grant"]))):
        return False
      records.append((reference, record))
    for reference, record in records:
      if not self.chainstore_hset(hkey=REVISIONS, key=job_id + "|" + reference, value=record,
                                  **dauth_registry_write_kwargs(self)):
        raise RuntimeError("Deployment secret replication is pending.")
    return True

  def _publish_deployment_secrets(self, job_id, operation, plan, pointer, deleted=False, resume_only=False):
    """
    Bind custodied secrets to a verified coordinator-signed final pointer.

    Verifies that ``pointer`` is the coordinator's signed publication for exactly this
    operation and that it has not been superseded. For a deployment it reads the
    published configuration from R1FS, checks it against the plan, and turns the
    prepared secret revision of the active attempt into the job's current, signed
    secret bundle; for a delete it revokes the job's previous secret revision and
    publishes an empty bundle. It then writes the bundle, writes the pointer and removes the
    previous pipeline CID from R1FS. The published-configuration read runs on the
    single dAuth request thread, so it is bounded: ``pin=False`` keeps
    ``ipfs pin add`` out and makes the 10 s ``timeout`` the real bound.

    Parameters
    ----------
    job_id : str
      The normalized Deeploy job ID.
    operation : dict
      The authenticated operation from ``_deployment_secret_context``; its phase is
      "finalizing", "finalizing_recovery" or (for a delete) "retiring_previous".
    plan : dict
      The operation's verified plan (``configs`` and ``previous_configs``). With
      phase "finalizing_recovery" the restored ``previous_configs`` are published,
      otherwise ``configs``.
    pointer : dict or None
      The coordinator-signed final deployment pointer from the request body
      (``job_id``, ``revision``, ``operation_id``, ``coordinator``, ``deleted``,
      ``pipeline_cid`` and, unless deleted, ``plan_cid``). None is rejected.
    deleted : bool, optional
      True for a delete: the pointer must carry ``pipeline_cid`` None, the job's
      previous secret revision is revoked and an empty bundle is published in place
      of the prepared one. Default False.
    resume_only : bool, optional
      A replacement may finish only if an exact signed custody write or pointer
      proves that publication already started.

    Returns
    -------
    bool
      True after publication. False when a resume-only call finds no proof of
      an earlier write. A missing replica does not prove publication failed.

    Raises
    ------
    ValueError
      When the pointer is missing, unsigned or does not match the operation, the
      publication was superseded, the published configuration differs from the
      plan, or the prepared secret revision is revoked or invalid.
    RuntimeError
      When the published configuration or the prepared secrets are not available, or
      a chain-store write was not confirmed (all retryable).

    Examples
    --------
    >>> self._publish_deployment_secrets("42", operation, plan, body["pointer"])
    >>> self._load_dauth_pipeline_cid("42") == body["pointer"]["pipeline_cid"]
    True
    """
    if not isinstance(pointer, dict):
      raise ValueError("A signed deployment publication pointer is required.")
    expected = dict(job_id=job_id, revision=operation["target_revision"],
                    operation_id=operation["operation_id"], coordinator=operation["coordinator"],
                    deleted=deleted, pipeline_cid=None if deleted else pointer.get("pipeline_cid"))
    if not deleted:
      expected["plan_cid"] = operation["plan_cid"]
    if ({key: value for key, value in pointer.items() if key not in AUTH_FIELDS} != expected
        or pointer.get("EE_SENDER") != operation["coordinator"]
        or not self.bc.verify(pointer, return_full_info=True, log_hash_sign_fails=False).valid):
      raise ValueError("Invalid deployment publication pointer.")
    current = self.chainstore_hget(hkey=POINTERS, key=job_id)
    current_fields = {key: value for key, value in current.items() if key not in AUTH_FIELDS} if isinstance(current, dict) else current
    replacing = operation.get("mutation") == STATELESS_REPLACEMENT
    if replacing and pointer != operation.get("replacement_publication"):
      raise ValueError("The replacement pointer must match the persisted publication intent.")
    already_published = current_fields == expected
    if replacing and already_published:
      # An unauthenticated replica cannot waive the exact placement check for a new publication.
      already_published = (current.get("EE_SENDER") == operation["coordinator"]
                           and self.bc.verify(current, return_full_info=True, log_hash_sign_fails=False).valid)
    if not already_published and (
      (isinstance(current, dict) and current.get("revision", 0) >= operation["target_revision"])
      or self._load_dauth_pipeline_cid(job_id) != operation.get("previous_pipeline_cid")
    ):
      raise ValueError("Deployment publication has been superseded.")
    started = already_published
    if replacing and not started:
      # dAuth writes the signed current bundle before the public pointer. Either exact write can prove continuation.
      previous_write = self._load_dauth_job_secret_bundle(job_id)
      if isinstance(previous_write, dict) and all(
        previous_write.get(key) == value for key, value in (
          ("job_id", job_id), ("operation_id", operation["operation_id"]), ("coordinator", operation["coordinator"]),
          ("deployment_revision", operation["target_revision"]), ("pipeline_cid", pointer["pipeline_cid"]), ("deleted", False),
        )
      ):
        signature = self.bc.verify(previous_write, return_full_info=True, log_hash_sign_fails=False)
        started = signature.valid and self.bc.is_dauth_oracle(
          node_address_eth=self.bc.node_address_to_eth_address(signature.sender),
        )
    if resume_only and not started:
      return False
    if deleted:
      self._revoke_deployment_secret_revisions(job_id, operation, plan, None)
      bundle = dict(job_id=job_id, job_secrets={})
    else:
      configs = plan["previous_configs" if operation["phase"] == "finalizing_recovery" else "configs"]
      representative = copy.deepcopy(next(iter(configs.values())))
      representative.pop("DEEPLOY_OPERATION", None)
      canonical = self._recursively_sort_pipeline_data(self.extract_invariable_data_from_pipeline(representative))
      # Read the published configuration within the 10 s timeout and without pinning: this node
      # does not need its own pin of it, because the writer and the relays keep theirs.
      published = self.r1fs.get_json(pointer["pipeline_cid"], timeout=10, pin=False, show_logs=False)
      if published is None:
        raise RuntimeError("Published deployment configuration is unavailable.")
      if published != canonical:
        raise ValueError("Published configuration does not match the operation plan.")
      reference = representative["DEEPLOY_SPECS"]["secret_revision"]
      record = self._deployment_secret_record(job_id, reference)
      placements = "repair_pipelines" if operation.get("mutation") == "same_host_repair_v1" else "pipelines"
      if replacing:
        placements = "replacement_pipelines"
        if (record is None or record.get("replacement_licenses") != operation["replacement_licenses"]
            or record.get("replacement_owner") != operation["owner"]):
          raise ValueError("Replacement publication requires the reviewed credential grant.")
      if (record is None or record.get(placements) != configs or
          (operation.get("mutation") == "same_host_repair_v1" and record.get("repair_plan_cid") != operation["plan_cid"])):
        raise RuntimeError("Active deployment secrets are unavailable.")
      bundle = {key: copy.deepcopy(value) for key, value in record.items()
                if key not in (placements, "repair_plan_cid", "repair_grant", "replacement_licenses", "replacement_owner")}
    bundle.update(job_id=job_id, deployment_revision=operation["target_revision"],
                  operation_id=operation["operation_id"], coordinator=operation["coordinator"],
                  deleted=deleted, pipeline_cid=pointer["pipeline_cid"])
    self.bc.sign(bundle, add_data=True, use_digest=True)
    if replacing and not started:
      # Recheck after loading R1FS and immediately before the first write to custody.
      check_replacement_placement(self, operation)
    if not self._write_dauth_job_secret_bundle(job_id, bundle):
      raise RuntimeError("Deployment secret publication is pending.")
    if not self._write_job_pipeline_cid(job_id, pointer):
      raise RuntimeError("Deployment metadata publication is pending.")
    previous_cid = operation.get("previous_pipeline_cid")
    if previous_cid and previous_cid != pointer["pipeline_cid"]:
      self._delete_pipeline_cid_from_r1fs(previous_cid)
    return True

  def _revoke_deployment_secret_revisions(self, job_id, operation, plan, active_attempt):
    """
    Erase only operation-derived unused references after lifecycle barriers.

    First checks that cleanup is allowed in the operation's phase: ``active_attempt``
    must match the phase, preparation cleanup waits for the preparation deadline, and
    a failed rollout that can still restore previous nodes is not cleaned up. When an
    attempt is active, the published pointer must belong to this operation and the
    published configuration, read from R1FS, must match the plan. Then each unused
    secret revision gets a "revoked" marker and its record is overwritten with a
    revoked copy that keeps no secrets. The published-configuration read runs on the
    single dAuth request thread, so it is bounded: ``pin=False`` keeps
    ``ipfs pin add`` out and makes the 10 s ``timeout`` the real bound.

    Parameters
    ----------
    job_id : str
      The normalized Deeploy job ID.
    operation : dict
      The authenticated operation from ``_deployment_secret_context``.
    plan : dict
      The operation's verified plan; its ``configs`` and ``previous_configs`` say
      which of the operation's revisions were prepared.
    active_attempt : str or None
      "deploy" when the target configuration is active (phase "finalizing"),
      "restore" when the previous configuration was restored (phase
      "finalizing_recovery"), or None when no attempt of this operation is active
      (preparation cleanup, a failed rollout, or a delete).

    Returns
    -------
    None
      The markers and revoked records are written to the chain store.

    Raises
    ------
    ValueError
      When cleanup does not match the lifecycle phase, the published configuration
      differs from the plan, or the operation's revision is already published and
      would be cleaned up as incomplete.
    RuntimeError
      When the publication is still pending, the published configuration cannot be
      read, or a chain-store write was not confirmed (all retryable).

    Examples
    --------
    >>> self._revoke_deployment_secret_revisions("42", operation, plan, "deploy")
    >>> self.chainstore_hget(hkey="DAUTH_JOB_SECRET_REVISIONS", key="42|" + operation["operation_id"] + ":restore")
    {'job_id': '42', 'revision': '<operation_id>:restore', 'revoked': True}
    """
    phase = operation["phase"]
    expected_active = {"finalizing": "deploy", "finalizing_recovery": "restore"}.get(phase)
    if active_attempt != expected_active or (
      phase in ("preparing", "cleaning_up_preparation") and self.time() < operation["preparation_deadline"]
    ) or (phase == "stopping_failed_rollout" and operation["kind"] != "create" and operation.get("previous_nodes")):
    # A failed update with no previous node left to restore is cleaned up like a failed create.
      raise ValueError("Secret cleanup does not match lifecycle recovery.")
    pointer = self.chainstore_hget(hkey=POINTERS, key=job_id)
    if active_attempt:
      configs = plan["configs" if active_attempt == "deploy" else "previous_configs"]
      representative = copy.deepcopy(next(iter(configs.values())))
      representative.pop("DEEPLOY_OPERATION", None)
      canonical = self._recursively_sort_pipeline_data(self.extract_invariable_data_from_pipeline(representative))
      if (not isinstance(pointer, dict) or pointer.get("deleted")
          or pointer.get("operation_id") != operation["operation_id"]
          or pointer.get("revision") != operation["target_revision"]
          or not pointer.get("pipeline_cid")):
        raise RuntimeError("Active deployment publication is pending.")
      # Read the published configuration within the 10 s timeout and without pinning: this node
      # does not need its own pin of it, because the writer and the relays keep theirs.
      published = self.r1fs.get_json(pointer["pipeline_cid"], timeout=10, pin=False, show_logs=False)
      if published is None:
        raise RuntimeError("Published deployment configuration is unavailable.")
      if published != canonical:
        raise ValueError("Published configuration does not match the operation plan.")
    elif operation["kind"] != "delete" and isinstance(pointer, dict) and pointer.get("operation_id") == operation["operation_id"]:
      # A stale preparing/failed snapshot must not revoke a revision that has
      # since become active, even if operation repair returned an older peer.
      raise ValueError("Published deployment secrets cannot be cleaned up as incomplete.")
    references = []
    if (active_attempt or operation["kind"] == "delete") and operation.get("previous_secret_revision"):
      references.append(operation["previous_secret_revision"])
    if operation["kind"] != "delete":
      for attempt, key in (("deploy", "configs"), ("restore", "previous_configs")):
        if attempt != active_attempt and plan[key]:
          references.append(_revision_ref(operation, attempt))
    repair_parent = (operation.get("repair_parent") if operation.get("mutation")
                     in ("same_host_repair_v1", STATELESS_REPLACEMENT) else None)
    if active_attempt and repair_parent:
      if (pointer.get("coordinator") != operation["coordinator"] or pointer.get("EE_SENDER") != operation["coordinator"]
          or pointer.get("plan_cid") != operation["plan_cid"]
          or not self.bc.verify(pointer, return_full_info=True, log_hash_sign_fails=False).valid):
        raise ValueError("The repair publication is unauthenticated.")
      # The held parent's two grants remain valid until the child really publishes one of its plans.
    # A failed replacement that dispatched workers also supersedes the parent.
    abandoned_parent = (operation.get("mutation") == STATELESS_REPLACEMENT and phase == "stopping_failed_rollout"
                        and bool(operation["dispatched_nodes"]))
    if repair_parent and (active_attempt or abandoned_parent):
      parent_id = repair_parent["operation_id"]  # The custody context verified the held parent.
      references.extend((parent_id + ":deploy", parent_id + ":restore"))
    for reference in set(references):
      key = job_id + "|" + reference
      marker = dict(job_id=job_id, revision=reference)
      if not self.chainstore_hset(hkey=REVISIONS, key=key + "|revoked", value=marker,
                                  **dauth_registry_write_kwargs(self)):
        raise RuntimeError("Deployment secret revocation is pending.")
      if not self.chainstore_hset(hkey=REVISIONS, key=key, value=dict(marker, revoked=True),
                                  **dauth_registry_write_kwargs(self)):
        raise RuntimeError("Deployment secret erasure is pending.")

  def process_dauth_deployment_secrets_request(self, body, requester, nonce):
    """Apply one authenticated lifecycle custody action and return references."""
    job_id, operation, plan = self._deployment_secret_context(body, requester)
    action = body["action"]
    result = dict(status="success", job_id=job_id, nonce=nonce, action=action,
                  operation_id=operation["operation_id"], plan_cid=operation["plan_cid"])
    if operation.get("mutation") == "same_host_repair_v1":
      result["repair_protocol"] = 1  # The receiver signs this capability alongside the attempt and plan.
    if action == "prepare":
      self._prepare_deployment_secret_revisions(job_id, operation, plan, body)
      result["prepared"] = True
    elif action == "status":
      if operation.get("mutation") == STATELESS_REPLACEMENT and operation["phase"] == "finalizing":
        # Old custodians refuse status in this phase, so none can start a fresh publication on this request.
        pointer = body.get("pointer")
        result["prepared"] = self._publish_deployment_secrets(job_id, operation, plan, pointer, resume_only=True)
        result["publication_committed"] = result["prepared"]
        result["pipeline_cid"] = pointer["pipeline_cid"]
      else:
        result["prepared"] = self._deployment_secrets_prepared(job_id, operation, plan)
    elif action == "revoke":
      self._revoke_deployment_secret_revisions(job_id, operation, plan, body.get("active_attempt"))
    else:
      try:
        self._publish_deployment_secrets(job_id, operation, plan, body.get("pointer"), deleted=action == "delete")
      except ReplacementPlacementMismatch:
        if (action != "commit" or operation.get("mutation") != STATELESS_REPLACEMENT
            or body.get("report_prewrite_refusal") is not True):
          raise
        # The checked placement failed before dAuth wrote either the bundle or pointer for this call.
        result["publication_refused_before_write"] = True
      result["pipeline_cid"] = body["pointer"]["pipeline_cid"]
    return result
