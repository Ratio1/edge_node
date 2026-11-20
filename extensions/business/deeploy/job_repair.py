"""CSP-approved recovery of a blocked single-worker-app license relink."""

import copy
import hashlib
import json
import re
import threading
import time
import uuid
from urllib.parse import urlsplit

from .deeploy_const import WORKER_APP_RUNNER_SIGNATURE
from .deployment_operations import DeploymentConflictError, NODE_OPERATIONS_HKEY, required_instances

MUTATION = "same_host_repair_v1"
# The original coordinator owns its parent. Serialize reservation against that coordinator's relink dispatch.
HANDOFF_LOCK = threading.RLock()
COMMIT = re.compile(r"[0-9a-f]{40}")


def worker(config):
  """Extract the sole supported Git worker instance.

  Parameters
  ----------
  config : dict
    Stored or observed worker pipeline.

  Returns
  -------
  dict
    Instance configuration, including its stable ID.

  Examples
  --------
  >>> worker({"PLUGINS": []})
  Traceback (most recent call last):
  ...
  ValueError: Repair requires one Git worker instance.
  """
  identities = required_instances(config)
  if len(config["PLUGINS"]) != 1 or len(identities) != 1 or identities[0][0] != WORKER_APP_RUNNER_SIGNATURE:
    raise ValueError("Repair requires one Git worker instance.")
  instance = config["PLUGINS"][0]["INSTANCES"][0]
  if config.get("PIPELINE_COMMAND") or instance.get("INSTANCE_COMMAND"):
    raise ValueError("A saved one-time runtime command cannot be replayed during recovery.")
  sync = instance.get("SYNC") or {}
  if (not isinstance(sync, dict) or sync.get("ENABLED", False) is not False
      or any(instance.get(key) for key in ("PER_NODE_CONFIG", "perNodeConfig", "VOLUMES", "FILE_VOLUMES", "FIXED_SIZE_VOLUMES"))):
    raise ValueError("A job with per-worker overrides or persistent volumes requires a different recovery.")
  return instance


def order_fields(config):
  """Read the three legacy lists in their actual order.

  Parameters
  ----------
  config : dict
    A single Git worker configuration.

  Returns
  -------
  dict
    Lists keyed by the signed correction contract.

  Examples
  --------
  >>> list(order_fields(config))  # doctest: +SKIP
  ['targets', 'commands', 'peers']
  """
  instance = worker(config)
  fields = dict(targets=config["DEEPLOY_SPECS"].get("current_target_nodes"),
                commands=instance.get("BUILD_AND_RUN_COMMANDS"), peers=instance.get("CHAINSTORE_PEERS"))
  for values in fields.values():
    if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
      raise ValueError("The previous worker's commands, targets or peers are unavailable.")
    if len(set(values)) != len(values):
      raise ValueError("The previous worker's order has ambiguous duplicate entries.")
  return fields


class _JobRepairMixin:
  """Recover a partially retired legacy revision on its original coordinator."""

  def _repair_aliases(self, stored, job):
    """Resolve each original paid slot against confirmed events and the current license.

    Parameters
    ----------
    stored : list
      Canonical previous targets in their original stored order.
    job : dict
      Current on-chain job details.

    Returns
    -------
    tuple
      Old-to-current internal addresses and the verified license ID/owner for each current worker.

    Examples
    --------
    >>> plugin._repair_aliases(["old"], job)  # doctest: +SKIP
    ({'old': 'current'}, {'current': [31, 'owner']})
    """
    confirmed = self.plugins_shmem.get("CHAIN_DIST_CONFIRMED_RELINKS") or {}
    active = {addr.lower() for addr in job["activeNodes"]}
    if type(job.get("numberOfNodesRequested")) is not int or job["numberOfNodesRequested"] != len(stored) or len(active) != len(stored):
      raise ValueError("The current paid placement does not account for every previous worker.")
    aliases, licenses, accounted = {}, {}, set()
    for old in stored:
      eth = self.bc.node_address_to_eth_address(old)
      link = confirmed.get(eth)
      if not link:
        raise ValueError("A confirmed same-license link is missing for a previous worker.")
      new_eth, license_id, owner = link
      new = self.bc.eth_addr_to_internal_addr(new_eth)
      info = self.bc.get_node_license_info(node_address_eth=new_eth, raise_if_error=True)
      # An unlinked address can have no license detail record. Query its explicit registration status.
      if (not new or self.bc.is_node_licensed(node_address_eth=eth) is not False or info.get("isValid") is not True
          or info.get("licenseId") != license_id or info["owner"].lower() != owner.lower()
          or info["nodeAddress"].lower() != new_eth.lower() or new in stored or new in aliases.values()):
        raise ValueError("The current node registration does not confirm the reviewed license relink.")
      slots = active & {eth.lower(), new_eth.lower()}
      if len(slots) != 1 or accounted & slots:
        raise ValueError("A paid slot does not match exactly one relinked license.")
      accounted.update(slots)
      aliases[old] = new
      licenses[new] = [license_id, owner.lower()]  # Pin the exact license even if the same address is later reused.
    return aliases, licenses

  def _assess_job_repair(self, job_id, owner, coordinator=None):
    """Build the same read-only recovery proposal for review and signed admission.

    Parameters
    ----------
    job_id : int
      Selected job.
    owner, coordinator : str
      Authenticated escrow owner and optional pinned receiver.

    Returns
    -------
    tuple
      Public proposal, corrected prior config, parent, signed stop receipts, and verified license bindings.

    Examples
    --------
    >>> proposal, previous, parent, stopped, licenses = plugin._assess_job_repair(31, owner)  # doctest: +SKIP
    """
    if type(job_id) is not int or job_id <= 0:
      raise ValueError("A positive job ID is required.")
    job = self.bc.get_job_details(job_id=job_id)
    if not job or str(job.get("escrowOwner", "")).lower() != owner.lower():
      raise ValueError("The selected job does not belong to the signed-in CSP.")
    pending = [op for op in self._operation_records().values() if str(op["job_id"]) == str(job_id)
               and op["phase"] != "completed"]
    if len(pending) != 1:
      raise DeploymentConflictError("The job must have one outstanding relink operation.")
    parent = pending[0]
    if (parent["kind"] != "update" or parent.get("mutation") != "node_relink"
        or parent["owner"].lower() != owner.lower() or parent["phase"] != "retiring_previous"
        or parent.get("recovery") != "blocked" or (parent.get("error") or {}).get("code") != "PREVIOUS_STOP_UNCONFIRMED"
        or parent.get("previous_revision") != 0 or parent.get("previous_secret_revision")
        or parent.get("previous_operation_id") or parent.get("outcome") or (coordinator and coordinator != parent["coordinator"])):
      raise DeploymentConflictError("The blocked relink changed. Refresh the job before reviewing recovery.")
    cid = self._get_pipeline_from_cstore(job_id)
    if not cid or cid != parent.get("previous_pipeline_cid"):
      raise DeploymentConflictError("The published job has changed since retirement started.")
    pipeline = self.get_pipeline_from_r1fs(cid, timeout=10, pin=False, raise_on_error=False, show_logs=False)
    if (not pipeline or pipeline.get("NAME") != parent["app_id"] or str(pipeline.get("OWNER", "")).lower() != owner.lower()
        or str(pipeline["DEEPLOY_SPECS"]["job_id"]) != str(job_id) or pipeline["DEEPLOY_SPECS"].get("revision", 0) != 0
        or pipeline["DEEPLOY_SPECS"].get("secret_revision")):
      raise ValueError("The original published worker revision cannot be verified.")
    if worker(pipeline).get("SETUP_REPO", True) is not True:
      raise ValueError("Repair requires the previous worker to clone its Git checkout for rollback.")
    fields = order_fields(pipeline)
    aliases, licenses = self._repair_aliases(fields["targets"], job)
    receipts = self._node_operation_reports(parent, "retire")
    stopped, witnesses = {}, []
    known = self._job_reports(pipeline)
    if any(configs for node, configs in known.items() if node not in aliases.values()):
      raise ValueError("An additional node reports this job. Resolve its workload before recovery.")
    ident = required_instances(pipeline)
    for old, current in aliases.items():
      parent_slots = {old, current} & set(parent["previous_nodes"])
      if len(parent_slots) != 1 or set(parent["previous_nodes"]) != set(parent["nodes"]) or len(parent["nodes"]) != len(aliases):
        raise ValueError("The previous operation's placement cannot be reconciled with the license records.")
      slot = parent_slots.pop()
      if [tuple(pair) for pair in parent["previous_instances"].get(slot, [])] != ident:
        raise ValueError("The prior operation contains a different worker instance.")
      receipt = receipts.get(slot, {})
      if receipt.get("status") == "stopped":
        # A prior stop from the current worker can be reused without issuing another stop to an empty pipeline.
        pin = receipt["instances"][0].get("runtime_artifacts", {}).get("git_commit")
        if slot != current or not isinstance(pin, str) or not COMMIT.fullmatch(pin) or known.get(current):
          raise ValueError("The stopped worker's identity, Git receipt or current disposition is uncertain.")
        stopped[current] = receipt
      else:
        reports = known.get(current) or []
        if len(reports) != 1 or not self._netmon_node_is_online_for_control(current):
          raise ValueError("A current worker must report the previous job before it can be inspected.")
        live = reports[0]
        if required_instances(live) != ident or live.get("OWNER", "").lower() != owner.lower():
          raise ValueError("The responding worker's instance or owner has changed.")
        witnesses.append(live)
    if not stopped or not witnesses:
      raise ValueError("Recovery needs the original stop receipt and a surviving worker for the prior revision.")
    live = order_fields(witnesses[0])
    if any(order_fields(config) != live for config in witnesses):
      raise ValueError("The surviving workers disagree about the previous execution order.")
    if any(set(fields[k]) != set(live[k]) for k in fields):
      raise ValueError("The previous worker configuration contains changed entries, not only an order change.")
    # Take all content from the canonical CID. Replace only integral permutations of the three allowed lists.
    corrected = copy.deepcopy(pipeline)
    corrected["DEEPLOY_SPECS"]["current_target_nodes"] = list(live["targets"])
    worker(corrected).update(BUILD_AND_RUN_COMMANDS=list(live["commands"]), CHAINSTORE_PEERS=list(live["peers"]))
    # Load the v1 comparison only for this flow so older Core can continue handling ordinary updates.
    from naeural_core.business.deployment_lifecycle import repair_config_fingerprint
    for observed in witnesses:
      if repair_config_fingerprint(corrected) != repair_config_fingerprint(observed):
        raise ValueError("The surviving worker differs outside the reviewed order corrections.")
    orders = {k: [fields[k].index(value) for value in live[k]] for k in fields}
    proposal = dict(version=1, network=self.evm_network, job_id=job_id, coordinator=parent["coordinator"],
                    parent=dict(operation_id=parent["operation_id"], sequence=parent["sequence"], plan_cid=parent["plan_cid"]),
                    pipeline_cid=cid, expected_revision=0, orders=orders, instance_id=ident[0][1],
                    placements=[dict(previous=old, current=aliases[old]) for old in live["targets"]])
    return proposal, corrected, parent, stopped, licenses

  def _inspect_repair_workers(self, parent, config, proposal, fingerprint, licenses, stopped):
    """Check every paid worker's compatibility and prior state before retiring any.

    Parameters
    ----------
    parent : dict
      Coordinator-signed original relink.
    config : dict
      Reviewed previous revision before the address substitutions.
    proposal, licenses, stopped : dict
      Reverified signed proposal, current license bindings and historical receipts.
    fingerprint : str
      Local digest of the exact previous worker configuration.

    Returns
    -------
    tuple
      Fresh running-worker observations and their original encrypted expectations.

    Examples
    --------
    >>> witnesses, seals = plugin._inspect_repair_workers(parent, corrected, proposal, fingerprint, licenses, stopped)  # doctest: +SKIP
    """
    parent_id = parent["operation_id"]
    # Bind reuse to the complete prior state and license authority. Desired edits need no new observation of that state.
    scope = hashlib.sha256(json.dumps([proposal, fingerprint, licenses, stopped], sort_keys=True).encode()).hexdigest()
    with HANDOFF_LOCK:
      now = self.time()
      cache = self._repair_inspections
      for key, (_, challenges) in list(cache.items()):
        if any(meta["expires_at"] <= now for meta in challenges.values()):
          del cache[key]
      entry = cache.get(parent_id)
      if entry is None or entry[0] != scope:
        targets = [row["current"] for row in proposal["placements"]]
        seals = {node: self.bc.encrypt_str(fingerprint, node) for node in targets if node not in stopped}
        if any(not isinstance(seal, str) or not seal for seal in seals.values()):
          raise ValueError("Could not bind the prior configuration to its current worker.")
        # Bound the cache even if many approved jobs request inspection at once.
        if parent_id not in cache and len(cache) >= 64:
          del cache[next(iter(cache))]
        entry = (scope, {node: self._request_worker_inspection(parent, node, config, seals.get(node)) for node in targets})
        cache[parent_id] = entry
        retry = False
      else:
        retry = True
    pending = dict(entry[1])
    seals = {node: meta["config_seal"] for node, meta in pending.items() if node not in stopped}
    fields = order_fields(config)
    ordered = [fields[key] for key in ("targets", "commands", "peers")]
    digest = hashlib.sha256(json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    observations = {}
    deadline = time.monotonic() + 12  # One bounded wait, independent of how many nodes receive the preflight.
    while time.monotonic() < deadline:
      for node, meta in list(pending.items()):
        result = self._read_worker_inspection(parent, meta, digest)
        if not result:
          if retry:
            # Retry the existing challenge once. A late valid response still satisfies this request.
            self._send_worker_inspection(parent, config, meta)
          continue
        if node in stopped:
          original_pin = stopped[node]["instances"][0]["runtime_artifacts"]["git_commit"]
          if result["instances"][0]["runtime_artifacts"]["git_commit"] != original_pin:
            raise ValueError("The stopped worker's local Git receipt changed since its original retirement.")
        else:
          observations[node] = result  # These observations authorize a later conditional retirement.
        del pending[node]
      if not pending:
        return observations, seals
      retry = False
      time.sleep(0.25)
    raise DeploymentConflictError("A paid worker did not confirm repair support and its previous state. Retry the update to check again.")

  def _request_worker_inspection(self, parent, node, config, seal):
    """Issue one bounded read to the selected current worker.

    Parameters
    ----------
    parent, config : dict
      Original relink and worker configuration.
    node : str
      Current authorized signer.
    seal : str or None
      Sealed expectation for a running worker, or None to check the local STOP journal.

    Returns
    -------
    dict
      The challenge and expected response scope.

    Examples
    --------
    >>> challenge = plugin._request_worker_inspection(parent, node, config, seal)  # doctest: +SKIP
    """
    meta = dict(action="inspect_worker_v1", attempt="inspect", operation_id=parent["operation_id"],
                coordinator=self.bc.address, node_addr=node, job_id=parent["job_id"], revision=parent["previous_revision"],
                instance_id=worker(config)["INSTANCE_ID"], challenge=uuid.uuid4().hex,
                expires_at=int(self.time()) + 110, peers=[self.bc.address])
    if seal is None:
      meta["confirm_prior_stop"] = True  # Ask the upgraded worker to reconfirm its old receipt without starting it.
    else:
      meta["config_seal"] = seal
    self._send_worker_inspection(parent, config, meta)
    return meta

  def _send_worker_inspection(self, parent, config, meta):
    """Send an existing scoped worker inspection challenge.

    Parameters
    ----------
    parent, config, meta : dict
      Original operation, prior pipeline and immutable challenge envelope.

    Returns
    -------
    None
      Queues the inspection for its named worker.

    Examples
    --------
    >>> plugin._send_worker_inspection(parent, corrected, challenge)  # doctest: +SKIP
    """
    self.cmdapi_start_pipeline(config={"NAME": parent["app_id"], "TYPE": config["TYPE"], "DEEPLOY_OPERATION": meta},
                               node_address=meta["node_addr"])

  def _read_worker_inspection(self, parent, meta, digest):
    """Read and verify one challenge from the local signed-report replica.

    Parameters
    ----------
    parent, meta : dict
      Original operation and exact issued challenge.
    digest : str
      Order-sensitive hash of the approved lists.

    Returns
    -------
    dict or None
      Verified worker response, or None before its arrival.

    Examples
    --------
    >>> result = plugin._read_worker_inspection(parent, challenge, digest)  # doctest: +SKIP
    """
    if self.time() >= meta["expires_at"]:
      return None  # A retry can request a fresh challenge after expiry.
    key = parent["operation_id"] + "|inspect|" + meta["node_addr"]
    result = self.chainstore_hget(NODE_OPERATIONS_HKEY, key)
    if not result or result.get("challenge") != meta["challenge"] or not self._verify_operation_record(result, "node_addr"):
      return None
    items = result.get("instances") or []
    if (any(result.get(key) != meta[key] for key in ("operation_id", "attempt", "coordinator", "node_addr",
                                                      "job_id", "revision", "expires_at"))
        or type(result.get("revision")) is not int or type(result.get("job_id")) is not int
        or self.time() >= meta["expires_at"] or result.get("app_id") != parent["app_id"] or result.get("status") != "observed"
        or len(items) != 1 or not isinstance(items[0], dict)
        or items[0].get("instance_id") != meta["instance_id"] or items[0].get("status") != "observed"
        or items[0].get("signature") != WORKER_APP_RUNNER_SIGNATURE
        or not COMMIT.fullmatch(str(items[0].get("runtime_artifacts", {}).get("git_commit", "")))):
      raise ValueError("The worker could not verify the exact previous configuration and Git commit.")
    if meta.get("confirm_prior_stop"):
      if result.get("confirm_prior_stop") is not True:
        raise ValueError("The paid worker did not confirm its own original retirement.")
    elif (result.get("confirm_prior_stop") or result.get("config_seal_hash") != hashlib.sha256(meta["config_seal"].encode()).hexdigest()
          or result.get("order_digest") != digest):
      raise ValueError("The surviving worker's configuration changed since review.")
    return result

  def _verify_repair_source(self, config, commits):
    """Check the previous Git objects at the runner's configured GitHub repository.

    Parameters
    ----------
    config : dict
      Canonical prior config. No user token is sent.
    commits : iterable
      Exact signed commits required by the restoration plan.

    Returns
    -------
    None
      Raises when the public source cannot be established.

    Examples
    --------
    >>> plugin._verify_repair_source(previous, {commit})  # doctest: +SKIP
    """
    vcs = worker(config).get("VCS_DATA") or {}
    owner, name = vcs.get("REPO_OWNER"), vcs.get("REPO_NAME")
    if not (owner and name):
      url = urlsplit(vcs.get("REPO_URL", ""))
      parts = url.path.strip("/").removesuffix(".git").split("/")
      if url.scheme != "https" or url.hostname != "github.com" or len(parts) != 2:
        raise ValueError("The previous Git repository cannot be verified for restoration.")
      owner, name = parts
    if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}", v) for v in (owner, name)):
      raise ValueError("The previous Git repository cannot be verified for restoration.")
    for commit in set(commits):
      if not COMMIT.fullmatch(commit):
        raise ValueError("The previous Git commit is invalid.")
      # This fixed public host never receives wallet or repository credentials; block redirects and ambient .netrc auth.
      import requests
      with requests.Session() as session:
        session.trust_env = False
        with session.get(f"https://api.github.com/repos/{owner}/{name}/commits/{commit}", stream=True,
                         headers={"Accept": "application/vnd.github.sha"}, timeout=(2, 4), allow_redirects=False) as response:
          # GitHub's SHA representation is 40 ASCII characters; cap reads even if a proxy answers with a diff.
          if response.status_code != 200 or response.raw.read(64, decode_content=True).strip() != commit.encode("ascii"):
            raise ValueError("The Git repository did not confirm the commit needed for restoration.")

  def _prepare_job_repair(self, request, owner):
    """Validate the signed correction and acquire the current workers' evidence.

    Parameters
    ----------
    request : dict
      Verified v3 wallet request for the repair endpoint.
    owner : str
      Verified current job owner.

    Returns
    -------
    dict
      Exact previous and proposed state for reservation and secret preparation.

    Examples
    --------
    >>> recovery = plugin._prepare_job_repair(signed_request, owner)  # doctest: +SKIP
    """
    approval = request.get("repair")
    if (not isinstance(approval, dict) or set(approval) != {"proposal", "same_host", "rotate_main_tunnel"}
        or approval["same_host"] is not True or type(approval["rotate_main_tunnel"]) is not bool):
      raise ValueError("Recovery requires explicit approval of the previous order and the same physical hosts.")
    proposal, corrected, parent, stopped, licenses = self._assess_job_repair(request["job_id"], owner, self.bc.address)
    if (json.dumps(approval["proposal"], sort_keys=True) != json.dumps(proposal, sort_keys=True)
        or request.get("expected_revision") != proposal["expected_revision"] or request.get("app_id") != parent["app_id"]):
      raise DeploymentConflictError("The reviewed job, coordinator or repair proposal has changed.")
    aliases = {row["previous"]: row["current"] for row in proposal["placements"]}
    if request.get("target_nodes") != list(aliases.values()):
      raise ValueError("The update must use exactly the reviewed paid targets in order.")
    from naeural_core.business.deployment_lifecycle import repair_config_fingerprint
    # Only the intended worker can open this full-config comparison, which may depend on protected values.
    fingerprint = repair_config_fingerprint(corrected)
    inspections, seals = self._inspect_repair_workers(parent, corrected, proposal, fingerprint, licenses, stopped)
    commits = [r["instances"][0]["runtime_artifacts"]["git_commit"] for r in (*inspections.values(), *stopped.values())]
    self._verify_repair_source(corrected, commits)
    return dict(proposal=proposal, prior=corrected, stopped=stopped, inspections=inspections, seals=seals, aliases=aliases,
                licenses=licenses,
                rotate_main_tunnel=approval["rotate_main_tunnel"])

  def _hold_repair_parent(self, operation, repair):
    """Reserve the existing operation before a child custody grant or retirement.

    Parameters
    ----------
    operation, repair : dict
      Child snapshot and receiver-computed evidence.

    Returns
    -------
    dict or None
      Existing child for an identical retry, otherwise a newly confirmed hold.

    Examples
    --------
    >>> plugin._hold_repair_parent(child, recovery)  # doctest: +SKIP
    """
    with HANDOFF_LOCK:
      # The worker also holds this lock while checking and advancing a relink it read earlier.
      proposal = repair["proposal"]
      records = self._operation_records()
      parent = records[proposal["parent"]["operation_id"]]
      for existing in records.values():
        if (existing.get("mutation") == MUTATION and existing["coordinator"] == self.bc.address
            and existing["phase"] != "completed" and existing["repair_parent"]["operation_id"] == parent["operation_id"]):
          if existing["request_hash"] == operation["request_hash"] and existing["request_id"] == operation["request_id"]:
            return existing  # A retry can arrive between saving the first child and saving the parent.
          raise DeploymentConflictError("Another approved update has already reserved this retirement.")
      if (parent["sequence"] != proposal["parent"]["sequence"] or parent["phase"] != "retiring_previous"
          or parent.get("plan_cid") != proposal["parent"]["plan_cid"]
          or self._get_pipeline_from_cstore(parent["job_id"]) != proposal["pipeline_cid"]):
        raise DeploymentConflictError("Retirement changed during the review. Refresh recovery.")
      parent["repair_child"] = dict(operation_id=operation["operation_id"], request_hash=operation["request_hash"],
                                    base_sequence=parent["sequence"], node_aliases=list(map(list, repair["aliases"].items())),
                                    licenses=repair["licenses"])
      # Persist the redacted, signed child identity first so a crash can always recover a reservation.
      self._save_operation(operation, message="Preparing signed same-host recovery.")
      self._save_operation(parent, "holding_for_repair", "Retirement held for the CSP-approved update.")

  def _reconcile_repair_parent(self, parent):
    """Reconstruct a reservation interrupted between the child and parent writes.

    Parameters
    ----------
    parent : dict
      Latest verified relink owned by this coordinator.

    Returns
    -------
    bool
      Whether a linked child owns retirement and the original operation must wait.

    Examples
    --------
    >>> held = plugin._reconcile_repair_parent(parent)  # doctest: +SKIP
    """
    if parent["phase"] != "holding_for_repair" and (parent["phase"] != "retiring_previous"
        or (parent.get("error") or {}).get("code") != "PREVIOUS_STOP_UNCONFIRMED"):
      return False  # Only the blocked relink can acquire a repair child.
    children = [op for op in self._operation_records().values() if op.get("mutation") == MUTATION
                and op["coordinator"] == self.bc.address and op["job_id"] == parent["job_id"]
                and op.get("repair_parent", {}).get("operation_id") == parent["operation_id"]]
    for child in children:
      link = child["repair_parent"]
      held = parent.get("repair_child") or {}
      if parent["phase"] == "holding_for_repair" and held.get("operation_id") == child["operation_id"]:
        if child["phase"] == "completed":
          if (child.get("error") or {}).get("code") == "ADMISSION_PREPARATION_FAILED":
            parent.pop("repair_child", None)  # No retirement was authorized by the failed preparation.
            self._save_operation(parent, "retiring_previous", "Recovery preparation ended before retirement.")
          else:
            parent.update(outcome="superseded", recovery="completed")
            self._save_operation(parent, "completed", "The linked recovery completed on the current workers.")
        return True
      if (parent["phase"] == "retiring_previous" and child["phase"] != "completed"
          and parent["sequence"] == link["sequence"] and parent["plan_cid"] == link["plan_cid"]):
        parent["repair_child"] = dict(operation_id=child["operation_id"], request_hash=child["request_hash"],
                                      base_sequence=link["sequence"], node_aliases=child["repair_aliases"],
                                      licenses=child["repair_licenses"])
        self._save_operation(parent, "holding_for_repair", "Recovered the reservation for the CSP-approved update.")
        return True
    return parent["phase"] == "holding_for_repair"

  def _repair_parent_is_held(self, child):
    """Check the original coordinator's signed reservation on restart.

    Parameters
    ----------
    child : dict
      CSP-approved operation.

    Returns
    -------
    bool
      Whether this exact operation owns the parent hold.

    Examples
    --------
    >>> held = plugin._repair_parent_is_held(child)  # doctest: +SKIP
    """
    parent = self._operation_records().get(child["repair_parent"]["operation_id"]) or {}
    reservation = parent.get("repair_child") or {}
    return (parent.get("phase") == "holding_for_repair" and parent.get("coordinator") == self.bc.address
            and parent.get("job_id") == child["job_id"] and parent.get("plan_cid") == child["repair_parent"]["plan_cid"]
            and reservation.get("base_sequence") == child["repair_parent"]["sequence"]
            and reservation.get("licenses") == child["repair_licenses"]
            and reservation.get("operation_id") == child["operation_id"] and reservation.get("request_hash") == child["request_hash"])

  def _retire_repair_workers(self, child, plan):
    """Retire only surviving instances, using the exact signed pre-stop evidence.

    Parameters
    ----------
    child, plan : dict
      Signed recovery and immutable redacted deployment plan.

    Returns
    -------
    None
      Advances only after exact STOP and Git evidence for each paid target.

    Examples
    --------
    >>> plugin._retire_repair_workers(child, plan)  # doctest: +SKIP
    """
    parent = self._operation_records()[child["repair_parent"]["operation_id"]]
    evidence = plan["repair_evidence"]
    reports = self._node_operation_reports(child, "retire")
    runtime = {}
    if self._get_pipeline_from_cstore(child["job_id"]) != child["previous_pipeline_cid"]:
      self._record_repair_block(child, "REPAIR_PLACEMENT_UNCONFIRMED", "The published job changed during repair.")
      raise DeploymentConflictError("The published job changed before recovery retirement.")
    for node, config in plan["previous_configs"].items():
      # Preserve and re-verify the original signer rather than moving a STOP to a different address or operation ID.
      historical = evidence["stopped"].get(node)
      original = historical or evidence["inspections"][node]
      if original.get("node_addr") != node or not self._verify_operation_record(original, "node_addr"):
        raise ValueError("The previous worker evidence is invalid.")
      source = original["instances"][0]
      identity = source["signature"] + "|" + source["instance_id"]
      if historical:
        runtime[node] = {identity: source["runtime_artifacts"]}
        continue
      # After a slow preparation or coordinator restart, the same worker can renew its observation.
      seal = evidence["seals"][node]
      observation = child.get("repair_observations", {}).get(node, original)
      report = reports.get(node) or {}
      pin = source["runtime_artifacts"]["git_commit"]
      if (report.get("status") == "stopped" and report.get("parent_operation_id") == parent["operation_id"]
          and report.get("challenge") in child.get("retire_challenges", {}).get(node, [])
          and report.get("order_digest") == original["order_digest"]
          and report.get("config_seal_hash") == original["config_seal_hash"]
          and report["instances"][0].get("runtime_artifacts", {}).get("git_commit") == pin):
        runtime[node] = {identity: report["instances"][0]["runtime_artifacts"]}
        continue
      if report.get("status") in ("failed", "stopped") or self.time() >= child["deadline"]:
        child["recovery"] = "blocked"
        child["error"] = dict(code="PREVIOUS_STOP_UNCONFIRMED", message="Exact worker retirement has not been confirmed.", retryable=True)
        self._save_operation(child)
        # Never convert a contradictory durable receipt into permission for another stop.
        if report.get("status") in ("failed", "stopped"):
          continue
      key = child["operation_id"] + "|retire|" + node
      if 0 <= self.time() - self._operations_sent_at.get(key, 0) < 10:
        continue
      self._operations_sent_at[key] = self.time()
      if observation["expires_at"] <= self.time() + 3:
        renewal = child.get("pending_inspections", {}).get(node)
        if not renewal or renewal["expires_at"] <= self.time() + 3:
          renewal = self._request_worker_inspection(parent, node, config, seal)
          child.setdefault("pending_inspections", {})[node] = renewal
          self._save_operation(child)  # Lost probes are harmless; after expiry the worker receives a new challenge.
          continue
        observation = self._read_worker_inspection(parent, renewal, original["order_digest"])
        if not observation:
          continue  # No synchronous wait on the shared deployment worker.
        if observation["instances"][0]["runtime_artifacts"]["git_commit"] != pin:
          self._record_repair_block(child, "REPAIR_SOURCE_CHANGED", "A worker's Git commit changed. Review its retirement before proceeding.")
          raise DeploymentConflictError("The worker changed since the CSP approved recovery.")
        child.setdefault("repair_observations", {})[node] = observation
        del child["pending_inspections"][node]
      meta = self._operation_metadata(child, "retire", "retire_worker_v1")
      meta.update(parent_operation_id=parent["operation_id"], node_addr=node, instance_id=source["instance_id"],
                  challenge=observation["challenge"], expires_at=observation["expires_at"],
                  order_digest=original["order_digest"], git_commit=pin, config_seal=seal)
      # A failed placement check saves its reason and must not imply that a STOP was attempted.
      self._recheck_repair_placement(child)
      sent = child.setdefault("retire_challenges", {}).setdefault(node, [])
      if observation["challenge"] not in sent:
        if len(sent) >= 64:
          raise ValueError("The worker has exhausted its retirement challenges. Review its outstanding commands.")
        sent.append(observation["challenge"])  # A delayed genuine STOP remains valid after challenge renewal.
      self._save_operation(child)  # Crash recovery must recognize the challenge before the stop leaves the coordinator.
      self.cmdapi_start_pipeline(config={"NAME": child["app_id"], "TYPE": config["TYPE"], "DEEPLOY_OPERATION": meta},
                                 node_address=node)
    if set(runtime) == set(plan["previous_configs"]):
      self._recheck_repair_placement(child)
      child["retired_runtime"] = runtime
      child.update(error=None, recovery=None, deadline=self.time() + self.cfg_deployment_readiness_timeout)
      self._save_operation(child, "waiting_for_readiness", "All previous workers accounted for on the approved hosts.")

  def _record_repair_block(self, child, code, message):
    """Publish a stable reason for a repair that must wait for evidence.

    Parameters
    ----------
    child : dict
      Coordinator-owned repair operation.
    code, message : str
      Static public reason without request or credential data.

    Returns
    -------
    None
      Saves one snapshot when the reason changes.

    Examples
    --------
    >>> plugin._record_repair_block(child, "REPAIR_PLACEMENT_UNCONFIRMED", "Placement changed.")  # doctest: +SKIP
    """
    block = dict(code=code, message=message, retryable=True)
    if child.get("repair_block") != block:
      child["repair_block"] = block
      self._save_operation(child)

  def _recheck_repair_placement(self, child, finalizing=False):
    """Verify chain authority immediately before sending a repair command.

    Parameters
    ----------
    child : dict
      Coordinator-signed saved recovery.
    finalizing : bool, optional
      Permit retry of this child's already published, signed plan pointer.

    Returns
    -------
    None
      Raises on a new owner, underpaid job, changed link or changed active pointer.

    Examples
    --------
    >>> plugin._recheck_repair_placement(child)  # doctest: +SKIP
    """
    aliases = dict(child["repair_aliases"])
    if self._get_pipeline_from_cstore(child["job_id"]) != child["previous_pipeline_cid"]:
      pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(child["job_id"])) if finalizing else None
      if (not isinstance(pointer, dict) or pointer.get("operation_id") != child["operation_id"]
          or pointer.get("coordinator") != self.bc.address or pointer.get("plan_cid") != child["plan_cid"]
          or pointer.get("revision") != child["target_revision"] or pointer.get("deleted") is not False
          or not self._verify_operation_record(pointer, "coordinator")):
        self._record_repair_block(child, "REPAIR_PLACEMENT_UNCONFIRMED", "The published job changed during repair.")
        raise DeploymentConflictError("The published job changed during recovery.")
    try:
      job = self.bc.get_job_details(job_id=child["job_id"])
      valid = (job and str(job.get("escrowOwner", "")).lower() == child["owner"].lower()
               and self._repair_aliases(list(aliases), job) == (aliases, child["repair_licenses"]))
    except Exception as exc:
      # A failed registry read must also hold dispatch and back off the shared reconciler.
      self._record_repair_block(child, "REPAIR_PLACEMENT_UNCONFIRMED", "The current licensed placement could not be verified.")
      raise DeploymentConflictError("The current licensed placement could not be verified.") from exc
    if not valid:
      self._record_repair_block(child, "REPAIR_PLACEMENT_UNCONFIRMED", "The job owner or licensed placement changed during repair.")
      raise DeploymentConflictError("The job, its owner or its licensed placement changed during recovery.")
    if child.pop("repair_block", None):
      self._save_operation(child)  # Dispatch only after fresh placement and worker evidence let recovery proceed.
