"""Durable Deeploy operations coordinated by their receiving oracle.

Operation snapshots and node reports are signed, sequence-ordered CStore records.
There is deliberately no distributed lock, election, or automatic takeover.
The receiving oracle resumes its own unfinished operations after restart;
other oracles only aggregate replicated observations for polling.
"""
# The repair schedule of a completed operation is looked up by age in a sorted tuple.
import bisect
# A size refusal stays the error admission raises when the save that ends its operation is not confirmed.
import contextlib
import copy
import hashlib
import json
import os
import re
import threading
# The call path of an error that stops an operation is logged (function names only).
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo
# The verified-fingerprint cache keeps insertion order, so its oldest entry can be dropped first.
from collections import OrderedDict

from naeural_core import constants as ct
from .container_allocations import redistribution_requirements
from naeural_core.business.deployment_lifecycle import SOURCE_FAILURES, deployment_source_mode
from ratio1.const.base import BCct, dAuth
# The SDK client's error for a secret record a dAuth server refused for its size: it ends a preparation at once.
from ratio1.bc.base import DauthSecretRecordTooLarge
from extensions.business.container_apps.container_utils import configured_image_ref, image_repository
from extensions.utils.per_node_config import iter_overlays, normalize_config, PER_NODE_CONFIG_KEYS
from .selected_secrets import inherit_selections
from .relink_placement import relink_configs, relink_pipeline
# Share the writer activation and local compatibility reader across Oracle API paths.
from . import r1fs_documents

from extensions.business.dauth.dauth_registry import get_dauth_registry_internal_peers
# The worker signature tells the restoration gate which runtime binding an instance needs.
from .deeploy_const import DEEPLOY_KEYS, CONTAINERIZED_APPS_SIGNATURES, WORKER_APP_RUNNER_SIGNATURE


OPERATIONS_HKEY = "DEEPLOY_OPERATIONS"
REPLACEMENT_REFUSALS_HKEY = "DEEPLOY_REPLACEMENT_REFUSALS"
NODE_OPERATIONS_HKEY = "DEEPLOY_NODE_OPERATIONS"
SECRET_REVISIONS_HKEY = "DAUTH_JOB_SECRET_REVISIONS"
# The ages after completion, in seconds, at which the coordinator sends the final snapshot of a completed operation
# again as peer repair once its first 600 s (re-sent every 30 s, as before) are over: ages that double from 600 s and
# are at most 1 h apart (600, 1,200, 2,400 and 4,800 s, then every 3,600 s), the last at 84,000 s. Fixed ages after
# each operation's own completion: the sends of operations stay spread as their completion times are, before and
# after a restart.
REPAIR_AGES = (600, 1200, 2400) + tuple(range(4800, 86400, 3600))
# An operation that is not completed and whose snapshot has not changed for this many seconds is re-sent to the peers
# as repair once per this many seconds, no longer every 30 s. An operation that waits for something that never comes
# (a blocked one) keeps the same snapshot for as long as it waits, and every oracle received and answered that
# snapshot about 115 times an hour.
OPEN_REPAIR_SECONDS = 600
# Extra phase deadlines an ordinary blocked operation may spend waiting for signed evidence.
BLOCKED_RECOVERY_GRACE_PERIODS = 24
BLOCKED_OPERATION_ENDED = "BLOCKED_OPERATION_ENDED"
# Check for worker receipts that reach an ended paid create after its terminal failure.
ENDED_CREATE_CLEANUP_CHECK_SECONDS = 60
class DeploymentAuthenticationError(ValueError):
  """The reusable read authorization is invalid or expired."""


STATELESS_REPLACEMENT = "stateless_replacement_v1"
RESOURCE_REDISTRIBUTION = "resource_redistribution_v1"


_OPERATION_PHASE_PREFIXES = {
  "same_host_repair_v1": "repair_v1_",
  STATELESS_REPLACEMENT: "stateless_v1_",
  RESOURCE_REDISTRIBUTION: "resources_v1_",
}


def deployment_operation_phase(operation):
  """Read the logical phase of a lifecycle operation.

  Parameters
  ----------
  operation : dict
    Signed deployment snapshot as stored by the coordinator.

  Returns
  -------
  str
    Logical phase used by current code and public progress.

  Examples
  --------
  >>> deployment_operation_phase({"mutation": STATELESS_REPLACEMENT, "phase": "stateless_v1_accepted"})
  'accepted'
  """
  phase = operation["phase"]
  return phase.removeprefix(_OPERATION_PHASE_PREFIXES.get(operation.get("mutation"), ""))


class DeploymentConflictError(ValueError):
  """A request conflicts with observed operation identity or revision."""


class StaleReplacementReviewError(DeploymentConflictError):
  """The coordinator refused a replacement whose signed proposal has changed."""


class ReplacementPlacementError(ValueError):
  """The replacement's paid job or license binding is no longer valid."""


class ReplacementPlacementMismatch(ReplacementPlacementError):
  """A successful chain read showed that the reviewed placement cannot proceed."""


class ReplacementPublicationRefused(ValueError):
  """dAuth definitively refused the coordinator's first publication before any write."""


def replacement_paid_slots(plugin, job_id, owner):
  """Read the paid capacity of a currently funded replacement job.

  Parameters
  ----------
  plugin : object
    Coordinator or custodian with chain and epoch access.
  job_id : int or str
    Paid job identifier.
  owner : str
    Expected escrow owner.

  Returns
  -------
  int
    Active paid slot count.

  Examples
  --------
  >>> replacement_paid_slots(plugin, 31, owner)  # doctest: +SKIP
  2
  """
  job = plugin.bc.get_job_details(job_id=int(job_id))
  slots = job.get("numberOfNodesRequested") if isinstance(job, dict) else None
  if type(slots) is not int or slots < 1 or str(job.get("escrowOwner", "")).lower() != owner.lower():
    raise ReplacementPlacementError("The published job does not have an active paid placement under this CSP.")
  # The last execution epoch is the first epoch outside the paid interval.
  expires = job.get("lastExecutionEpoch")
  if type(expires) is not int:
    raise ReplacementPlacementError("The job's paid execution term could not be verified.")
  if expires <= plugin.netmon.epoch_manager.get_current_epoch():
    raise ReplacementPlacementMismatch("The job has no paid execution epochs remaining.")
  return slots


def replacement_license_binding(bc, node):
  """Read the active registration for one replacement target.

  Parameters
  ----------
  bc : object
    Blockchain wrapper.
  node : str
    Exact internal worker address.

  Returns
  -------
  list
    License ID and normalized license owner.

  Examples
  --------
  >>> replacement_license_binding(bc, worker)  # doctest: +SKIP
  [42, '0xowner']
  """
  eth = bc.node_address_to_eth_address(node)
  # Read invalid registrations as data. A transport failure remains retryable.
  info = bc.get_node_license_info(node_address_eth=eth, raise_if_error=False)
  if (not isinstance(info, dict) or info.get("isValid") is not True or type(info.get("licenseId")) is not int
      or str(info.get("nodeAddress", "")).lower() != eth.lower()
      or not isinstance(info.get("owner"), str) or not info["owner"]):
    raise ReplacementPlacementError("Each replacement target needs an active node license.")
  return [info["licenseId"], info["owner"].lower()]


def check_replacement_placement(plugin, operation):
  """Revalidate the paid job and exact licensed targets before an external effect.

  Parameters
  ----------
  plugin : object
    Coordinator or custodian with chain and epoch access.
  operation : dict
    Signed replacement snapshot.

  Returns
  -------
  None
    Raises if the placement is unavailable or no longer authorized.

  Examples
  --------
  >>> check_replacement_placement(plugin, operation)  # doctest: +SKIP
  """
  bindings = operation.get("replacement_licenses", {})
  if set(bindings) != set(operation["nodes"]):
    raise ReplacementPlacementError("The replacement placement could not be verified.")
  if replacement_paid_slots(plugin, operation["job_id"], operation["owner"]) != len(bindings):
    raise ReplacementPlacementMismatch("The replacement's paid worker count changed. Review the job again.")
  if any(replacement_license_binding(plugin.bc, node) != binding for node, binding in bindings.items()):
    raise ReplacementPlacementMismatch("A replacement worker's license changed. Review the job again.")


class DeploymentCustodyError(RuntimeError):
  """dAuth could not do a custody call now; past preparation the operations worker waits before it tries again.

  Raised by `_deployment_secret_request` in place of the RuntimeError of the SDK call (request not signed, a
  call that failed or timed out, an HTTP error, a refusal, or a preparation not finished yet). It stays a
  RuntimeError, so the admission endpoints still answer 503 for it, as before.
  """


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


def report_confirms_retirement(report, expected):
  """Check the worker's stop evidence against the planned instance identities.

  A worker can acknowledge an absent pipeline with an empty aggregate report.
  A relink needs evidence for each previously deployed instance.

  Parameters
  ----------
  report : dict
    Authenticated node report for the retirement attempt.
  expected : list
    Signature and instance ID pairs from the coordinator's signed operation.

  Returns
  -------
  bool
    True when the complete set of expected instances individually stopped.

  Examples
  --------
  >>> report_confirms_retirement({"status": "stopped", "instances": []}, [("APP", "one")])
  False
  """
  items = report.get("instances")
  if report.get("status") != "stopped" or not expected or not isinstance(items, list) or len(items) != len(expected):
    return False  # An empty or partial report cannot account for the prior placement.
  identities = set()
  for item in items:
    if not isinstance(item, dict) or item.get("status") != "stopped":
      return False  # The aggregate cannot override an individual instance.
    if not isinstance(item.get("signature"), str) or not isinstance(item.get("instance_id"), str):
      return False  # Reject malformed signed observations before accessing their identity.
    identities.add((item["signature"], item["instance_id"]))
  return len(identities) == len(items) and identities == {tuple(pair) for pair in expected}


def report_is_ready(report, config, pins=None, restore_bindings=None):
  """Require an explicit ready report for every planned plugin instance.

  Nodes publish on changes in status or version. Callers pair the latest
  report with NetMon liveness because a healthy workload can stay unchanged.
  """
  return node_rollout_state(config, report, online=True, deadline=False, pins=pins,
                            restore_bindings=restore_bindings) == "ready"


def pinned_sources(config):
  """Project required content identities for local readiness checks.

  Parameters
  ----------
  config : dict
    The coordinator's stored pipeline for one node.

  Returns
  -------
  dict
    SHA-256 of the required commit or repository@digest for each pinned instance. Hashing
    keeps source names out of the signed public operation. Invalid legacy values never match.

  Examples
  --------
  >>> pinned_sources({"PLUGINS": []})
  {}
  """
  pins = {}
  for group in config.get("PLUGINS", []):
    signature = group["SIGNATURE"]
    for instance in group.get("INSTANCES", []):
      if deployment_source_mode(signature, config, instance) != "pinned":
        continue
      expected = None
      if signature.upper() == WORKER_APP_RUNNER_SIGNATURE:
        commit = (instance.get("VCS_DATA") or {}).get("COMMIT")
        if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit):
          expected = commit
      else:
        image, digest = instance.get("IMAGE"), instance.get("IMAGE_DIGEST")
        if isinstance(image, str) and image and isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
          server = (instance.get("CR_DATA") or {}).get("SERVER")
          expected = image_repository(configured_image_ref(image, server)) + "@" + digest
      pins[signature + "|" + instance["INSTANCE_ID"]] = hashlib.sha256(expected.encode()).hexdigest() if expected else ""
  return pins


def validate_saved_overlays(config):
  """Recheck stored per-node overlays before dispatching to a mixed-version placement.

  Parameters
  ----------
  config : dict
    Pipeline from a previously admitted revision or a resumed operation.

  Returns
  -------
  None
    Raises ValueError if a stored override would replace a system-managed field.

  Examples
  --------
  >>> validate_saved_overlays({"PLUGINS": []})
  """
  for plugin in config.get("PLUGINS", []):
    for instance in plugin.get("INSTANCES", []):
      for key in PER_NODE_CONFIG_KEYS:
        if key in instance:
          normalize_config(instance[key])  # Check all selectors, including ones for another node.


def validate_source_pins(configs):
  """Validate source pins before staging the revision.

  Parameters
  ----------
  configs : dict
    Final per-node pipelines, including their runtime overlays.

  Returns
  -------
  None
    Raises ValueError for conflicting, misplaced or malformed pins.

  Examples
  --------
  >>> validate_source_pins({})
  """
  pins = {}
  for config in configs.values():
    for plugin in config.get("PLUGINS", []):
      signature = plugin["SIGNATURE"].upper()
      for instance in plugin.get("INSTANCES", []):
        mode = deployment_source_mode(signature, config, instance)
        if mode is None and (config.get("DEEPLOY_SPECS") or {}).get("job_app_type") != "service":
          continue  # Other plugins own their own configuration schema.
        vcs = instance.get("VCS_DATA") or {}
        has_commit = isinstance(vcs, dict) and "COMMIT" in vcs
        pinned = instance.get("PINNED_VERSION", False)
        has_digest = "IMAGE_DIGEST" in instance
        for key in PER_NODE_CONFIG_KEYS:
          for overlay in iter_overlays(instance.get(key)):
            overlay_vcs = overlay.get("VCS_DATA", {})
            if ("PINNED_VERSION" in overlay or "IMAGE_DIGEST" in overlay
                or (isinstance(overlay_vcs, dict) and "COMMIT" in overlay_vcs)
                or (has_commit and not isinstance(overlay_vcs, dict))):
              raise ValueError("A per-node override cannot change a source pin.")
        if mode in (None, "service") and ("PINNED_VERSION" in instance or has_digest or has_commit):
          raise ValueError("Catalogue services do not accept source pins.")
        if type(pinned) is not bool:
          raise ValueError("PINNED_VERSION must be a boolean.")
        worker = signature == WORKER_APP_RUNNER_SIGNATURE
        if has_commit != (pinned and worker) or has_digest != (pinned and not worker):
          raise ValueError("A source pin requires exactly the hash for its runner.")
        version = vcs["COMMIT"] if has_commit else instance.get("IMAGE_DIGEST")
        if pinned and (not isinstance(version, str) or not re.fullmatch(
            r"[0-9a-f]{40}" if worker else r"sha256:[0-9a-f]{64}", version)):
          raise ValueError("Invalid pinned Git commit or registry digest.")
        identity = (signature, instance["INSTANCE_ID"])
        if pins.setdefault(identity, (mode, version)) != (mode, version):
          raise ValueError("A plugin instance must use the same source pin on every node.")


def node_rollout_state(config, report, online, deadline, pins=None, allow_waiting_for_source=True, restore_bindings=None):
  """Decide whether one node permits a revision to take effect.

  Each planned instance needs its own evidence. A lifecycle error always wins
  over a source failure in another instance on the same node.

  Parameters
  ----------
  config, report : dict
    Stored pipeline and its latest authenticated attempt report.
  online, deadline : bool
    Current node liveness and whether the readiness deadline has passed.
  pins : dict, optional
    Signed projection of the plan when status polling has only the planned instance identities.
  allow_waiting_for_source : bool, optional
    Whether a source-following deployment can take effect before it becomes ready.
  restore_bindings : dict or None, optional
    The exact signed stop artifacts for this worker during a repair restore.

  Returns
  -------
  str
    ready, kept, pending, failed, legacy_failed or legacy_timeout.

  Examples
  --------
  >>> node_rollout_state({}, {}, False, True)
  'pending'
  """
  if not report:
    return "pending"
  if report.get("error"):
    return "failed"  # Pipeline-level errors (such as rejected config) cannot be kept.
  planned = {(p["SIGNATURE"], i["INSTANCE_ID"]): i
             for p in config.get("PLUGINS", []) for i in p.get("INSTANCES", [])}
  if pins is None:
    pins = pinned_sources(config)  # Execution always takes its requirements directly from the durable plan.
  seen = set()
  kept = False
  pending = False
  kept_failure = False
  old_node = False
  instances = report.get("instances", [])
  if not isinstance(instances, list):
    return "failed"  # A malformed signed report cannot establish readiness.
  for item in instances:
    if not isinstance(item, dict):
      return "failed"
    identity = (item.get("signature"), item.get("instance_id"))
    instance = planned.get(identity)
    mode = deployment_source_mode(identity[0], config, instance) if instance is not None else None
    pin_key = "|".join(identity) if instance is not None else None
    if pin_key in pins:
      mode = "pinned"  # The local-only polling projection is signed by the coordinator.
    reported_mode = item.get("source_mode")
    following = allow_waiting_for_source and mode == reported_mode == "following"
    status = item.get("status")
    legacy = mode in ("following", "pinned") and reported_mode is None
    if restore_bindings is not None and instance is not None and status == "ready":
      # A repair restore binds each worker to its own stop, even if the configured branch is shared.
      commit = (restore_bindings.get(pin_key) or {}).get("git_commit")
      artifacts = item.get("runtime_artifacts")
      if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
          or not isinstance(artifacts, dict) or artifacts.get("git_commit") != commit):
        return "failed"
    if mode == "pinned" and status == "ready":
      if legacy:
        return "legacy_failed"  # Older nodes bind their first start, which may differ from the request.
      artifacts = item.get("runtime_artifacts")
      field = "git_commit" if identity[0].upper() == WORKER_APP_RUNNER_SIGNATURE else "image_ref"
      version = artifacts.get(field) if isinstance(artifacts, dict) else None
      if (reported_mode != "pinned" or not isinstance(version, str)
          or hashlib.sha256(version.encode()).hexdigest() != pins.get(pin_key)):
        return "failed"  # A signed ready state alone cannot establish the requested revision.
    if status == "failed":
      error = item.get("error")
      if not following or not isinstance(error, dict) or error.get("code") not in SOURCE_FAILURES:
        return "legacy_failed" if legacy else "failed"
      kept_failure = True
      # A previously reported source failure cannot stand in for an offline node.
      kept |= online
      pending |= not online
    elif identity in planned and (status != "ready" or not online):
      if following and online and deadline:
        kept = True
      else:
        pending = True
        old_node |= legacy
    seen.add(identity)
  if report.get("status") == "failed" and not kept_failure:
    return "failed"  # No instance evidence explains the pipeline failure.
  if deadline and old_node:
    return "legacy_timeout"
  if pending or not planned or not planned.keys() <= seen:
    return "pending"
  if kept:
    return "kept"
  return "ready" if report.get("status") == "ready" and online else "pending"


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


def with_observed_legacy_metadata_order(pipeline, observed):
  """Match permutations of known unordered Deeploy metadata in a comparison copy.

  Parameters
  ----------
  pipeline, observed : dict
    Stored pipeline (or its independently corrected copy) and the worker's report.

  Returns
  -------
  dict
    Pipeline with equivalent metadata aligned to the observed order. The inputs remain intact.

  Examples
  --------
  >>> cfg = {"DEEPLOY_SPECS": {"spare_nodes": ["a", "b"]}}
  >>> report = {"DEEPLOY_SPECS": {"spare_nodes": ["b", "a"]}}
  >>> with_observed_legacy_metadata_order(cfg, report) == report
  True
  """
  stored_specs, live_specs = pipeline.get("DEEPLOY_SPECS"), observed.get("DEEPLOY_SPECS")
  if not isinstance(stored_specs, dict) or not isinstance(live_specs, dict):
    return pipeline  # An incomplete report cannot establish an equivalent order.

  def align(stored, running):
    if (isinstance(stored, list) and isinstance(running, list)
        and all(isinstance(value, str) and value for value in stored + running)
        and sorted(stored) == sorted(running)):
      return list(running)  # Match membership and multiplicity before taking the order.
    return stored

  specs = dict(stored_specs)
  if "spare_nodes" in specs:
    specs["spare_nodes"] = align(specs["spare_nodes"], live_specs.get("spare_nodes"))
  stored_keys, live_keys = specs.get("chainstore_response_keys"), live_specs.get("chainstore_response_keys")
  if isinstance(stored_keys, dict) and isinstance(live_keys, dict):
    # Responses are keyed by ID. Each key must stay with its original node.
    specs["chainstore_response_keys"] = {node: align(keys, live_keys.get(node))
                                         for node, keys in stored_keys.items()}
  return dict(pipeline, DEEPLOY_SPECS=specs)


class _DeploymentOperationsMixin:
  """Persist and reconcile asynchronous deployment operations.

  The hosting plugin runs a coordinator worker and serves owner-scoped status
  from verified snapshots.

  Parameters
  ----------
  None

  Returns
  -------
  _DeploymentOperationsMixin
    Operation helpers for the hosting plugin.

  Notes
  -----
  The worker's in-memory cleanup clock permits an immediate receipt check
  after startup, then paces checks for ended paid creates every 60 seconds.
  The signed operation, rather than the clock, preserves the outcome.

  Examples
  --------
  >>> plugin._reconcile_coordinator_operations()  # doctest: +SKIP
  """

  # The worker owns the cadence. Restarting permits one immediate read of the local receipts.
  _last_ended_create_cleanup_check = None

  def _init_deployment_operations(self):
    """Start the independent execution worker and initialize bounded caches.

    Creates every field the operation mixin needs before the worker thread
    starts: the admission handoff markers, the bounded plan cache (at most 32
    plans) with its lock, the wake-up and stop events, and three in-process
    bookkeeping maps. `_operations_sent_at` holds the command resend times
    that used to be written into the signed operation snapshot, so a command
    retry no longer produces a new CStore write; `_operations_confirmed`
    holds the last confirmed send of each snapshot, so an unchanged snapshot
    is no longer re-sent on every 2 s pass; `_operations_repaired` holds, per
    completed operation, how many ages of its repair schedule (`REPAIR_AGES`)
    were already served. `_verified_operation_records`, a FIFO cache,
    holds the fingerprints of the records whose signature was already checked
    and found valid (see `_verify_operation_record`); its lock and
    `_verified_operation_records_dropped`, the count of fingerprints dropped
    from it since the start, sit next to it. `_custody_retry` holds,
    per operation out of the "preparing" phase with a failed dAuth custody
    call since its last pass without an error, how long the worker waits
    before calling dAuth again (see `_reconcile_coordinator_operations`).
    They are created here, next to
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
    and joins the thread. The three bookkeeping maps live only in process
    memory and are not pruned: they hold one small entry per operation and
    per command target. After a restart they start empty, so the current
    snapshot of each own operation that is unfinished or completed less than
    600 s ago is sent once more and pending commands are sent again; nodes
    de-duplicate commands by operation id and attempt. An operation completed
    600 s to 24 h ago is not sent at once: the first pass marks the current
    age of its repair schedule as served, and its next send falls on the next
    age of that schedule (see `_reconcile_coordinator_operations`).
    `_custody_retry` is pruned on every worker pass and also starts empty, so
    after a restart each waiting operation calls dAuth on the first pass.

    Examples
    --------
    >>> plugin._init_deployment_operations()
    >>> plugin._deployment_operations_thread.name
    'deeploy-operations'
    >>> plugin._operations_confirmed, plugin._operations_sent_at, plugin._custody_retry, plugin._operations_repaired
    ({}, {}, {}, {})
    """
    self._deployment_preparations = {}
    # Last confirmed send per operation id, as (sequence, signature, time): it lets _replicate_operation
    # skip an unchanged snapshot for 30 s instead of re-sending it to every oracle on each 2 s pass.
    self._operations_confirmed = {}
    # Per completed operation id, how many ages of REPAIR_AGES were served: 0 from a pass in its first 600 s, then the
    # ages sent or passed, the current one marked by the first pass that sees it later (as after a restart). From 600 s
    # on, _reconcile_coordinator_operations re-sends the final snapshot when its age reaches the next one.
    self._operations_repaired = {}
    # Last command time per "operation id|attempt|action|node": the 10 s resend throttle lives in process
    # memory, so a command retry no longer writes a new signed snapshot that every oracle re-stores.
    self._operations_sent_at = {}
    # Keep the last 10,000 verified fingerprints in insertion order; hits do not refresh their position.
    self._verified_operation_records = OrderedDict()
    # The worker thread and the plugin thread both look up and insert: one lock for the cache.
    self._verified_operation_records_lock = threading.Lock()
    # Fingerprints dropped from the full cache since the start, changed under the lock above: every 10,000th drop
    # makes one red line, the only sign that more valid records are alive than the cache holds.
    self._verified_operation_records_dropped = 0
    # Operation id -> (failures in a row, time of the last one, seconds to wait) after a failed dAuth custody
    # call: the worker waits that long before it calls the same dAuth server again, instead of every 2 s.
    self._custody_retry = {}
    self._repair_inspections = {}  # Short-lived admission challenges keyed by the original operation.
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
    Accept only signed records whose claimed writer matches their signer, remembering the valid ones.

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
    The cache lives in process memory, so after a restart every record is checked once more.
    It holds at most 10,000 fingerprints. Inserting a new one at capacity evicts only the oldest
    insertion; hits do not refresh that order. Evicted records are checked again when next read.
    Sequential scans of more than 10,000 distinct valid records can still miss on every lookup.
    A lock protects lookups and insertion/eviction shared by the worker and plugin threads.
    Signature verification runs outside the lock, so concurrent misses can check the same record
    more than once; membership is checked again before insertion to avoid unnecessary eviction.
    Evictions are counted under the same lock; every 10,000th eviction since the start makes one
    red line, logged after the lock is released, so 10,000 evictions lie between two lines. If the
    line repeats on every pass, more than 10,000 valid records are alive and every record is checked
    again on every pass.

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
      # Look the fingerprint up under the cache lock; the signature check below runs outside it.
      with self._verified_operation_records_lock:
        if fingerprint in self._verified_operation_records:
          # These exact bytes were checked before and were valid: no second signature check.
          return True
      verification = self.bc.verify(record, return_full_info=True)
      # The full check, as before: a valid signature made by the address the record names as its writer.
      valid = bool(verification.valid and record.get("EE_SENDER") == record[signer_key])
      if valid:
        # Set under the lock below when this insertion makes the 10,000th drop since the last red line.
        log_replaced = False
        # Insert under the cache lock, so the size check, the drop and the insert are one step.
        with self._verified_operation_records_lock:
          # Another thread may have verified and inserted this fingerprint while the lock was released.
          if fingerprint not in self._verified_operation_records:
            if len(self._verified_operation_records) >= 10000:
              # At capacity drop only the oldest insertion, so the other cached checks are kept.
              self._verified_operation_records.popitem(last=False)
              # Count the drop with the cache, under its lock, so two threads never lose one.
              self._verified_operation_records_dropped += 1
              # One line per 10,000 drops: often enough to see a cache that is too small, never once per drop.
              log_replaced = self._verified_operation_records_dropped % 10000 == 0
            # Remember only records that passed; retain the other cached verifications at capacity.
            self._verified_operation_records[fingerprint] = True
        if log_replaced:
          self.P("Replaced 10,000 remembered Deeploy record fingerprints. If this line repeats on every pass, more "
                 "than 10,000 valid records are alive and every record is checked again.", color='r')
      # The outcome of the full check; a record that failed it was not remembered above.
      return valid
    except Exception:
      return False

  def _operation_records(self, *, job_id=None, operation_id=None, own_only=False):
    """Select the newest verified snapshots matching the local read scope.

    Parameters
    ----------
    job_id, operation_id : int or str, optional
      Limit registry dependencies to the requested job or operation.
    own_only : bool, optional
      Reconcile only operations signed by this coordinator.

    Returns
    -------
    dict
      Operation ID to verified snapshot.

    Examples
    --------
    >>> records = plugin._operation_records(job_id=31)  # doctest: +SKIP
    """
    latest = {}
    trusted = {self.bc.address} if own_only else set(self._operation_peers())
    registered = None
    for record in (self.chainstore_hgetall(OPERATIONS_HKEY) or {}).values():
      # Scope before any registry lookup. An unrelated remote signer must not stall local reconciliation.
      if (not isinstance(record, dict) or (job_id is not None and str(record.get("job_id")) != str(job_id))
          or (operation_id is not None and record.get("operation_id") != operation_id)
          or (own_only and record.get("coordinator") != self.bc.address)):
        continue
      if not self._verify_operation_record(record, "coordinator"):
        continue
      if record.get("network") != self.evm_network:
        continue
      coordinator = record["coordinator"]
      if coordinator not in trusted:
        # A persisted oracle record can remain valid after its signer drops out of the local NetMon view.
        if registered is None:
          try:
            registered = {address.lower() for address in self.bc.get_eth_oracles()}
          except Exception as exc:
            # Authority unavailable is distinct from a signer that is absent from the registry.
            raise RuntimeError("Deployment operation authority is temporarily unavailable.") from exc
        try:
          if self.bc.node_address_to_eth_address(coordinator).lower() not in registered:
            continue
        except (AttributeError, TypeError, ValueError):
          continue
        trusted.add(coordinator)
      record_id = record.get("operation_id")
      sequence = record.get("sequence")
      if not isinstance(record_id, str) or type(sequence) is not int:
        continue
      writer_prefix = hashlib.sha256(record["coordinator"].encode()).hexdigest()[:16] + "-"
      if not record_id.startswith(writer_prefix):
        continue
      previous = latest.get(record_id)
      if previous is None or sequence > previous["sequence"]:
        latest[record_id] = record
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
    prefix = _OPERATION_PHASE_PREFIXES.get(operation.get("mutation"))
    if prefix and phase not in (None, "completed"):
      phase = prefix + phase.removeprefix(prefix)  # Older coordinators cannot dispatch this phase.
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

  def _replicate_operation(self, operation, every=30):
    """Retry the exact snapshot until confirmed; once confirmed, re-send it every `every` seconds as repair.

    A confirmation needs only part of the peers, and nothing else brings an oracle that missed the write
    up to date. The re-sent snapshot is the same record: peers that already hold it do not save it again.

    The snapshot is identified by its `sequence` and its signature. Until
    that exact snapshot has been confirmed once, every call writes it again
    and raises while the write stays unconfirmed, so the caller does not act
    on state the peers may lack. Once confirmed, a call within `every` seconds
    (30 by default) of the last send returns without writing; after that the
    same record is sent again as peer repair, and a failed repair send is not
    an error. Before this throttle the unchanged snapshot was re-sent to every
    oracle peer on every 2 s pass of the worker.

    An operation that is not completed keeps the 30 s repair only while its
    snapshot is younger than `OPEN_REPAIR_SECONDS` (600 s, by `updated_at`).
    Once the snapshot has not changed for that long, its repair waits 600 s
    after the last send instead: 6 sends an hour, where a blocked operation
    was sent about 115 times an hour to every oracle. A change of the
    operation makes a new snapshot, which is young again.

    Parameters
    ----------
    operation : dict
      A signed operation snapshot exactly as stored, with `operation_id`,
      `sequence`, `phase`, `updated_at` and `EE_SIGN`. It is written as is
      and never modified.
    every : float, optional
      Seconds a repair waits after the last send of the same snapshot.
      Default 30; `_reconcile_coordinator_operations` passes 0 for an
      operation completed 600 s or more ago, whose sends its repair schedule
      times. For an operation that is not completed and whose snapshot is
      `OPEN_REPAIR_SECONDS` old or older, the wait is `OPEN_REPAIR_SECONDS`
      whatever is passed.

    Returns
    -------
    None
      After a send (confirmed, or a failed repair of an already confirmed
      snapshot) its time is recorded in `_operations_confirmed`; a call inside
      the `every` window returns without sending or recording anything.

    Raises
    ------
    RuntimeError
      If the write is not confirmed and this exact snapshot was never
      confirmed before.

    Notes
    -----
    The timer is measured with `self.time()`; a negative age (a clock step
    backwards) counts as expired, so the record is sent rather than held
    back. A failed repair send also restarts the timer.

    The send times are kept in process memory, so after a restart the first
    call sends the snapshot at once, whatever its age, and the wait counts
    from that send. With the longer wait an oracle that missed an unchanged
    open snapshot gets it within 600 s instead of 30 s; until then it does
    not see that operation, or sees an older snapshot of it.

    Examples
    --------
    >>> plugin._replicate_operation(operation)  # not confirmed yet: writes and records the send
    >>> plugin._replicate_operation(operation)  # within 30 s: returns without writing
    >>> plugin.now += 31
    >>> plugin._replicate_operation(operation)  # repair: the same record is sent once more
    >>> plugin._replicate_operation(operation, every=0)  # no wait: the same record is sent once more
    >>> plugin.now += 600
    >>> plugin._replicate_operation(operation)  # open, unchanged for 600 s: sent, and then once per 600 s
    """
    if operation["phase"] != "completed" and (
      operation.get("recovery") == "blocked" or self.time() - operation["updated_at"] >= OPEN_REPAIR_SECONDS
    ):
      # An open operation whose snapshot has not changed for 600 s is repaired once per 600 s, not per 30 s:
      # a blocked operation was re-sent about 115 times an hour to every oracle with nothing new in it.
      every = OPEN_REPAIR_SECONDS
    # Read the confirmations kept in process memory since init; the signed snapshot carries no send bookkeeping.
    confirmed = self._operations_confirmed
    # Identify the snapshot by sequence and signature, and look up when it was last sent with confirmation.
    marker, last = (operation["sequence"], operation.get("EE_SIGN")), confirmed.get(operation["operation_id"])
    # Hold the repair back while the last send of this snapshot is less than `every` seconds old (30 s unless the
    # caller passes 0, for an operation completed 600 s or more ago, whose repair schedule times its sends).
    if last and last[:2] == marker and 0 <= self.time() - last[2] < every:
      return
    key = "{}|{}".format(operation["operation_id"], operation["sequence"] % 8)
    if not self.chainstore_hset(OPERATIONS_HKEY, key, operation, readonly=True,
                               **self._operation_write_kwargs()):
      if not last or last[:2] != marker:
        # Only a snapshot that was never confirmed blocks the caller; a failed repair of an already
        # confirmed one no longer stops the node commands that follow it.
        raise RuntimeError("Deployment state replication is pending.")
    # Record this send (or failed repair) so the next repair of the same snapshot waits `every` seconds again.
    confirmed[operation["operation_id"]] = marker + (self.time(),)

  def _assert_no_active_deployment(self, job_id=None, app_id=None):
    """Serialize other job mutations against known deployment/recovery work."""
    if any((str(record["job_id"]) == str(job_id) or (app_id and record["app_id"] == app_id))
           and record["phase"] != "completed"
           for record in self._operation_records().values()):
      raise DeploymentConflictError("Deployment or recovery is active; wait before changing this job.")

  def _find_request_operation(self, request, owner, kind, repair_parent=None):
    """Find an identical request or check whether another operation blocks it.

    Check the verified operation records for this owner and job before
    deciding whether a new request can proceed.

    Parameters
    ----------
    request : dict
      Deployment input including the job and stable request ID.
    owner : str
      Authenticated escrow owner.
    kind : str
      Kind of deployment operation being admitted.
    repair_parent : str or None, optional
      Active parent operation that may coexist with its own repair request.

    Returns
    -------
    dict or None
      The matching operation on an identical replay, or None for new input
      that does not conflict with observed operations.

    Raises
    ------
    ValueError
      The request ID is missing or is outside the allowed length.
    DeploymentConflictError
      The request ID matches different input, unrelated work is still active,
      or a new paid create would overlap an ended create's unconfirmed cleanup.

    Notes
    -----
    An exact replay returns the existing record before checking conflicts
    for new input. A completed phase can still block a new paid create until
    its recovery state confirms cleanup.

    Examples
    --------
    >>> plugin._find_request_operation(request, owner, "create")  # doctest: +SKIP
    """
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
      raise ValueError("A stable request_id of 1 to 128 characters is required.")
    digest = request_digest(request)
    job_id = str(request.get("job_id"))
    records = [record for record in self._operation_records(job_id=job_id).values()
               if record.get("owner", "").lower() == owner.lower()
               and str(record.get("job_id")) == job_id]
    for record in records:
      if record["request_id"] == request_id and record["kind"] == kind:
        if record["request_hash"] != digest:
          raise DeploymentConflictError("request_id was already used for different deployment input.")
        return record
    # Terminal execution never permits an overlapping paid create while its earlier workers may still run.
    if kind == "create" and any(record["kind"] == "create" and record.get("unconfirmed_nodes")
                                and record["phase"] == "completed" and record.get("recovery") == "blocked"
                                for record in records):
      raise DeploymentConflictError("A previous deployment still has unconfirmed cleanup for this paid job.")
    if any(record["phase"] != "completed" and (not repair_parent or record["operation_id"] != repair_parent) for record in records):
      raise DeploymentConflictError("A deployment operation or recovery is already active for this job.")
    return None

  def _replacement_refusal_key(self, owner, job_id, request_id, coordinator):
    """Index a terminal outcome by the same owner and job scope as admission."""
    identity = [self.evm_network, owner.lower(), str(job_id), request_id, coordinator]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()

  def _replacement_refusal_path(self, key):
    # The existing data volume contains these small records independently of the CStore flush interval.
    return os.path.join(self.log.get_data_folder(), f"deeploy-refusal-{key}.json")

  @staticmethod
  def _replacement_status_coordinator(request):
    # Limit the outcome lookup to a specific update and reviewed coordinator.
    coordinator, request_id = request.get("replacement_coordinator"), request.get("request_id")
    if (request.get("kind") == "update" and isinstance(request_id, str) and 1 <= len(request_id) <= 128
        and request.get("job_id") is not None and not request.get("operation_id")
        and isinstance(coordinator, str) and 1 <= len(coordinator) <= 128):
      return coordinator
    return None

  def _load_replacement_refusal(self, owner, job_id, request_id, coordinator):
    """Read a terminal refusal from this oracle's local durable replica."""
    key = self._replacement_refusal_key(owner, job_id, request_id, coordinator)
    record = None
    if coordinator == self.bc.address:
      try:
        with open(self._replacement_refusal_path(key), encoding="utf-8") as stream:
          record = json.load(stream)
      except FileNotFoundError:
        pass  # A replica may still have a prior record.
      except (OSError, ValueError) as exc:
        raise RuntimeError("The local replacement refusal could not be read.") from exc
      else:
        if not isinstance(record, dict):
          raise RuntimeError("The local replacement refusal is invalid.")
    if record is None:
      record = self.chainstore_hget(hkey=REPLACEMENT_REFUSALS_HKEY, key=key)
    if record is None:
      return None
    if (not isinstance(record, dict) or record.get("EE_SENDER") != coordinator
        or record.get("owner") != owner.lower()
        or not self.bc.verify(record, return_full_info=True, log_hash_sign_fails=False).valid):
      raise RuntimeError("Replacement refusal could not be verified.")
    proof = record.get("proof")
    if (not isinstance(proof, dict) or proof.get("network") != self.evm_network
        or proof.get("coordinator") != coordinator or proof.get("job_id") != str(job_id)
        or proof.get("request_id") != request_id):
      raise RuntimeError("Replacement refusal identity mismatch.")
    return record

  def _replacement_refusal_response(self, proof):
    """Return the same definitive result for a refused submission or exact retry."""
    return self._get_response({
      "status_code": 409, "status": "error", "non_admission": proof,
      "error": {"code": "REPLACEMENT_REVIEW_STALE", "retryable": False,
                "message": "The reviewed job or its operation changed. Review replacement again."},
    })

  def _refused_replacement_request(self, request, owner):
    """Reject reuse of a refused request ID before reserving a new operation."""
    record = self._load_replacement_refusal(owner, request["job_id"], request["request_id"], self.bc.address)
    if record is None:
      return None
    proof = record["proof"]
    if proof["request_hash"] != request["EE_HASH"]:
      raise DeploymentConflictError("request_id was already used for different replacement input.")
    # A previous local decision may have survived an unconfirmed CStore broadcast.
    self._replicate_replacement_refusal(record)
    return proof

  def _replicate_replacement_refusal(self, record):
    # Retry the same signed immutable value. Re-signing it could disagree with a peer that already has it.
    proof = record["proof"]
    key = self._replacement_refusal_key(record["owner"], proof["job_id"], proof["request_id"], proof["coordinator"])
    if not self.chainstore_hset(hkey=REPLACEMENT_REFUSALS_HKEY, key=key, value=record, readonly=True,
                                **self._operation_write_kwargs()):
      raise RuntimeError("Replacement refusal replication is pending.")

  def _refuse_replacement_request(self, request, owner, parent):
    """Resolve a stale replacement against the coordinator's admission record.

    Parameters
    ----------
    request : dict
      Authenticated wallet request with its stable ID and signed payload hash.
    owner : str
      Authenticated escrow owner, also used to scope status lookups.
    parent : str or None
      The reviewed retirement, which does not count as a competing admission.

    Returns
    -------
    dict
      An existing acceptance or a durable, signed refusal for this request.

    Examples
    --------
    >>> plugin._refuse_replacement_request(request, owner, parent)  # doctest: +SKIP
    """
    from .job_repair import HANDOFF_LOCK

    with HANDOFF_LOCK:
      existing = self._find_request_operation(request, owner, "update", repair_parent=parent)
      if existing:
        return self._accepted_operation_response(existing)
      proof = self._refused_replacement_request(request, owner)
      if proof is None:
        # This small, domain-separated signature can be verified from the coordinator's node address.
        job_id, request_id = str(request["job_id"]), request["request_id"]
        fields = [self.evm_network, job_id, self.bc.address, request_id, request["EE_HASH"]]
        message = "Ratio1 Deeploy replacement refusal v1\n" + json.dumps(
          fields, ensure_ascii=False, separators=(",", ":"),
        )
        proof = dict(network=self.evm_network, job_id=job_id, coordinator=self.bc.address,
                     request_id=request_id, request_hash=request["EE_HASH"],
                     signature=self.bc.eth_sign_text(message, no_hash=True))
        record = dict(owner=owner.lower(), proof=proof)
        self.bc.sign(record, add_data=True, use_digest=True)
        key = self._replacement_refusal_key(owner, job_id, request_id, self.bc.address)
        # A coordinator crash before the next CStore flush must not bring a refused request back to life.
        self._save_cache_file_strict(self._replacement_refusal_path(key), record, as_json=True)
        self._replicate_replacement_refusal(record)
      return self._replacement_refusal_response(proof)

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
    """Request custody work through the SDK without fetching protected bundles.

    Sends one custody step of an operation to dAuth through the SDK's signed secret reconciliation call
    and returns its checked answer. The SDK raises RuntimeError when the request could not be signed, when
    the call failed or timed out (dAuth may still have received it), when dAuth answered with an HTTP error
    or refused, and when a preparation is not finished; that error is raised again as
    `DeploymentCustodyError`, so the operations worker can wait before it calls the same dAuth server again.
    A ValueError (invalid payload, answer, signature or signer, and the SDK's `DauthSecretRecordTooLarge` for a
    secret record a dAuth server refused for its size) is raised unchanged: admission answers 400 for it, and the
    worker tries its own call again on the next pass, as before. Only a "prepare", which admission sends, can be
    refused for size.

    Parameters
    ----------
    action : str
      The custody step: "prepare", "status", "commit", "revoke" or "delete".
    operation : dict
      The coordinator's operation snapshot. A copy is sent; the snapshot itself is not changed.
    **payload
      The step's other fields, such as `new_secrets`, `active_attempt` or `pointer`.

    Returns
    -------
    dict
      The authenticated dAuth result. For "prepare" and "status" it holds the boolean `prepared`.

    Raises
    ------
    DeploymentCustodyError
      When the SDK call raised RuntimeError. The original error is its `__cause__` and its text is kept.
      It is a RuntimeError, so admission still answers 503 (`ADMISSION_UNAVAILABLE`) for it.
    ValueError
      When the payload or dAuth's answer is invalid, unchanged; admission still answers 400 for it.
    DauthSecretRecordTooLarge
      When dAuth refused a "prepare" because the chain store does not accept a secret record of the job for its
      size (a ValueError too); admission ends the operation at once for it.

    Notes
    -----
    Called by admission ("prepare") on the request thread, and by the operations worker for every
    other step. Only the worker waits after a `DeploymentCustodyError`, and only for an operation out of the
    "preparing" phase (see `_reconcile_coordinator_operations`).

    Examples
    --------
    >>> plugin._deployment_secret_request("status", operation)["prepared"]
    True
    >>> plugin._deployment_secret_request("revoke", operation, active_attempt=None)  # dAuth down
    Traceback (most recent call last):
    DeploymentCustodyError: dAuth reconciliation transport could not be confirmed.
    """
    try:
      # The signed custody call, unchanged; only its RuntimeError is given a type of its own below.
      result = self.bc.reconcile_dauth_job_secrets(dict(
        job_id=str(operation["job_id"]), operation=copy.deepcopy(operation),
        action=action, **payload,
      ))
      if operation.get("mutation") == "same_host_repair_v1" and (
          type(result.get("repair_protocol")) is not int or result["repair_protocol"] != 1):
        raise DeploymentCustodyError("The custodian did not confirm same-host repair support.")
      return result
    except RuntimeError as exc:
      # The SDK raises RuntimeError when the request could not be signed, when the call failed or timed out
      # (dAuth may still have received it), when dAuth answered with an HTTP error or refused it (for any
      # reason), and when a preparation is not finished; a type of its own lets the worker wait before the
      # next call, and it stays a RuntimeError for admission.
      raise DeploymentCustodyError(str(exc)) from exc

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

  def _previous_deployment_configs(self, pipeline, reports=None):
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
    reports : dict, optional
      Job reports already observed for this admission. An empty observation is valid.

    Returns
    -------
    dict
      Copies of the saved configurations keyed by the exact prior node set,
      with per-instance response keys removed.

    Raises
    ------
    ValueError
      The saved plan is unavailable or does not cover the prior placement,
      or legacy observations disagree with the saved configuration.

    Notes
    -----
    A signed pointer may reference either protected or legacy plan storage.
    For a restored revision, read the plan's previous configurations.

    Examples
    --------
    >>> config_by_node = plugin._previous_deployment_configs(pipeline)  # doctest: +SKIP
    """
    specs = pipeline["DEEPLOY_SPECS"]
    nodes = specs.get("current_target_nodes", [])
    pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(specs["job_id"]))
    if isinstance(pointer, dict) and pointer.get("plan_cid"):
      # Older plans and protected plans are both valid restoration inputs.
      plan = r1fs_documents.read_r1fs_document(self.r1fs, pointer["plan_cid"], timeout=10) or {}
      restored = str(specs.get("secret_revision", "")).endswith(":restore")
      configs = plan.get("previous_configs" if restored else "configs")
      if not isinstance(configs, dict) or set(configs) != set(nodes):
        raise ValueError("The stored deployment plan is unavailable.")
    else:
      if reports is None:  # Standalone mutation planning has no placement observation yet.
        reports = self._job_reports(pipeline)
      if any(required_instances(config) != required_instances(pipeline)
             or list_order_differs(with_observed_legacy_metadata_order(pipeline, config), config)
             for node_configs in reports.values() for config in node_configs):
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
    observed = [record["target_revision"] for record in self._operation_records(job_id=job_id).values()
                if str(record["job_id"]) == str(job_id)]
    return max([previous_revision, generation] + observed) + 1

  def _admit_prepared_deployment(self, request, auth_result, app_id, configs,
                                 prior_pipeline, is_create, mutation=None,
                                 restore_owner=None, identity_aliases=None, node_aliases=None, repair=None, replacement=None,
                                 resource_tier=None, deferred_capacity=False):
    """Save exact redacted plans and secret revisions before accepting work.

    Builds the operation's redacted plan (the target configs and, for an update,
    the previous configs to restore), stores it in R1FS, saves the operation in
    its "preparing" phase and asks dAuth to prepare the secret revisions. The
    operation is accepted when dAuth prepared them before the preparation
    deadline (created + 120 s).

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
    mutation : str, optional
      The kind of update for the record ("scale_up", "owner_transfer",
      "node_relink"); None for a create or a plain update.
    restore_owner : str, optional
      The owner the previous configs get for a restore (an owner transfer).
    identity_aliases : dict, optional
      Current plugin identity -> source identity for the instances a
      scale-up generates, so they inherit the source's secret values.
    node_aliases : dict, optional
      Old node -> new node for a relink. ``prior_pipeline`` still names the old
      node; its previous configs and placement are renamed here.

    resource_tier : dict, optional
      Chain-confirmed ceiling for ordinary Native and Stack edits.
    deferred_capacity : bool
      Require a balanced resource edit before deferring a failed pre-retirement capacity check.

    Returns
    -------
    dict
      Signed HTTP acceptance response.

    Raises
    ------
    DauthSecretRecordTooLarge
      When dAuth refused a secret record of the job for its size, also when
      the save that ends the operation is not confirmed. The operation is then
      already failed with the error's text and in cleanup, or, with that save
      unconfirmed, left to the worker as it is stored.
    DeploymentConflictError
      When the request's expected revision is not the stored one.
    ValueError
      When the configs or an update's previous revision are invalid (such as
      conflicting secret values at one path, or no exact placement to
      restore), or dAuth's answer is invalid.
    RuntimeError
      When the plan cannot be stored, a write is not confirmed, or a dAuth
      custody call fails (``DeploymentCustodyError``); the operation, if
      saved, is left to the worker.

    Notes
    -----
    A size refusal is final: no retry can store the record. The operation is
    then marked failed at once (``ADMISSION_PREPARATION_FAILED`` with the SDK
    error's text) and its preparation deadline is set to now, so that dAuth
    accepts the cleanup of anything staged at the worker's next pass and the
    job takes a corrected request right after it. Before, the operation stayed
    "preparing" until created + 120 s: the worker asked dAuth for its status
    on every 2 s pass, the same request was answered 202 for it and a
    corrected one 409. When the save that ends the operation is not confirmed,
    the size error is still the one raised (the API answers 400), not the
    save's RuntimeError (503 "retry with the same request_id"): the worker
    finishes from what is stored, the cleanup, or the 120 s path when nothing
    was stored.

    Examples
    --------
    >>> plugin._admit_prepared_deployment(request, auth_result, "app", {"A": config},
    ...                                   prior_pipeline=None, is_create=True)["status_code"]
    202
    """
    validate_source_pins(configs)  # Refuse invalid revisions before staging any secrets or plans.
    owner = auth_result[DEEPLOY_KEYS.ESCROW_OWNER]
    job_id = request["job_id"]
    previous_revision = 0 if is_create else (prior_pipeline or {}).get(
      "DEEPLOY_SPECS", {}).get("revision", 0)
    if not is_create:
      if not isinstance(prior_pipeline, dict):
        raise ValueError("An update requires a recoverable previous configuration.")
      if type(request.get("expected_revision")) is not int or request["expected_revision"] != previous_revision:
        raise DeploymentConflictError("The deployment revision changed; refresh before updating.")
    if repair is not None:
      from .job_repair import worker
      approved_id = repair["proposal"]["instance_id"]
      if (set(configs) != set(repair["aliases"].values()) or any(
          worker(config)["INSTANCE_ID"] != approved_id or config.get("NAME") != app_id
          or config.get("DEEPLOY_SPECS", {}).get("current_target_nodes") != list(repair["aliases"].values())
          for config in configs.values())):
        raise ValueError("The prepared update changed the approved worker identity or placement.")
      prior_pipeline = repair["prior"]  # Canonical content plus only the reviewed permutations.
      node_aliases = repair["aliases"]
    stored_pipeline = prior_pipeline
    prior_pipeline = relink_pipeline(prior_pipeline, node_aliases or {})
    operation_id = hashlib.sha256(self.bc.address.encode()).hexdigest()[:16] + "-" + uuid.uuid4().hex
    revision = self._next_deployment_revision(job_id, previous_revision)
    revision_prefix = operation_id + (":repair_v1" if repair else "")
    secret_revision = revision_prefix + ":deploy"
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
    if replacement:
      # Use the previous pointer for version and custody checks, with no plan to restart the previous placement.
      previous_secret_revision_to_release = prior_pipeline.get("DEEPLOY_SPECS", {}).get("secret_revision")
    if not is_create and not replacement:
      previous_nodes = prior_pipeline.get("DEEPLOY_SPECS", {}).get("current_target_nodes", [])
      if not previous_nodes:
        raise ValueError("The previous revision has no recoverable node placement.")
      previous_secret_revision = revision_prefix + ":restore"
      prior_secret_revision = prior_pipeline.get("DEEPLOY_SPECS", {}).get("secret_revision")
      previous_secret_revision_to_release = prior_secret_revision
      previous_operation_id = prior_secret_revision.split(":", 1)[0] if prior_secret_revision else None
      if repair:
        # One common legacy configuration; per-node overlays and multiple instances were excluded by assessment.
        previous_configs = {node: copy.deepcopy(prior_pipeline) for node in previous_nodes}
      else:
        reports = self._job_reports(stored_pipeline)  # Placement and legacy order validation share one observation.
        previous_configs = relink_configs(self._previous_deployment_configs(stored_pipeline, reports), node_aliases or {})
        # A relink also retires the workers it retains. One missing peer can strand the whole job after a partial stop.
        must_report = previous_nodes if mutation == "node_relink" else set(previous_nodes) - set(configs)
        if any(not reports.get(node) for node in must_report):
          if mutation == "node_relink":
            raise ValueError("A previous target does not report its workload at the current address. "
                             "Automatic relink requires an observed workload on every previous target.")
          raise ValueError("A previous target no longer reports this job. Restore connectivity or resolve its relink before updating.")
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
        validate_saved_overlays(old_config)  # Refuse an unsafe recovery plan before retiring the live placement.
        old_config.pop("DEEPLOY_OPERATION", None)
        if restore_owner is not None:
          old_config["OWNER"] = restore_owner
        old_config.setdefault("DEEPLOY_SPECS", {}).update(
          revision=previous_revision, secret_revision=previous_secret_revision,
        )
    # Compare authenticated materialized configs for the exact signed revision on every worker.
    budgets = (redistribution_requirements(previous_configs, configs, resource_tier)
               if resource_tier is not None and mutation is None and not is_create else {})
    if deferred_capacity and not budgets:
      raise ValueError("Insufficient free resources for an ordinary update without a balanced redistribution.")
    if budgets:
      # Legacy name inference remains available for unrelated edits. A paid redistribution must name every survivor.
      rows = request.get("plugins") or [request]
      explicit = {row.get("instance_id") or row.get("INSTANCE_ID") for row in rows}
      for node, config in configs.items():
        previous_ids = set(required_instances(previous_configs[node]))
        survivors = {iid for sig, iid in required_instances(config)
                     if sig in CONTAINERIZED_APPS_SIGNATURES and (sig, iid) in previous_ids}
        if not survivors <= explicit:
          raise ValueError("A container redistribution must explicitly identify every surviving instance_id.")
      mutation = RESOURCE_REDISTRIBUTION
    plan = dict(configs=configs, previous_configs=previous_configs)
    if budgets:
      plan["resource_requirements"] = budgets  # Immutable desired CPU, RAM and persistent disk allocations.
    if repair:
      # Keep signed historic and fresh receipts in the immutable plan under their actual signer.
      plan["repair_evidence"] = dict(stopped=repair["stopped"], inspections=repair["inspections"], seals=repair["seals"])
    # Execution plans use the same gated writer as the canonical job copy.
    plan_cid = r1fs_documents.write_r1fs_document(self.r1fs, plan, "deployment-plan.json")
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
    # Polling reads only signed local replicas and needs the same pin checks as execution, including restores.
    for attempt, placement in (("deploy", configs), ("restore", previous_configs)):
      requirements = {node: pins for node, config in placement.items() if (pins := pinned_sources(config))}
      if requirements:
        operation.setdefault("pinned_sources", {})[attempt] = requirements
    # The recovery owner must exist before any plaintext revision is staged.
    # If admission stops here, the worker either confirms complete preparation
    # or revokes its staged references without touching the running revision.
    if budgets:
      operation["phase"] = "resources_v1_preparing"  # Older coordinators cannot bypass the capacity barrier.
    if repair:
      operation.update(phase="repair_v1_preparing", repair_parent=repair["proposal"]["parent"],
                       previous_pipeline_cid=repair["proposal"]["pipeline_cid"],
                       repair_aliases=list(map(list, repair["aliases"].items())), repair_licenses=repair["licenses"],
                       rotate_main_tunnel=repair["rotate_main_tunnel"])
    if replacement:
      proposal = replacement["proposal"]
      operation.update(phase="stateless_v1_preparing", previous_pipeline_cid=proposal["pipeline_cid"],
                       unconfirmed_previous_nodes=replacement["unconfirmed_previous_nodes"],
                       replacement_licenses=replacement["licenses"], dispatched_nodes=[])
      if proposal["parent"]:
        operation["repair_parent"] = proposal["parent"]  # Reserve the active retirement before any side effect.
    finished = threading.Event()
    self._deployment_preparations[operation_id] = finished
    try:
      if repair:
        existing = self._hold_repair_parent(operation, repair)
        if existing:
          return self._accepted_operation_response(existing)
      elif replacement:
        from .job_repair import HANDOFF_LOCK
        with HANDOFF_LOCK:  # Serialize the short reservation, leaving chain and custody calls outside the lock.
          parent = (operation.get("repair_parent") or {}).get("operation_id")
          existing = self._find_request_operation(request, owner, "update", repair_parent=parent)
          if existing:
            return self._accepted_operation_response(existing)
          refusal = self._refused_replacement_request(request, owner)
          if refusal:
            return self._replacement_refusal_response(refusal)
          if parent:
            existing = self._hold_repair_parent(operation, replacement)
            if existing:
              return self._accepted_operation_response(existing)
          else:
            if self._get_pipeline_from_cstore(job_id) != operation["previous_pipeline_cid"]:
              raise StaleReplacementReviewError("The published job changed during replacement review.")
            self._save_operation(operation, message="Preparing stateless replacement.")
      else:
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
    except DauthSecretRecordTooLarge as exc:
      # The preparation ends now: dAuth accepts the cleanup of an operation only past its preparation deadline
      # (no "prepare" of it can still be in flight), and this one's only "prepare" was answered. Before, the
      # deadline stayed at created + 120 s, and with it the status calls and the 409 for a corrected request.
      operation["preparation_deadline"] = self.time()
      # An unconfirmed save ("replication is pending") must not replace the size error: it made the API answer 503
      # "retry with the same request_id" for a request that can never succeed. The worker then ends the operation
      # from what is stored: the cleanup, or the 120 s path when nothing was stored.
      with contextlib.suppress(RuntimeError):
        # Failed at once with the SDK's text, which the job's owner reads in the operation's status too.
        self._expire_deployment_preparation(operation, str(exc))
      # Raised on, as before: the API answers 400 with the same text.
      raise
    finally:
      # Keep the marker until the worker discards its old snapshots and reloads
      # durable state. This also hands interrupted admission to recovery.
      finished.set()
    self._deployment_operations_event.set()
    return self._accepted_operation_response(operation)

  def _load_operation_plan(self, operation):
    """Load the immutable, redacted plan for executing an operation.

    Reuse a cached plan or download it once before returning a private copy.

    Parameters
    ----------
    operation : dict
      Signed operation containing the plan's CID.

    Returns
    -------
    dict
      Independent copy of the validated plan, including its config mapping.

    Raises
    ------
    RuntimeError
      The plan is unavailable or its configs field is invalid.

    Notes
    -----
    A cache miss supports legacy and protected documents through one download.
    The cache lock covers bookkeeping only. Status polling does not load plans.

    Examples
    --------
    >>> configs = plugin._load_operation_plan(operation)["configs"]  # doctest: +SKIP
    """
    cid = operation["plan_cid"]
    with self._deployment_plan_cache_lock:
      plan = self._deployment_plans.get(cid)
    if plan is None:
      # Recovery can use either passphrase while fetching the plan only once.
      plan = r1fs_documents.read_r1fs_document(self.r1fs, cid, timeout=10)
      if not isinstance(plan, dict) or not isinstance(plan.get("configs"), dict):
        raise RuntimeError("Deployment plan is temporarily unavailable.")
      # Only cache bookkeeping is locked; storage reads never hold this lock.
      with self._deployment_plan_cache_lock:
        if cid not in self._deployment_plans and len(self._deployment_plans) >= 32:
          self._deployment_plans.pop(next(iter(self._deployment_plans)))
        self._deployment_plans[cid] = plan
    return copy.deepcopy(plan)

  def _node_is_ready(self, node, report, config, pins=None, restore_bindings=None):
    """Pair the attempt's one-time ready report with current NetMon liveness."""
    return (report_is_ready(report, config, pins=pins, restore_bindings=restore_bindings)
            and self._netmon_node_is_online_for_control(node))

  def _node_operation_reports(self, operation, attempt):
    """Read newest signed reports from the planned nodes for this attempt."""
    reports = {}
    nodes = set(operation["nodes"] if attempt == "deploy" else operation["previous_nodes"])
    revision = operation["target_revision"] if attempt == "deploy" else operation["previous_revision"]
    for report in (self.chainstore_hgetall(NODE_OPERATIONS_HKEY) or {}).values():
      if not isinstance(report, dict) or report.get("operation_id") != operation["operation_id"]:
        continue
      if report.get("app_id") != operation["app_id"]:
        continue
      if report.get("attempt") != attempt or type(report.get("revision")) is not int or report["revision"] != revision:
        continue
      node = report.get("node_addr")
      if not isinstance(node, str) or report.get("coordinator") != operation["coordinator"]:
        continue
      if node not in nodes:
        # A legacy plan can key the same worker by its bare, case-sensitive address.
        prefix = BCct.ADDR_PREFIX
        node = node.removeprefix(prefix) if node.startswith(prefix) else prefix + node
        if node not in nodes:
          continue
      # Verify the untouched report against its signer. Index it by the original plan key.
      if not self._verify_operation_record(report, "node_addr"):
        continue
      sequence = report.get("sequence")
      if type(sequence) is not int:
        continue
      if node not in reports or reports[node]["sequence"] < sequence:
        reports[node] = report
    if attempt == "retire" and operation.get("mutation") in ("node_relink", "same_host_repair_v1", RESOURCE_REDISTRIBUTION):
      # Filter after selecting the newest signature so an older stop cannot hide later contradictory evidence.
      reports = {node: report for node, report in reports.items() if report.get("status") != "stopped"
                 or report_confirms_retirement(report, operation["previous_instances"].get(node))}
    return reports

  def _operation_metadata(self, operation, attempt, action):
    """Bind a node command to its coordinator, attempt, and content revision."""
    metadata = dict(
      operation_id=operation["operation_id"], attempt=attempt, action=action,
      revision=operation["target_revision"] if attempt == "deploy" else operation["previous_revision"],
      coordinator=operation["coordinator"], peers=self._operation_peers(),
      job_id=operation["job_id"],
      expected_previous_operation_id=operation.get("previous_operation_id") if attempt == "retire" else None,
    )
    if action == "start" and operation.get("mutation") == "same_host_repair_v1":
      # Both workers must fence legacy writes, including one stopped by the original coordinator operation.
      metadata.update(action="start_repaired_worker_v1", parent_operation_id=operation["repair_parent"]["operation_id"],
                      previous_revision=operation["previous_revision"])
    if action == "start" and operation.get("mutation") == STATELESS_REPLACEMENT:
      metadata["action"] = "start_stateless_replacement_v1"  # Old workers cannot interpret this as an ordinary start.
    return metadata

  def _send_operation_commands(self, operation, configs, attempt, action, reports):
    """Retry scoped commands while recording intent before transport dispatch.

    For every planned node that has not yet reported the wanted outcome
    (stopped for "stop" and "retire", ready for "start"), sends a pipeline
    command at most once per 10 s. Before each command the operation is saved
    so the durable record leads the side effect; a restore or owner-transfer
    start also binds each pinned or catalogue instance to the runtime artifacts
    the retired revision reported. Each command carries the operation metadata
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
      The coordinator's operation snapshot. It may be saved, and when an
      instance's needed runtime binding (Git commit for a worker app, image
      id for a container app) is missing it is marked `recovery="blocked"`
      and saved with an event naming what is missing.
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
      If a restore or owner-transfer start lacks the previous runtime binding
      an instance needs (the Git commit for a worker app, the image id for a
      container app), or if a save is not confirmed.
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
    check_placement = action == "start" and operation.get("mutation") == "same_host_repair_v1"
    check_replacement = action == "start" and operation.get("mutation") == STATELESS_REPLACEMENT
    repair_restore = check_placement and attempt == "restore"
    # Normal delivery remains responsive. Repeated commands for a blocked phase use the replica repair cadence.
    interval = OPEN_REPAIR_SECONDS if operation.get("recovery") == "blocked" else 10
    for node, config in configs.items():
      report = reports.get(node, {})
      if action in ("stop", "retire") and report.get("status") == "stopped":
        continue
      restore_bindings = operation.get("retired_runtime", {}).get(node, {}) if repair_restore else None
      if action == "start" and report_is_ready(report, config, restore_bindings=restore_bindings):
        continue
      # Resend throttle in process memory, not in the signed snapshot; nodes de-duplicate by operation_id|attempt.
      sent_at = self._operations_sent_at
      # The map is shared by all operations, so the key starts with the operation id; the old in-snapshot
      # key needed only attempt|action|node.
      key = "{}|{}|{}|{}".format(operation["operation_id"], attempt, action, node)
      # Missing send history permits the first attempt even immediately after a coordinator starts.
      if key in sent_at and 0 <= self.time() - sent_at[key] < interval:
        continue
      if check_placement:
        # One fresh read covers this batch, including starts retried after a coordinator restart.
        self._recheck_repair_placement(operation)
        check_placement = False
      if check_replacement:
        # Check once for this batch of actual sends, including retries after a restart.
        check_replacement_placement(self, operation)
        check_replacement = False
      if action == "start":
        validate_saved_overlays(config)  # Resumed plans may predate the reserved restoration field.
      # Record the send time in memory only: the save below then finds nothing changed and writes no new
      # snapshot for a mere retry.
      payload = copy.deepcopy(config) if action == "start" else {
        "NAME": operation["app_id"], "TYPE": config["TYPE"],
      }
      if action == "start" and (attempt == "restore" or operation.get("mutation") == "owner_transfer"):
        bindings = operation.get("retired_runtime", {}).get(node, {})
        for plugin in payload.get("PLUGINS", []):
          if plugin["SIGNATURE"].upper() not in CONTAINERIZED_APPS_SIGNATURES:
            continue
          for instance in plugin.get("INSTANCES", []):
            if deployment_source_mode(plugin["SIGNATURE"], payload, instance) == "following":
              instance.pop("DEEPLOY_RUNTIME_ARTIFACTS", None)  # Older restored configs can carry a stale binding.
              continue
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
      if action == "start" and operation.get("mutation") == STATELESS_REPLACEMENT:
        if self.time() >= operation["deadline"]:
          return  # Chain checks can take the rollout past its deadline before any dispatch intent is recorded.
        # Once persisted, cleanup must assume this worker may have received the command.
        operation["dispatched_nodes"] = sorted(set(operation["dispatched_nodes"]) | {node})
      self._save_operation(operation)
      sent_at[key] = self.time()
      self.cmdapi_start_pipeline(config=payload, node_address=node)

  def _advance_serialized_operation(self, operation):
    """Advance a signed snapshot, fencing superseded retirement at the owning coordinator."""
    if operation["coordinator"] != self.bc.address or operation["phase"] == "completed":
      return
    if operation.get("mutation") == "node_relink" and hasattr(self, "_reconcile_repair_parent"):
      from .job_repair import HANDOFF_LOCK
      with HANDOFF_LOCK:
        current = self._operation_records(operation_id=operation["operation_id"], own_only=True).get(operation["operation_id"])
        if not current or current["sequence"] != operation["sequence"] or self._reconcile_repair_parent(current):
          return  # An HTTP reservation may have completed after this worker took its snapshot.
        return self._advance_deployment_operation(operation)
    return self._advance_deployment_operation(operation)

  def _post_retirement_capacity(self, node, stopped_at, required):
    """Check one direct heartbeat sampled after the signed stop receipt.

    Parameters
    ----------
    node : str
      Retained worker identity.
    stopped_at : float
      Sender-clock timestamp of its signed complete stop.
    required : list
      Desired CPU cores and memory/disk bytes as exact decimal strings.

    Returns
    -------
    tuple
      Fresh sender timestamp and whether the sample covers the desired allocation.

    Examples
    --------
    >>> plugin._post_retirement_capacity("worker", 100.0, ["1", "100", "0"])  # doctest: +SKIP
    (102.0, True)
    """
    try:
      hb = self.netmon.network_node_last_heartbeat(node)  # Read one direct frame, never display-summary fields.
      if hb.get(ct.PAYLOAD_DATA.EE_TZ):
        zone = ZoneInfo(hb[ct.PAYLOAD_DATA.EE_TZ])  # A named zone preserves half-hour offsets and DST.
      else:
        offset = str(hb[ct.PAYLOAD_DATA.EE_TIMEZONE]).removeprefix("UTC").replace("--", "-") or "0"
        zone = timezone(timedelta(hours=int(offset)))
      local = datetime.strptime(hb[ct.HB.CURRENT_TIME], ct.HB.TIMESTAMP_FORMAT)
      recent = [ts for ts in {local.replace(tzinfo=zone, fold=f).timestamp() for f in (0, 1)}
                if 0 <= self.time() - ts <= 60]
      if len(recent) != 1:
        return None, False  # Only a unique, current sender-clock time can authorize a start.
      sampled = recent[0]
      if not sampled > stopped_at:
        return None, False  # Delayed pre-stop packets and stale or future-dated samples cannot credit capacity.
      cores, load, ram, disk = (Decimal(str(hb[key])) for key in
                                (ct.HB.CPU_NR_CORES, ct.HB.CPU_USED, ct.HB.AVAILABLE_MEMORY, ct.HB.AVAILABLE_DISK))
      if not all(value.is_finite() and value >= 0 for value in (cores, load, ram, disk)) or load > 100:
        return None, False
      free = (cores * (100 - load) / 100, ram * 1024 ** 3, disk * 1024 ** 3)
      return sampled, all(observed >= Decimal(wanted) for observed, wanted in zip(free, required, strict=True))
    except (KeyError, ValueError, TypeError, OverflowError, InvalidOperation, OSError, RuntimeError):
      return None, False  # Unknown telemetry leaves the bounded recovery deadline running.

  def _advance_deployment_operation(self, operation):
    """Advance the eligible operation by one coordinator pass.

    Process preparation, worker confirmation and publication or recovery
    for the saved phase. Dispatch commands after the applicable guards pass.

    Parameters
    ----------
    operation : dict
      Coordinator snapshot with the current phase, deadlines and plan.

    Returns
    -------
    None
      Persists progress or waits for the next eligible pass.

    Raises
    ------
    RuntimeError
      Required plan, custody or operation replication is unavailable.

    Notes
    -----
    Foreign and completed operations are ignored. Delete uses its own
    retirement path. Ordinary blocked retirement, failed-rollout cleanup
    and restoration can end after their deadline plus 24 readiness
    timeouts. Same-host repair and stateless replacement retain their
    applicable reservation, stop and publication barriers.

    Examples
    --------
    >>> plugin._advance_deployment_operation(operation)  # doctest: +SKIP
    """
    if operation["coordinator"] != self.bc.address or operation["phase"] == "completed":
      return
    if operation["kind"] == "delete":
      return self._advance_delete_operation(operation)
    repair = operation.get("mutation") == "same_host_repair_v1"
    replacing = operation.get("mutation") == STATELESS_REPLACEMENT
    redistributing = operation.get("mutation") == RESOURCE_REDISTRIBUTION
    # Signed repair and replacement retain their own durable handoff and publication barriers.
    recovery_grace = self.cfg_deployment_readiness_timeout * BLOCKED_RECOVERY_GRACE_PERIODS
    if (repair or (replacing and operation.get("repair_parent"))) and not self._repair_parent_is_held(operation):
      return  # A crash between reservation writes is repaired from the parent pass.
    phase = deployment_operation_phase(operation)
    if phase == "preparing" and self.time() >= operation["preparation_deadline"]:
      self._expire_deployment_preparation(operation)
    elif (repair and phase in ("accepted", "retiring_previous") and not operation.get("retire_challenges")
          and self.time() >= max(operation["deadline"], operation["preparation_deadline"])):
      # A repair can safely release its parent only before any STOP challenge was durably recorded.
      self._expire_deployment_preparation(operation)
    self._replicate_operation(operation)
    if deployment_operation_phase(operation) == "cleaning_up_preparation":
      self._deployment_secret_request("revoke", operation, active_attempt=None)
      operation["recovery"] = "completed"
      self._save_operation(operation, "completed", "Incomplete deployment preparation cleaned up.")
      return
    if deployment_operation_phase(operation) == "preparing":
      return self._finish_deployment_preparation(operation)
    plan = self._load_operation_plan(operation)
    configs = plan["configs"]
    reports = self._node_operation_reports(operation, "deploy")
    phase = deployment_operation_phase(operation)
    resume_replacement = False
    if phase == "accepted":
      next_phase = "retiring_previous" if operation["kind"] == "update" and not replacing else "waiting_for_readiness"
      message = "Starting replacement targets without previous stop confirmation." if replacing else "Preparing target nodes."
      self._save_operation(operation, next_phase, message)
      phase = deployment_operation_phase(operation)
    if phase == "retiring_previous" and repair:
      return self._retire_repair_workers(operation, plan)
    if phase == "retiring_previous":
      retired = self._node_operation_reports(operation, "retire")
      # Only the workers in the previous placement can satisfy its retirement barrier.
      missing = [node for node in plan["previous_configs"] if retired.get(node, {}).get("status") != "stopped"]
      if not missing:
        operation["retired_runtime"] = {
          node: {item["signature"] + "|" + item["instance_id"]: copy.deepcopy(item["runtime_artifacts"])
                 for item in report.get("instances", []) if item.get("runtime_artifacts")}
          for node, report in retired.items()
        }
        if operation.get("error"):
          operation["restore_deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          # The restoration phase has its own readiness deadline and responsive initial sends.
          operation["recovery"] = "in_progress"
          self._save_operation(operation, "restoring_previous", "Restoring the previous revision.")
        elif redistributing:
          # Each stop receipt and the matching heartbeat are timestamped by the same worker.
          operation["capacity_after"] = {node: retired[node].get("updated_at") for node in plan["previous_configs"]}
          operation["deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          self._save_operation(operation, "waiting_for_capacity", "Previous instances stopped; awaiting fresh worker capacity.")
        else:
          operation["deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          self._save_operation(operation, "waiting_for_readiness", "Previous instances stopped; starting target nodes.")
      else:
        if self.time() >= operation["deadline"] + recovery_grace:
          return self._end_blocked_operation(operation, missing)
        if operation.get("recovery") != "blocked" and (
          self.time() >= operation["deadline"] or any(r.get("status") == "failed" for r in retired.values())
        ):
          operation["error"] = dict(code="PREVIOUS_STOP_UNCONFIRMED",
                                    message="Waiting for confirmed stop of the previous revision.", retryable=True)
          operation["recovery"] = "blocked"
          # Publish the blocked state even when the next command is still throttled.
          self._save_operation(operation)
        self._send_operation_commands(operation, plan["previous_configs"], "retire", "retire", retired)
      return
    if phase == "waiting_for_capacity":
      # Admit the desired start only once every retained worker reports sufficient capacity.
      first_samples = dict(operation.get("first_capacity_sample", {}))
      missing = []
      for node, required in plan["resource_requirements"].items():
        sampled, sufficient = self._post_retirement_capacity(node, operation["capacity_after"].get(node), required)
        if sampled is None or not sufficient or sampled <= first_samples.get(node, float("inf")):
          missing.append(node)
        if sampled is not None:
          # CURRENT_TIME is written after resource collection. The next heartbeat starts a new collection.
          first_samples.setdefault(node, sampled)
      if first_samples != operation.get("first_capacity_sample", {}):
        operation["first_capacity_sample"] = first_samples
        self._save_operation(operation)  # Preserve the first observation across coordinator restart.
      if self.time() >= operation["deadline"]:
        operation["error"] = dict(code="POST_RETIRE_CAPACITY_UNCONFIRMED",
                                  message="Worker capacity was insufficient or unconfirmed after retirement.",
                                  nodes=missing, retryable=True)
        operation["restore_deadline"] = self.time() + self.cfg_deployment_readiness_timeout
        operation["recovery"] = "in_progress"
        self._save_operation(operation, "restoring_previous", "Restoring the saved allocation and membership.")
      elif not missing:
        operation["deadline"] = self.time() + self.cfg_deployment_readiness_timeout
        self._save_operation(operation, "waiting_for_readiness", "All retained workers confirmed sufficient free capacity.")
      return
    if phase in ("finalizing", "finalizing_recovery"):
      restoring = phase == "finalizing_recovery"
      active_reports = self._node_operation_reports(operation, "restore") if restoring else reports
      active_configs = plan["previous_configs"] if restoring else configs
      expired = self.time() >= operation.get("restore_deadline" if restoring else "deadline", operation["deadline"])
      for node, config in active_configs.items():
        pins = pinned_sources(config)
        # A node may go offline between the readiness barrier and publication of the revision.
        recheck = repair or replacing or redistributing or bool(pins) or any(
          deployment_source_mode(plugin["SIGNATURE"], config, instance) == "following"
          for plugin in config.get("PLUGINS", []) for instance in plugin.get("INSTANCES", [])
        )
        online = self._netmon_node_is_online_for_control(node) if recheck else True
        restore_bindings = operation.get("retired_runtime", {}).get(node, {}) if repair and restoring else None
        state = node_rollout_state(config, active_reports.get(node), online, expired, pins=pins,
                                   allow_waiting_for_source=not (repair or replacing or redistributing), restore_bindings=restore_bindings)
        if state in ("failed", "legacy_failed") or (recheck and state not in ("ready", "kept")):
          # Once the revision is published, its remaining secret/metadata writes must still finish.
          pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(operation["job_id"]))
          if not isinstance(pointer, dict) or pointer.get("operation_id") != operation["operation_id"]:
            if replacing and operation.get("replacement_publication_started"):
              resume_replacement = True  # Only dAuth may finish a publication once readiness is lost.
              break
            phase = "restoring_previous" if restoring else "waiting_for_readiness"
            self._save_operation(operation, phase, "Rechecking node evidence before revision publication.")
          break
    if phase == "waiting_for_readiness":
      expired = self.time() >= operation["deadline"]
      # Repair keeps the existing all-workers-ready barrier, including for source-following apps.
      states = {node: node_rollout_state(config, reports.get(node), self._netmon_node_is_online_for_control(node), expired,
                                         allow_waiting_for_source=not (repair or replacing or redistributing))
                for node, config in configs.items()}
      failed = any(state in ("failed", "legacy_failed") for state in states.values())
      if failed or (expired and any(state in ("pending", "legacy_timeout") for state in states.values())):
        message = "A required instance failed." if failed else "Not all target nodes confirmed readiness in time."
        if any(state in ("legacy_failed", "legacy_timeout") for state in states.values()):
          # Stop snapshots replace failure snapshots; keep upgrade guidance on the operation.
          message += " Update the node to support the requested source mode."
        self._fail_deployment_rollout(operation, "INSTANCE_FAILED" if failed else "READINESS_DEADLINE_EXCEEDED", message)
      elif "pending" not in states.values():
        operation["waiting_for_source"] = "kept" in states.values()  # Persist the barrier decision across restarts.
        self._save_operation(operation, "finalizing", "Revision applied; waiting for source." if operation["waiting_for_source"]
                             else "All required instances are ready.")
      else:
        pending = {node: configs[node] for node, state in states.items() if state == "pending"}
        try:
          self._send_operation_commands(operation, pending, "deploy", "start", reports)
        except ReplacementPlacementError as exc:
          # A confirmed license or payment change never starts additional targets.
          self._fail_deployment_rollout(operation, "REPLACEMENT_PLACEMENT_CHANGED", str(exc))
      return
    if phase == "stopping_failed_rollout":
      # Requiring all stop acknowledgments provides the stateful restoration barrier.
      if replacing:
        # Dispatch intent survives a crash. Targets that never got an intent must not receive a STOP.
        configs = {node: configs[node] for node in operation["dispatched_nodes"]}
      # Stop evidence remains mandatory for restoration, including after the grace period expires.
      missing = [node for node in configs if reports.get(node, {}).get("status") != "stopped"]
      if not missing:
        if operation["kind"] == "update" and operation["previous_nodes"]:
          operation["restore_deadline"] = self.time() + self.cfg_deployment_readiness_timeout
          # Confirmed stops clear the prior blockage while restoration begins.
          operation["recovery"] = "in_progress"
          self._save_operation(operation, "restoring_previous", "Restoring the previous revision.")
        else:
          self._release_unused_secret_revisions(operation, plan, active_attempt=None)
          operation.update(outcome="failed", recovery="completed")
          self._save_operation(operation, "completed", "Failed deployment stopped on all target nodes.")
      else:
        # Earlier snapshots already provide the durable start of cleanup.
        deadline = operation["recovery_started_at"] + self.cfg_deployment_readiness_timeout
        if not (repair or replacing) and self.time() >= deadline + recovery_grace:
          return self._end_blocked_operation(operation, missing)
        if operation.get("recovery") != "blocked" and self.time() >= deadline:
          operation["recovery"] = "blocked"
          # The failure remains visible while waiting for the next permitted send.
          self._save_operation(operation)
        self._send_operation_commands(operation, configs, "deploy", "stop", reports)
      return
    if phase == "restoring_previous":
      previous_configs = plan["previous_configs"]
      previous_reports = self._node_operation_reports(operation, "restore")
      expired = self.time() >= operation["restore_deadline"]
      states = {node: node_rollout_state(config, previous_reports.get(node), self._netmon_node_is_online_for_control(node), expired,
                                         allow_waiting_for_source=not (repair or redistributing),
                                         restore_bindings=operation.get("retired_runtime", {}).get(node, {}) if repair else None)
                for node, config in previous_configs.items()}
      if all(state in ("ready", "kept") for state in states.values()):
        message = "Previous revision restored and waiting for source." if "kept" in states.values() else "Previous revision is ready on all required nodes."
        self._save_operation(operation, "finalizing_recovery", message)
      else:
        # Keep the already running restoration candidates and name the ones without positive readiness.
        unresolved = {node: previous_configs[node] for node, state in states.items() if state not in ("ready", "kept")}
        if not (repair or replacing) and self.time() >= operation["restore_deadline"] + recovery_grace:
          return self._end_blocked_operation(operation, unresolved)
        if operation.get("recovery") != "blocked" and (
          expired or any(state in ("failed", "legacy_failed") for state in states.values())
        ):
          operation["recovery"] = "blocked"
          # A pending throttle must not hide newly blocked restoration from the caller.
          self._save_operation(operation)
        self._send_operation_commands(operation, unresolved, "restore", "start", previous_reports)
      return
    if phase in ("finalizing", "finalizing_recovery"):
      restored = phase == "finalizing_recovery"
      active_configs = plan["previous_configs"] if restored else configs
      if repair:
        self._recheck_repair_placement(operation, finalizing=True)  # A placement can change after readiness.
      if replacing:
        pointer = self.chainstore_hget("DEEPLOY_DEPLOYED_JOBS", str(operation["job_id"]))
        if not resume_replacement and (not isinstance(pointer, dict) or pointer.get("operation_id") != operation["operation_id"]):
          try:
            check_replacement_placement(self, operation)
          except ReplacementPlacementError as exc:
            if not operation.get("replacement_publication_started"):
              self._fail_deployment_rollout(operation, "REPLACEMENT_PLACEMENT_CHANGED", str(exc))
              return
            # Once custody might have published, a missing replica is insufficient evidence for rollback.
            operation.update(error=dict(code="REPLACEMENT_PLACEMENT_CHANGED", message=str(exc), retryable=True),
                             recovery="blocked")
            self._save_operation(operation)
            resume_replacement = True
        if resume_replacement:
          result = self.commit_deployment_revision(operation, next(iter(active_configs.values())), resume_only=True)
          if (result.get("publication_committed") is not True
              or result.get("pipeline_cid") != operation["replacement_publication"]["pipeline_cid"]):
            message = "Waiting to verify replacement publication or worker readiness."
            if not operation.get("error"):
              operation.update(error=dict(code="REPLACEMENT_PUBLICATION_UNCONFIRMED", message=message, retryable=True),
                               recovery="blocked")
              self._save_operation(operation)
            raise DeploymentCustodyError(message)
          # A confirmed response can recover the notice from the already-published pointer.
          publication = result
        else:
          try:
            # Keep evidence of any legacy rewrite until the last signed custody request succeeds.
            publication = self._commit_operation_revision(operation, active_configs)
          except ReplacementPublicationRefused as exc:
            self._fail_deployment_rollout(operation, "REPLACEMENT_PLACEMENT_CHANGED", str(exc))
            return
        if (operation.get("error") or {}).get("code") in (
          "REPLACEMENT_PLACEMENT_CHANGED", "REPLACEMENT_PUBLICATION_UNCONFIRMED",
        ):
          operation.update(error=None, recovery=None)  # The custodian confirmed the exact publication.
          self._save_operation(operation)
      else:
        # Standard updates and restores also return their verified publication evidence.
        publication = self._commit_operation_revision(operation, active_configs)
      self._release_unused_secret_revisions(operation, plan, active_attempt="restore" if restored else "deploy")
      if publication and publication.get("credential_rotation_required") is True:
        # The final signed operation records the notice after all custody steps used the prior signature.
        operation["credential_rotation_required"] = True
      applied_outcome = "waiting_for_source" if operation.get("waiting_for_source") else "succeeded"
      operation.update(outcome="failed" if restored else applied_outcome,
                       recovery="completed" if restored else None)
      self._save_operation(operation, "completed",
                           "Previous revision restored." if restored else "Deployment completed.")

  def _end_blocked_operation(self, operation, missing):
    """End a phase whose workers did not supply the required evidence.

    Save the terminal result before contacting custody so a transient custody
    outage cannot keep sending workload commands or delay the failure result.

    Parameters
    ----------
    operation : dict
      Coordinator-owned operation still waiting for worker reports.
    missing : iterable of str
      Addresses without the expected signed stop or readiness report.

    Returns
    -------
    None

    Raises
    ------
    ValueError
      This oracle is not the operation coordinator.
    RuntimeError
      Replication of the terminal snapshot is unconfirmed.

    Notes
    -----
    The signed terminal snapshot keeps the phase and workers outstanding at
    expiry even if a replica sees newer worker reports later. Deletion leaves
    the published configuration and credentials available to the existing job.
    For other operations, the pending flag lets reconciliation retry revocation
    of the abandoned deployment revision after the terminal save. Workload
    command dispatch ends with the saved terminal transition.

    Examples
    --------
    >>> plugin._end_blocked_operation(operation, ["worker-b"])  # doctest: +SKIP
    """
    # Preserve the last work phase so readers can distinguish restore readiness from stop evidence.
    phase = deployment_operation_phase(operation)
    # Keep every affected worker in the signed snapshot so lagging replicas can report the same result.
    missing = sorted(missing)
    # This terminal event describes the unconfirmed evidence, without claiming a workload stopped.
    evidence = "readiness" if phase == "restoring_previous" else "shutdown"
    # Explain which confirmation the coordinator was missing in the event and the public error.
    message = "The operation ended before confirming {} on every required worker.".format(evidence)
    # Record failure while distinguishing the unfinished cleanup from the ended execution.
    operation.update(outcome="failed", recovery="blocked", blocked_phase=phase, unconfirmed_nodes=missing,
                     error=dict(code=BLOCKED_OPERATION_ENDED, message=message, retryable=False))
    if operation["kind"] != "delete":
      # Only an abandoned deploy revision needs revocation after the terminal save.
      operation["abandoned_deploy_revocation_pending"] = True
    # Persist the terminal transition and event before the reconciler can contact custody.
    self._save_operation(operation, "completed", message)

  def _confirm_ended_create_cleanup(self, operation):
    """Confirm late cleanup for an ended paid create using signed receipts.

    A positive result leaves the failure and its recorded shutdown gaps in
    history, while allowing the user to submit a new paid-job request.

    Parameters
    ----------
    operation : dict
      Coordinator-owned terminal snapshot with revocation already confirmed.

    Returns
    -------
    bool
      True after saving confirmed cleanup, or False if the operation is
      ineligible or still lacks an exact signed stop.

    Raises
    ------
    RuntimeError
      Replication of the updated snapshot is unconfirmed.
    ValueError
      The caller is not the operation's coordinator.

    Notes
    -----
    Every planned worker must have a verified stop for the exact attempt.
    An empty signed instance list fences an absent attempt. Otherwise the
    report must confirm retirement of the full planned instance set.

    Examples
    --------
    >>> plugin._confirm_ended_create_cleanup(operation)  # doctest: +SKIP
    True
    """
    # Other terminal operation types keep their original recovery state.
    if (operation["kind"] != "create" or operation.get("blocked_phase") != "stopping_failed_rollout"
        or operation.get("recovery") != "blocked"):
      return False
    # A replica can receive old or foreign receipts. Only the newest verified report for each planned worker counts.
    reports = self._node_operation_reports(operation, "deploy")
    for node in operation["nodes"]:
      report = reports.get(node, {})
      if report.get("status") != "stopped":
        return False
      # An empty signed report proves the worker fenced an absent attempt. Otherwise check its full instance set.
      if report.get("instances") != [] and not report_confirms_retirement(report, operation["instances"][node]):
        return False
    # Only the recovery state changes. The terminal reason, phase, and original unresolved addresses remain recorded.
    operation["recovery"] = "completed"
    self._save_operation(operation, message="All attempted workers later confirmed shutdown; cleanup is complete.")
    return True

  def _fail_deployment_rollout(self, operation, code, message):
    """Schedule cleanup of a deployment that cannot finish.

    Parameters
    ----------
    operation : dict
      Coordinator-owned rollout snapshot.
    code, message : str
      Sanitized public failure.

    Returns
    -------
    None
      Saves the failure and the next phase.

    Examples
    --------
    >>> plugin._fail_deployment_rollout(operation, "INSTANCE_FAILED", "A required instance failed.")  # doctest: +SKIP
    """
    operation.update(error=dict(code=code, message=message, retryable=False), recovery="in_progress",
                     recovery_started_at=self.time())
    self._save_operation(operation, "stopping_failed_rollout", "Cleaning up the failed rollout.")

  def _expire_deployment_preparation(self, operation,
                                     message="Deployment preparation did not complete; the running revision is unchanged."):
    """Record deadline failure before waiting for plan or secret cleanup.

    Marks the operation failed with the error ``ADMISSION_PREPARATION_FAILED`` (not retryable) and saves it in
    the "cleaning_up_preparation" phase, in which the worker asks dAuth to revoke whatever was staged.

    Parameters
    ----------
    operation : dict
      The coordinator's operation snapshot, in its "preparing" phase; replaced in place by the saved snapshot.
    message : str, optional
      The error's text. The default says that the preparation did not complete; admission passes the SDK's text
      of a secret record refused for its size.

    Returns
    -------
    None

    Raises
    ------
    RuntimeError
      When the replicated write of the snapshot is not confirmed (see ``_save_operation``).

    Examples
    --------
    >>> plugin._expire_deployment_preparation(operation)
    >>> operation["phase"], operation["error"]["code"]
    ('cleaning_up_preparation', 'ADMISSION_PREPARATION_FAILED')
    """
    operation.update(outcome="failed", recovery="in_progress", error=dict(
      code="ADMISSION_PREPARATION_FAILED",
      # The caller's text: a size refusal gets the SDK's text in place of "did not complete".
      message=message,
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
    """Commit canonical metadata after readiness or restoration evidence.

    Use one representative configuration for the canonical copy while
    retaining the operation's exact per-worker plan.

    Parameters
    ----------
    operation : dict
      Signed operation entering finalization.
    configs : dict
      Ready or restored configuration per node.

    Returns
    -------
    dict
      Authenticated custody result and any confirmed legacy rewrite notice.

    Notes
    -----
    Finalization records an affirmative rewrite notice on the completed
    operation after releasing unused secret revisions. This call leaves
    the notice in the returned custody result until that save is due.

    Examples
    --------
    >>> plugin._commit_operation_revision(operation, configs)  # doctest: +SKIP
    """
    # All active configurations share the canonical pipeline identity.
    representative = next(iter(configs.values()))
    # Forward the confirmed publication data while preserving the signed operation.
    return self.commit_deployment_revision(operation, representative)

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
    a completed one whose last update is less than 24 h old is handed to
    `_replicate_operation`, which re-sends the final snapshot as peer repair:
    at most every 30 s while the completion is less than 600 s old, as
    before, then each time its age reaches the next age of `REPAIR_AGES`:
    600, 1,200, 2,400 and 4,800 s after completion and every 3,600 s after
    that.

    The repair of completed operations exists because a write needs only one
    confirmation, so an oracle can miss the final snapshot and nothing else
    sent it again. That oracle kept showing the operation as running and
    refused new changes to the job. Peers that already hold the record do not
    save it again. Before, the repair stopped 600 s after completion, so an
    oracle away longer never got the final snapshot; now it gets it at the
    first send after it is back, within 1 h while the coordinator runs (an
    age that passes while the coordinator is down is skipped), up to the last
    send 84,000 s (about 23.3 h) after completion.

    After a failed dAuth custody call (`DeploymentCustodyError`) the operation
    is skipped for 10 s, then 20, 40 and so on, up to 300 s, counted from the
    failure. Before, it called the same dAuth server again on every 2 s pass,
    for ever, and kept that server's request thread busy. An operation still
    in the "preparing" phase is not paced: it asks dAuth on every pass until
    its preparation deadline (created + 120 s), as before, so a dAuth that
    recovers in the last seconds before the deadline still gets the
    deployment accepted. At the deadline it moves to cleanup, whose failed
    custody calls are paced. Any other failure, for example a chain-store
    write that was not confirmed, is tried again on the next pass, as before,
    except the final snapshot of an operation completed 600 s or more ago,
    tried again at the next age of its repair schedule. A pass of the
    operation without an error drops its wait.

    Parameters
    ----------
    None

    Returns
    -------
    None
      A failure on one operation is logged in red and the pass continues with
      the next one. The line names the operation, its job and phase, the type
      of the error and the functions it passed through (outermost first, cut
      to 300 characters); the error text is not logged because it can carry
      request values. After a failed custody call outside the "preparing"
      phase the line ends with "(custody failure N, next try in D s)".

    Notes
    -----
    Runs on the `deeploy-operations` thread every 2 s, or sooner when the
    wake-up event is set. Each operation is deep-copied before it is
    advanced, so the replica's records are not mutated in place.

    Ended paid creates can finish cleanup without resuming workload command
    dispatch. The worker checks verified stop receipts every 60 seconds
    and checks immediately after a pending custody revocation succeeds.

    The waits live in `_custody_retry`, which only this thread reads and
    writes. A waiting operation is skipped without any call, so the others are
    handled in the same pass. An entry is dropped when its operation has a
    pass without an error (it advanced, or it completed with either outcome)
    and, at the start of every pass, when its operation is no longer read
    from the replica.

    With the 2 s pass, a completed operation is re-sent 19 times in its first
    600 s, as before, then 26 more times, at the first pass at or after each
    age of `REPAIR_AGES` (once when a pass reaches several): 600, 1,200,
    2,400 and 4,800 s after completion, then every 3,600 s up to 84,000 s.
    Which ages were served is kept in process memory only
    (`_operations_repaired`). A pass in the first 600 s marks none served, so
    the 600 s age is sent also after a restart in that time. The first pass that
    sees the operation later, as after a restart, marks its current age as
    served without a send. So a restart 600 s or more after completion sends
    nothing at once, the next send falls on the operation's own next age (the
    sends stay spread as the completion times are), and restarts do not move
    that age; an age that passes while the process is down is skipped. A
    send that is not confirmed raises, one red line, while this process has
    not seen that snapshot confirmed: a final snapshot never confirmed is
    logged on every pass in its first 600 s, as before, then at each of its
    ages, before a restart and after it alike, and after a restart so is a
    confirmed one until a send of it is confirmed again.

    Examples
    --------
    >>> operation = plugin._save_operation(operation, "completed", "Deployment completed.")
    >>> plugin._reconcile_coordinator_operations()  # just confirmed: nothing is sent
    >>> plugin.now += 31
    >>> plugin._reconcile_coordinator_operations()  # 31 s: the last send is over 30 s old, the same record is sent
    >>> plugin.now += 1000
    >>> plugin._reconcile_coordinator_operations()  # 1,031 s: past the age 600 s, sent once
    >>> plugin.now += 100
    >>> plugin._reconcile_coordinator_operations()  # 1,131 s: the next age is 1,200 s, nothing is sent
    >>> plugin.now += 86400
    >>> plugin._reconcile_coordinator_operations()  # past 24 h: left alone

    With dAuth down, a cleanup operation calls it again only after the wait:

    >>> plugin._reconcile_coordinator_operations()  # custody failure 1, next try in 10 s
    >>> plugin.now += 2
    >>> plugin._reconcile_coordinator_operations()  # waiting: no dAuth call
    >>> plugin.now += 8
    >>> plugin._reconcile_coordinator_operations()  # custody failure 2, next try in 20 s

    A preparing operation asks dAuth again on the next pass:

    >>> plugin._reconcile_coordinator_operations()  # status failed, no wait
    >>> plugin.now += 2
    >>> plugin._reconcile_coordinator_operations()  # status answered "prepared": accepted
    """
    # Clear completed handoffs BEFORE reading snapshots. Admissions that finish
    # during that read keep their marker until the next pass, avoiding a stale
    # `preparing` snapshot racing the request's final `accepted` write.
    for operation_id, finished in self._deployment_preparations.copy().items():
      if finished.is_set():
        self._deployment_preparations.pop(operation_id)
    own = [copy.deepcopy(operation) for operation in self._operation_records(own_only=True).values()]
    # A single clock drives passive receipt checks, independent of command and custody retries.
    last = self._last_ended_create_cleanup_check
    now = self.time()
    check_ended_create_cleanup = last is None or not 0 <= now - last < ENDED_CREATE_CLEANUP_CHECK_SECONDS
    if check_ended_create_cleanup:
      self._last_ended_create_cleanup_check = now
    # Keep a custody wait only for an operation still read here, so one whose records are gone leaves no
    # entry behind and the map never holds more than this oracle's own operations.
    self._custody_retry = {operation["operation_id"]: self._custody_retry[operation["operation_id"]]
                           for operation in own if operation["operation_id"] in self._custody_retry}
    for operation in own:
      if operation["operation_id"] in self._deployment_preparations:
        continue
      # (failures in a row, time of the last one, seconds to wait) after a failed dAuth custody call, else None.
      pause = self._custody_retry.get(operation["operation_id"])
      if pause and 0 <= self.time() - pause[1] < pause[2]:
        # Do not call the same dAuth server again yet; only this operation waits, the pass goes on with the
        # next one. A clock step backwards ends the wait, as for the other throttles in this file.
        continue
      try:
        # Seconds since the operation's last snapshot; for a completed operation, since its completion.
        age = self.time() - operation["updated_at"]
        if operation["phase"] != "completed":
          # Unfinished operations are advanced as before; completed ones are no longer skipped outright but
          # get the repair re-send below.
          if operation.get("mutation") == "node_relink" and hasattr(self, "_reconcile_repair_parent"):
            self._advance_serialized_operation(operation)
          else:
            self._advance_deployment_operation(operation)
        elif operation.get("abandoned_deploy_revocation_pending"):
          # Retry only custody after a terminal failure. Workload commands never resume for the ended operation.
          self._deployment_secret_request("revoke", operation, active_attempt=None)
          operation.pop("abandoned_deploy_revocation_pending")
          # Authenticated stop receipts can arrive before custody responds. Check them immediately after release.
          if not self._confirm_ended_create_cleanup(operation):
            self._save_operation(operation)
        elif check_ended_create_cleanup and self._confirm_ended_create_cleanup(operation):
          # The new snapshot was replicated by the save; no further repair is due on this pass.
          continue
        # For 600 s after completion, oracles that missed the final snapshot get it too, as before.
        elif age < 600:
          # No age of REPAIR_AGES is served yet, also when this is the first pass after a restart: 600 s is sent.
          self._operations_repaired[operation["operation_id"]] = 0
          # Re-send the final snapshot as repair, throttled to once per 30 s, and on every pass while it is not
          # confirmed, as before; peers that already hold it do not save it again.
          self._replicate_operation(operation)
        # Up to 24 h after completion too; before, only for 600 s, so an oracle away longer never got the final
        # snapshot and kept showing the operation as running and refusing job changes.
        elif age < 86400:
          # How many ages of the repair schedule this age has reached: the point of the schedule it is at.
          point = bisect.bisect_right(REPAIR_AGES, age)
          # The point served last, in process memory only. The first pass that sees the operation 600 s or more after
          # completion (as after a restart) marks the current point as served without a send: a restart sends nothing at
          # once, and the next point stays fixed after completion whatever the restarts.
          if point > self._operations_repaired.setdefault(operation["operation_id"], point):
            # Served before the send, so a send that raises is not tried again before the next point either.
            self._operations_repaired[operation["operation_id"]] = point
            # Re-send the final snapshot as repair. With every=0 the schedule times the send, not the time since the
            # last one: at ages that double from 600 s up to 1 h apart, 26 more sends per completed operation.
            self._replicate_operation(operation, every=0)
        # A pass without an error ends the custody wait, so a later failed custody call waits 10 s again.
        self._custody_retry.pop(operation["operation_id"], None)
      except Exception as exc:
        # The functions the error passed through, outermost first, cut to 300 characters to bound the log line: on a
        # very deep path the innermost names (where the error was raised) are the ones cut. Before, one fixed line
        # ("waiting for storage or transport recovery") was logged for every error, so the log could not tell an
        # unconfirmed chain-store write from a dAuth custody call that failed, a plan that could not be read or a
        # command that could not be sent. Only names are logged, never the error text: it can carry request values.
        path = " > ".join(frame.name for frame in traceback.extract_tb(exc.__traceback__))[:300]
        # Any other error (a chain-store write, a plan read, a command) is tried again on the next pass, as before; the
        # final snapshot of an operation completed 600 s or more ago at the next age of its repair schedule.
        retry = ""
        # A preparing operation is not paced: it asks dAuth on every pass until its preparation deadline (created
        # + 120 s), as before, so a dAuth that recovers in the last seconds still gets the deployment accepted.
        # At the deadline it moves to cleanup, which has no deadline; the phase is read after the failed step.
        repair_conflict = operation.get("mutation") == "same_host_repair_v1" and isinstance(exc, DeploymentConflictError)
        if (isinstance(exc, DeploymentCustodyError) or repair_conflict) and deployment_operation_phase(operation) != "preparing":
          # Custody calls that failed in a row; a pass without an error resets the count (see above).
          failures = pause[0] + 1 if pause else 1
          # Wait 10 s after the first failure and double the wait after each further one, up to 300 s. Before,
          # the same dAuth server was called again on every 2 s pass and its request thread was kept busy.
          delay = min(10 * 2 ** min(failures - 1, 5), 300)
          # Kept in process memory only: after a restart the operation calls dAuth on the first pass.
          self._custody_retry[operation["operation_id"]] = (failures, self.time(), delay)
          # The red line says how many custody calls failed in a row and when the next one is made.
          retry = " ({} failure {}, next try in {} s)".format("repair placement" if repair_conflict else "custody", failures, delay)
        self.P("Deployment operation {} (job {}, phase {}) was not advanced and is tried again: {} in {}{}".format(
          operation["operation_id"], operation["job_id"], operation["phase"], type(exc).__name__, path, retry), color="r")

  def _deployment_operation_worker(self):
    """
    Advance this coordinator's operations in the background, independently of HTTP requests and UI polling.

    Runs on the `deeploy-operations` thread until the stop event is set: one pass of
    `_reconcile_coordinator_operations`, then a wait of 2 s or until the wake-up event is set.

    Returns
    -------
    None

    Notes
    -----
    An error that escapes a whole pass (the per-operation errors are caught inside the pass) is logged in
    red with its type and call path (cut to 300 characters), and the next pass runs as usual.

    Examples
    --------
    >>> threading.Thread(target=plugin._deployment_operation_worker, name="deeploy-operations").start()
    """
    while not self._deployment_operations_stop.is_set():
      try:
        self._reconcile_coordinator_operations()
      except Exception as exc:
        # As in the pass itself: the type of the error and the functions it passed through, not its text.
        # Before, one fixed line hid what failed. The path, outermost first, is cut to 300 characters to
        # bound the log line, so on a very deep path the innermost names are the ones cut.
        path = " > ".join(frame.name for frame in traceback.extract_tb(exc.__traceback__))[:300]
        self.P("Deployment operation pass failed and runs again in 2 s: {} in {}".format(
          type(exc).__name__, path), color="r")
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
      - "replacement_coordinator" (str, optional): adds a verified refusal
        to a request lookup scoped by job ID and update kind.
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
      and "revision". If the saved operation records an expired blocked
      phase, "blocked_phase" identifies that phase and "unconfirmed_nodes"
      lists the worker addresses missing the required evidence at expiry.
      Both fields preserve the terminal diagnosis even if later reports
      confirm a worker stopped or finish cleanup for a failed paid create.
      "credential_rotation_required" is present only on a completed
      operation whose saved record explicitly sets the flag to True after
      a confirmed protected rewrite.

      When nothing matches, a short answer has "status"
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

    Notes
    -----
    An unfinished operation reports "observation_stale" only when the
    snapshot is older than 30 seconds and its coordinator is offline for
    control. Snapshots change with durable state, so a healthy coordinator
    may serve the same snapshot throughout a long wait.

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
    records = self._operation_records(job_id=request.get("job_id"), operation_id=request.get("operation_id"))
    for record in records.values():
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
      # Only the owner's request lookup can return a stored refusal; missing replica state stays uncertain.
      coordinator = self._replacement_status_coordinator(request)
      if coordinator:
        refusal = self._load_replacement_refusal(owner, request["job_id"], request["request_id"], coordinator)
        if refusal:
          return {"status": "synchronizing", "job_id": request["job_id"], "non_admission": refusal["proof"]}
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
    phase = deployment_operation_phase(operation)
    # An ended phase keeps the report attempt that was relevant at the timeout, even on another oracle.
    observed_phase = operation.get("blocked_phase", phase)
    restoring = observed_phase in ("restoring_previous", "finalizing_recovery") or (
      "blocked_phase" not in operation and operation["outcome"] == "failed" and operation["kind"] == "update"
      and operation.get("mutation") != STATELESS_REPLACEMENT
      and (operation.get("error") or {}).get("code") != "ADMISSION_PREPARATION_FAILED"
    )
    attempt = "retire" if operation["kind"] == "delete" or observed_phase in ("retiring_previous", "waiting_for_capacity") else "restore" if restoring else "deploy"
    reports = self._node_operation_reports(operation, attempt)
    if attempt == "retire" and operation.get("mutation") == "same_host_repair_v1":
      # An already stopped worker owes no second STOP. Display the original signed receipt at its actual signer.
      parent_id = operation["repair_parent"]["operation_id"]
      parent = records.get(parent_id)
      if parent is None and request.get("operation_id"):
        parent = self._operation_records(job_id=operation["job_id"], operation_id=parent_id).get(parent_id)
      parent = parent or {}
      if (parent.get("repair_child") or {}).get("operation_id") == operation["operation_id"]:
        for node, receipt in self._node_operation_reports(parent, "retire").items():
          if report_confirms_retirement(receipt, operation["previous_instances"].get(node)):
            reports.setdefault(node, receipt)
    deployed_reports = self._node_operation_reports(operation, "deploy") if restoring else reports
    identities = operation["previous_instances"] if attempt != "deploy" else operation["instances"]
    configs = {node: {"PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": instance}]} for signature, instance in values]}
               for node, values in identities.items()}
    pins = operation.get("pinned_sources", {}).get(attempt, {})  # Polling never downloads the private plan.
    repair_restore = attempt == "restore" and operation.get("mutation") == "same_host_repair_v1"
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
      action = phase
      if operation["kind"] == "update" and action == "retiring_previous":
        # Only previous workers owe a retire report. A new target is waiting for that barrier.
        if node not in identities:
          action = "waiting_to_start"
        elif report.get("status") == "stopped":
          action = "stop_reported"  # Verified for this worker, revision and retirement attempt above.
        elif operation["coordinator"] == self.bc.address:
          action = "awaiting_stop_report"
        else:
          action = "stop_report_unavailable"  # A replica can lack a report its coordinator already has.
      nodes.append(dict(
        node_id=node, observed_revision=report.get("revision"),
        ready=node in configs and self._node_is_ready(
          node, report, configs[node], pins.get(node),
          restore_bindings=operation.get("retired_runtime", {}).get(node, {}) if repair_restore else None,
        ),
        # Replicas can learn later node snapshots after the operation itself has completed.
        report_attempt=report.get("attempt"), report_sequence=report.get("sequence"),
        workload_state=report.get("status", "unknown"),
        updated_at=updated_at, stale=report.get("status") != "stopped" and (
          updated_at is None or not self._netmon_node_is_online_for_control(node)),
        instances=instances, error=copy.deepcopy(report.get("error")),
        action=action,
      ))
    fields = ("operation_id", "request_id", "job_id", "app_id", "kind", "mutation", "sequence",
              "target_revision", "previous_revision", "phase", "outcome", "recovery",
              "coordinator", "created_at", "updated_at", "error")
    result = {key: copy.deepcopy(operation.get(key)) for key in fields}
    if phase == "completed" and operation.get("credential_rotation_required") is True:
      # Report the first legacy-copy migration only after its custody publication completed.
      result["credential_rotation_required"] = True
    if "unconfirmed_nodes" in operation:
      # The coordinator's terminal snapshot names the exact missing workers independently of replica report lag.
      result.update(unconfirmed_nodes=list(operation["unconfirmed_nodes"]), blocked_phase=operation["blocked_phase"])
    if operation.get("mutation") == "same_host_repair_v1":
      # The prior address remains available for audit; its successor alone occupies the paid slot.
      result["relinked_nodes"] = [{"previous": old, "current": current} for old, current in operation["repair_aliases"]]
      if phase != "completed" and operation.get("repair_block"):
        # Expose the current hold without overwriting the original rollout failure in the operation.
        result.update(recovery="blocked", error=copy.deepcopy(operation["repair_block"]))
    if operation.get("mutation") == STATELESS_REPLACEMENT:
      # Reusing an address resolves it only when the new workload has passed readiness and publication.
      taken_over = set(operation["nodes"]) if operation.get("outcome") == "succeeded" else set()
      result["unconfirmed_previous_nodes"] = [
        node for node in operation["unconfirmed_previous_nodes"] if node not in taken_over
      ]
    if operation.get("repair_child"):
      result["repair_child_operation_id"] = operation["repair_child"]["operation_id"]
    limit = request.get("events_limit", 64)
    if type(limit) is not int or not 1 <= limit <= 128:
      raise ValueError("events_limit must be between 1 and 128.")
    after = request.get("after_event_cursor", 0)
    if type(after) is not int or after < 0:
      raise ValueError("after_event_cursor must be a non-negative integer.")
    events = [event for event in operation["events"] if event["sequence"] > after]
    result.update(
      phase=phase, status=phase, nodes=nodes, target_nodes=len(configs),
      ready_nodes=sum(node["ready"] for node in nodes),
      # Snapshots now change only with state: an old one is stale only while its coordinator is away.
      observation_stale=operation["phase"] != "completed" and now - operation["updated_at"] > 30
        # With the coordinator online, an old snapshot only means nothing durable changed during a long
        # wait (snapshots are no longer rewritten per retry), so it is not reported as an outdated view.
        and not self._netmon_node_is_online_for_control(operation["coordinator"]),
      poll_after_ms=2000, events=events[:limit],
      next_event_cursor=events[limit - 1]["sequence"] if len(events) > limit else None,
      revision=operation["target_revision"] if operation["outcome"] in ("succeeded", "waiting_for_source") else operation["previous_revision"] or 0,
    )
    return result
