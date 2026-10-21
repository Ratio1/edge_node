"""dAuth custody for the receiving coordinator's existing deployment lifecycle."""
import copy
import hashlib

from .dauth_registry import dauth_registry_write_kwargs
from extensions.business.deeploy.deployment_operations import required_instances, SIGNATURE_KEYS


REVISIONS = "DAUTH_JOB_SECRET_REVISIONS"
CURRENT = "DAUTH_JOB_SECRETS"
POINTERS = "DEEPLOY_DEPLOYED_JOBS"
AUTH_FIELDS = SIGNATURE_KEYS | {"EE_ETH_SENDER", "EE_ETH_SIGN"}


class _DauthDeploymentSecretsMixin:
  """Prepare immutable secrets and publish only at lifecycle finalization."""

  def _deployment_secret_context(self, body, requester):
    """Authenticate an operation and its immutable, entirely redacted plan."""
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
    action, phase = body.get("action"), operation.get("phase")
    phases = {
      "prepare": {"preparing"}, "status": {"preparing"},
      "commit": {"finalizing", "finalizing_recovery"},
      "revoke": {"preparing", "stopping_failed_rollout", "finalizing", "finalizing_recovery", "retiring_previous"},
      "delete": {"retiring_previous"},
    }
    if action not in phases or phase not in phases[action]:
      raise ValueError("Secret action does not match the deployment phase.")
    if (operation.get("kind") == "delete") != (action == "delete" or (action == "revoke" and phase == "retiring_previous")):
      raise ValueError("Secret action does not match the deployment kind.")
    plan = self.r1fs.get_json(operation["plan_cid"], timeout=10, show_logs=False)
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
        if operation["kind"] != "delete" and specs.get("secret_revision") != operation_id + ":" + attempt:
          raise ValueError("Deployment secret reference is invalid.")
    # Repair before inspecting immutable values or revocation markers. A warm
    # local copy alone cannot prove that another custodian has not revoked it.
    for namespace in (REVISIONS, CURRENT, POINTERS, "DEEPLOY_OPERATIONS"):
      if not self.chainstore_hsync(hkey=namespace, timeout=5, **dauth_registry_write_kwargs(self)):
        raise RuntimeError("Deployment secret synchronization is unavailable.")
    for record in (self.chainstore_hgetall(hkey="DEEPLOY_OPERATIONS") or {}).values():
      if (isinstance(record, dict) and record.get("operation_id") == operation_id
          and record.get("coordinator") == requester and record.get("EE_SENDER") == requester
          and self.bc.verify(record, return_full_info=True, log_hash_sign_fails=False).valid
          and record.get("sequence", 0) > operation.get("sequence", 0)):
        raise RuntimeError("A newer deployment operation snapshot is available.")
    return job_id, operation, plan

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
    """Reconcile target and restoration copies without changing the active CID."""
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
      else:
        prior_bundle = self._load_current_dauth_secret_bundle(job_id, prior_cid, prior_pipeline, require_unversioned=True)
    elif prior_cid:
      raise ValueError("A create cannot replace an active pipeline.")
    aliases = {tuple(current): tuple(source) for current, source in body.get("identity_aliases", [])}
    records = []
    for attempt, key, fragments in (
      ("restore", "previous_configs", body.get("previous_new_secrets")),
      ("deploy", "configs", body.get("new_secrets")),
    ):
      configs = plan[key]
      if not configs:
        continue
      reference = operation["operation_id"] + ":" + attempt
      bundle = dict(job_id=job_id, job_secrets={})
      prior_configs = (prior_bundle or {}).get("pipelines", plan["previous_configs"])
      for node, config in configs.items():
        node_bundle = self._build_complete_dauth_job_secret_bundle(
          job_id, config, fragments,
          prior_bundle=prior_bundle, prior_pipeline=prior_configs.get(node, prior_pipeline),
          current_identity_aliases=aliases if attempt == "deploy" else None,
        )
        bundle["job_secrets"] = self._merge_deeploy_dauth_secret_fragments(
          bundle["job_secrets"], node_bundle["job_secrets"], reject_conflicts=True,
        )
      record = dict(bundle, revision=reference, pipelines=copy.deepcopy(configs))
      existing = self._deployment_secret_record(job_id, reference)
      if existing is not None and existing != record:
        raise ValueError("An immutable secret revision cannot be replaced.")
      records.append((reference, record))
    # Validate both copies before staging either. A partial replication can still
    # need recovery, but invalid target placeholders must not create an orphan.
    for reference, record in records:
      if not self.chainstore_hset(hkey=REVISIONS, key=job_id + "|" + reference, value=record,
                                  **dauth_registry_write_kwargs(self)):
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
      if record is None or record.get("pipelines") != configs:
        return False
      records.append((reference, record))
    for reference, record in records:
      if not self.chainstore_hset(hkey=REVISIONS, key=job_id + "|" + reference, value=record,
                                  **dauth_registry_write_kwargs(self)):
        raise RuntimeError("Deployment secret replication is pending.")
    return True

  def _publish_deployment_secrets(self, job_id, operation, plan, pointer, deleted=False):
    """Bind custodied secrets to a verified coordinator-signed final pointer."""
    if not isinstance(pointer, dict):
      raise ValueError("A signed deployment publication pointer is required.")
    expected = dict(job_id=job_id, revision=operation["target_revision"],
                    operation_id=operation["operation_id"], coordinator=operation["coordinator"],
                    deleted=deleted, pipeline_cid=None if deleted else pointer.get("pipeline_cid"))
    if ({key: value for key, value in pointer.items() if key not in AUTH_FIELDS} != expected
        or pointer.get("EE_SENDER") != operation["coordinator"]
        or not self.bc.verify(pointer, return_full_info=True, log_hash_sign_fails=False).valid):
      raise ValueError("Invalid deployment publication pointer.")
    current = self.chainstore_hget(hkey=POINTERS, key=job_id)
    current_fields = {key: value for key, value in current.items() if key not in AUTH_FIELDS} if isinstance(current, dict) else current
    already_published = current_fields == expected
    if not already_published and (
      (isinstance(current, dict) and current.get("revision", 0) >= operation["target_revision"])
      or self._load_dauth_pipeline_cid(job_id) != operation.get("previous_pipeline_cid")
    ):
      raise ValueError("Deployment publication has been superseded.")
    if deleted:
      self._revoke_deployment_secret_revisions(job_id, operation, plan, None)
      bundle = dict(job_id=job_id, job_secrets={})
    else:
      configs = plan["previous_configs" if operation["phase"] == "finalizing_recovery" else "configs"]
      representative = copy.deepcopy(next(iter(configs.values())))
      representative.pop("DEEPLOY_OPERATION", None)
      canonical = self._recursively_sort_pipeline_data(self.extract_invariable_data_from_pipeline(representative))
      published = self.r1fs.get_json(pointer["pipeline_cid"], timeout=10, show_logs=False)
      if published is None:
        raise RuntimeError("Published deployment configuration is unavailable.")
      if published != canonical:
        raise ValueError("Published configuration does not match the operation plan.")
      reference = representative["DEEPLOY_SPECS"]["secret_revision"]
      record = self._deployment_secret_record(job_id, reference)
      if record is None or record.get("pipelines") != configs:
        raise RuntimeError("Active deployment secrets are unavailable.")
      bundle = {key: copy.deepcopy(value) for key, value in record.items() if key != "pipelines"}
    bundle.update(job_id=job_id, deployment_revision=operation["target_revision"],
                  operation_id=operation["operation_id"], coordinator=operation["coordinator"],
                  deleted=deleted, pipeline_cid=pointer["pipeline_cid"])
    self.bc.sign(bundle, add_data=True, use_digest=True)
    if not self._write_dauth_job_secret_bundle(job_id, bundle):
      raise RuntimeError("Deployment secret publication is pending.")
    if not self._write_job_pipeline_cid(job_id, pointer):
      raise RuntimeError("Deployment metadata publication is pending.")
    previous_cid = operation.get("previous_pipeline_cid")
    if previous_cid and previous_cid != pointer["pipeline_cid"]:
      self._delete_pipeline_cid_from_r1fs(previous_cid)

  def _revoke_deployment_secret_revisions(self, job_id, operation, plan, active_attempt):
    """Erase only operation-derived unused references after lifecycle barriers."""
    phase = operation["phase"]
    expected_active = {"finalizing": "deploy", "finalizing_recovery": "restore"}.get(phase)
    if active_attempt != expected_active or (
      phase == "preparing" and self.time() < operation["preparation_deadline"]
    ) or (phase == "stopping_failed_rollout" and operation["kind"] != "create"):
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
      published = self.r1fs.get_json(pointer["pipeline_cid"], timeout=10, show_logs=False)
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
          references.append(operation["operation_id"] + ":" + attempt)
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
    if action == "prepare":
      self._prepare_deployment_secret_revisions(job_id, operation, plan, body)
      result["prepared"] = True
    elif action == "status":
      result["prepared"] = self._deployment_secrets_prepared(job_id, operation, plan)
    elif action == "revoke":
      self._revoke_deployment_secret_revisions(job_id, operation, plan, body.get("active_attempt"))
    else:
      self._publish_deployment_secrets(job_id, operation, plan, body.get("pointer"), deleted=action == "delete")
      result["pipeline_cid"] = body["pointer"]["pipeline_cid"]
    return result
