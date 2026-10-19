"""Custodian-side staging for updates coordinated by trusted protocol oracles.

The wallet authorizes the update; the protocol oracle remains responsible for
its prepared plan, as it is for the existing add_secrets write contract. Old
secret values and rollback state never leave the dAuth registry.
"""
from ratio1.bc.base import compact_canonical_sha256

from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.deeploy_job_mixin import _DeeployJobMixin
from .dauth_registry import DAUTH_JOB_UPDATES_HKEY, dauth_registry_write_kwargs, save_job_secret_generation


class _DauthJobUpdatesMixin(_DeeployMixin, _DeeployJobMixin):
  def _save_dauth_update(self, operation_id, operation):
    if not self.chainstore_hset(
      hkey=DAUTH_JOB_UPDATES_HKEY, key=operation_id, value=operation,
      **dauth_registry_write_kwargs(self),
    ):
      raise ValueError("Failed to persist dAuth update operation.")

  def _dauth_update_receipt(self, operation):
    return {
      key: operation[key] for key in (
        "operation_id", "coordinator", "job_id", "app_id", "owner",
        "prior_cid", "staged_cid", "plan_hash", "phase",
      )
    }

  def process_dauth_job_update(self, body):
    coordinator, coordinator_eth = self._verify_signed_dauth_body(body)
    nonce = self._validate_dauth_secret_request_nonce(body)
    if not self._is_protocol_oracle_eth(coordinator_eth):
      raise ValueError("Only protocol oracles may coordinate dAuth updates.")
    action = body.get("action")
    if action not in ("stage", "commit", "rollback"):
      raise ValueError("Invalid dAuth update action.")
    if action != "stage":
      receipt = body.get("receipt")
      if not isinstance(receipt, dict):
        raise ValueError("Missing dAuth update receipt.")
      operation_id = receipt.get("operation_id")
      operation = self.chainstore_hget(hkey=DAUTH_JOB_UPDATES_HKEY, key=operation_id)
      if not isinstance(operation, dict) or operation.get("coordinator") != coordinator:
        raise ValueError("Unknown dAuth update or coordinator.")
      expected = self._dauth_update_receipt(operation)
      if any(receipt.get(key) != value for key, value in expected.items() if key != "phase"):
        raise ValueError("dAuth update receipt does not match the stored operation.")
      terminal = "committed" if action == "commit" else "rolled_back"
      if operation["phase"] == terminal:
        return {"status": "success", "nonce": nonce, "receipt": expected}
      intent = "committing" if action == "commit" else "rolling_back"
      if operation["phase"] not in ("staged", intent):
        raise ValueError("dAuth update has already been settled differently.")
      state = operation["state"]
      operation["phase"] = intent
      self._save_dauth_update(operation_id, operation)
      settle = (
        self.commit_staged_job_pipeline_and_secrets if action == "commit"
        else self.rollback_staged_job_pipeline_and_secrets
      )
      already_restored = (
        action == "rollback"
        and self._get_pipeline_from_cstore(operation["job_id"]) == state["prior_cid"]
        and self._load_dauth_job_secret_bundle(operation["job_id"]) == state["prior_bundle"]
        and self.chainstore_hget(hkey="DAUTH_JOB_SECRETS", key=operation["job_id"]) == state["prior_bundle"]
      )
      # A previous rollback may have restored the pointer before its legacy
      # compatibility write failed. Finish only that exact partial restoration.
      if (
        action == "rollback" and not already_restored
        and self._get_pipeline_from_cstore(operation["job_id"]) == state["prior_cid"]
        and (state["prior_bundle"] is None or self._load_dauth_job_secret_bundle(operation["job_id"]) == state["prior_bundle"])
        and self.chainstore_hget(hkey="DAUTH_JOB_SECRETS", key=operation["job_id"]) == state["staged_bundle"]
      ):
        already_restored = self._write_dauth_job_secret_bundle(operation["job_id"], state["prior_bundle"])
      if not already_restored and not settle(state):
        raise ValueError("dAuth update generation changed before settlement.")
      operation["phase"] = terminal
      operation.pop("state", None)
      self._save_dauth_update(operation_id, operation)
      return {"status": "success", "nonce": nonce, "receipt": self._dauth_update_receipt(operation)}

    wallet_request = body.get("wallet_request")
    if not isinstance(wallet_request, dict):
      raise ValueError("Missing signed wallet update request.")
    sender, inputs = self.deeploy_verify_and_get_inputs(wallet_request, request_type="update pipeline")
    auth = self.deeploy_get_auth_result(inputs)
    owner = auth["escrow_owner"]
    escrow = self.bc.get_user_escrow_details(sender)
    if not isinstance(escrow, dict) or not escrow.get("isActive"):
      raise ValueError("Update sender has no active escrow.")
    if str(escrow.get("escrowOwner", "")).lower() != str(owner).lower():
      raise ValueError("Update escrow owner mismatch.")
    if sender.lower() != str(owner).lower() and not (int(escrow.get("permissions", 0)) & 1):
      raise ValueError("Update sender lacks deployment permission.")
    job_id = self._normalize_dauth_job_id(inputs.get("job_id"))
    app_id = inputs.get("app_id")
    expected_cid = body.get("expected_pipeline_cid")
    if not isinstance(app_id, str) or not app_id or not isinstance(expected_cid, str) or not expected_cid:
      raise ValueError("Update app identity and previous generation are required.")
    operation_id = compact_canonical_sha256({"coordinator": coordinator, "wallet_request": wallet_request})
    configs = body.get("pipeline_configs")
    if not isinstance(configs, dict) or not configs:
      raise ValueError("Prepared update pipeline configs are required.")
    request_hash = compact_canonical_sha256({
      "wallet_request": wallet_request, "pipeline_configs": configs,
      "expected_pipeline_cid": expected_cid,
    })
    operation = self.chainstore_hget(hkey=DAUTH_JOB_UPDATES_HKEY, key=operation_id)
    if operation is not None:
      if operation.get("request_hash") != request_hash:
        raise ValueError("dAuth update retry changed the authorized operation.")
      if operation["phase"] == "rolled_back":
        raise ValueError("dAuth update was rolled back; submit a new update.")
    else:
      pipeline_cid, prior_pipeline = self._load_dauth_job_pipeline_record(job_id)
      if pipeline_cid != expected_cid or not isinstance(prior_pipeline, dict):
        raise ValueError("Persisted pipeline generation changed before dAuth staging.")
      if prior_pipeline.get("NAME") != app_id or str(prior_pipeline.get("OWNER", "")).lower() != str(owner).lower():
        raise ValueError("Update does not own the persisted app.")
      job = self.bc.get_job_details(job_id=int(job_id))
      if not isinstance(job, dict) or str(job.get("escrowOwner", "")).lower() != str(owner).lower():
        raise ValueError("Update does not own the on-chain job.")
      for pipeline in configs.values():
        if not isinstance(pipeline, dict):
          raise ValueError("Invalid prepared pipeline config.")
        specs = pipeline.get("DEEPLOY_SPECS", {})
        if (
          pipeline.get("NAME") != app_id
          or str(pipeline.get("OWNER", "")).lower() != str(owner).lower()
          or str(specs.get("job_id")) != job_id
          or set(specs.get("current_target_nodes") or []) != set(configs)
        ):
          raise ValueError("Prepared pipeline deployment identity mismatch.")
      prior_bundle = self._load_dauth_job_secret_bundle(job_id)
      if prior_bundle is not None:
        prior_bundle = self._load_current_dauth_secret_bundle(job_id, pipeline_cid, prior_pipeline)
      redacted, bundle = self._redact_pipeline_configs_and_build_secret_bundle(
        job_id, configs, prior_bundle, prior_pipeline=prior_pipeline,
      )
      operation = {
        "operation_id": operation_id, "request_hash": request_hash,
        "coordinator": coordinator, "job_id": job_id, "app_id": app_id,
        "owner": owner, "prior_cid": expected_cid,
        "plan_hash": compact_canonical_sha256(redacted),
        "pipeline_configs": redacted, "phase": "prepared",
      }
      def before_publish(state):
        operation["staged_cid"] = state["staged_cid"]
        operation["state"] = self.deepcopy(state)
        self._save_dauth_update(operation_id, operation)
      if self._get_pipeline_from_cstore(job_id) != expected_cid:
        raise ValueError("Persisted pipeline changed while preparing dAuth update.")
      state = self.stage_job_pipeline_and_secrets(
        next(iter(redacted.values())), job_id, bundle, before_publish=before_publish,
      )
      operation["state"] = state
      operation["phase"] = "staged"
      self._save_dauth_update(operation_id, operation)

    if operation["phase"] == "prepared":
      state = operation["state"]
      if self._get_pipeline_from_cstore(job_id) not in (expected_cid, state["staged_cid"]):
        raise ValueError("A newer generation superseded the interrupted update.")
      canonical = self._recursively_sort_pipeline_data(self.extract_invariable_data_from_pipeline(
        next(iter(operation["pipeline_configs"].values())),
      ))
      if self._save_pipeline_to_r1fs(canonical) != state["staged_cid"]:
        raise ValueError("Interrupted dAuth update payload could not be restored.")
      save_job_secret_generation(self, job_id, state["prior_bundle"])
      if not self._write_dauth_job_secret_bundle(job_id, state["staged_bundle"]):
        raise ValueError("Failed to resume dAuth secret staging.")
      if not self._write_job_pipeline_cid(job_id, state["staged_cid"]):
        raise ValueError("Failed to resume dAuth pipeline staging.")
      state["bundle_staged"] = state["pipeline_staged"] = True
      operation["phase"] = "staged"
      self._save_dauth_update(operation_id, operation)
    if operation["phase"] not in ("staged", "committed"):
      raise ValueError("dAuth update settlement is in progress.")
    if operation["phase"] == "staged" and self._get_pipeline_from_cstore(job_id) != operation["staged_cid"]:
      raise ValueError("A newer generation superseded the staged update.")
    return {
      "status": "success", "nonce": nonce,
      "receipt": self._dauth_update_receipt(operation),
      "pipeline_configs": self.deepcopy(operation["pipeline_configs"]),
    }
