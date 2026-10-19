"""Signed dAuth staging receipts for a protocol-oracle deployment coordinator."""
from ratio1.bc.base import compact_canonical_sha256


class _DeeployDauthUpdatesMixin:
  def _stage_dauth_pipeline_update(
    self, wallet_request, pipeline_configs, request_type="update pipeline",
    new_nodes=None, current_identity_aliases=None,
  ):
    job_id = str(wallet_request["job_id"])
    prior_cid = self._get_pipeline_from_cstore(job_id)
    result = self.bc.request_dauth_job_update({
      "action": "stage", "wallet_request": self.deepcopy(wallet_request),
      "expected_pipeline_cid": prior_cid, "pipeline_configs": pipeline_configs,
      "request_type": request_type, "new_nodes": list(new_nodes or []),
      "identity_aliases": [
        [signature, instance_id, source_id]
        for (signature, instance_id), (_, source_id) in (current_identity_aliases or {}).items()
      ],
    })
    receipt = result.get("receipt")
    configs = result.get("pipeline_configs")
    operation_id = compact_canonical_sha256({
      "coordinator": self.bc.address, "wallet_request": wallet_request, "request_type": request_type,
    })
    representative = next(iter(pipeline_configs.values()))
    if not isinstance(receipt, dict) or (
      receipt.get("operation_id") != operation_id
      or receipt.get("coordinator") != self.bc.address
      or receipt.get("job_id") != job_id
      or receipt.get("request_type") != request_type
      or receipt.get("app_id") != representative.get("NAME")
      or receipt.get("owner") != representative.get("OWNER")
      or receipt.get("target_nodes") != representative.get("DEEPLOY_SPECS", {}).get("current_target_nodes")
      or receipt.get("prior_cid") != prior_cid
      or receipt.get("phase") not in ("staged", "committed")
      or not receipt.get("staged_cid")
    ):
      raise ValueError("dAuth staging receipt does not match the update.")
    if not isinstance(configs, dict) or set(configs) != set(pipeline_configs):
      raise ValueError("dAuth returned unexpected deployment targets.")
    if compact_canonical_sha256(configs) != receipt.get("plan_hash"):
      raise ValueError("dAuth staging plan digest mismatch.")
    for pipeline in configs.values():
      _, exposed_secrets = self._extract_and_redact_deeploy_dauth_secrets(pipeline)
      if exposed_secrets is not None:
        raise ValueError("dAuth staging response contains unredacted secrets.")
    return configs, {"dauth_update": True, **receipt}

  def _settle_dauth_pipeline_update(self, state, action):
    receipt = {key: value for key, value in state.items() if key not in (
      "dauth_update", "dispatch_attempted", "dispatch_uncertain", "retain_on_failed_dispatch",
    )}
    try:
      result = self.bc.request_dauth_job_update({"action": action, "receipt": receipt})
      returned = result.get("receipt", {})
      terminal = "committed" if action == "commit" else "rolled_back"
      if returned.get("phase") != terminal or any(
        returned.get(key) != value for key, value in receipt.items() if key != "phase"
      ):
        raise ValueError("dAuth settlement receipt mismatch.")
      return True
    except Exception:
      # Preserve the staged generation on uncertain settlement. Do not log the
      # signed request or transport exception, which may contain credentials.
      self.P("dAuth update settlement could not be confirmed; its generation is retained.", color='y')
      return False
