"""Signed dAuth staging receipts for a protocol-oracle deployment coordinator."""
from ratio1.bc.base import compact_canonical_sha256
from ratio1.const.base import dAuth
from requests import RequestException


class _DeeployDauthUpdatesMixin:
  def _request_dauth_pipeline_update(self, payload):
    body = {**payload, "nonce": hex(int(self.time() * 1000))}
    self.bc.sign(body)
    network = self.bc.get_evm_network()
    url = self.bc.get_network_data(network)[dAuth.EvmNetData.DAUTH_URL_KEY]
    for attempt in range(2):
      try:
        response = self.requests.post(
          url.replace("/get_auth_data", "/stage_job_update"),
          json={"body": body}, timeout=(10, 60),
        )
        break
      except RequestException:
        if attempt:
          raise RuntimeError("dAuth update transport could not be confirmed.") from None
        body["nonce"] = hex(int(self.time() * 1000))
        self.bc.sign(body)
    if response.status_code != 200:
      raise RuntimeError("dAuth update staging service is unavailable.")
    try:
      result = response.json().get("result")
    except (ValueError, TypeError, AttributeError):
      raise ValueError("Invalid dAuth update response.") from None
    if not isinstance(result, dict):
      raise ValueError("Invalid dAuth update response.")
    verified = self.bc.verify(result, return_full_info=True)
    if not verified.valid:
      raise ValueError("Invalid dAuth update response signature.")
    signer_eth = self.bc.node_address_to_eth_address(verified.sender)
    if not self.bc.is_dauth_oracle(node_address_eth=signer_eth):
      raise ValueError("Unauthorized dAuth update response signer.")
    if result.get("nonce") != body["nonce"]:
      raise ValueError("dAuth update response nonce mismatch.")
    if result.get("status") != "success" or result.get("error"):
      raise RuntimeError("dAuth rejected the update staging operation.")
    return result

  def _stage_dauth_pipeline_update(self, wallet_request, pipeline_configs):
    job_id = str(wallet_request["job_id"])
    prior_cid = self._get_pipeline_from_cstore(job_id)
    result = self._request_dauth_pipeline_update({
      "action": "stage", "wallet_request": self.deepcopy(wallet_request),
      "expected_pipeline_cid": prior_cid, "pipeline_configs": pipeline_configs,
    })
    receipt = result.get("receipt")
    configs = result.get("pipeline_configs")
    operation_id = compact_canonical_sha256({"coordinator": self.bc.address, "wallet_request": wallet_request})
    if not isinstance(receipt, dict) or (
      receipt.get("operation_id") != operation_id
      or receipt.get("coordinator") != self.bc.address
      or receipt.get("job_id") != job_id
      or receipt.get("app_id") != wallet_request.get("app_id")
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
      result = self._request_dauth_pipeline_update({"action": action, "receipt": receipt})
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
