"""Forward signed Deeploy repairs to the oracle that owns the blocked deployment."""

import json
import time
from uuid import uuid4


_RELAY_KEY = "DEEPLOY_REPAIR_RELAY_V1"
_RELAY_TIMEOUT = 45
_RELAY_MAX_PENDING = 32
_RELAY_MAX_PER_TICK = 32
_RELAY_REQUEST_BYTES = 256 * 1024


class _RepairRelayMixin:
  """Deliver a repair and its reply over the existing encrypted admin listener."""

  def _forward_job_repair(self, request, owner, method):
    # These entry points have already checked the signed wallet request and escrow.
    proposal = request["repair"]["proposal"] if method == "update" else request
    coordinator = proposal.get("coordinator")
    parent_id = (proposal.get("parent") or {}).get("operation_id") if method == "update" else None
    replacing = method == "update" and request["repair"].get("replace_stateless") is True
    if not isinstance(coordinator, str) or (method == "update" and not replacing and not isinstance(parent_id, str)):
      return None
    # A signed operation determines the destination. Retried updates can name a parent already superseded.
    matches = [record for record in self._operation_records().values()
               if record["coordinator"] == coordinator and str(record["job_id"]) == str(request["job_id"])
               and record["owner"].lower() == owner.lower() and record.get("mutation") == "node_relink"
               and (record["operation_id"] == parent_id if method == "update"
                    else record["phase"] == "retiring_previous")]
    if replacing and parent_id is None:
      # An exact retry may be looking up an already admitted replacement. Match only the verified owner and job.
      admitted = [record for record in self._operation_records().values()
                  if record["coordinator"] == coordinator and record.get("request_id") == request.get("request_id")
                  and str(record["job_id"]) == str(request["job_id"]) and record["owner"].lower() == owner.lower()]
      if not admitted and self._stateless_replacement_proposal(request["job_id"], owner)[0] != proposal:
        return None  # A forwarded request without a parent must name the current reviewed admission owner.
    elif len(matches) != 1:
      return None
    if not self._is_repair_relay_oracle(coordinator):  # A custody-only peer cannot receive the wallet envelope or its token.
      return None
    if len(json.dumps(request, ensure_ascii=False).encode()) > _RELAY_REQUEST_BYTES:
      raise ValueError("The signed repair is too large to forward.")
    # Never cache a wallet payload or credentials in the relay's pending state.
    now = time.monotonic()
    for relay_id, pending in list(self._repair_relay_pending.items()):
      if pending["deadline"] <= now:
        del self._repair_relay_pending[relay_id]
    if len(self._repair_relay_pending) >= _RELAY_MAX_PENDING:
      return self._repair_relay_unavailable(method)
    relay_id = uuid4().hex
    self._repair_relay_pending[relay_id] = {"coordinator": coordinator, "deadline": now + _RELAY_TIMEOUT}
    try:
      self.send_encrypted_payload(node_addr=coordinator, **{_RELAY_KEY: {
        "id": relay_id, "method": method, "valid_until": int(self.time()) + _RELAY_TIMEOUT, "request": request,
      }})
    except Exception:
      self._repair_relay_pending.pop(relay_id, None)  # A send failure may occur after enqueueing.
      return self._repair_relay_unavailable(method)
    return self.create_postponed_request(self._wait_job_repair_reply, {"relay_id": relay_id, "method": method})

  def _repair_relay_unavailable(self, method):
    if method == "preview":
      return self._get_response({"status": "blocked", "reason": "The repair coordinator did not respond. Try Review repair again."})
    # The client treats a retryable 503 as uncertain and keeps the original signed request ID.
    return self._get_response({"status_code": 503, "status": "error", "error": {
      "code": "ADMISSION_UNAVAILABLE", "message": "Repair acceptance is uncertain. Retry with the same request_id.",
      "retryable": True,
    }})

  def _wait_job_repair_reply(self, relay_id, method):
    # Postpone on the FastAPI loop so other HTTP requests and incoming peer messages can advance.
    pending = self._repair_relay_pending.get(relay_id)
    if pending is None or pending["deadline"] <= time.monotonic():
      self._repair_relay_pending.pop(relay_id, None)
      return self._repair_relay_unavailable(method)
    if "result" in pending:
      del self._repair_relay_pending[relay_id]
      return pending["result"]
    return self.create_postponed_request(self._wait_job_repair_reply, {"relay_id": relay_id, "method": method})

  def _process_job_repair_relay(self):
    fields = self.const.PAYLOAD_DATA  # Use the actual Core wire keys, including EE_DEST.
    registered = None
    examined = 0
    for payload in self.dataapi_struct_datas(as_list=True):
      if not isinstance(payload, dict) or payload.get(fields.EE_IS_ENCRYPTED) is not True:
        continue
      path = payload.get(fields.EE_PAYLOAD_PATH)
      if not isinstance(path, list) or len(path) != 4 or str(path[2]).upper() != "DEEPLOY_MANAGER_API":
        continue
      ciphertext = payload.get(fields.EE_ENCRYPTED_DATA)
      if (payload.get(fields.EE_DESTINATION) != self.bc.address or not isinstance(ciphertext, str)
          or len(ciphertext) > 2 * _RELAY_REQUEST_BYTES):
        continue
      if examined >= _RELAY_MAX_PER_TICK:
        break  # Leave the Deeploy process time for other admin work.
      examined += 1
      if registered is None:
        try:
          registered = {address.lower() for address in self.bc.get_eth_oracles()}
        except Exception:
          self.P("Could not authenticate Deeploy repair relay peers.", color="y")
          return  # An unavailable registry cannot authorize any relay message in this batch.
      try:
        self._handle_job_repair_peer(payload, registered=registered)
      except Exception:
        # Never log incoming payloads, decrypted data, or exception text that could echo them.
        self.P("Could not process a Deeploy repair relay message.", color="y")

  def _is_repair_relay_oracle(self, node, registered=None):
    # Resolve the address directly from its public key, independently of the local heartbeat roster.
    if not isinstance(node, str):
      return False
    try:
      eth_address = self.bc.node_address_to_eth_address(node).lower()
      roster = registered if registered is not None else {address.lower() for address in self.bc.get_eth_oracles()}
      return eth_address in roster
    except (AttributeError, TypeError, ValueError):
      return False

  def _handle_job_repair_peer(self, payload, registered=None):
    sender = payload.get(self.const.PAYLOAD_DATA.EE_SENDER)
    if not self._is_repair_relay_oracle(sender, registered) or not self.bc.verify(payload, return_full_info=True).valid:
      return
    message = self.receive_and_decrypt_payload(payload).get(_RELAY_KEY)
    if not isinstance(message, dict) or not isinstance(message.get("id"), str) or len(message["id"]) != 32:
      return
    relay_id, method = message["id"], message.get("method")
    if method == "reply":
      pending = self._repair_relay_pending.get(relay_id)
      result = message.get("result")
      if (pending and pending["coordinator"] == sender and pending["deadline"] > time.monotonic()
          and "result" not in pending and isinstance(result, dict)):
        pending["result"] = result  # Preserve the original coordinator's signed API response.
      return
    valid_until, request = message.get("valid_until"), message.get("request")
    if type(valid_until) is not int or not 0 < valid_until - self.time() <= 2 * _RELAY_TIMEOUT or not isinstance(request, dict):
      return
    # Accept only requests naming this receiver. The local public handlers reverify the wallet and job authorization.
    if method == "preview" and request.get("coordinator") == self.bc.address:
      result = self.get_job_repair_preview(request)
    elif method == "update" and isinstance(request.get("repair"), dict):
      proposal = request["repair"].get("proposal")
      if not isinstance(proposal, dict) or proposal.get("coordinator") != self.bc.address:
        return
      result = self.repair_update_pipeline(request)
    else:
      return
    self.send_encrypted_payload(node_addr=sender, **{_RELAY_KEY: {"id": relay_id, "method": "reply", "result": result}})
