"""RM-141: Demo jobs attested on Base Sepolia, on behalf of the Navigator.

The Navigator's Demo has no node and no wallet; it calls these two endpoints through its one Demo
exit (`lib/demo/edgeBridge.ts`) with the backend token. The edge signs with the node key, pays with
the `DEMO.ATTESTATION` wallet and sends on that block's `NETWORK`, never the live block or the
node's own network. It never reads a Demo job record: the caller passes the few fields that go on
chain, and only a `demo-` job id is accepted.

Endpoints run on the plugin thread, so a submit is handed to one worker thread and answered through
a postponed request. The single worker serialises Demo submits; the SDK takes the nonce from the
latest block without waiting for mining, so the worker leaves `SETTLE_SECONDS` between two sends.
"""

import hashlib
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from ..constants import RUN_MODE_CONTINUOUS_MONITORING
from .config import get_attestation_config, get_demo_attestation_config

DEMO_JOB_PREFIX = "demo-"
DEMO_ATTESTATION_NETWORK_LABEL = "base-sepolia"
DEMO_ATTESTATION_EVENTS = {
  "start": "submitRedmeshJobStartAttestation",
  "complete": "submitRedmeshTestAttestation",
}
# The registry reverts a score above 100 (`InvalidVulnerabilityScore`).
MAX_VULNERABILITY_SCORE = 100
MAX_NODE_COUNT = 0xFFFF
MAX_PENDING = 32
# Under the Navigator's 60 s timeout, so the caller always gets an answer; no send starts after it.
DEADLINE_SECONDS = 45.0
ZERO_NODE_HASHES = "0x" + ("00" * 32)
_RFC5737_NETWORKS = tuple(
  ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def _error(status_code, error_class, message):
  return {"status": "error", "status_code": status_code, "error_class": error_class, "message": message}


def demo_execution_id(job_id):
  """The 8 ASCII characters that stand for a Demo job on chain: a prefix of its sha256."""
  return hashlib.sha256(job_id.encode("utf-8")).hexdigest()[:8]


def _pack_demo_target(owner, target):
  """Pack an RFC 5737 documentation IPv4 address as the live path does; anything else is `0x0000`."""
  host = owner._attestation_extract_host(target)
  try:
    address = ipaddress.ip_address(host)
  except (TypeError, ValueError):
    return "0x0000"
  if address.version != 4 or not any(address in net for net in _RFC5737_NETWORKS):
    return "0x0000"
  return owner._attestation_pack_ip_obfuscated(str(address))


def _bounded_int(value, maximum):
  try:
    number = int(round(float(value)))
  except (TypeError, ValueError):
    return 0
  return min(max(number, 0), maximum)


def _normalize_tx_hash(tx_hash):
  # The SDK answers `HexBytes.hex()`, which has no `0x` with hexbytes >= 1.0.
  tx_hash = str(tx_hash).strip().lower()
  return tx_hash if tx_hash.startswith("0x") else "0x" + tx_hash


def _classify_submit_error(exc):
  # Only a class leaves the edge: the RPC body and the key never do.
  if "insufficient" in str(exc).lower():
    return "insufficient_funds"
  return "submit_failed"


def _executor(owner):
  executor = owner.__dict__.get("_demo_attestation_executor")
  if executor is None:
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="redmesh-demo-attestation")
    owner._demo_attestation_executor = executor
  return executor


def _pending(owner):
  pending = owner.__dict__.get("_demo_attestation_pending")
  if pending is None:
    pending = {}
    owner._demo_attestation_pending = pending
  return pending


def _run_demo_submit(owner, work):
  """Worker thread: wait out the settle delay, then send with bounded retries."""
  settle = work["settle_seconds"]
  last_error = None
  for attempt in range(1, work["retries"] + 1):
    wait = owner.__dict__.get("_demo_attestation_last_send", 0.0) + settle - time.monotonic()
    if wait > 0:
      time.sleep(wait)
    # The caller has been answered `timeout` by now: a late send would be an orphan transaction.
    if time.monotonic() >= work["deadline"]:
      return {"error_class": "deadline"}
    try:
      tx_hash = owner.bc.submit_attestation(**work["submit_kwargs"])
    except Exception as exc:
      last_error = exc
      owner.P(
        f"[DEMO-ATTESTATION] {work['event']} attempt {attempt}/{work['retries']} failed: "
        f"{type(exc).__name__}", color='y')
      # A failed send may still have reached the mempool; space the retry like a send.
      owner._demo_attestation_last_send = time.monotonic()
      continue
    owner._demo_attestation_last_send = time.monotonic()
    if tx_hash:
      return {"tx_hash": _normalize_tx_hash(tx_hash)}
  return {"error_class": _classify_submit_error(last_error) if last_error else "submit_failed"}


def _key_material(key):
  key = (key or "").strip().lower()
  return key[2:] if key.startswith("0x") else key


def _shares_the_live_wallet(owner, cfg):
  # Two senders on one wallet would race its nonce outside the Demo worker. Compared without the
  # `0x` prefix and case, which do not change the key.
  demo_key = _key_material(cfg["PRIVATE_KEY"])
  return bool(demo_key) and demo_key == _key_material(get_attestation_config(owner)["PRIVATE_KEY"])


def get_demo_attestation_status(owner):
  """Whether Demo attestation is on and has a key of its own; never the key."""
  cfg = get_demo_attestation_config(owner)
  return {
    "configured": bool(cfg["ENABLED"] and cfg["PRIVATE_KEY"]) and not _shares_the_live_wallet(owner, cfg),
    "network": DEMO_ATTESTATION_NETWORK_LABEL,
    "evm_network": cfg["NETWORK"],
  }


def submit_demo_attestation(owner, *, job_id="", event="", target="", run_mode="", node_count=0,
                            vulnerability_score=0):
  """Validate one Demo attestation and hand it to the worker; a postponed request or an error."""
  cfg = get_demo_attestation_config(owner)
  if not cfg["ENABLED"]:
    return _error(409, "demo_attestation_disabled", "Demo attestation is disabled.")
  if not cfg["PRIVATE_KEY"]:
    return _error(409, "demo_attestation_not_configured", "Demo attestation has no wallet key.")
  if _shares_the_live_wallet(owner, cfg):
    return _error(409, "demo_wallet_shared", "Demo attestation needs a wallet other than the live one.")
  if not isinstance(job_id, str) or not job_id.startswith(DEMO_JOB_PREFIX) or len(job_id) > 128:
    return _error(400, "demo_job_required", "Only a Demo job can be attested here.")
  function_name = DEMO_ATTESTATION_EVENTS.get(event) if isinstance(event, str) else None
  if function_name is None:
    return _error(400, "invalid_event", "event must be start or complete.")
  pending = _pending(owner)
  if len(pending) >= MAX_PENDING:
    return _error(429, "demo_attestation_busy", "Too many Demo attestations are pending.")

  test_mode = 1 if str(run_mode or "").upper() == RUN_MODE_CONTINUOUS_MONITORING else 0
  nodes = _bounded_int(node_count, MAX_NODE_COUNT)
  execution_id = owner._attestation_pack_execution_id(demo_execution_id(job_id))
  ip_obfuscated = _pack_demo_target(owner, target)
  if event == "start":
    function_args = [test_mode, nodes, execution_id, ZERO_NODE_HASHES, ip_obfuscated]
  else:
    score = _bounded_int(vulnerability_score, MAX_VULNERABILITY_SCORE)
    function_args = [test_mode, nodes, score, execution_id, ip_obfuscated,
                     owner._attestation_pack_cid_obfuscated(None)]
  submit_kwargs = owner._attestation_submit_kwargs(
    function_name, function_args, tx_private_key=cfg["PRIVATE_KEY"], network=cfg["NETWORK"])

  owner.P(
    f"[DEMO-ATTESTATION] Submitting {event} for {job_id}: execution={execution_id}, "
    f"mode={'CONTINUOUS' if test_mode else 'SINGLEPASS'}, nodes={nodes}, target={ip_obfuscated}, "
    f"network={cfg['NETWORK']}")
  pending_id = uuid4().hex
  deadline = time.monotonic() + DEADLINE_SECONDS
  work = {"event": event, "submit_kwargs": submit_kwargs, "retries": cfg["RETRIES"],
          "settle_seconds": cfg["SETTLE_SECONDS"], "deadline": deadline}
  pending[pending_id] = {
    "future": _executor(owner).submit(_run_demo_submit, owner, work),
    "deadline": deadline,
    "job_id": job_id,
    "event": event,
    "execution_id": execution_id,
  }
  return owner.create_postponed_request(
    solver_method=owner.solve_postponed_demo_attestation,
    method_kwargs={"pending_id": pending_id},
  )


def solve_demo_attestation(owner, pending_id):
  """The postponed answer: the tx hash, an error class, or postpone again until the deadline."""
  pending = _pending(owner)
  state = pending.get(pending_id)
  if state is None:
    return _error(410, "demo_attestation_unavailable", "The Demo attestation request is gone.")
  future = state["future"]
  if not future.done():
    if time.monotonic() < state["deadline"]:
      return owner.create_postponed_request(
        solver_method=owner.solve_postponed_demo_attestation,
        method_kwargs={"pending_id": pending_id},
      )
    # A queued submit is dropped; a running one may still land, and the caller records a timeout
    # and does not retry.
    future.cancel()
    pending.pop(pending_id, None)
    return _error(504, "timeout", "The Demo attestation did not finish in time.")
  pending.pop(pending_id, None)
  try:
    outcome = future.result()
  except Exception:
    outcome = {"error_class": "submit_failed"}
  if not outcome.get("tx_hash"):
    owner.P(f"[DEMO-ATTESTATION] {state['event']} for {state['job_id']} failed: {outcome['error_class']}",
            color='y')
    return _error(502, outcome["error_class"], "The Demo attestation was not submitted.")
  owner.P(f"[DEMO-ATTESTATION] {state['event']} for {state['job_id']} sent: {outcome['tx_hash']}", color='g')
  return {
    "status": "ok",
    "tx_hash": outcome["tx_hash"],
    "execution_id": state["execution_id"],
    "network": DEMO_ATTESTATION_NETWORK_LABEL,
    # The node that signed the attestation; the Demo wallet pays and sends.
    "signer": owner.bc.eth_address,
  }
