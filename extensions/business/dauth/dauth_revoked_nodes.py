"""
dauth_revoked_nodes.py
======================

dAuth refuses any request signed by one of the node keys listed in
`EE_REVOKED_NODE_ADDRESSES`, whatever the license state. Requests are matched on the
ETH address derived from the signing key, never on the address text: one key has more
than one valid internal-address spelling. The refusal happens in the request; the
bookkeeping does not. A background thread (`dauth-revoked-recorder`) appends each
refused try to a local JSONL registry and checks the node's on-chain license. When the
node has no license, the plugin loop (`process`) keeps the time of the try in the
`DAUTH_REVOKED_UNLICENSED_NODES` ChainStore hash (one timestamp per node address,
rewritten at most every `DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL` seconds, dAuth servers
only). ChainStore calls stay on the plugin thread because they use the plugin's timers,
which are not safe across threads. Revoked keys retry often, and doing this work in the
request would hold the single dAuth request thread for every refusal. The list is
deployed privately in the seeds' .env and is never part of this repository; dAuth hands
it to every oracle as a supervisor key (see `dauth_manager.py`), since the oracle API
also reads it.

Key rotation: dAuth's refusal of a revoked node carries `dAuth.DAUTH_REVOKED`, and the
node then creates a new key and announces it on `/announce_node_key`, signed by both
keys. dAuth keeps only the first new key announced for each revoked key, in the
`NODE_KEY_ROTATIONS` ChainStore hash (field = revoked key's ETH address, value = new node
address), written read-only so other writers cannot replace it. The oracle API serves
that hash to the dApp, where the license owner links the new key.
"""
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone

from ratio1.const.base import dAuth

from .dauth_registry import dauth_registry_write_kwargs


# Comma-separated internal node addresses (with or without the `0xai_` prefix).
DAUTH_REVOKED_NODES_ENV_KEY = "EE_REVOKED_NODE_ADDRESSES"
DAUTH_REVOKED_TRIES_FILE = "dauth_revoked_node_tries.jsonl"
# A revoked key can sign as many requests as it likes: stop appending (but keep
# refusing) once the registry reaches this size.
DAUTH_REVOKED_TRIES_MAX_BYTES = 64 * 1024 * 1024
# Field = internal node address, value = unix time of the last recorded unlicensed try.
DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY = "DAUTH_REVOKED_UNLICENSED_NODES"
# A node's timestamp is rewritten only when the stored (replicated) one is older than
# this many seconds, so the gate holds across all dAuth servers.
DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL = 600
# The plugin loop never waits longer than this for peer confirmations of one write, and
# makes at most one such write per `process` call.
DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT = 3
# Field = revoked key's lowercase ETH address, value = first new node address announced.
NODE_KEY_ROTATIONS_CSTORE_HKEY = "NODE_KEY_ROTATIONS"
# The announcement request waits at most this long for peer confirmations (seconds).
NODE_KEY_ROTATION_WRITE_TIMEOUT = 3
# The on-chain license result is reused for this many seconds; a revoked node's license
# rarely changes, and its timestamp is rewritten at most every 600 seconds anyway.
DAUTH_REVOKED_LICENSE_CHECK_INTERVAL = 60 * 60
# A failed license lookup is retried after this many seconds.
DAUTH_REVOKED_LICENSE_RETRY_INTERVAL = 60
# Refused tries waiting for the recorder; beyond this, new tries are refused but not recorded.
DAUTH_REVOKED_PENDING_MAX = 10000
# The recorder wakes on every refused try, and at least this often (seconds).
DAUTH_REVOKED_RECORDER_INTERVAL = 2
# `on_close` waits at most this long for the recorder's final pass (seconds).
DAUTH_REVOKED_RECORDER_STOP_TIMEOUT = 10

_INTERNAL_ADDRESS_RE = re.compile(r"^[A-Za-z0-9_-]{44}$")
_REPORTED_KEYS = (
  dAuth.DAUTH_SENDER_APP_VER,
  dAuth.DAUTH_SENDER_CORE_VER,
  dAuth.DAUTH_SENDER_SDK_VER,
  dAuth.DAUTH_SENDER_ALIAS,
)
_REPORTED_MAX_LEN = 64


def parse_revoked_node_addresses(bc, value):
  """
  Return {lowercase ETH address: unprefixed internal address}. The ETH address is
  the key's identity: the compressed and uncompressed point, or the address with
  characters the base64 decoder skips, all resolve to the same one. Errors never
  echo an address.
  """
  if not isinstance(value, str) or not value.strip():
    raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} is not set.")
  revoked = {}
  for position, item in enumerate(value.split(","), start=1):
    if not item.strip():
      continue
    internal = bc.maybe_remove_prefix(item.strip())
    if not _INTERNAL_ADDRESS_RE.match(internal):
      raise ValueError(
        f"{DAUTH_REVOKED_NODES_ENV_KEY} item #{position} is not a well-formed internal node address."
      )
    try:
      eth = bc.node_address_to_eth_address(bc.maybe_add_prefix(internal))
    except Exception:
      raise ValueError(
        f"{DAUTH_REVOKED_NODES_ENV_KEY} item #{position} is not a valid node public key."
      ) from None
    revoked[eth.lower()] = internal
  if not revoked:
    raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} holds no node addresses.")
  return revoked


class _DauthRevokedNodesMixin(object):
  """Denylist of revoked node addresses."""

  def _load_dauth_revoked_nodes(self):
    """
    Read the denylist once from `EE_REVOKED_NODE_ADDRESSES` (called from `on_init` on
    every node). A missing or malformed list is kept as an error for
    `_require_dauth_revoked_nodes`, since only dAuth servers need it. Only the count
    and a hash are logged, never the addresses.
    """
    self._dauth_revoked_license_checks = {}
    self._init_dauth_revoked_recorder()
    try:
      self._dauth_revoked_nodes = self._parse_dauth_revoked_nodes(
        self.os_environ.get(DAUTH_REVOKED_NODES_ENV_KEY)
      )
      self._dauth_revoked_error = None
    except ValueError as exc:
      self._dauth_revoked_nodes = {}
      self._dauth_revoked_error = str(exc)
      return
    self.P(
      "dAuth revoked-node denylist loaded from {}: {} node addresses, sha256 {}".format(
        DAUTH_REVOKED_NODES_ENV_KEY, len(self._dauth_revoked_nodes),
        hashlib.sha256(",".join(sorted(self._dauth_revoked_nodes.values())).encode()).hexdigest(),
      ),
      boxed=True,
    )
    return

  def _require_dauth_revoked_nodes(self):
    """A mainnet dAuth server never starts without the list; other networks warn."""
    error = self._dauth_revoked_error
    if error is None:
      return
    if self.evm_network == dAuth.EvmNetData.MAINNET:
      raise ValueError(error)
    self.P(f"{error} dAuth revoked-node check is OFF on {self.evm_network}.", color='y', boxed=True)
    return

  def _parse_dauth_revoked_nodes(self, value):
    return parse_revoked_node_addresses(self.bc, value)

  def _announce_node_key(self, body):
    """
    Keep the first new key announced for a revoked node key.

    The request is signed by the new key and carries the announcement
    (`dAuth.DAUTH_KEY_ROTATION`) signed by the revoked key, naming the new key. The
    first new key stored for a revoked key is final; later announcements only read it.
    A matching announcement rewrites the same value so a write lost the first time is
    replicated on retry.

    Returns
    -------
    dict
      `old_node`, `new_node` (the address stored for the revoked key) and `confirmed`
      (True when the stored address is this request's and peers confirmed it).
    """
    new_node, new_eth = self._verify_signed_dauth_body(body, endpoint="announce_node_key")
    announcement = body.get(dAuth.DAUTH_KEY_ROTATION)
    if not isinstance(announcement, dict) or not self.bc.verify(announcement, return_full_info=True).valid:
      raise ValueError("Invalid node key announcement signature.")
    if (
      announcement.get("purpose") != dAuth.DAUTH_KEY_ROTATION_PURPOSE
      or announcement.get("network") != self.evm_network
      or not isinstance(announcement.get("new_node"), str)
      or self.bc.node_address_to_eth_address(announcement["new_node"]).lower() != new_eth.lower()
    ):
      raise ValueError("Invalid node key announcement.")
    old_node = announcement.get(self.const.BASE_CT.BCctbase.SENDER)
    old_eth = self.bc.node_address_to_eth_address(old_node).lower()
    if old_eth not in self._dauth_revoked_nodes:
      raise ValueError("Only a revoked node key can announce a new key.")

    stored = self.chainstore_hget(hkey=NODE_KEY_ROTATIONS_CSTORE_HKEY, key=old_eth)
    confirmed = False
    if stored in (None, new_node):
      confirmed = bool(self.chainstore_hset(
        hkey=NODE_KEY_ROTATIONS_CSTORE_HKEY, key=old_eth, value=new_node,
        readonly=True, timeout=NODE_KEY_ROTATION_WRITE_TIMEOUT, max_retries=0,
      ))
      stored = self.chainstore_hget(hkey=NODE_KEY_ROTATIONS_CSTORE_HKEY, key=old_eth)
    self.P("Node key announcement for revoked {} -> {}: stored {}, confirmed {}".format(
      old_eth, new_eth, stored, confirmed and stored == new_node,
    ), color='y')
    return {
      "old_node": old_node,
      "new_node": stored,
      "confirmed": confirmed and stored == new_node,
    }

  def _is_dauth_node_revoked(self, endpoint, node_address, requester_type=None, body=None):
    """
    True if the signed requester's key is revoked. Call only after the signature was
    verified. The ETH address is derived here from `node_address` (the key that signed),
    so every spelling of a revoked key matches. The refusal never depends on the license.
    """
    revoked = getattr(self, "_dauth_revoked_nodes", None)
    if revoked is None:
      raise RuntimeError("dAuth revoked-node denylist is not loaded.")
    if not revoked:
      return False
    node_address_eth = self.bc.node_address_to_eth_address(node_address)
    internal = revoked.get(node_address_eth.lower())
    if internal is None:
      return False

    body = body if isinstance(body, dict) else {}
    source_ip = self.get_request_client_ip()
    record = {
      "time_utc": datetime.now(timezone.utc).isoformat(),
      "endpoint": endpoint,
      "source_ip": source_ip,
      "node_address": node_address,
      "eth_address": node_address_eth,
      "requester_type": requester_type,
      **{
        key: body[key][:_REPORTED_MAX_LEN] if isinstance(body.get(key), str) else None
        for key in _REPORTED_KEYS
      },
    }
    self._queue_dauth_revoked_try(internal, node_address_eth, record)
    self.P(
      "dAuth refused revoked {} {} ({}) from {} on /{}".format(
        requester_type or "requester", node_address, node_address_eth, source_ip, endpoint,
      ),
      color='r',
    )
    return True

  def _init_dauth_revoked_recorder(self):
    """Create the recorder state once; the thread starts with the dAuth server."""
    if getattr(self, "_dauth_revoked_pending_lock", None) is not None:
      return
    self._dauth_revoked_pending = []
    self._dauth_revoked_pending_dropped = 0
    # {internal address: ETH address} of unlicensed nodes whose try awaits its ChainStore write.
    self._dauth_revoked_unlicensed_pending = {}
    self._dauth_revoked_pending_lock = threading.Lock()
    self._dauth_revoked_wake = threading.Event()
    self._dauth_revoked_stop = threading.Event()
    self._dauth_revoked_thread = None
    return

  def _start_dauth_revoked_recorder(self):
    """Start the background recorder unless it already runs."""
    self._init_dauth_revoked_recorder()
    thread = self._dauth_revoked_thread
    if thread is not None and thread.is_alive():
      return
    self._dauth_revoked_stop.clear()
    self._dauth_revoked_thread = threading.Thread(
      target=self._dauth_revoked_recorder_loop,
      name="dauth-revoked-recorder", daemon=True,
    )
    self._dauth_revoked_thread.start()
    return

  def _stop_dauth_revoked_recorder(self, timeout=DAUTH_REVOKED_RECORDER_STOP_TIMEOUT):
    """Stop the recorder after a final pass over the pending tries."""
    thread = getattr(self, "_dauth_revoked_thread", None)
    if thread is None:
      return
    self._dauth_revoked_stop.set()
    self._dauth_revoked_wake.set()
    thread.join(timeout=timeout)
    return

  def _dauth_revoked_recorder_loop(self):
    while True:
      stopping = self._dauth_revoked_stop.is_set()
      try:
        self._flush_dauth_revoked_tries()
      except Exception as exc:
        self.P(f"dAuth revoked-try recorder pass failed: {exc}", color='r')
      if stopping:
        return
      self._dauth_revoked_wake.wait(DAUTH_REVOKED_RECORDER_INTERVAL)
      self._dauth_revoked_wake.clear()

  def _queue_dauth_revoked_try(self, internal, node_address_eth, record):
    """Hand one refused try to the recorder. Never blocks on I/O."""
    with self._dauth_revoked_pending_lock:
      if len(self._dauth_revoked_pending) < DAUTH_REVOKED_PENDING_MAX:
        self._dauth_revoked_pending.append((internal, node_address_eth, record))
      else:
        self._dauth_revoked_pending_dropped += 1
    self._dauth_revoked_wake.set()
    return

  def _flush_dauth_revoked_tries(self):
    """
    Record every pending try: append them to the registry, then check the license once
    per node and hand unlicensed nodes to the plugin loop for the ChainStore write. Runs
    on the recorder thread and never calls ChainStore.
    """
    with self._dauth_revoked_pending_lock:
      pending, self._dauth_revoked_pending = self._dauth_revoked_pending, []
      dropped, self._dauth_revoked_pending_dropped = self._dauth_revoked_pending_dropped, 0
    if dropped:
      self.P(f"dAuth revoked-try backlog was full: {dropped} tries not recorded.", color='r')
    if not pending:
      return
    self._record_dauth_revoked_tries([record for _, _, record in pending])
    nodes = {}
    for internal, node_address_eth, _ in pending:
      nodes.setdefault(internal, node_address_eth)
    unlicensed = {
      internal: node_address_eth
      for internal, node_address_eth in nodes.items()
      if self._is_dauth_revoked_node_licensed(internal, node_address_eth) is False
    }
    if unlicensed:
      with self._dauth_revoked_pending_lock:
        self._dauth_revoked_unlicensed_pending.update(unlicensed)
    return

  def _maybe_publish_dauth_revoked_unlicensed_tries(self):
    """
    Called from `process` on the plugin thread. Write the ChainStore timestamp of pending
    unlicensed nodes, skipping nodes whose stored timestamp is recent, and stop after the
    first attempted write so one call blocks the request thread at most
    `DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT` seconds.
    """
    lock = getattr(self, "_dauth_revoked_pending_lock", None)
    if lock is None:
      return
    while True:
      with lock:
        if not self._dauth_revoked_unlicensed_pending:
          return
        internal = next(iter(self._dauth_revoked_unlicensed_pending))
        node_address_eth = self._dauth_revoked_unlicensed_pending.pop(internal)
      result = self._maybe_publish_dauth_revoked_unlicensed_try(internal, node_address_eth)
      if result is True:
        self.P(
          f"dAuth revoked node {node_address_eth} has no license: try written to "
          f"{DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY}",
          color='r',
        )
      if result is not None:
        return

  def _record_dauth_revoked_tries(self, records):
    """Append records to the plugin-local JSONL registry. Never raises."""
    try:
      folder = os.path.join(self.get_data_folder(), self._resolve_data_subfolder())
      os.makedirs(folder, exist_ok=True)
      path = os.path.join(folder, DAUTH_REVOKED_TRIES_FILE)
      size = os.path.getsize(path) if os.path.exists(path) else 0
      written = 0
      with open(path, "a", encoding="utf-8") as fh:
        for record in records:
          if size >= DAUTH_REVOKED_TRIES_MAX_BYTES:
            break
          line = json.dumps(record, sort_keys=True) + "\n"
          fh.write(line)
          size += len(line.encode("utf-8"))
          written += 1
      if written < len(records):
        self.P(
          f"dAuth revoked-try registry is full: {len(records) - written} tries not recorded.",
          color='r',
        )
    except Exception as exc:
      self.P(f"Could not record revoked dAuth tries: {exc}", color='r')
    return

  def _maybe_publish_dauth_revoked_unlicensed_try(self, internal, node_address_eth):
    """
    Keep one timestamp per unlicensed revoked node in ChainStore, rewritten at most
    once per `DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL` across all dAuth servers. The
    write goes to dAuth registry peers only, like job secrets. Plugin thread only.
    Never raises.

    Returns
    -------
    bool or None
      True if written, False if the write (or its preparation) failed, None if the
      stored timestamp is recent enough and nothing was written.
    """
    try:
      now = self.time()
      last = self.chainstore_hget(hkey=DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY, key=internal)
      if isinstance(last, (int, float)) and now - last < DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL:
        return None
      if self.chainstore_hset(
        hkey=DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY,
        key=internal,
        value=now,
        timeout=DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT,
        max_retries=0,
        **dauth_registry_write_kwargs(self),
      ):
        return True
      self.P(f"Could not write unlicensed revoked dAuth try to {DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY}.", color='r')
    except Exception as exc:
      self.P(f"Could not write unlicensed revoked dAuth try: {exc}", color='r')
    return False

  def _is_dauth_revoked_node_licensed(self, internal, node_address_eth):
    """
    True or False from the chain, reused for `DAUTH_REVOKED_LICENSE_CHECK_INTERVAL`;
    None when the lookup failed, retried after `DAUTH_REVOKED_LICENSE_RETRY_INTERVAL`.
    """
    now = self.time()
    checked = self._dauth_revoked_license_checks.get(internal)
    interval = (
      DAUTH_REVOKED_LICENSE_RETRY_INTERVAL
      if checked is not None and checked[1] is None
      else DAUTH_REVOKED_LICENSE_CHECK_INTERVAL
    )
    if checked is None or now - checked[0] >= interval:
      try:
        licensed = self.bc.is_node_licensed(node_address_eth=node_address_eth)
      except Exception as exc:
        self.P(f"Could not check the license of a revoked dAuth node: {exc}", color='r')
        licensed = None
      checked = (now, licensed)
      self._dauth_revoked_license_checks[internal] = checked
    return checked[1]
