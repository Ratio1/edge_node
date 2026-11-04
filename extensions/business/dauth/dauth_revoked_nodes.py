"""
dauth_revoked_nodes.py
======================

dAuth refuses any request signed by one of the internal node addresses listed in
`EE_REVOKED_NODE_ADDRESSES`, whatever the license state, and appends each refused try
to a local JSONL registry so we can see which revoked keys are still in use. When the
on-chain license check finds no license for the node, the time of the try is also kept
in the `DAUTH_REVOKED_UNLICENSED_NODES` ChainStore hash, one timestamp per node address,
which only dAuth servers receive and which is rewritten at most every
`DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL` seconds.
The list is deployed privately in the dAuth servers' .env and is never part of this
repository.

Remove this module and the `_is_dauth_node_revoked` calls in `dauth_mixin.py` once
on-chain node address revocation (`revokeNodeAddresses` in ND/MND) and the node
key-rotation update are live.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from ratio1.const.base import dAuth

from .dauth_registry import dauth_registry_write_kwargs


# Comma-separated internal node addresses (with or without the `0xai_` prefix).
DAUTH_REVOKED_NODES_ENV_KEY = "EE_REVOKED_NODE_ADDRESSES"
DAUTH_REVOKED_TRIES_FILE = "dauth_revoked_node_tries.jsonl"
# A revoked key can sign as many requests as it likes: stop appending (but keep
# refusing and counting) once the registry reaches this size.
DAUTH_REVOKED_TRIES_MAX_BYTES = 64 * 1024 * 1024
# One field per unlicensed revoked node: field = internal node address, value = unix
# time of the last recorded try. The hash is bounded by the number of revoked addresses.
DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY = "DAUTH_REVOKED_UNLICENSED_NODES"
# A node's timestamp is rewritten only when the stored one is older than this many
# seconds. The stored value is replicated, so the gate holds across all dAuth servers.
DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL = 600
# The dAuth request loop never waits longer than this for peer confirmations.
DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT = 3
# The on-chain license of a revoked address is reused for this many seconds, including
# when the lookup failed.
DAUTH_REVOKED_LICENSE_CHECK_INTERVAL = 60

_INTERNAL_ADDRESS_RE = re.compile(r"^[A-Za-z0-9_-]{44}$")
_REPORTED_KEYS = (
  dAuth.DAUTH_SENDER_APP_VER,
  dAuth.DAUTH_SENDER_CORE_VER,
  dAuth.DAUTH_SENDER_SDK_VER,
  dAuth.DAUTH_SENDER_ALIAS,
)
_REPORTED_MAX_LEN = 64


class _DauthRevokedNodesMixin(object):
  """Denylist of revoked node addresses."""

  def _load_dauth_revoked_nodes(self):
    """
    Read the denylist once from `EE_REVOKED_NODE_ADDRESSES`, called from `on_init` on
    every node. An unusable value is kept as an error for `_require_dauth_revoked_nodes`,
    since only nodes that serve dAuth need the list. Only the count and a hash are
    logged, never the addresses.
    """
    self._dauth_revoked_tries = {}
    self._dauth_revoked_license_checks = {}
    try:
      revoked = self._parse_dauth_revoked_nodes(self.os_environ.get(DAUTH_REVOKED_NODES_ENV_KEY))
    except ValueError as exc:
      self._dauth_revoked_nodes = frozenset()
      self._dauth_revoked_error = str(exc)
      return

    self._dauth_revoked_nodes = frozenset(revoked)
    self._dauth_revoked_error = None
    self.P(
      "dAuth revoked-node denylist loaded from {}: {} node addresses, sha256 {}".format(
        DAUTH_REVOKED_NODES_ENV_KEY, len(revoked),
        hashlib.sha256(",".join(sorted(revoked)).encode()).hexdigest(),
      ),
      boxed=True,
    )
    return

  def _require_dauth_revoked_nodes(self):
    """
    Call before this node starts serving dAuth. A mainnet server raises when the list
    is unset, empty or malformed, so it never runs without the check; on other
    networks it warns and runs with the check off.
    """
    error = self._dauth_revoked_error
    if error is None:
      return
    if self.evm_network == dAuth.EvmNetData.MAINNET:
      raise ValueError(error)
    self.P(f"{error} dAuth revoked-node check is OFF on {self.evm_network}.", color='y', boxed=True)
    return

  def _parse_dauth_revoked_nodes(self, value):
    """Return the unprefixed internal addresses; errors never echo an address."""
    if not isinstance(value, str) or not value.strip():
      raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} is not set.")
    revoked = set()
    for position, item in enumerate(value.split(","), start=1):
      item = item.strip()
      if not item:
        continue
      internal = self.bc.maybe_remove_prefix(item)
      if not _INTERNAL_ADDRESS_RE.match(internal):
        raise ValueError(
          f"{DAUTH_REVOKED_NODES_ENV_KEY} item #{position} is not a well-formed internal node address."
        )
      revoked.add(internal)
    if not revoked:
      raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} holds no node addresses.")
    return revoked

  def _is_dauth_node_revoked(
    self, endpoint, node_address, node_address_eth, requester_type=None, body=None
  ):
    """
    Return True if the signed requester's internal address is revoked. Call only after
    the request signature was verified. Every refusal is counted, logged and appended
    to the local registry of tries; for unlicensed nodes the time of the try is also
    kept in ChainStore. The refusal never depends on the license.
    """
    revoked = getattr(self, "_dauth_revoked_nodes", None)
    if revoked is None:
      raise RuntimeError("dAuth revoked-node denylist is not loaded.")
    if not revoked:
      return False
    internal = self.bc.maybe_remove_prefix(node_address)
    if internal not in revoked:
      return False

    tries = self._dauth_revoked_tries.get(internal, 0) + 1
    self._dauth_revoked_tries[internal] = tries
    body = body if isinstance(body, dict) else {}
    reported = {
      key: body[key][:_REPORTED_MAX_LEN] if isinstance(body.get(key), str) else None
      for key in _REPORTED_KEYS
    }
    record = {
      "time_utc": datetime.now(timezone.utc).isoformat(),
      "endpoint": endpoint,
      "node_address": node_address,
      "eth_address": node_address_eth,
      "requester_type": requester_type,
      "first_seen": self._dauth_revoked_first_seen(node_address),
      "tries_since_start": tries,
      **reported,
    }
    recorded = self._record_dauth_revoked_try(record)
    published = self._maybe_publish_dauth_revoked_unlicensed_try(internal, record)
    self.P(
      "dAuth refused revoked {} {} ({}) on /{}: try #{} since start, {} tries from {} revoked addresses{}{}".format(
        requester_type or "requester", node_address, node_address_eth, endpoint, tries,
        sum(self._dauth_revoked_tries.values()), len(self._dauth_revoked_tries),
        "" if recorded else " (not recorded in registry)",
        f" (no license, written to {DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY})" if published else "",
      ),
      color='r',
    )
    return True

  def _maybe_publish_dauth_revoked_unlicensed_try(self, internal, record):
    """
    Keep one timestamp per unlicensed revoked node in ChainStore, rewritten at most once
    per `DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL` across all dAuth servers. The write
    goes to dAuth registry peers only, like job secrets. Never raises.
    """
    try:
      if self._is_dauth_revoked_node_licensed(internal, record["eth_address"]) is not False:
        return False
      now = self.time()
      last = self.chainstore_hget(hkey=DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY, key=internal)
      if isinstance(last, (int, float)) and now - last < DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL:
        return False
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
      self.P(f"Could not check or write unlicensed revoked dAuth try: {exc}", color='r')
    return False

  def _is_dauth_revoked_node_licensed(self, internal, node_address_eth):
    """
    On-chain license of a revoked node, reused for `DAUTH_REVOKED_LICENSE_CHECK_INTERVAL`.
    True or False from the chain; None when the last lookup in the interval failed.
    """
    now = self.time()
    checked = self._dauth_revoked_license_checks.get(internal)
    if checked is None or now - checked[0] >= DAUTH_REVOKED_LICENSE_CHECK_INTERVAL:
      try:
        licensed = self.bc.is_node_licensed(node_address_eth=node_address_eth)
      except Exception as exc:
        self.P(f"Could not check the license of a revoked dAuth node: {exc}", color='r')
        licensed = None
      checked = (now, licensed)
      self._dauth_revoked_license_checks[internal] = checked
    return checked[1]

  def _dauth_revoked_first_seen(self, node_address):
    """NetMon first-seen date of the node, for the registry only (never used to decide)."""
    try:
      node_data = self.netmon.epoch_manager.data.get(self.bc.maybe_add_prefix(node_address), {})
      return node_data.get("first_seen")
    except Exception:
      return None

  def _record_dauth_revoked_try(self, record):
    """Append one record to the plugin-local JSONL registry. Never raises."""
    try:
      folder = os.path.join(self.get_data_folder(), self._resolve_data_subfolder())
      os.makedirs(folder, exist_ok=True)
      path = os.path.join(folder, DAUTH_REVOKED_TRIES_FILE)
      if os.path.exists(path) and os.path.getsize(path) >= DAUTH_REVOKED_TRIES_MAX_BYTES:
        return False
      with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
      return True
    except Exception as exc:
      self.P(f"Could not record revoked dAuth try: {exc}", color='r')
      return False
