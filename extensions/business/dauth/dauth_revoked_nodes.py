"""
dauth_revoked_nodes.py
======================

TEMPORARY (November 2026 incident response): every node key that existed before the
2026-11-03 key rotations is treated as stolen. dAuth refuses any request signed by one
of the internal node addresses listed in `EE_REVOKED_NODE_ADDRESSES`, whatever the
license state, and appends each refused try to a local JSONL registry so we can see
which revoked keys are still in use. The list is deployed privately in the dAuth
servers' .env and is never part of this repository.

Remove this module and the `_dauth_revoked_refusal` calls in `dauth_mixin.py` once
on-chain node address revocation (`revokeNodeAddresses` in ND/MND) and the node
key-rotation update are live.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from ratio1.const.base import dAuth


# Comma-separated internal node addresses (with or without the `0xai_` prefix).
DAUTH_REVOKED_NODES_ENV_KEY = "EE_REVOKED_NODE_ADDRESSES"
DAUTH_REVOKED_TRIES_FILE = "dauth_revoked_node_tries.jsonl"
# Holders of stolen keys can sign as many requests as they like: stop appending
# (but keep refusing and counting) once the registry reaches this size.
DAUTH_REVOKED_TRIES_MAX_BYTES = 64 * 1024 * 1024
DAUTH_REVOKED_NODE_MESSAGE = (
  "Node address revoked after the November 2026 security incident: its key is treated "
  "as compromised. Generate a new node key and relink the license to the new node address."
)

_INTERNAL_ADDRESS_RE = re.compile(r"^[A-Za-z0-9_-]{44}$")
_REPORTED_KEYS = (
  dAuth.DAUTH_SENDER_APP_VER,
  dAuth.DAUTH_SENDER_CORE_VER,
  dAuth.DAUTH_SENDER_SDK_VER,
  dAuth.DAUTH_SENDER_ALIAS,
)
_REPORTED_MAX_LEN = 64


class _DauthRevokedNodesMixin(object):
  """Temporary denylist of node addresses revoked after the November 2026 incident."""

  def _load_dauth_revoked_nodes(self):
    """
    Read the denylist once from `EE_REVOKED_NODE_ADDRESSES`, called from `on_init` on
    every node. An unusable value is kept as an error for `_require_dauth_revoked_nodes`,
    since only nodes that serve dAuth need the list. Only the count and a hash are
    logged, never the addresses.
    """
    self._dauth_revoked_tries = {}
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

  def _dauth_revoked_refusal(
    self, endpoint, node_address, node_address_eth, requester_type=None, body=None
  ):
    """
    Return the refusal message if the signed requester's internal address is revoked,
    else None. Call only after the request signature was verified. Every refusal is
    counted, logged and appended to the local registry of tries.
    """
    revoked = getattr(self, "_dauth_revoked_nodes", None)
    if revoked is None:
      raise RuntimeError("dAuth revoked-node denylist is not loaded.")
    if not revoked:
      return None
    internal = self.bc.maybe_remove_prefix(node_address)
    if internal not in revoked:
      return None

    tries = self._dauth_revoked_tries.get(internal, 0) + 1
    self._dauth_revoked_tries[internal] = tries
    body = body if isinstance(body, dict) else {}
    reported = {
      key: body[key][:_REPORTED_MAX_LEN] if isinstance(body.get(key), str) else None
      for key in _REPORTED_KEYS
    }
    recorded = self._record_dauth_revoked_try({
      "time_utc": datetime.now(timezone.utc).isoformat(),
      "endpoint": endpoint,
      "node_address": node_address,
      "eth_address": node_address_eth,
      "requester_type": requester_type,
      "first_seen": self._dauth_revoked_first_seen(node_address),
      "tries_since_start": tries,
      **reported,
    })
    self.P(
      "dAuth refused revoked {} {} ({}) on /{}: try #{} since start, {} tries from {} revoked addresses{}".format(
        requester_type or "requester", node_address, node_address_eth, endpoint, tries,
        sum(self._dauth_revoked_tries.values()), len(self._dauth_revoked_tries),
        "" if recorded else " (not recorded in registry)",
      ),
      color='r',
    )
    return DAUTH_REVOKED_NODE_MESSAGE

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
