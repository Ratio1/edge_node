"""
dauth_revoked_nodes.py
======================

dAuth refuses any request signed by one of the internal node addresses listed in
`EE_REVOKED_NODE_ADDRESSES`, whatever the license state. Each refused try is appended
to a local JSONL registry. When the node also has no on-chain license, the time of the
try is kept in the `DAUTH_REVOKED_UNLICENSED_NODES` ChainStore hash (one timestamp per
node address, rewritten at most every `DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL`
seconds, dAuth servers only). The list is deployed privately in the dAuth servers'
.env and is never part of this repository.

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
# refusing) once the registry reaches this size.
DAUTH_REVOKED_TRIES_MAX_BYTES = 64 * 1024 * 1024
# Field = internal node address, value = unix time of the last recorded unlicensed try.
DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY = "DAUTH_REVOKED_UNLICENSED_NODES"
# A node's timestamp is rewritten only when the stored (replicated) one is older than
# this many seconds, so the gate holds across all dAuth servers.
DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL = 600
# The dAuth request loop never waits longer than this for peer confirmations.
DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT = 3
# The on-chain license result (or its failure) is reused for this many seconds.
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
    Read the denylist once from `EE_REVOKED_NODE_ADDRESSES` (called from `on_init` on
    every node). A missing or malformed list is kept as an error for
    `_require_dauth_revoked_nodes`, since only dAuth servers need it. Only the count
    and a hash are logged, never the addresses.
    """
    self._dauth_revoked_license_checks = {}
    try:
      self._dauth_revoked_nodes = self._parse_dauth_revoked_nodes(
        self.os_environ.get(DAUTH_REVOKED_NODES_ENV_KEY)
      )
      self._dauth_revoked_error = None
    except ValueError as exc:
      self._dauth_revoked_nodes = frozenset()
      self._dauth_revoked_error = str(exc)
      return
    self.P(
      "dAuth revoked-node denylist loaded from {}: {} node addresses, sha256 {}".format(
        DAUTH_REVOKED_NODES_ENV_KEY, len(self._dauth_revoked_nodes),
        hashlib.sha256(",".join(sorted(self._dauth_revoked_nodes)).encode()).hexdigest(),
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
    """Return the unprefixed internal addresses; errors never echo an address."""
    if not isinstance(value, str) or not value.strip():
      raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} is not set.")
    revoked = set()
    for position, item in enumerate(value.split(","), start=1):
      if not item.strip():
        continue
      internal = self.bc.maybe_remove_prefix(item.strip())
      if not _INTERNAL_ADDRESS_RE.match(internal):
        raise ValueError(
          f"{DAUTH_REVOKED_NODES_ENV_KEY} item #{position} is not a well-formed internal node address."
        )
      revoked.add(internal)
    if not revoked:
      raise ValueError(f"{DAUTH_REVOKED_NODES_ENV_KEY} holds no node addresses.")
    return frozenset(revoked)

  def _is_dauth_node_revoked(
    self, endpoint, node_address, node_address_eth, requester_type=None, body=None
  ):
    """
    True if the signed requester's internal address is revoked. Call only after the
    signature was verified. The refusal never depends on the license.
    """
    revoked = getattr(self, "_dauth_revoked_nodes", None)
    if revoked is None:
      raise RuntimeError("dAuth revoked-node denylist is not loaded.")
    if not revoked:
      return False
    internal = self.bc.maybe_remove_prefix(node_address)
    if internal not in revoked:
      return False

    body = body if isinstance(body, dict) else {}
    record = {
      "time_utc": datetime.now(timezone.utc).isoformat(),
      "endpoint": endpoint,
      "node_address": node_address,
      "eth_address": node_address_eth,
      "requester_type": requester_type,
      **{
        key: body[key][:_REPORTED_MAX_LEN] if isinstance(body.get(key), str) else None
        for key in _REPORTED_KEYS
      },
    }
    recorded = self._record_dauth_revoked_try(record)
    published = self._maybe_publish_dauth_revoked_unlicensed_try(internal, node_address_eth)
    self.P(
      "dAuth refused revoked {} {} ({}) on /{}{}{}".format(
        requester_type or "requester", node_address, node_address_eth, endpoint,
        "" if recorded else " (not recorded in registry)",
        f" (no license, written to {DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY})" if published else "",
      ),
      color='r',
    )
    return True

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

  def _maybe_publish_dauth_revoked_unlicensed_try(self, internal, node_address_eth):
    """
    Keep one timestamp per unlicensed revoked node in ChainStore, rewritten at most
    once per `DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL` across all dAuth servers. The
    write goes to dAuth registry peers only, like job secrets. Never raises.
    """
    try:
      if self._is_dauth_revoked_node_licensed(internal, node_address_eth) is not False:
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
    """True or False from the chain, None when the lookup failed; reused per interval."""
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
