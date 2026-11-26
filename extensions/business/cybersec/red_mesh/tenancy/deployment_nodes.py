"""RM-126: the deployment's node directory, a name and the tags of each configured peer as the
node's network monitor knows them.

Pure and tolerant: a peer the monitor has not seen (`MISSING_ID`), a missing monitor or a failing
call names nothing, and nothing here raises for one address. The monitor strips the `0xai_` prefix
itself, so the configured peer addresses are passed as they are. The tags use the oracle's
vocabulary (`KYB`, `DC:<provider>`, `CT:<country>`), so the console reads either source the same way.

RM-127: each node publishes its own public IP into the `<instance_id>:node_info` hash, keyed by its
address, as `{"ip", "published_at"}`. `node_directory` reads what the caller passes from that hash:
a global address published within `NODE_INFO_MAX_AGE` is the node's `ip`, anything else is None. The
IP is self-reported by the node, not authenticated.
"""
from datetime import datetime, timedelta, timezone
import ipaddress
import math

# naeural_core.main.net_mon.MISSING_ID: what `network_node_eeid` answers for an unknown node.
MISSING_ID = "missing_id"
# A node republishes at least hourly; an older entry is a node that stopped publishing.
NODE_INFO_MAX_AGE = timedelta(hours=2)
# naeural_core.main.net_mon: what `network_node_last_seen(as_sec=True)` answers for a node never seen.
UNSEEN_SECONDS = 9999999999


def global_ip(value):
  """`value` when it is a string naming a global (public) IP address, else None."""
  if not isinstance(value, str):
    return None
  try:
    return value if ipaddress.ip_address(value).is_global else None
  except ValueError:
    return None


def node_info_entry(ip, now=None):
  """The `node_info` value a node publishes for itself."""
  return {"ip": ip, "published_at": (now or datetime.now(timezone.utc)).isoformat()}


def published_ip(info, now):
  """The IP in one `node_info` entry, or None when it is malformed, not global or stale."""
  if not isinstance(info, dict) or not isinstance(info.get("published_at"), str):
    return None
  try:
    published_at = datetime.fromisoformat(info["published_at"].replace("Z", "+00:00"))
  except ValueError:
    return None
  if published_at.tzinfo is None or not now - NODE_INFO_MAX_AGE <= published_at <= now + timedelta(minutes=5):
    return None
  return global_ip(info.get("ip"))


def node_directory(netmon, addresses, node_info=None, now=None):
  """`{address: {"alias": str | None, "tags": [str], "ip": str | None}}` for every address, in the
  given order, plus RM-212 `"online": bool | None` and `"last_seen": ISO UTC | None` (see `_liveness`). `node_info` is the `<instance_id>:node_info` hash as read; None or malformed names no IP."""
  now = now or datetime.now(timezone.utc)
  info = node_info if isinstance(node_info, dict) else {}
  return {address: {**_entry(netmon, address), **_liveness(netmon, address, now),
                    "ip": published_ip(info.get(address), now)} for address in addresses}


def _entry(netmon, address):
  if netmon is None:
    return {"alias": None, "tags": []}
  alias = None
  try:
    found = netmon.network_node_eeid(address)
    if isinstance(found, str) and found and found != MISSING_ID:
      alias = found
  except Exception:
    alias = None
  tags = []
  try:
    found = netmon.get_network_node_tags(address)
    if isinstance(found, list):
      tags = [tag for tag in found if isinstance(tag, str)]
  except Exception:
    tags = []
  return {"alias": alias, "tags": tags}


def _liveness(netmon, address, now):
  """RM-212: `{"online", "last_seen"}` from the monitor; None when it is missing or fails. `online` is the
  soft summary-backed check (`network_node_is_online_for_control`, falling back to `network_node_is_online`
  as `deeploy_mixin` does): it lags by about 60 to 240 s. `last_seen` is `now` minus the monitor's
  elapsed seconds; the unseen sentinel, a negative or a non-finite value is None."""
  online, last_seen = None, None
  if netmon is None:
    return {"online": online, "last_seen": last_seen}
  try:
    checker = getattr(netmon, "network_node_is_online_for_control", None)
    found = checker(address) if callable(checker) else netmon.network_node_is_online(address)
    online = found if isinstance(found, bool) else None
  except Exception:
    online = None
  try:
    elapsed = netmon.network_node_last_seen(address, as_sec=True)
    if (isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and math.isfinite(elapsed)
        and 0 <= elapsed < UNSEEN_SECONDS):
      last_seen = (now - timedelta(seconds=elapsed)).isoformat()
  except Exception:
    last_seen = None
  return {"online": online, "last_seen": last_seen}


def node_readiness(directory, address, in_deployment):
  """RM-212: `{online, lastSeen, inDeployment, state}` for one node, advisory and never stored.
  `in_deployment` is True or False, or None when the peer list could not be read. `state`: `not_in_deployment`
  when False; else `unknown` when the monitor said nothing or `in_deployment` is None; else `ready` when
  online, else `offline`. `ready` means online and a configured peer; it does not prove RedMesh runs there."""
  entry = directory.get(address) if isinstance(directory, dict) else None
  entry = entry if isinstance(entry, dict) else {}
  online = entry.get("online") if isinstance(entry.get("online"), bool) else None
  last_seen = entry.get("last_seen") if isinstance(entry.get("last_seen"), str) else None
  if in_deployment is False:
    state = "not_in_deployment"
  elif online is None or in_deployment is None:
    state = "unknown"
  else:
    state = "ready" if online else "offline"
  return {"online": online, "lastSeen": last_seen, "inDeployment": in_deployment, "state": state}


def named_entry(directory, address):
  """The directory's answer for `address`, sanitized; an absent or malformed entry names nothing."""
  entry = directory.get(address) if isinstance(directory, dict) else None
  alias = entry.get("alias") if isinstance(entry, dict) else None
  tags = entry.get("tags") if isinstance(entry, dict) else None
  return {"alias": alias if isinstance(alias, str) and alias else None,
          "tags": [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else [],
          "ip": global_ip(entry.get("ip")) if isinstance(entry, dict) else None}
