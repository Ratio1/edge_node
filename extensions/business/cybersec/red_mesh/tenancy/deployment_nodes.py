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

# naeural_core.main.net_mon.MISSING_ID: what `network_node_eeid` answers for an unknown node.
MISSING_ID = "missing_id"
# A node republishes at least hourly; an older entry is a node that stopped publishing.
NODE_INFO_MAX_AGE = timedelta(hours=2)


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
  given order. `node_info` is the `<instance_id>:node_info` hash as read; None or malformed names no IP."""
  now = now or datetime.now(timezone.utc)
  info = node_info if isinstance(node_info, dict) else {}
  return {address: {**_entry(netmon, address), "ip": published_ip(info.get(address), now)} for address in addresses}


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


def named_entry(directory, address):
  """The directory's answer for `address`, sanitized; an absent or malformed entry names nothing."""
  entry = directory.get(address) if isinstance(directory, dict) else None
  alias = entry.get("alias") if isinstance(entry, dict) else None
  tags = entry.get("tags") if isinstance(entry, dict) else None
  return {"alias": alias if isinstance(alias, str) and alias else None,
          "tags": [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else [],
          "ip": global_ip(entry.get("ip")) if isinstance(entry, dict) else None}
