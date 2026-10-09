"""RM-126: the deployment's node directory, a name and the tags of each configured peer as the
node's network monitor knows them.

Pure and tolerant: a peer the monitor has not seen (`MISSING_ID`), a missing monitor or a failing
call names nothing, and nothing here raises for one address. The monitor strips the `0xai_` prefix
itself, so the configured peer addresses are passed as they are. The tags use the oracle's
vocabulary (`KYB`, `DC:<provider>`, `CT:<country>`), so the console reads either source the same way.
"""

# naeural_core.main.net_mon.MISSING_ID: what `network_node_eeid` answers for an unknown node.
MISSING_ID = "missing_id"


def node_directory(netmon, addresses):
  """`{address: {"alias": str | None, "tags": [str]}}` for every address, in the given order."""
  return {address: _entry(netmon, address) for address in addresses}


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
          "tags": [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []}
