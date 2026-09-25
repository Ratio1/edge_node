"""dAuth registry lookup and ChainStore routing helpers."""


DAUTH_SECRET_PIPELINE_CID_KEY = "pipeline_cid"


def resolve_dauth_registry_internal_peers(plugin, eth_oracles):
  """Resolve cached registry ETH addresses through current NetMon state."""
  current_eth = plugin.bc.eth_address.lower()
  peers = []
  for eth_address in eth_oracles:
    internal_address = plugin.bc.eth_addr_to_internal_addr(eth_address)
    if internal_address is None and eth_address.lower() == current_eth:
      internal_address = plugin.bc.address
    if isinstance(internal_address, str) and internal_address:
      peers.append(internal_address)
  return list(dict.fromkeys(peers))


def load_dauth_registry_snapshot(plugin):
  """Load the current dAuth registry and resolve its currently known peers."""
  eth_oracles = plugin.bc.get_eth_dauth_oracles()
  eth_oracles = list(dict.fromkeys(
    address
    for address in eth_oracles or []
    if isinstance(address, str) and address
  ))
  if not eth_oracles:
    raise ValueError("No dAuth oracles are registered.")

  peers = resolve_dauth_registry_internal_peers(plugin, eth_oracles)
  if not peers:
    raise ValueError("No dAuth registry internal peers are available.")
  return peers, eth_oracles


def get_cached_dauth_registry_internal_peers(plugin):
  """Return the latest cached dAuth oracle internal addresses."""
  eth_oracles = getattr(plugin, "_dauth_registry_eth_oracles", None)
  if eth_oracles:
    peers = resolve_dauth_registry_internal_peers(plugin, eth_oracles)
    if peers:
      plugin._dauth_registry_internal_peers = peers
  peers = getattr(plugin, "_dauth_registry_internal_peers", None)
  if not peers:
    raise ValueError("dAuth registry peers are not cached.")
  return list(peers)


def get_dauth_registry_internal_peers(plugin):
  """Return cached manager peers or resolve peers for another plugin."""
  if (
    getattr(plugin, "_dauth_registry_eth_oracles", None)
    or hasattr(plugin, "_dauth_registry_internal_peers")
  ):
    return get_cached_dauth_registry_internal_peers(plugin)
  peers, _ = plugin.bc.get_dauth_oracles()
  peers = list(dict.fromkeys(
    peer for peer in peers or []
    if isinstance(peer, str) and peer
  ))
  if not peers:
    raise ValueError("No dAuth registry internal peers are available.")
  return peers


def dauth_registry_write_kwargs(plugin, peers=None):
  """Route a ChainStore write exclusively to dAuth registry peers."""
  if peers is None:
    peers = get_dauth_registry_internal_peers(plugin)
  return {
    "extra_peers": list(peers),
    "include_default_peers": False,
    "include_configured_peers": False,
  }


def pipeline_registry_write_kwargs(plugin, peers=None):
  """Add dAuth peers without disabling normal pipeline metadata peers."""
  if peers is None:
    peers = get_dauth_registry_internal_peers(plugin)
  return {
    "extra_peers": list(peers),
    "include_default_peers": True,
    "include_configured_peers": True,
  }
