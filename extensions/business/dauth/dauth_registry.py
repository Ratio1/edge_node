"""dAuth registry lookup and ChainStore routing helpers."""


DAUTH_SECRET_PIPELINE_CID_KEY = "pipeline_cid"
DAUTH_JOB_SECRET_GENERATIONS_HKEY = "DAUTH_JOB_SECRET_GENERATIONS"
DAUTH_JOB_UPDATES_HKEY = "DAUTH_JOB_UPDATES"


def load_job_secret_bundle(plugin, job_id):
  """Select the immutable bundle for the published generation, then legacy data."""
  job_id = str(job_id)
  cid = plugin.chainstore_hget(hkey="DEEPLOY_DEPLOYED_JOBS", key=job_id)
  if cid:
    bundle = plugin.chainstore_hget(
      hkey=DAUTH_JOB_SECRET_GENERATIONS_HKEY, key=f"{job_id}:{cid}",
    )
    if isinstance(bundle, dict):
      return bundle
  return plugin.chainstore_hget(hkey="DAUTH_JOB_SECRETS", key=job_id)


def save_job_secret_generation(plugin, job_id, bundle, write_kwargs=None):
  """Retain generation-specific secrets without allowing a revision overwrite."""
  cid = bundle.get(DAUTH_SECRET_PIPELINE_CID_KEY) if isinstance(bundle, dict) else None
  if not cid:
    return
  if str(bundle.get("job_id")) != str(job_id):
    raise ValueError("dAuth secret generation job ID mismatch.")
  key = f"{job_id}:{cid}"
  existing = plugin.chainstore_hget(hkey=DAUTH_JOB_SECRET_GENERATIONS_HKEY, key=key)
  if existing is not None:
    if existing != bundle:
      raise ValueError("dAuth secret generation already exists with different contents.")
    return
  if write_kwargs is None:
    write_kwargs = dauth_registry_write_kwargs(plugin)
  if not plugin.chainstore_hset(
    hkey=DAUTH_JOB_SECRET_GENERATIONS_HKEY, key=key, value=bundle, **write_kwargs,
  ):
    raise ValueError("Failed to retain dAuth secret generation.")


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
