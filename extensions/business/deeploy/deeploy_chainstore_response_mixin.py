class _DeeployChainstoreResponseMixin:
  """
  Deeploy-specific chainstore response reset helpers.

  Deeploy resets response keys from an oracle seed peer before dispatching node
  create commands. The target app node addresses are chainstore peers for the
  app payload, not the peers that should author the reset write.
  """

  def _normalize_chainstore_response_reset_peers(self, peers, exclude_local=False):
    if isinstance(peers, str):
      peers = [peers]
    elif not isinstance(peers, (list, tuple, set)):
      peers = []

    local_addr = getattr(self, "ee_addr", None)
    result = []
    for peer in peers:
      if not isinstance(peer, str) or not peer:
        continue
      if exclude_local and peer == local_addr:
        continue
      if peer in result:
        continue
      result.append(peer)
    return result

  def _get_chainstore_response_seed_nodes(self):
    configured = getattr(self, "seed_nodes", None)
    if configured:
      return self._normalize_chainstore_response_reset_peers(configured)

    bc = getattr(self, "bc", None)
    getter = getattr(bc, "get_oracles", None)
    if callable(getter):
      try:
        oracles = getter()
        if isinstance(oracles, tuple):
          oracles = oracles[0]
        return self._normalize_chainstore_response_reset_peers(oracles)
      except Exception as exc:
        printer = getattr(self, "Pd", None) or getattr(self, "P", None)
        if callable(printer):
          printer(f"Failed to resolve oracle seed peers for chainstore reset: {exc}", color='y')

    return []

  def _select_chainstore_response_seed_peer(self, seed_peers):
    normalized = self._normalize_chainstore_response_reset_peers(seed_peers)
    return normalized[0] if normalized else None

  def _get_chainstore_response_local_reset_peers(self):
    seed_peers = self._normalize_chainstore_response_reset_peers(
      self._get_chainstore_response_seed_nodes()
    )
    non_local_seed_peers = self._normalize_chainstore_response_reset_peers(
      seed_peers,
      exclude_local=True,
    )
    if non_local_seed_peers:
      seed_peers = non_local_seed_peers
    selected_peer = self._select_chainstore_response_seed_peer(seed_peers)
    return [selected_peer] if selected_peer else []

  def _get_chainstore_response_local_reset_write_kwargs(self):
    return {
      "extra_peers": self._get_chainstore_response_local_reset_peers(),
      "include_default_peers": False,
      "include_configured_peers": False,
      "debug": True,
    }

  def _reset_chainstore_response_key(self, response_key, write_kwargs=None):
    if not isinstance(response_key, str) or not response_key:
      raise ValueError("Invalid chainstore response key for reset.")

    write_kwargs = write_kwargs or {}
    try:
      result = self.chainstore_set(response_key, None, **write_kwargs)
    except Exception as exc:
      raise ValueError(
        f"Failed to reset chainstore response key '{response_key}': {exc}"
      ) from exc

    if not result:
      raise ValueError(f"Failed to reset chainstore response key '{response_key}'.")

    return True
