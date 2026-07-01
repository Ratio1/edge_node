from copy import deepcopy as _deepcopy


CANONICAL_PER_NODE_CONFIG_KEY = "PER_NODE_CONFIG"
PER_NODE_TARGET_NODES_KEY = "PER_NODE_TARGET_NODES"
PER_NODE_CONFIG_KEYS = ("perNodeConfig", CANONICAL_PER_NODE_CONFIG_KEY)
PER_NODE_CONFIG_STRUCTURED_KEYS = {
  "default",
  "DEFAULT",
  "byIndex",
  "BY_INDEX",
  "byNode",
  "BY_NODE",
}
PER_NODE_CONFIG_SYSTEM_KEYS = {
  "INSTANCE_ID",
  "CHAINSTORE_PEERS",
  "CHAINSTORE_RESPONSE_KEY",
  "CONTAINER_RESOURCES",
  "CONTAINER_USER",
  "CLOUDFLARE_TOKEN",
  "CR",
  "CR_DATA",
  "ENV_OVERRIDES",
  "FIXED_SIZE_VOLUMES",
  "IMAGE",
  "NGROK_AUTH_TOKEN",
  "PER_NODE_TARGET_NODES",
  "PLUGIN_NAME",
  "PLUGIN_SIGNATURE",
  "RESET",
  "SIGNATURE",
  "SEMAPHORE",
  "SEMAPHORED_KEYS",
  "SYNC",
  "TUNNEL_ENGINE",
  "TUNNEL_ENGINE_ENABLED",
}


def deep_merge_config(base, overlay, copy_fn=_deepcopy):
  if isinstance(base, dict) and isinstance(overlay, dict):
    merged = copy_fn(base)
    for key, value in overlay.items():
      if key == "SEMAPHORED_KEYS" and isinstance(merged.get(key), list) and isinstance(value, list):
        merged[key] = sorted(set(merged[key]) | set(value))
      elif key in merged:
        merged[key] = deep_merge_config(merged[key], value, copy_fn=copy_fn)
      else:
        merged[key] = copy_fn(value)
    return merged
  return copy_fn(overlay)


def get_structured_section(raw_config, section_name, aliases, label="perNodeConfig"):
  present_aliases = [key for key in aliases if key in raw_config]
  if len(present_aliases) > 1:
    raise ValueError(
      f"{label}.{section_name} has duplicate aliases: {present_aliases}."
    )
  if not present_aliases:
    return {}
  value = raw_config[present_aliases[0]]
  if value is None:
    return {}
  if not isinstance(value, dict):
    raise ValueError(f"{label}.{section_name} must be a dictionary.")
  return value


def normalize_config(
    raw_config,
    label="perNodeConfig",
    config_keys=PER_NODE_CONFIG_KEYS,
    system_keys=PER_NODE_CONFIG_SYSTEM_KEYS,
):
  """
  Normalize per-node config into default, index, and node overlays.

  Parameters
  ----------
  raw_config : dict or None
    Structured sections or a direct node-selector map.

  Returns
  -------
  tuple[dict, dict[int, dict], dict[str, dict]]
    ``default_overlay``, ``by_index``, and ``by_node``.
  """
  if raw_config is None:
    return {}, {}, {}
  if not isinstance(raw_config, dict):
    raise ValueError(f"{label} must be a dictionary.")

  has_structured_keys = any(
    key in raw_config
    for key in PER_NODE_CONFIG_STRUCTURED_KEYS
  )
  if has_structured_keys:
    extra_keys = [key for key in raw_config if key not in PER_NODE_CONFIG_STRUCTURED_KEYS]
    if extra_keys:
      raise ValueError(
        f"{label} cannot mix structured keys with direct node selectors: {extra_keys}."
      )
    default_overlay = get_structured_section(
      raw_config, "default", ("default", "DEFAULT"), label=label
    )
    by_index = get_structured_section(
      raw_config, "byIndex", ("byIndex", "BY_INDEX"), label=label
    )
    by_node = get_structured_section(
      raw_config, "byNode", ("byNode", "BY_NODE"), label=label
    )
  else:
    default_overlay = {}
    by_index = {}
    by_node = raw_config

  if not isinstance(default_overlay, dict):
    raise ValueError(f"{label}.default must be a dictionary.")
  if not isinstance(by_index, dict):
    raise ValueError(f"{label}.byIndex must be a dictionary.")
  if not isinstance(by_node, dict):
    raise ValueError(f"{label}.byNode must be a dictionary.")

  normalized_by_index = {}
  for raw_index, overlay in by_index.items():
    if not isinstance(overlay, dict):
      raise ValueError(f"{label}.byIndex[{raw_index!r}] must be a dictionary.")
    try:
      index = int(raw_index)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"{label}.byIndex key {raw_index!r} must be an integer index.") from exc
    if index < 0:
      raise ValueError(f"{label}.byIndex key {raw_index!r} must be non-negative.")
    normalized_by_index[index] = overlay

  normalized_by_node = {}
  for raw_node, overlay in by_node.items():
    if not isinstance(overlay, dict):
      raise ValueError(f"{label}.byNode[{raw_node!r}] must be a dictionary.")
    normalized_by_node[str(raw_node)] = overlay

  for overlay in [default_overlay, *normalized_by_index.values(), *normalized_by_node.values()]:
    for key in overlay:
      normalized_key = str(key).upper()
      if key in config_keys:
        raise ValueError(f"Nested {label} overlays are not supported.")
      if normalized_key in system_keys:
        raise ValueError(
          f"{label} cannot override system-managed or preflighted key '{key}'."
        )

  return default_overlay, normalized_by_index, normalized_by_node


def iter_overlays(
    raw_config,
    label="perNodeConfig",
    config_keys=PER_NODE_CONFIG_KEYS,
    system_keys=PER_NODE_CONFIG_SYSTEM_KEYS,
):
  default_overlay, by_index, by_node = normalize_config(
    raw_config,
    label=label,
    config_keys=config_keys,
    system_keys=system_keys,
  )
  for overlay in [default_overlay, *by_index.values(), *by_node.values()]:
    if overlay:
      yield overlay


def lookup_keys(node_addr):
  """
  Return full and compact selectors for one node address.

  Parameters
  ----------
  node_addr : Any
    Full or compact node address.

  Returns
  -------
  list[str]
    Lookup order with the caller-provided spelling first.
  """
  if node_addr is None:
    return []
  node_addr = str(node_addr)
  alternate = node_addr[5:] if node_addr.startswith("0xai_") else f"0xai_{node_addr}"
  return [value for value in (node_addr, alternate) if value]


def overlay_for_node(
    raw_config,
    node_addr,
    node_index,
    label="perNodeConfig",
    copy_fn=_deepcopy,
    config_keys=PER_NODE_CONFIG_KEYS,
    system_keys=PER_NODE_CONFIG_SYSTEM_KEYS,
):
  """
  Build the effective overlay for one node.

  Parameters
  ----------
  raw_config : dict or None
    Raw per-node config.
  node_addr : Any
    Node address used for selector matching.
  node_index : int or None
    Node index used for ``byIndex`` matching.

  Returns
  -------
  dict
    Merged default, by-index, and first matching by-node overlay.

  Notes
  -----
  An overlay is a partial config patch merged over a base plugin config. For
  example, ``{"ENV": {"ROLE": "node-b"}}`` overrides only ``ENV.ROLE`` while
  preserving other base ``ENV`` keys.
  """
  default_overlay, by_index, by_node = normalize_config(
    raw_config,
    label=label,
    config_keys=config_keys,
    system_keys=system_keys,
  )
  overlay = copy_fn(default_overlay)

  if node_index in by_index:
    overlay = deep_merge_config(overlay, by_index[node_index], copy_fn=copy_fn)

  for lookup_key in lookup_keys(node_addr):
    if lookup_key in by_node:
      overlay = deep_merge_config(overlay, by_node[lookup_key], copy_fn=copy_fn)
      break

  return overlay


def validate_selectors(
    raw_configs,
    nodes,
    label="perNodeConfig",
    config_keys=PER_NODE_CONFIG_KEYS,
    system_keys=PER_NODE_CONFIG_SYSTEM_KEYS,
):
  """
  Validate selectors against the target node set.

  Parameters
  ----------
  raw_configs : iterable[dict]
    Raw per-node configs. Generators are consumed once.
  nodes : list
    Ordered target nodes.

  Returns
  -------
  bool
    ``True`` when all selectors are valid.
  """
  node_count = len(nodes or [])
  node_lookup = {
    lookup_key
    for node in nodes or []
    for lookup_key in lookup_keys(node)
  }
  for raw_config in raw_configs:
    _default_overlay, by_index, by_node = normalize_config(
      raw_config,
      label=label,
      config_keys=config_keys,
      system_keys=system_keys,
    )
    out_of_range = [idx for idx in by_index if idx >= node_count]
    if out_of_range:
      raise ValueError(
        f"{label}.byIndex contains indexes outside target nodes: {out_of_range}."
      )
    unknown_nodes = [node for node in by_node if node not in node_lookup]
    if unknown_nodes:
      raise ValueError(
        f"{label}.byNode contains unknown target node selector(s): {unknown_nodes}."
      )
  return True
