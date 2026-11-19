"""License relinks change deployment selectors without rewriting application data."""

from copy import deepcopy

from extensions.utils.per_node_config import PER_NODE_CONFIG_KEYS, PER_NODE_CONFIG_STRUCTURED_KEYS


def relink_keys(mapping, aliases):
  """Move address-keyed entries without overwriting a destination.

  Values and insertion order remain intact, including sparse secret overlays.

  Parameters
  ----------
  mapping, aliases : dict
    Address-keyed entries and verified old-to-current addresses.

  Returns
  -------
  dict
    Entries keyed by their new recipient.

  Examples
  --------
  >>> relink_keys({"old": "old"}, {"old": "new"})
  {'new': 'old'}
  """
  result = {aliases.get(key, key): value for key, value in mapping.items()}
  if len(result) != len(mapping):  # Two old identities must never share a secret or an overlay.
    raise ValueError("Relink would merge distinct node selectors.")
  return result


def relink_pipeline(pipeline, aliases):
  """Move placement references in a pipeline or its sparse secret fragment.

  Only declared placement fields, per-node selectors and the corresponding
  selector segment in SECRET_PATHS belong to the deployment system.

  Parameters
  ----------
  pipeline : dict
    Canonical pipeline, per-node pipeline, or its sparse job_secrets fragment.
  aliases : dict
    Verified mapping of old addresses to current addresses.

  Returns
  -------
  dict
    Independent copy with the existing execution and placement order.

  Examples
  --------
  >>> relink_pipeline({"NAME": "old"}, {"old": "new"})
  {'NAME': 'old'}
  """
  result = deepcopy(pipeline)
  if not result or not aliases:
    return result
  specs = result.get("DEEPLOY_SPECS", {})
  # Each pair names a schema-owned list. Never descend into ENV or customer dictionaries.
  address_lists = [(specs, key) for key in ("current_target_nodes", "spare_nodes")]
  if specs.get("chainstore_response_keys"):
    specs["chainstore_response_keys"] = relink_keys(specs["chainstore_response_keys"], aliases)
  # R1DB indexes tunnels, certificates and replicas by position in this allocation.
  job_config = specs.get("job_config")
  params = job_config.get("pipeline_params") if isinstance(job_config, dict) else None
  for allocation in (params.get("deeploy_cockroachdb") if isinstance(params, dict) else None,
                     result.get("deeploy_cockroachdb"), result.get("DEEPLOY_COCKROACHDB")):
    if isinstance(allocation, dict) and allocation.get("service") == "cockroachdb":
      address_lists.append((allocation, "nodeOrder"))
      for tunnel in allocation.get("internalTunnels") or []:
        if isinstance(tunnel, dict) and tunnel.get("nodeAddress") in aliases:
          tunnel["nodeAddress"] = aliases[tunnel["nodeAddress"]]  # Keep the original tunnel/index/token association.
  for plugin in result.get("PLUGINS", []):
    if not plugin:  # Sparse custody fragments can omit unrelated plugins.
      continue
    for instance in plugin.get("INSTANCES", []):
      if not instance:  # Sparse custody fragments can omit unrelated instances.
        continue
      address_lists.extend((instance, key) for key in ("CHAINSTORE_PEERS", "PER_NODE_TARGET_NODES"))
      for key in PER_NODE_CONFIG_KEYS:
        selectors = instance.get(key)
        if not selectors:
          continue
        if PER_NODE_CONFIG_STRUCTURED_KEYS.isdisjoint(selectors):
          instance[key] = relink_keys(selectors, aliases)  # Legacy direct node map.
        else:
          for section in ("byNode", "BY_NODE"):
            if selectors.get(section):
              selectors[section] = relink_keys(selectors[section], aliases)
      for path in instance.get("SECRET_PATHS", []):
        if isinstance(path, list) and len(path) >= 3 and path[0] in PER_NODE_CONFIG_KEYS and path[1] in ("byNode", "BY_NODE"):
          path[2] = aliases.get(path[2], path[2])  # Subsequent ENV names and path components are user data.
        elif isinstance(path, list) and len(path) >= 3 and path[0] in PER_NODE_CONFIG_KEYS and path[1] in aliases:
          path[1] = aliases[path[1]]  # The legacy direct-map form has no byNode prefix.
  for container, key in address_lists:
    if isinstance(container.get(key), list):
      original = container[key]
      moved = [aliases.get(node, node) for node in original]
      if len(set(moved)) != len(set(original)):  # Keep pre-existing multiplicity; disallow a new collision.
        raise ValueError("Relink would merge distinct placement entries.")
      container[key] = moved
  return result


def relink_configs(configs, aliases):
  """Move every per-worker plan to its current address.

  Address-map keys and the corresponding fields inside each plan must agree.

  Parameters
  ----------
  configs, aliases : dict
    Per-worker pipeline map and verified address mapping.

  Returns
  -------
  dict
    Re-keyed plans with application-owned fields preserved.

  Examples
  --------
  >>> relink_configs({"old": {"NAME": "old"}}, {"old": "new"})
  {'new': {'NAME': 'old'}}
  """
  return {node: relink_pipeline(config, aliases) for node, config in relink_keys(configs, aliases).items()}
