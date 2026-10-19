"""Request selectors and instance metadata for conditionally secret environment values."""

import copy

from extensions.utils.per_node_config import (
  PER_NODE_CONFIG_STRUCTURED_KEYS,
  deep_merge_config,
  normalize_config,
  overlay_for_node,
)


def path_value(payload, path):
  current = payload
  for part in path:
    if isinstance(current, dict) and isinstance(part, str) and part in current:
      current = current[part]
    elif isinstance(current, list) and type(part) is int and 0 <= part < len(current):
      current = current[part]
    else:
      raise ValueError("secret_paths must reference an existing value.")
  return current


def selected_value_paths(instance, path):
  """Validate a relative variable selector and expand it to scalar secret leaves."""
  if not isinstance(path, list) or not all(isinstance(p, str) and p for p in path):
    raise ValueError("secret_paths contains a malformed variable selector.")
  tail = path
  if path[:1] == ["PER_NODE_CONFIG"]:
    if len(path) == 4 and path[1] == "default":
      tail = path[2:]
    elif len(path) == 5 and path[1] in ("byNode", "byIndex"):
      if path[1] == "byIndex" and (not path[2].isascii() or not path[2].isdecimal() or str(int(path[2])) != path[2]):
        raise ValueError("secret_paths has an invalid byIndex selector.")
      tail = path[3:]
    else:
      raise ValueError("secret_paths has an unsupported per-node selector.")
  if len(tail) != 2 or tail[0] not in ("ENV", "DYNAMIC_ENV"):
    raise ValueError("secret_paths may select only ENV or whole DYNAMIC_ENV variables.")
  value = path_value(instance, path)
  if tail[0] == "ENV":
    if value is None or not isinstance(value, (str, int, float, bool)):
      raise ValueError("Selected ENV values must be non-null scalars.")
    return [path]
  if not isinstance(value, list) or not value:
    raise ValueError("Selected DYNAMIC_ENV variables must be non-empty lists.")
  leaves = []
  for idx, part in enumerate(value):
    if not isinstance(part, dict) or part.get("type") not in ("static", "host_ip", "shmem"):
      raise ValueError("Selected DYNAMIC_ENV has an invalid part type.")
    if part["type"] == "static":
      scalar = part.get("value")
      if not isinstance(scalar, str):
        raise ValueError("Selected DYNAMIC_ENV static values must be strings.")
      leaves.append(path + [idx, "value"])
  return leaves


def reject_injected_metadata(payload):
  if isinstance(payload, dict):
    if any(isinstance(key, str) and key.upper() == "SECRET_PATHS" for key in payload):
      # The request-level lower-case field is handled separately by the caller.
      raise ValueError("SECRET_PATHS is server-owned; use top-level secret_paths.")
    for key, item in payload.items():
      if key not in ("ENV", "DYNAMIC_ENV"):
        reject_injected_metadata(item)
  elif isinstance(payload, list):
    for item in payload:
      reject_injected_metadata(item)


def compile_request_selections(request, normalized_request):
  """Validate in the signed request namespace, never the grouped runtime namespace."""
  reject_injected_metadata({k: v for k, v in request.items() if k != "secret_paths"})
  if "secret_paths" not in request:
    return
  selectors = request["secret_paths"]
  if not isinstance(selectors, list):
    raise ValueError("secret_paths must be a list.")
  selections = {}
  for path in selectors:
    if (
      not isinstance(path, list) or len(path) < 4 or path[0] != "plugins"
      or type(path[1]) is not int or path[1] < 0
    ):
      raise ValueError("secret_paths must use the request plugins namespace.")
    instance = path_value(request, path[:2])
    selected_value_paths(instance, path[2:])
    relative = path[2:]
    paths = selections.setdefault(path[1], [])
    if relative not in paths:
      paths.append(relative)
  for idx, instance in enumerate(normalized_request.get("plugins") or []):
    instance["SECRET_PATHS"] = copy.deepcopy(selections.get(idx, []))


def iter_instances(payload):
  if not isinstance(payload, dict):
    return
  for plugin in payload.get("PLUGINS", payload.get("plugins", [])) or []:
    for instance in plugin.get("INSTANCES", []) or []:
      yield (str(plugin.get("SIGNATURE", "")).upper(), str(instance.get("INSTANCE_ID", ""))), instance


def canonicalize_selected_per_node_config(instance, selectors):
  """Keep accepted overlay aliases from looking like removal of a selected value."""
  if not any(isinstance(path, list) and path[:1] == ["PER_NODE_CONFIG"] for path in selectors):
    return
  if "PER_NODE_CONFIG" not in instance:
    return
  default, by_index, by_node = normalize_config(instance["PER_NODE_CONFIG"])
  instance["PER_NODE_CONFIG"] = {
    "default": default,
    "byIndex": {str(index): overlay for index, overlay in by_index.items()},
    "byNode": by_node,
  }


def restore_per_node_response_shape(original, canonical):
  """Put redacted canonical overlays back under the request's accepted aliases."""
  if original is None:
    return None
  default, by_index, by_node = normalize_config(canonical)

  def overlay_shape(source, redacted):
    if source is None:
      return None
    return {key: copy.deepcopy(redacted[key.upper()]) for key in source}

  if not any(key in PER_NODE_CONFIG_STRUCTURED_KEYS for key in original):
    return {node: overlay_shape(overlay, by_node[str(node)]) for node, overlay in original.items()}
  result = {}
  for key, section in original.items():
    if section is None:
      result[key] = None
    elif key in ("default", "DEFAULT"):
      result[key] = overlay_shape(section, default)
    elif key in ("byIndex", "BY_INDEX"):
      result[key] = {index: overlay_shape(overlay, by_index[int(index)]) for index, overlay in section.items()}
    else:
      result[key] = {node: overlay_shape(overlay, by_node[str(node)]) for node, overlay in section.items()}
  return result


def inherit_selections(pipeline, prior_pipeline, placeholder, identity_aliases=None):
  """Omission preserves metadata; explicit removal cannot publish a hidden value."""
  prior_instances = dict(iter_instances(prior_pipeline))
  for identity, instance in iter_instances(pipeline):
    identity = (identity_aliases or {}).get(identity, identity)
    prior = prior_instances.get(identity, {})
    previous = prior.get("SECRET_PATHS", [])
    if not isinstance(previous, list):
      raise ValueError("Invalid persisted SECRET_PATHS metadata.")
    explicit = "SECRET_PATHS" in instance
    current = instance.get("SECRET_PATHS", [])
    if not isinstance(current, list):
      raise ValueError("Invalid SECRET_PATHS metadata.")
    canonicalize_selected_per_node_config(instance, previous + current)
    for path in previous:
      selected_value_paths(prior, path)
      try:
        path_value(instance, path)
      except ValueError:
        continue  # Removing the variable is not declassification.
      leaves = selected_value_paths(instance, path)
      if not explicit:
        if path not in current:
          current.append(copy.deepcopy(path))
      elif path not in current and any(path_value(instance, leaf) == placeholder for leaf in leaves):
        raise ValueError("Removing a secret selection requires replacement plaintext.")
    if current or explicit or previous:
      instance["SECRET_PATHS"] = current


def selected_leaf_paths(payload):
  """Find metadata-bearing instances in pipelines, plugin lists, or request copies."""
  def walk(value, prefix):
    if isinstance(value, dict):
      if "SECRET_PATHS" in value:
        paths = value["SECRET_PATHS"]
        if not isinstance(paths, list):
          raise ValueError("Invalid SECRET_PATHS metadata.")
        for path in paths:
          for leaf in selected_value_paths(value, path):
            yield tuple(prefix + leaf)
      for key, child in value.items():
        if key not in ("SECRET_PATHS", "ENV", "DYNAMIC_ENV"):
          yield from walk(child, prefix + [key])
    elif isinstance(value, list):
      for idx, child in enumerate(value):
        yield from walk(child, prefix + [idx])
  yield from walk(payload, [])


def same_dynamic_structure(path, pipeline, prior_pipeline):
  """An old scalar is reusable only if its complete dynamic expression is stable."""
  if "DYNAMIC_ENV" not in path:
    return True
  pos = path.index("DYNAMIC_ENV")
  root = path[:pos + 2]
  try:
    current = path_value(pipeline, root)
    prior_root = list(root)
    if prior_root[:1] == ["PLUGINS"] and isinstance(prior_pipeline, dict) and "PLUGINS" not in prior_pipeline:
      prior_root[0] = "plugins"
    previous = path_value(prior_pipeline, prior_root)
  except ValueError:
    return False
  def structure(parts):
    if not isinstance(parts, list):
      return None
    return [
      {key: value for key, value in part.items() if key != "value" or part.get("type") != "static"}
      if isinstance(part, dict) else part
      for part in parts
    ]
  return structure(current) == structure(previous)


def materialized_selections(instance, node_addr, node_index):
  """Project classification through the same overlay precedence as the values."""
  selected = {tuple(path) for path in instance["SECRET_PATHS"]}

  def markers(value, prefix):
    if not isinstance(value, dict):
      return copy.deepcopy(value)
    result = {}
    for key, item in value.items():
      if key == "SECRET_PATHS":
        continue
      if key in ("ENV", "DYNAMIC_ENV") and isinstance(item, dict):
        result[key] = {name: tuple(prefix + [key, name]) in selected for name in item}
      else:
        result[key] = markers(item, prefix + [key])
    return result

  classified = markers(instance, [])
  raw_config = classified.pop("PER_NODE_CONFIG", None)
  overlay = overlay_for_node(raw_config, node_addr, node_index)
  classified = deep_merge_config(classified, overlay)
  return [
    [kind, name]
    for kind in ("ENV", "DYNAMIC_ENV")
    for name, secret in (classified.get(kind) or {}).items()
    if secret
  ]
