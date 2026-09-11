"""Strict preset asset values and persisted domain records; no runtime target requests."""
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address
import json
import re
from uuid import UUID
from urllib.parse import unquote

from .identity import canonical_account_id
from ..graybox.http_client import path_in_scope


def canonical_digest(value):
  return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def valid_digest(value):
  return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def canonical_uuid(value):
  if not isinstance(value, str) or str(UUID(value)) != value:
    raise ValueError("Invalid UUID")
  return value


def normalize_name(value, maximum=120):
  if not isinstance(value, str):
    raise ValueError("Invalid name")
  value.encode("utf-8", errors="strict")
  if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch == "\ufeff" for ch in value):
    raise ValueError("Invalid name")
  value = value.strip()
  if not 1 <= len(value) <= maximum:
    raise ValueError("Invalid name")
  return value


def _url_text(value):
  if not isinstance(value, str) or not 1 <= len(value) <= 2048:
    raise ValueError("Invalid URL text")
  value.encode("utf-8", errors="strict")
  if any(ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch in "\ufeff\\?#" for ch in value):
    raise ValueError("Invalid URL text")
  return value


def _validated_path(path, *, encoded):
  """Reject ambiguous forms before the existing graybox helper can normalize them."""
  current = path
  for round_index in range(4):
    _url_text(current)
    if (not current.startswith("/") or "//" in current
        or any(part in (".", "..") for part in current.split("/"))):
      raise ValueError("Invalid path")
    if "%" not in current:
      return current
    if not encoded or round_index == 3 or re.search(r"%(?![0-9a-fA-F]{2})", current):
      raise ValueError("Invalid path encoding")
    current = unquote(current, encoding="utf-8", errors="strict")


def _normalize_url(value, *, https_only=False):
  raw = _url_text(value)
  match = re.fullmatch(r"(https?)://([^/]+)(/.*)?", raw, flags=re.IGNORECASE | re.ASCII)
  if match is None:
    raise ValueError("Invalid URL")
  scheme, authority, path = match.groups()
  scheme, path = scheme.lower(), path or "/"
  if (https_only and scheme != "https") or "@" in authority:
    raise ValueError("Invalid URL")
  if authority.startswith("["):
    match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", authority)
    if match is None or "%" in match[1]:
      raise ValueError("Invalid IPv6 authority")
    host, port = "[" + IPv6Address(match[1]).compressed + "]", match[2]
  else:
    match = re.fullmatch(r"([^:]+)(?::([0-9]+))?", authority)
    if match is None:
      raise ValueError("Invalid authority")
    match[1].encode("ascii", errors="strict")
    host, port = match[1].lower(), match[2]
    if len(host) > 253 or any(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) is None
                              for label in host.split(".")):
      raise ValueError("Invalid hostname")
    try:
      canonical_ip = str(IPv4Address(host))
    except ValueError:
      if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]*)", host.split(".")[-1], re.IGNORECASE):
        raise ValueError("Ambiguous numeric hostname") from None
    else:
      if canonical_ip != host:
        raise ValueError("Noncanonical IPv4")
  if port is not None:
    if len(port) > 5 or not 1 <= int(port) <= 65535 or str(int(port)) != port:
      raise ValueError("Invalid port")
    if int(port) == (443 if scheme == "https" else 80):
      port = None
  decoded_path = _validated_path(path, encoded=True)
  return f"{scheme}://{host}{':' + port if port else ''}{path}", decoded_path


def normalize_target(value):
  if not isinstance(value, dict):
    raise ValueError("Invalid target")
  if value.get("kind") == "network" and set(value) == {"kind", "address"}:
    address = value["address"]
    if not isinstance(address, str) or str(IPv4Address(address)) != address:
      raise ValueError("Invalid target")
    return {"kind": "network", "address": address}
  if value.get("kind") == "webapp" and set(value) == {"kind", "url", "allowedPathPrefix"}:
    url, path = _normalize_url(value["url"])
    prefix = _validated_path(value["allowedPathPrefix"], encoded=False).rstrip("/") or "/"
    if not path_in_scope(path, prefix):
      raise ValueError("Target outside allowed prefix")
    return {"kind": "webapp", "url": url, "allowedPathPrefix": prefix}
  if value.get("kind") == "model" and set(value) == {"kind", "adapter", "endpointUrl", "model"}:
    endpoint, _ = _normalize_url(value["endpointUrl"], https_only=True)
    if value["adapter"] != "openai_compatible" or not endpoint.endswith("/chat/completions"):
      raise ValueError("Invalid model endpoint")
    return {"kind": "model", "adapter": "openai_compatible", "endpointUrl": endpoint,
            "model": normalize_name(value["model"], maximum=200)}
  raise ValueError("Invalid target")


def validate_asset(row, ids):
  if (len(ids) != 2 or row.get("tenant_id") != ids[0] or row.get("asset_id") != ids[1]
      or ids[1] != "as_" + canonical_uuid(row.get("request_id"))
      or type(row.get("active")) is not bool
      or normalize_name(row.get("display_name")) != row["display_name"]
      or normalize_target(row.get("target")) != row["target"]
      or not valid_digest(row.get("create_intent_digest"))
      or canonical_digest(row["target"]) != row.get("target_digest")):
    raise ValueError("Invalid asset")
  for field in ("created_by", "changed_by"):
    if not row.get(field) or canonical_account_id(row[field]) != row[field]:
      raise ValueError("Invalid asset attribution")
  for field in ("created_at", "changed_at"):
    if not isinstance(row.get(field), str) or datetime.fromisoformat(row[field]).tzinfo != timezone.utc:
      raise ValueError("Invalid asset timestamp")
  # Unknown stored fields are preserved, but must still form a valid JSON version/readback value.
  canonical_digest(row)
