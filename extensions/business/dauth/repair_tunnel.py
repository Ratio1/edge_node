"""Custodian-only validation of a rotated main Cloudflare connector in same-host repairs."""

import base64
import json
import re
from uuid import UUID

from ratio1.const.base import dAuth

from extensions.business.deeploy.job_repair import worker


def _connector(token):
  """Decode the connector identity and its secret on the custodian.

  Only disposable local values or the custodied connector token enter this function.
  Errors deliberately omit input and decoded content.

  Parameters
  ----------
  token : str
    Base64-encoded Cloudflare connector credentials.

  Returns
  -------
  tuple
    Account, tunnel UUID, and decoded secret for an in-memory comparison.

  Examples
  --------
  >>> _connector("invalid")
  Traceback (most recent call last):
    ...
  ValueError: Invalid Cloudflare connector credential.
  """
  try:
    if not isinstance(token, str) or not 0 < len(token) <= 8192:
      raise ValueError
    data = json.loads(base64.b64decode(token, validate=True))  # cloudflared's connector envelope.
    account, tunnel = data["a"], UUID(data["t"])
    secret = base64.b64decode(data["s"], validate=True)  # Compare the actual credential bytes.
    if not isinstance(account, str) or not re.fullmatch("[a-fA-F0-9]{32}", account) or len(secret) < 32:
      raise ValueError
    return account.lower(), tunnel, secret
  except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
    raise ValueError("Invalid Cloudflare connector credential.") from None


def _main_tunnel(config):
  """Locate the effective main token aliases in the narrow worker repair profile.

  The original pipeline can carry only the legacy field, while an edited pipeline
  can write both that field and the corresponding main exposed-port token.

  Parameters
  ----------
  config : dict
    Redacted per-worker plan.

  Returns
  -------
  tuple or None
    Stable worker identity, main port number, and relative token paths, when configured.

  Examples
  --------
  >>> _main_tunnel({"PLUGINS": []})  # no previous worker to bind
  Traceback (most recent call last):
    ...
  ValueError: Repair requires one Git worker instance.
  """
  error = "Repair requires one worker with one unambiguous main Cloudflare tunnel."
  instance = worker(config)  # Use the same single Git worker, stable ID and no-overrides profile as admission.
  exposed = instance.get("EXPOSED_PORTS") or {}
  if not isinstance(exposed, dict) or any(not isinstance(entry, dict) for entry in exposed.values()):
    raise ValueError(error)
  if instance.get("EXTRA_TUNNELS") or (instance.get("TUNNEL_ENGINE_PARAMETERS") or {}).get("CLOUDFLARE_TOKEN"):
    raise ValueError(error)  # A second credential source is outside the reviewed main-connector scope.
  if not instance.get("CLOUDFLARE_TOKEN") and not any(entry.get("token") or entry.get("tunnel") for entry in exposed.values()):
    return None  # Token-free jobs need neither approval nor Cloudflare-specific port and engine validation.
  paths, ports = [], set()
  engine = instance.get("TUNNEL_ENGINE") or "cloudflare"
  if instance.get("TUNNEL_ENGINE_ENABLED") is not True or not isinstance(engine, str) or engine.lower() != "cloudflare":
    raise ValueError(error)
  if instance.get("PORT") is not None:
    ports.add(str(instance["PORT"]))  # Legacy main port may be stored as an integer.
  if instance.get("CLOUDFLARE_TOKEN") == dAuth.DAUTH_SECRET_PLACEHOLDER:
    paths.append(("CLOUDFLARE_TOKEN",))
  for port, entry in exposed.items():
    if entry.get("is_main_port") is True or str(port) in ports:
      if entry.get("is_main_port") is True:
        ports.add(str(port))
      if entry.get("tunnel") or (entry.get("engine") or "cloudflare").lower() != "cloudflare":
        raise ValueError(error)  # An alternate tunnel source needs its own supported binding.
      if entry.get("token") == dAuth.DAUTH_SECRET_PLACEHOLDER:
        paths.append(("EXPOSED_PORTS", port, "token"))
    elif entry.get("token") or entry.get("tunnel"):
      raise ValueError(error)  # This repair binds one connector, so a second route cannot silently inherit it.
  if len(ports) != 1 or not paths or not instance.get("INSTANCE_ID"):
    raise ValueError(error)
  port = ports.pop()
  if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
    raise ValueError(error)
  return instance["INSTANCE_ID"], port, paths


def reconcile_restore_tunnel(custodian, canonical, previous, desired, fresh, rotate):
  """Update only the original main connector aliases in the staged restore copy.

  Per-node plans must agree on the same worker, port and token paths. The fresh
  deployment fragments must describe a rotation of the original tunnel.

  Parameters
  ----------
  custodian : object
    dAuth plugin exposing its existing sparse-fragment read/write methods.
  canonical : dict
    Original redacted pipeline from the authoritative custody pointer.
  previous, desired : dict
    Private, reconciled restore and deployment revision records.
  fresh : dict
    Fresh values extracted from the CSP's signed update.
  rotate : bool
    Whether the CSP explicitly approved rotation for deployment and restoration.

  Returns
  -------
  None
    Replaces validated token values in the private restore record in memory.

  Examples
  --------
  >>> reconcile_restore_tunnel(custodian, canonical, restore_record, deploy_record, edits, rotate=True)  # doctest: +SKIP
  """
  prefix = ["PLUGINS", 0, "INSTANCES", 0]
  original = _main_tunnel(canonical)
  tokens, paths, identities = [], [], []
  # Without approval compare the effective staged values, including unchanged values inherited from custody.
  target_fragment = fresh if rotate else desired["job_secrets"]
  for record, fragment in ((previous, previous["job_secrets"]), (desired, target_fragment)):
    locations = [_main_tunnel(config) for config in record["pipelines"].values()]
    if (not locations or any(item != locations[0] for item in locations)
        or (record is previous and locations[0] != original)):
      raise ValueError("The repair's tunnel configuration differs between workers.")
    if locations[0] is None:
      if original is not None or rotate:
        raise ValueError("Repair requires one worker with one unambiguous main Cloudflare tunnel.")
      tokens.append(None)
      identities.append(None)
      continue
    instance, port, aliases = locations[0]
    identities.append((instance, port))
    values = [custodian._get_dauth_secret_fragment_value(fragment, prefix + list(alias)) for alias in aliases]
    if any(not found or not isinstance(value, str) for found, value in values) or len({value for _, value in values}) != 1:
      raise ValueError("The repair requires matching, explicit main tunnel credentials.")
    tokens.append(values[0][1])
    paths.append(aliases)
  if not rotate:
    if identities[0] != identities[1] or tokens[0] != tokens[1]:
      raise ValueError("Changing the repair's main tunnel requires explicit rotation approval.")
    return
  old, new = map(_connector, tokens)
  if identities[0] != identities[1] or old[:2] != new[:2] or old[2] == new[2]:
    raise ValueError("The replacement must rotate the same worker's existing Cloudflare tunnel.")
  for alias in paths[0]:  # Never create a new secret path on the previous executable.
    custodian._set_dauth_secret_fragment_value(previous["job_secrets"], prefix + list(alias), tokens[1])
