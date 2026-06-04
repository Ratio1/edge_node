from typing import Optional

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.0'

MESSAGE_PREFIX = "Please sign this message to manage your tunnels: "
MESSAGE_PREFIX_DEEPLOY = "Please sign this message for Deeploy: "

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  'PROCESS_DELAY': 5 * 60,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,

  'BASE_CLOUDFLARE_URL': 'https://api.cloudflare.com',
  'TCP_PROXY_URL': 'tcp.ratio1.link',
  'TCP_ROUTES_HKEY': 'tunnels_manager_tcp_routes',
  'TCP_PUBLIC_PORT_RANGE_START': 30000,
  'TCP_PUBLIC_PORT_RANGE_END': 30499,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

class TunnelsManagerPlugin(BasePlugin):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(TunnelsManagerPlugin, self).__init__(**kwargs)
    return

  def on_init(self):
    super(TunnelsManagerPlugin, self).on_init()
    self.chainstore_hsync(hkey="tunnels_manager_secrets")  # warm up the cache
    self._sync_tcp_routes()
    return

  def process(self):
    self._sync_tcp_routes()
    return

  def _tcp_route_key(self, public_port):
    return str(int(public_port))

  def _normalize_public_port(self, public_port):
    try:
      port = int(public_port)
    except (TypeError, ValueError):
      raise Exception(f"Invalid TCP public port: {public_port}")
    if port < 1 or port > 65535:
      raise Exception(f"Invalid TCP public port: {public_port}")
    return port

  def _tcp_public_range(self):
    start = int(self.cfg_tcp_public_port_range_start)
    end = int(self.cfg_tcp_public_port_range_end)
    if start < 1 or end > 65535 or end < start:
      raise Exception(f"Invalid TCP public port range: {start}-{end}")
    return start, end

  def _sync_tcp_routes(self):
    try:
      return self.chainstore_hsync(hkey=self.cfg_tcp_routes_hkey)
    except Exception as exc:
      self.P(f"Could not sync TCP route registry: {exc}", color="y")
    return None

  def _get_tcp_route_record(self, public_port):
    port = self._normalize_public_port(public_port)
    route = self.chainstore_hget(hkey=self.cfg_tcp_routes_hkey, key=self._tcp_route_key(port))
    return route if isinstance(route, dict) else None

  def _make_tcp_route_record(self, public_port, tunnel_id, hostname, alias):
    port = self._normalize_public_port(public_port)
    return {
      "public_port": port,
      "public_host": self.cfg_tcp_proxy_url,
      "public_endpoint": f"{self.cfg_tcp_proxy_url}:{port}",
      "tunnel_id": tunnel_id,
      "hostname": hostname,
      "alias": alias,
      "enabled": True,
    }

  def _is_tcp_route_record_owner(self, route, tunnel_id, hostname):
    return isinstance(route, dict) and route.get("tunnel_id") == tunnel_id and route.get("hostname") == hostname

  def _claim_tcp_route(self, tunnel_id, hostname, alias):
    start, end = self._tcp_public_range()
    tried_ports = set()
    max_attempts = end - start + 1

    while len(tried_ports) < max_attempts:
      port = int(self.np.random.randint(start, end + 1))
      if port in tried_ports:
        continue
      tried_ports.add(port)

      existing = self._get_tcp_route_record(port)
      if existing:
        continue

      route = self._make_tcp_route_record(
        public_port=port,
        tunnel_id=tunnel_id,
        hostname=hostname,
        alias=alias,
      )
      stored = self.chainstore_hset(
        hkey=self.cfg_tcp_routes_hkey,
        key=self._tcp_route_key(port),
        value=route,
      )
      if not stored:
        verified = self._get_tcp_route_record(port)
        if self._is_tcp_route_record_owner(verified, tunnel_id, hostname):
          self._delete_tcp_route(public_port=port, expected_tunnel_id=tunnel_id)
        continue

      verified = self._get_tcp_route_record(port)
      if self._is_tcp_route_record_owner(verified, tunnel_id, hostname):
        return verified

    raise Exception(f"No available TCP public ports in range {start}-{end}")

  def _delete_tcp_route(self, public_port, expected_tunnel_id=None):
    if public_port is None:
      return False
    port = self._normalize_public_port(public_port)
    route = self._get_tcp_route_record(port)
    if not isinstance(route, dict):
      return False
    if expected_tunnel_id is not None and route.get("tunnel_id") != expected_tunnel_id:
      raise Exception(f"Refusing to delete TCP route {port}: route belongs to tunnel {route.get('tunnel_id')}, not {expected_tunnel_id}")
    deleted = self.chainstore_hset(
      hkey=self.cfg_tcp_routes_hkey,
      key=self._tcp_route_key(port),
      value=None,
    )
    if not deleted:
      raise Exception(f"Could not delete TCP route {port}")
    return deleted

  def _attach_tcp_route_to_tunnel(self, tunnel):
    if not isinstance(tunnel, dict):
      return tunnel
    metadata = tunnel.get("metadata") or {}
    if metadata.get("type", "http") != "tcp":
      return tunnel
    public_port = metadata.get("tcp_public_port")
    if public_port is None:
      return tunnel
    route = self._get_tcp_route_record(public_port)
    if not route or route.get("tunnel_id") != tunnel.get("id"):
      return tunnel
    try:
      route = self.deepcopy(route)
    except Exception:
      route = dict(route)
    route["public_port"] = self._normalize_public_port(route["public_port"])
    tunnel["tcp_route"] = route
    tunnel["tcp_public_port"] = route["public_port"]
    tunnel["tcp_public_host"] = route["public_host"]
    tunnel["tcp_public_endpoint"] = route["public_endpoint"]
    return tunnel

  @BasePlugin.endpoint(method="get")
  def get_tcp_route(self, public_port: int):
    """
    Return only the Cloudflare origin hostname for a public TCP proxy port.
    """
    route = self._get_tcp_route_record(public_port)
    if not route or not route.get("enabled", True):
      raise Exception(f"No TCP route found for port {public_port}")
    hostname = route.get("hostname")
    if not hostname:
      raise Exception(f"TCP route for port {public_port} has no hostname")
    return hostname

  def _cloudflare_update_metadata(self, tunnel_id: str, metadata: dict, cloudflare_account_id: str, cloudflare_api_key: str):
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{tunnel_id}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}",
      "Accept": "application/json",
    }
    data = {
      "metadata": metadata
    }
    return self.requests.patch(url, headers=headers, json=data).json()

  def _format_cloudflare_errors(self, response):
    """
    Return a sanitized, user-actionable Cloudflare error string.

    Parameters
    ----------
    response : dict
        Parsed Cloudflare API response.

    Returns
    -------
    str
        Concise error text built from Cloudflare error/message fields.
    """
    if not isinstance(response, dict):
      return "invalid response from Cloudflare"

    errors = response.get("errors") or []
    messages = response.get("messages") or []
    if not isinstance(errors, (list, tuple)):
      errors = [errors]
    if not isinstance(messages, (list, tuple)):
      messages = [messages]
    parts = []

    for item in list(errors) + list(messages):
      if isinstance(item, dict):
        code = item.get("code")
        message = item.get("message") or item.get("error") or str(item)
        parts.append(f"{code}: {message}" if code else str(message))
      else:
        parts.append(str(item))

    if parts:
      return "; ".join(parts)
    return "Cloudflare returned an unsuccessful response"

  def _require_cloudflare_result(self, response, action, require_result=True):
    """
    Validate a Cloudflare API response before indexing into ``result``.

    Parameters
    ----------
    response : dict
        Parsed Cloudflare API response.
    action : str
        Human-readable operation name used in raised errors.
    require_result : bool, optional
        Whether a non-empty ``result`` value is required.

    Returns
    -------
    dict
        The validated Cloudflare ``result`` payload.
    """
    if not isinstance(response, dict):
      raise Exception(f"{action}: invalid response from Cloudflare")

    result = response.get("result")
    if response.get("success") is not True or (require_result and result is None):
      raise Exception(f"{action}: {self._format_cloudflare_errors(response)}")
    return result

  def _cleanup_partial_tunnel(self, cloudflare_account_id, cloudflare_zone_id, cloudflare_api_key, tunnel_id=None, dns_record_ids=None):
    """
    Best-effort cleanup for resources created before a tunnel setup failure.

    Parameters
    ----------
    cloudflare_account_id : str
        Cloudflare account id.
    cloudflare_zone_id : str
        Cloudflare zone id.
    cloudflare_api_key : str
        Cloudflare API token.
    tunnel_id : str, optional
        Created tunnel id to delete.
    dns_record_ids : list[str], optional
        Created DNS record ids to delete before deleting the tunnel.
    """
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}",
      "Accept": "application/json",
    }
    logger = getattr(self, "P", lambda *args, **kwargs: None)

    for dns_record_id in dns_record_ids or []:
      if not dns_record_id:
        continue
      try:
        url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{dns_record_id}"
        response = self.requests.delete(url, headers=headers).json()
        if isinstance(response, dict) and response.get("success") is False:
          logger(f"Cloudflare cleanup failed for DNS record {dns_record_id}: {self._format_cloudflare_errors(response)}", color="y")
      except Exception as exc:
        logger(f"Cloudflare cleanup raised while deleting DNS record {dns_record_id}: {exc}", color="y")

    if tunnel_id:
      try:
        url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{tunnel_id}"
        response = self.requests.delete(url, headers=headers).json()
        if isinstance(response, dict) and response.get("success") is False:
          logger(f"Cloudflare cleanup failed for tunnel {tunnel_id}: {self._format_cloudflare_errors(response)}", color="y")
      except Exception as exc:
        logger(f"Cloudflare cleanup raised while deleting tunnel {tunnel_id}: {exc}", color="y")
    return

  def _verify_nonce(self, hex_nonce: str):
    str_nonce = hex_nonce.replace("0x", "")
    try:
      scaled = int(str_nonce, 16)
    except:
      raise ValueError("Nonce is invalid!")
    _time = scaled / 1000
    diff = self.time() - _time
    if diff < 0:
      raise ValueError("Nonce is invalid(f)!")
    if diff > 12*60*60:
      raise ValueError("Nonce is expired!")      
    str_timestamp = self.time_to_str(_time)
    return str_timestamp

  @BasePlugin.endpoint(method="post")
  def get_secrets(self, payload: dict):
    """
    Get Cloudflare secrets for the sender address.
    """
    self._verify_nonce(payload['nonce'])
    sender = None
    signature_errors = []
    for prefix in (MESSAGE_PREFIX, MESSAGE_PREFIX_DEEPLOY):
      try:
        sender = self.bc.eth_verify_payload_signature(
          payload=payload,
          message_prefix=prefix,
          no_hash=True,
          indent=1,
          raise_if_error=True,
          verify_safe=True,
        )
        break
      except Exception as exc:
        signature_errors.append(str(exc))
    if sender is None:
      signature_errors_msg = "\n".join(signature_errors)
      raise Exception(f"Signature verification failed for provided payload: {signature_errors_msg}")
    secrets = self.chainstore_hget(hkey="tunnels_manager_secrets", key=sender)
    # TODO we should add a CSP password to be used as token in cstore
    if secrets is None:
      raise Exception("No secrets found for sender: " + sender)
    return secrets

  @BasePlugin.endpoint(method="post")
  def add_secrets(self, payload: dict):
    """
    Endpoint for CSP addresses to add their own Cloudflare secrets.
    """
    sender = self.bc.eth_verify_payload_signature(
      payload=payload,
      no_hash=True,
      indent=1,
      verify_safe=True,
    )
    secrets = {
      "cloudflare_api_key": payload['cloudflare_api_key'],
      "cloudflare_account_id": payload['cloudflare_account_id'],
      "cloudflare_zone_id": payload['cloudflare_zone_id'],
      "cloudflare_domain": payload['cloudflare_domain'],
    }
    self.chainstore_hset(hkey="tunnels_manager_secrets", key=sender, value=secrets)
    return {
      "success": True
    }

  @BasePlugin.endpoint(method="get")
  def check_secrets_exist(self, csp_address: str):
    """
    Public endpoint to check if Cloudflare secrets exist for a specific CSP address.
    Returns only whether secrets exist, not the actual secrets.
    """
    secrets = self.chainstore_hget(hkey="tunnels_manager_secrets", key=csp_address)
    return {
      "exists": secrets is not None
    }

  @BasePlugin.endpoint(method="post")
  def new_tunnel(self, alias: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str, tunnel_type: str = "http", service_name: Optional[str] = None,):
    """
    Create a new Cloudflare tunnel.

    Parameters:
    - alias: A user-friendly name for the tunnel.
    - cloudflare_account_id: The Cloudflare account ID.
    - cloudflare_zone_id: The Cloudflare zone ID.
    - cloudflare_api_key: The API key for Cloudflare authentication.
    - cloudflare_domain: The main domain associated with the Cloudflare account.
    - type: The type of tunnel ("http" or "tcp"). Default is "http".
    - service_name: Optional service name to prefix the tunnel ID.
    """
    if tunnel_type not in ["http", "tcp"]:
      raise Exception("Invalid tunnel type. Must be 'http' or 'tcp'.")

    tunnel_id = None
    dns_record_id = None
    tcp_route = None
    new_uuid = self.uuid()
    prefixes = []
    if service_name is not None:
      prefixes.append(service_name)
    new_id = f"{'-'.join(prefixes)}-{new_uuid}" if prefixes else new_uuid
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}",
      "Accept": "application/json",
    }

    try:
      url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel"
      data = {
        "name": new_id,
        "config_src": "local"
      }
      tunnel_info = self.requests.post(url, headers=headers, json=data).json()
      tunnel_result = self._require_cloudflare_result(tunnel_info, "Error creating tunnel")
      tunnel_id = tunnel_result.get("id")
      tunnel_token = tunnel_result.get("token")
      if not tunnel_id or not tunnel_token:
        raise Exception("Error creating tunnel: Cloudflare response is missing tunnel id or token")

      url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records"
      data = {
        "type": "CNAME",
        "proxied": True,
        "name": new_id,
        "content": f"{tunnel_id}.cfargotunnel.com",
      }
      dns_record = self.requests.post(url, headers=headers, json=data).json()
      dns_record_result = self._require_cloudflare_result(dns_record, "Error creating tunnel DNS record")
      dns_record_id = dns_record_result.get("id")
      if not dns_record_id:
        raise Exception("Error creating tunnel DNS record: Cloudflare response is missing DNS record id")

      if tunnel_type == "tcp":
        tcp_route = self._claim_tcp_route(
          tunnel_id=tunnel_id,
          hostname=f"{new_id}.{cloudflare_domain}",
          alias=alias,
        )

      metadata = {
        "alias": alias,
        "tunnel_token": tunnel_token,
        "dns_record_id": dns_record_id,
        "dns_name": f"{new_id}.{cloudflare_domain}",
        "custom_hostnames": [],
        "type": tunnel_type,
        "creator": "ratio1"
      }
      if tcp_route is not None:
        metadata.update({
          "tcp_public_port": tcp_route["public_port"],
          "tcp_public_host": tcp_route["public_host"],
          "tcp_public_endpoint": tcp_route["public_endpoint"],
        })

      res = self._cloudflare_update_metadata(
        tunnel_id=tunnel_id,
        metadata=metadata,
        cloudflare_account_id=cloudflare_account_id,
        cloudflare_api_key=cloudflare_api_key
      )
      result = self._require_cloudflare_result(res, "Error updating tunnel metadata")
      if isinstance(result, dict):
        result_metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        result_metadata.update(metadata)
        result["metadata"] = result_metadata
        if tcp_route is not None:
          result["tcp_route"] = tcp_route
          result["tcp_public_port"] = tcp_route["public_port"]
          result["tcp_public_host"] = tcp_route["public_host"]
          result["tcp_public_endpoint"] = tcp_route["public_endpoint"]
      return result
    except Exception:
      if tcp_route is not None:
        try:
          self._delete_tcp_route(
            public_port=tcp_route["public_port"],
            expected_tunnel_id=tunnel_id,
          )
        except Exception as exc:
          self.P(f"TCP route cleanup failed for tunnel {tunnel_id}: {exc}", color="y")
      self._cleanup_partial_tunnel(
        cloudflare_account_id=cloudflare_account_id,
        cloudflare_zone_id=cloudflare_zone_id,
        cloudflare_api_key=cloudflare_api_key,
        tunnel_id=tunnel_id,
        dns_record_ids=[dns_record_id],
      )
      raise

  @BasePlugin.endpoint(method="get")
  def get_tunnels(self, cloudflare_account_id: str, cloudflare_api_key: str):
    """
    Get a list of all Cloudflare tunnels for the specified account.
    """
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel?is_deleted=false"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.get(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error fetching tunnels: " + str(response['errors']))
    result = response['result']
    if isinstance(result, list):
      for tunnel in result:
        self._attach_tcp_route_to_tunnel(tunnel)
    return result

  @BasePlugin.endpoint(method="get")
  def get_tunnel(self, tunnel_id: str, cloudflare_account_id: str, cloudflare_api_key: str):
    """
    Get details for a specific Cloudflare tunnel based on its ID.
    """
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{tunnel_id}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.get(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error fetching tunnel: " + str(response['errors']))
    return self._attach_tcp_route_to_tunnel(response['result'])

  @BasePlugin.endpoint(method="get")
  def get_tunnel_by_token(self, tunnel_token: str, cloudflare_account_id: str, cloudflare_api_key: str):
    """
    Get tunnel details using its tunnel token.
    """
    tunnels = self.get_tunnels(cloudflare_account_id, cloudflare_api_key)
    for tunnel in tunnels:
      metadata = tunnel.get('metadata', {})
      if metadata.get('tunnel_token') == tunnel_token:
        return tunnel
    raise Exception("Tunnel not found for provided token.")

  @BasePlugin.endpoint(method="delete")
  def delete_tunnel(self, tunnel_id: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str):
    """
    Delete a Cloudflare tunnel and its associated DNS record.
    This will fail if the tunnel has custom hostnames still connected.
    """
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)

    metadata = value.get('metadata', {})
    if (len(metadata.get('custom_hostnames', [])) > 0):
      raise Exception("Cannot delete tunnel with custom hostnames. Please remove them first.")

    is_tcp_tunnel = metadata.get('type', 'http') == "tcp"
    tcp_public_port = metadata.get("tcp_public_port") if is_tcp_tunnel else None

    # Delete the DNS record first
    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{metadata['dns_record_id']}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error deleting DNS record: " + str(response['errors']))

    # Then delete the tunnel
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{value['id']}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error deleting tunnel: " + str(response['errors']))

    if is_tcp_tunnel:
      self._delete_tcp_route(public_port=tcp_public_port, expected_tunnel_id=value['id'])

    return {
      "success": True,
    }

  @BasePlugin.endpoint(method="post")
  def add_custom_hostname(self, tunnel_id: str, hostname: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str):
    """
    Add a new custom hostname for a specific tunnel based on its ID.
    """
    if hostname.endswith(cloudflare_domain):
      raise Exception(f"Hostname cannot be a subdomain of the main domain {cloudflare_domain}. Use add_alias instead.")
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)
    if value is None:
      raise Exception(f"Tunnel {tunnel_id} not found.")
    if hostname in value['metadata']['custom_hostnames']:
      raise Exception(f"Hostname {hostname} already exists for tunnel {tunnel_id}.")
    if value['metadata'].get('type', 'http') == "tcp":
      raise Exception("Custom hostnames are not supported for TCP tunnels.")

    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/custom_hostnames"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    data = {
      "hostname": hostname,
      "ssl": {
        "method": "http",
        "type": "dv"
      },
      "custom_origin_server": value['metadata']['dns_name'],
    }
    response = self.requests.post(url, headers=headers, json=data).json()
    if response["success"] is False:
      raise Exception("Error adding custom hostname: " + str(response['errors']))

    value['metadata']['custom_hostnames'].append({
      "id": response['result']['id'],
      "hostname": hostname
    })
    self._cloudflare_update_metadata(
      tunnel_id=tunnel_id,
      metadata=value['metadata'],
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )

    return {
      "success": True,
    }

  @BasePlugin.endpoint(method="delete")
  def delete_custom_hostname(self, tunnel_id: str, hostname_id: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str):
    """
    Remove a custom hostname from a specific tunnel based on its ID.
    """
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)
    if value is None:
      raise Exception(f"Tunnel {tunnel_id} not found.")

    custom_hostname = next((ch for ch in value['metadata']['custom_hostnames'] if ch['id'] == hostname_id), None)
    if custom_hostname is None:
      raise Exception(f"Custom hostname {hostname_id} not found for tunnel {tunnel_id}.")

    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/custom_hostnames/{hostname_id}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error removing custom hostname: " + str(response['errors']))

    value['metadata']['custom_hostnames'].remove(custom_hostname)
    self._cloudflare_update_metadata(
      tunnel_id=tunnel_id,
      metadata=value['metadata'],
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )

    return {
      "success": True,
    }
  
  @BasePlugin.endpoint(method="post")
  def add_alias(self, tunnel_id: str, alias: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str):
    """
    Add a new alias (CNAME) on the same domain for a specific tunnel based on its ID.
    """
    if not alias.endswith(cloudflare_domain):
      raise Exception(f"Alias must be a subdomain of the main domain {cloudflare_domain}. Use add_custom_hostname instead.")
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)
    if value is None:
      raise Exception(f"Tunnel {tunnel_id} not found.")

    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    tunnel_type = value['metadata'].get('type', 'http')
    data = {
      "type": "CNAME",
      "proxied": True,
      "name": alias,
      "content": f"{value['id']}.cfargotunnel.com",
    }
    dns_record = self.requests.post(url, headers=headers, json=data).json()
    if dns_record["success"] is False:
      raise Exception("Error creating alias: " + str(dns_record['errors']))

    if 'aliases' not in value['metadata']:
      value['metadata']['aliases'] = []
    alias_metadata = {
      "id": dns_record['result']['id'],
      "name": alias,
      "type": "origin" if tunnel_type == "tcp" else "dns",
    }
    value['metadata']['aliases'].append(alias_metadata)
    self._cloudflare_update_metadata(
      tunnel_id=tunnel_id,
      metadata=value['metadata'],
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )
    return {
      "success": True,
    }

  @BasePlugin.endpoint(method="delete")
  def delete_alias(self, tunnel_id: str, alias_id: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str):
    """
    Remove an alias (CNAME) from a specific tunnel based on its ID.
    """
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)
    if value is None:
      raise Exception(f"Tunnel {tunnel_id} not found.")

    if 'aliases' not in value['metadata']:
      raise Exception(f"No aliases found for tunnel {tunnel_id}.")

    alias = next((a for a in value['metadata']['aliases'] if a['id'] == alias_id), None)
    if alias is None:
      raise Exception(f"Alias {alias_id} not found for tunnel {tunnel_id}.")

    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{alias_id}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error deleting alias: " + str(response['errors']))
    
    if alias.get('public_id') is not None:
      url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{alias['public_id']}"
      headers = {
        "Authorization": f"Bearer {cloudflare_api_key}"
      }
      response = self.requests.delete(url, headers=headers).json()
      if response["success"] is False:
        raise Exception("Error deleting public alias: " + str(response['errors']))

    value['metadata']['aliases'].remove(alias)
    self._cloudflare_update_metadata(
      tunnel_id=tunnel_id,
      metadata=value['metadata'],
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )

    return {
      "success": True,
    }

  @BasePlugin.endpoint(method="post")
  def rename_tunnel(self, tunnel_id: str, new_alias: str, cloudflare_account_id: str, cloudflare_api_key: str):
    """
    Change the alias from a specific tunnel based on its ID.
    """
    value = self.get_tunnel(tunnel_id, cloudflare_account_id, cloudflare_api_key)
    if value is None:
      raise Exception(f"Tunnel {tunnel_id} not found.")

    value['metadata']['alias'] = new_alias
    self._cloudflare_update_metadata(
      tunnel_id=tunnel_id,
      metadata=value['metadata'],
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )
    return {
      "success": True
    }
