from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.2.2'

MESSAGE_PREFIX = "Please sign this message to manage your tunnels: "
MESSAGE_PREFIX_DEEPLOY = "Please sign this message for Deeploy: "

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,

  'BASE_CLOUDFLARE_URL': 'https://api.cloudflare.com',
  'TCP_PROXY_URL': 'tcp.ratio1.link',
  'TCP_PREFIX': 'cft',

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
    return

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
  def new_tunnel(self, alias: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str, tunnel_type: str = "http", service_name: str | None = None,):
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
    dns_record_public_id = None
    new_uuid = self.uuid()
    prefixes = []
    if tunnel_type == "tcp":
      prefixes.append(self.cfg_tcp_prefix)
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

      public_name = None
      if tunnel_type == "tcp":
        # TCP tunnels need a second public CNAME that points at the TCP proxy.
        public_name = new_id.removeprefix(f"{self.cfg_tcp_prefix}-")
        data_public = {
          "type": "CNAME",
          "proxied": True,
          "name": public_name,
          "content": self.cfg_tcp_proxy_url,
        }
        dns_record_public = self.requests.post(url, headers=headers, json=data_public).json()
        dns_record_public_result = self._require_cloudflare_result(dns_record_public, "Error creating TCP tunnel public DNS record")
        dns_record_public_id = dns_record_public_result.get("id")
        if not dns_record_public_id:
          raise Exception("Error creating TCP tunnel public DNS record: Cloudflare response is missing DNS record id")

      res = self._cloudflare_update_metadata(
        tunnel_id=tunnel_id,
        metadata={
          "alias": alias,
          "tunnel_token": tunnel_token,
          "dns_record_id": dns_record_id,
          "dns_name": f"{new_id}.{cloudflare_domain}",
          "dns_record_public_id": dns_record_public_id,
          "dns_public_name": f"{public_name}.{cloudflare_domain}" if public_name else None,
          "custom_hostnames": [],
          "type": tunnel_type,
          "creator": "ratio1"
        },
        cloudflare_account_id=cloudflare_account_id,
        cloudflare_api_key=cloudflare_api_key
      )
      return self._require_cloudflare_result(res, "Error updating tunnel metadata")
    except Exception:
      self._cleanup_partial_tunnel(
        cloudflare_account_id=cloudflare_account_id,
        cloudflare_zone_id=cloudflare_zone_id,
        cloudflare_api_key=cloudflare_api_key,
        tunnel_id=tunnel_id,
        dns_record_ids=[dns_record_public_id, dns_record_id],
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
    return response['result']

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
    return response['result']

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

    if (len(value['metadata']['custom_hostnames']) > 0):
      raise Exception("Cannot delete tunnel with custom hostnames. Please remove them first.")

    # Delete the DNS record first
    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{value['metadata']['dns_record_id']}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error deleting DNS record: " + str(response['errors']))

    # Also delete the public DNS record for TCP tunnels
    if value['metadata'].get('type', 'http') == "tcp":
      url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records/{value['metadata']['dns_record_public_id']}"
      headers = {
        "Authorization": f"Bearer {cloudflare_api_key}"
      }
      response = self.requests.delete(url, headers=headers).json()
      if response["success"] is False:
        raise Exception("Error deleting public DNS record: " + str(response['errors']))

    # Then delete the tunnel
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{value['id']}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    response = self.requests.delete(url, headers=headers).json()
    if response["success"] is False:
      raise Exception("Error deleting tunnel: " + str(response['errors']))

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
    prefix = f"{self.cfg_tcp_prefix}-" if tunnel_type == "tcp" else ""
    data = {
      "type": "CNAME",
      "proxied": True,
      "name": f"{prefix}{alias}",
      "content": f"{value['id']}.cfargotunnel.com",
    }
    dns_record = self.requests.post(url, headers=headers, json=data).json()
    if dns_record["success"] is False:
      raise Exception("Error creating alias: " + str(dns_record['errors']))

    if tunnel_type == "tcp":
      data_public = {
        "type": "CNAME",
        "proxied": True,
        "name": alias,
        "content": self.cfg_tcp_proxy_url,
      }
      dns_record_public = self.requests.post(url, headers=headers, json=data_public).json()
      if dns_record_public["success"] is False:
        raise Exception("Error creating public alias: " + str(dns_record_public['errors']))

    if 'aliases' not in value['metadata']:
      value['metadata']['aliases'] = []
    value['metadata']['aliases'].append({
      "id": dns_record['result']['id'],
      "name": alias,
      "public_id": dns_record_public['result']['id'] if tunnel_type == "tcp" else None,
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
