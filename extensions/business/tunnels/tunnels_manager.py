from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.1.0'

MESSAGE_PREFIX = "Please sign this message to manage your tunnels: "
MESSAGE_PREFIX_DEEPLOY = "Please sign this message for Deeploy: "

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,

  'BASE_CLOUDFLARE_URL': 'https://api.cloudflare.com',

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
    return

  def _cloudflare_update_metadata(self, tunnel_id: str, metadata: dict, cloudflare_account_id: str, cloudflare_api_key: str):
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel/{tunnel_id}"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    data = {
      "metadata": metadata
    }
    return self.requests.patch(url, headers=headers, json=data).json()

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
        )
        break
      except Exception as exc:
        signature_errors.append(str(exc))
    if sender is None:
      raise Exception(f"Signature verification failed for provided payload: {signature_errors}")
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
  def new_tunnel(self, alias: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str, service_name: str | None = None,):
    """
    Create a new Cloudflare tunnel.
    """
    new_uuid = self.uuid()
    new_id = f"{service_name}-{new_uuid}" if service_name is not None else new_uuid
    url = f"{self.cfg_base_cloudflare_url}/client/v4/accounts/{cloudflare_account_id}/cfd_tunnel"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    data = {
      "name": new_id,
      "config_src": "local"
    }
    tunnel_info = self.requests.post(url, headers=headers, json=data).json()
    if tunnel_info["success"] is False:
      raise Exception("Error creating tunnel: " + str(tunnel_info['errors']))

    url = f"{self.cfg_base_cloudflare_url}/client/v4/zones/{cloudflare_zone_id}/dns_records"
    headers = {
      "Authorization": f"Bearer {cloudflare_api_key}"
    }
    data = {
      "type": "CNAME",
      "proxied": True,
      "name": new_id,
      "content": f"{tunnel_info['result']['id']}.cfargotunnel.com",
    }
    dns_record = self.requests.post(url, headers=headers, json=data).json()

    res = self._cloudflare_update_metadata(
      tunnel_id=tunnel_info['result']['id'],
      metadata={
        "alias": alias,
        "tunnel_token": tunnel_info['result']['token'],
        "dns_record_id": dns_record['result']['id'],
        "dns_name": f"{new_id}.{cloudflare_domain}",
        "custom_hostnames": [],
        "creator": "ratio1"
      },
      cloudflare_account_id=cloudflare_account_id,
      cloudflare_api_key=cloudflare_api_key
    )
    return res['result']

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
    value['metadata']['aliases'].append({
      "id": dns_record['result']['id'],
      "name": alias
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
