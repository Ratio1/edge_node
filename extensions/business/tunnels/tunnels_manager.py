from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.0.1'

MESSAGE_PREFIX = "Please sign this message to manage your tunnels: "

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,

  'BASE_CLOUDFLARE_URL': 'https://api.cloudflare.com',

  'ADMIN_ADDRESSES': [
    '0x95E9EeEf459a9cDA096af7C6033D4d9582B9513c',
    '0xDA05C48CDbA9A67A422cFA40b4C0F6b7FFB0E4a5',
    '0xA59eF3f6B10723577e7F8966dC88670233B8a0d5',
    '0x13a457188877781AF4263109296312AAbE6A2905',
    ''
  ],

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
    sender = self.bc.eth_verify_payload_signature(
      payload=payload,
      message_prefix=MESSAGE_PREFIX,
      no_hash=True,
      indent=1,
    )
    secrets = self.chainstore_hget(hkey="tunnels_manager_secrets", key=sender)
    if secrets is None:
      raise Exception("No secrets found for sender: " + sender)
    return secrets

  @BasePlugin.endpoint(method="post")
  def add_secrets(self, payload: dict):
    """
    Admin endpoint to add Cloudflare secrets for a specific address.
    """
    sender = self.bc.eth_verify_payload_signature(
      payload=payload,
      no_hash=True,
      indent=1,
    )
    admin_addresses = self.cfg_admin_addresses
    if sender not in admin_addresses:
      raise Exception(f"Sender {sender} is not authorized to add secrets.")
    secrets = {
      "cloudflare_api_key": payload['cloudflare_api_key'],
      "cloudflare_account_id": payload['cloudflare_account_id'],
      "cloudflare_zone_id": payload['cloudflare_zone_id'],
      "cloudflare_domain": payload['cloudflare_domain'],
    }
    self.chainstore_hset(hkey="tunnels_manager_secrets", key=payload['csp_address'], value=secrets)
    return {
      "success": True
    }

  @BasePlugin.endpoint(method="post")
  def new_tunnel(self, alias: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str, cloudflare_domain: str):
    """
    Create a new Cloudflare tunnel.
    """
    new_id = self.uuid()
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
  def add_custom_hostname(self, tunnel_id: str, hostname: str, cloudflare_account_id: str, cloudflare_zone_id: str, cloudflare_api_key: str):
    """
    Add a new custom hostname for a specific tunnel based on its ID.
    """
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
