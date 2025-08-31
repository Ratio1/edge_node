from naeural_core import constants as ct

class _NodeTagsMixin(object):
  def __init__(self):
    super(_NodeTagsMixin, self).__init__()
    return

  def get_allowed_node_tags_list(self):
    """Get all available node tag method names as an array of strings"""
    allowed_tags = []
    
    # Get all methods that follow the pattern get_ee_nodetag_{tag_name}
    for method_name in dir(self):
      if method_name.lower().startswith('get_ee_nodetag_'):
        # Extract the tag name from the method name and format it as EE_NODETAG_{TAG_NAME}
        tag_name = method_name.replace('get_', '')
        formatted_tag = f"{tag_name.upper()}"
        allowed_tags.append(formatted_tag)
    
    return allowed_tags

  def fetch_node_tags(self, node_address):
    """Get all available node tags for a given address"""
    tags = {}

    # Get all methods that follow the pattern get_ee_nodetag_{tag_name}
    for method_name in dir(self):
      if method_name.startswith('get_ee_nodetag_'):
        tag_name = method_name.replace('get_', '').upper()
        method = getattr(self, method_name)
        if callable(method):
          try:
            tag_value = method(node_address)
            tags[tag_name] = tag_value
          except Exception as e:
            self.P(f"Error getting tag {tag_name}: {e}", color='r')
    return tags

  def get_ee_nodetag_kyb(self, node_address):
    """
    Get the EE_NODETAG_KYB tag for node_address.
    Returns tag_value.
    """
    base_url = self.bc.get_network_data().get(self.const.BASE_CT.dAuth.EvmNetData.EE_DAPP_API_URL_KEY)

    url = "".join([base_url, "/accounts/is-kyb"])
    params = {
      "walletAddress": node_address,
    }
    response = self.requests.get(url, params=params)
    is_kyb = False
    if response.status_code == 200:
      try:
        json = response.json()
        is_kyb = json.get("data", False)
      except Exception as e:
        self.P("Error parsing JSON response: {}".format(e), color='r')
    else:
      self.P("Could not fetch is_kyb for wallet {}. Response status code: {}".format(
        node_address,
        response.status_code
      ))

    return is_kyb
