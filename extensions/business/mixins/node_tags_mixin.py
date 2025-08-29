from naeural_core import constants as ct

class _NodeTagsMixin(object):
  def __init__(self):
    super(_NodeTagsMixin, self).__init__()
    return

  def get_ee_nodetag_kyb(self, node_address):
    """
    Get the EE_NODETAG_KYB tag for node_address.
    Returns a tuple of (tag_name, tag_value).
    """
    base_url = self.bc.get_network_data().get(ct.HB.EE_NODETAG_KYB)
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

    return ct.HB.EE_NODETAG_KYB, is_kyb

  def get_ee_nodetag_datacenter(self, node_address):
    """
    Get the EE_NODETAG_KYB tag for node_address.
    Returns a tuple of (tag_name, tag_value).
    """
    base_url = self.bc.get_network_data().get(ct.HB.EE_NODETAG_KYB)
    url = "".join([base_url, "/accounts/is-datacenter"])
    # mock for now, as no backend endpoint exists
    params = {
      "walletAddress": node_address,
    }
    response = self.requests.get(url, params=params)
    is_datacenter = False
    if response.status_code == 200:
      try:
        if node_address in ["0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g", "Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"]:
          is_datacenter = True
      except Exception as e:
        self.P("Error parsing JSON response: {}".format(e), color='r')
    else:
      self.P("Could not fetch is_datacenter for wallet {}. Response status code: {}".format(
        node_address,
        response.status_code
      ))

    return ct.HB.EE_NODETAG_DATACENTER, is_datacenter
