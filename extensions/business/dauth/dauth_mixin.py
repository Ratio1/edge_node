"""
dauth_mixin.py
==============

This module contains the dAuth mixin class that handles the decentralized authentication process.
This mixin is responsible for processing dAuth requests and performin various checks such as:
- default verification of the request signature (via de public key empeddedn in the rrquester node address)
- checking using EVM smart-contract if the node is linked to a valid on-chain license
- checking the version of the node that is sending the request
- checking if the node is a oracle node (including a seed node)
- other heuristic checks
This module is part of the Ratio1e ecosystem and is used in conjunction with the dAuth manager
plugin to provide a complete decentralized authentication solution.

"""


def version_to_int(version):
  """
  Convert a version string to an integer.
  """
  val = 0
  if version is not None:
    try:
      parts = version.strip().split('.')
      for i, part in enumerate(reversed(parts)):
        val += int(part) * (1000 ** i)
    except:
      pass
  return val

class _DotDict(dict):
  __getattr__ = dict.__getitem__
  __setattr__ = dict.__setitem__
  __delattr__ = dict.__delitem__
  
  
class VersionCheckData(_DotDict):
  """
  Data class for version check.
  """
  def __init__(self, result=False, message="", requester_type=None):
    self.result = result
    self.message = message
    self.requester_type = requester_type
    return
  
### START OF MIXIN ###

class _DauthMixin(object):

  def __init__(self):
    super(_DauthMixin, self).__init__()    
    return

  def Pd(self, s, *args, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_dauth_verbose:
      s = "[dDBG] " + s
      self.P(s, *args, **kwargs)
    return  
  
  def is_seed_node(self):
    """
    Check if this is a seed node via a heuristic.
    """
    url = self.os_environ.get(self.const.BASE_CT.dAuth.EvmNetData.DAUTH_URL_KEY)
    if isinstance(url, str) and not url.startswith("http"):
      # if the url is not a http url, we assume this is a seed node
      return True
    return False

  
  def version_check(
    self, 
    sender_app_version : str,
    sender_core_version : str,
    sender_sdk_version : str
  ):
    """
    Check the version of the node that is sending the request.
    Returns `None` if all ok and a message if there is a problem.
    
    
    """    
    #
    output = VersionCheckData(result=True, message="")
    dAuthCt = self.const.BASE_CT.dAuth
    int_sender_app_version = version_to_int(sender_app_version)
    int_sender_core_version = version_to_int(sender_core_version)
    int_sender_sdk_version = version_to_int(sender_sdk_version)
    int_server_app_version = version_to_int(self.ee_ver)
    int_server_core_version = version_to_int(self.ee_core_ver)
    int_server_sdk_version = version_to_int(self.ee_sdk_ver)
    
    if int_sender_app_version == 0 and int_sender_core_version == 0 and int_sender_sdk_version > 0:
      output.requester_type = dAuthCt.DAUTH_SENDER_TYPE_SDK
      output.message += f"INFO: SDK v{sender_sdk_version} accepted for dAuth request."
    elif int_sender_app_version == 0 and int_sender_core_version >0 and int_sender_sdk_version > 0:
      output.requester_type = dAuthCt.DAUTH_SENDER_TYPE_CORE
      output.result = False # we should block this
      output.message = "FAIL: Invalid sender version data - core and sdk only not allowed for dAuth"
    elif int_sender_app_version > 0 and int_sender_core_version > 0 and int_sender_sdk_version > 0:
      output.requester_type = dAuthCt.DAUTH_SENDER_TYPE_NODE
      output.message += f"INFO: Edge Node v{sender_app_version} pre-accepted for dAuth request."
    else:
      output.requester_type = "unknown"
      output.result = False
      output.message = "FAIL: Invalid sender version data: {} {} {} vs this server: {} {} {}".format(
        sender_app_version, sender_core_version, sender_sdk_version,
        self.ee_ver, self.ee_core_ver, self.ee_sdk_ver
      )
    
    if int_sender_app_version > 0 and int_sender_app_version < int_server_app_version:
      output.message += f" WARNING: Sender app version {sender_app_version} is lower than server app version {self.ee_ver}."
      diff = int_server_app_version - int_sender_app_version
      if diff >= 10:
        output.result = False
        output.message = f" FAIL: Sender app version {sender_app_version} is too old (diff: {diff})."
    #end app version check
      
    if int_sender_core_version > 0 and int_sender_core_version < int_server_core_version:
      output.message += f" WARNING: Sender core version {sender_core_version} is lower than server core version {self.ee_core_ver}."
      # maybe we should block below a certain level
      
    if int_sender_sdk_version > 0 and int_sender_sdk_version < int_server_sdk_version:
      output.message += f" WARNING: Sender sdk version {sender_sdk_version} is lower than server sdk version {self.ee_sdk_ver}."
    elif int_sender_sdk_version != int_server_sdk_version:
      output.message += f" INFO: Sender sdk version {sender_sdk_version} is different from server sdk version {self.ee_sdk_ver}."
      # maybe we should block below a certain level
    return output
  
  def check_if_node_allowed(
    self, 
    node_address : str, 
    node_address_eth : str, 
    version_check_data : VersionCheckData
  ):
    """
    Check if the node address is allowed to request authentication data.
    """
    self.Pd(f"Checking if node {node_address} (ETH: {node_address_eth}) is allowed")
    msg = ""
    result = True    
    if not version_check_data.result:
      result = False
      msg = "Version check failed: {}".format(version_check_data.message)
    else:
      try:
        if version_check_data.requester_type != self.const.BASE_CT.dAuth.DAUTH_SENDER_TYPE_SDK:
          result = self.bc.is_node_licensed(node_address_eth=node_address_eth)
          str_allowed = "allowed" if result else "not allowed"
          msg = f"node {node_address_eth} {str_allowed} on {self.evm_network}"
      except Exception as e:
        result = False
        msg = "Error checking if node is allowed ({} on {}): {} ".format(
          node_address_eth, self.evm_network, e
        )
    return result, msg
  
  
  def chainstore_store_dauth_request(
    self, 
    node_address : str, 
    node_address_eth : str, 
    dauth_data : dict,
    sender_nonce : str,
  ):
    """
    Set the chainstore data for the requester.
    
    
    """
    self.Pd("CSTORE dAuth request '{}' data for node {} ({})".format(
      sender_nonce, node_address, node_address_eth)
    )
    return
  
  
  def fill_dauth_data(self,
                      dauth_data,
                      requester_node_address,
                      is_node=False,
                      sender_eth_address=None):
    """
    Fill the data with the authentication data.
    """
    dAuthCt = self.const.BASE_CT.dAuth
    
    ## TODO: review this section:
    ##         maybe we should NOT use the default values or maybe we should just use the default values
    lst_auth_env_keys = self.cfg_auth_env_keys
    lst_auth_node_only_keys = self.cfg_auth_node_env_keys
    dct_auth_predefined_keys = self.cfg_auth_predefined_keys
    
    default_env_keys = self.const.ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_ENV_KEYS"]
    default_node_only_keys = self.const.ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_NODE_ENV_KEYS"]
    default_predefined_keys = self.const.ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_PREDEFINED_KEYS"]

    lst_auth_env_keys = list(set(lst_auth_env_keys + default_env_keys))
    lst_auth_node_only_keys = list(set(lst_auth_node_only_keys + default_node_only_keys))
    dct_auth_predefined_keys = {**dct_auth_predefined_keys, **default_predefined_keys}
    
    if lst_auth_env_keys is None:
      raise ValueError("No auth env keys defined (AUTH_ENV_KEYS==null). Please check the configuration!")
    
    if dct_auth_predefined_keys is None:
      raise ValueError("No predefined keys defined (AUTH_PREDEFINED_KEYS==null). Please check the configuration")
    
    full_whitelist = []
    oracles = []
    if is_node:
      ### get the mandatory oracles whitelist and populate answer  ###  
      oracles, oracles_names, oracles_eth = self.bc.get_oracles(include_eth_addrs=True)   
      if len(oracles_eth) > 0 and len(oracles) == 0:
        self.P(f"Oracle check failed: found ETH oracles {oracles_eth} but conversion to nodes failed.", color='r')
      else:
        self.Pd(f"Oracles on {self.evm_network}: {oracles_eth}")
      full_whitelist = [
        a + (f"  {b}" if len(b) > 0 else "") 
        for a, b in zip(oracles, oracles_names)
      ]
    
      # normally this used to be ran only if the current node is a seed oracle however
      # this means that auto-oracles will NOT send their whitelist (which where receved
      # from the seed oracle) to the other nodes thus creating a problem
      wl, aliases = self.bc.get_whitelist_with_names()
      for _node, _alias in zip(wl, aliases):
        if _node not in oracles:
          full_whitelist.append(_node + (f"  {_alias}" if len(_alias) > 0 else ""))
    # end if is_node
    
    dauth_data[dAuthCt.DAUTH_WHITELIST] = full_whitelist

    #####  finally prepare the env auth data #####
    
    # first set is the universal (node, sdk, core) keys
    for key in lst_auth_env_keys:
      if key.startswith(dAuthCt.DAUTH_ENV_KEYS_PREFIX) and key not in lst_auth_node_only_keys:
        dauth_data[key] = self.os_environ.get(key)
        
    if is_node:
      # then set the node-only keys
      for key in lst_auth_node_only_keys:
        if key.startswith(dAuthCt.DAUTH_ENV_KEYS_PREFIX):
          dauth_data[key] = self.os_environ.get(key)
      # end for
    
    # overwrite the predefined keys
    for key in dct_auth_predefined_keys:
      dauth_data[key] = dct_auth_predefined_keys[key]

    # set node tags
    tags = self.get_node_tags(sender_eth_address=sender_eth_address)
    if isinstance(tags, dict) and len(tags) > 0:
      for key, value in tags.items():
        self.P("Tag: {}={}".format(key, value))
        if isinstance(key, str) and key.startswith(dAuthCt.DAUTH_ENV_KEYS_PREFIX):
          dauth_data[key] = value

    # end set node tags

    # set the supervisor flag if this is identified as an oracle
    if is_node and requester_node_address in oracles:
      dauth_data["EE_SUPERVISOR"] = True
      for key in self.cfg_supervisor_keys:
        if isinstance(key, str) and len(key) > 0:
          dauth_data[key] = self.os_environ.get(key)
        # end if
      # end for
    else:
      dauth_data["EE_SUPERVISOR"] = False
    # end set supervisor flag

    return dauth_data


  def fill_extra_info(
    self, 
    data : dict, 
    sender_eth_address : str, 
    body : dict,
    version_check_data : VersionCheckData
  ):
    """
    Fill the data with the extra information.
    """
    dAuthConst = self.const.BASE_CT.dAuth
    requester = body.get(self.const.BASE_CT.BCctbase.SENDER)

      
    data[dAuthConst.DAUTH_SERVER_INFO] = {
      dAuthConst.DAUTH_SENDER_ETH : sender_eth_address,
      dAuthConst.DAUTH_SENDER_TYPE : version_check_data.requester_type,
      dAuthConst.DAUTH_SERVER_IS_SEED : self.is_seed_node(),
      # "info" : str(version_check_data), 
    }

    if self.cfg_dauth_verbose:
      data[dAuthConst.DAUTH_REQUEST] = body

    return data
  
  
  
  def process_dauth_request(self, body):
    """
    This is the main method that processes the request for authentication.
    """
    error = None
    _non_critical_error = None
    requester_eth = None
    version_check_data = VersionCheckData(result=False, message="", requester_type=None)
        
    dAuthConst = self.const.BASE_CT.dAuth
    
    data = {
      dAuthConst.DAUTH_SUBKEY : {
        'error' : None,
      },
    }
    dct_dauth = data[dAuthConst.DAUTH_SUBKEY]
    
    sender_nonce = body.get(dAuthConst.DAUTH_NONCE)
    
    requester = body.get(self.const.BASE_CT.BCctbase.SENDER)
    requester_send_eth = body.get(self.const.BASE_CT.BCctbase.ETH_SENDER)
    requester_alias = body.get("sender_alias")
    
    sender_app_version = body.get(dAuthConst.DAUTH_SENDER_APP_VER)
    sender_core_version = body.get(dAuthConst.DAUTH_SENDER_CORE_VER)
    sender_sdk_version = body.get(dAuthConst.DAUTH_SENDER_SDK_VER)            
                
    if requester is None:
      error = 'No sender address in request.'
      
    if error is None:
      try:
        requester_eth = self.bc.node_address_to_eth_address(requester)
        if requester_eth != requester_send_eth:
          error = 'Sender eth address and recovered eth address do not match.'  
        else:
          self.Pd("dAuth req from '{}' <{}> | <{}>, app:{}, core:{}, sdk:{}".format(
            requester_alias, requester, requester_eth,
            sender_app_version, sender_core_version, sender_sdk_version
          ))
      except Exception as e:
        error = 'Error converting node address to eth address: {}'.format(e)
    
    ###### verify the request signature ######
    if error is None:
      verify_data = self.bc.verify(body, return_full_info=True)
      if not verify_data.valid:
        error = 'Invalid request signature: {}'.format(verify_data.message)

    ###### basic version checks ######
    if error is None:
      version_check_data : VersionCheckData = self.version_check(
        sender_app_version=sender_app_version,
        sender_core_version=sender_core_version,
        sender_sdk_version=sender_sdk_version
      )
      if not version_check_data.result:
        # not None means we have a error message
        error = 'Version check failed: {}'.format(version_check_data.message)
      elif version_check_data.message not in [None, '']:
        _non_critical_error = version_check_data.message

    is_requester_a_node = version_check_data.requester_type == dAuthConst.DAUTH_SENDER_TYPE_NODE
    
    ###### check if node_address is allowed ######   
    if error is None:
      allowed_to_dauth, message = self.check_if_node_allowed(
        node_address=requester, node_address_eth=requester_eth, 
        version_check_data=version_check_data
      )
      if not allowed_to_dauth:
        error = 'Node not allowed to request auth data. ' + message
    
    if False and hasattr(self, "DEBUG_BYPASS") and self.DEBUG_BYPASS:
      # this is a debug flag that allows us to bypass the node check
      # this is useful for testing
      if not allowed_to_dauth:
        self.Pd("DEBUG: Bypassing node check")
        allowed_to_dauth = True
        _non_critical_error = error + " (DEBUG: Bypassing node check)"
        error = None
    # end if DEBUG_BYPASS
    
    ####### now we prepare env variables ########
    short_requester = requester[:8] + '...' + requester[-4:]
    short_eth = requester_eth[:6] + '...' + requester_eth[-4:]
    if error is not None:
      dct_dauth['error'] = error
      self.P("dAuth request '{}' failed for <{}>  '{}' (ETH: {}): {}".format(
        sender_nonce, short_requester, requester_alias, short_eth, error), color='r'
      )
    else:
      if _non_critical_error is not None:
        dct_dauth['error'] = _non_critical_error
        self.Pd("Non-critical error on request from {}: {}".format(requester, _non_critical_error))
      ### Finally we fill the data with the authentication data
      self.fill_dauth_data(
        dauth_data=dct_dauth, requester_node_address=requester, is_node=is_requester_a_node,
        sender_eth_address=requester_eth
      )
      self.P("dAuth req '{}' success for <{}> '{}' (ETH: {})".format(
        sender_nonce, short_eth, requester_alias, short_eth)
      )
      ### end fill data
              
      # record the node_address and the auth data      
      self.chainstore_store_dauth_request(
        node_address=requester, node_address_eth=requester_eth, 
        dauth_data=data, sender_nonce=sender_nonce
      )
    #end no errors
    
    ####### add some extra info to payloads ########
    self.fill_extra_info(
      data=data, body=body, sender_eth_address=requester_eth,
      version_check_data=version_check_data
    )
    return data


  def get_node_tags(self, sender_eth_address: str):
    tags = {}
    try:
      base_url = self.os_environ.get(self.const.BASE_CT.dAuth.EvmNetData.EE_DAPP_API_URL_KEY)
      self.P("Base URL for dApp API: {}".format(base_url))
      if not base_url:
        base_url = "https://devnet-dapp-api.ratio1.ai"
      url = "".join([base_url, "/accounts/is-kyb"])
      params = {
        "walletAddress": sender_eth_address,
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
          sender_eth_address,
          response.status_code
        ))

      tags[self.const.BASE_CT.dAuth.EvmNetData.EE_NODETAG_KYB] = is_kyb

    except Exception as e:
      self.P("Error getting node tags: {}".format(e), color='r')
    return tags


if __name__ == '__main__':
  import json
  import os

  import naeural_core.constants as ct
  from ratio1._ver import __VER__ as sdk_ver
  from naeural_core.main.ver import __VER__ as core_ver
  from constants import ADMIN_PIPELINE
  from naeural_core.utils.plugins_base.bc_wrapper import BCWrapper
  
    
  from ratio1.bc import DefaultBlockEngine
  from ratio1 import Logger
  from ver import __VER__ as ee_ver
  
  os.environ[ct.BASE_CT.dAuth.EvmNetData.DAUTH_URL_KEY] = 'N/A'
  
  l = Logger("DAUTH", base_folder=".", app_folder="_local_cache")
  bc_eng = DefaultBlockEngine(
    log=l, name="dr1s-db-1",
    config={"PEM_FILE" : "dr1s-db-1.pem"},
  )
  
  bc = BCWrapper(bc_eng, owner=l)
  
  
  # os.environ['EE_EVM_NET'] = 'testnet'
  eng = _DauthMixin()
  eng.DEBUG_BYPASS = True
  eng.const = ct
  eng.bc = bc
  eng.evm_network = bc.get_evm_network()
  eng.cfg_dauth_verbose = True
  eng.P = l.P
  eng.json_dumps = json.dumps
  eng.ee_ver = ee_ver
  eng.ee_core_ver = core_ver
  eng.ee_sdk_ver = sdk_ver
  eng.os_environ = os.environ
  eng.cfg_auth_env_keys = ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_ENV_KEYS"]
  eng.cfg_auth_predefined_keys = ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_PREDEFINED_KEYS"]
  eng.cfg_auth_node_env_keys = ADMIN_PIPELINE["DAUTH_MANAGER"]["AUTH_NODE_ENV_KEYS"]
  
  l.P("Starting dAuth Mixin. is_seed_node: {}".format(eng.is_seed_node()))
  
  request_sdk = {
      "sender_alias": "test1",
      "nonce": "a14473a1",
      "sender_app_ver": None,
      "sender_sdk_ver": "2.6.29",
      "sender_core_ver": None,
      "EE_SIGN": "MEQCIAnXNWxcskr_2zj5kGRFQobJdDVovA57J_WMphFIOCf7AiAkDE7P446N4mQCAO2OAnQvW7PCdLNsRsHvGkBEz-BL4Q==",
      "EE_SENDER": "0xai_AjcIThkOqrPlp35-S8czHUOV-y4mnhksnLs8NGjTbmty",
      "EE_ETH_SENDER": "0x13Dc6Ee23D45D1e4bF0BDBDf58BFdF24bB077e69",
      "EE_ETH_SIGN": "0xBEEF",
      "EE_HASH": "e6a3f87d035b632c119cf1cacf02fcda79887fa24b3fa6355f6ec26b6c6cae70"
  }
  
  request_bad_node = {
      "nonce": "74c4629f",
      "sender_app_ver": "2.7.27",
      "sender_sdk_ver": "2.7.27",
      "sender_core_ver": "7.6.61",
      "sender_alias": "test1",
      "EE_SIGN": "MEUCIEmnPjCNwsSAlGANkT16IWMV4clYY4RoistByxIBIqJaAiEAsVSFSa3gip4TtiV-35PAjYZLVAdcIjJOJIT7_L4BxUI=",
      "EE_SENDER": "0xai_AlgFNEkQMDvLLKW4EzxPN038XCH3vAC8ClO73LbG7N8K",
      "EE_ETH_SENDER": "0x2f7B47edF44a1eD1ED04099F1beaf1aCb8176498",
      "EE_ETH_SIGN": "0xBEEF",
      "EE_HASH": "6e8b5267f163d7bdb476cbb75d305c755bfb9534be7aee9083c142d9d371de9c"
    }
  
  good_request = {
    "nonce": "a780cbf5",
    "sender_app_ver": "2.8.90",
    "sender_sdk_ver": "3.3.7",
    "sender_core_ver": "7.7.1",
    "sender_alias": "aid01",
    "EE_SIGN": "MEQCIDm0tMGaXCbd27cvy8Yv6u1PRXbE869C7ae-lT57H3V6AiBBkNJPJgdgHzESvaoRmR8WQeunALkicWsIigfxb0to_Q==",
    "EE_SENDER": "0xai_A74xZKZJa4LekjvJ6oJz29qxOOs5nLClXAZEhYv59t3Z",
    "EE_ETH_SENDER": "0x37379B80c7657620E5631832c4437B51D67A88cB",
    "EE_ETH_SIGN": "0xBEEF",
    "EE_HASH": "850c7a12fa7e6d3fe4216613bc8fea67c8d94721d5e18aa3f944f2df970c0c36"
  }

  
  
  request_faulty = {
    "EE_SENDER" : "0xai_AjcIThkOqrPlp35-S8czHUOV-y4mnhksnLs8NGjTbmty",
  }
  
  # res = eng.process_dauth_request(request_faulty)
  res = eng.process_dauth_request(request_sdk)
  # res = eng.process_dauth_request(request_bad)
  l.P(f"Result:\n{json.dumps(res, indent=2)}")
      