"""

The EpochManager01Plugin is a FastAPI web app that provides endpoints to interact with the
oracle network of the Naeural Edge Protocol

Each request will generate data as follows:
- availablity data is requested from the oracle API
- the data is signed with EVM signature and signature/address is added
- other oracle peers signatures are added - all must be on same agreed availability
- package is node-signed and returned to the client

"""

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.3'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  # 'ASSETS': 'plugins/business/fastapi/epoch_manager',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class EpochManager01Plugin(BasePlugin):
  """
  This plugin is a FastAPI web app that provides endpoints to interact with the
  EpochManager of the Neural Core.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(EpochManager01Plugin, self).__init__(**kwargs)
    return
  

  def on_init(self):
    super(EpochManager01Plugin, self).on_init()
    my_address = self.bc.address
    current_epoch = self.__get_current_epoch()
    start_epoch = current_epoch - 6
    end_epoch = current_epoch - 1
    if start_epoch < 1:
      start_epoch = 1
    if end_epoch < 1:
      end_epoch = 1
    my_node_info = self.__get_node_epochs(
      my_address, 
      start_epoch=start_epoch, end_epoch=end_epoch
    )
    self.P("Started {} plugin in epoch {}. Local node info:\n{}".format(
      self.__class__.__name__, current_epoch, self.json_dumps(my_node_info, indent=2))
    )
    return


  def __sign(self, data):
    """
    Sign the given data using the blockchain engine.
    Returns the signature. 
    Use the data param as it will be modified in place.
    """
    signature = self.bc.sign(data, add_data=True, use_digest=True)
    return signature


  def __get_response(self, dct_data: dict):
    """
    Create a response dictionary with the given data.

    Parameters
    ----------
    dct_data : dict
        The data to include in the response - data already prepared 

    Returns
    -------
    dict
        The input dictionary with the following keys added:
        - server_alias: str
            The literal alias of the current node.

        - server_time: str
            The current time in UTC of the current node.

        - server_current_epoch: int
            The current epoch of the current node.

        - server_uptime: str
            The time that the current node has been running.
    """
    str_utc_date = self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    # dct_data['server_id'] = self.node_addr # redundant due to the EE_SENDER
    dct_data['server_alias'] = self.node_id
    dct_data['server_version'] = self.ee_ver
    dct_data['server_time'] = str_utc_date
    dct_data['server_current_epoch'] = self.__get_current_epoch()
    dct_data['server_uptime'] = str(self.timedelta(seconds=int(self.time_alive)))
    self.__sign(dct_data) # add the signature over full data
    return dct_data

  def __get_current_epoch(self):
    """
    Get the current epoch of the node.

    Returns
    -------
    int
        The current epoch of the node.
    """
    return self.netmon.epoch_manager.get_current_epoch()
  
  
  def __eth_to_internal(self, eth_node_address):
    result = self.netmon.epoch_manager.eth_to_internal(eth_node_address)
    if result is None:
      result = f"unknown:{eth_node_address}"
    return result
  
  
  def __get_signed_data(self, node_addr : str, epochs : list, epochs_vals : list, sign=True, node_addr_eth=None):
    """    
    Sign the given data using the blockchain engine.
    Returns the signature. 
    Use the data param as it will be modified in place.
    
    Parameters
    ----------
    
    node_addr: str
      The internal node address (not EVM)
    
    """
    if node_addr_eth is None:
      node_addr_eth = self.bc.node_address_to_eth_address(node_addr)
    try:
      node_alias = self.netmon.network_node_eeid(addr=node_addr)
    except:
      node_alias = "unknown"
    # end if node_addr_eth is not None
    if sign:
      res = self.bc.eth_sign_node_epochs(
        node=node_addr_eth, 
        epochs=epochs,
        epochs_vals=epochs_vals, 
        signature_only=False,
      )    
      eth_signature = res["signature"]
      inputs = res["eth_signed_data"]
    else:
      eth_signature = []
      inputs = []
    
    eth_signatures = [eth_signature]
    eth_addresses = [self.bc.eth_address]
    
    # now add oracle peers signatures and addresses
    # ... 
    # end add the oracle signatures and addresses
    
    data = {
      'node': node_addr,
      'node_eth_address': node_addr_eth,
      'node_alias': node_alias,
      'epochs': epochs,
      'epochs_vals': epochs_vals,
      
      'eth_signed_data' : {
        "input" : inputs,
        "signature_field" : "eth_signature",        
      },
      
      'eth_signatures': eth_signatures, 
      'eth_addresses': eth_addresses, 
    }    
    return data
  
  
  def __get_node_epochs(self, node_addr: str, start_epoch: int = 1, end_epoch: int = None):
    """
    Get the epochs availabilities for a given node.

    Parameters
    ----------
    node_addr : str
        The internal address of a node.
        
    start_epoch : int
        The first epoch to get the availability for.
        
    end_epoch : int
        The last epoch to get the availability for.

    Returns
    -------
      dict
        A dictionary with the following keys
        - node: str
            The address of the node.
        - epochs_vals: list
            A list of integers, each integer is the epoch value for the node.
        - eth_signature: str  
            The EVM signature of the data.
        - eth_address: str
            The address of the EVM account used to sign the data.
            

    """
    unknown_address = False
    error_msg = None
    if end_epoch is None:
      end_epoch = self.__get_current_epoch() - 1
    if node_addr is None:
      error_msg = "Node address is None"
    if not isinstance(node_addr, str):
      error_msg = "Node address is not a string"
    if isinstance(start_epoch, str):
      start_epoch = int(start_epoch)
    if isinstance(end_epoch, str):
      end_epoch = int(end_epoch)
    if not isinstance(start_epoch, int):
      error_msg = "Start epoch is not an integer"
    if not isinstance(end_epoch, int):
      error_msg = "End epoch is not an integer"
    if start_epoch > end_epoch:
      error_msg = "Start epoch is greater than end epoch"
    if end_epoch < 1:
      error_msg = "End epoch is less than 1"
    if end_epoch >= self.__get_current_epoch():
      error_msg = "End epoch is greater or equal than the current epoch"
    # end if checks
    
    node_eth_address = None
    try:
      if "unknown:" in node_addr.lower(): # node is actually a error message
        error_msg = node_addr
        unknown_address = True
        node_eth_address = node_addr.replace("unknown:", "")
      else:
        node_eth_address = self.bc.node_address_to_eth_address(node_addr)
    except Exception as e:            
      str_except = f"Error converting node address <{node_addr}> to eth address: {e}"
      error_msg = str_except if error_msg is None else f"{error_msg}. {str_except}"
    # end try
    
    epochs_vals = None
    if error_msg is None:   
      self.P(f"Getting epochs for node {node_addr} from {start_epoch} to {end_epoch}")
      epochs_vals = self.netmon.epoch_manager.get_node_epochs(
        node_addr, 
        autocomplete=True,
        as_list=False
      )    
    if epochs_vals is None and not unknown_address:
      data = {
        'node': node_addr,
        'node_eth_address': node_eth_address,
        'error': "No epochs found for the given node",
      }
    else:      
      epochs = list(range(start_epoch, end_epoch + 1)) 
      if unknown_address:
        epochs_vals = {x : 0 for x in epochs}
      epochs_vals_selected = [epochs_vals[x] for x in epochs]
      # end try
      oracle_state = self.netmon.epoch_manager.get_oracle_state(
        start_epoch=start_epoch, end_epoch=end_epoch
      )
      valid = oracle_state['manager']['valid']
      data = self.__get_signed_data(
        node_addr=node_addr, epochs=epochs, epochs_vals=epochs_vals_selected, 
        sign=valid, node_addr_eth=node_eth_address
      )
      try:
        last_seen = round(self.netmon.network_node_last_seen(node_addr),2)
      except:
        last_seen = -1
      data['node_last_seen_sec'] = last_seen
      try:
        data['node_is_online'] = self.netmon.network_node_is_online(node_addr)
        data['node_version'] = self.netmon.network_node_version(node_addr)
        data['node_is_oracle'] = self.netmon.network_node_is_supervisor(node_addr)
      except:
        data['node_is_online'] = False
        data['node_version'] = "unknown"
        data['node_is_oracle'] = False
      # end try
      if not valid:
        data["error"] = "Oracle state is not valid for some of the epochs. Please check [result.oracle.manager.certainty] and report to devs. For testing purposes try using valid/certain epochs."
      # now add the certainty for each requested epoch
      data["oracle"] = oracle_state
      if error_msg is not None:
        data["error"] = error_msg
      if unknown_address:
        data["error"] = f"[No internal node address found]:  {node_addr}"
      # end if error_msg is not None
    #endif
    return data

  # List of endpoints, these are basically wrappers around the netmon
  # epoch manager.

  @BasePlugin.endpoint
  # /nodes_list
  def nodes_list(self):
    """
    Returns the list of all known nodes in the network - both online and offline.
    The known nodes are nodes that sent at least one heartbeat while the current node was running.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - nodes: list
            A list of strings, each string is the address of a node in the network.

        - server_id: str
            The address of the responding node.

        - server_time: str
            The current time in UTC of the responding node.

        - server_current_epoch: int
            The current epoch of the responding node.

        - server_uptime: str
            The time that the responding node has been running.
    """
    # nodes = self.netmon.epoch_manager.get_node_list()
    # nodes = {
    #   x : {
    #     "alias" :  self.netmon.network_node_eeid(addr=x),
    #     "eth_address" : self.bc.node_address_to_eth_address(x),
    #   } for x in nodes 
    # }    
    nodes = self.netmon.epoch_manager.get_stats(display=True, online_only=False)
    response = self.__get_response({
      'nodes': nodes,
    })
    return response
  

  @BasePlugin.endpoint
  # /active_nodes_list
  def active_nodes_list(self, items_per_page: int = 10, page: int = 1):
    """
    Returns the list of known and currently active nodes in the network.
    For all the nodes use the `nodes_list` endpoint.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - nodes: list
            A list of strings, each string is the address of a node in the network.

        - server_id: str
            The address of the responding node.

        - server_time: str
            The current time in UTC of the responding node.

        - server_current_epoch: int
            The current epoch of the responding node.

        - server_uptime: str
            The time that the responding node has been running.
    """
    # nodes = self.netmon.epoch_manager.get_node_list()
    # nodes = {
    #   x : {
    #     "alias" :  self.netmon.network_node_eeid(addr=x),
    #     "eth_address" : self.bc.node_address_to_eth_address(x),        
    #   } for x in nodes 
    #   if self.netmon.network_node_simple_status(addr=x) == self.const.DEVICE_STATUS_ONLINE
    # }
    nodes = self.netmon.epoch_manager.get_stats(display=True, online_only=True)
    error = nodes.pop("error", None)
    keys = sorted(list(nodes.keys()))
    total_items = len(keys)
    total_pages = (total_items + items_per_page - 1) // items_per_page
    if page < 1:
      page = 1
    if page > total_pages:
      page = total_pages
    start = (page - 1) * items_per_page
    end = start + items_per_page
    nodes = {k: nodes[k] for k in keys[start:end]}
    response = self.__get_response({
      'error' : error,
      'nodes_total_items': total_items,
      'nodes_total_pages': total_pages,
      'nodes_items_per_page': items_per_page,
      'nodes_page': page,
      'nodes': nodes,      
    })
    return response
  
  
  @BasePlugin.endpoint
  def node_epochs_range(
    self, 
    start_epoch : int, 
    end_epoch : int, 
    eth_node_addr : str = None, 
    node_addr: str = None
  ):
    """
    Returns the list of epochs availabilities for a given node in a given range of epochs.

    Parameters
    ----------
    eth_node_addr : str
        The address of a node.
        
    node_addr : str
        The internal address of a node.
        
    start_epoch : int
        The first epoch of the range.
        
    end_epoch : int
        The last epoch of the range.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - node: str
            The address of the node.

        - epochs_vals: list
            A list of integers, each integer is the epoch value for the node.

        - server_id: str
            The address of the responding node.

        - server_time: str
            The current time in UTC of the responding node.

        - server_current_epoch: int
            The current epoch of the responding node.

        - server_uptime: str
            The time that the responding node has been running.
    """  
    if eth_node_addr is not None:
      node_addr = self.__eth_to_internal(eth_node_addr)
    elif node_addr is None:
      raise ValueError("Please provide either `eth_node_addr` or `node_addr`")
    
    response = self.__get_response(self.__get_node_epochs(
      node_addr, start_epoch=start_epoch, end_epoch=end_epoch
    ))
    return response


  @BasePlugin.endpoint
  # /node_epochs
  def node_epochs(self, eth_node_addr: str = None, node_addr: str = None):
    """
    Returns the list of epochs availabilities for a given node.

    Parameters
    ----------
    eth_node_addr : str
        The EVM address of a node.
        
    node_addr : str
        The internal address of a node.

    Returns
    -------
    dict

    """
    if eth_node_addr is not None:
      node_addr = self.__eth_to_internal(eth_node_addr)
    elif node_addr is None:
      raise ValueError("Please provide either `eth_node_addr` or `node_addr`")
    
    
    if node_addr is None:
      return None
    if not isinstance(node_addr, str):
      return None

    response = self.__get_response(self.__get_node_epochs(node_addr))
    return response

  @BasePlugin.endpoint
  # /node_epoch
  def node_epoch(self, epoch: int, eth_node_addr: str = None, node_addr: str = None):
    """
    Returns the availability of a given node in a given epoch.

    Parameters
    ----------
    eth_node_addr : str
        The EVM address of a node.
        
    node_addr : str
        The internal address of a node.
        
    epoch : int
        The target epoch.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - node: str
            The address of the node.

        - epoch_id: int
            The target epoch.

        - epoch_val: int
            The availability score of the node in the epoch (between 0 and 255).

        - epoch_prc: float
            The availability score of the node in the epoch as a percentage (between 0 and 1).
    """
    if eth_node_addr is not None:
      node_addr = self.__eth_to_internal(eth_node_addr)
    elif node_addr is None:
      raise ValueError("Please provide either `eth_node_addr` or `node_addr`")

    data = self.__get_node_epochs(node_addr, start_epoch=epoch, end_epoch=epoch)
    if isinstance(data.get('epochs_vals'), list) and len(data['epochs_vals']) > 0:
      epoch_val = data['epochs_vals'][0]
      epoch_val_direct = self.netmon.epoch_manager.get_node_epoch(node_addr, epoch)
      assert epoch_val == epoch_val_direct
      response = self.__get_response({
        'epoch_id': epoch,
        'epoch_val': epoch_val,
        'epoch_prc': round(epoch_val / 255, 4),
        **data
      })
    else:
      response = self.__get_response({
        **data
      })
    return response

  @BasePlugin.endpoint
  # /node_last_epoch
  def node_last_epoch(self, eth_node_addr: str = None, node_addr: str = None):
    """
    Returns the availability of a given node in the last epoch.

    Parameters
    ----------
    eth_node_addr : str
        The EVM address of a node.
        
    node_addr : str
        The internal address of a node.
        
    Note: Please provide either `eth_node_addr` or `node_addr`.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - node: str
            The address of the node.

        - last_epoch_id: int
            The last epoch.

        - last_epoch_val: int
            The availability score of the node in the last epoch (between 0 and 255).

        - last_epoch_prc: float
            The availability score of the node in the last epoch as a percentage (between 0 and 1).

    """
    if eth_node_addr is not None:
      node_addr = self.__eth_to_internal(eth_node_addr)
    elif node_addr is None:
      raise ValueError("Please provide either `eth_node_addr` or `node_addr`")
    
    epoch = self.__get_current_epoch() - 1
    data = self.__get_node_epochs(node_addr, start_epoch=epoch, end_epoch=epoch)
    if isinstance(data.get('epochs_vals'), list) and len(data['epochs_vals']) > 0:
      epoch_val = data['epochs_vals'][0]
      epoch_val_direct = self.netmon.epoch_manager.get_node_epoch(node_addr, epoch)
      assert epoch_val == epoch_val_direct
      response = self.__get_response({
        'last_epoch_id': epoch,
        'last_epoch_val': epoch_val,
        'last_epoch_prc': round(epoch_val / 255, 4),
        **data
      })
    else:
      response = self.__get_response({
        **data
      })
    return response


  @BasePlugin.endpoint
  # /current_epoch
  def current_epoch(self):
    """
    Returns the current epoch of the node.

    Returns
    -------
    dict
        A dictionary with the following keys:
        - current_epoch: int
            The current epoch of the node.

        - server_id: str
            The address of the responding node.

        - server_time: str
            The current time in UTC of the responding node.

        - server_current_epoch: int
            The current epoch of the responding node.

        - server_uptime: str
            The time that the responding node has been running.
    """
    response = self.__get_response({
      'current_epoch': self.__get_current_epoch(),
    })
    return response
