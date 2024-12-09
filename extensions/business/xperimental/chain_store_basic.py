"""
TODO:


  - Solve the issue for set-contention in the chain storage when two nodes try to set the same key at the same time
    - (better) implement a lock mechanism for the chain storage when setting a key value that 
      will allow multiple nodes to compete for the set-operation and thus load-balance it
      OR
    - implement set-value moving TOKEN via the network
  

  - peer-to-peer managed:
    - node 1 registers a app_id X via a list of peers that includes node 1, node 2 and node 3
    - node 2 sets value by:
      - key
      - value 
      - app_id X
    - node 2 broadcasts the set opration to all app_id X peers (not all peers)
    - node 2 waits for confirmations from at least half of the app_id peers
    - if node 4 tries to set key in app_id X, it will be rejected
    
  


"""


from naeural_core.business.base.network_processor import NetworkProcessorPlugin as BaseClass

_CONFIG = {
  **BaseClass.CONFIG,
  
  'ALLOW_EMPTY_INPUTS' : True,  
  "ACCEPT_SELF" : False,
  
  "FULL_DEBUG_PAYLOADS" : False,
  "CHAIN_STORE_DEBUG" : True, # main debug flag
  
  
  "MIN_CONFIRMATIONS" : 1,
  
  "CHAIN_PEERS_REFRESH_INTERVAL" : 60,

  'VALIDATION_RULES' : { 
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },  
}

__VER__ = '0.1.0'

class ChainStoreBasicPlugin(BaseClass):
  CONFIG = _CONFIG
  
  CS_STORE = "SSTORE"
  CS_CONFIRM = "SCONFIRM"
  CS_DATA = "CHAIN_STORE_DATA"
  CS_CONFIRM_BY = "confirm_by"
  CS_CONFIRMATIONS = "confirms"
  CS_MIN_CONFIRMATIONS = "min_confirms"
  CS_OP = "op"
  CS_KEY = "key"
  CS_VALUE = "value"
  CS_OWNER = "owner"
  CS_STORAGE_MEM = "__chain_storage" # shared memory key
  CS_GETTER = "__chain_storage_get"
  CS_SETTER = "__chain_storage_set"
  
  
  
  
  def on_init(self):
    super().on_init() # not mandatory anymore?
    
    self.P(" === ChainStoreBasicPlugin INIT")
    
    self.__chainstore_identity = "CS_MSG_{}".format(self.uuid(7))
    
    self.__ops = self.deque()
    
    try:
      self.__chain_storage = self.cacheapi_load_pickle(default={}, verbose=True)
    except Exception as e:
      self.P(f" === Chain storage could not be loaded: {e}")
      self.__chain_storage = {}
      

    ## DEBUG ONLY:
    if self.CS_STORAGE_MEM in self.plugins_shmem:
      self.P(" === Chain storage already exists", color="r")
      self.__chain_storage = self.plugins_shmem[self.CS_STORAGE_MEM]
    ## END DEBUG ONLY
    
    self.plugins_shmem[self.CS_STORAGE_MEM] = self.__chain_storage
    self.plugins_shmem[self.CS_GETTER] = self._get_value
    self.plugins_shmem[self.CS_SETTER] = self._set_value
    
    self.__last_chain_peers_refresh = 0
    self.__chain_peers = []
    self.__maybe_refresh_chain_peers()
    return
  
  
  def __maybe_refresh_chain_peers(self):
    if (self.time() - self.__last_chain_peers_refresh) > self.cfg_chain_peers_refresh_interval:
      _chain_peers = self.bc.get_whitelist(with_prefix=True)
      # now check and preserve only online peers
      self.__chain_peers = [
        peer for peer in _chain_peers if self.netmon.network_node_is_online(peer)
      ]
      self.__last_chain_peers_refresh = self.time()
    return
  
  
  def __send_data_to_chain_peers(self, data):
    self.send_encrypted_payload(node_addr=self.__chain_peers, **data)
    return
  
  
  def __get_min_peer_confirmations(self):
    if self.cfg_min_confirmations is not None and self.cfg_min_confirmations > 0:
      return self.cfg_min_confirmations    
    return len(self.__chain_peers) // 2 + 1
  
  
  def __save_chain_storage(self):
    self.cacheapi_save_pickle(self.__chain_storage, verbose=True)
    self.__last_chain_storage_save = self.time()
    return
  
  ## START setter-getter methods

  def __get_key_value(self, key):
    return self.__chain_storage.get(key, {}).get(self.CS_VALUE, None)


  def __get_key_owner(self, key):
    return self.__chain_storage.get(key, {}).get(self.CS_OWNER, None)


  def __get_key_confirmations(self, key):
    return self.__chain_storage.get(key, {}).get(self.CS_CONFIRMATIONS, 0)
  
  def __get_key_min_confirmations(self, key):
    return self.__chain_storage.get(key, {}).get(self.CS_MIN_CONFIRMATIONS, 0)


  def __reset_confirmations(self, key):
    self.__chain_storage[key][self.CS_CONFIRMATIONS] = 0
    self.__chain_storage[key][self.CS_MIN_CONFIRMATIONS] = self.__get_min_peer_confirmations()
    return


  def __increment_confirmations(self, key):
    self.__chain_storage[key][self.CS_CONFIRMATIONS] += 1
    return


  def __set_key_value(self, key, value, owner):
    """
    
    """
    # key should be composed of the chainstore app identity and the actual key
    # so if two chainstore apps are running on the same node, they will not overwrite each other
    # also this way we can implement chaistore app allow-listing
    chain_key = key
    self.__chain_storage[chain_key] = {
      self.CS_KEY   : key,
      self.CS_VALUE : value,
      self.CS_OWNER : owner,
    }
    self.__reset_confirmations(key)
    self.__save_chain_storage()
    return


  def _set_value(self, key, value, owner=None, debug=False):
    """ This method is called to set a value in the chain storage and push a broadcast request to the network """
    if owner is None:
      owner = self.get_instance_path()
    need_store = True
    if key in self.__chain_storage:
      existing_value = self.__get_key_value(key)
      existing_owner = self.__get_key_owner(key)
      if existing_value == value:
        if self.cfg_chain_store_debug:
          self.P(f" === Key {key} already stored by {existing_owner} has the same value")
        need_store = False
    if need_store:
      self.__set_key_value(key, value, owner)
      # self.__reset_confirmations(key)
      # now send set-value confirmation to all
      op = {      
          self.CS_OP : self.CS_STORE,
          self.CS_KEY: key,        
          self.CS_VALUE : value,   
          self.CS_OWNER : owner,
      }
      self.__ops.append(op)
      if debug:
        self.P(f" === Key {key} locally stored by {owner}")
      # at this point we can wait until we have enough confirmations
      _timeout = self.time() + 10
      _done = False
      _prev_confirm = 0
      _max_retries = 1
      _retries = 0
      while not _done: # this LOCKS the calling thread set_value
        recv_confirm = self.__get_key_confirmations(key)
        if recv_confirm > _prev_confirm:
          _prev_confirm = recv_confirm
          self.P(f" === Key received '{key}' has {recv_confirm} confirmations")
        if recv_confirm >= self.__get_key_min_confirmations(key):
          _done = True
          self.P(f" === KEY CONFIRMED '{key}': has enough ({recv_confirm}) confirmations")
        elif self.time() > _timeout:
          self.P(f" === Key '{key}' has not enough confirmations after timeout", color='r')
          _retries += 1
          if _retries > _max_retries:
            self.P(" === Key '{key}' has not enough confirmations after {_max_retries}retries", color='r')
            _done = True
            need_store = False
          else:
            self.P(f" === Retrying key '{key}' after timeout", color='r')
            self._ops.append(op)
        # end if timeout
        self.sleep(0.05)
    return need_store


  def _get_value(self, key, get_owner=False, debug=False):
    """ This method is called to get a value from the chain storage """
    if debug:
      self.P(f" === Getting value for key {key}")
    value = self.__get_key_value(key)
    if get_owner:
      owner = self.__get_key_owner(key)
      return value, owner
    return value
  
  ### END setter-getter methods


  def __maybe_broadcast(self):
    """ 
    This method is called to broadcast the chain store operations to the network.
    For each operation in the queue, a broadcast is sent to the network    
    """
    if self.cfg_chain_store_debug and len(self.__ops) > 0:
      self.P(f" === Broadcasting {len(self.__ops)} chain store {self.CS_STORE} ops to {self.__chain_peers}")
    while len(self.__ops) > 0:
      data = {
        self.CS_DATA : self.__ops.popleft()
      }
      self.__send_data_to_chain_peers(data)
    return


  def __exec_store(self, data):
    """ 
    This method is called when a store operation is received from the network. The method will:
      - set the value in the chain storage
      - send a ecrypted confirmation of the storage operation to the network
    """
    key = data.get(self.CS_KEY, None)
    value = data.get(self.CS_VALUE , None)
    owner = data.get(self.CS_OWNER, None)
  
    result = self._set_value(key, value, owner=owner)
    if result:
      # now send confirmation of the storage execution
      if self.cfg_chain_store_debug:
        self.P(f" === Sending storage confirm of {key} by {owner} to {self.__chain_peers}")
      data = {
        self.CS_DATA : {
          self.CS_OP : self.CS_CONFIRM,
          self.CS_KEY: key,
          self.CS_VALUE : value,
          self.CS_OWNER : owner,
          self.CS_CONFIRM_BY : self.get_instance_path(),
        }
      }
      self.__send_data_to_chain_peers(data)
    return


  def __exec_received_confirm(self, data):
    """ This method is called when a confirmation of a broadcasted store operation is received from the network """
    key = data.get(self.CS_KEY, None)
    value = data.get(self.CS_VALUE, None)
    owner = data.get(self.CS_OWNER, None)
    confirm_by = data.get(self.CS_CONFIRM_BY, None)
    
    local_owner = self.__get_key_owner(key)
    local_value = self.__get_key_value(key)
    if self.cfg_chain_store_debug:
      self.P(f" === Received conf from {confirm_by} for  {key}={value}, owner{owner}")
    if owner == local_owner and value == local_value:
      self.__increment_confirmations(key)
      if self.cfg_chain_store_debug:
        self.P(f" === Key {key} confirmed by {confirm_by}")
    return


  def on_payload_chain_store_basic(self, payload):
    sender = payload.get(self.const.PAYLOAD_DATA.EE_SENDER, None)
    destination = payload.get(self.const.PAYLOAD_DATA.EE_DESTINATION, None)
    is_encrypted = payload.get(self.const.PAYLOAD_DATA.EE_ENCRYPTED_DATA, False)
    destination = destination if isinstance(destination, list) else [destination]
    if self.cfg_full_debug_payloads:
      self.P(f" === on_payload_chain_store_basic from {sender} (enc={is_encrypted})")
      if self.ee_addr in destination:
        self.P(f" === on_payload_chain_store_basic received for me")
      else:
        self.P(f" === on_payload_chain_store_basic to {destination} (not for me)", color='r')
        return
    # try to decrypt the payload
    decrypted_data = self.receive_and_decrypt_payload(data=payload)    
    if self.cfg_full_debug_payloads:
      if decrypted_data is None or len(decrypted_data) == 0:
        self.P(f" === on_payload_chain_store_basic FAILED decrypting payload")
      else:
        self.P(f" === on_payload_chain_store_basic decrypted payload OK")
    # get the data and call the appropriate operation method
    data = decrypted_data.get(self.CS_DATA, {})
    operation = data.get(self.CS_OP, None)
    if operation == self.CS_STORE:
      self.__exec_store(data)      
    elif operation == self.CS_CONFIRM:
      self.__exec_received_confirm(data)
    return
  

  
  def process(self):
    self.__maybe_refresh_chain_peers()
    self.__maybe_broadcast()
    return 
