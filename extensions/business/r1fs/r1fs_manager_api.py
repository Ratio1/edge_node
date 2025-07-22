from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.2'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31235, # dynamic
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'R1FS_VERBOSE' : True,
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

DEFAULT_CHAINSTORE_KEY = 'r1fs'

class R1fsManagerApiPlugin(BasePlugin):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for R1FS.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(R1fsManagerApiPlugin, self).__init__(**kwargs)
    return

  def on_init(self):
    super(R1fsManagerApiPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    self.P("#2323123")
    self.P("Started {} plugin on {} / {}".format(
      self.__class__.__name__, my_address, my_eth_address,
    ))
    return
  
  def __get_current_epoch(self):
    """
    Get the current epoch of the node.

    Returns
    -------
    int
        The current epoch of the node.
    """
    return self.netmon.epoch_manager.get_current_epoch()
  
   
  
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
  


  @BasePlugin.endpoint(method="get", require_token=False) 
  def get_status(self, chainstore_key=DEFAULT_CHAINSTORE_KEY):   # /get_status
    """
    """
    self.P("Getting all", color='g')
    hset_dump = self.chainstore_hgetall(chainstore_key)

    self.P(f"dump: {hset_dump}", color='g')

    data = {
      'keys' : hset_dump
    }
    
    response = self.__get_response({
      **data
    })
    return response


  # @BasePlugin.endpoint(method="post", require_token=False)
  # def add_file(self, file, fn: str = None, secret: str = None):   # first parameter must be named token
  #   """
  #   """
  #   self.P(f"Adding data={file} to R1FS, secret='{secret}'", color='g')
  #   cid = self.r1fs.add_file(data=file, fn=fn, secret=secret)
  #   self.P(f"Cid='{cid}'")
  #
  #   response_data = {
  #     "cid" : cid
  #   }
  #
  #   response = self.__get_response({
  #     **response_data
  #   })
  #   return response

  @BasePlugin.endpoint(method="post", require_token=False)
  def add_file_base64(self, file_base64_str: str, filename: str = None, secret: str = None):  # first parameter must be named token
    """
    """
    self.P(f"New base64 File={file_base64_str}")
    if not filename:
      filename = self.r1fs._get_unique_or_complete_upload_name()

    fn = self.diskapi_save_bytes_to_output(data=file_base64_str, filename=filename, from_base64=True)
    self.P(f"File saved to {fn}")
    self.P("Saving to R1FS")
    cid = self.r1fs.add_file(file_path=fn, secret=secret)
    self.P(f"Added to R1FS, secret='{secret}'", color='g')
    self.P(f"Cid='{cid}'")

    response_data = {
      "cid" : cid
    }

    response = self.__get_response({
      **response_data
    })
    return response


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_yaml(self, data: dict, fn: str = None, secret: str = None):   # first parameter must be named token
    """
    """
    self.P(f"Adding data={data} to yaml, secret='{secret}'", color='g')
    cid = self.r1fs.add_yaml(data=data, fn=fn, secret=secret)
    self.P(f"Cid='{cid}'")

    response_data = {
      "cid" : cid
    }

    response = self.__get_response({
      **response_data
    })
    return response

  @BasePlugin.endpoint(method="get", require_token=False)
  def get_file(self, cid: str, secret: str = None):
    """
    """
    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"fn: {fn}")
    file_data = self.diskapi_load_r1fs_file(fn, verbose=True, to_base64=True)
    self.P(f"file_data={file_data}")
    data = {
      "file_data" : file_data
    }

    response = self.__get_response({
      **data
    })
    return response

  @BasePlugin.endpoint(method="get", require_token=False)
  def get_yaml(self, cid: str, secret: str = None):
    """
    """
    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"fn: {fn}")
    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      file_data = "error"
    data = {
      "file_data" : file_data
    }

    response = self.__get_response({
      **data
    })
    return response

  @BasePlugin.endpoint(method="get", require_token=False)
  def test1(self):
    """
    """
    cid="QmRsXRzeDVuQHJbQb6UQQYFYGz9AjiGo2CeUZiE5V29BeF"
    self.P(f"Retrieving file with CID={cid}...")

    d = {'key2': 'val2'}
    cid = self.r1fs.add_yaml(data=d)
    self.P(f"Saved file with CID={cid}, d={d}")

    fn = self.r1fs.get_file(cid)

    self.P(f"fn: {fn}")

    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      file_data = "error"
    data = {
      "file_data" : file_data
    }

    response = self.__get_response({
      **data
    })
    return response

  @BasePlugin.endpoint(method="get", require_token=False)
  def test2(self):
    """
    """
    d = {'key1': 'val1'}
    secret = 's1'
    cid = self.r1fs.add_yaml(data=d, secret=secret)
    self.P(f"Saved file with CID='{cid}', secret='{secret}', d='{d}'")

    fn = self.r1fs.get_file(cid, secret=secret)

    self.P(f"fn: {fn}")

    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      file_data = "error"
    data = {
      "file_data" : file_data
    }

    response = self.__get_response({
      **data
    })
    return response

  @BasePlugin.endpoint(method="get", require_token=False)
  def test3(self):
    """
    """
    secret = 's1'
    cid = "Qmc7QpGJJ9MMXi5FdTB8DadXt2ydWrM6jMaSRfjwcBr5Df"
    self.P(f"Saved file with CID={cid}, secret={secret}")

    fn = self.r1fs.get_file(cid, secret=secret)

    self.P(f"fn: {fn}")

    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      file_data = "error"
    data = {
      "file_data" : file_data
    }

    response = self.__get_response({
      **data
    })
    return response

