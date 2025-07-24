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

DEFAULT_TOKENS = ['admin']

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
  def get_status(self):   # /get_status
    """
    """
    # RETURN INFO HERE
    self.P("Getting all", color='g')
    hset_dump = self.chainstore_hgetall('r1fs')

    self.P(f"dump: {hset_dump}", color='g')

    data = {
      'keys' : hset_dump
    }

    return data


  @BasePlugin.endpoint(method="post", streaming_type="upload", require_token=True)
  def add_file(self, token: str, file_path: str, body: dict):
    """Process the uploaded file located at file_path"""

    self.P(f"Starting upload_large_file with uploaded file at: {file_path}")
    self.P(f"body: {body}")

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    secret = body.get('secret', None)

    cid = self.r1fs.add_file(file_path=file_path, secret=secret)

    data = {
      "message": f"File uploaded successfully",
      "cid": cid
    }

    return data


  @BasePlugin.endpoint(method="get", streaming_type="download", require_token=True)
  def get_file(self, token: str, cid: str, secret: str = None):
    """
    """
    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"fn: {fn}")

    return fn


  @BasePlugin.endpoint(method="post", require_token=True)
  def add_file_base64(self, token: str, file_base64_str: str, filename: str = None, secret: str = None):  # first parameter must be named token
    """
    """

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    self.P(f"New base64 File={file_base64_str}")
    if not filename:
      filename = self.r1fs._get_unique_or_complete_upload_name()

    fn = self.diskapi_save_bytes_to_output(data=file_base64_str, filename=filename, from_base64=True)
    self.P(f"File saved to {fn}")
    self.P("Saving to R1FS")
    cid = self.r1fs.add_file(file_path=fn, secret=secret)
    self.P(f"Added to R1FS, secret='{secret}'", color='g')
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }

    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def get_file_base64(self, token: str, cid: str, secret: str = None):  # first parameter must be named token
    """
    """

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    self.P(f"Trying to download file -> {cid}")
    file = self.r1fs.get_file(cid=cid, secret=secret)
    filename = file.split('/')[-1] if file else None
    self.P(f"File retrieved: {file}")
    file_base64 = self.diskapi_load_r1fs_file(file, verbose=True, to_base64=True)
    self.P("file retrieved: {}".format(file_base64))

    data = {
      "file_base64_str": file_base64,
      "filename": filename
    }

    return data


  @BasePlugin.endpoint(method="post", require_token=True)
  def add_yaml(self, token: str, data: dict, fn: str = None, secret: str = None):   # first parameter must be named token
    """
    """
    self.P(f"Adding data={data} to yaml, secret='{secret}'", color='g')

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    cid = self.r1fs.add_yaml(data=data, fn=fn, secret=secret)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }

    return data


  @BasePlugin.endpoint(method="get", require_token=True)
  def get_yaml(self, token: str, cid: str, secret: str = None):
    """
    """
    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    if not token or token not in DEFAULT_TOKENS:
      self.P(f"Invalid token: {token}", color='r')
      return {"error": "Invalid token"}

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"fn: {fn}")
    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      return "error"

    data = {
      "file_data" : file_data
    }

    return data

#########################################################################
#########################################################################
