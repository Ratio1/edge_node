from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.2'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31235, # dynamic
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'R1FS_VERBOSE' : 11,
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


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

  def _log_request_response(self, endpoint_name: str, request_data: dict = None, response_data: dict = None):
    """Helper method to log requests and responses when verbose mode is enabled"""
    if hasattr(self, 'cfg_r1fs_verbose') and self.cfg_r1fs_verbose > 10:
      self.P(f"=== {endpoint_name} ENDPOINT ===", color='y')
      if request_data:
        self.P(f"REQUEST: {self.json.dumps(request_data, indent=2)}", color='c')
      if response_data:
        self.P(f"RESPONSE: {self.json.dumps(response_data, indent=2)}", color='g')
      self.P(f"=== END {endpoint_name} ===", color='y')


  @BasePlugin.endpoint(method="get", require_token=False)
  def get_status(self):   # /get_status
    """
    """
    # Log request
    self._log_request_response("GET_STATUS", request_data={})
    
    status = self.r1fs.get_ipfs_id()

    data = {
      'status' : status
    }

    # Log response
    self._log_request_response("GET_STATUS", response_data=data)

    return data


  @BasePlugin.endpoint(method="post", streaming_type="upload", require_token=False)
  def add_file(self, file_path: str, body_json: any):
    """Process the uploaded file located at file_path"""

    # Log request
    request_data = {
      'file_path': file_path,
      'body_json': body_json
    }
    self._log_request_response("ADD_FILE", request_data=request_data)

    self.P(f"Starting add_file with uploaded file at: {file_path}")
    self.P(f"Body: {self.json.dumps(body_json, indent=2)}")

    secret = body_json.get('secret', None)
    self.P(f"Extracted secret: {secret}")

    cid = self.r1fs.add_file(file_path=file_path, secret=secret)

    data = {
      "message": f"File uploaded successfully",
      "cid": cid
    }

    # Log response
    self._log_request_response("ADD_FILE", response_data=data)

    return data


  @BasePlugin.endpoint(method="get", streaming_type="download", require_token=False)
  def get_file(self, cid: str, secret: str = None):
    """
    """
    # Log request
    request_data = {
      'cid': cid,
      'secret': "***"
    }
    self._log_request_response("GET_FILE", request_data=request_data)

    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    fn = self.r1fs.get_file(cid=cid, secret=secret)

    meta = {
      'file': fn,
      'filename': self.os_path.basename(fn)
    }
    response = {
      'file_path': fn,
      'meta': meta
    }

    self.P(f"response: {self.json.dumps(response, indent=2)}")

    # Log response
    self._log_request_response("GET_FILE", response_data=response)

    return response


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_file_base64(self, file_base64_str: str, filename: str = None, secret: str = None):  # first parameter must be named token
    """
    """
    # Log request (truncate base64 string for readability)
    request_data = {
      'file_base64_str': file_base64_str[:100] + "..." if len(file_base64_str) > 100 else file_base64_str,
      'filename': filename,
      'secret': '***'
    }
    self._log_request_response("ADD_FILE_BASE64", request_data=request_data)

    self.P(f"New base64 File={file_base64_str}")
    if not filename:
      filename = self.r1fs._get_unique_or_complete_upload_name()

    fn = self.diskapi_save_bytes_to_output(data=file_base64_str, filename=filename, from_base64=True)
    cid = self.r1fs.add_file(file_path=fn, secret=secret)

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("ADD_FILE_BASE64", response_data=data)
    
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def get_file_base64(self, cid: str, secret: str = None):  # first parameter must be named token
    """
    """
    # Log request
    request_data = {
      'cid': cid,
      'secret': secret
    }
    self._log_request_response("GET_FILE_BASE64", request_data=request_data)

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
    
    # Log response (truncate base64 string for readability)
    response_data = {
      "file_base64_str": file_base64[:100] + "..." if len(file_base64) > 100 else file_base64,
      "filename": filename
    }
    self._log_request_response("GET_FILE_BASE64", response_data=response_data)
    
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_yaml(self, data: dict, fn: str = None, secret: str = None):   # first parameter must be named token
    """
    """
    # Log request
    request_data = {
      'data': data,
      'fn': fn,
      'secret': secret
    }
    self._log_request_response("ADD_YAML", request_data=request_data)

    self.P(f"Adding data={data} to yaml, secret='{secret}'", color='g')

    cid = self.r1fs.add_yaml(data=data, fn=fn, secret=secret)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("ADD_YAML", response_data=data)
    
    return data


  @BasePlugin.endpoint(method="get", require_token=False)
  def get_yaml(self, cid: str, secret: str = None):
    """
    """
    # Log request
    request_data = {
      'cid': cid,
      'secret': secret
    }
    self._log_request_response("GET_YAML", request_data=request_data)

    self.P(f"Retrieving file with CID='{cid}', secret='{secret}'...")

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"fn: {fn}")
    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      self.P(f"File found: {file_data}")

    else:
      self.P(f"Error retrieving file: {fn}")
      error_response = "error"
      self._log_request_response("GET_YAML", response_data={'error': error_response})
      return error_response

    data = {
      "file_data" : file_data
    }
    
    # Log response
    self._log_request_response("GET_YAML", response_data=data)
    
    return data

#########################################################################
#########################################################################
