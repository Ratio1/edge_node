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


  @BasePlugin.endpoint(method="post", streaming_type="upload", require_token=False)
  def add_file(self, file_path: str, body_json: any):
    """Process the uploaded file located at file_path"""

    self.P(f"Starting add_file with uploaded file at: {file_path}")
    self.P(f"Body: {self.json.dumps(body_json, indent=2)}")

    secret = body_json.get('secret', None)
    self.P(f"Extracted secret: {secret}")

    cid = self.r1fs.add_file(file_path=file_path, secret=secret)

    data = {
      "message": f"File uploaded successfully",
      "cid": cid
    }

    return data


  @BasePlugin.endpoint(method="get", streaming_type="download", require_token=False)
  def get_file(self, cid: str, secret: str = None):
    """
    """
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

    return response


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

    data = {
      "cid" : cid
    }
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def get_file_base64(self, cid: str, secret: str = None):  # first parameter must be named token
    """
    """

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


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_yaml(self, data: dict, fn: str = None, secret: str = None):   # first parameter must be named token
    """
    """
    self.P(f"Adding data={data} to yaml, secret='{secret}'", color='g')

    cid = self.r1fs.add_yaml(data=data, fn=fn, secret=secret)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }
    return data


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
      return "error"

    data = {
      "file_data" : file_data
    }
    return data

#########################################################################
#########################################################################
