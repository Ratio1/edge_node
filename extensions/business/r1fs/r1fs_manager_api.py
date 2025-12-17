from shapely import total_bounds

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.3'

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

  def Pd(self, s, *args, score=-1, **kwargs):
    """
    Print debug message if verbosity level allows.

    Parameters
    ----------
    s : str
        Message to print
    score : int, optional
        Verbosity threshold (default: -1). Message prints if cfg_r1fs_verbose > score
    *args
        Additional positional arguments passed to P()
    **kwargs
        Additional keyword arguments passed to P()

    Returns
    -------
    None
    """
    if hasattr(self, 'cfg_r1fs_verbose') and self.cfg_r1fs_verbose > score:
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return


  def _log_request_response(self, endpoint_name: str, request_data: dict = None, response_data: dict = None):
    """Helper method to log requests and responses when verbose mode is enabled"""
    if hasattr(self, 'cfg_r1fs_verbose') and self.cfg_r1fs_verbose > 10:
      if request_data is not None:
        self.P(f"[{endpoint_name}] request: {self.json.dumps(request_data)}", color='c')
      if response_data is not None:
        self.P(f"[{endpoint_name}] response: {self.json.dumps(response_data)}", color='g')
    # end if
    return

  @BasePlugin.endpoint(method="get", require_token=False)
  def get_status(self):   # /get_status
    """
    Get the current status of the R1FS service.
    
    Returns:
        dict: IPFS node information including node ID and connection status
    """
    start_time = self.time()
    status = self.r1fs.get_ipfs_id_data()
    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS get_status took {elapsed_time:.2f}s")

    return status


  @BasePlugin.endpoint(method="post", streaming_type="upload", require_token=False)
  def add_file(self, file_path: str, body_json: any = None, secret: str = None, nonce: int = None):
    """
    Upload a file to R1FS (Ratio1 File System) via IPFS.
    
    This endpoint accepts a file upload and stores it in the decentralized file system.
    The file is encrypted with an optional secret key for security.
    
    Args:
        file_path (str): Path to the uploaded file on the server
        body_json (dict): JSON body containing metadata including:
            - secret (str, optional): Encryption key for the file
        secret (str): Encryption key for the file (passed as parameter)
        nonce (int, optional): Nonce value for encryption

    Returns:
        dict: Response containing success message and the Content Identifier (CID)
    """
    start_time = self.time()
    self.Pd(f"Starting add_file for {file_path}")
    body_json = body_json or {}
    if not isinstance(body_json, dict):
      body_json = {}
    secret = body_json.get('secret', None)

    cid = self.r1fs.add_file(file_path=file_path, secret=secret, nonce=nonce)

    data = {
      "message": f"File uploaded successfully",
      "cid": cid
    }

    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS add_file took {elapsed_time:.2f}s")
    return data


  @BasePlugin.endpoint(method="get", streaming_type="download", require_token=False)
  def get_file(self, cid: str, secret: str = None):
    """
    Download a file from R1FS using its Content Identifier (CID).
    
    This endpoint retrieves a file from the decentralized file system and
    provides it as a downloadable stream. The file is decrypted using the
    provided secret key if it was encrypted during upload.
    
    Args:
        cid (str): Content Identifier of the file to retrieve
        secret (str, optional): Decryption key if the file was encrypted
    
    Returns:
        dict: Response containing file path and metadata including:
            - file_path: Path to the retrieved file
            - meta: Dictionary containing file information
                - file: Full file path
                - filename: Original filename
    """
    # Log request
    start_time = self.time()
    self.Pd(f"Retrieving file with CID='{cid}', secret_provided={'yes' if secret else 'no'}")

    fn = self.r1fs.get_file(cid=cid, secret=secret)

    if fn is None:
      error_msg = f"Failed to retrieve file with CID '{cid}'. The file may not exist or the IPFS download failed."
      self.P(error_msg, color='r')
      return {
        'error': error_msg,
        'file_path': None,
        'meta': None
      }

    meta = {
      'file': fn,
      'filename': self.os_path.basename(fn)
    }
    response = {
      'file_path': fn,
      'meta': meta
    }

    total_elapsed = self.time() - start_time
    self.Pd(f"R1FS get_file took {total_elapsed:.2f}s")
    return response


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_file_base64(self, file_base64_str: str, filename: str = None, secret: str = None, nonce: int = None):  # first parameter must be named token
    """
    Upload a file to R1FS using base64-encoded data.
    
    This endpoint accepts file data as a base64 string and stores it in the
    decentralized file system. Useful for uploading files directly from web
    applications without multipart form data.
    
    Args:
        file_base64_str (str): Base64-encoded file data
        filename (str, optional): Name for the file. If not provided, a unique name is generated
        secret (str, optional): Encryption key for the file
        nonce (int, optional): Nonce value for encryption
    
    Returns:
        dict: Response containing the Content Identifier (CID) of the uploaded file
    """
    start_timer = self.time()

    payload_len = (len(file_base64_str) if file_base64_str else 0) / 1024**2

    self.Pd(f"R1FS add_file_base64 payload length={payload_len:.2f} MB.")
    if not filename:
      filename = self.r1fs._get_unique_or_complete_upload_name()

    disk_start = self.time()
    fn = self.diskapi_save_bytes_to_output(data=file_base64_str, filename=filename, from_base64=True)
    disk_elapsed = self.time() - disk_start

    r1add_start = self.time()
    cid = self.r1fs.add_file(file_path=fn, secret=secret, nonce=nonce)
    r1add_elapsed = self.time() - r1add_start

    total_elapsed = self.time() - start_timer
    self.Pd("R1FS add_file_base64 in {:.4f}s (disk_save: {:.4f}s, r1fs add: {:.4f}s)".format(
      total_elapsed, disk_elapsed, r1add_elapsed
    ))

    data = {
      "cid" : cid
    }

    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def get_file_base64(self, cid: str, secret: str = None):  # first parameter must be named token
    """
    Download a file from R1FS and return it as base64-encoded data.
    
    This endpoint retrieves a file from the decentralized file system and
    returns it as a base64 string. Useful for web applications that need
    to handle file data directly in JavaScript.
    
    Args:
        cid (str): Content Identifier of the file to retrieve
        secret (str, optional): Decryption key if the file was encrypted
    
    Returns:
        dict: Response containing base64-encoded file data and filename:
            - file_base64_str: Base64-encoded file content
            - filename: Original filename
    """
    start_timer = self.time()

    self.Pd(f"Trying to download file -> {cid}")
    file = self.r1fs.get_file(cid=cid, secret=secret)
    get_file_elapsed = self.time() - start_timer

    if file is None:
      error_msg = f"Failed to retrieve file with CID '{cid}'. The file may not exist or the IPFS download failed."
      self.P(error_msg, color='r')
      return {
        'error': error_msg,
        'file_base64_str': None,
        'filename': None
      }


    file = file.replace("/edge_node", ".") if file else file
    filename = file.split('/')[-1] if file else None
    self.Pd(f"File retrieved: {file}")

    disk_read_start = self.time()
    file_base64 = self.diskapi_load_r1fs_file(file, verbose=True, to_base64=True)
    disk_read_elapsed = self.time() - disk_read_start

    self.Pd(f"Encoded payload length={len(file_base64) if file_base64 else 0}")

    data = {
      "file_base64_str": file_base64,
      "filename": filename
    }

    total_elapsed = self.time() - start_timer
    self.Pd("R1FS get_file_base64 in {:.4f}s (r1fs get: {:.4f}s, disk read: {:.4f}s)".format(
      total_elapsed, get_file_elapsed, disk_read_elapsed
    ))
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_yaml(self, data: dict, fn: str = None, secret: str = None, nonce: int = None):   # first parameter must be named token
    """
    Store YAML data in R1FS.
    
    This endpoint converts a Python dictionary to YAML format and stores it
    in the decentralized file system. The data can be encrypted with an
    optional secret key for security.
    
    Args:
        data (dict): Python dictionary to be stored as YAML
        fn (str, optional): Filename for the YAML file. If not provided, a unique name is generated
        secret (str, optional): Encryption key for the YAML data
        nonce (int, optional): Nonce value for encryption
    
    Returns:
        dict: Response containing the Content Identifier (CID) of the stored YAML:
            - cid: Content Identifier of the uploaded YAML file
    """
    start_time = self.time()

    cid = self.r1fs.add_yaml(data=data, fn=fn, secret=secret)
    self.Pd(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }

    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS add_yaml took {elapsed_time:.4f} seconds")

    return data


  @BasePlugin.endpoint(method="get", require_token=False)
  def get_yaml(self, cid: str, secret: str = None):
    """
    Retrieve and parse YAML data from R1FS.
    
    This endpoint downloads a YAML file from the decentralized file system
    and parses it back into a Python dictionary. The file is decrypted
    using the provided secret key if it was encrypted during storage.
    
    Args:
        cid (str): Content Identifier of the YAML file to retrieve
        secret (str, optional): Decryption key if the YAML was encrypted
    
    Returns:
        dict: Response containing the parsed YAML data as a Python dictionary:
            - file_data: Parsed YAML content as a Python dictionary
        str: Error message if the file is not a valid YAML file
    """
    total_elapsed, get_file_elapsed, disk_read_elapsed = 0.0, 0.0, 0.0
    start_time = self.time()
    self.Pd(f"Retrieving YAML with CID='{cid}', secret_provided={'yes' if secret else 'no'}")

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.Pd(f"Retrieved file path: {fn}")
    get_file_elapsed = self.time() - start_time

    if fn is None:
      error_msg = f"Failed to retrieve file with CID '{cid}'. The file may not exist or the IPFS download failed."
      self.P(error_msg, color='r')
      self._log_request_response("GET_YAML", response_data={'error': error_msg})
      return {'error': error_msg}

    # Transform absolute path to relative path for diskapi functions
    fn = fn.replace("/edge_node", ".") if fn else fn

    if fn.endswith('.yaml') or fn.endswith('.yml'):
      disk_read_start = self.time()
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      disk_read_elapsed = self.time() - disk_read_start

    else:
      self.P(f"Error retrieving file: {fn}")
      error_response = "error"
      self._log_request_response("GET_YAML", response_data={'error': error_response})
      return error_response

    data = {
      "file_data" : file_data
    }

    total_elapsed = self.time() - start_time

    self.Pd("R1FS get_yaml in {:.2f}s (r1fs get: {:.2f}s, disk read: {:.2f}s)".format(
      total_elapsed, get_file_elapsed, disk_read_elapsed
    ))
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_json(self, data: dict, fn: str = None, secret: str = None, nonce: int = None):
    """
    Store JSON data in R1FS.
    
    This endpoint converts a Python dictionary to JSON format and stores it
    in the decentralized file system. The data can be encrypted with an
    optional secret key for security.
    
    Args:
        data (dict): Python dictionary to be stored as JSON
        fn (str, optional): Filename for the JSON file. If not provided, a default name is used
        secret (str, optional): Encryption key for the JSON data
        nonce (int, optional): Nonce value for encryption
    
    Returns:
        dict: Response containing the Content Identifier (CID) of the stored JSON:
            - cid: Content Identifier of the uploaded JSON file
    """
    start_time = self.time()
    cid = self.r1fs.add_json(data=data, fn=fn, secret=secret, nonce=nonce)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }
    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS add_json took {elapsed_time:.2f} s")
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def add_pickle(self, data: object, fn: str = None, secret: str = None, nonce: int = None):
    """
    Store pickle data in R1FS.
    
    This endpoint serializes a Python object to pickle format and stores it
    in the decentralized file system. The data can be encrypted with an
    optional secret key for security.
    
    Args:
        data (object): Python object to be stored as pickle
        fn (str, optional): Filename for the pickle file. If not provided, a unique name is generated
        secret (str, optional): Encryption key for the pickle data
        nonce (int, optional): Nonce value for encryption
    
    Returns:
        dict: Response containing the Content Identifier (CID) of the stored pickle:
            - cid: Content Identifier of the uploaded pickle file
    """
    start_time = self.time()
    cid = self.r1fs.add_pickle(data=data, fn=fn, secret=secret, nonce=nonce)
    self.Pd(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }

    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS add_pickle took {elapsed_time:.4f}")
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def calculate_json_cid(self, data: dict, nonce: int, fn: str = None, secret: str = None):
    """
    Calculate the Content Identifier (CID) of JSON data without storing it in R1FS.
    
    This endpoint calculates what the CID would be if the JSON data were to be
    stored in the decentralized file system. Useful for determining the CID
    before actually uploading the data.
    
    Args:
        data (dict): Python dictionary to calculate CID for
        nonce (int): Nonce value for encryption (required for deterministic CID calculation)
        fn (str, optional): Filename for the JSON file. If not provided, a default name is used
        secret (str, optional): Encryption key for the JSON data
    
    Returns:
        dict: Response containing the calculated Content Identifier (CID):
            - cid: Content Identifier that would be generated for this JSON data
    """
    start_time = self.time()
    # Log request
    request_data = {
      'data': data,
      'nonce': nonce,
      'fn': fn,
      'secret': "***" if secret else None,
    }
    self._log_request_response("CALCULATE_JSON_CID", request_data=request_data)

    cid = self.r1fs.calculate_json_cid(data=data, nonce=nonce, fn=fn, secret=secret)
    self.Pd(f"Calculated Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("CALCULATE_JSON_CID", response_data=data)
    elapsed_time = self.time() - start_time
    self.Pd(f"R1FS calculate_json_cid took {elapsed_time:.2f}s")
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def calculate_pickle_cid(self, data: object, nonce: int, fn: str = None, secret: str = None):
    """
    Calculate the Content Identifier (CID) of pickle data without storing it in R1FS.
    
    This endpoint calculates what the CID would be if the pickle data were to be
    stored in the decentralized file system. Useful for determining the CID
    before actually uploading the data.
    
    Args:
        data (object): Python object to calculate CID for
        nonce (int): Nonce value for encryption (required for deterministic CID calculation)
        fn (str, optional): Filename for the pickle file. If not provided, a unique name is generated
        secret (str, optional): Encryption key for the pickle data
    
    Returns:
        dict: Response containing the calculated Content Identifier (CID):
            - cid: Content Identifier that would be generated for this pickle data
    """
    start_time = self.time()
    # Log request
    request_data = {
      'data': data,
      'nonce': nonce,
      'fn': fn,
      'secret': "***" if secret else None,
    }
    self._log_request_response("CALCULATE_PICKLE_CID", request_data=request_data)

    cid = self.r1fs.calculate_pickle_cid(data=data, nonce=nonce, fn=fn, secret=secret)
    self.Pd(f"Calculated Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("CALCULATE_PICKLE_CID", response_data=data)
    elapsed = self.time() - start_time
    self.Pd(f"R1FS calculate_pickle_cid took {elapsed:.2f}s")
    return data


  @BasePlugin.endpoint(method="post", require_token=False)
  def delete_file(
    self,
    cid: str,
    unpin_remote: bool = True,
    run_gc: bool = False,
    cleanup_local_files: bool = False
  ):
    """
    Delete a file from R1FS by unpinning it locally and optionally on the relay.

    This endpoint removes a file from the decentralized file system by unpinning it.
    The file is marked for garbage collection and will be removed when GC runs.

    Args:
        cid (str): Content Identifier of the file to delete
        unpin_remote (bool, optional): Whether to also unpin from the relay. Default is True
        run_gc (bool, optional): Whether to run garbage collection immediately. Default is False
        cleanup_local_files (bool, optional): Whether to remove local downloaded files. Default is False

    Returns:
        dict: Response containing success status and message:
            - success: Boolean indicating if deletion was successful
            - message: Status message
            - cid: The CID that was deleted
    """
    start_time = self.time()
    self.Pd(f"Deleting file with CID='{cid}', unpin_remote={unpin_remote}, run_gc={run_gc}")

    success = self.r1fs.delete_file(
      cid=cid,
      unpin_remote=unpin_remote,
      run_gc=run_gc,
      cleanup_local_files=cleanup_local_files,
      show_logs=True,
      raise_on_error=False
    )

    if success:
      message = f"File {cid} deleted successfully"
      self.Pd(message)
    else:
      message = f"Failed to delete file {cid}"
      self.P(message, color='r')

    response = {
      "success": success,
      "message": message,
      "cid": cid
    }

    elapsed_time = self.time() - start_time

    self.Pd(f"R1FS delete_file took {elapsed_time:.4f} seconds")

    return response


  @BasePlugin.endpoint(method="post", require_token=False)
  def delete_files(
    self,
    cids: list,
    unpin_remote: bool = True,
    run_gc_after_all: bool = True,
    cleanup_local_files: bool = False
  ):
    """
    Delete multiple files from R1FS in bulk.

    This endpoint removes multiple files from the decentralized file system by
    unpinning them. More efficient than calling delete_file repeatedly as it
    can run garbage collection once at the end.

    Args:
        cids (list): List of Content Identifiers to delete
        unpin_remote (bool, optional): Whether to also unpin from the relay. Default is True
        run_gc_after_all (bool, optional): Whether to run GC once after all deletions. Default is True
        cleanup_local_files (bool, optional): Whether to remove local downloaded files. Default is False

    Returns:
        dict: Response containing deletion results:
            - success: List of successfully deleted CIDs
            - failed: List of CIDs that failed to delete
            - total: Total number of CIDs processed
            - success_count: Number of successful deletions
            - failed_count: Number of failed deletions
    """
    start_time = self.time()
    self.Pd(f"Bulk deleting {len(cids)} files, unpin_remote={unpin_remote}, run_gc_after_all={run_gc_after_all}")

    result = self.r1fs.delete_files(
      cids=cids,
      unpin_remote=unpin_remote,
      run_gc_after_all=run_gc_after_all,
      cleanup_local_files=cleanup_local_files,
      show_logs=True,
      raise_on_error=False
    )
    elapsed_time = self.time() - start_time

    self.Pd(f"R1FS delete_files took {elapsed_time:.4f} seconds")

    return result

#########################################################################
#########################################################################
