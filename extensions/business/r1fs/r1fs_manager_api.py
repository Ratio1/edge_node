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
      if request_data is not None:
        sanitized_request = self._sanitize_payload(request_data)
        self.P(f"[{endpoint_name}] request: {self.json.dumps(sanitized_request)}", color='c')
      if response_data is not None:
        sanitized_response = self._sanitize_payload(response_data)
        self.P(f"[{endpoint_name}] response: {self.json.dumps(sanitized_response)}", color='g')

  def _sanitize_payload(self, payload, max_length: int = 64, depth: int = 0, key_path: str = ""):
    """
    Sanitize payloads before logging to avoid leaking secrets or large contents.
    """
    sensitive_tokens = (
      "secret", "key", "token", "pass", "pwd", "credential", "auth",
      "signature", "base64", "content", "body", "payload", "data", "yaml",
      "json", "pickle"
    )

    if payload is None:
      return None

    if depth >= 3:
      return "[truncated]"

    if isinstance(payload, dict):
      sanitized = {}
      for key, value in payload.items():
        child_path = f"{key_path}.{key}" if key_path else str(key)
        sanitized[key] = self._sanitize_payload(value, max_length, depth + 1, child_path)
      return sanitized

    if isinstance(payload, (list, tuple, set)):
      sanitized_iterable = [
        self._sanitize_payload(value, max_length, depth + 1, f"{key_path}.{idx}")
        for idx, value in enumerate(payload)
      ]
      return sanitized_iterable

    if isinstance(payload, bytes):
      return f"[bytes len={len(payload)}]"

    if isinstance(payload, str):
      lower_path = key_path.lower()
      if any(token in lower_path for token in sensitive_tokens):
        return "***"
      if len(payload) > max_length:
        return f"{payload[:max_length]}... (len={len(payload)})"
      return payload

    if isinstance(payload, (int, float, bool)):
      return payload

    if any(token in key_path.lower() for token in sensitive_tokens):
      return "***"

    return f"[{payload.__class__.__name__}]"


  @BasePlugin.endpoint(method="get", require_token=False)
  def get_status(self):   # /get_status
    """
    Get the current status of the R1FS service.
    
    Returns:
        dict: IPFS node information including node ID and connection status
    """
    # Log request
    self._log_request_response("GET_STATUS", request_data={})
    
    status = self.r1fs.get_ipfs_id_data()

    # Log response
    self._log_request_response("GET_STATUS", response_data=status)

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
    # Log request
    request_data = {
      'file_path': file_path,
      'body_json': body_json,
      'nonce': nonce,
      'secret': "***" if secret else None,
    }
    self._log_request_response("ADD_FILE", request_data=request_data)

    self.P(f"Starting add_file for {file_path}")
    body_json = body_json or {}
    if not isinstance(body_json, dict):
      body_json = {}
    secret = body_json.get('secret', None)
    self.P(f"Secret provided: {'yes' if secret else 'no'}")

    cid = self.r1fs.add_file(file_path=file_path, secret=secret, nonce=nonce)

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
    request_data = {
      'cid': cid,
      'secret': "***" if secret else None,
    }
    self._log_request_response("GET_FILE", request_data=request_data)

    self.P(f"Retrieving file with CID='{cid}', secret_provided={'yes' if secret else 'no'}")

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

    self.P(f"GET_FILE completed, file_path set: {bool(fn)}")

    # Log response
    self._log_request_response("GET_FILE", response_data=response)

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
    # Log request (truncate base64 string for readability)
    request_data = {
      'file_base64_str': file_base64_str[:100] + "..." if len(file_base64_str) > 100 else file_base64_str,
      'filename': filename,
      'nonce': nonce,
      'secret': "***" if secret else None,
    }
    self._log_request_response("ADD_FILE_BASE64", request_data=request_data)

    self.P(f"Received base64 payload length={len(file_base64_str) if file_base64_str else 0}")
    if not filename:
      filename = self.r1fs._get_unique_or_complete_upload_name()

    fn = self.diskapi_save_bytes_to_output(data=file_base64_str, filename=filename, from_base64=True)
    cid = self.r1fs.add_file(file_path=fn, secret=secret, nonce=nonce)

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("ADD_FILE_BASE64", response_data=data)
    
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
    # Log request
    request_data = {
      'cid': cid,
      'secret': "***" if secret else None,
    }
    self._log_request_response("GET_FILE_BASE64", request_data=request_data)

    self.P(f"Trying to download file -> {cid}")
    file = self.r1fs.get_file(cid=cid, secret=secret)
    
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
    self.P(f"File retrieved: {file}")
    file_base64 = self.diskapi_load_r1fs_file(file, verbose=True, to_base64=True)
    self.P(f"Encoded payload length={len(file_base64) if file_base64 else 0}")

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
    # Log request
    request_data = {
      'data': data,
      'fn': fn,
      'nonce': nonce,
      'secret': "***" if secret else None,
    }
    self._log_request_response("ADD_YAML", request_data=request_data)

    yaml_keys = list(data.keys()) if isinstance(data, dict) else type(data).__name__
    self.P(f"Adding YAML payload with keys={yaml_keys}, secret_provided={'yes' if secret else 'no'}", color='g')

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
    # Log request
    request_data = {
      'cid': cid,
      'secret': "***" if secret else None,
    }
    self._log_request_response("GET_YAML", request_data=request_data)

    self.P(f"Retrieving YAML with CID='{cid}', secret_provided={'yes' if secret else 'no'}")

    fn = self.r1fs.get_file(cid=cid, secret=secret)
    self.P(f"Retrieved file path: {fn}")
    
    if fn is None:
      error_msg = f"Failed to retrieve file with CID '{cid}'. The file may not exist or the IPFS download failed."
      self.P(error_msg, color='r')
      self._log_request_response("GET_YAML", response_data={'error': error_msg})
      return {'error': error_msg}
    
    if fn.endswith('.yaml') or fn.endswith('.yml'):
      file_data = self.diskapi_load_yaml(fn, verbose=False)
      summary = list(file_data.keys()) if isinstance(file_data, dict) else type(file_data).__name__
      self.P(f"Parsed YAML payload summary: {summary}")

    else:
      self.P(f"Error retrieving file: {fn}")
      error_response = "error"
      self._log_request_response("GET_YAML", response_data={'error': error_response})
      return error_response

    data = {
      "file_data" : file_data
    }
    
    # Log response
    response_summary = {
      'file_data_type': type(file_data).__name__,
      'file_data_keys': list(file_data.keys()) if isinstance(file_data, dict) else None
    }
    self._log_request_response("GET_YAML", response_data=response_summary)
    
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
    # Log request

    request_data = {
      'data': data,
      'fn': fn,
      'nonce': nonce,
      'secret': "***" if secret else None,
    }
    self._log_request_response("ADD_JSON", request_data=request_data)

    cid = self.r1fs.add_json(data=data, fn=fn, secret=secret, nonce=nonce)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("ADD_JSON", response_data=data)
    
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
    # Log request
    request_data = {
      'data': data,
      'fn': fn,
      'nonce': nonce,
      'secret': "***" if secret else None,
    }
    self._log_request_response("ADD_PICKLE", request_data=request_data)

    cid = self.r1fs.add_pickle(data=data, fn=fn, secret=secret, nonce=nonce)
    self.P(f"Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("ADD_PICKLE", response_data=data)
    
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
    # Log request
    request_data = {
      'data': data,
      'nonce': nonce,
      'fn': fn,
      'secret': "***" if secret else None,
    }
    self._log_request_response("CALCULATE_JSON_CID", request_data=request_data)

    cid = self.r1fs.calculate_json_cid(data=data, nonce=nonce, fn=fn, secret=secret)
    self.P(f"Calculated Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("CALCULATE_JSON_CID", response_data=data)
    
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
    # Log request
    request_data = {
      'data': data,
      'nonce': nonce,
      'fn': fn,
      'secret': "***" if secret else None,
    }
    self._log_request_response("CALCULATE_PICKLE_CID", request_data=request_data)

    cid = self.r1fs.calculate_pickle_cid(data=data, nonce=nonce, fn=fn, secret=secret)
    self.P(f"Calculated Cid='{cid}'")

    data = {
      "cid" : cid
    }
    
    # Log response
    self._log_request_response("CALCULATE_PICKLE_CID", response_data=data)
    
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
    # Log request
    request_data = {
      'cid': cid,
      'unpin_remote': unpin_remote,
      'run_gc': run_gc,
      'cleanup_local_files': cleanup_local_files
    }
    self._log_request_response("DELETE_FILE", request_data=request_data)

    self.P(f"Deleting file with CID='{cid}', unpin_remote={unpin_remote}, run_gc={run_gc}")

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
      self.P(message, color='g')
    else:
      message = f"Failed to delete file {cid}"
      self.P(message, color='r')

    response = {
      "success": success,
      "message": message,
      "cid": cid
    }

    # Log response
    self._log_request_response("DELETE_FILE", response_data=response)

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
    # Log request
    request_data = {
      'cids': cids,
      'unpin_remote': unpin_remote,
      'run_gc_after_all': run_gc_after_all,
      'cleanup_local_files': cleanup_local_files
    }
    self._log_request_response("DELETE_FILES", request_data=request_data)

    self.P(f"Bulk deleting {len(cids)} files, unpin_remote={unpin_remote}, run_gc_after_all={run_gc_after_all}")

    result = self.r1fs.delete_files(
      cids=cids,
      unpin_remote=unpin_remote,
      run_gc_after_all=run_gc_after_all,
      cleanup_local_files=cleanup_local_files,
      show_logs=True,
      raise_on_error=False
    )

    # Log response
    self._log_request_response("DELETE_FILES", response_data=result)

    return result

#########################################################################
#########################################################################
