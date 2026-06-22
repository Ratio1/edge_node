from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.0.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 5081,
  'NGROK_ENABLED': False,
  'NGROK_USE_API': False,
  'ASSETS': '',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class EdgeNodeApiTestPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self):
    super(EdgeNodeApiTestPlugin, self).on_init()
    return


  @BasePlugin.endpoint(method='post')
  def some_j33ves_endpoint(self, message: str = "Create a simple users table DDL", domain: str = "sql"):
    self.P(f"Received request: message={message} | domain={domain}")
    response = {
      'request': {
        'message': message,
        'domain': domain
      },
      'response': 'something',
      'server': {
        'alias': self.node_id,
        'address': self.node_addr
      }
    }
    return response

  # ============================================================================
  # Diskapi endpoints -- used by tests/e2e/car/diskapi_path_reorg to exercise
  # pickle/json/dataframe save+load via a REAL deployed plugin and confirm the
  # files land under pipelines_data/{sid}/{iid}/...
  #
  # Uses plugin built-in accessors (self.pd, self.os_path, self.diskapi_*)
  # instead of top-level imports so the SECURED-mode code safety check
  # (_perform_module_safety_check) lets this plugin load.
  # ============================================================================

  @BasePlugin.endpoint(method='get')
  def whoami(self):
    """
    Return the plugin's identity + the resolved instance data subfolder /
    absolute base path. Lets tests discover the expected on-disk layout
    without relying on log scraping.
    """
    return {
      'stream_id': self._stream_id,
      'instance_id': self.cfg_instance_id,
      'plugin_id': self.plugin_id,
      'instance_data_subfolder': self._get_instance_data_subfolder(),
      'plugin_absolute_base': self._get_plugin_absolute_base(),
      'data_folder': self.get_data_folder(),
    }

  @BasePlugin.endpoint(method='post')
  def write_pickle(self, filename: str = "test.pkl", payload: dict = None, subfolder: str = None):
    """Save a pickle via diskapi_save_pickle_to_data."""
    if payload is None:
      payload = {'hello': 'world', 'n': 42}
    captured = []
    self.__capture_warnings(captured)
    try:
      self.diskapi_save_pickle_to_data(payload, filename, subfolder=subfolder)
      return {'ok': True, 'warnings': captured}
    except AssertionError as exc:
      return {'ok': False, 'error': 'assertion', 'message': str(exc), 'warnings': captured}
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def read_pickle(self, filename: str = "test.pkl", subfolder: str = None):
    """Load a pickle via diskapi_load_pickle_from_data."""
    captured = []
    self.__capture_warnings(captured)
    try:
      obj = self.diskapi_load_pickle_from_data(filename, subfolder=subfolder)
      return {'ok': True, 'payload': obj, 'warnings': captured}
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def write_json(self, filename: str = "test.json", payload: dict = None, subfolder: str = None):
    if payload is None:
      payload = {'k': 'v', 'n': 42}
    captured = []
    self.__capture_warnings(captured)
    try:
      self.diskapi_save_json_to_data(payload, filename, subfolder=subfolder)
      return {'ok': True, 'warnings': captured}
    except AssertionError as exc:
      return {'ok': False, 'error': 'assertion', 'message': str(exc), 'warnings': captured}
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def read_json(self, filename: str = "test.json", subfolder: str = None):
    captured = []
    self.__capture_warnings(captured)
    try:
      obj = self.diskapi_load_json_from_data(filename, subfolder=subfolder)
      return {'ok': True, 'payload': obj, 'warnings': captured}
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def write_dataframe(self, filename: str = "test.csv", rows: list = None, subfolder: str = None):
    """Save a DataFrame built from `rows` (list of dicts) via diskapi_save_dataframe_to_data."""
    if rows is None:
      rows = [{'a': 1, 'b': 'x'}, {'a': 2, 'b': 'y'}]
    df = self.pd.DataFrame(rows)
    captured = []
    self.__capture_warnings(captured)
    try:
      self.diskapi_save_dataframe_to_data(df, filename, subfolder=subfolder)
      return {'ok': True, 'warnings': captured, 'rows': len(df)}
    except AssertionError as exc:
      return {'ok': False, 'error': 'assertion', 'message': str(exc), 'warnings': captured}
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def read_dataframe(self, filename: str = "test.csv", subfolder: str = None):
    captured = []
    self.__capture_warnings(captured)
    try:
      df = self.diskapi_load_dataframe_from_data(filename, subfolder=subfolder)
      if df is None:
        return {'ok': True, 'payload': None, 'warnings': captured}
      return {
        'ok': True,
        'payload': df.to_dict(orient='records'),
        'rows': len(df),
        'warnings': captured,
      }
    finally:
      self.__restore_warnings()

  @BasePlugin.endpoint(method='post')
  def delete_file(self, filename: str = "test.pkl", subfolder: str = None):
    """
    Delete a filename under the plugin's data area via diskapi_delete_file
    (which runs through is_path_safe). Resolves the path the same way
    diskapi save does: default subfolder 'plugin_data' under the instance
    folder, or the named sibling.
    """
    sub = subfolder if subfolder else 'plugin_data'
    full = self.os_path.abspath(
      self.os_path.join(self.get_data_folder(), self._get_instance_data_subfolder(), sub, filename)
    )
    existed = self.os_path.isfile(full)
    if existed:
      # diskapi_delete_file checks is_path_safe and logs on failure but
      # doesn't surface a return value; follow up with a filesystem check.
      self.diskapi_delete_file(full)
    gone = not self.os_path.isfile(full)
    return {'ok': True, 'existed': existed, 'gone': gone, 'path': full}

  # ---- private warning-capture plumbing ------------------------------------

  def __capture_warnings(self, sink):
    """Redirect self.P calls matching DEPRECATION into `sink`."""
    self.__orig_P = self.P
    orig = self.__orig_P
    def _P(msg, *args, **kwargs):
      s = str(msg)
      if 'DEPRECATION' in s:
        sink.append(s)
      return orig(msg, *args, **kwargs)
    self.P = _P

  def __restore_warnings(self):
    if hasattr(self, '_EdgeNodeApiTestPlugin__orig_P'):
      self.P = self.__orig_P
      del self.__orig_P
