from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.1.0.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'CODE_TIMEOUT': 10,
  'SAVE_PERIOD': 60,
  "PROCESS_DELAY": 0.2,

  'ASSETS': 'plugins/business/fastapi/sandbox',
  'JINJA_ARGS': {
    'html_files': [
      {
        'name': 'index.html',
        'route': '/',
        'method': 'get'
      }
    ]
  },
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class NaeuralCodeSandboxPlugin(BasePlugin):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(NaeuralCodeSandboxPlugin, self).__init__(**kwargs)
    self.last_persistence_save_ts = self.time()
    self.request_history = []
    return

  def on_init(self):
    super(NaeuralCodeSandboxPlugin, self).on_init()
    self.load_persistence_data()
    return

  def maybe_persistence_save(self, force=False):
    if force or self.time() - self.last_persistence_save_ts > self.cfg_save_period:
      self.last_persistence_save_ts = self.time()
      obj = {
        'request_history': self.request_history
      }
      self.persistence_serialization_save(obj)
    # endif save needed
    return

  def load_persistence_data(self):
    data = self.persistence_serialization_load()
    if data is not None:
      prev_history = data.get('request_history', [])
      self.request_history = self.request_history + prev_history
    return

  @BasePlugin.endpoint(method='get')
  def code_history(self):
    return self.request_history

  @BasePlugin.endpoint(method='post')
  def remote_execute(self, code: str, debug: bool = False):
    if isinstance(code, str) and len(code) > 0:
      self.request_history.append({
        'code': code,
        'debug': debug,
        'ts': self.time()
      })
    # endif code added to the history
    return self.execute_remote_code(
      code=code,
      debug=debug,
      timeout=self.cfg_code_timeout
    )

  def process(self):
    super(NaeuralCodeSandboxPlugin, self).process()
    self.maybe_persistence_save()
    return

