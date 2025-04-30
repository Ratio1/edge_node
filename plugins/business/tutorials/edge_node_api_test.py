from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.1.0.0'

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
