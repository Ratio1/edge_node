from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from extensions.business.mixins.chainstore_response_mixin import _ChainstoreResponseMixin

__VER__ = '0.1.0.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  # Optional key for sending plugin lifecycle confirmations to chainstore (set once after init)
  'CHAINSTORE_RESPONSE_KEY': None,

  'PORT': 5081,
  'NGROK_ENABLED': False,
  'NGROK_USE_API': False,
  'ASSETS': '',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class EdgeNodeApiTestPlugin(BasePlugin, _ChainstoreResponseMixin):
  CONFIG = _CONFIG

  def on_init(self):
    super(EdgeNodeApiTestPlugin, self).on_init()

    # Reset chainstore response key at start (signals "initializing")
    self._reset_chainstore_response()

    # Plugin initialization happens here (currently minimal)

    # Send chainstore response at end (signals "ready")
    self._send_chainstore_response()

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
