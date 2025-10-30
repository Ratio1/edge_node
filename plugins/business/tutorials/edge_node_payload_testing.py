from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.1.0.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 44444,
  'NGROK_ENABLED': False,
  'NGROK_USE_API': False,
  'ASSETS': '',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
"""
In order to deploy this plugin, you have to run the code below:
  node = "node_address"
  session: Session = Session(encrypt_comms=True)
  session.wait_for_node(node)

  pipeline: Pipeline = session.create_pipeline(
    node=node,
    name='edge_node__test',
  )

  instance: Instance = pipeline.create_plugin_instance(
    signature='EDGE_NODE_PAYLOAD_TESTING',
    instance_id='edge_node_payload_test_001',

    config={
      'DEBUG_MODE': True,
      'ASSETS': ''
    },
  )

  pipeline.deploy()

  session.wait(
    seconds=6000,            # we wait the session for 6000 seconds
    close_pipelines=True,   # we close the pipelines after the session
    close_session=True,     # we close the session after the session
  )
"""

class EdgeNodePayloadTestingPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self):
    super(EdgeNodePayloadTestingPlugin, self).on_init()
    return


  @BasePlugin.endpoint(method='post')
  def send_messages(self, count: int = 1, length: int = 46, node_address: str = ''):
    messages = []
    for i in range(count):
      word = ''.join(ALPHABET[i] for i in self.np.random.randint(len(ALPHABET), size=length))
      messages.append(word)
    try:
      self.send_encrypted_payload(node_addr=node_address, messages=messages)
    except Exception as e:
      self.P("An error occurred:")
      self.P(e)
    return messages



