"""Docker-only HTTP fixture: real endpoint/auth methods, EOA crypto, fake chain/CStore.

Run with ``python -m extensions.business.deeploy.tests.delegate_aliases_harness``.
The published 0x01 test key is synthetic; never point this fixture at live services.
"""

import ast
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_checksum_address, to_checksum_address

from extensions.business.deeploy.delegate_aliases import _DelegateAliasesMixin, ETH_ADDRESS
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS

TEST_KEY = '01' * 32
OWNER = Account.from_key(TEST_KEY).address.lower()
DELEGATE = Account.from_key('02' * 32).address.lower()
OTHER_OWNER = Account.from_key('03' * 32).address.lower()
OTHER_DELEGATE = '0x' + '0' * 39 + '3'
ESCROW = '0x' + 'a' * 40
PREFIX = 'Please sign this message for Deeploy: '


# Extract unchanged production method bodies without importing the entire runtime.
def load_class(filename, class_name, method_names, bases, namespace):
  tree = ast.parse((Path(__file__).parents[1] / filename).read_text())
  original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
  methods = [node for node in original.body if isinstance(node, ast.FunctionDef) and node.name in method_names]
  assert len(methods) == len(method_names), 'Production method names changed; update the fixture explicitly.'
  for method in methods:
    method.decorator_list = []  # HTTP decorator registration belongs to the excluded web runtime.
  tree.body = [ast.ClassDef(name=class_name, bases=[ast.Name(id=base, ctx=ast.Load()) for base in bases], keywords=[], body=methods, decorator_list=[])]
  exec(compile(ast.fix_missing_locations(tree), filename, 'exec'), namespace)
  return namespace[class_name]


class Inputs(dict):
  __getattr__ = dict.__getitem__


class Chain:
  network = 'devnet'
  active = True
  members = {DELEGATE, OTHER_DELEGATE}

  def is_valid_eth_address(self, address):
    return isinstance(address, str) and bool(ETH_ADDRESS.fullmatch(address))

  eth_addr_to_checksum_address = staticmethod(to_checksum_address)  # Same checksum normalization as the real adapter.

  def get_evm_network(self):
    return self.network

  def get_user_escrow_details(self, address):
    if not is_checksum_address(address):  # Model the Web3 ABI boundary used by the real SDK adapter.
      raise ValueError('Web3 requires a checksummed Ethereum address.')
    if address.lower() == OTHER_OWNER:  # Independent CSP owner for UI scope-isolation tests.
      return {'isActive': True, 'escrowAddress': '0x' + 'b' * 40, 'escrowOwner': OTHER_OWNER}
    return {'isActive': self.active and address.lower() in self.members | {OWNER}, 'escrowAddress': ESCROW, 'escrowOwner': OWNER}

  def eth_verify_payload_signature(self, payload, **kwargs):
    unsigned = {key: value for key, value in payload.items() if key not in ('EE_ETH_SIGN', 'EE_ETH_SENDER')}
    message = PREFIX + json.dumps(unsigned, indent=1, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return Account.recover_message(encode_defunct(text=message), signature=payload['EE_ETH_SIGN'])  # Real EIP-191 recovery; no accepted fake signatures.


namespace = {
  'BASE_CT': SimpleNamespace(BCctbase=SimpleNamespace(ETH_SENDER='EE_ETH_SENDER', ETH_SIGN='EE_ETH_SIGN', HASH='EE_HASH')),
  'DEEPLOY_KEYS': DEEPLOY_KEYS, 'DEEPLOY_STATUS': DEEPLOY_STATUS,
  'DEEPLOY_DEBUG': False, 'MESSAGE_PREFIX': PREFIX,
  '_DelegateAliasesMixin': _DelegateAliasesMixin,
}
_DeeployMixin = load_class('deeploy_mixin.py', '_DeeployMixin', {
  '__verify_signature', '__check_allowed_wallet', 'deeploy_verify_and_get_inputs',
  'deeploy_get_auth_result', 'deeploy_get_nonce',
}, [], namespace)
DeeployManagerApiPlugin = load_class('deeploy_manager_api.py', 'DeeployManagerApiPlugin', {
  'get_delegate_aliases', 'set_delegate_alias',
}, ['_DeeployMixin', '_DelegateAliasesMixin'], namespace)


def make_plugin(storage=None):
  plugin = DeeployManagerApiPlugin()
  plugin.bc = Chain()
  plugin.bc.members = {DELEGATE, OTHER_DELEGATE}  # Each test controls its own mocked chain state.
  plugin.NestedDotDict = Inputs
  plugin.time = time.time
  plugin.time_to_str = str
  plugin.Pd = plugin.P = lambda *args, **kwargs: None
  plugin._redact_per_node_config_for_log = lambda payload: payload
  plugin._get_response = lambda result: result
  plugin._DeeployManagerApiPlugin__handle_error = lambda exc, request: {'status': 'fail', 'error': str(exc)}
  plugin.storage = {} if storage is None else storage
  plugin.write_ok = True
  plugin.chainstore_hget = lambda hkey, key: plugin.storage.get(hkey + '/' + key)

  def write(hkey, key, value):
    if not plugin.write_ok:
      return False
    plugin.storage[hkey + '/' + key] = value
    return True

  plugin.chainstore_hset = write
  return plugin


def sign(payload, private_key=TEST_KEY, nonce=None):
  payload = {**payload, 'nonce': nonce or hex(int(time.time() * 1000) - 1000)}  # Exercise production nonce expiry validation too.
  message = PREFIX + json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
  signature = Account.sign_message(encode_defunct(text=message), private_key).signature.hex()
  return {**payload, 'EE_ETH_SENDER': Account.from_key(private_key).address, 'EE_ETH_SIGN': '0x' + signature}


if __name__ == '__main__':
  store_path = Path(os.environ.get('ALIAS_TEST_STORE', '/tmp/delegate-aliases.json'))
  plugin = make_plugin(json.loads(store_path.read_text()) if store_path.exists() else {})

  class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
      self.send_response(204)
      self.send_header('Access-Control-Allow-Origin', '*')
      self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
      self.send_header('Access-Control-Allow-Methods', 'POST,OPTIONS,GET')
      self.end_headers()

    def do_GET(self):
      self.send_response(200)
      self.end_headers()
      self.wfile.write(b'alias fixture ready')

    def do_POST(self):
      method = {'/get_delegate_aliases': plugin.get_delegate_aliases, '/set_delegate_alias': plugin.set_delegate_alias}.get(self.path)
      request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['request']
      result = method(request) if method else {'status': 'fail', 'error': 'Unknown endpoint'}
      store_path.write_text(json.dumps(plugin.storage))  # Fixture persistence proves new sessions do not depend on browser state.
      self.send_response(200)
      self.send_header('Access-Control-Allow-Origin', '*')
      self.send_header('Content-Type', 'application/json')
      self.end_headers()
      self.wfile.write(json.dumps({'result': result}).encode())

  HTTPServer(('0.0.0.0', 5000), Handler).serve_forever()
