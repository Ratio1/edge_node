"""
Point a node's hard-coded network addresses at the localnet (test bed only).

The SDK hard-codes, per network, the web addresses of the services a node
talks to (dAuth, the oracle and Deeploy APIs, the blockchain RPC) and the
list of seed nodes. None of the real ones is reachable from a localnet, and
none may be reached. ``install`` replaces them with the localnet's own
services and seed nodes. Nothing else changes: contract addresses, epoch
length and thresholds stay those of the chosen network, and blockchain
questions are answered over JSON-RPC by ``infra/chain_rpc.py``, so the SDK
and the node run unmodified.

The table lives in ``ratio1/const/evm_net.py``, a file without imports. It is
loaded by path and registered under its real module name before anything
else is imported. Importing the ``ratio1`` package here instead would change
the import order of production (core first, then SDK), and the SDK would
then fail to detect the core version it reports to dAuth.
"""

import importlib.util
import json
import os
import sys

REGISTRY_PATH = os.environ.get('R1_LOCALNET_REGISTRY', '/run/localnet/registry.json')
SRC = os.environ.get('R1_LOCALNET_SRC', '/opt/r1src')
MODULE_NAME = 'ratio1.const.evm_net'
PUBLIC_MARKERS = ('ratio1.ai', 'publicnode.com', 'pocket.network', 'naeural.ai', 'github')

SERVICES = {
  'EE_DAUTH_URL': 'http://dauth.localnet/get_auth_data',
  'EE_DAUTH_RPC': 'http://rpc.localnet:8545',
  'EE_ORACLE_API_URL': 'http://oracle.localnet',
  'EE_DEEPLOY_API_URL': 'http://deeploy-api.localnet',
  'EE_DAPP_API_URL_KEY': 'http://dapp-api.localnet',
  'EE_DAPP_APP_URL': 'http://app.localnet',
  'EE_EXPLORER_APP_URL': 'http://explorer.localnet',
  'EE_DEEPLOY_APP_URL': 'http://deeploy.localnet',
}


def say(msg):
  print('[chain_shim] ' + msg, flush=True)
  return


def refuse(msg):
  say('REFUSING TO START: ' + msg)
  sys.stdout.flush()
  os._exit(95)


def load_tables():
  if MODULE_NAME in sys.modules:
    return sys.modules[MODULE_NAME]
  if 'ratio1' in sys.modules or 'naeural_core' in sys.modules:
    refuse('node code was imported before the network tables were replaced')
  path = os.path.join(SRC, 'sdk', 'ratio1', 'const', 'evm_net.py')
  spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  sys.modules[MODULE_NAME] = module
  return module


def leaks(module, net):
  table = module.EVM_NET_DATA[net]
  return ['{}={}'.format(key, value) for key, value in table.items()
          if isinstance(value, str) and any(marker in value for marker in PUBLIC_MARKERS)]


def install():
  with open(REGISTRY_PATH, 'rt') as fh:
    registry = json.load(fh)
  module = load_tables()
  net = os.environ['EE_EVM_NET']
  table = module.EVM_NET_DATA[net]
  for key, value in SERVICES.items():
    if key in table:
      table[key] = value
  for key, value in (registry.get('network') or {}).items():
    if key in table:
      table[key] = value
  consts = module.EVM_NET_CONSTANTS[net]
  seeds = consts[module.EvmNetConstants.SEED_NODES_ADDRESSES_KEY]
  seeds[:] = list(registry.get('seed_addresses') or [])  # in place: code that copied the list sees it too
  for key, value in (registry.get('constants') or {}).items():
    if key in consts:
      consts[key] = value
  left = leaks(module, net)
  if left:
    refuse('public addresses left in the {} table: {}'.format(net, left))
  say('network {}: service addresses and seed list now point at the localnet'.format(net))
  return registry


def verify(need_versions=True):
  """Call after the node code is imported: the tables in use must be the replaced ones."""
  import ratio1.const.evm_net as in_use
  net = os.environ['EE_EVM_NET']
  if in_use is not sys.modules[MODULE_NAME] or leaks(in_use, net):
    refuse('the node imported its own copy of the network tables')
  if in_use.EVM_NET_DATA[net]['EE_DAUTH_URL'] != SERVICES['EE_DAUTH_URL']:
    refuse('the dAuth address in use is {}'.format(in_use.EVM_NET_DATA[net]['EE_DAUTH_URL']))
  if need_versions:
    import ratio1.bc.base as bc_base
    if not bc_base.app_version or not bc_base.core_version:
      refuse('the SDK did not detect the node versions (app {}, core {}): dAuth would reject this node'.format(
        bc_base.app_version, bc_base.core_version))
    say('versions reported to dAuth: app {}, core {}'.format(bc_base.app_version, bc_base.core_version))
  return True
