"""
Local stand-in for everything a node looks up outside itself (test bed only).

A production node reads three kinds of facts from outside:

  * web addresses of network services (dAuth, the oracle and Deeploy APIs,
    the blockchain RPC), which the SDK hard-codes per network;
  * the network's seed nodes and thresholds, also hard-coded per network;
  * blockchain state: who is an oracle, which node is licensed, which job
    belongs to whom.

None of these exist inside a localnet. ``install`` points the addresses at
localnet services, replaces the seed list with the localnet seeds and answers
the blockchain questions from ``registry.json``, a file generated with the
localnet. It runs before the node code is imported and changes only SDK
tables and SDK blockchain methods, never node logic.
"""

import json
import os

REGISTRY_PATH = os.environ.get('R1_LOCALNET_REGISTRY', '/run/localnet/registry.json')
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


def load_registry():
  with open(REGISTRY_PATH, 'rt') as fh:
    return json.load(fh)


def rewrite_network_tables(registry):
  from ratio1.const import evm_net
  net = os.environ['EE_EVM_NET']
  table = evm_net.EVM_NET_DATA[net]
  for key, value in SERVICES.items():
    if key in table:
      table[key] = value
  for key, value in (registry.get('network') or {}).items():
    if key in table:
      table[key] = value
  consts = evm_net.EVM_NET_CONSTANTS[net]
  consts[evm_net.EvmNetConstants.SEED_NODES_ADDRESSES_KEY] = list(registry.get('seed_addresses') or [])
  for key, value in (registry.get('constants') or {}).items():
    if key in consts:
      consts[key] = value
  leaks = ['{}={}'.format(key, value) for key, value in table.items()
           if isinstance(value, str) and any(marker in value for marker in PUBLIC_MARKERS)]
  if leaks:
    say('REFUSING TO START: public addresses left in the {} table: {}'.format(net, leaks))
    os._exit(95)
  say('network {}: service addresses and seed list now point at the localnet'.format(net))
  return


def install():
  registry = load_registry()
  rewrite_network_tables(registry)
  return registry
