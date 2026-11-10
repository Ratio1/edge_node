#!/usr/bin/env python3
"""
Local blockchain for a localnet: a JSON-RPC endpoint that answers the contract
calls a Ratio1 node makes, from a JSON state file.

Why a JSON-RPC endpoint and not patched SDK methods: with it the SDK and the
node run unmodified. They build the same web3 calls, pay a network round trip
with a configurable delay, decode the same ABI answers and keep the same
caches as against the real chain. An RPC outage or slowdown can be injected.

Contracts are recognised by the addresses and ABIs of the SDK source tree
under test, so the service follows whatever that SDK version calls. A call to
a function without a handler gets a zero answer of the right shape and is
counted, so missing coverage shows up in ``/_stats``.

State (``chain.json``)
----------------------
nodes    eth address -> {name, address, licensed, banned, oracle, dauth_oracle,
                         license_type, license_id, owner, assign_ts}
escrows  escrow address -> {owner, active, permissions}
jobs     job id -> {project_hash, request_ts, start_ts, last_nodes_change_ts,
                    job_type, price_per_epoch, last_execution_epoch,
                    nodes_requested, balance, last_allocated_epoch,
                    active_nodes, escrow}
logs     emitted events (licence link / unlink, escrow owner transfer)

Control (plain HTTP, same port)
-------------------------------
GET  /_stats    counters per RPC method and contract function
GET  /_state    the current state
POST /_control  {"latency_ms": n, "jitter_ms": n, "fail": bool, "hang_s": n,
                 "dapp_latency_ms": n, "dapp_hang_s": n}
GET  /accounts/is-kyb   the one dApp backend call a node makes (dAuth node tags)
POST /_admin    {"op": "...", ...}: add_node, set_node, relink, add_escrow,
                add_job, set_job, remove_job
"""

import importlib.util
import json
import os
import random
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, '/opt/localnet/node')
import guard  # noqa: E402

STATE_PATH = os.environ.get('R1_CHAIN_STATE', '/chain/chain.json')
SDK_ROOT = os.environ.get('R1_LOCALNET_SDK', '/opt/r1src/sdk')
NETWORK = os.environ.get('EE_EVM_NET', 'mainnet')
PORT = int(os.environ.get('R1_CHAIN_PORT', '8545'))
CHAIN_IDS = {'mainnet': 8453, 'testnet': 84532, 'devnet': 84532}
ZERO_ADDRESS = '0x' + '00' * 20
BLOCK_SECONDS = 2
BLOCK_BASE = 30_000_000

LOCK = threading.RLock()
STATE = {}
STATS = {'rpc': {}, 'calls': {}, 'unhandled': {}, 'transactions': 0, 'started': time.time()}
CONTROL = {
  'latency_ms': float(os.environ.get('R1_CHAIN_LATENCY_MS', '120')),
  'jitter_ms': float(os.environ.get('R1_CHAIN_JITTER_MS', '80')),
  'fail': False,
  'hang_s': 0.0,
  'dapp_latency_ms': float(os.environ.get('R1_DAPP_LATENCY_MS', '150')),
  'dapp_hang_s': 0.0,
}
SELECTORS = {}  # (contract address lower | None, selector) -> (contract name, function abi)
EVENT_TOPICS = {}  # event name -> topic0
RECEIPTS = {}
NONCES = {}


def say(msg):
  print('[chain {}] {}'.format(time.strftime('%H:%M:%S'), msg), flush=True)
  return


# ---------------------------------------------------------------- ABI

def canonical(item):
  if item['type'].startswith('tuple'):
    return '(' + ','.join(canonical(comp) for comp in item['components']) + ')' + item['type'][5:]
  return item['type']


def zero(item_type, components=None):
  if item_type.endswith(']'):
    return []
  if item_type.startswith('tuple'):
    return tuple(zero(comp['type'], comp.get('components')) for comp in components)
  if item_type.startswith(('uint', 'int')):
    return 0
  if item_type == 'bool':
    return False
  if item_type == 'address':
    return ZERO_ADDRESS
  if item_type == 'string':
    return ''
  if item_type == 'bytes':
    return b''
  if item_type.startswith('bytes'):
    return b'\x00' * int(item_type[5:])
  raise ValueError('unknown ABI type ' + item_type)


def load_contracts():
  from eth_utils import keccak
  spec = importlib.util.spec_from_file_location('r1_evm_net', os.path.join(SDK_ROOT, 'ratio1', 'const', 'evm_net.py'))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  net = module.EVM_NET_DATA[NETWORK]
  address_of = {
    'CONTROLLER_ABI': net.get('EE_DAUTH_CONTROLLER_ADDR'),
    'DAUTH_ORACLE_REGISTRY_ABI': net.get('EE_DAUTH_ORACLE_REGISTRY_ADDR'),
    'ND_ABI': net.get('EE_DAUTH_ND_ADDR'),
    'ERC20_ABI': net.get('EE_DAUTH_R1_ADDR'),
    'PROXY_ABI': net.get('EE_DAUTH_PROXYAPI_ADDR'),
    'POAI_MANAGER_ABI': net.get('EE_DAUTH_POAI_MANAGER_ADDR'),
    'ATTESTATION_REGISTRY_ABI': net.get('EE_DAUTH_ATTESTATION_REGISTRY_ADDR'),
    'CSP_ESCROW_ABI': None,  # one contract per escrow, any address
  }
  abis = module.EVM_ABI_DATA
  for name in dir(abis):
    if not name.endswith('_ABI'):
      continue
    address = address_of.get(name)
    for item in getattr(abis, name):
      if item.get('type') == 'function':
        signature = '{}({})'.format(item['name'], ','.join(canonical(inp) for inp in item['inputs']))
        selector = keccak(text=signature)[:4].hex()
        SELECTORS[(address.lower() if address else None, selector)] = (name, item)
        SELECTORS.setdefault((None, selector), (name, item))
      elif item.get('type') == 'event':
        signature = '{}({})'.format(item['name'], ','.join(inp['type'] for inp in item['inputs']))
        EVENT_TOPICS[item['name']] = '0x' + keccak(text=signature).hex()
  STATE['_contracts'] = {name: address for name, address in address_of.items() if address}
  say('contracts of {}: {} functions, {} events'.format(NETWORK, len({k[1] for k in SELECTORS}), len(EVENT_TOPICS)))
  return


# ---------------------------------------------------------------- state

def block_number():
  return BLOCK_BASE + int((time.time() - STATE['genesis']) / BLOCK_SECONDS)


def checksum(address):
  from eth_utils import to_checksum_address
  return to_checksum_address(address)


def load_state():
  with open(STATE_PATH, 'rt') as fh:
    data = json.load(fh)
  data.setdefault('nodes', {})
  data.setdefault('escrows', {})
  data.setdefault('jobs', {})
  data.setdefault('logs', [])
  data.setdefault('genesis', time.time() - 3600)
  data['nodes'] = {key.lower(): val for key, val in data['nodes'].items()}
  data['escrows'] = {key.lower(): val for key, val in data['escrows'].items()}
  STATE.update(data)
  return


def save_state():
  tmp = STATE_PATH + '.tmp'
  with open(tmp, 'wt') as fh:
    json.dump({key: val for key, val in STATE.items() if not key.startswith('_')}, fh, indent=1, sort_keys=True)
  os.replace(tmp, STATE_PATH)
  return


def emit(contract, event, indexed, data_types, data_values):
  from eth_abi import encode
  topics = [EVENT_TOPICS[event]]
  for kind, value in indexed:
    topics.append('0x' + encode([kind], [value]).hex())
  number = block_number()
  STATE['logs'].append({
    'address': checksum(STATE['_contracts'][contract]),
    'topics': topics,
    'data': '0x' + encode(data_types, data_values).hex(),
    'blockNumber': number,
    'transactionHash': '0x' + os.urandom(32).hex(),
    'logIndex': len(STATE['logs']),
  })
  return


def job_tuple(job_id, with_escrow=True):
  job = STATE['jobs'][str(job_id)]
  base = (
    int(job_id), bytes.fromhex(job.get('project_hash', '00' * 32)), int(job.get('request_ts', 0)),
    int(job.get('start_ts', 0)), int(job.get('last_nodes_change_ts', 0)), int(job.get('job_type', 1)),
    int(job.get('price_per_epoch', 0)), int(job.get('last_execution_epoch', 0)),
    int(job.get('nodes_requested', len(job.get('active_nodes', [])))), int(job.get('balance', 10 ** 12)),
    int(job.get('last_allocated_epoch', 0)), [checksum(addr) for addr in job.get('active_nodes', [])],
  )
  if not with_escrow:
    return base
  escrow = job.get('escrow', ZERO_ADDRESS)
  owner = STATE['escrows'].get(escrow.lower(), {}).get('owner', ZERO_ADDRESS)
  return base + (checksum(escrow), checksum(owner))


def node_of(address):
  return STATE['nodes'].get(str(address).lower())


# ---------------------------------------------------------------- contract functions

def fn_isNodeActive(to, args):
  node = node_of(args[0])
  return [bool(node and node.get('licensed') and not node.get('banned'))]


def fn_getOracles(to, args):
  return [[checksum(addr) for addr, node in sorted(STATE['nodes'].items()) if node.get('oracle')]]


def fn_getDAuthOracles(to, args):
  return [[checksum(addr) for addr, node in sorted(STATE['nodes'].items()) if node.get('dauth_oracle')]]


def fn_isDAuthOracle(to, args):
  node = node_of(args[0])
  return [bool(node and node.get('dauth_oracle'))]


def fn_getNodeLicenseDetails(to, args):
  node = node_of(args[0])
  if not node or not node.get('licensed'):
    return None
  return [(
    int(node.get('license_type', 1)), int(node.get('license_id', 0)), checksum(node.get('owner', ZERO_ADDRESS)),
    checksum(args[0]), 0, 0, 0, int(node.get('assign_ts', STATE['genesis'])), ZERO_ADDRESS,
    bool(node.get('banned')), 0, 0,
  )]


def fn_getWalletNodes(to, args):
  wallet = str(args[0]).lower()
  return [[checksum(addr) for addr, node in sorted(STATE['nodes'].items())
           if node.get('licensed') and str(node.get('owner', '')).lower() == wallet]]


def fn_getAddressesBalances(to, args):
  return [[(checksum(addr), 10 ** 18, 10 ** 21) for addr in args[0]]]


def fn_getUserEscrowDetails(to, args):
  wallet = str(args[0]).lower()
  for escrow, info in STATE['escrows'].items():
    if str(info.get('owner', '')).lower() == wallet or wallet in [str(x).lower() for x in info.get('delegates', [])]:
      return [(bool(info.get('active', True)), checksum(escrow), checksum(info['owner']), int(info.get('permissions', 15)))]
  return None


def fn_escrowToOwner(to, args):
  info = STATE['escrows'].get(str(args[0]).lower())
  return [checksum(info['owner'])] if info else None


def fn_getJobDetails(to, args):
  if str(args[0]) not in STATE['jobs']:
    return None
  return [job_tuple(args[0])]


def fn_getAllActiveJobs(to, args):
  return [[job_tuple(job_id) for job_id in sorted(STATE['jobs'], key=int)]]


def fn_getActiveJobs(to, args):
  return [[job_tuple(job_id, with_escrow=False) for job_id in sorted(STATE['jobs'], key=int)
           if str(STATE['jobs'][job_id].get('escrow', '')).lower() == str(to).lower()]]


def fn_getUnvalidatedJobIds(to, args):
  # A bought job stays unvalidated until an oracle reports the nodes that run it (submitNodeUpdate).
  return [[int(job_id) for job_id in sorted(STATE['jobs'], key=int) if not int(STATE['jobs'][job_id].get('start_ts', 0))]]


def fn_getIsLastEpochAllocated(to, args):
  return [True]


def fn_getFirstClosableJobId(to, args):
  return [0]


def fn_balanceOf(to, args):
  return [10 ** 21]


def fn_decimals(to, args):
  return [18]


def tx_submitNodeUpdate(sender, args):
  job = STATE['jobs'].get(str(args[0]))
  if job is not None:
    job['active_nodes'] = [checksum(addr) for addr in args[1]]
    job['last_nodes_change_ts'] = int(time.time())
    if job['active_nodes'] and not int(job.get('start_ts', 0)):
      job['start_ts'] = int(time.time())
    job.setdefault('node_updates', []).append({'by': sender, 'at': time.time(), 'nodes': job['active_nodes']})
  return


TRANSACTIONS = {'submitNodeUpdate': tx_submitNodeUpdate}


def eth_call(params):
  from eth_abi import decode, encode
  call = params[0]
  to = str(call.get('to') or '').lower()
  data = call.get('data') or call.get('input') or '0x'
  selector = data[2:10]
  found = SELECTORS.get((to, selector)) or SELECTORS.get((None, selector))
  if not found:
    STATS['unhandled']['selector ' + selector] = STATS['unhandled'].get('selector ' + selector, 0) + 1
    return '0x'
  _contract, item = found
  name = item['name']
  STATS['calls'][name] = STATS['calls'].get(name, 0) + 1
  args = decode([canonical(inp) for inp in item['inputs']], bytes.fromhex(data[10:])) if item['inputs'] else ()
  handler = globals().get('fn_' + name)
  with LOCK:
    values = handler(to, args) if handler else None
  if handler is None:
    STATS['unhandled'][name] = STATS['unhandled'].get(name, 0) + 1
  if values is None:
    values = [zero(out['type'], out.get('components')) for out in item['outputs']]
  return '0x' + encode([canonical(out) for out in item['outputs']], values).hex()


def send_raw_transaction(params):
  import rlp
  from eth_abi import decode
  from eth_account import Account
  from eth_utils import keccak
  raw = bytes.fromhex(params[0][2:])
  tx_hash = '0x' + keccak(raw).hex()
  sender = Account.recover_transaction(params[0])
  if raw[0] <= 0x7f:
    fields = rlp.decode(raw[1:])
    to, data = (fields[5], fields[7]) if raw[0] == 2 else (fields[4], fields[6])
  else:
    fields = rlp.decode(raw)
    to, data = fields[3], fields[5]
  found = SELECTORS.get(('0x' + to.hex(), data[:4].hex())) or SELECTORS.get((None, data[:4].hex()))
  name = found[1]['name'] if found else 'unknown'
  with LOCK:
    STATS['transactions'] += 1
    STATS['calls']['tx ' + name] = STATS['calls'].get('tx ' + name, 0) + 1
    NONCES[sender.lower()] = NONCES.get(sender.lower(), 0) + 1
    if found and name in TRANSACTIONS:
      item = found[1]
      args = decode([canonical(inp) for inp in item['inputs']], data[4:])
      TRANSACTIONS[name](sender, args)
      save_state()
    number = block_number()
    RECEIPTS[tx_hash] = {
      'transactionHash': tx_hash, 'transactionIndex': '0x0', 'blockNumber': hex(number),
      'blockHash': '0x' + keccak(number.to_bytes(8, 'big')).hex(), 'from': sender, 'to': checksum('0x' + to.hex()),
      'cumulativeGasUsed': '0x5208', 'gasUsed': '0x5208', 'effectiveGasPrice': '0x3b9aca00', 'contractAddress': None,
      'logs': [], 'logsBloom': '0x' + '00' * 256, 'status': '0x1', 'type': '0x2',
    }
  return tx_hash


def get_logs(params):
  from eth_utils import keccak
  flt = params[0]
  start = int(flt.get('fromBlock', '0x0'), 16) if str(flt.get('fromBlock', '0x0')).startswith('0x') else 0
  end_raw = flt.get('toBlock', 'latest')
  end = int(end_raw, 16) if str(end_raw).startswith('0x') else block_number()
  addresses = flt.get('address')
  if isinstance(addresses, str):
    addresses = [addresses]
  addresses = [addr.lower() for addr in addresses] if addresses else None
  topics = flt.get('topics') or []
  result = []
  with LOCK:
    for entry in STATE['logs']:
      if not start <= entry['blockNumber'] <= end:
        continue
      if addresses and entry['address'].lower() not in addresses:
        continue
      matched = True
      for idx, want in enumerate(topics):
        if want is None:
          continue
        wants = [want] if isinstance(want, str) else want
        if idx >= len(entry['topics']) or entry['topics'][idx].lower() not in [w.lower() for w in wants]:
          matched = False
          break
      if matched:
        result.append({
          'address': entry['address'], 'topics': entry['topics'], 'data': entry['data'],
          'blockNumber': hex(entry['blockNumber']), 'transactionHash': entry['transactionHash'],
          'transactionIndex': '0x0', 'logIndex': hex(entry['logIndex']), 'removed': False,
          'blockHash': '0x' + keccak(entry['blockNumber'].to_bytes(8, 'big')).hex(),
        })
  return result


def block(number):
  from eth_utils import keccak
  return {
    'number': hex(number), 'hash': '0x' + keccak(number.to_bytes(8, 'big')).hex(),
    'parentHash': '0x' + keccak((number - 1).to_bytes(8, 'big')).hex(),
    'timestamp': hex(int(STATE['genesis'] + (number - BLOCK_BASE) * BLOCK_SECONDS)),
    'gasLimit': hex(30_000_000), 'gasUsed': '0x0', 'baseFeePerGas': hex(10 ** 6), 'transactions': [],
    'miner': ZERO_ADDRESS, 'difficulty': '0x0', 'totalDifficulty': '0x0', 'extraData': '0x', 'size': '0x0',
    'nonce': '0x0000000000000000', 'sha3Uncles': '0x' + '00' * 32, 'logsBloom': '0x' + '00' * 256,
    'transactionsRoot': '0x' + '00' * 32, 'stateRoot': '0x' + '00' * 32, 'receiptsRoot': '0x' + '00' * 32,
    'uncles': [], 'mixHash': '0x' + '00' * 32,
  }


def dispatch(method, params):
  if method == 'eth_call':
    return eth_call(params)
  if method == 'eth_chainId':
    return hex(CHAIN_IDS[NETWORK])
  if method == 'net_version':
    return str(CHAIN_IDS[NETWORK])
  if method == 'web3_clientVersion':
    return 'r1-localnet-chain/1.0'
  if method == 'eth_blockNumber':
    return hex(block_number())
  if method == 'eth_getBlockByNumber':
    tag = params[0]
    return block(int(tag, 16) if str(tag).startswith('0x') else block_number())
  if method == 'eth_getBalance':
    return hex(10 ** 18)
  if method == 'eth_getTransactionCount':
    return hex(NONCES.get(str(params[0]).lower(), 0))
  if method in ('eth_gasPrice', 'eth_maxPriorityFeePerGas'):
    return hex(10 ** 6)
  if method == 'eth_estimateGas':
    return hex(200_000)
  if method == 'eth_feeHistory':
    count = int(params[0], 16) if isinstance(params[0], str) else int(params[0])
    return {'oldestBlock': hex(block_number() - count), 'baseFeePerGas': [hex(10 ** 6)] * (count + 1),
            'gasUsedRatio': [0.1] * count, 'reward': [[hex(10 ** 6)] * len(params[2] or [])] * count}
  if method == 'eth_getCode':
    return '0x6000'
  if method == 'eth_sendRawTransaction':
    return send_raw_transaction(params)
  if method == 'eth_getTransactionReceipt':
    return RECEIPTS.get(params[0])
  if method == 'eth_getTransactionByHash':
    receipt = RECEIPTS.get(params[0])
    return dict(receipt, hash=params[0], input='0x', value='0x0', nonce='0x0', gas='0x5208') if receipt else None
  if method == 'eth_getLogs':
    return get_logs(params)
  if method == 'eth_syncing':
    return False
  STATS['unhandled']['rpc ' + method] = STATS['unhandled'].get('rpc ' + method, 0) + 1
  raise ValueError('method {} is not supported by the localnet chain'.format(method))


# ---------------------------------------------------------------- admin

def admin(request):
  op = request.get('op')
  with LOCK:
    if op in ('add_node', 'set_node'):
      eth = request['eth_address'].lower()
      node = STATE['nodes'].setdefault(eth, {})
      node.update({key: val for key, val in request.items() if key not in ('op', 'eth_address')})
      node.setdefault('licensed', True)
      node.setdefault('assign_ts', int(time.time()))
    elif op == 'relink':
      # The owner moves a licence from one node to another, as the dApp does: UnlinkNode then LinkNode.
      old, new = request['old'].lower(), request['new'].lower()
      src = STATE['nodes'][old]
      owner, license_id = checksum(src['owner']), int(src['license_id'])
      dst = STATE['nodes'].setdefault(new, {})
      dst.update({key: src[key] for key in ('license_type', 'license_id', 'owner') if key in src})
      dst.update({'licensed': True, 'assign_ts': int(time.time())})
      dst.update({key: val for key, val in request.items() if key in ('name', 'address')})
      src['licensed'] = False
      emit('ND_ABI', 'UnlinkNode', [('address', owner), ('uint256', license_id)], ['address'], [checksum(old)])
      emit('ND_ABI', 'LinkNode', [('address', owner), ('uint256', license_id)], ['address'], [checksum(new)])
    elif op == 'add_escrow':
      STATE['escrows'][request['escrow'].lower()] = {
        'owner': request['owner'], 'active': request.get('active', True), 'permissions': request.get('permissions', 15),
        'delegates': request.get('delegates', []),
      }
    elif op in ('add_job', 'set_job'):
      job = STATE['jobs'].setdefault(str(request['job_id']), {})
      job.update({key: val for key, val in request.items() if key not in ('op', 'job_id')})
      job.setdefault('request_ts', int(time.time()))
      job.setdefault('start_ts', 0)  # not started: Deeploy accepts a first deployment only for such a job
    elif op == 'remove_job':
      STATE['jobs'].pop(str(request['job_id']), None)
    else:
      raise ValueError('unknown admin op {}'.format(op))
    save_state()
  return {'ok': True, 'block': block_number()}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'

  def log_message(self, *args):
    return

  def _send(self, payload, code=200):
    body = json.dumps(payload).encode()
    self.send_response(code)
    self.send_header('Content-Type', 'application/json')
    self.send_header('Content-Length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)
    return

  def do_GET(self):
    if self.path == '/_stats':
      return self._send(dict(STATS, control=CONTROL, block=block_number(), uptime=time.time() - STATS['started']))
    if self.path == '/_state':
      with LOCK:
        return self._send({key: val for key, val in STATE.items()})
    if self.path.startswith('/accounts/is-kyb'):
      # The dApp backend, which dAuth asks whether a licence owner passed business verification.
      STATS['calls']['dapp is-kyb'] = STATS['calls'].get('dapp is-kyb', 0) + 1
      if CONTROL['dapp_hang_s']:
        time.sleep(CONTROL['dapp_hang_s'])
      time.sleep(CONTROL['dapp_latency_ms'] / 1000.0)
      return self._send({'data': False})
    return self._send({'error': 'not found'}, 404)

  def _one(self, request):
    method = request.get('method')
    STATS['rpc'][method] = STATS['rpc'].get(method, 0) + 1
    try:
      return {'jsonrpc': '2.0', 'id': request.get('id'), 'result': dispatch(method, request.get('params') or [])}
    except Exception as exc:
      return {'jsonrpc': '2.0', 'id': request.get('id'), 'error': {'code': -32000, 'message': str(exc)}}

  def do_POST(self):
    length = int(self.headers.get('Content-Length') or 0)
    try:
      request = json.loads(self.rfile.read(length) or b'{}')
    except ValueError:
      return self._send({'error': 'bad json'}, 400)
    if self.path == '/_control':
      CONTROL.update({key: val for key, val in request.items() if key in CONTROL})
      return self._send(CONTROL)
    if self.path == '/_admin':
      try:
        return self._send(admin(request))
      except Exception as exc:
        return self._send({'ok': False, 'error': str(exc)}, 400)
    if CONTROL['hang_s']:
      time.sleep(CONTROL['hang_s'])
    delay = CONTROL['latency_ms'] + random.uniform(0, CONTROL['jitter_ms'])
    if delay > 0:
      time.sleep(delay / 1000.0)
    if CONTROL['fail']:
      return self._send({'error': 'localnet chain: injected RPC failure'}, 503)
    if isinstance(request, list):
      return self._send([self._one(item) for item in request])
    return self._send(self._one(request))


def main():
  guard.enforce(who='chain')
  load_state()
  load_contracts()
  save_state()
  say('{} nodes ({} oracles), {} jobs; latency {} ms + up to {} ms'.format(
    len(STATE['nodes']), sum(1 for node in STATE['nodes'].values() if node.get('oracle')), len(STATE['jobs']),
    CONTROL['latency_ms'], CONTROL['jitter_ms']))
  server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
  server.daemon_threads = True
  say('JSON-RPC listening on :{}'.format(PORT))
  server.serve_forever()


if __name__ == '__main__':
  main()
