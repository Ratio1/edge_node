#!/usr/bin/env python3
"""
The rest of the network: emulated ordinary nodes.

A localnet runs a handful of real nodes. Mainnet has about 216 more that the
oracles must serve. This process plays them with real keys and real
signatures, so every message passes the same checks as one from a real node:

  * each emulated node keeps one broker session, placed across the four
    brokers like mainnet (61 / 51 / 51 / 53), and publishes a heartbeat of
    production size every 10 s. The heartbeat is a real one captured from a
    node of this localnet, re-labelled and re-signed with the emulated key;
  * emulated nodes ask dAuth for their settings when they "start", through
    the same SDK call a node makes. Revoked nodes are refused and keep
    retrying on the node's own schedule (15 s plus 1-15 s), which is where
    most dAuth traffic on mainnet comes from;
  * optional extra subscribers to the heartbeat topic stand for supervisors
    that are not oracles.

Output: ``/out/stats.jsonl`` (totals every 10 s) and ``/out/dauth.jsonl`` (one
line per dAuth request with outcome and latency).
"""

import argparse
import base64
import heapq
import json
import os
import random
import threading
import time
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import common

WHO = 'fleet'
SIGNATURE_FIELDS = ('EE_SIGN', 'EE_SENDER', 'EE_ETH_SENDER', 'EE_ETH_SIGN', 'EE_HASH', 'SIGN_CANON_V')
WORKER_PLUGINS = ('NET_CONFIG_MONITOR', 'NET_MON_01', 'UPDATE_MONITOR_01', 'PLUGIN_MONITOR_01', 'LOCAL_COMMS_01',
                  'CHAIN_STORE_BASE', 'CSTORE_MANAGER_API', 'R1FS_MANAGER_API')
MAINNET_SPREAD = (61, 51, 51, 53)


def utc_now():
  return datetime.now(timezone.utc).replace(tzinfo=None)


def capture_template(manifest, secrets, timeout=120):
  """Take one real heartbeat from the mesh and return (envelope, decoded inner data)."""
  found = []

  def on_message(client, userdata, msg):
    try:
      data = json.loads(msg.payload)
    except ValueError:
      return
    if data.get('EE_EVENT_TYPE') == 'HEARTBEAT' and 'ENCODED_DATA' in data and not found:
      found.append(data)

  broker = sorted(manifest['mesh']['brokers'].values(), key=lambda item: item['ip'])[0]
  client = common.mqtt_client('fleet_template_' + uuid.uuid4().hex[:8], broker['ip'], secrets, on_message=on_message)
  client.on_connect = lambda c, u, f, rc, p=None: c.subscribe('naeural/ctrl', 1)
  client.loop_start()
  end = time.time() + timeout
  while not found and time.time() < end:
    time.sleep(0.2)
  client.loop_stop()
  client.disconnect()
  if not found:
    raise RuntimeError('no heartbeat seen on the mesh within {} s: are the seed nodes up?'.format(timeout))
  envelope = found[0]
  inner = json.loads(zlib.decompress(base64.b64decode(envelope['ENCODED_DATA'])))
  return envelope, inner


class Node:
  def __init__(self, info, broker_ip, eng, template, secrets, supervisors):
    self.name = info['name']
    self.revoked = info['revoked']
    self.engine = eng
    self.address = eng.address
    self.broker_ip = broker_ip
    self.started = time.time() - random.uniform(600, 170000)
    self.seq = 0
    self.connected = False
    envelope, inner = template
    self.envelope = {key: val for key, val in envelope.items() if key not in SIGNATURE_FIELDS}
    self.inner = dict(inner)
    self.inner['EE_ADDR'] = self.address
    self.inner['EE_IS_SUPER'] = False
    self.inner['ACTIVE_PLUGINS'] = [item for item in inner.get('ACTIVE_PLUGINS', [])
                                    if item.get('SIGNATURE') in WORKER_PLUGINS]
    self.inner['COMM_RELAY'] = broker_ip
    self.inner['R1FS_ID'] = '12D3KooW' + uuid.uuid4().hex + uuid.uuid4().hex[:12]
    self.inner['EE_WHITELIST'] = list(supervisors)
    self.client = common.mqtt_client('{}_HEARTBE_{}'.format(self.name, uuid.uuid4().hex[:8]), broker_ip, secrets)
    self.client.on_connect = self._on_connect
    self.client.on_disconnect = self._on_disconnect
    return

  def _on_connect(self, client, userdata, flags, reason_code, properties=None):
    self.connected = True
    client.subscribe('naeural/{}/config'.format(self.address), 1)
    return

  def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
    self.connected = False
    return

  def heartbeat(self):
    now = utc_now()
    self.seq += 1
    inner = self.inner
    inner['CURRENT_TIME'] = now.strftime('%Y-%m-%d %H:%M:%S.%f')
    inner['TIMESTAMP'] = now.strftime('%Y%m%d%H%M%S%f')
    inner['UPTIME'] = time.time() - self.started
    inner['CPU_USED'] = round(random.uniform(3, 60), 1)
    message = dict(self.envelope)
    message.update({
      'EE_ID': self.name,
      'EE_ADDR': self.address,
      'EE_PAYLOAD_PATH': [self.name, None, None, None],
      'EE_MESSAGE_ID': str(uuid.uuid4()),
      'EE_MESSAGE_SEQ': self.seq,
      'EE_TOTAL_MESSAGES': self.seq,
      'EE_TIMESTAMP': now.strftime('%Y-%m-%d %H:%M:%S.%f'),
      'ENCODED_DATA': base64.b64encode(zlib.compress(json.dumps(inner).encode())).decode(),
    })
    self.engine.sign(message, add_data=True, use_digest=True)
    return json.dumps(message)


def spread(count, weights):
  total = sum(weights)
  shares = [count * weight // total for weight in weights]
  for idx in range(count - sum(shares)):
    shares[idx % len(shares)] += 1
  return shares


def main():
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  parser.add_argument('--nodes', type=int, default=None, help='emulated licensed nodes (default: all generated)')
  parser.add_argument('--revoked', type=int, default=None, help='emulated revoked nodes (default: all generated)')
  parser.add_argument('--heartbeat', type=float, default=10.0, help='seconds between heartbeats of one node')
  parser.add_argument('--no-heartbeats', action='store_true')
  parser.add_argument('--dauth-restart-hours', type=float, default=12.0,
                      help='a licensed node asks dAuth for its settings about this often (0: never)')
  parser.add_argument('--no-revoked-retries', action='store_true', help='revoked nodes stay silent')
  parser.add_argument('--ctrl-subscribers', type=int, default=8,
                      help='extra sessions subscribed to the heartbeat topic (mainnet: 19 supervisors, 11 of them oracles)')
  parser.add_argument('--versions', default='2.10.690,7.7.352,3.5.67', help='app,core,sdk versions the nodes report')
  parser.add_argument('--keys', default='/fleet')
  args = parser.parse_args()

  manifest, secrets = common.start(WHO)
  stats_file = common.Recorder('stats.jsonl')
  dauth_file = common.Recorder('dauth.jsonl')
  fleet = manifest.get('fleet') or []
  licensed = [item for item in fleet if not item['revoked']]
  revoked = [item for item in fleet if item['revoked']]
  licensed = licensed[:args.nodes] if args.nodes is not None else licensed
  revoked = revoked[:args.revoked] if args.revoked is not None else revoked
  brokers = [info['ip'] for _name, info in sorted(manifest['mesh']['brokers'].items())]
  supervisors = [node['address'].replace('0xai_', '') for node in manifest['nodes'] if node['supervisor']]

  common.say(WHO, 'waiting for a real heartbeat to use as the template')
  template = capture_template(manifest, secrets)
  common.say(WHO, 'template: {} bytes from {}'.format(len(json.dumps(template[0])), template[0].get('EE_ID')))

  nodes = []
  shares = spread(len(licensed), MAINNET_SPREAD[:len(brokers)])
  placement = [broker for broker, share in zip(brokers, shares) for _ in range(share)]
  for info, broker_ip in zip(licensed, placement):
    nodes.append(Node(info, broker_ip, common.engine(args.keys, info['name']), template, secrets, supervisors))
  refused = [Node(info, random.choice(brokers), common.engine(args.keys, info['name']), template, secrets, supervisors)
             for info in revoked]
  common.say(WHO, '{} licensed nodes on brokers {}, {} revoked nodes'.format(len(nodes), dict(zip(brokers, shares)), len(refused)))

  counters = {'hb_sent': 0, 'hb_bytes': 0, 'hb_late': 0, 'dauth_ok': 0, 'dauth_refused': 0, 'dauth_failed': 0,
              'ctrl_received': 0}
  lock = threading.Lock()

  subscribers = []
  for idx in range(args.ctrl_subscribers):
    def on_message(client, userdata, msg):
      counters['ctrl_received'] += 1
    client = common.mqtt_client('sup{:02d}_COMMAND_{}'.format(idx, uuid.uuid4().hex[:8]), brokers[idx % len(brokers)],
                                secrets, on_message=on_message)
    client.on_connect = lambda c, u, f, rc, p=None: c.subscribe('naeural/ctrl', 1)
    client.loop_start()
    subscribers.append(client)

  if not args.no_heartbeats:
    for node in nodes:
      node.client.loop_start()

  app_ver, core_ver, sdk_ver = args.versions.split(',')
  pool = ThreadPoolExecutor(max_workers=24, thread_name_prefix='dauth')

  def ask_dauth(node):
    started = time.time()
    outcome, detail = 'failed', ''
    try:
      result = node.engine.dauth_autocomplete(
        add_env=False, debug=False, max_tries=1, return_full_data=True, debug_data=True,
        request_timeout=(10, 120), sender_alias=node.name,
        sender_app_ver=app_ver, sender_core_ver=core_ver, sender_sdk_ver=sdk_ver,
      )
      if isinstance(result, dict) and any(key.startswith('EE_') for key in result):
        outcome = 'ok'
      elif isinstance(result, dict):
        auth = (result.get('result') or {}).get('auth') if 'result' in result else result.get('auth')
        outcome = 'refused'
        detail = str((auth or {}).get('error') or result.get('error') or '')[:120]
      else:
        outcome = 'failed'
    except Exception as exc:
      detail = '{}: {}'.format(type(exc).__name__, exc)[:160]
    took = time.time() - started
    with lock:
      counters['dauth_' + outcome] += 1
    dauth_file.write(node=node.name, revoked=node.revoked, outcome=outcome, s=round(took, 3), detail=detail)
    return outcome

  # (time, tie-breaker, kind, node)
  schedule = []
  now = time.time()
  if not args.no_heartbeats:
    for idx, node in enumerate(nodes):
      heapq.heappush(schedule, (now + random.uniform(1.0, 1.0 + args.heartbeat), idx, 'hb', node))
  if args.dauth_restart_hours > 0:
    for idx, node in enumerate(nodes):
      heapq.heappush(schedule, (now + random.uniform(5, args.dauth_restart_hours * 3600), 10000 + idx, 'dauth', node))
  if not args.no_revoked_retries:
    for idx, node in enumerate(refused):
      heapq.heappush(schedule, (now + random.uniform(2, 32), 20000 + idx, 'dauth', node))

  def after_dauth(future, node, tie):
    # A refused node sleeps 15 s plus 1-15 s and asks again, as the node start-up loop does.
    try:
      outcome = future.result()
    except Exception:
      outcome = 'failed'
    if node.revoked or outcome != 'ok':
      delay = 15 + random.randint(1, 15)
    else:
      delay = random.uniform(0.5, 1.5) * args.dauth_restart_hours * 3600
    with lock:
      heapq.heappush(schedule, (time.time() + delay, tie, 'dauth', node))
    return

  last_report = time.time()
  common.say(WHO, 'running')
  while True:
    with lock:
      due = schedule[0][0] if schedule else time.time() + 1
    wait = due - time.time()
    if wait > 0:
      time.sleep(min(wait, 0.5))
    else:
      with lock:
        _due, tie, kind, node = heapq.heappop(schedule)
      if kind == 'hb':
        if -wait > 2.0:
          counters['hb_late'] += 1
        payload = node.heartbeat()
        node.client.publish('naeural/ctrl', payload, qos=1)
        counters['hb_sent'] += 1
        counters['hb_bytes'] += len(payload)
        with lock:
          heapq.heappush(schedule, (max(time.time(), _due + args.heartbeat), tie, 'hb', node))
      else:
        future = pool.submit(ask_dauth, node)
        future.add_done_callback(lambda fut, node=node, tie=tie: after_dauth(fut, node, tie))
    if time.time() - last_report >= 10:
      last_report = time.time()
      connected = sum(1 for node in nodes if node.connected)
      stats_file.write(connected=connected, **counters)
      common.say(WHO, 'connected {}/{} | {}'.format(connected, len(nodes), ' '.join(
        '{}={}'.format(key, val) for key, val in counters.items())))


if __name__ == '__main__':
  main()
