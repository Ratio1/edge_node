#!/usr/bin/env python3
"""
A job owner using Deeploy on the localnet, and the production incident on demand.

The client signs requests with a wallet the way the Deeploy web app does and
sends them to the public Deeploy name (the localnet front spreads them over
the oracles, as Cloudflare does on mainnet). The wallet, its escrow and its
jobs are registered on the local chain first, as buying a job does on
mainnet.

Commands
--------
setup     register the wallet, its escrow and job ids on the local chain
create    deploy a small job on real workers and wait for it
update    change a running job
delete    remove a job
load      create several jobs one after another
watch     print the state of a job's operation every few seconds

The incident: ``create`` a job on one worker, stop that worker's container,
then ``delete`` the job. The operation cannot finish while the worker is
away. The number of times the oracle rewrites and re-sends the operation
record is ``sequence`` in the status; that stream is what saturated the
chain store on mainnet.

Output: one JSON line per step on stdout and in ``/out/deeploy.jsonl``.
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import uuid

import common

WHO = 'deeploy'
V2_PREFIX = 'Please sign this message for Deeploy: '
AUTH_KEYS = ('EE_ETH_SIGN', 'EE_ETH_SENDER')
PLUGIN = 'A_SIMPLE_PLUGIN'
API = 'http://deeploy-api.localnet'
CHAIN = 'http://rpc.localnet:8545'
KEY_FILE = os.path.join(common.OUT, 'wallet.key')
ESCROW = '0x' + 'e5c0' * 10


def chain_admin(**request):
  req = urllib.request.Request(CHAIN + '/_admin', data=json.dumps(request).encode(), headers={'Content-Type': 'application/json'})
  with urllib.request.urlopen(req, timeout=20) as resp:
    return json.loads(resp.read())


def wallet():
  from eth_account import Account
  if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wt') as fh:
      fh.write(Account.create().key.hex())
    os.chmod(KEY_FILE, 0o600)
  with open(KEY_FILE, 'rt') as fh:
    return Account.from_key(fh.read().strip())


def nonce():
  return hex(int(time.time() * 1000) - 2000)


def v2_text(payload):
  body = {key: value for key, value in payload.items() if key not in AUTH_KEYS}
  first = json.dumps(body, separators=(',', ':'), ensure_ascii=False, indent=1)
  return V2_PREFIX + json.dumps(json.loads(first), sort_keys=True, separators=(',', ':'), ensure_ascii=False, indent=1)


def sign(account, payload):
  from eth_account import Account
  from eth_account.messages import encode_defunct
  payload = {key: value for key, value in payload.items() if key not in AUTH_KEYS + ('EE_HASH',)}
  signature = Account.sign_message(encode_defunct(text=v2_text(payload)), private_key=account.key).signature.hex()
  payload['EE_ETH_SIGN'] = signature if signature.startswith('0x') else '0x' + signature
  payload['EE_ETH_SENDER'] = account.address
  return payload


class Client:
  def __init__(self, base, account, out):
    self.base, self.account, self.out = base.rstrip('/'), account, out
    self._auth, self._auth_at = None, 0.0
    return

  def post(self, endpoint, request, timeout=180):
    started = time.time()
    req = urllib.request.Request('{}/{}'.format(self.base, endpoint), data=json.dumps({'request': request}).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        code, raw = resp.status, resp.read()
    except urllib.error.HTTPError as err:
      code, raw = err.code, err.read()
    except Exception as exc:
      return {'http': 0, 'body': {'error': '{}: {}'.format(type(exc).__name__, exc)}, 's': round(time.time() - started, 3)}
    try:
      data = json.loads(raw)
    except ValueError:
      data = {'raw': raw[:300].decode(errors='replace')}
    body = data.get('detail' if code >= 400 else 'result', data) if isinstance(data, dict) else data
    return {'http': code, 'body': body, 's': round(time.time() - started, 3),
            'server': data.get('ee_node_alias') if isinstance(data, dict) else None}

  def submit(self, endpoint, payload):
    return self.post(endpoint, sign(self.account, dict(payload, nonce=nonce())))

  def status(self, **query):
    if self._auth is None or time.time() - self._auth_at > 6 * 3600:
      self._auth, self._auth_at = sign(self.account, {'nonce': nonce()}), time.time()
    request = dict(self._auth)
    request.update({key: value for key, value in query.items() if value is not None})
    request.setdefault('events_limit', 64)
    return self.post('get_deployment_status', request)

  def wait(self, operation_id, timeout=900, poll=5.0, phases=('completed',)):
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
      result = self.status(operation_id=operation_id)
      last = result['body']
      if result['http'] == 200 and isinstance(last, dict) and last.get('phase') in phases:
        return last
      time.sleep(poll)
    return last

  def record(self, step, job_id, accepted, final=None):
    body = accepted['body'] if isinstance(accepted.get('body'), dict) else {'raw': accepted.get('body')}
    final = final if isinstance(final, dict) else {}
    created = final.get('created_at') or 0
    row = dict(
      step=step, job=job_id, http=accepted['http'], admit_s=accepted['s'], server=accepted.get('server'),
      status=body.get('status'), error=body.get('error'), operation_id=body.get('operation_id'), app_id=body.get('app_id'),
      phase=final.get('phase'), outcome=final.get('outcome'), sequence=final.get('sequence'),
      op_error=final.get('error'),
      total_s=round((final.get('updated_at') or 0) - created, 2) if final.get('phase') == 'completed' and created else None,
      timeline=[(event['phase'], round(event['time'] - created, 2)) for event in final.get('events') or []],
    )
    self.out.write(**row)
    print(json.dumps(row, default=str), flush=True)
    return row


def padding(size):
  """Settings that make the job as large as a production container job (the operation record grows with it)."""
  if size <= 0:
    return {}
  return {'LOCALNET_SETTINGS': {'SETTING_%03d' % idx: 'v' * 56 for idx in range(max(1, size // 76))}}


def create_payload(job_id, nodes, alias, delay=5, config_bytes=0):
  return {
    'request_id': 'create-{}-{}'.format(job_id, uuid.uuid4().hex[:12]),
    'app_alias': alias,
    'job_id': int(job_id),
    'job_app_type': 'native',
    'pipeline_input_type': 'void',
    'target_nodes': list(nodes),
    'target_nodes_count': len(nodes),
    'plugins': [dict({'plugin_signature': PLUGIN, 'PROCESS_DELAY': delay}, **padding(config_bytes))],
  }


def first_instance(status_body):
  for node in (status_body or {}).get('nodes') or []:
    for instance in node.get('instances') or []:
      if instance.get('instance_id'):
        return instance['instance_id']
  return None


def worker_addresses(manifest, names):
  wanted = set(names or [])
  return [node['address'] for node in manifest['nodes'] if node['role'] == 'worker' and (not wanted or node['name'] in wanted)]


def main():
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  parser.add_argument('--api', default=API, help='Deeploy address (default: the public name, any oracle answers)')
  sub = parser.add_subparsers(dest='cmd', required=True)
  one = sub.add_parser('setup')
  one.add_argument('--first-job', type=int, default=1001)
  one.add_argument('--jobs', type=int, default=20)
  for name in ('create', 'delete', 'update', 'watch'):
    one = sub.add_parser(name)
    one.add_argument('--job', type=int, required=True)
    one.add_argument('--nodes', nargs='*', help='worker names (default: all workers)')
    one.add_argument('--no-wait', action='store_true')
    one.add_argument('--every', type=float, default=15.0)
    one.add_argument('--count', type=int, default=0, help='watch: stop after this many polls (0: forever)')
    one.add_argument('--config-bytes', type=int, default=0, help='create: size of the job settings (production jobs: about 16000)')
  one = sub.add_parser('load')
  one.add_argument('--first-job', type=int, default=1001)
  one.add_argument('--jobs', type=int, default=5)
  one.add_argument('--nodes', nargs='*')
  one.add_argument('--config-bytes', type=int, default=0)
  args = parser.parse_args()

  manifest, _secrets = common.start(WHO)
  out = common.Recorder('deeploy.jsonl')
  account = wallet()
  client = Client(args.api, account, out)

  if args.cmd == 'setup':
    chain_admin(op='add_escrow', escrow=ESCROW, owner=account.address, active=True, permissions=15)
    for job_id in range(args.first_job, args.first_job + args.jobs):
      chain_admin(op='add_job', job_id=job_id, escrow=ESCROW, job_type=16, start_ts=0, price_per_epoch=1000000,
                  balance=30000000, nodes_requested=1, active_nodes=[])
    common.say(WHO, 'wallet {} with escrow and jobs {}..{} registered on the local chain'.format(
      account.address, args.first_job, args.first_job + args.jobs - 1))
    return 0

  if args.cmd in ('create', 'load'):
    workers = worker_addresses(manifest, args.nodes)
    jobs = [args.job] if args.cmd == 'create' else list(range(args.first_job, args.first_job + args.jobs))
    for idx, job_id in enumerate(jobs):
      nodes = workers if args.cmd == 'create' else [workers[idx % len(workers)]]
      accepted = client.submit('create_pipeline', create_payload(job_id, nodes, 'lnet{}'.format(job_id),
                                                                config_bytes=args.config_bytes))
      body = accepted['body'] if isinstance(accepted['body'], dict) else {}
      final = None
      if body.get('status') == 'accepted' and not getattr(args, 'no_wait', False):
        final = client.wait(body['operation_id'])
      client.record('create', job_id, accepted, final)
    return 0

  current = client.status(job_id=args.job)['body']
  current = current if isinstance(current, dict) else {}
  if args.cmd == 'delete':
    payload = {'request_id': 'delete-{}-{}'.format(args.job, uuid.uuid4().hex[:12]), 'job_id': int(args.job),
               'app_id': current.get('app_id'), 'expected_revision': int(current.get('revision') or 0)}
    accepted = client.submit('delete_pipeline', payload)
    body = accepted['body'] if isinstance(accepted['body'], dict) else {}
    final = client.wait(body['operation_id']) if body.get('status') == 'accepted' and not args.no_wait else None
    client.record('delete', args.job, accepted, final)
  elif args.cmd == 'update':
    payload = {
      'request_id': 'update-{}-{}'.format(args.job, uuid.uuid4().hex[:12]), 'app_id': current.get('app_id'),
      'app_alias': 'lnet{}'.format(args.job), 'job_id': int(args.job), 'job_app_type': 'native',
      'expected_revision': int(current.get('revision') or 0), 'pipeline_input_type': 'void',
      'plugins': [dict({'plugin_signature': PLUGIN, 'instance_id': first_instance(current), 'PROCESS_DELAY': 7},
                       **padding(args.config_bytes))],
    }
    accepted = client.submit('update_pipeline', payload)
    body = accepted['body'] if isinstance(accepted['body'], dict) else {}
    final = client.wait(body['operation_id']) if body.get('status') == 'accepted' and not args.no_wait else None
    client.record('update', args.job, accepted, final)
  else:
    polls = 0
    while True:
      result = client.status(job_id=args.job)
      body = result['body'] if isinstance(result['body'], dict) else {}
      row = dict(step='watch', job=args.job, http=result['http'], s=result['s'], server=result.get('server'),
                 operation_id=body.get('operation_id'), kind=body.get('kind'), phase=body.get('phase'),
                 recovery=body.get('recovery'), sequence=body.get('sequence'),
                 error=(body.get('error') or {}).get('code') if isinstance(body.get('error'), dict) else body.get('error'))
      out.write(**row)
      print(json.dumps(row, default=str), flush=True)
      polls += 1
      if args.count and polls >= args.count:
        break
      time.sleep(args.every)
  return 0


if __name__ == '__main__':
  sys.exit(main())
