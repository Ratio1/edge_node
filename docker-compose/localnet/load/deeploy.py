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
cycle     create jobs one after another and delete each one after the next one is created
watch     print the state of a job's operation every few seconds
sync-app  deploy one container app of a container-sync set (provider or consumer) on
          one worker, as the Deeploy web app builds it; the worker must run Docker;
          ``--secret NAME`` adds the set's secret as a dAuth secret (``secret_paths``)

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

# The tool's folder (/opt/localnet in the container), for the secret derivation shared with the host tool.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Same derivation as the host's scan and custody check: a set's secret from its name, never written down.
from lnlib.common import sync_secret  # noqa: E402

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


# The test app of a container-sync set (POSIX sh, runs in any BusyBox image). A provider waits
# SYNC_PERIOD seconds, then, while it has published fewer than SYNC_PUBLISHES archives, writes a counter
# and a payload file into its fixed-size volume and asks for a publish through the request file. Every
# offline publish restarts the app, which starts this script again. Every role prints what it holds.
# At every start the app writes how many bytes R1EN_SYNC_SECRET has in its environment to secret_len (65 for
# a 64-character secret and its newline, 0 when the variable is absent): a count, never the value. A
# provider puts the set's key into the publish metadata, so a check can tell two sets on one node apart.
SYNC_APP_SCRIPT = r'''
D=/data; P=${SYNC_PERIOD:-30}; M=${SYNC_PUBLISHES:-1}
# Bytes of the secret variable in this container's environment (with the newline), never the value.
printenv R1EN_SYNC_SECRET | wc -c > "$D/secret_len"
echo "syncapp start role=${R1_SYNC_TYPE:-none} key=${R1_SYNC_KEY:-none}"
if [ "${R1_SYNC_TYPE:-}" = provider ]; then
  sleep "$P"
  n=$(cat "$D/counter" 2>/dev/null || echo 0)
  if [ "$n" -lt "$M" ]; then
    n=$((n + 1))
    echo "$n" > "$D/counter"
    echo "payload $n from $(hostname) at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$D/payload.txt"
    # The publish request; its metadata names the set, so a check can tell sets on one node apart.
    printf '{"archive_paths": ["%s/"], "metadata": {"n": %s, "key": "%s"}}\n' "$D" "$n" "$R1_SYNC_KEY" > "$R1_VOLUME_SYNC_DIR/request.json.tmp"
    mv "$R1_VOLUME_SYNC_DIR/request.json.tmp" "$R1_SYNC_REQUEST_FILE"
    echo "syncapp publish requested n=$n"
  fi
fi
while true; do
  echo "syncapp holds n=$(cat $D/counter 2>/dev/null || echo -) payload=$(cat $D/payload.txt 2>/dev/null | sha256sum | cut -c1-16)"
  sleep 60
done
'''

# Smallest generic job type of Deeploy (micro): 0.25 CPU, 512 MB, 2 GB of storage.
MICRO_JOB_TYPE = 53
# Its resources, as Deeploy checks them against the paid job type.
MICRO = {'cpu': 0.25, 'memory': '512m', 'storage': '2g'}
# The environment variable a node reads the set's secret from.
SYNC_SECRET_ENV = 'R1EN_SYNC_SECRET'
# "--secret malformed": 32 x "a" is not 64 lowercase hex, so a node must refuse it (and it is no secret).
MALFORMED_SECRET = 'a' * 32


def sync_app_payload(job_id, node, role, key, image, period=30, publishes=1, secret=None):
  """
  Deeploy create request for one container app of a container-sync set, as the Deeploy web app builds it.

  Parameters
  ----------
  job_id : int
    Job registered on the local chain with ``setup --job-type 53``.
  node : str
    Address of the worker it runs on (the worker must run Docker).
  role : str
    ``provider`` or ``consumer``.
  key : str
    The set's sync key (the chain-store field the provider writes and the consumers read).
  image : str
    Image already loaded into the worker's Docker daemon; the app never pulls it (pull policy "manual").
  period : int
    Provider: seconds before each publish.
  publishes : int
    Provider: archives to publish in all.
  secret : str or None
    The set's secret, sent as ``ENV.R1EN_SYNC_SECRET`` and selected by the top-level ``secret_paths``, so
    Deeploy keeps it out of the stored job and dAuth delivers it to the node; None sends no secret.

  Returns
  -------
  dict
    The request: a generic job with one CONTAINER_APP_RUNNER instance, a 1 GB fixed-size volume at
    ``/data`` and the ``SYNC`` block (enabled, role, key), as ``formatGenericJobPayload`` of the web app.

  Examples
  --------
  >>> sync_app_payload(3001, '0xai_A...', 'provider', 'lnet-sync-s0', 'localnet/syncapp:1')['plugins'][0]['SYNC']
  {'ENABLED': True, 'TYPE': 'provider', 'KEY': 'lnet-sync-s0'}
  >>> sync_app_payload(3001, '0xai_A...', 'provider', 'k', 'img', secret='ab' * 32)['secret_paths']
  [['plugins', 0, 'ENV', 'R1EN_SYNC_SECRET']]
  """
  # The app's variables: the provider's pace.
  env = {'SYNC_PERIOD': str(period), 'SYNC_PUBLISHES': str(publishes)}
  if secret is not None:
    # The secret is one more ENV entry, as the web app adds it; secret_paths below selects it.
    env[SYNC_SECRET_ENV] = secret
  # Field for field what formatGenericJobPayload and withSecretPaths of the web app produce.
  return {
    'request_id': 'create-{}-{}'.format(job_id, uuid.uuid4().hex[:12]),
    'app_alias': 'lnsync{}'.format(job_id),
    'job_id': int(job_id),
    'job_app_type': 'generic',
    'target_nodes': [node],
    'spare_nodes': [],
    'allow_replication_in_the_wild': False,
    'target_nodes_count': 1,
    'job_tags': [],
    'node_res_req': dict(MICRO),
    'plugins': [{
      'plugin_signature': 'CONTAINER_APP_RUNNER',
      # The web app reserves the fixed volume inside the tier's storage: 2 GB tier - 1 GB volume.
      'CONTAINER_RESOURCES': {'cpu': MICRO['cpu'], 'memory': MICRO['memory'], 'storage': '1g'},
      'PORT': None,
      'TUNNEL_ENGINE': 'cloudflare',
      'TUNNEL_ENGINE_ENABLED': False,
      'CLOUDFLARE_TOKEN': None,
      'EXPOSED_PORTS': {},
      # The app's variables, the secret among them when one is sent.
      'ENV': env,
      'DYNAMIC_ENV': {},
      'VOLUMES': {},
      'FILE_VOLUMES': {},
      # A loop-mounted ext4 volume: the kind of volume a sync archive is taken from and applied to.
      'FIXED_SIZE_VOLUMES': {'data': {'SIZE': '1G', 'MOUNTING_POINT': '/data'}},
      'RESTART_POLICY': 'always',
      # "manual" (the web app's other value): the image is used from the node's store, never pulled.
      'IMAGE_PULL_POLICY': 'manual',
      'SYNC': {'ENABLED': True, 'TYPE': role, 'KEY': key},
      'IMAGE': image,
      'CR_DATA': {'SERVER': 'docker.io'},
      # The test app is a shell script; the image's own entrypoint is not used.
      'CONTAINER_ENTRYPOINT': ['/bin/sh', '-c'],
      'CONTAINER_START_COMMAND': [SYNC_APP_SCRIPT],
    }],
    'pipeline_input_type': 'void',
    'pipeline_input_uri': None,
    'chainstore_response': True,
    # Secret paths travel at the top level (the web app's withSecretPaths); Deeploy refuses them in a plugin.
    # The secret's path is the one the web app emits: plugin 0, its ENV, the variable.
    'secret_paths': [['plugins', 0, 'ENV', SYNC_SECRET_ENV]] if secret is not None else [],
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


def delete_job(client, job_id, wait=True):
  """
  Delete one job through the Deeploy API, as the ``delete`` command does, and record the outcome.

  Parameters
  ----------
  client : Client
    The signed client of the job owner.
  job_id : int
    The job to delete.
  wait : bool, optional
    Wait until the delete operation completes (default True).

  Returns
  -------
  dict
    The JSON line recorded for the delete (admission, phase timeline, outcome).

  Examples
  --------
  >>> delete_job(client, 2001)['phase']
  'completed'
  """
  # The job's current app and revision, which the delete request must name.
  current = client.status(job_id=job_id)['body']
  # A refused status answer names no app.
  current = current if isinstance(current, dict) else {}
  # The delete request, with the app and the revision it expects.
  payload = {'request_id': 'delete-{}-{}'.format(job_id, uuid.uuid4().hex[:12]), 'job_id': int(job_id),
             'app_id': current.get('app_id'), 'expected_revision': int(current.get('revision') or 0)}
  # Signed by the job owner, through the public Deeploy name.
  accepted = client.submit('delete_pipeline', payload)
  # The admission answer (an error body on a refusal).
  body = accepted['body'] if isinstance(accepted['body'], dict) else {}
  # The operation's end, when it was accepted and the caller waits.
  final = client.wait(body['operation_id']) if body.get('status') == 'accepted' and wait else None
  # One JSON line with the admission, the phase timeline and the outcome.
  return client.record('delete', job_id, accepted, final)


def main():
  """
  Command line of the Deeploy client (see the module docstring for the commands).

  Returns
  -------
  int
    0, except ``sync-app``: 1 when the request was refused or its operation did not complete (each
    step's outcome is in its JSON line and in ``/out/deeploy.jsonl``).

  Examples
  --------
  >>> sys.argv = ['deeploy.py', 'setup', '--first-job', '3001', '--jobs', '2', '--job-type', '53']
  >>> main()
  0
  """
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  parser.add_argument('--api', default=API, help='Deeploy address (default: the public name, any oracle answers)')
  sub = parser.add_subparsers(dest='cmd', required=True)
  one = sub.add_parser('setup')
  one.add_argument('--first-job', type=int, default=1001)
  one.add_argument('--jobs', type=int, default=20)
  # 16 is the smallest native job; container apps need a generic type such as 53 (micro).
  one.add_argument('--job-type', type=int, default=16, help='on-chain job type (16: native entry, 53: generic micro)')
  # One app of a container-sync set.
  one = sub.add_parser('sync-app')
  # A job registered by "setup --job-type 53".
  one.add_argument('--job', type=int, required=True)
  # One worker per app, as the web app's target node.
  one.add_argument('--node', required=True, help='worker name; it must run Docker')
  # The app's side of the set.
  one.add_argument('--role', required=True, choices=('provider', 'consumer'))
  # The same key on every app of the set.
  one.add_argument('--key', required=True, help='sync key of the set')
  # Never pulled: loaded beforehand with "localnet.py image".
  one.add_argument('--image', default='localnet/syncapp:1', help='image already loaded into the worker')
  # Provider pace: wait before each publish.
  one.add_argument('--period', type=int, default=30, help='provider: seconds before each publish')
  # Provider: how many archives in all.
  one.add_argument('--publishes', type=int, default=1, help='provider: archives to publish in all')
  # How long a "node is not online" refusal is retried (a worker that has just started).
  one.add_argument('--online-wait', type=float, default=180, help='seconds to retry while the worker is not online yet')
  # The set's secret by name (derived from the cluster's private settings, never given on the command line).
  one.add_argument('--secret', metavar='NAME',
                   help='send the secret of set NAME as a dAuth secret (another name: a wrong secret; "malformed": 32 x "a")')
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
  # Creates and deletes in turn, as a user who replaces a job: writes every Deeploy and dAuth namespace.
  one = sub.add_parser('cycle')
  # Jobs registered by "setup"; each is created once and deleted after the next one is created.
  one.add_argument('--first-job', type=int, default=2001)
  # How many jobs in all; the cycle ends after the last one.
  one.add_argument('--jobs', type=int, default=40)
  # Worker names, taken in turn (default: all workers).
  one.add_argument('--nodes', nargs='*')
  # Settings that make each job as large as a production job, as for "create".
  one.add_argument('--config-bytes', type=int, default=0)
  # Seconds between two steps of the cycle.
  one.add_argument('--pause', type=float, default=5.0)
  args = parser.parse_args()

  # The cluster's private settings also give each named set its secret (sync-app --secret).
  manifest, cluster_secrets = common.start(WHO)
  out = common.Recorder('deeploy.jsonl')
  account = wallet()
  client = Client(args.api, account, out)

  if args.cmd == 'setup':
    chain_admin(op='add_escrow', escrow=ESCROW, owner=account.address, active=True, permissions=15)
    for job_id in range(args.first_job, args.first_job + args.jobs):
      # Deeploy checks the requested resources against the paid job type, so the type follows the app kind.
      chain_admin(op='add_job', job_id=job_id, escrow=ESCROW, job_type=args.job_type, start_ts=0, price_per_epoch=1000000,
                  balance=30000000, nodes_requested=1, active_nodes=[])
    # The job type is now part of the line, as it decides which apps the jobs accept.
    common.say(WHO, 'wallet {} with escrow and jobs {}..{} (type {}) registered on the local chain'.format(
      account.address, args.first_job, args.first_job + args.jobs - 1, args.job_type))
    return 0

  if args.cmd == 'sync-app':
    # No secret, the fixed malformed value, or the named set's 64-hex secret.
    secret = None if args.secret is None else MALFORMED_SECRET if args.secret == 'malformed' else sync_secret(cluster_secrets, args.secret)
    # A worker that started moments ago is not yet online for the oracles: retry that refusal, as a user would.
    deadline = time.time() + args.online_wait
    # One attempt per lap.
    while True:
      # The worker's node address from the manifest; a fresh request id for every attempt.
      payload = sync_app_payload(args.job, worker_addresses(manifest, [args.node])[0], args.role, args.key, args.image,
                                 # The provider's pace, and the set's secret (None: no secret is sent).
                                 period=args.period, publishes=args.publishes, secret=secret)
      # Signed by the job owner's wallet, sent through the public Deeploy name.
      accepted = client.submit('create_pipeline', payload)
      # The admission answer (an error body on a refusal).
      body = accepted['body'] if isinstance(accepted['body'], dict) else {}
      # Any other answer, or the end of the wait, is final.
      if body.get('status') == 'accepted' or 'is not online' not in json.dumps(body) or time.time() > deadline:
        break
      # Said once per retry, in the generator's log.
      common.say(WHO, 'worker {} is not online for Deeploy yet; trying again in 10 s'.format(args.node))
      # The oracles mark a node online after its first heartbeats.
      time.sleep(10)
    # The same wait and record as "create": the operation must reach its completed phase.
    final = client.wait(body['operation_id']) if body.get('status') == 'accepted' else None
    # One JSON line with the admission, the phase timeline and the outcome.
    row = client.record('sync-app-' + args.role, args.job, accepted, final)
    # A refused request or an operation that did not complete stops the scenario at once (non-zero exit).
    return 0 if row['phase'] == 'completed' and row['outcome'] == 'succeeded' else 1

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

  if args.cmd == 'cycle':
    # The workers' node addresses.
    workers = worker_addresses(manifest, args.nodes)
    # The job created last, deleted after the next one is created, so one job stays alive between steps.
    previous = None
    # Each registered job once.
    for idx, job_id in enumerate(range(args.first_job, args.first_job + args.jobs)):
      # One worker per job, taken in turn.
      accepted = client.submit('create_pipeline', create_payload(job_id, [workers[idx % len(workers)]], 'lnet{}'.format(job_id),
                                                                config_bytes=args.config_bytes))
      # The admission answer (an error body on a refusal).
      body = accepted['body'] if isinstance(accepted['body'], dict) else {}
      # Each create is waited for, so the operations follow one another as a user's do.
      final = client.wait(body['operation_id']) if body.get('status') == 'accepted' else None
      # One JSON line per create.
      client.record('create', job_id, accepted, final)
      if previous is not None:
        # The job before it goes, which rewrites records written before it.
        delete_job(client, previous)
      # This job is deleted after the next one is created.
      previous = job_id
      # A short pause between two steps of the cycle.
      time.sleep(args.pause)
    # Every job was created (and all but the last deleted).
    return 0

  current = client.status(job_id=args.job)['body']
  current = current if isinstance(current, dict) else {}
  if args.cmd == 'delete':
    # The same request and record as before, through the helper the cycle shares.
    delete_job(client, args.job, wait=not args.no_wait)
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
