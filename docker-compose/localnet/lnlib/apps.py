"""
Container apps on localnet nodes: the inner Docker daemon, its images, and container sync.

A node created with ``init --docker-nodes`` starts its own Docker daemon, as a production node does
(``node/dind.sh``). This module holds what the host does around it:

  * create and release what such a node holds outside its container (its inner Docker data volume,
    and the loop devices of its apps' fixed-size volumes, which outlive the container);
  * load an image into the inner daemon from an image that already exists on this machine, so that
    no app ever pulls from a registry;
  * prove from inside a node that an inner container reaches no public network;
  * check a container-sync set: what the provider published, the chain-store record on the oracles,
    what each consumer applied and when, and whether the consumer's file equals the provider's.
"""

# Digests of the files apps hold, to compare provider and consumer.
import hashlib
# Node inspection output and the sync reports.
import json
# The image stream from the host's Docker into a node's daemon.
import subprocess
# Delays and polling of the sync check.
import time
# The host's loop-device table in sysfs.
from pathlib import Path

# Shell, names and paths shared by the whole tool.
from .common import HERE, LABEL, NODE_IMAGE, PROJECT, PYTHON, LocalnetError, container, log, sh
# The localnet front: the one address an inner container must reach in the isolation probe.
from .infra import EDGE_IP
# Volume names and node logs.
from .nodes import docker_volume, node_log

# Where the container app runner keeps the sync history of an app (sent by a provider, received by a
# consumer), and the quarantine of records a consumer refused, inside a node's data folder.
SYNC_READER = r'''
import glob, json
root = '/edge_node/_local_cache/_data'
def entries(kind):
  rows = []
  for path in glob.glob(root + '/**/sync_history/' + kind + '/*.json', recursive=True):
    try:
      with open(path) as fh:
        item = json.load(fh)
    except Exception:
      continue
    rows.append({key: item.get(key) for key in ('cid', 'version', 'published_timestamp', 'applied_timestamp', 'node_id')})
  return sorted(rows, key=lambda row: (row.get('version') or 0, row.get('published_timestamp') or row.get('applied_timestamp') or 0))
quarantine = glob.glob(root + '/**/sync_history/state/quarantine/*', recursive=True)
print('SYNCSTATE ' + json.dumps({'sent': entries('sent'), 'received': entries('received'), 'quarantine': len(quarantine)}))
'''

# The chain-store replica an oracle last saved, and the record of one sync key in it.
RECORD_READER = r'''
import base64, hashlib, json, os, pickle, sys, time
path = '/edge_node/_local_cache/_data/cache_plugins/admin_pipeline__chain_store_base__chain_store_base_inst/object.pickle'
key = 'hs:{}:{}'.format(hashlib.sha256(b'CHAINSTORE_SYNC').hexdigest()[:10], base64.urlsafe_b64encode(sys.argv[1].encode()).decode())
value = None
if os.path.exists(path):
  with open(path, 'rb') as fh:
    record = pickle.load(fh).get(key)
  value = record.get('value') if isinstance(record, dict) else record
out = {'cid': value.get('cid'), 'version': value.get('version'), 'node_id': value.get('node_id')} if isinstance(value, dict) else None
print('RECORD ' + json.dumps({'record': out, 'age_s': round(time.time() - os.path.getmtime(path), 1) if os.path.exists(path) else None}))
'''


def docker_nodes(manifest):
  """
  Names of the nodes that run their own Docker daemon.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.

  Returns
  -------
  list of str
    Node names, in manifest order.

  Examples
  --------
  >>> docker_nodes({'nodes': [{'name': 'r1s-01'}, {'name': 'r1w-01', 'docker': True}]})
  ['r1w-01']
  """
  # The nodes "init --docker-nodes" marked.
  return [node['name'] for node in manifest['nodes'] if node.get('docker')]


def create_docker_volumes(nodes):
  """
  Create the inner Docker data volume of every node that runs Docker, empty and labelled.

  Parameters
  ----------
  nodes : list of dict
    Nodes of ``nodes.plan``.

  Returns
  -------
  list of str
    The volumes created.

  Examples
  --------
  >>> create_docker_volumes([{'name': 'r1w-01', 'docker': True}])
  ['r1ln_r1w-01_docker']
  """
  # Volumes created, for the caller's log line.
  made = []
  # Only the nodes that run Docker get one.
  for node in nodes:
    if not node.get('docker'):
      continue
    # A fresh volume: an inner daemon never starts on images or containers of an earlier localnet.
    sh('docker', 'volume', 'rm', '-f', docker_volume(node['name']), check=False)
    # The localnet label lets "down --purge" find and remove it.
    sh('docker', 'volume', 'create', '--label', LABEL + '=volume', docker_volume(node['name']))
    # Recorded for the caller.
    made.append(docker_volume(node['name']))
  # Every volume created.
  return made


def wait_docker(manifest, names, timeout=240):
  """
  Wait until the inner Docker daemon of each named node that runs Docker answers.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  names : list of str
    Nodes just started; those without Docker are skipped.
  timeout : float
    Seconds to wait for all of them.

  Returns
  -------
  float
    Seconds waited.

  Raises
  ------
  LocalnetError
    A daemon did not answer in time.

  Notes
  -----
  Until ``node/dind.sh`` has moved the container's processes into their child cgroup and the daemon is
  up, a ``docker exec`` into the node can fail ("procReady not received"); "up" returns only after this.

  Examples
  --------
  >>> wait_docker(manifest, ['r1w-01', 'r1w-02'])
  12.4
  """
  # Start of the wait.
  started = time.time()
  # The started nodes that run Docker and have not answered yet.
  pending = [name for name in docker_nodes(manifest) if name in names]
  # Look until all answered or the time is up.
  while pending and time.time() - started < timeout:
    # A node whose daemon answers "docker info" is ready.
    pending = [name for name in pending
               if sh('docker', 'exec', container(name), 'docker', 'info', check=False, timeout=60).returncode != 0]
    if pending:
      # Not yet: look again later.
      time.sleep(3)
  if pending:
    # A node whose daemon never answered: the cluster is not usable for apps.
    raise LocalnetError('inner Docker daemon did not answer within {} s on {}'.format(timeout, pending))
  # How long the daemons took.
  return round(time.time() - started, 1)


def release_docker(manifest):
  """
  Release what the nodes that run Docker hold in the host kernel, before the localnet is removed.

  Each such node is killed (its inner daemon, apps and mounts end with it), then ``node/dind_down.sh``
  runs in a throwaway privileged container that has the node's data volume at the node's own path and
  sits on the internal localnet network; it detaches every loop device still bound to an image file of
  that node's fixed-size volumes.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.

  Returns
  -------
  dict
    Node name -> the script's ``TEARDOWN detached=<n> left=<n>`` line, or the reason it did not run.

  Notes
  -----
  Without this step every fixed-size volume of every app would stay attached to a loop device of the
  host after ``down``, holding the space of a volume that no longer exists.

  Examples
  --------
  >>> release_docker(home.manifest())
  {'r1w-01': 'TEARDOWN detached=2 left=0', 'r1w-02': 'TEARDOWN detached=2 left=0'}
  """
  # Nothing to release in a localnet without Docker nodes.
  names = docker_nodes(manifest)
  if not names:
    # No node ran Docker: nothing was attached.
    return {}
  # The throwaway container must sit on the localnet network: without it, nothing privileged is started.
  if sh('docker', 'network', 'inspect', PROJECT, check=False).returncode != 0:
    # Said per node, so that "down" prints why; leaked_loops() then lists what is left.
    return {name: 'not run: network {} is gone (see "loop devices left" below)'.format(PROJECT) for name in names}
  # One summary line per node.
  result = {}
  # Each node that runs Docker, one at a time.
  for node in manifest['nodes']:
    if not node.get('docker'):
      continue
    # Killing ends the node, its inner daemon, its apps and every mount they made; loop devices remain.
    sh('docker', 'kill', container(node['name']), check=False)
    # The node's data volume at the node's own path, the tool's scripts read-only, on the localnet network.
    out = sh(
      'docker', 'run', '--rm', '--privileged', '--network', PROJECT, '--label', LABEL + '=tool',
      '-v', '{}:/edge_node/_local_cache'.format(node['volume']), '-v', '{}:/opt/localnet:ro'.format(HERE),
      '--entrypoint', '/bin/sh', NODE_IMAGE, '/opt/localnet/node/dind_down.sh', check=False, timeout=180,
    ).stdout or ''
    # Keep the script's one summary line, or the end of its output when it failed.
    lines = [line for line in out.splitlines() if line.startswith('TEARDOWN')]
    # The summary, or what the script said instead.
    result[node['name']] = lines[-1] if lines else out.strip()[-300:]
  # Per node: what was detached and what is left.
  return result


def leaked_loops():
  """
  Loop devices of the host still bound to an image file of a container app's fixed-size volume.

  Returns
  -------
  list of str
    ``/dev/loopN <backing file>`` for each such device (read from sysfs, no privileges needed).

  Notes
  -----
  The kernel reports the backing file by the path the attaching process saw, here the node's
  ``/edge_node/_local_cache/...``; the image files of the container app runner always lie under
  ``fixed_volumes/images/``, which no other loop user of the host has.

  Examples
  --------
  >>> leaked_loops()
  []
  """
  # The devices found.
  leaked = []
  # Every attached loop device of the host has a backing_file entry in sysfs.
  for path in sorted(Path('/sys/block').glob('loop*/loop/backing_file')):
    try:
      # The path of the image file the device is bound to.
      backing = path.read_text().strip()
    except OSError:
      continue
    # Only the images the container app runner creates (fixed_volumes/images/<volume>.img).
    if '/fixed_volumes/images/' in backing:
      # Device name and image path, for the operator who must detach it.
      leaked.append('/dev/{} {}'.format(path.parent.parent.name, backing))
  # Empty when the localnet left nothing behind.
  return leaked


def load_image(manifest, image, names=None, tag=None):
  """
  Copy an image that exists on this machine into the inner Docker daemon of nodes, without any pull.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  image : str
    An image of the host's Docker, for example ``redis:7-alpine`` (read with ``docker save``; the host's
    image is not changed).
  names : list of str or None
    Nodes to load it into (None: every node that runs Docker).
  tag : str or None
    Extra name given to the image inside each node, for example ``localnet/syncapp:1``.

  Returns
  -------
  dict
    Node name -> image id inside that node.

  Raises
  ------
  LocalnetError
    A named node does not run Docker, or the save or load fails.

  Examples
  --------
  >>> load_image(manifest, 'redis:7-alpine', ['r1w-01'], tag='localnet/syncapp:1')
  {'r1w-01': 'sha256:...'}
  """
  # Only nodes with an inner daemon can take an image.
  allowed = docker_nodes(manifest)
  # Default: every such node.
  names = list(names or allowed)
  # Loading into a node without an inner daemon would only fail later, inside the node.
  if set(names) - set(allowed):
    # Refused before anything is copied.
    raise LocalnetError('nodes without Docker: {} (init --docker-nodes)'.format(sorted(set(names) - set(allowed))))
  # Image id per node.
  ids = {}
  # One node at a time.
  for name in names:
    # The host's image as a tar stream, straight into the node's daemon: no registry is involved.
    save = subprocess.Popen(['docker', 'save', image], stdout=subprocess.PIPE)
    # The node's own Docker client loads the stream into the node's daemon.
    load = subprocess.run(['docker', 'exec', '-i', container(name), 'docker', 'load', '-q'], stdin=save.stdout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
    # Our copy of the pipe end is no longer needed once the loader holds it.
    save.stdout.close()
    # Both ends must succeed: a truncated stream would load nothing.
    if save.wait(timeout=60) != 0 or load.returncode != 0:
      # The node's own error, for the operator.
      raise LocalnetError('loading {} into {} failed: {}'.format(image, name, (load.stdout or '')[-500:]))
    if tag:
      # The name the apps are configured with, inside the node only.
      sh('docker', 'exec', container(name), 'docker', 'tag', image, tag)
    # The id the node's daemon gives the image, for the log.
    ids[name] = sh('docker', 'exec', container(name), 'docker', 'image', 'inspect', '-f', '{{.Id}}', tag or image).stdout.strip()
  # Node -> image id.
  return ids


def isolation(manifest, name, image):
  """
  Prove from inside a node that its inner containers reach no public network and pull nothing.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  name : str
    A node that runs Docker.
  image : str
    An image already in that node's daemon (``load_image``); the probe needs ``sh``, ``wget``,
    ``nslookup`` and ``timeout`` (BusyBox has them).

  Returns
  -------
  dict
    ``networks`` and ``published_ports`` of the node container, and for an inner container whether a
    public address answered, a public name resolved, the localnet front answered, and whether a pull
    from the public registry succeeded; ``ok`` is True only when nothing public was reached.

  Examples
  --------
  >>> isolation(manifest, 'r1w-01', 'localnet/syncapp:1')['ok']
  True
  """
  # The node's container name on the host.
  cname = container(name)
  # The node container as the host's Docker sees it.
  info = json.loads(sh('docker', 'inspect', cname).stdout)[0]
  # The node container is attached to the localnet network only.
  networks = sorted(info['NetworkSettings']['Networks'])
  # And publishes no port on the host.
  published = {port: bind for port, bind in (info['HostConfig'].get('PortBindings') or {}).items() if bind}
  # Two public probes that must fail, and one to the localnet front that must answer (its 404), which
  # shows that the probe's network path works and is only cut where it leaves the localnet.
  probe = ('timeout 6 wget -q -O /dev/null http://1.1.1.1/ && echo PUBLIC_IP_REACHED; '
           'timeout 6 nslookup github.com >/dev/null 2>&1 && echo PUBLIC_NAME_RESOLVED; '
           'timeout 6 wget -q -O /dev/null http://{}/ 2>&1 | grep -q 404 && echo FRONT_ANSWERED; echo PROBE_DONE').format(
             EDGE_IP)
  # A throwaway inner container: the same network path a container app has (inner bridge, then the node).
  out = sh('docker', 'exec', cname, 'docker', 'run', '--rm', '--entrypoint', '/bin/sh', image, '-c', probe,
           check=False, timeout=120).stdout or ''
  # A pull from the public registry must fail: the inner daemon resolves and reaches nothing outside.
  pull = sh('docker', 'exec', cname, 'timeout', '60', 'docker', 'pull', '-q', 'busybox:1.36', check=False, timeout=120)
  # What was seen, one field per probe.
  report = {
    'node': name, 'networks': networks, 'published_ports': published,
    'public_ip_reached': 'PUBLIC_IP_REACHED' in out, 'public_name_resolved': 'PUBLIC_NAME_RESOLVED' in out,
    'localnet_front_answered': 'FRONT_ANSWERED' in out, 'probe_ran': 'PROBE_DONE' in out,
    'public_pull_succeeded': pull.returncode == 0, 'pull_error': (pull.stdout or '').strip()[-160:],
  }
  # Isolated: only the localnet network, nothing published, nothing public reached, and the probe really ran.
  report['ok'] = (networks == [PROJECT] and not published and report['probe_ran'] and not report['public_ip_reached']
                  and not report['public_name_resolved'] and not report['public_pull_succeeded'])
  # The verdict with its evidence.
  return report


def _exec_python(name, code, *args):
  """
  Run a short Python program, read from stdin, with the node's own interpreter inside a node.

  Parameters
  ----------
  name : str
    Node name.
  code : str
    Program text (standard library only; run with ``-I``).
  *args : str
    Its arguments.

  Returns
  -------
  str
    Its output.

  Examples
  --------
  >>> _exec_python('r1w-01', "print('x')")
  'x\\n'
  """
  # Isolated mode: the program imports nothing from the node's working folder.
  return sh('docker', 'exec', '-i', container(name), PYTHON, '-I', '-', *args, stdin=code, check=False, timeout=120).stdout or ''


def _tagged(out, tag):
  """
  The JSON that follows ``tag`` on the last output line that starts with it.

  Parameters
  ----------
  out : str
    Program output.
  tag : str
    Line prefix, for example ``SYNCSTATE``.

  Returns
  -------
  object or None
    The decoded JSON, or None when no such line exists.

  Examples
  --------
  >>> _tagged('noise\\nRECORD {"cid": "Qm1"}\\n', 'RECORD')
  {'cid': 'Qm1'}
  """
  # Only the lines the reader programs print for us.
  lines = [line for line in out.splitlines() if line.startswith(tag + ' ')]
  # The last one wins; none means the program failed.
  return json.loads(lines[-1][len(tag) + 1:]) if lines else None


def sync_state(name):
  """
  Sync history of the container apps of one node: archives sent, archives applied, quarantined records.

  Parameters
  ----------
  name : str
    Node name.

  Returns
  -------
  dict
    ``sent`` and ``received`` (each a list of cid, version, timestamps), ``quarantine`` (count).

  Examples
  --------
  >>> sync_state('r1w-02')['received'][-1]['cid']
  'Qm...'
  """
  # An empty history when the node could not be read (for example while it restarts).
  return _tagged(_exec_python(name, SYNC_READER), 'SYNCSTATE') or {'sent': [], 'received': [], 'quarantine': 0}


def chain_record(name, key):
  """
  The container-sync record of one sync key in the chain-store replica an oracle last saved.

  Parameters
  ----------
  name : str
    Oracle name.
  key : str
    The sync key (``SYNC.KEY`` of the apps).

  Returns
  -------
  dict
    ``record`` (cid, version, node_id, or None) and ``age_s`` of the replica file.

  Examples
  --------
  >>> chain_record('r1s-01', 'lnet-sync-s0')['record']['cid']
  'Qm...'
  """
  # No record when the replica could not be read.
  return _tagged(_exec_python(name, RECORD_READER, key), 'RECORD') or {'record': None, 'age_s': None}


def app_file(name, image, path):
  """
  Content of a file as the container app on a node sees it.

  Parameters
  ----------
  name : str
    Node name.
  image : str
    The app's image, to find its container in the node's inner daemon.
  path : str
    Absolute path inside the app container.

  Returns
  -------
  dict
    ``container`` (inner container name or None), ``text`` and ``sha256`` (None when unreadable).

  Examples
  --------
  >>> app_file('r1w-02', 'localnet/syncapp:1', '/data/payload.txt')['sha256'][:8]
  '3f1c...'
  """
  # The running inner container of that image (an app being restarted for a sync has none for a moment).
  names = sh('docker', 'exec', container(name), 'docker', 'ps', '--filter', 'ancestor=' + image, '--format', '{{.Names}}',
             check=False).stdout.split()
  if not names:
    # No app running right now.
    return {'container': None, 'text': None, 'sha256': None}
  # The file read inside the app container, as the app reads it.
  proc = sh('docker', 'exec', container(name), 'docker', 'exec', names[0], 'cat', path, check=False)
  # A missing file reads as None, not as an empty text.
  text = proc.stdout if proc.returncode == 0 else None
  # The digest is what provider and consumers are compared by.
  return {'container': names[0], 'text': text, 'sha256': hashlib.sha256(text.encode()).hexdigest() if text else None}


def sync_check(manifest, provider, consumers, key, image, publishes=1, path='/data/payload.txt', within=150,
               timeout=900, poll=10):
  """
  Wait until every consumer of a sync set applied the provider's latest archive, then measure the set.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  provider : str
    Node of the provider app.
  consumers : list of str
    Nodes of the consumer apps.
  key : str
    The set's sync key.
  image : str
    The apps' image (to find their containers).
  publishes : int
    Archives the provider is expected to publish.
  path : str
    File the provider writes and every consumer must hold the same of.
  within : float
    Seconds a consumer may take from a publish to holding that archive or a later one (with the
    default settings: a 10 s poll, a 60 s chain-store refresh, then the apply).
  timeout : float
    Seconds to wait for the set to converge before measuring anyway.
  poll : float
    Seconds between looks.

  Returns
  -------
  dict
    Per publish: cid, the oracles whose replica holds the record, and each consumer's delay; per consumer:
    archives applied, quarantined records and refusal log lines; the file on every node; ``failures`` (a
    list of reasons, empty when the set passed) and ``ok``.

  Examples
  --------
  >>> report = sync_check(manifest, 'r1w-01', ['r1w-02'], 'lnet-sync-s0', 'localnet/syncapp:1')
  >>> report['ok'], report['publishes'][0]['delay_s']
  (True, {'r1w-02': 41.2})
  """
  # Start of the wait, for the report and the timeout.
  started = time.time()
  # Look until the set converged or the time is up.
  while True:
    # What the provider published so far.
    prov = sync_state(provider)
    # What each consumer applied so far.
    cons = {name: sync_state(name) for name in consumers}
    # The provider's archives, oldest first.
    sent = prov['sent']
    # Converged: the expected publishes exist and every consumer last applied the latest of them.
    done = len(sent) >= publishes and all(
      cons[name]['received'] and cons[name]['received'][-1]['cid'] == sent[-1]['cid'] for name in consumers)
    if done or time.time() - started > timeout:
      break
    # Not yet: look again later.
    time.sleep(poll)
  # Every oracle keeps a replica of the chain store.
  oracles = [node['name'] for node in manifest['nodes'] if node['role'] in ('seed', 'oracle')]
  # The set's record as each oracle last saved it.
  records = {name: chain_record(name, key) for name in oracles}
  # One row per publish.
  rows = []
  # Each publish, oldest first.
  for idx, entry in enumerate(sent):
    # A consumer that skipped this archive for a later one of the same set still holds it in time.
    later = {item['cid'] for item in sent[idx:]}
    # Delay per consumer.
    delays = {}
    # Each consumer of the set.
    for name in consumers:
      # When the consumer applied this archive or a later one.
      hits = [item['applied_timestamp'] for item in cons[name]['received'] if item['cid'] in later]
      # The first such apply, counted from the publish; None when it never happened.
      delays[name] = round(min(hits) - entry['published_timestamp'], 1) if hits else None
    # The publish with its delays.
    rows.append({'cid': entry['cid'], 'published': entry['published_timestamp'], 'delay_s': delays})
  # The archive every node should hold at the end.
  latest = sent[-1]['cid'] if sent else None
  # Each oracle whose saved replica points the set at the latest archive.
  holding = sorted(name for name, item in records.items() if (item.get('record') or {}).get('cid') == latest and latest)
  # The file as the provider app and each consumer app read it.
  files = {name: app_file(name, image, path) for name in [provider] + list(consumers)}
  # Per consumer counts.
  per_consumer = {}
  # Each consumer of the set.
  for name in consumers:
    # The consumer node's log, for its refusal lines.
    text = node_log(name)
    # What the consumer applied, and what it refused.
    per_consumer[name] = {
      'applied': len(cons[name]['received']), 'latest_cid': (cons[name]['received'] or [{}])[-1].get('cid'),
      'quarantine_files': cons[name]['quarantine'],
      # The two log lines the sync code writes when it refuses or postpones a record.
      'cannot_prepare_lines': text.count('[sync] cannot prepare'),
      'quarantined_skips': text.count('[sync] skipping quarantined'),
    }
  # Reasons the set failed; empty means PASS.
  failures = []
  if len(sent) < publishes:
    # The provider did not publish what the scenario asked for.
    failures.append('provider published {} of {} archives'.format(len(sent), publishes))
  if latest and not holding:
    # The record never reached a replica that was saved.
    failures.append('no oracle replica holds the latest record')
  # Each publish.
  for row in rows:
    # Each consumer's delay for it.
    for name, delay in row['delay_s'].items():
      # Every publish must reach every consumer, and in time.
      if delay is None or delay > within:
        # Late or never.
        failures.append('{} held {} after {} s (bound {} s)'.format(name, row['cid'], delay, within))
  # Each consumer's end state.
  for name, item in per_consumer.items():
    if item['latest_cid'] != latest:
      # The consumer ends on another archive than the provider's latest.
      failures.append('{} last applied {} instead of {}'.format(name, item['latest_cid'], latest))
    if item['quarantine_files'] or item['cannot_prepare_lines']:
      # A refused record of a set whose records are all valid.
      failures.append('{} refused records: {} quarantined, {} "cannot prepare" lines'.format(
        name, item['quarantine_files'], item['cannot_prepare_lines']))
  # The provider's file digest.
  digest = files[provider]['sha256']
  # The file written on the provider must be readable, and the same, on every consumer.
  if not digest or any(files[name]['sha256'] != digest for name in consumers):
    # Unreadable on the provider, or different on a consumer.
    failures.append('file {} differs: {}'.format(path, {name: item['sha256'] for name, item in files.items()}))
  # The whole measurement.
  return {
    'key': key, 'provider': provider, 'consumers': list(consumers), 'waited_s': round(time.time() - started, 1),
    'publishes': rows, 'record_on_oracles': '{}/{}'.format(len(holding), len(oracles)), 'records': records,
    'consumers_state': per_consumer, 'files': files, 'failures': failures, 'ok': not failures,
  }


def sync_text(report):
  """
  A short human summary of a ``sync_check`` report.

  Parameters
  ----------
  report : dict
    Result of ``sync_check``.

  Returns
  -------
  str
    A few lines ending with ``PASS`` or ``FAIL`` and the reasons.

  Examples
  --------
  >>> print(sync_text(report).splitlines()[-1])
  PASS
  """
  # The set, its nodes and how long the check waited.
  lines = ['sync set {} provider {} -> consumers {} (waited {} s)'.format(
    report['key'], report['provider'], ', '.join(report['consumers']), report['waited_s'])]
  # One line per publish.
  for row in report['publishes']:
    # The archive and each consumer's delay.
    lines.append('  publish {} delay to consumers {}'.format(row['cid'], row['delay_s']))
  # How many oracle replicas point at the latest archive.
  lines.append('  chain-store record on oracles holding the latest archive: {}'.format(report['record_on_oracles']))
  # One line per consumer.
  for name, item in report['consumers_state'].items():
    # Applies and refusals.
    lines.append('  {} applied {} archive(s), quarantined {}, "cannot prepare" lines {}'.format(
      name, item['applied'], item['quarantine_files'], item['cannot_prepare_lines']))
  # One line per node's file.
  for name, item in report['files'].items():
    # Its text and digest prefix.
    lines.append('  {} {}: {}'.format(name, (item['text'] or '').strip()[:80], (item['sha256'] or '-')[:16]))
  # The verdict last.
  lines.append('PASS' if report['ok'] else 'FAIL: ' + '; '.join(report['failures']))
  # One text block.
  return '\n'.join(lines)


def wait_source(name, arm_rev, since, timeout=600):
  """
  Wait until a node restarted on another source tree is back on the network with that tree.

  Parameters
  ----------
  name : str
    Node name.
  arm_rev : str
    The ``edge_node@<rev>`` line of the tree it must report (from ``.localnet_rev``).
  since : float
    Time of the restart; only a start after it counts.
  timeout : float
    Seconds to wait.

  Returns
  -------
  float
    Seconds from ``since`` until the node reported the tree and its broker connection.

  Raises
  ------
  LocalnetError
    The node did not come back on that tree in time.

  Examples
  --------
  >>> wait_source('r1w-02', 'edge_node@ef11564', time.time())
  48.3
  """
  # Look until the node is back or the time is up.
  while time.time() - since < timeout:
    # The node's log since its container was created.
    text = node_log(name)
    # The last start of the node: its launcher prints the source trees, then the node connects.
    start = text.rfind('[launch] source trees:')
    if start >= 0:
      # Everything the node printed in that start.
      run = text[start:]
      # Back on the wanted tree and connected to its broker.
      if arm_rev in run.splitlines()[0] and 'MQTT conn ok' in run:
        # Seconds since the restart began.
        return round(time.time() - since, 1)
    # Not yet: look again later.
    time.sleep(5)
  # Never came back on that tree.
  raise LocalnetError('{} did not come back on {} within {} s'.format(name, arm_rev, timeout))


def log_report(report):
  """
  Write a ``sync_check`` summary to the tool log, one line at a time.

  Parameters
  ----------
  report : dict
    Result of ``sync_check``.

  Returns
  -------
  None

  Examples
  --------
  >>> log_report(report)
  """
  # Each line of the summary.
  for line in sync_text(report).splitlines():
    # One tool log line per summary line.
    log(line)
  return
