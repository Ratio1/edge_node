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
    what each consumer applied and when, and whether the consumer's file equals the provider's; and
    that a consumer which must refuse the set's records refused them before any download;
  * check the custody of a set's secret (stored redacted in R1FS, delivered to the node) and scan the
    nodes for secret material.
"""

# Digests of the files apps hold, to compare provider and consumer, and the forms of a secret a scan looks for.
import hashlib
# The MAC subkey a node derives from a set's secret (one of the forms the scan looks for).
import hmac
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
# consumer), and the quarantine of records a consumer refused, inside a node's data folder; and the
# folders R1FS downloads archives into. Only the history of one set is kept: a provider's test app puts
# the set's key into its publish metadata (load/deeploy.py), so two sets on one node stay apart.
SYNC_READER = r'''
# Standard library only: the node's own modules are not imported (-I).
import glob, json, os, sys
root = '/edge_node/_local_cache/_data'
# The set whose history is wanted.
key = sys.argv[1]
def entries(kind):
  rows = []
  for path in glob.glob(root + '/**/sync_history/' + kind + '/*.json', recursive=True):
    try:
      with open(path) as fh:
        item = json.load(fh)
    except Exception:
      # An entry being rewritten at this moment is skipped; the next look reads it.
      continue
    # A sent entry keeps the app's request (with its metadata); a received entry keeps the record's metadata.
    meta = (item.get('request') or {}).get('metadata') if kind == 'sent' else item.get('metadata')
    # Entries of other sets on the same node are left out.
    if (meta or {}).get('key') != key:
      # Another set's entry (or one written before apps named their set).
      continue
    # The fields the check needs.
    rows.append(dict({name: item.get(name) for name in ('cid', 'version', 'published_timestamp', 'applied_timestamp', 'node_id')},
                     # The archive format tag the entry's manifest names (None when it has none).
                     encryption=(item.get('manifest') or {}).get('encryption')))
  return sorted(rows, key=lambda row: (row.get('version') or 0, row.get('published_timestamp') or row.get('applied_timestamp') or 0))
# The CID of every quarantine file of the node (any set; the caller keeps the set's own).
quarantine = []
# One file per refused record, written by the sync code.
for path in glob.glob(root + '/**/sync_history/state/quarantine/*.json', recursive=True):
  # Each file names the refused record's CID.
  with open(path) as fh:
    # Kept for the host, which keeps the set's own.
    quarantine.append(json.load(fh).get('cid'))
# R1FS writes each fetched CID into a folder of that name here (the logger's output folder).
downloads = '/edge_node/_local_cache/_output/ipfs_downloads'
# One tagged line for the host.
print('SYNCSTATE ' + json.dumps({'sent': entries('sent'), 'received': entries('received'), 'quarantine': quarantine,
                                 # The folders present, none when R1FS never fetched anything.
                                 'downloads': sorted(os.listdir(downloads)) if os.path.isdir(downloads) else []}))'''

# The log line a consumer writes when it refuses a record before downloading it.
REFUSAL_MARKER = '[sync] cannot prepare'
# Log lines that name a CID only when R1FS fetched it, or tried to: the download folder in the success and
# decryption-failure lines, the two download-failure lines, and the sync code's own get_file error lines.
GET_FILE_MARKERS = ('ipfs_downloads', 'ipfs get failed', 'Failed to download CID', 'get_file(')
# The chain-store replica a node last saved (owner, value and stamps per record, keyed "hs:<hash>:<field>").
CSTORE_PICKLE = '/edge_node/_local_cache/_data/cache_plugins/admin_pipeline__chain_store_base__chain_store_base_inst/object.pickle'
# The value Deeploy stores in place of each selected secret (ratio1 dAuth.DAUTH_SECRET_PLACEHOLDER).
DAUTH_PLACEHOLDER = '__R1_DAUTH_SECRET__'
# The context string under which a node derives a set's record MAC subkey from the set's secret.
SYNC_MAC_CONTEXT = b'r1en-volume-sync-record-v1'
# A node's IPFS repository: the SDK puts it in the logger's base folder (the cache folder) as ".ipfs".
IPFS_HOME = '/edge_node/_local_cache/.ipfs'

# On an oracle: the job's pointer in DEEPLOY_DEPLOYED_JOBS, then each document it names (the stored job and
# the deployment plan) read from R1FS with the default key, as any node can read it. Prints, per document,
# what the instances hold at ENV.R1EN_SYNC_SECRET ("placeholder" or "other", never a value), their
# SECRET_PATHS, and whether the secret occurs anywhere in it. NEEDLE (the secret) is put in front by the
# caller, through stdin. The node keeps its IPFS repository at IPFS_HOME.
CUSTODY_READER = r'''
# Standard library and the node image's cryptography package only (-I).
import base64, hashlib, json, os, pickle, subprocess, sys, tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# The Deeploy job id.
job = sys.argv[1]
# The record name of the job's pointer: "hs:" + 10 hex characters of the hash name's SHA-256 + ":" + base64url(job).
field = 'hs:{}:{}'.format(hashlib.sha256(b'DEEPLOY_DEPLOYED_JOBS').hexdigest()[:10], base64.urlsafe_b64encode(job.encode()).decode())
# The replica as the oracle last saved it.
with open(CSTORE_PICKLE, 'rb') as fh:
  record = pickle.load(fh).get(field)
# The stored value: a signed dict naming the stored job and the plan, or a bare CID (older pointers).
pointer = record.get('value') if isinstance(record, dict) else record
# The documents to read.
cids = {'pipeline': pointer.get('pipeline_cid'), 'plan': pointer.get('plan_cid')} if isinstance(pointer, dict) else {'pipeline': pointer}
def read(cid):
  # A throwaway folder, removed with what it holds.
  with tempfile.TemporaryDirectory() as tmp:
    # The node's own IPFS client fetches the object (a folder holding one encrypted file).
    got = subprocess.run(['ipfs', 'get', cid, '-o', tmp + '/o'], env=dict(os.environ, IPFS_PATH=IPFS_HOME),
                         capture_output=True, text=True, timeout=90)
    if got.returncode != 0:
      return None
    # The one file in it.
    with open(os.path.join(tmp, 'o', os.listdir(tmp + '/o')[0]), 'rb') as fh:
      blob = fh.read()
  # R1FS layout: 12-byte nonce, 4-byte metadata length, metadata, content, 16-byte GCM tag, one AES-GCM stream.
  meta_len = int.from_bytes(blob[12:16], 'big')
  # The default key: SHA-256 of the default secret "ratio1", as every node reads a stored job.
  dec = Cipher(algorithms.AES(hashlib.sha256(b'ratio1').digest()), modes.GCM(blob[:12])).decryptor()
  # The metadata (the file name) comes first in the stream.
  dec.update(blob[16:16 + meta_len])
  # The content, authenticated by the tag.
  return (dec.update(blob[16 + meta_len:-16]) + dec.finalize_with_tag(blob[-16:])).decode()
def walk(doc, values, paths):
  if isinstance(doc, dict):
    # An instance's variables.
    env = doc.get('ENV')
    if isinstance(env, dict) and 'R1EN_SYNC_SECRET' in env:
      # Only whether it is the placeholder: the value itself is never printed.
      values.append('placeholder' if env['R1EN_SYNC_SECRET'] == PLACEHOLDER else 'other')
      # The instance's selections, as Deeploy keeps them.
      paths.append(doc.get('SECRET_PATHS'))
    for item in doc.values():
      walk(item, values, paths)
  elif isinstance(doc, list):
    for item in doc:
      walk(item, values, paths)
# Per document: what was found.
docs = {}
# The stored job, then the plan.
for kind, cid in cids.items():
  # The plain text, None when the object could not be fetched.
  text = read(cid) if cid else None
  # What the instances hold at the variable, and their selections.
  values, paths = [], []
  if text is not None:
    walk(json.loads(text), values, paths)
  # Kinds and selections only; the secret is looked up, never echoed.
  docs[kind] = {'cid': cid, 'readable': text is not None, 'values': values, 'secret_paths': paths,
                'secret_in_doc': text is not None and NEEDLE in text}
# One tagged line for the host.
print('CUSTODY ' + json.dumps({'pointer': type(pointer).__name__ if pointer else None, 'docs': docs}))'''

# On any node: every file under the node's cache folder (logs, plugin data, the apps' mounted system and data
# volumes, R1FS downloads, store files), read as bytes and searched for each form of the secret (NEEDLES,
# kind -> text, put in front by the caller through stdin). Loop-device image files are skipped: their
# content is read through their mounts. A file removed while the scan runs (a temporary file) is skipped.
# The chain-store replica is searched record by record, and the records of DAUTH_JOB_SECRETS and
# DAUTH_JOB_SECRET_REVISIONS, where dAuth keeps the bundles it serves (current and per revision), are counted
# apart.
SCAN_READER = r'''
# Standard library only (-I).
import hashlib, json, os, pickle
# The node's whole cache folder.
root = '/edge_node/_local_cache'
# The record-name prefixes of dAuth's two bundle hashes in the replica (current bundle, bundle per revision).
dauth = tuple('hs:{}:'.format(hashlib.sha256(name).hexdigest()[:10]) for name in (b'DAUTH_JOB_SECRETS', b'DAUTH_JOB_SECRET_REVISIONS'))
def kinds(blob):
  # The kinds whose text occurs in the bytes.
  return sorted(kind for kind, needle in NEEDLES.items() if needle.encode() in blob)
# Findings, files and bytes read, and the kinds found in dAuth's bundle records.
hits, files, size, dauth_kinds = [], 0, 0, []
# Every folder, mounted app volumes included.
for folder, dirs, names in os.walk(root):
  # Loop-device images: read through their mounts instead.
  if folder.endswith('/fixed_volumes/images'):
    continue
  for name in names:
    # The file's full path.
    path = os.path.join(folder, name)
    # Regular files only: no links, sockets or pipes.
    if os.path.islink(path) or not os.path.isfile(path):
      continue
    if path == CSTORE_PICKLE:
      # The replica, read record by record.
      with open(path, 'rb') as fh:
        store = pickle.load(fh)
      # dAuth's bundle records hold the secrets dAuth serves: reported apart.
      dauth_kinds = kinds(repr({k: v for k, v in store.items() if k.startswith(dauth)}).encode())
      # Every other record is searched like a file.
      blob = repr({k: v for k, v in store.items() if not k.startswith(dauth)}).encode()
    else:
      try:
        # The file's bytes.
        with open(path, 'rb') as fh:
          blob = fh.read()
      except FileNotFoundError:
        continue
    # Counted as read.
    files, size = files + 1, size + len(blob)
    # The kinds it holds.
    found = kinds(blob)
    if found:
      # Path and kinds only, never the text found.
      hits.append({'path': path, 'kinds': found})
# One tagged line for the host.
print('SCAN ' + json.dumps({'files': files, 'bytes': size, 'hits': hits, 'dauth_bundle_kinds': dauth_kinds}))'''

# The chain-store replica an oracle last saved, and the record of one sync key in it: its archive, version and
# publisher, the archive format tag of its manifest, and the form of its record MAC ("hex64", "other", or None
# when the record has none), never the MAC itself.
RECORD_READER = r'''
# re: the MAC's form is checked, its value is not printed.
import base64, hashlib, json, os, pickle, re, sys, time
path = '/edge_node/_local_cache/_data/cache_plugins/admin_pipeline__chain_store_base__chain_store_base_inst/object.pickle'
key = 'hs:{}:{}'.format(hashlib.sha256(b'CHAINSTORE_SYNC').hexdigest()[:10], base64.urlsafe_b64encode(sys.argv[1].encode()).decode())
value = None
if os.path.exists(path):
  with open(path, 'rb') as fh:
    record = pickle.load(fh).get(key)
  value = record.get('value') if isinstance(record, dict) else record
# A set's record carries a top-level "mac"; a shared-key record has none.
mac = value.get('mac') if isinstance(value, dict) else None
# The MAC's form only: 64 lowercase hex characters, something else, or absent.
form = None if mac is None else 'hex64' if isinstance(mac, str) and re.fullmatch('[0-9a-f]{64}', mac) else 'other'
# The record's archive, version and publisher.
out = {'cid': value.get('cid'), 'version': value.get('version'), 'node_id': value.get('node_id'),
       # The manifest's format tag ("r1fs-default" or "r1fs-set-v1") and the MAC's form.
       'encryption': (value.get('manifest') or {}).get('encryption'), 'mac': form} if isinstance(value, dict) else None
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
  # Isolated mode: the program imports nothing from the node's working folder. Up to 10 minutes: a secret
  # scan reads every file of the node's cache folder.
  return sh('docker', 'exec', '-i', container(name), PYTHON, '-I', '-', *args, stdin=code, check=False, timeout=600).stdout or ''


def _with_values(code, **values):
  """
  A reader program with names defined in front of it, so values (a secret among them) reach the node
  through stdin and never through a command line.

  Parameters
  ----------
  code : str
    Program text that uses the names.
  **values
    Name -> value (str, number, dict or list of them); each becomes one ``NAME = <literal>`` line.

  Returns
  -------
  str
    The program text with the definitions first.

  Examples
  --------
  >>> _with_values('print(X)', X='a')
  "X = 'a'\\nprint(X)"
  """
  # One literal per name (repr of a str, number, dict or list is valid Python), then the program.
  return ''.join('{} = {!r}\n'.format(name, value) for name, value in values.items()) + code


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


def sync_state(name, key):
  """
  Sync history of one set's container apps on one node: archives sent, archives applied, and what any app
  of the node quarantined or downloaded.

  Parameters
  ----------
  name : str
    Node name.
  key : str
    The set's sync key; only history entries of that set are returned (several sets can share a node).

  Returns
  -------
  dict
    ``sent`` and ``received`` (each a list of cid, version, timestamps) of the set, ``quarantine`` (CIDs of
    the node's quarantine files) and ``downloads`` (CIDs in the node's R1FS download folder).

  Examples
  --------
  >>> sync_state('r1w-02', 'lnet-sync-s0')['received'][-1]['cid']
  'Qm...'
  """
  # An empty history when the node could not be read (for example while it restarts).
  return _tagged(_exec_python(name, SYNC_READER, key), 'SYNCSTATE') or {'sent': [], 'received': [], 'quarantine': [], 'downloads': []}


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


def app_file(name, image, key, path):
  """
  Content of a file as one set's container app on a node sees it.

  Parameters
  ----------
  name : str
    Node name.
  image : str
    The app's image, to find its container in the node's inner daemon.
  key : str
    The set's sync key: the app is the one whose ``R1_SYNC_KEY`` is this key (several sets can share a node).
  path : str
    Absolute path inside the app container.

  Returns
  -------
  dict
    ``container`` (inner container name or None), ``text`` and ``sha256`` (None when unreadable).

  Examples
  --------
  >>> app_file('r1w-02', 'localnet/syncapp:1', 'lnet-sync-s0', '/data/payload.txt')['sha256'][:8]
  '3f1c...'
  """
  # The running inner containers of that image (an app being restarted for a sync has none for a moment).
  running = sh('docker', 'exec', container(name), 'docker', 'ps', '--filter', 'ancestor=' + image, '--format', '{{.Names}}',
               check=False).stdout.split()
  # The one of the set: the container app runner gives each app of an enabled set its key as R1_SYNC_KEY.
  names = [item for item in running if sh('docker', 'exec', container(name), 'docker', 'exec', item, 'printenv', 'R1_SYNC_KEY',
                                          check=False).stdout.strip() == key]
  if not names:
    # No app of the set running right now.
    return {'container': None, 'text': None, 'sha256': None}
  # The file read inside the app container, as the app reads it.
  proc = sh('docker', 'exec', container(name), 'docker', 'exec', names[0], 'cat', path, check=False)
  # A missing file reads as None, not as an empty text.
  text = proc.stdout if proc.returncode == 0 else None
  # The digest is what provider and consumers are compared by.
  return {'container': names[0], 'text': text, 'sha256': hashlib.sha256(text.encode()).hexdigest() if text else None}


def _cid_lines(text, cids, markers):
  """
  Lines of a node log that name one of a set's CIDs and carry one of the given markers.

  Parameters
  ----------
  text : str
    The node's log.
  cids : set of str
    CIDs of the set's archives.
  markers : tuple of str
    Texts of which a line must hold at least one.

  Returns
  -------
  list of str
    The matching lines, in log order.

  Examples
  --------
  >>> _cid_lines('[sync] cannot prepare v1 (cid=Qm1): bad\\nother Qm1\\n', {'Qm1'}, (REFUSAL_MARKER,))
  ['[sync] cannot prepare v1 (cid=Qm1): bad']
  """
  # A line can name a CID of any set: keep the lines of this set that carry a wanted marker.
  return [line for line in text.splitlines() if any(cid in line for cid in cids) and any(mark in line for mark in markers)]


def sync_check(manifest, provider, consumers, key, image, publishes=1, path='/data/payload.txt', within=150,
               timeout=900, poll=10, refusing=None, encryption=None):
  """
  Wait until every consumer of a sync set applied the provider's latest archive and every refusing
  consumer refused it, then measure the set.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  provider : str
    Node of the provider app.
  consumers : list of str
    Nodes of the consumer apps that must apply every publish (may be empty).
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
  refusing : dict or None
    Node -> text: consumer apps of the set that must refuse its records before any download. Each needs a
    refusal line for the latest record (one of its refusal lines holding the text, when the text is not
    empty), no R1FS fetch line and no download folder for any of the set's CIDs, nothing applied, and its
    file unchanged and unlike the provider's.
  encryption : str or None
    The archive format tag the latest record must carry on every oracle replica that holds it:
    ``r1fs-set-v1`` (a set with a secret: the record must also carry a 64-hex ``mac``) or ``r1fs-default``
    (a shared-key set: no ``mac``); None does not check the format.

  Returns
  -------
  dict
    Per publish: cid, the format tag the provider published it with, and each consumer's delay; the oracles
    whose replica holds the latest record and that record's (format tag, MAC form) per oracle; per consumer:
    archives applied, quarantine files and refusal log lines of this set; per refusing consumer: the CIDs
    and reasons it refused, its fetch lines, downloads and applies; the file on every node; ``failures`` (a
    list of reasons, empty when the set passed) and ``ok``.

  Examples
  --------
  >>> report = sync_check(manifest, 'r1w-01', ['r1w-02'], 'lnet-sync-s0', 'localnet/syncapp:1',
  ...                     refusing={'r1w-04': 'unsupported encryption'})
  >>> report['ok'], report['publishes'][0]['delay_s']
  (True, {'r1w-02': 41.2})
  """
  # Nodes that must refuse, with the text one of their refusal lines must hold ('' for any refusal).
  refusing = dict(refusing or {})
  # Start of the wait, for the report and the timeout.
  started = time.time()
  # A refusing app's file before the check: a refusal must leave it as it is.
  before = {name: app_file(name, image, key, path)['sha256'] for name in refusing}
  # Look until the set converged or the time is up.
  while True:
    # What the provider published so far.
    prov = sync_state(provider, key)
    # What each consumer, refusing ones included, applied, quarantined and downloaded so far.
    cons = {name: sync_state(name, key) for name in list(consumers) + list(refusing)}
    # The provider's archives, oldest first.
    sent = prov['sent']
    # The set's CIDs: refusal, fetch and download evidence is looked up by them.
    cids = {item['cid'] for item in sent}
    # The refusing nodes' logs, for their refusal and fetch lines.
    logs = {name: node_log(name) for name in refusing}
    # Converged: the expected publishes exist, every consumer last applied the latest of them, and every
    # refusing consumer logged its refusal of the latest.
    done = len(sent) >= publishes and all(
      # Each consumer's last apply is the provider's latest archive.
      cons[name]['received'] and cons[name]['received'][-1]['cid'] == sent[-1]['cid'] for name in consumers) and all(
      # Each refusing consumer's log names the latest archive in a refusal line.
      _cid_lines(logs[name], {sent[-1]['cid']}, (REFUSAL_MARKER,)) for name in refusing)
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
    # The publish with its format tag (from the provider's sent history) and its delays.
    rows.append({'cid': entry['cid'], 'published': entry['published_timestamp'], 'encryption': entry.get('encryption'),
                 'delay_s': delays})
  # The archive every node should hold at the end.
  latest = sent[-1]['cid'] if sent else None
  # Each oracle whose saved replica points the set at the latest archive.
  holding = sorted(name for name, item in records.items() if (item.get('record') or {}).get('cid') == latest and latest)
  # The file as the provider app and each consumer app read it, refusing ones included.
  files = {name: app_file(name, image, key, path) for name in [provider] + list(consumers) + list(refusing)}
  # The provider's file digest.
  digest = files[provider]['sha256']
  # Per consumer counts.
  per_consumer = {}
  # Each consumer of the set.
  for name in consumers:
    # The consumer node's log, for its refusal lines.
    text = node_log(name)
    # What the consumer applied, and what it refused.
    per_consumer[name] = {
      'applied': len(cons[name]['received']), 'latest_cid': (cons[name]['received'] or [{}])[-1].get('cid'),
      # The node's quarantine files of this set's records (other sets can share the node).
      'quarantine_files': len(cids & set(cons[name]['quarantine'])),
      # The two log lines the sync code writes when it refuses or postpones a record of this set.
      'cannot_prepare_lines': len(_cid_lines(text, cids, (REFUSAL_MARKER,))),
      # Ticks that skipped one of this set's records while it was quarantined.
      'quarantined_skips': len(_cid_lines(text, cids, ('[sync] skipping quarantined',))),
    }
  # Reasons the set failed; empty means PASS.
  failures = []
  if len(sent) < publishes:
    # The provider did not publish what the scenario asked for.
    failures.append('provider published {} of {} archives'.format(len(sent), publishes))
  if latest and not holding:
    # The record never reached a replica that was saved.
    failures.append('no oracle replica holds the latest record')
  # The form each holding replica gives the latest record: its format tag and the form of its MAC.
  forms = {name: (records[name]['record'].get('encryption'), records[name]['record'].get('mac')) for name in holding}
  # A set with a secret publishes its tag with a 64-hex MAC; a shared-key set its tag with no MAC.
  wanted = (encryption, 'hex64' if encryption == 'r1fs-set-v1' else None)
  if encryption and any(form != wanted for form in forms.values()):
    # The record is not in the format the code under test must publish.
    failures.append('latest record (format, mac) on the oracles {} instead of {}'.format(forms, wanted))
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
  # Per refusing consumer: what it refused, and the evidence that it fetched and applied nothing.
  per_refusing = {}
  # Each refusing consumer, with the text its refusal must hold.
  for name, expected in refusing.items():
    # Its refusal lines for this set's records.
    lines = _cid_lines(logs[name], cids, (REFUSAL_MARKER,))
    # Its evidence.
    per_refusing[name] = {
      # The text its refusal must hold ('' for any).
      'expected': expected,
      # The records it refused (a refusal line names the CID).
      'refused_cids': sorted(cid for cid in cids if any(cid in line for line in lines)),
      # The reasons, as each line gives them after "(cid=...): " (fixed texts, never a value).
      'reasons': sorted({line.split(REFUSAL_MARKER, 1)[1].split('): ', 1)[-1].strip() for line in lines}),
      # An R1FS fetch of any of the set's archives leaves a log line (success, decryption or download failure).
      'get_file_lines': len(_cid_lines(logs[name], cids, GET_FILE_MARKERS)),
      # A fetch that succeeded leaves the archive's folder in the node's download folder.
      'downloads': sorted(cids & set(cons[name]['downloads'])),
      # Archives of the set it applied (none for a consumer that refuses them all).
      'applied': len(cons[name]['received']),
      # Its quarantine files of this set's records.
      'quarantine_files': len(cids & set(cons[name]['quarantine'])),
      # Its app's file before and after the check (None while missing).
      'file_before': before[name], 'file_after': files[name]['sha256'],
    }
  # Each refusing consumer's end state.
  for name, item in per_refusing.items():
    if latest not in item['refused_cids']:
      # It never refused the latest record (it may not have seen it, or it accepted it).
      failures.append('{} logged no refusal of the latest record {}'.format(name, latest))
    if item['expected'] and not any(item['expected'] in reason for reason in item['reasons']):
      # It refused for another reason than the one the step expects.
      failures.append('{} refused without "{}": {}'.format(name, item['expected'], item['reasons']))
    if item['get_file_lines'] or item['downloads'] or item['applied']:
      # The refusal came after a download, or the record was applied.
      failures.append('{} fetched or applied records it must refuse: {} fetch lines, downloads {}, {} applied'.format(
        name, item['get_file_lines'], item['downloads'], item['applied']))
    if item['file_after'] != item['file_before'] or (item['file_after'] is not None and item['file_after'] == digest):
      # The app's file changed, or holds the provider's data.
      failures.append('{} file {} changed or equals the provider\'s'.format(name, path))
  # The file written on the provider must be readable, and the same, on every consumer.
  if not digest or any(files[name]['sha256'] != digest for name in consumers):
    # Unreadable on the provider, or different on a consumer.
    failures.append('file {} differs: {}'.format(path, {name: item['sha256'] for name, item in files.items()}))
  # The whole measurement.
  return {
    'key': key, 'provider': provider, 'consumers': list(consumers), 'waited_s': round(time.time() - started, 1),
    'publishes': rows, 'record_on_oracles': '{}/{}'.format(len(holding), len(oracles)), 'records': records,
    # The latest record's (format tag, MAC form) per holding oracle, and the expected tag (None: not checked).
    'record_forms': forms, 'encryption': encryption,
    # The refusing consumers' evidence beside the consumers' counts.
    'consumers_state': per_consumer, 'refusing': per_refusing, 'files': files, 'failures': failures, 'ok': not failures,
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
    # The archive, its format tag and each consumer's delay.
    lines.append('  publish {} ({}) delay to consumers {}'.format(row['cid'], row.get('encryption'), row['delay_s']))
  # How many oracle replicas point at the latest archive.
  lines.append('  chain-store record on oracles holding the latest archive: {}'.format(report['record_on_oracles']))
  # Its format tag and MAC form, as each holding oracle keeps it (the MAC value is never read out).
  lines.append('  latest record (format, mac) per oracle: {} (expected format {})'.format(
    report['record_forms'], report['encryption']))
  # One line per consumer.
  for name, item in report['consumers_state'].items():
    # Applies and refusals.
    lines.append('  {} applied {} archive(s), quarantined {}, "cannot prepare" lines {}'.format(
      name, item['applied'], item['quarantine_files'], item['cannot_prepare_lines']))
  # One line per refusing consumer.
  for name, item in report['refusing'].items():
    # What it refused and why, and the evidence that it fetched and applied nothing.
    lines.append('  {} refused {} record(s) {}; fetch lines {}, downloads {}, applied {}'.format(
      name, len(item['refused_cids']), item['reasons'], item['get_file_lines'], len(item['downloads']), item['applied']))
  # One line per node's file.
  for name, item in report['files'].items():
    # Its text and digest prefix.
    lines.append('  {} {}: {}'.format(name, (item['text'] or '').strip()[:80], (item['sha256'] or '-')[:16]))
  # The verdict last.
  lines.append('PASS' if report['ok'] else 'FAIL: ' + '; '.join(report['failures']))
  # One text block.
  return '\n'.join(lines)


def sync_needles(secret):
  """
  The forms of a set's secret that must not appear in node logs, plugin data or store files.

  Parameters
  ----------
  secret : str
    The set's secret (64 lowercase hex characters).

  Returns
  -------
  dict
    Kind -> text: ``secret`` (the value), ``archive_key`` (SHA-256 of it in hex, the R1FS archive key),
    ``archive_key_16`` (the first 16 bytes of that key in hex, as debug lines of older SDK versions print
    keys) and ``mac_subkey`` (the record MAC subkey in hex: HMAC-SHA256 keyed by the secret over the fixed context).

  Examples
  --------
  >>> sorted(sync_needles('ab' * 32))
  ['archive_key', 'archive_key_16', 'mac_subkey', 'secret']
  """
  # The archive key R1FS derives from a secret: SHA-256 of its UTF-8 text.
  archive_key = hashlib.sha256(secret.encode('utf-8')).digest()
  # Each form as the hex text a log line or a file would hold.
  return {
    'secret': secret,
    'archive_key': archive_key.hex(),
    'archive_key_16': archive_key[:16].hex(),
    # HMAC-SHA256 keyed by the secret's ASCII text over the fixed context.
    'mac_subkey': hmac.new(secret.encode('ascii'), SYNC_MAC_CONTEXT, hashlib.sha256).hexdigest(),
  }


def custody(job, secret, oracle, node=None, key=None, image='localnet/syncapp:1', secret_len=None, timeout=180, poll=10):
  """
  Check the custody of a set's secret for one Deeploy job: stored redacted, and delivered to the node.

  On ``oracle``, the job's pointer in DEEPLOY_DEPLOYED_JOBS names the stored job and its deployment plan in
  R1FS; each is read with the default key, as any node can read it, and must hold only the dAuth
  placeholder at ``ENV.R1EN_SYNC_SECRET`` and the secret nowhere. On ``node``, the set's app reports in
  ``/data/secret_len`` how many bytes the variable has in its environment.

  Parameters
  ----------
  job : int
    The Deeploy job id.
  secret : str
    The set's secret (only searched for, never printed).
  oracle : str
    Oracle whose saved chain-store replica and IPFS repository are read.
  node : str or None
    Node of the job's app; None skips the app check.
  key : str or None
    The set's sync key, to find the app on ``node``.
  image : str
    The app's image.
  secret_len : int or None
    Expected count in ``/data/secret_len`` (65: the secret reached the container; 0: it did not); None only
    reports it.
  timeout : float
    Seconds to wait for the pointer to appear in the oracle's saved replica.
  poll : float
    Seconds between looks.

  Returns
  -------
  dict
    ``pointer`` (its type, or None), ``docs`` (per stored document: cid, readable, what the instances hold at
    the variable as "placeholder"/"other", their SECRET_PATHS, whether the secret occurs in it), the app's
    ``secret_len``, ``failures`` and ``ok``.

  Examples
  --------
  >>> custody(3001, secret, 'r1s-01', node='r1w-01', key='lnet-sync-k1', secret_len=65)['ok']
  True
  """
  # Start of the wait for the pointer.
  started = time.time()
  # The reader with the secret and the node's paths in front of it: values travel through stdin only.
  code = _with_values(CUSTODY_READER, NEEDLE=secret, CSTORE_PICKLE=CSTORE_PICKLE, IPFS_HOME=IPFS_HOME,
                      PLACEHOLDER=DAUTH_PLACEHOLDER)
  # The pointer reaches the saved replica some seconds after the operation completed.
  while True:
    # One read of the replica and of the documents the pointer names.
    found = _tagged(_exec_python(oracle, code, str(job)), 'CUSTODY')
    if (found and found['pointer']) or time.time() - started > timeout:
      break
    # Not saved yet: look again later.
    time.sleep(poll)
  # The documents read, none when there is no pointer.
  docs = found['docs'] if found and found['pointer'] else {}
  # The app's own count of the variable's bytes (written by the test app at every start).
  text = app_file(node, image, key, '/data/secret_len')['text'] if node else None
  # A count, or None when no app or file was found.
  length = int(text) if text else None
  # Reasons the custody check failed; empty means PASS.
  failures = []
  if not docs:
    # Deeploy stored no pointer for the job, the replica was not saved in time, or the read failed.
    failures.append('no DEEPLOY_DEPLOYED_JOBS pointer for job {} could be read on {} within {} s'.format(job, oracle, timeout))
  # Each stored document.
  for kind, doc in docs.items():
    if not doc['readable']:
      # Any node can read a stored job with the default key; this one could not be read so.
      failures.append('stored {} {} is not readable with the default key'.format(kind, doc['cid']))
    elif set(doc['values']) != {'placeholder'}:
      # The variable is missing, or holds something other than the placeholder.
      failures.append('stored {} holds {} at ENV.R1EN_SYNC_SECRET, not only the placeholder'.format(kind, doc['values']))
    if doc['secret_in_doc']:
      # The secret itself is in a document every node can read.
      failures.append('stored {} holds the secret'.format(kind))
  if secret_len is not None and length != secret_len:
    # The node did not deliver the secret to the app as the code version should.
    failures.append('{} app has {} bytes of R1EN_SYNC_SECRET in its environment, expected {}'.format(node, length, secret_len))
  # The whole check.
  return {
    'job': job, 'oracle': oracle, 'pointer': found['pointer'] if found else None, 'docs': docs, 'node': node,
    'secret_len': length, 'expected_secret_len': secret_len, 'waited_s': round(time.time() - started, 1),
    'failures': failures, 'ok': not failures,
  }


def custody_text(report):
  """
  A short human summary of a ``custody`` report.

  Parameters
  ----------
  report : dict
    Result of ``custody``.

  Returns
  -------
  str
    A few lines ending with ``PASS`` or ``FAIL`` and the reasons.

  Examples
  --------
  >>> print(custody_text(report).splitlines()[-1])
  PASS
  """
  # The job, where it was read, and the pointer's kind.
  lines = ['custody of job {}: pointer {} on {} (waited {} s)'.format(
    report['job'], report['pointer'], report['oracle'], report['waited_s'])]
  # One line per stored document.
  for kind, doc in report['docs'].items():
    # What it holds at the variable, its selections, and whether the secret is in it.
    lines.append('  stored {} {}: readable {}, ENV.R1EN_SYNC_SECRET {}, SECRET_PATHS {}, secret in it {}'.format(
      kind, doc['cid'], doc['readable'], doc['values'], doc['secret_paths'], doc['secret_in_doc']))
  if report['node']:
    # The app's count.
    lines.append('  {} app: {} bytes of R1EN_SYNC_SECRET in its environment (expected {})'.format(
      report['node'], report['secret_len'], report['expected_secret_len']))
  # The verdict last.
  lines.append('PASS' if report['ok'] else 'FAIL: ' + '; '.join(report['failures']))
  # One text block.
  return '\n'.join(lines)


def scan(manifest, secret):
  """
  Search every node of the localnet for a set's secret in any of its forms.

  Each node's log (``docker logs``) and every file of its cache folder (logs, plugin data, the apps'
  mounted system and data volumes, R1FS downloads, store files) are searched for each form of
  ``sync_needles``. In the chain-store replica, the records of DAUTH_JOB_SECRETS and
  DAUTH_JOB_SECRET_REVISIONS, where dAuth keeps the bundles it serves, are reported apart and are no failure.

  Parameters
  ----------
  manifest : dict
    The localnet manifest.
  secret : str
    The set's secret (never printed; only the kinds of what was found are).

  Returns
  -------
  dict
    Per node: files and bytes read, ``hits`` (file path and kinds), ``log_kinds``, ``dauth_bundle_kinds``;
    ``failures`` (one per hit, and per node that could not be read) and ``ok``.

  Examples
  --------
  >>> scan(manifest, secret)['ok']
  True
  """
  # The forms looked for.
  needles = sync_needles(secret)
  # The reader with the forms in front of it: they travel through stdin only.
  code = _with_values(SCAN_READER, NEEDLES=needles, CSTORE_PICKLE=CSTORE_PICKLE)
  # Per node results.
  nodes = {}
  # Reasons the scan failed; empty means PASS.
  failures = []
  # Every real node: seeds, oracles and workers.
  for node in manifest['nodes']:
    # The node's files.
    found = _tagged(_exec_python(node['name'], code), 'SCAN')
    # The node's log as Docker keeps it.
    text = node_log(node['name'])
    # The forms its log holds.
    log_kinds = sorted(kind for kind, needle in needles.items() if needle in text)
    if found is None:
      # A node that could not be read is no proof of absence.
      failures.append('{} could not be scanned'.format(node['name']))
      # Nothing read on it.
      found = {'files': 0, 'bytes': 0, 'hits': [], 'dauth_bundle_kinds': []}
    # The node's result.
    nodes[node['name']] = dict(found, log_kinds=log_kinds)
    # One failure per file that holds a form of the secret.
    for hit in found['hits']:
      # The path and the kinds, never the text found.
      failures.append('{}: {} in {}'.format(node['name'], ', '.join(hit['kinds']), hit['path']))
    if log_kinds:
      # The node's log holds a form of the secret.
      failures.append('{}: {} in its log'.format(node['name'], ', '.join(log_kinds)))
  # The whole scan.
  return {'nodes': nodes, 'failures': failures, 'ok': not failures}


def scan_text(report):
  """
  A short human summary of a ``scan`` report.

  Parameters
  ----------
  report : dict
    Result of ``scan``.

  Returns
  -------
  str
    One line per node, then ``PASS`` or ``FAIL`` and the reasons.

  Examples
  --------
  >>> print(scan_text(report).splitlines()[-1])
  PASS
  """
  # One line per node: what was read, what was found, and the dAuth bundle forms reported apart.
  lines = ['  {}: {} files, {:.1f} MB, hits {}, log {}, dAuth bundle records {}'.format(
    name, item['files'], item['bytes'] / 1e6, len(item['hits']), item['log_kinds'], item['dauth_bundle_kinds'])
    for name, item in report['nodes'].items()]
  # The verdict last.
  lines.append('PASS' if report['ok'] else 'FAIL: ' + '; '.join(report['failures']))
  # One text block.
  return '\n'.join(lines)


# On a node: COUNT received-history entries written into the history folder of the job's container app, as a
# consumer that has applied many archives keeps them (one file per apply, never pruned). Each entry names a
# CID no publish has, an old version, a written-at marker older than any real apply (so it is never the "last
# applied" entry), a deletion already done (so no apply tries to retire it) and the set name "seed" in its
# metadata (so the sync check, which reads one set's entries, leaves them out).
HISTORY_SEEDER = r'''
# Standard library only (-I).
import glob, json, os, sys, time
# The Deeploy job whose app gets the entries, and how many.
job, count = sys.argv[1], int(sys.argv[2])
# The app's instance folder: <pipelines data>/<job's pipeline>/<instance> (the pipeline is named after the job).
folders = glob.glob('/edge_node/_local_cache/_data/pipelines_data/lnsync{}_*/*/fixed_volumes'.format(job))
# One app per job in these scenarios; none means the app does not exist yet.
received = os.path.join(os.path.dirname(folders[0]), 'sync_history', 'received') if len(folders) == 1 else None
if received:
  # The runner creates it at its first apply; created here before that.
  os.makedirs(received, exist_ok=True)
  # Ten days before now, in nanoseconds: older than any apply of this run.
  base = time.time_ns() - 10 * 86400 * 10 ** 9
  for n in range(count):
    # An old version (a Unix time in 2001) and a CID no publish has.
    version, cid = 1000000000 + n, 'QmSEED{:040d}'.format(n)
    # The fields a received entry has: the record's CID, version and publish time, the apply time.
    entry = {'cid': cid, 'version': version, 'source_timestamp': float(version), 'applied_timestamp': float(version),
             # Another set's name, a manifest with no paths, nothing extracted.
             'node_id': 'seed', 'metadata': {'key': 'seed'}, 'manifest': {}, 'extracted_paths': [],
             # Written long ago, and already retired.
             'history_written_at_ns': base + n, 'deletion': {'deleted_at': float(version), 'deletion_succeeded': True, 'deletion_error': None}}
    # The runner's file name: 10-digit version (unique per entry), two underscores, the first 12 characters of the CID.
    with open(os.path.join(received, '{:010d}__{}.json'.format(version, cid[:12])), 'w') as fh:
      # One JSON document per file, as the runner writes it.
      json.dump(entry, fh)
# One tagged line for the host: the folder and how many entries it holds now.
print('SEEDED ' + json.dumps({'folder': received, 'files': len(os.listdir(received)) if received else 0}))'''


def seed_history(name, job, count):
  """
  Write ``count`` received-history entries into the history folder of a job's container app on a node.

  A consumer keeps one received-history file per apply and never prunes them, and every tick reads all of
  them while a record is refused. This gives an app the history of a long-lived consumer before a run.

  Parameters
  ----------
  name : str
    Node name.
  job : int
    Deeploy job id of the app (its pipeline is named after it).
  count : int
    Entries to write.

  Returns
  -------
  dict
    ``folder`` (the app's received-history folder, None when the app was not found) and ``files`` (entries in
    it after the write).

  Raises
  ------
  LocalnetError
    The app was not found, or the folder does not hold the entries afterwards.

  Examples
  --------
  >>> seed_history('r1w-02', 3002, 1000)['files']
  1000
  """
  # The node's interpreter writes the files where the runner reads them.
  report = _tagged(_exec_python(name, HISTORY_SEEDER, str(job), str(count)), 'SEEDED') or {'folder': None, 'files': 0}
  if report['folder'] is None or report['files'] < count:
    # Fail loudly: a run measured without the seeded history would measure something else.
    raise LocalnetError('history of job {} on {} could not be seeded: {}'.format(job, name, report))
  # The folder and its file count.
  return report


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
