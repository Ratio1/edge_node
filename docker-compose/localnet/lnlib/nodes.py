"""
Real nodes of a localnet: topology, identities, registry, environment and
compose services.

The topology follows mainnet. Four seed oracles each sit next to one broker
and hold the whole configuration in their environment, as the mainnet seeds
do in ``/var/cache/edge_node/.env``. Every other node knows only its name
and role and receives the rest from dAuth when it starts.
"""

import json
import os
import re
import time

from .common import (
  HERE, LABEL, NODE_IMAGE, PROJECT, PYTHON, LocalnetError, compose, container, ctl_exec, ip, log, sh, tool_run,
)
from .infra import BROKERS

# name, broker next to it, relay it uses (mainnet: r1s-01 / r1s-03 use relay r03, r1s-02 / r1s-04 use relay r04)
SEEDS = (
  ('r1s-01', 'emqx-a', 'relay-03'),
  ('r1s-02', 'emqx-b', 'relay-04'),
  ('r1s-03', 'emqx-c', 'relay-03'),
  ('r1s-04', 'emqx-d', 'relay-04'),
)
ORACLE_NAMES = ('r1s-db', 'r1s-ai01', 'r1s-smart', 'r1s-cap', 'r1o-09', 'r1o-10', 'r1o-11',
                'r1o-12', 'r1o-13', 'r1o-14', 'r1o-15', 'r1o-16', 'r1o-17', 'r1o-18', 'r1o-19')

# Fixed ports for the web plugins that mainnet publishes through Cloudflare tunnels. The localnet
# front (``edge``) forwards to them instead of a tunnel.
WEB_PLUGINS = {
  'DAUTH_MANAGER': 31301,
  'DEEPLOY_MANAGER_API': 31302,
  'ORACLE_API': 31303,
}
NO_TUNNEL_PLUGINS = ('NAEURAL_RELEASE_APP', 'TUNNELS_MANAGER', 'LIVENESS_API')
# Each web plugin of a node is two more processes of about 650 MB. A "headless" node runs the whole node
# (messaging, network monitor, chain store, oracle sync) without them, so that a workstation can hold a
# mainnet-sized set of chain-store peers. Requests are served by the full oracles only.
WEB_PLUGIN_SIGNATURES = ('DAUTH_MANAGER', 'DEEPLOY_MANAGER_API', 'ORACLE_API', 'NAEURAL_RELEASE_APP',
                         'TUNNELS_MANAGER', 'LIVENESS_API', 'CSTORE_MANAGER_API', 'R1FS_MANAGER_API')

# Mainnet oracles share one Cloudflare tunnel token per web plugin. A plugin refuses to start without a
# token, so the localnet supplies a marker; no tunnel is started (TUNNEL_ENGINE_ENABLED is false).
TUNNEL_TOKEN_KEYS = (
  'EE_CLOUDFLARE_TOKEN_EPOCH_MANAGER', 'EE_CLOUDFLARE_TOKEN_RELEASE_APP', 'EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER',
  'EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER', 'EE_CLOUDFLARE_TOKEN_TUNNELS_MANAGER', 'EE_CLOUDFLARE_TOKEN_LIVENESS_API',
)

PLACEHOLDER_ENV = {
  # Values mainnet keeps in the seed .env that have no service behind them here.
  'EE_GITVER': 'localnet',
  'EE_MINIO_ENDPOINT': 'minio.localnet:9000',
  'EE_MINIO_ACCESS_KEY': 'localnet',
  'EE_MINIO_SECRET_KEY': 'localnet-not-a-secret',
  'EE_MINIO_SECURE': 'false',
  'EE_MINIO_MODEL_BUCKET': 'localnet-models',
  'EE_MINIO_UPLOAD_BUCKET': 'localnet-uploads',
  'EE_NGROK_AUTH_TOKEN': '',
}


def volume(name):
  return '{}_{}_cache'.format(PROJECT, name)


def docker_volume(name):
  """
  Name of the volume that holds the inner Docker daemon's data of one node.

  Parameters
  ----------
  name : str
    Node name, for example ``r1w-01``.

  Returns
  -------
  str
    Docker volume name, labelled as a localnet volume when created, so ``down --purge`` removes it.

  Notes
  -----
  The volume keeps loaded images and container state across a recreation of the node container
  (``switch``), and puts ``/var/lib/docker`` on the host's file system, so the inner daemon can use
  overlay2 instead of an overlay on an overlay.

  Examples
  --------
  >>> docker_volume('r1w-01')
  'r1ln_r1w-01_docker'
  """
  # Same pattern as the node's data volume, so every localnet volume starts with the project name.
  return '{}_{}_docker'.format(PROJECT, name)


def plan(oracles=11, workers=2, arms=None, default_arm='new', evm_net='mainnet', full_oracles=None, full_workers=1,
         docker_nodes=(), web=None, web_of=None):
  """
  Return the list of real nodes of a localnet.

  The first ``full_oracles`` oracles (never fewer than the seeds) and the first ``full_workers`` workers
  run their web plugins; the others are headless. A node named in ``docker_nodes`` runs its own Docker
  daemon, as a production node does, so it can run container apps.

  Parameters
  ----------
  oracles : int
    Real oracle nodes; the first four are the seeds.
  workers : int
    Real nodes that are not oracles.
  arms : dict or None
    Node name -> source tree it runs; others run ``default_arm``.
  default_arm : str
    Source tree of every node not named in ``arms``.
  evm_net : str
    Network whose constants and code paths the nodes use.
  full_oracles : int or None
    Oracles that run their web plugins (None: all).
  full_workers : int
    Workers that run their web plugins.
  docker_nodes : sequence of str
    Nodes that start the inner Docker daemon (``EE_DD=1``, privileged, on the internal network only).
  web : list of str or None
    Web plugins every node with web plugins keeps (None: all of them).
  web_of : dict or None
    Node name -> list of web plugins that node keeps, overriding ``web``.

  Returns
  -------
  list of dict
    One dict per node: name, role, ip, arm, volume, and ``docker``, ``env``, ``web`` where they apply.

  Raises
  ------
  LocalnetError
    Too few or too many oracles, an unknown node or web plugin name, or a seed without dAuth.

  Examples
  --------
  >>> nodes = plan(oracles=4, workers=2, full_workers=0, docker_nodes=('r1w-01', 'r1w-02'),
  ...              web=['DAUTH_MANAGER'], web_of={'r1s-01': ['DAUTH_MANAGER', 'DEEPLOY_MANAGER_API']})
  >>> [node['name'] for node in nodes if node.get('docker')]
  ['r1w-01', 'r1w-02']
  """
  arms = arms or {}
  full_oracles = max(len(SEEDS), oracles if full_oracles is None else full_oracles)
  if oracles < len(SEEDS):
    raise LocalnetError('a localnet needs at least the {} seed oracles'.format(len(SEEDS)))
  if oracles - len(SEEDS) > len(ORACLE_NAMES):
    raise LocalnetError('at most {} oracles are supported'.format(len(SEEDS) + len(ORACLE_NAMES)))
  # Web plugin names are checked up front: a misspelt one would otherwise silently disable a plugin.
  for chosen in [web or []] + list((web_of or {}).values()):
    # Names that are not web plugins of the node.
    unknown = sorted(set(chosen) - set(WEB_PLUGIN_SIGNATURES))
    if unknown:
      # Refused, with the list of valid names.
      raise LocalnetError('unknown web plugin(s) {} (known: {})'.format(unknown, ', '.join(WEB_PLUGIN_SIGNATURES)))
  nodes = []
  for idx, (name, broker, relay) in enumerate(SEEDS):
    nodes.append({'name': name, 'role': 'seed', 'supervisor': True, 'broker': broker, 'relay': relay, 'ip': ip(51 + idx)})
  for idx, name in enumerate(ORACLE_NAMES[:oracles - len(SEEDS)]):
    nodes.append({'name': name, 'role': 'oracle', 'supervisor': True, 'ip': ip(55 + idx),
                  'headless': len(SEEDS) + idx >= full_oracles})
  for idx in range(workers):
    nodes.append({'name': 'r1w-{:02d}'.format(idx + 1), 'role': 'worker', 'supervisor': False, 'ip': ip(81 + idx),
                  'headless': idx >= full_workers})
  # The node names of this topology.
  names = {node['name'] for node in nodes}
  # A node name that is not in the topology would otherwise be ignored without a word.
  unknown = sorted((set(docker_nodes) | set(web_of or {})) - names)
  if unknown:
    # Refused, with the names this topology has.
    raise LocalnetError('unknown node name(s) {} (this topology has: {})'.format(unknown, ', '.join(sorted(names))))
  for node in nodes:
    node['arm'] = arms.get(node['name'], default_arm)
    node['evm_net'] = evm_net
    node['volume'] = volume(node['name'])
    # The web plugins this node keeps when it is not headless (absent: every web plugin, as before).
    kept = (web_of or {}).get(node['name'], web)
    if kept is not None:
      # Stored in the manifest, read by the start-up overrides and the front.
      node['web'] = list(kept)
    # A seed serves dAuth on mainnet, and "up" waits for the dAuth plugin of every seed.
    if node['role'] == 'seed' and 'DAUTH_MANAGER' not in node.get('web', ['DAUTH_MANAGER']):
      # Refused before anything is generated.
      raise LocalnetError('seed {} must keep DAUTH_MANAGER among its web plugins'.format(node['name']))
    if node['name'] in docker_nodes:
      # Read by the compose service, the volumes and every container-app command.
      node['docker'] = True
      # EE_DD=1 makes the image entrypoint start the inner Docker daemon and the node report container
      # support in its heartbeat ("did"), which Deeploy requires of a node it places a container app on.
      node['env'] = dict(node.get('env') or {}, EE_DD='1')
  return nodes


def create_identities(home, nodes):
  """Create one cache volume and one fresh key per node. Adds 'address' and 'eth_address' to each node."""
  mounts = [(HERE, '/opt/localnet', 'ro'), (home.src / nodes[0]['arm'], '/opt/r1src', 'ro')]
  for node in nodes:
    sh('docker', 'volume', 'rm', '-f', node['volume'], check=False)
    sh('docker', 'volume', 'create', '--label', LABEL + '=volume', node['volume'])
    mounts.append((node['volume'], '/nodes/{}/_local_cache'.format(node['name']), 'rw'))
  out = tool_run(
    '{} /opt/localnet/ctl/keygen.py /nodes {}'.format(PYTHON, ' '.join(node['name'] for node in nodes)),
    mounts=mounts, env={'PYTHONPATH': '/opt/r1src/sdk', 'EE_EVM_NET': nodes[0]['evm_net'], 'R1_LOCALNET': '1'},
    timeout=900,
  )
  line = [item for item in out.stdout.splitlines() if item.startswith('KEYS ')]
  if not line:
    raise LocalnetError('key generation failed:\n' + out.stdout[-2000:])
  keys = json.loads(line[-1][5:])
  for node in nodes:
    node.update(keys[node['name']])
  return nodes


FLEET_VOLUME = PROJECT + '_fleet_keys'


def create_fleet_identities(home, arm, evm_net, licensed=216, revoked=40):
  """
  Keys of the emulated part of the network: ``licensed`` ordinary nodes that only send heartbeats and
  ask dAuth for their settings, and ``revoked`` nodes that dAuth must refuse (mainnet carries such a
  list in EE_REVOKED_NODE_ADDRESSES and most dAuth requests come from nodes on it).
  """
  names = ['f{:04d}'.format(idx + 1) for idx in range(licensed)] + ['x{:04d}'.format(idx + 1) for idx in range(revoked)]
  sh('docker', 'volume', 'rm', '-f', FLEET_VOLUME, check=False)
  sh('docker', 'volume', 'create', '--label', LABEL + '=volume', FLEET_VOLUME)
  if not names:
    return []
  out = tool_run(
    '{} /opt/localnet/ctl/keygen.py /fleet {}'.format(PYTHON, ' '.join(names)),
    mounts=[(HERE, '/opt/localnet', 'ro'), (home.src / arm, '/opt/r1src', 'ro'), (FLEET_VOLUME, '/fleet', 'rw')],
    env={'PYTHONPATH': '/opt/r1src/sdk', 'EE_EVM_NET': evm_net, 'R1_LOCALNET': '1'}, timeout=1800,
  )
  line = [item for item in out.stdout.splitlines() if item.startswith('KEYS ')]
  if not line:
    raise LocalnetError('fleet key generation failed:\n' + out.stdout[-2000:])
  keys = json.loads(line[-1][5:])
  return [dict(keys[name], name=name, revoked=name.startswith('x')) for name in names]


def seed_chain_store(home, nodes, keys=3657, value_bytes=1400, legacy_jobs=30, legacy_first=101):
  """Write the same production-sized synthetic replica into every oracle's data folder (nodes must be stopped)."""
  oracles = [node for node in nodes if node['role'] in ('seed', 'oracle')]
  if keys <= 0 or not oracles:
    return None
  mounts = [(HERE, '/opt/localnet', 'ro')] + [
    (node['volume'], '/nodes/{}/_local_cache'.format(node['name']), 'rw') for node in oracles]
  out = tool_run(
    '{} -I /opt/localnet/ctl/seed_cstore.py /nodes {} {} {} {} {} {}'.format(
      PYTHON, keys, value_bytes, oracles[0]['address'], legacy_jobs, legacy_first,
      ' '.join(node['name'] for node in oracles)),
    mounts=mounts, timeout=600,
  )
  line = [item for item in out.stdout.splitlines() if item.startswith('SEEDED ')]
  if not line:
    raise LocalnetError('chain-store seeding failed:\n' + out.stdout[-2000:])
  return json.loads(line[-1][7:])


def seed_whitelists(home, nodes):
  """
  Write the complete oracle list into the allowed-senders file of every seed (nodes must be stopped).
  See ctl/seed_whitelist.py for why a first start without it is not the state of a mainnet seed.
  """
  seeds = [node for node in nodes if node['role'] == 'seed']
  oracles = [[node['address'], node['name']] for node in nodes if node['role'] in ('seed', 'oracle')]
  if not seeds:
    return None
  mounts = [(HERE, '/opt/localnet', 'ro')] + [
    (node['volume'], '/nodes/{}/_local_cache'.format(node['name']), 'rw') for node in seeds]
  out = tool_run(
    "{} -I /opt/localnet/ctl/seed_whitelist.py /nodes '{}' {}".format(
      PYTHON, json.dumps(oracles), ' '.join(node['name'] for node in seeds)),
    mounts=mounts, timeout=300,
  )
  line = [item for item in out.stdout.splitlines() if item.startswith('WHITELISTED ')]
  if not line:
    raise LocalnetError('whitelist seeding failed:\n' + out.stdout[-2000:])
  return json.loads(line[-1][12:])


def wallet(index):
  """A made-up licence owner wallet."""
  return '0x' + '{:040x}'.format(0xA11CE00000 + index)


def build_registry(nodes):
  """What ``node/chain_shim.py`` puts into the SDK's per-network tables: the localnet seed nodes."""
  return {'seed_addresses': [node['address'] for node in nodes if node['role'] == 'seed']}


def build_chain_state(nodes, fleet=None):
  """Initial state of the local blockchain (``infra/chain_rpc.py``): licences and the oracle registries."""
  state = {'nodes': {}, 'escrows': {}, 'jobs': {}, 'logs': []}
  entries = [dict(node, oracle=node['role'] in ('seed', 'oracle')) for node in nodes]
  entries += [dict(item, oracle=False) for item in (fleet or [])]
  for index, node in enumerate(entries):
    state['nodes'][node['eth_address']] = {
      'name': node['name'],
      'address': node['address'],
      'oracle': node['oracle'],
      'dauth_oracle': node['oracle'],
      'licensed': node.get('licensed', True),
      'banned': False,
      'license_id': index + 1,
      'license_type': 1,
      'owner': wallet(index // 3),  # owners hold a few licences each
    }
  return state


def _startup_overrides(node):
  """
  Localnet settings merged into the production start-up configuration of one node.

  Parameters
  ----------
  node : dict
    A node of ``plan``; reads ``headless`` and ``web``.

  Returns
  -------
  dict
    ``ADMIN_PIPELINE`` overrides (fixed web plugin ports, no tunnels, disabled web plugins) and the
    switched-off low-memory restart.

  Examples
  --------
  >>> admin = _startup_overrides({'web': ['DAUTH_MANAGER']})['ADMIN_PIPELINE']
  >>> admin['DAUTH_MANAGER'].get('DISABLED'), admin['ORACLE_API']['DISABLED']
  (None, True)
  """
  admin = {}
  for signature, port in WEB_PLUGINS.items():
    admin[signature] = {'PORT': port, 'TUNNEL_ENGINE_ENABLED': False}
  for signature in NO_TUNNEL_PLUGINS:
    admin[signature] = {'TUNNEL_ENGINE_ENABLED': False}
  # A headless node runs no web plugin; a node with a "web" list runs only the plugins on that list.
  kept = () if node.get('headless') else node.get('web')
  if kept is not None:
    for signature in WEB_PLUGIN_SIGNATURES:
      if signature not in kept:
        # Disabled in the admin pipeline: the plugin and its two processes never start.
        admin.setdefault(signature, {})['DISABLED'] = True
  return {
    'ADMIN_PIPELINE': admin,
    # A node restarts itself when the host runs low on memory. Here one host holds the whole network,
    # so that check would stop every node at once; it is switched off.
    'MIN_AVAIL_MEM_THR': -1,
    'CRITICAL_RESTART_LOW_MEM': -1,
  }


def node_env(node, manifest, secrets):
  env = {
    'R1_LOCALNET': '1',
    'EE_EVM_NET': node['evm_net'],
    'EE_DD': '0',  # no docker-in-docker: the image entrypoint then execs python as PID 1, as in production
    'EE_ID': node['name'],
    'PYTHONPATH': '/opt/r1src/sdk:/opt/r1src/core',
    'SSL_CERT_FILE': '/run/localnet/mqtt-ca.crt',
    'R1_LOCALNET_NODE': node['name'],
  }
  if node['role'] == 'seed':
    mesh, relay = manifest['mesh'], manifest['relays'][node['relay']]
    env.update(PLACEHOLDER_ENV)
    env.update({key: 'localnet-no-tunnel' for key in TUNNEL_TOKEN_KEYS})
    env.update({
      'EE_SUPERVISOR': 'true',
      'EE_TUNNEL_ENGINE': 'cloudflare',
      'EE_DAUTH_URL': 'seed_node',  # the marker mainnet seeds carry: do not ask dAuth, serve it
      'EE_REVOKED_NODE_ADDRESSES': ','.join(manifest.get('revoked_addresses') or []),
      'EE_MQTT_HOST': mesh['brokers'][node['broker']]['ip'],
      'EE_MQTT_HOST_SEED': ' '.join(mesh['brokers'][broker]['ip'] for broker in BROKERS),
      'EE_MQTT_PORT': '8883',
      'EE_MQTT_USER': secrets['mesh']['client_username'],
      'EE_MQTT': secrets['mesh']['client_password'],
      'EE_MQTT_SUBTOPIC': 'address',
      'EE_MQTT_CERT': '',
      'EE_IPFS_RELAY': relay['multiaddr'],
      'EE_IPFS_RELAY_API': relay['api'],
      'EE_IPFS_API_KEY_BASE64': secrets['relay']['relay_api_key_b64'],
      'EE_IPFS_CERTIFICATE_BASE64': relay['cert_b64'],
      'EE_SWARM_KEY_CONTENT_BASE64': secrets['relay']['swarm_key_b64'],
    })
  env.update(node.get('env') or {})
  return env


def node_startup(node):
  """
  Start-up overrides of one node: the localnet's own, then the node's ``startup`` entry (``init --startup-of``).

  ``node/launch.py`` merges the result into the production start-up file of the node's source tree, two levels
  deep: a section such as ``ADMIN_PIPELINE`` or ``CAPTURE_ENVIRONMENT`` is merged key by key, and a plugin's
  settings are added to the ones it already has. The node's entry is merged here the same way, so it adds to the
  localnet's own overrides (web plugin ports, no tunnels, disabled web plugins) instead of replacing them.

  Parameters
  ----------
  node : dict
    A node of ``plan``; reads ``headless`` and ``web`` (through ``_startup_overrides``) and ``startup``.

  Returns
  -------
  dict
    The overrides written to the node's ``node.json``: the localnet's own in sorted key order at every level (the
    order the file always had), then each plugin or setting the localnet does not override, in the order the
    node's entry gives it.

  Notes
  -----
  The order matters for the admin pipeline: the node starts the plugins named in the start-up file first, in
  that order, and then the mandatory ones it lacks. A plugin added here therefore starts earlier than it would
  otherwise, unless the plugins that precede it are listed before it too (with empty settings).

  Examples
  --------
  >>> startup = node_startup({'headless': True, 'startup': {'ADMIN_PIPELINE': {'CHAIN_STORE_BASE': {'CHAIN_STORE_DEBUG': True}}}})
  >>> startup['ADMIN_PIPELINE']['CHAIN_STORE_BASE'], startup['ADMIN_PIPELINE']['ORACLE_API']['DISABLED']
  ({'CHAIN_STORE_DEBUG': True}, True)
  """
  # The localnet's own overrides, a new dict on each call, in sorted key order at every level: node.json was
  # written with sorted keys, and launch.py adds the admin plugins in the file's order, so they start as before.
  merged = json.loads(json.dumps(_startup_overrides(node), sort_keys=True))
  # Each section or setting of the node's own entry, in its order.
  for key, value in (node.get('startup') or {}).items():
    if isinstance(value, dict) and isinstance(merged.get(key), dict):
      # Both are sections: merged key by key, as launch.py merges them into the production file.
      for sub_key, sub_value in value.items():
        if isinstance(sub_value, dict) and isinstance(merged[key].get(sub_key), dict):
          # A plugin the localnet already overrides keeps its overrides and gets these settings too.
          merged[key][sub_key] = dict(merged[key][sub_key], **sub_value)
        else:
          # A plugin or setting the localnet does not override, added after its own.
          merged[key][sub_key] = sub_value
    else:
      # A section or setting the localnet does not override.
      merged[key] = value
  # What write_node_files puts under "startup" in node.json.
  return merged


def write_node_files(home, manifest, secrets):
  """
  Write each node's environment file and ``node.json`` (name, role, source tree, start-up overrides).

  Parameters
  ----------
  home : Home
    The localnet's state folder; the files go to ``<run>/nodes/<name>/``.
  manifest : dict
    The localnet's manifest; reads ``nodes`` and what ``node_env`` reads.
  secrets : dict
    The localnet's generated secrets (broker and relay credentials of the seeds).

  Returns
  -------
  None

  Examples
  --------
  >>> write_node_files(home, home.manifest(), home.secrets())   # before "up" and after "switch"
  """
  for node in manifest['nodes']:
    ndir = home.run / 'nodes' / node['name']
    ndir.mkdir(parents=True, exist_ok=True)
    (home.run / 'out' / node['name']).mkdir(parents=True, exist_ok=True)
    env = node_env(node, manifest, secrets)
    (ndir / 'env').write_text(''.join('{}={}\n'.format(key, val) for key, val in sorted(env.items())))
    os.chmod(ndir / 'env', 0o600)
    # Keys in sorted order and no sort on writing: the same file as before for a node without a start-up entry,
    # and the entry's own order for the plugins it adds (sorting them would change the order the node starts them).
    (ndir / 'node.json').write_text(json.dumps({
      # The node's tree, name and role, written in the sorted order sort_keys gave them before.
      'arm': node['arm'], 'name': node['name'], 'role': node['role'],
      # The localnet's overrides with the node's own entry merged in (before, a shallow merge: a section of the
      # entry would have replaced the localnet's section of the same name).
      'startup': node_startup(node),
      # Indented as before; no sort_keys, which would reorder the plugins an entry adds.
    }, indent=1))
  return


def node_services(home, manifest):
  """
  Compose services of the real nodes.

  Parameters
  ----------
  home : Home
    Folder layout of the localnet.
  manifest : dict
    The localnet manifest; reads ``nodes``.

  Returns
  -------
  dict
    Service name -> compose service. A node with ``docker`` runs privileged with a private cgroup
    namespace, starts through ``node/dind.sh`` and keeps its inner Docker data in its own volume; like
    every node it is attached to the internal localnet network only and publishes no port.

  Examples
  --------
  >>> services = node_services(home, manifest)
  >>> services['r1w-01']['privileged']   # a node created with --docker-nodes r1w-01
  True
  """
  services = {}
  for node in manifest['nodes']:
    ndir = home.run / 'nodes' / node['name']
    service = {
      'image': NODE_IMAGE,
      'container_name': container(node['name']),
      'hostname': node['name'],
      'labels': {LABEL: 'node', LABEL + '.role': node['role'], LABEL + '.arm': node['arm']},
      'command': ['python3', '/opt/localnet/node/launch.py'],
      'env_file': [str(ndir / 'env')],
      'networks': {PROJECT: {'ipv4_address': node['ip']}},
      'cap_add': ['SYS_PTRACE'],  # lets a sampling profiler attach from inside the container
      'volumes': [
        '{}:/opt/localnet:ro'.format(HERE),
        '{}:/opt/r1src:ro'.format(home.src / node['arm']),
        '{}:/run/localnet/registry.json:ro'.format(home.run / 'registry.json'),
        '{}:/run/localnet/node.json:ro'.format(ndir / 'node.json'),
        '{}:/run/localnet/mqtt-ca.crt:ro'.format(home.run / 'brokers' / 'mqtt-ca.crt'),
        '{}:/out'.format(home.run / 'out' / node['name']),
        '{}:/edge_node/_local_cache'.format(node['volume']),
      ],
      'stop_grace_period': '90s',
      # Production restarts a node that exits (systemd for the seeds, the container runtime elsewhere).
      # A node that cannot get its settings from dAuth exits and tries again, as it does there.
      'restart': 'unless-stopped',
    }
    if (home.root / 'tools' / 'py-spy').exists():
      service['volumes'].append('{}:/opt/tools/py-spy:ro'.format(home.root / 'tools' / 'py-spy'))
    if node.get('cpus'):
      service['cpus'] = node['cpus']
    if node.get('cpuset'):
      service['cpuset'] = node['cpuset']
    if node.get('mem_limit'):
      service['mem_limit'] = node['mem_limit']
    if node.get('docker'):
      # Production runs the node privileged: the inner Docker daemon needs cgroups, mounts and iptables,
      # and fixed-size app volumes need losetup and mount. The container stays on the internal network.
      service['privileged'] = True
      # A private cgroup namespace keeps the inner containers inside this node's own control group.
      service['cgroup'] = 'private'
      # The guard and the cgroup set-up run before the image's own entrypoint starts the daemon.
      service['entrypoint'] = ['/bin/sh', '/opt/localnet/node/dind.sh']
      # Inner images and containers survive a recreation of the node container (rolling update).
      service['volumes'].append('{}:/var/lib/docker'.format(docker_volume(node['name'])))
    services[node['name']] = service
  return services


def node_volumes(manifest):
  """
  External volumes the compose file refers to: each node's data volume and, for a node that runs
  Docker, its inner Docker data volume.

  Parameters
  ----------
  manifest : dict
    The localnet manifest; reads ``nodes``.

  Returns
  -------
  dict
    Volume name -> ``{'external': True}`` (``init`` creates every one with the localnet label).

  Examples
  --------
  >>> sorted(node_volumes({'nodes': [{'name': 'r1w-01', 'volume': 'r1ln_r1w-01_cache', 'docker': True}]}))
  ['r1ln_r1w-01_cache', 'r1ln_r1w-01_docker']
  """
  # The data volume of every node.
  volumes = {node['volume']: {'external': True} for node in manifest['nodes']}
  # The inner Docker data volume of each node that runs Docker.
  volumes.update({docker_volume(node['name']): {'external': True} for node in manifest['nodes'] if node.get('docker')})
  # All of them, created beforehand by init.
  return volumes


def describe(nodes):
  for node in nodes:
    log('  {:<10} {:<7} {:<8} {:<5} {:<13} {}'.format(
      node['name'], node['role'], 'headless' if node.get('headless') else 'full', node['arm'], node['ip'],
      node.get('address', '')))
  return


# ---------------------------------------------------------------- start-up sequencing

ANSI = re.compile(r'\x1b\[[0-9;]*m')


def node_log(name, tail=None):
  cmd = ['docker', 'logs']
  if tail:
    cmd += ['--tail', str(tail)]
  out = sh(*cmd, container(name), check=False, timeout=120).stdout or ''
  return ANSI.sub('', out)


def wait_dauth(manifest, names, timeout=420):
  """Wait until the dAuth plugin of each named oracle accepts requests."""
  ips = [node['ip'] for node in manifest['nodes'] if node['name'] in names]
  probe = (
    "import json,sys,urllib.request\n"
    "bad=[]\n"
    "for ip in sys.argv[1:]:\n"
    "  try:\n"
    "    req=urllib.request.Request('http://%s:{port}/get_auth_data'%ip,data=b'{{\"body\":{{}}}}',headers={{'Content-Type':'application/json'}})\n"
    "    urllib.request.urlopen(req,timeout=10).read()\n"
    "  except Exception as exc:\n"
    "    bad.append(ip)\n"
    "print('BAD',' '.join(bad))\n"
  ).format(port=WEB_PLUGINS['DAUTH_MANAGER'])
  end = time.time() + timeout
  bad = ips
  while time.time() < end:
    out = ctl_exec(PYTHON, '-c', probe, *ips, check=False, timeout=120).stdout or ''
    line = [item for item in out.splitlines() if item.startswith('BAD')]
    bad = line[-1].split()[1:] if line else ips
    if not bad:
      return True
    time.sleep(5)
  raise LocalnetError('dAuth did not come up on {} within {} s'.format(bad, timeout))


def supervisor_state(name):
  """
  True / False as the node resolved its role in its current run, or None while it is not connected yet.
  Only a run that reached its broker counts: a node that could not reach dAuth exits and starts again.
  """
  text = node_log(name)
  start = text.rfind('[launch] isolation check passed')
  text = text[start:] if start >= 0 else text
  found = re.findall(r'SUPERVISOR = (True|False) \(', text)
  if not found or 'MQTT conn ok' not in text:
    return None
  return found[-1] == 'True'


def settle_oracles(home, manifest, names, timeout=600):
  """
  A node that is not a seed learns its role from dAuth. dAuth recognises an oracle only after the seeds
  have seen that node's heartbeats, so an oracle that joins a fresh network first comes up as an ordinary
  node and takes its oracle role on the next start. Restart such oracles until they have it.
  """
  oracles = [node['name'] for node in manifest['nodes'] if node['role'] == 'oracle' and node['name'] in names]
  pending = set(oracles)
  restarts = {name: 0 for name in oracles}
  seen_plain = {}
  end = time.time() + timeout
  while pending and time.time() < end:
    for name in sorted(pending):
      state = supervisor_state(name)
      if state is True:
        pending.discard(name)
        log('  {} is an oracle (after {} restart(s))'.format(name, restarts[name]))
      elif state is False:
        first = seen_plain.setdefault(name, time.time())
        if time.time() - first > 45 and restarts[name] < 4:
          restarts[name] += 1
          seen_plain.pop(name)
          # Kill, do not stop: a node that stops through its exception path is treated as offline by the
          # others for an hour, which must not be the state a test starts from.
          sh('docker', 'kill', container(name), check=False)
          sh('docker', 'start', container(name), check=False)
    time.sleep(5)
  if pending:
    raise LocalnetError('oracles without their role after {} s: {}'.format(timeout, sorted(pending)))
  return restarts
