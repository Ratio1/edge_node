"""
Shared infrastructure of a localnet, shaped like mainnet:

  * four EMQX brokers joined by a full mesh of MQTT bridges, rendered by the
    same code that renders the mainnet brokers (``r1infra`` from the
    ratio1-cyber-infra repository), with the mainnet session limits and the
    mainnet file-descriptor limit;
  * two private-swarm IPFS relays (Kubo, TCP only, DHT server, circuit relay
    service on) that peer with each other, each behind an nginx front that
    exposes only ``pin/add``, ``pin/rm`` and ``version`` over TLS 1.3 with
    basic auth, as built on mainnet.

Every credential, key and certificate is generated here and is throwaway.
"""

import base64
import gzip
import os
import secrets as pysecrets
import shutil
import sys
import time
from pathlib import Path

from .common import (
  EMQX_IMAGE, LABEL, NGINX_IMAGE, NODE_IMAGE, PROJECT, SUBNET, LocalnetError,
  container, ip, log, me, sh, tool_run,
)

BROKERS = ('emqx-a', 'emqx-b', 'emqx-c', 'emqx-d')
RELAYS = ('relay-03', 'relay-04')
RELAY_IP = {'relay-03': ip(23), 'relay-04': ip(24)}
CLIENT_USERNAME = 'ratio1'
RELAY_API_USER = 'r1fs'


def find_infra_repo(explicit=None):
  candidates = [explicit, os.environ.get('R1_INFRA_REPO')]
  here = Path(__file__).resolve()
  for parent in here.parents:
    candidates.append(parent / 'ratio1-cyber-infra')
  for cand in candidates:
    if cand and (Path(cand) / 'tools' / 'lib' / 'r1infra' / 'emqx_lab.py').exists():
      return Path(cand).resolve()
  return None


# ---------------------------------------------------------------- brokers

def render_brokers(home, infra_repo, overrides=None, nofile=1024):
  """Render the mainnet bridge mesh for four local brokers. Returns {'brokers': {...}, 'secrets': {...}}."""
  if infra_repo is None:
    raise LocalnetError(
      'the ratio1-cyber-infra repository is needed to render the mainnet broker mesh '
      '(pass --infra-repo or set R1_INFRA_REPO)')
  sys.path.insert(0, str(infra_repo / 'tools' / 'lib'))
  try:
    from r1infra.emqx_lab import render_lab
  finally:
    sys.path.pop(0)
  out = home.run / 'brokers'
  manifest = render_lab(out, overrides=overrides or {}, ulimit_nofile=nofile, image=EMQX_IMAGE,
                        project=PROJECT, subnet=SUBNET)
  # The lab's own compose file publishes ports on the host. Localnet publishes nothing.
  for leftover in ('compose.yml', 'lab.json'):
    (out / leftover).unlink(missing_ok=True)
  seed = container('emqx-etc-seed')
  sh('docker', 'rm', '-f', seed, check=False)
  sh('docker', 'create', '--name', seed, '--label', LABEL + '=tool', EMQX_IMAGE)
  try:
    for broker in BROKERS:
      bdir = out / broker
      if (bdir / 'etc').exists():
        shutil.rmtree(bdir / 'etc')
      sh('docker', 'cp', '{}:/opt/emqx/etc'.format(seed), str(bdir))
      for item in (bdir / 'overlay').iterdir():
        shutil.copy(item, bdir / 'etc' / item.name)
      _broker_certificate(bdir / 'etc' / 'certs', manifest['brokers'][broker]['ip'], broker)
      for sub in ('data', 'log'):
        (bdir / sub).mkdir(exist_ok=True)
        os.chmod(bdir / sub, 0o777)
  finally:
    sh('docker', 'rm', '-f', seed, check=False)
  # Nodes verify the broker certificate. On mainnet the SDK ships one self-signed certificate per broker
  # address; here the node gets the same kind of certificates as its trusted set (SSL_CERT_FILE).
  bundle = ''.join((out / broker / 'etc' / 'certs' / 'cert.pem').read_text() for broker in BROKERS)
  (out / 'mqtt-ca.crt').write_text(bundle)
  return {
    'brokers': {name: {'ip': info['ip'], 'node_name': info['node_name'], 'peers': info['peers']}
                for name, info in manifest['brokers'].items()},
    'secrets': dict(manifest['secrets'], client_username=CLIENT_USERNAME),
    'nofile': nofile,
  }


def _broker_certificate(certs_dir, address, name):
  """Self-signed certificate for the broker address, shaped like the mainnet ones (CN and SAN = address)."""
  sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
     '-keyout', certs_dir / 'key.pem', '-out', certs_dir / 'cert.pem', '-subj', '/CN={}'.format(address),
     '-addext', 'subjectAltName=DNS:{0},IP:{0},DNS:{1},DNS:{1}.local'.format(address, name),
     '-addext', 'basicConstraints=critical,CA:TRUE')
  shutil.copy(certs_dir / 'cert.pem', certs_dir / 'cacert.pem')
  os.chmod(certs_dir / 'key.pem', 0o644)  # read by the broker container user
  return


def broker_services(home, mesh):
  services = {}
  for name, info in mesh['brokers'].items():
    bdir = home.run / 'brokers' / name
    services[name] = {
      'image': EMQX_IMAGE,
      'container_name': container(name),
      'hostname': name + '.local',
      'labels': {LABEL: 'broker'},
      'environment': {'EMQX_NODE__NAME': info['node_name']},
      'ulimits': {'nofile': {'soft': mesh['nofile'], 'hard': mesh['nofile']}},
      'networks': {PROJECT: {'ipv4_address': info['ip'], 'aliases': [name + '.local']}},
      'volumes': [
        '{}:/opt/emqx/etc'.format(bdir / 'etc'),
        '{}:/opt/emqx/data'.format(bdir / 'data'),
        '{}:/opt/emqx/log'.format(bdir / 'log'),
      ],
      'stop_grace_period': '20s',
    }
  return services


# ---------------------------------------------------------------- relays

RELAY_INIT = r'''
set -eu
export IPFS_PATH=/root/.ipfs
if [ ! -f "$IPFS_PATH/config" ]; then ipfs init >/dev/null 2>&1; fi
ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
ipfs bootstrap rm --all >/dev/null
ipfs config --json Swarm.Transports.Network '{"TCP": true, "QUIC": false, "Websocket": false, "WebTransport": false, "WebRTCDirect": false}'
ipfs config --json Swarm.RelayService '{"Enabled": true, "MaxCircuits": 64, "MaxReservations": 512}'
ipfs config --json Swarm.RelayClient.Enabled false
ipfs config Routing.Type dhtserver
ipfs config --json Discovery.MDNS.Enabled false
ipfs config --json AutoTLS.Enabled false
ipfs config Datastore.StorageMax 400GB
ipfs config --json Datastore.StorageGCWatermark 90
ipfs config Datastore.GCPeriod 1h
install -m 600 /setup/swarm.key "$IPFS_PATH/swarm.key"
if [ -n "${SIBLING:-}" ]; then
  ipfs bootstrap add "$SIBLING" >/dev/null
  ipfs config --json Peering.Peers "[{\"ID\": \"${SIBLING##*/}\", \"Addrs\": [\"${SIBLING%/p2p/*}\"]}]"
fi
ipfs config Identity.PeerID
'''

NGINX_CONF = '''
worker_processes 1;
events {{ worker_connections 1024; }}
http {{
  access_log /dev/stdout;
  error_log /dev/stderr warn;
  server {{
    listen {ip}:5443 ssl http2;
    ssl_certificate     /etc/ssl/certs/r1fs_cert.crt;
    ssl_certificate_key /etc/ssl/private/r1fs_cert.key;
    ssl_protocols       TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;

    auth_basic           "IPFS Private Relay API";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_read_timeout 600s;
    location = /api/v0/pin/add {{ proxy_pass http://127.0.0.1:5001; }}
    location = /api/v0/pin/rm {{ proxy_pass http://127.0.0.1:5001; }}
    location = /api/v0/version {{ proxy_pass http://127.0.0.1:5001; }}
    location /               {{ return 403; }}
  }}
}}
'''


def _volume(name):
  return '{}_{}'.format(PROJECT, name)


def init_relays(home):
  """Create swarm key, relay identities, API certificates and credentials. Returns the relay manifest."""
  rdir = home.run / 'relays'
  rdir.mkdir(parents=True, exist_ok=True)
  swarm_key = '/key/swarm/psk/1.0.0/\n/base16/\n{}\n'.format(pysecrets.token_hex(32))
  (rdir / 'swarm.key').write_text(swarm_key)
  os.chmod(rdir / 'swarm.key', 0o600)
  api_password = pysecrets.token_urlsafe(18)
  relays = {}
  for name in RELAYS:
    one = rdir / name
    one.mkdir(exist_ok=True)
    address = RELAY_IP[name]
    # Self-signed certificate for the relay IP, as on mainnet (RSA 4096, CN and IP SAN = host IP).
    sh('openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-days', '3650',
       '-keyout', one / 'r1fs_cert.key', '-out', one / 'r1fs_cert.crt',
       '-subj', '/CN={}'.format(address), '-addext', 'subjectAltName=IP:{}'.format(address))
    os.chmod(one / 'r1fs_cert.key', 0o644)  # read by the nginx container user
    hashed = sh('openssl', 'passwd', '-apr1', api_password).stdout.strip()
    (one / 'htpasswd').write_text('{}:{}\n'.format(RELAY_API_USER, hashed))
    (one / 'nginx.conf').write_text(NGINX_CONF.format(ip=address))
    relays[name] = {'ip': address, 'volume': _volume(name + '_repo')}
  # Identities first, then each relay learns its sibling.
  for name in RELAYS:
    sh('docker', 'volume', 'rm', '-f', relays[name]['volume'], check=False)
    sh('docker', 'volume', 'create', '--label', LABEL + '=volume', relays[name]['volume'])
    out = tool_run(RELAY_INIT, mounts=[(relays[name]['volume'], '/root/.ipfs', 'rw'), (rdir, '/setup', 'ro')])
    relays[name]['peer_id'] = out.stdout.strip().splitlines()[-1]
    relays[name]['multiaddr'] = '/ip4/{}/tcp/4001/p2p/{}'.format(relays[name]['ip'], relays[name]['peer_id'])
  for name in RELAYS:
    sibling = [other for other in RELAYS if other != name][0]
    tool_run(RELAY_INIT, mounts=[(relays[name]['volume'], '/root/.ipfs', 'rw'), (rdir, '/setup', 'ro')],
             env={'SIBLING': relays[sibling]['multiaddr']})
    cert = (rdir / name / 'r1fs_cert.crt').read_bytes()
    relays[name]['api'] = 'https://{}:5443'.format(relays[name]['ip'])
    relays[name]['cert_b64'] = base64.b64encode(gzip.compress(cert)).decode()
  secrets = {
    'swarm_key_b64': base64.b64encode(swarm_key.encode()).decode(),
    'relay_api_user': RELAY_API_USER,
    'relay_api_password': api_password,
    'relay_api_key_b64': base64.b64encode('{}:{}'.format(RELAY_API_USER, api_password).encode()).decode(),
  }
  return relays, secrets


def relay_services(home, relays):
  services = {}
  for name, info in relays.items():
    one = home.run / 'relays' / name
    services[name] = {
      'image': NODE_IMAGE,
      'container_name': container(name),
      'hostname': name,
      'labels': {LABEL: 'relay'},
      'entrypoint': ['/usr/local/bin/ipfs'],
      'command': ['daemon', '--migrate', '--enable-gc'],
      'environment': {'IPFS_PATH': '/root/.ipfs', 'LIBP2P_FORCE_PNET': '1'},
      'networks': {PROJECT: {'ipv4_address': info['ip']}},
      'volumes': ['{}:/root/.ipfs'.format(info['volume'])],
      'stop_signal': 'SIGINT',
      'stop_grace_period': '20s',
    }
    services[name + '-api'] = {
      'image': NGINX_IMAGE,
      'container_name': container(name + '-api'),
      'labels': {LABEL: 'relay-api'},
      'network_mode': 'service:' + name,  # same address as the relay, like nginx on the relay host
      'depends_on': [name],
      'volumes': [
        '{}:/etc/nginx/nginx.conf:ro'.format(one / 'nginx.conf'),
        '{}:/etc/ssl/certs/r1fs_cert.crt:ro'.format(one / 'r1fs_cert.crt'),
        '{}:/etc/ssl/private/r1fs_cert.key:ro'.format(one / 'r1fs_cert.key'),
        '{}:/etc/nginx/.htpasswd:ro'.format(one / 'htpasswd'),
      ],
    }
  return services


def relay_volumes(relays):
  return {info['volume']: {'external': True} for info in relays.values()}


# ---------------------------------------------------------------- readiness

def bridge_clients(broker):
  out = sh('docker', 'exec', container(broker), 'emqx', 'ctl', 'clients', 'list', check=False, timeout=30).stdout or ''
  return sum(1 for line in out.splitlines() if 'Client(to_' in line and 'connected=true' in line)


def wait_brokers(mesh, timeout=180):
  end = time.time() + timeout
  while time.time() < end:
    ready = 0
    for broker in mesh['brokers']:
      out = sh('docker', 'exec', container(broker), 'emqx', 'ctl', 'status', check=False, timeout=30).stdout or ''
      ready += 1 if 'is started' in out else 0
    if ready == len(mesh['brokers']):
      return True
    time.sleep(2)
  raise LocalnetError('brokers did not start within {} s'.format(timeout))


def wait_bridges(mesh, timeout=180):
  expected = 4 * (len(mesh['brokers']) - 1)
  counts = {}
  end = time.time() + timeout
  while time.time() < end:
    counts = {broker: bridge_clients(broker) for broker in mesh['brokers']}
    if all(count >= expected for count in counts.values()):
      return counts
    time.sleep(3)
  log('warning: bridges not fully connected: {}'.format(counts))
  return counts


# ---------------------------------------------------------------- chain and service front

CHAIN_IP = ip(30)
EDGE_IP = ip(40)
# Public names mainnet reaches through Cloudflare; here one nginx front spreads them over the oracles.
EDGE_NAMES = {
  'dauth.localnet': 31301,
  'deeploy-api.localnet': 31302,
  'oracle.localnet': 31303,
}

EDGE_CONF_HEAD = '''
worker_processes 2;
events { worker_connections 4096; }
http {
  log_format timed '$msec $host $upstream_addr $status $request_time $upstream_response_time $request_length $bytes_sent "$request"';
  access_log /out/access.log timed;
  error_log /dev/stderr warn;
  client_max_body_size 64m;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_connect_timeout 3s;
  proxy_read_timeout 100s;   # Cloudflare gives up on an origin after 100 s
  proxy_send_timeout 100s;
  proxy_next_upstream error timeout;
'''


def chain_service(home, arm, evm_net):
  return {
    'chain': {
      'image': NODE_IMAGE,
      'container_name': container('chain'),
      'hostname': 'chain',
      'labels': {LABEL: 'chain'},
      'user': me(),
      'entrypoint': ['/opt/python/bin/python3', '-u', '/opt/localnet/infra/chain_rpc.py'],
      'environment': {
        'R1_LOCALNET': '1', 'EE_EVM_NET': evm_net, 'PYTHONDONTWRITEBYTECODE': '1',
        'R1_CHAIN_STATE': '/chain/chain.json', 'R1_LOCALNET_SDK': '/opt/r1src/sdk', 'HOME': '/tmp',
      },
      'networks': {PROJECT: {'ipv4_address': CHAIN_IP, 'aliases': ['rpc.localnet']}},
      'volumes': [
        '{}:/opt/localnet:ro'.format(Path(__file__).resolve().parent.parent),
        '{}:/opt/r1src/sdk:ro'.format(home.src / arm / 'sdk'),
        '{}:/chain'.format(home.run / 'chain'),
      ],
      'stop_grace_period': '2s',
    },
  }


def edge_service(home, nodes):
  """nginx in the role Cloudflare plays on mainnet: one public name per web plugin, spread over the oracles."""
  oracles = [node for node in nodes if node['role'] in ('seed', 'oracle') and not node.get('headless')]
  conf = [EDGE_CONF_HEAD]
  for name, port in EDGE_NAMES.items():
    upstream = name.split('.')[0].replace('-', '_')
    conf.append('  upstream {} {{\n    random;\n{}\n  }}'.format(
      upstream, '\n'.join('    server {}:{} max_fails=0;'.format(node['ip'], port) for node in oracles)))
    conf.append('  server {{ listen 80; server_name {}; location / {{ proxy_pass http://{}; }} }}'.format(name, upstream))
  conf.append('  server {{ listen 80; server_name dapp-api.localnet; location / {{ proxy_pass http://{}:8545; }} }}'.format(CHAIN_IP))
  conf.append('  server { listen 80 default_server; return 404; }\n}\n')
  edir = home.run / 'edge'
  edir.mkdir(parents=True, exist_ok=True)
  (edir / 'nginx.conf').write_text('\n'.join(conf))
  out = home.run / 'out' / 'edge'
  out.mkdir(parents=True, exist_ok=True)
  os.chmod(out, 0o777)
  return {
    'edge': {
      'image': NGINX_IMAGE,
      'container_name': container('edge'),
      'hostname': 'edge',
      'labels': {LABEL: 'edge'},
      'networks': {PROJECT: {'ipv4_address': EDGE_IP, 'aliases': list(EDGE_NAMES) + [
        'dapp-api.localnet', 'app.localnet', 'explorer.localnet', 'deeploy.localnet']}},
      'volumes': ['{}:/etc/nginx/nginx.conf:ro'.format(edir / 'nginx.conf'), '{}:/out'.format(out)],
      'stop_grace_period': '2s',
    },
  }
