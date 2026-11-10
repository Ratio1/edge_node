#!/usr/bin/env python3
"""
localnet: an isolated local copy of the Ratio1 mainnet infrastructure, for
testing node changes with real node processes and no deployment.

Run ``python3 localnet.py --help``. See README.md next to this file.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lnlib import infra, load as loadlib, nodes as nodelib  # noqa: E402
from lnlib.common import (  # noqa: E402
  HERE, LABEL, NODE_IMAGE, PROJECT, PYTHON, SUBNET, Home, LocalnetError,
  compose, container, ctl_exec, die, ip, log, sh,
)

REPOS = {'core': 'naeural_core', 'edge': 'edge_node', 'sdk': 'ratio1_sdk'}


def ctl_service(home):
  return {
    'ctl': {
      'image': NODE_IMAGE,
      'container_name': container('ctl'),
      'hostname': 'ctl',
      'labels': {LABEL: 'ctl'},
      'entrypoint': ['/bin/sleep', 'infinity'],
      'init': True,
      'working_dir': '/opt/localnet',
      'environment': {
        'R1_LOCALNET': '1', 'EE_EVM_NET': 'mainnet', 'PYTHONDONTWRITEBYTECODE': '1',
        'SSL_CERT_FILE': '/run/localnet/mqtt-ca.crt',
      },
      'networks': {PROJECT: {'ipv4_address': ip(200)}},
      'volumes': [
        '{}:/opt/localnet:ro'.format(HERE),
        '{}:/run/localnet/manifest.json:ro'.format(home.manifest_path),
        '{}:/run/localnet/secrets.json:ro'.format(home.secrets_path),
        '{}:/run/localnet/registry.json:ro'.format(home.run / 'registry.json'),
        '{}:/run/localnet/mqtt-ca.crt:ro'.format(home.run / 'brokers' / 'mqtt-ca.crt'),
        '{}:/out'.format(home.run / 'out'),
      ],
      'stop_grace_period': '2s',
    },
  }


def write_compose(home, manifest):
  services = {}
  services.update(infra.broker_services(home, manifest['mesh']))
  services.update(infra.relay_services(home, manifest['relays']))
  services.update(ctl_service(home))
  services.update(infra.chain_service(home, manifest['nodes'][0]['arm'], manifest['evm_net']))
  services.update(infra.edge_service(home, manifest['nodes']))
  services.update(nodelib.node_services(home, manifest))
  volumes = {}
  volumes.update(infra.relay_volumes(manifest['relays']))
  volumes.update(nodelib.node_volumes(manifest))
  doc = {
    'name': PROJECT,
    'services': services,
    'volumes': volumes,
    'networks': {
      PROJECT: {
        'name': PROJECT,
        'internal': True,  # no route out: nothing in a localnet can reach a public network
        'labels': {LABEL: 'network'},
        'ipam': {'config': [{'subnet': SUBNET}]},
      },
    },
  }
  # Keep the machinery around the nodes (brokers, relays, chain, load generators) on its own CPUs, so
  # that it does not take CPU time from the nodes being measured.
  pools = manifest.get('cpus') or {}
  for name, service in services.items():
    is_node = service['labels'].get(LABEL) == 'node'
    pool = pools.get('nodes' if is_node else 'infra')
    if pool and 'cpuset' not in service and 'network_mode' not in service:
      service['cpuset'] = pool
  home.save(home.compose_path, doc)
  return doc


def infra_service_names(manifest):
  return list(manifest['mesh']['brokers']) + [
    name for relay in manifest['relays'] for name in (relay, relay + '-api')] + ['ctl', 'chain', 'edge']


# ---------------------------------------------------------------- commands

def cmd_stage(args):
  """Extract a git revision of the three repositories as one named source tree."""
  home = Home(args.home)
  workspace = Path(args.workspace).resolve()
  refs = {'core': args.core, 'edge': args.edge, 'sdk': args.sdk}
  for part, repo in REPOS.items():
    dest = home.src / args.name / part
    if dest.exists():
      sh('rm', '-rf', dest)
    dest.mkdir(parents=True)
    rev = sh('git', '-C', workspace / repo, 'rev-parse', '--short', refs[part]).stdout.strip()
    archive = sh('git', '-C', workspace / repo, 'archive', '--format=tar', '-o', dest.parent / (part + '.tar'), refs[part])
    sh('tar', '-xf', dest.parent / (part + '.tar'), '-C', dest)
    (dest.parent / (part + '.tar')).unlink()
    (dest / '.localnet_rev').write_text('{}@{}\n'.format(repo, rev))
    log('staged {} {} ({}) as {}/{}'.format(repo, refs[part], rev, args.name, part))
    del archive
  return 0


def cmd_init(args):
  home = Home(args.home)
  if home.compose_path.exists():
    cmd_down(args, quiet=True)
  arms = dict(item.split('=', 1) for item in (args.arm_of or []))
  for arm in set([args.arm] + list(arms.values())):
    if not (home.src / arm / 'core' / 'naeural_core').exists():
      raise LocalnetError('source tree "{}" is not staged under {} (run "stage" first)'.format(arm, home.src))
  home.run.mkdir(parents=True, exist_ok=True)
  (home.run / 'out').mkdir(exist_ok=True)
  infra_repo = infra.find_infra_repo(args.infra_repo)
  log('rendering the mainnet broker mesh (infra repo: {})'.format(infra_repo))
  mesh = infra.render_brokers(home, infra_repo, nofile=args.broker_nofile)
  log('creating relay identities, swarm key and relay API certificates')
  relays, relay_secrets = infra.init_relays(home)
  secrets = {'mesh': mesh.pop('secrets'), 'relay': relay_secrets}
  log('creating node identities')
  plan = nodelib.plan(oracles=args.oracles, workers=args.workers, arms=arms, default_arm=args.arm, evm_net=args.evm_net)
  nodelib.create_identities(home, plan)
  nodelib.describe(plan)
  log('creating {} emulated node identities ({} of them revoked)'.format(args.fleet + args.revoked, args.revoked))
  fleet = nodelib.create_fleet_identities(home, args.arm, args.evm_net, licensed=args.fleet, revoked=args.revoked)
  manifest = {
    'created': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'mesh': mesh, 'relays': relays, 'nodes': plan,
    'evm_net': args.evm_net, 'fleet': fleet,
    'cpus': {'infra': args.infra_cpus, 'nodes': args.node_cpus} if args.infra_cpus or args.node_cpus else {},
    'revoked_addresses': [item['address'] for item in fleet if item['revoked']],
  }
  home.save(home.secrets_path, secrets, private=True)
  home.save(home.manifest_path, manifest)
  home.save(home.run / 'registry.json', nodelib.build_registry(plan))
  home.save(home.run / 'chain' / 'chain.json', nodelib.build_chain_state(plan, fleet))
  nodelib.write_node_files(home, manifest, secrets)
  write_compose(home, manifest)
  log('initialised {}'.format(home.run))
  return 0


def cmd_up(args):
  home = Home(args.home)
  manifest = home.manifest()
  nodelib.write_node_files(home, manifest, home.secrets())
  write_compose(home, manifest)
  compose(home, 'up', '-d', '--no-color', *infra_service_names(manifest))
  infra.wait_brokers(manifest['mesh'])
  log(ctl_exec(PYTHON, '/opt/localnet/ctl/broker_auth.py').stdout.strip().splitlines()[-1])
  counts = infra.wait_bridges(manifest['mesh'])
  log('broker mesh up, bridge clients per broker: {}'.format(counts))
  if args.infra_only:
    return 0
  wanted = set(args.nodes or [])
  names = [node['name'] for node in manifest['nodes'] if not wanted or node['name'] in wanted]
  seeds = [node['name'] for node in manifest['nodes'] if node['role'] == 'seed' and node['name'] in names]
  others = [name for name in names if name not in seeds]
  if seeds:
    compose(home, 'up', '-d', '--no-color', *seeds)
    log('seed oracles started: {}'.format(', '.join(seeds)))
    nodelib.wait_dauth(manifest, seeds)
    log('dAuth answers on every seed')
  if others:
    compose(home, 'up', '-d', '--no-color', *others)
    log('nodes started: {}'.format(', '.join(others)))
    nodelib.settle_oracles(home, manifest, [name for name in others])
  return 0


def cmd_down(args, quiet=False):
  home = Home(args.home)
  if home.compose_path.exists():
    compose(home, 'down', '--remove-orphans', '-t', str(getattr(args, 'grace', 5)), check=False)
  leftovers = sh('docker', 'ps', '-aq', '--filter', 'label=' + LABEL, check=False).stdout.split()
  if leftovers:
    sh('docker', 'rm', '-f', *leftovers, check=False)
  loadlib.stop()
  sh('docker', 'network', 'rm', PROJECT, check=False)
  if getattr(args, 'purge', False):
    volumes = sh('docker', 'volume', 'ls', '-q', '--filter', 'label=' + LABEL, check=False).stdout.split()
    if volumes:
      sh('docker', 'volume', 'rm', '-f', *volumes, check=False)
    if home.run.exists():
      # Broker data and node output are written by container users: remove them from inside a container.
      sh('docker', 'run', '--rm', '--network', 'none', '-v', '{}:/w'.format(home.run), '--entrypoint', '/bin/sh',
         NODE_IMAGE, '-c', 'rm -rf /w/* /w/.[!.]* 2>/dev/null; true', check=False)
  if not quiet:
    log('localnet stopped{}'.format(' and purged' if getattr(args, 'purge', False) else ''))
  return 0


def cmd_status(args):
  home = Home(args.home)
  out = sh('docker', 'ps', '-a', '--filter', 'label=' + LABEL,
           '--format', '{{.Names}}\t{{.Status}}\t{{.Label "' + LABEL + '"}}', check=False).stdout
  print(out.strip() or 'no localnet containers')
  if home.manifest_path.exists():
    manifest = home.manifest()
    running = sh('docker', 'ps', '-q', '--filter', 'name=' + container('emqx-a'), check=False).stdout.strip()
    if running:
      print('bridge clients per broker:', {b: infra.bridge_clients(b) for b in manifest['mesh']['brokers']})
  return 0


def cmd_load(args):
  home = Home(args.home)
  if args.action == 'start':
    extra = [item for item in args.args if item != '--']
    name = loadlib.start(home, args.generator, extra, tag=args.tag)
    log('load generator started: {}'.format(name))
  elif args.action == 'run':
    extra = [item for item in args.args if item != '--']
    sys.stdout.write(loadlib.start(home, args.generator, extra, tag=args.tag, detach=False, timeout=args.timeout))
  elif args.action == 'stop':
    loadlib.stop(args.generator if args.generator != 'all' else None, tag=args.tag)
    log('load generator stopped: {}'.format(args.generator))
  else:
    sys.stdout.write(loadlib.logs(args.generator, tag=args.tag, tail=args.tail))
  return 0


def cmd_ctl(args):
  proc = ctl_exec(*args.cmd, check=False, timeout=args.timeout)
  sys.stdout.write(proc.stdout or '')
  return proc.returncode


def main():
  parser = argparse.ArgumentParser(prog='localnet', description=__doc__.strip().splitlines()[0])
  parser.add_argument('--home', help='state folder (default: $R1_LOCALNET_HOME or ~/.cache/r1-localnet)')
  sub = parser.add_subparsers(dest='command', required=True)

  one = sub.add_parser('stage', help='extract a revision of the three repositories as a named source tree')
  one.add_argument('name', help='name of the source tree, for example "base" or "new"')
  one.add_argument('--workspace', required=True, help='folder that holds naeural_core, edge_node and ratio1_sdk')
  one.add_argument('--core', required=True, help='git revision of naeural_core')
  one.add_argument('--edge', required=True, help='git revision of edge_node')
  one.add_argument('--sdk', required=True, help='git revision of ratio1_sdk')
  one.set_defaults(func=cmd_stage)

  one = sub.add_parser('init', help='generate keys, certificates, broker, relay and node configuration')
  one.add_argument('--infra-repo', help='path of the ratio1-cyber-infra checkout (renders the mainnet broker mesh)')
  one.add_argument('--broker-nofile', type=int, default=1024, help='broker file-descriptor limit (mainnet: 1024)')
  one.add_argument('--oracles', type=int, default=11, help='real oracle nodes, the first four are the seeds (mainnet: 11)')
  one.add_argument('--workers', type=int, default=2, help='real non-oracle nodes')
  one.add_argument('--fleet', type=int, default=216, help='emulated ordinary nodes (mainnet: about 216)')
  one.add_argument('--revoked', type=int, default=40, help='emulated nodes on the dAuth revoked list')
  one.add_argument('--infra-cpus', help='CPU list for brokers, relays, chain and load generators, for example "0,6"')
  one.add_argument('--node-cpus', help='CPU list shared by the real nodes, for example "1-5,7-11"')
  one.add_argument('--arm', default='new', help='source tree every node runs unless --arm-of says otherwise')
  one.add_argument('--arm-of', action='append', metavar='NODE=TREE', help='source tree of one node (mixed fleets)')
  one.add_argument('--evm-net', default='mainnet', choices=('mainnet', 'testnet', 'devnet'),
                   help='network whose constants and code paths the nodes use (addresses always point at the localnet)')
  one.set_defaults(func=cmd_init)

  one = sub.add_parser('up', help='start the localnet')
  one.add_argument('--infra-only', action='store_true', help='start brokers, relays and the control container only')
  one.add_argument('nodes', nargs='*', help='start only these nodes (default: all)')
  one.set_defaults(func=cmd_up)

  one = sub.add_parser('down', help='stop the localnet')
  one.add_argument('--purge', action='store_true', help='also delete volumes and generated state')
  one.add_argument('--grace', type=int, default=5, help='seconds a container gets to stop')
  one.set_defaults(func=cmd_down)

  one = sub.add_parser('status', help='show containers and mesh state')
  one.set_defaults(func=cmd_status)

  one = sub.add_parser('load', help='start, run, stop or read a load generator (see load/)')
  one.add_argument('action', choices=('start', 'run', 'stop', 'logs'))
  one.add_argument('generator', help='fleet, cstore, dauth, deeploy, probe, or "all" for stop')
  one.add_argument('--tag', help='suffix to run several instances of one generator')
  one.add_argument('--tail', type=int, default=40)
  one.add_argument('--timeout', type=float, default=3600)
  one.add_argument('args', nargs=argparse.REMAINDER, help='arguments of the generator, after --')
  one.set_defaults(func=cmd_load)

  one = sub.add_parser('ctl', help='run a command in the control container (on the isolated network)')
  one.add_argument('--timeout', type=float, default=600)
  one.add_argument('cmd', nargs=argparse.REMAINDER)
  one.set_defaults(func=cmd_ctl)

  args = parser.parse_args()
  try:
    return args.func(args)
  except LocalnetError as exc:
    die(exc)


if __name__ == '__main__':
  sys.exit(main())
