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

# apps: container apps on nodes that run their own Docker daemon (images, sync check, teardown).
from lnlib import apps as applib, compare as comparelib, infra, load as loadlib, metrics, nodes as nodelib, profile as profilelib, replicas as replicalib, scenario as scenariolib  # noqa: E402
# The statistics line reader and the request-trace watcher.
from lnlib import cstats as cstatslib, trace as tracelib  # noqa: E402
from lnlib.common import (  # noqa: E402
  HERE, LABEL, NODE_IMAGE, PROJECT, PYTHON, SUBNET, Home, LocalnetError,
  # sync_secret: a set's secret from its name, for the custody check and the scan.
  compose, container, ctl_exec, die, ip, log, sh, sync_secret,
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
  """
  Generate keys, certificates, broker, relay and node configuration of a new localnet.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``init`` (see ``main``), among them ``docker_nodes``, ``web_plugins`` and ``web_of``.

  Returns
  -------
  int
    0.

  Raises
  ------
  LocalnetError
    A source tree is not staged, or the topology options are inconsistent.

  Examples
  --------
  >>> cmd_init(parser.parse_args(['init', '--arm', 'rel', '--oracles', '4', '--docker-nodes', 'r1w-01,r1w-02']))
  0
  """
  home = Home(args.home)
  if home.compose_path.exists():
    cmd_down(args, quiet=True)
  arms = dict(item.split('=', 1) for item in (args.arm_of or []))
  for arm in set([args.arm] + list(arms.values())):
    if not (home.src / arm / 'core' / 'naeural_core').exists():
      raise LocalnetError('source tree "{}" is not staged under {} (run "stage" first)'.format(arm, home.src))
  # Comma lists of the command line: nodes that run Docker, and web plugins kept (everywhere / per node).
  docker_names = [name for name in (args.docker_nodes or '').split(',') if name]
  # None keeps every web plugin, as without the option.
  web = [name for name in args.web_plugins.split(',') if name] if args.web_plugins else None
  # NODE=SIG,SIG per --web-of.
  web_of = {item.split('=', 1)[0]: [name for name in item.split('=', 1)[1].split(',') if name] for item in (args.web_of or [])}
  home.run.mkdir(parents=True, exist_ok=True)
  (home.run / 'out').mkdir(exist_ok=True)
  # The topology is checked before anything slow is generated.
  plan = nodelib.plan(oracles=args.oracles, workers=args.workers, arms=arms, default_arm=args.arm, evm_net=args.evm_net,
                      full_oracles=args.full_oracles, full_workers=args.full_workers, docker_nodes=docker_names,
                      web=web, web_of=web_of)
  if args.probe_period:
    # Each node of the topology.
    for node in plan:
      # Every node's probe samples at this period (node/launch.py reads the variable).
      node['env'] = dict(node.get('env') or {}, R1_LOCALNET_PROBE_PERIOD=str(args.probe_period))
  infra_repo = infra.find_infra_repo(args.infra_repo)
  log('rendering the mainnet broker mesh (infra repo: {})'.format(infra_repo))
  mesh = infra.render_brokers(home, infra_repo, nofile=args.broker_nofile)
  log('creating relay identities, swarm key and relay API certificates')
  relays, relay_secrets = infra.init_relays(home)
  secrets = {'mesh': mesh.pop('secrets'), 'relay': relay_secrets}
  log('creating node identities')
  nodelib.create_identities(home, plan)
  # Empty inner Docker data volumes for the nodes that run Docker.
  made = applib.create_docker_volumes(plan)
  if made:
    # Said once, so that the privileged nodes are visible in every init log.
    log('nodes that run their own Docker daemon (privileged, internal network only): {}'.format(', '.join(docker_names)))
  nodelib.describe(plan)
  seeded = nodelib.seed_chain_store(home, plan, keys=args.cstore_keys, legacy_jobs=args.legacy_jobs)
  if seeded:
    log('chain store of every oracle seeded: {} records, {:.1f} MB, {} old-style job pointers'.format(
      seeded['keys'], seeded['bytes'] / 1e6, len(seeded['legacy_jobs'])))
  if args.empty_whitelist:
    log('seeds start with an empty list of allowed senders (first start of a new network)')
  else:
    listed = nodelib.seed_whitelists(home, plan)
    if listed:
      log('allowed senders of every seed set to the {} oracles, as on a long-running seed'.format(listed['senders']))
  log('creating {} emulated node identities ({} of them revoked)'.format(args.fleet + args.revoked, args.revoked))
  fleet = nodelib.create_fleet_identities(home, args.arm, args.evm_net, licensed=args.fleet, revoked=args.revoked)
  manifest = {
    'created': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'mesh': mesh, 'relays': relays, 'nodes': plan,
    'evm_net': args.evm_net, 'fleet': fleet, 'legacy_jobs': (seeded or {}).get('legacy_jobs', []),
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
  """
  Start the localnet: infrastructure, then the seeds, then every other node.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``up`` (``infra_only``, ``nodes``).

  Returns
  -------
  int
    0 once the seeds serve dAuth, the oracles hold their role and the inner Docker daemons answer.

  Raises
  ------
  LocalnetError
    A part did not come up in time.

  Examples
  --------
  >>> cmd_up(parser.parse_args(['up']))
  0
  """
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
  # A scenario may exec into a node right away: wait until each inner Docker daemon answers.
  waited = applib.wait_docker(manifest, names)
  if applib.docker_nodes(manifest):
    # How long the daemons took after the nodes started.
    log('inner Docker daemons answer (waited {} s)'.format(waited))
  return 0


def cmd_down(args, quiet=False):
  """
  Stop the localnet, and with ``--purge`` delete its volumes and generated state.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``down`` (``purge``, ``grace``); ``init`` passes its own.
  quiet : bool
    Do not log the final line.

  Returns
  -------
  int
    0.

  Notes
  -----
  Nodes that run Docker are killed first and the loop devices of their apps' fixed-size volumes are
  detached (``apps.release_docker``); a loop device still bound to a localnet image afterwards is
  reported, because only a privileged process can detach it.

  Examples
  --------
  >>> cmd_down(parser.parse_args(['down', '--purge']))
  0
  """
  home = Home(args.home)
  if home.manifest_path.exists():
    # Before the network goes: the release runs a throwaway container on it.
    for name, line in applib.release_docker(home.manifest()).items():
      # What was detached and what is left, per node.
      log('{}: {}'.format(name, line))
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
  # A loop device left bound to an app volume image holds host disk space until a privileged detach.
  leaked = applib.leaked_loops()
  if leaked:
    # Named with the command that frees them; the tool itself has no host privileges.
    log('loop devices left bound to container-app volume images (detach with "losetup -d" as root): {}'.format(leaked))
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


def cmd_collect(args):
  home = Home(args.home)
  end = time.time() if args.end is None else args.end
  start = end - args.last if args.start is None else args.start
  result = metrics.collect(home, start, end, logs=not args.no_logs)
  if args.out:
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True))
    log('measurements written to {}'.format(args.out))
  print(metrics.table(result))
  return 0


def cmd_profile(args):
  home = Home(args.home)
  manifest = home.manifest()
  names = args.nodes or [node['name'] for node in manifest['nodes'] if node['role'] == 'seed']
  report = profilelib.profile(names, seconds=args.seconds, rate=args.rate)
  if args.out:
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(profilelib.text(report))
  return 0


def cmd_scenario(args):
  home = Home(args.home)
  out = scenariolib.run(home, args.file, tag=args.tag)
  print((out / 'summary.txt').read_text() if (out / 'summary.txt').exists() else '')
  return 0


def cmd_replicas(args):
  """
  Compare the oracles' saved replicas, in all and per named namespace.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``replicas``: ``out`` and ``namespaces`` (a comma list, or None).

  Returns
  -------
  int
    0.

  Examples
  --------
  >>> cmd_replicas(parser.parse_args(['replicas', '--namespaces', 'DEEPLOY_OPERATIONS,DAUTH_JOB_SECRETS']))
  0
  """
  home = Home(args.home)
  # The namespaces to report apart, from the comma list.
  namespaces = [name for name in (args.namespaces or '').split(',') if name] or None
  # Totals, and per namespace when some are named.
  report = replicalib.compare(home.manifest(), namespaces=namespaces)
  if args.out:
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(replicalib.text(report))
  return 0


def cmd_cstats(args):
  """
  Print the chain store's statistics and census lines of nodes, with named namespaces.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``cstats``: ``nodes``, ``since``, ``until``, ``namespaces`` and ``out``.

  Returns
  -------
  int
    0.

  Examples
  --------
  >>> cmd_cstats(parser.parse_args(['cstats', 'r1s-db', '--since', str(time.time() - 900)]))
  0
  """
  # The localnet's folders and manifest.
  home = Home(args.home)
  # Every node of the manifest unless some are named.
  names = args.nodes or [node['name'] for node in home.manifest()['nodes']]
  # More namespaces to name, from the comma list.
  extra = [name for name in (args.namespaces or '').split(',') if name]
  # Each node's statistics and census lines in the window, with named buckets.
  report = {name: cstatslib.summary(cstatslib.node_lines(name, since=args.since, until=args.until), extra=extra)
            for name in names}
  if args.out:
    # The output's folder, made when missing.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # The full summary as JSON.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(cstatslib.text(report))
  # Done.
  return 0


def cmd_loops(args):
  """
  Print the pauses of a node's main loop and chain-store loop in a window, from its probe.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``loops``: ``node``, ``start``, ``end``, ``floor_hz``, ``window_s`` and ``out``.

  Returns
  -------
  int
    0.

  Examples
  --------
  >>> cmd_loops(parser.parse_args(['loops', 'r1s-db', '--start', str(time.time() - 900)]))
  0
  """
  # The localnet's folders, where the node's probe file is.
  home = Home(args.home)
  # The window ends now unless an end is given.
  report = metrics.loop_gaps(home, args.node, args.start, args.end or time.time(), floor_hz=args.floor_hz,
                             window_s=args.window_s)
  if args.out:
    # The output's folder, made when missing.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # The report as JSON.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(json.dumps(report, indent=1, sort_keys=True))
  # Done.
  return 0


def cmd_trace(args):
  """
  Watch every oracle's saved replica for a Deeploy request in another oracle's request trace.

  Parameters
  ----------
  args : argparse.Namespace
    Options of ``trace``: ``node``, ``endpoint``, ``since``, ``timeout`` and ``out``.

  Returns
  -------
  int
    0.

  Examples
  --------
  >>> cmd_trace(parser.parse_args(['trace', 'r1s-01', '--since', str(time.time())]))
  0
  """
  # The localnet's folders and manifest.
  home = Home(args.home)
  # Every oracle read about once a second until each shows the request answered, or the time is up.
  report = tracelib.watch(home.manifest(), args.node, args.endpoint, args.since, timeout=args.timeout)
  if args.out:
    # The output's folder, made when missing.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # The report as JSON.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(tracelib.text(report))
  # Done.
  return 0


def cmd_compare(args):
  home = Home(args.home)
  text = (comparelib.curve if args.curve else comparelib.compare)(home, args.scenario, args.tags, focus=args.focus)
  if args.out:
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text + '\n')
  print(text)
  return 0


def cmd_ctl(args):
  proc = ctl_exec(*args.cmd, check=False, timeout=args.timeout)
  sys.stdout.write(proc.stdout or '')
  return proc.returncode


def cmd_image(args):
  """
  Load an image of this machine into the inner Docker daemon of nodes, then prove they stay isolated.

  Parameters
  ----------
  args : argparse.Namespace
    ``image`` (host image), ``tag`` (name inside the nodes), ``nodes`` (default: every node with Docker).

  Returns
  -------
  int
    0 when every node passed the isolation probe, 1 otherwise.

  Examples
  --------
  >>> cmd_image(parser.parse_args(['image', 'redis:7-alpine', '--tag', 'localnet/syncapp:1']))
  0
  """
  # The running localnet's manifest.
  manifest = Home(args.home).manifest()
  # Copied from the host's image store, never pulled.
  ids = applib.load_image(manifest, args.image, args.nodes, tag=args.tag)
  # Nodes that failed the isolation probe.
  failed = 0
  # Each node the image went into.
  for name, image_id in ids.items():
    # The probe runs in a throwaway container of the image just loaded.
    report = applib.isolation(manifest, name, args.tag or args.image)
    # The image id and the probe's evidence, per node.
    log('{}: loaded {} as {} ({}); isolation {}'.format(name, args.image, args.tag or args.image, image_id[:19],
                                                        json.dumps(report, sort_keys=True)))
    # One node that reaches outside is a failure of the whole command.
    failed += 0 if report['ok'] else 1
  # Non-zero when any node reached something public.
  return 1 if failed else 0


def cmd_sync(args):
  """
  Check a container-sync set on the running localnet and print PASS or FAIL with its numbers.

  Parameters
  ----------
  args : argparse.Namespace
    ``key``, ``provider``, ``consumers``, ``refusing`` (``NODE`` or ``NODE=TEXT`` items), ``image``,
    ``publishes``, ``within``, ``timeout``, ``encryption`` (the latest record's expected format tag), ``out``.

  Returns
  -------
  int
    0 on PASS, 1 on FAIL.

  Examples
  --------
  >>> cmd_sync(parser.parse_args(['sync', 'lnet-sync-s0', 'r1w-01', 'r1w-02', '--refusing', 'r1w-04=unsupported encryption']))
  0
  """
  # The running localnet's manifest.
  manifest = Home(args.home).manifest()
  # NODE or NODE=TEXT: the consumers that must refuse, with the text their refusal line must hold.
  refusing = dict((item.split('=', 1) + [''])[:2] for item in args.refusing or [])
  # Waits for the set to converge, then measures it.
  report = applib.sync_check(manifest, args.provider, args.consumers, args.key, args.image, publishes=args.publishes,
                             # The delay bound, the wait, and the consumers that must refuse.
                             within=args.within, timeout=args.timeout, refusing=refusing,
                             # The format tag the latest record must carry (None: not checked).
                             encryption=args.encryption)
  if args.out:
    # The full report next to the summary, when asked for.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys keep two reports comparable with diff.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(applib.sync_text(report))
  # The exit code carries the verdict.
  return 0 if report['ok'] else 1


def cmd_custody(args):
  """
  Check the custody of a set's secret for one Deeploy job and print PASS or FAIL with what was found.

  Parameters
  ----------
  args : argparse.Namespace
    ``job``, ``secret`` (the set's name; the value is derived and never printed), ``oracle``, ``node``,
    ``key``, ``image``, ``secret_len``, ``timeout``, ``out``.

  Returns
  -------
  int
    0 on PASS, 1 on FAIL.

  Examples
  --------
  >>> cmd_custody(parser.parse_args(['custody', '3001', '--secret', 's1', '--node', 'r1w-01', '--key', 'k', '--secret-len', '65']))
  0
  """
  # The localnet folder: its private settings give the set's secret.
  home = Home(args.home)
  # Stored redacted in R1FS (read on the oracle), and what the app's environment holds (read on the node).
  report = applib.custody(args.job, sync_secret(home.secrets(), args.secret), args.oracle, node=args.node, key=args.key,
                          image=args.image, secret_len=args.secret_len, timeout=args.timeout)
  if args.out:
    # The full report (kinds and counts only, no secret) next to the summary, when asked for.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys keep two reports comparable with diff.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(applib.custody_text(report))
  # The exit code carries the verdict.
  return 0 if report['ok'] else 1


def cmd_scan(args):
  """
  Search every node for a set's secret in any of its forms and print PASS or FAIL with where it was found.

  Parameters
  ----------
  args : argparse.Namespace
    ``secret`` (the set's name; the value is derived and never printed), ``out``.

  Returns
  -------
  int
    0 when nothing was found, 1 otherwise.

  Examples
  --------
  >>> cmd_scan(parser.parse_args(['scan', 's1']))
  0
  """
  # The localnet folder: its manifest names the nodes, its private settings give the set's secret.
  home = Home(args.home)
  # Every node's log and cache folder.
  report = applib.scan(home.manifest(), sync_secret(home.secrets(), args.secret))
  if args.out:
    # The full report (paths and kinds only, no secret), when asked for.
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # Sorted keys keep two reports comparable with diff.
    Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True))
  print(applib.scan_text(report))
  # The exit code carries the verdict.
  return 0 if report['ok'] else 1


def cmd_switch(args):
  """
  Move one node to another staged source tree: one step of a rolling update or of a rollback.

  The node's container is recreated on the other tree with the same identity, data volume and, for a
  node that runs Docker, the same inner Docker data. By default it is stopped as an update stops it
  (SIGTERM, then the grace period); ``--kill`` ends it at once. A seed is back only once its dAuth
  answers, as ``up`` waits for it: its web plugins start some seconds after its broker connection, and a
  request sent to it in between is refused.

  Parameters
  ----------
  args : argparse.Namespace
    ``node``, ``arm`` (staged tree name), ``kill``, ``timeout``.

  Returns
  -------
  int
    0 once the node reports the new tree and is connected (a seed: and its dAuth answers).

  Raises
  ------
  LocalnetError
    Unknown node or tree, or the node (a seed: its dAuth) did not come back in time.

  Examples
  --------
  >>> cmd_switch(parser.parse_args(['switch', 'r1w-02', 'next']))
  0
  """
  # The localnet folder and its manifest.
  home = Home(args.home)
  # Changed in place and saved below.
  manifest = home.manifest()
  # The node to move.
  node = next((item for item in manifest['nodes'] if item['name'] == args.node), None)
  if node is None:
    # Refused: nothing changed yet.
    raise LocalnetError('unknown node {}'.format(args.node))
  # The tree's revision line, also what the node must report once back.
  rev_file = home.src / args.arm / 'edge' / '.localnet_rev'
  if not rev_file.exists():
    # Refused: the tree must be staged first.
    raise LocalnetError('source tree "{}" is not staged under {} (run "stage" first)'.format(args.arm, home.src))
  # The old tree is kept for the log line.
  previous, node['arm'] = node['arm'], args.arm
  # The manifest, the node's files and the compose file all name the tree the node runs.
  home.save(home.manifest_path, manifest)
  # The node's environment and start-up file follow the manifest.
  nodelib.write_node_files(home, manifest, home.secrets())
  # The compose file mounts the new tree for this node.
  write_compose(home, manifest)
  # The node's time away is measured from here.
  started = time.time()
  if args.kill:
    # The fast way out: no grace period, nothing closed by the node.
    sh('docker', 'kill', container(args.node), check=False)
  # Compose sees the changed source mount and recreates only this node (stop with its grace period, start).
  compose(home, 'up', '-d', '--no-deps', '--no-color', args.node, timeout=600)
  # Back when the node reports the new tree and its broker connection.
  took = applib.wait_source(args.node, rev_file.read_text().strip(), started, timeout=args.timeout)
  if node['role'] == 'seed':
    # A seed's web plugins (dAuth, Deeploy) answer some seconds after its broker connection; wait as "up" does.
    nodelib.wait_dauth(manifest, [args.node])
    # The time away now runs until dAuth answers.
    took = round(time.time() - started, 1)
  # Old and new tree, how the node was stopped, and its time away.
  log('{} moved from {} to {} ({}), back on the network after {} s'.format(
    args.node, previous, args.arm, 'killed' if args.kill else 'stopped', took))
  # The node runs the new tree.
  return 0


def main():
  """
  Command line of the localnet tool.

  Returns
  -------
  int
    The exit code of the command run.

  Raises
  ------
  SystemExit
    Through ``die`` (exit code 2) when a command raises ``LocalnetError``, and through argparse on a
    bad command line.

  Examples
  --------
  >>> sys.argv = ['localnet.py', '--home', '/tmp/ln', 'status']
  >>> main()
  0
  """
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
  one.add_argument('--full-oracles', type=int, default=None,
                   help='oracles that run their web plugins (about 5.4 GB each); the rest are headless (about 1 GB)')
  one.add_argument('--full-workers', type=int, default=1, help='workers that run their web plugins (about 3 GB each)')
  one.add_argument('--fleet', type=int, default=216, help='emulated ordinary nodes (mainnet: about 216)')
  one.add_argument('--revoked', type=int, default=40, help='emulated nodes on the dAuth revoked list')
  one.add_argument('--cstore-keys', type=int, default=3657,
                   help='records of the synthetic chain-store replica given to every oracle (mainnet: 3,657; 0: empty)')
  one.add_argument('--legacy-jobs', type=int, default=30,
                   help='old-style deployed-job pointers in the seeded replica (their documents are not in R1FS)')
  one.add_argument('--empty-whitelist', action='store_true',
                   help='leave the seeds\' list of allowed senders empty, as on the first start of a new network '
                        '(default: the complete oracle list, as on a long-running mainnet seed)')
  one.add_argument('--infra-cpus', help='CPU list for brokers, relays, chain and load generators, for example "0,6"')
  one.add_argument('--node-cpus', help='CPU list shared by the real nodes, for example "1-5,7-11"')
  one.add_argument('--arm', default='new', help='source tree every node runs unless --arm-of says otherwise')
  one.add_argument('--arm-of', action='append', metavar='NODE=TREE', help='source tree of one node (mixed fleets)')
  one.add_argument('--evm-net', default='mainnet', choices=('mainnet', 'testnet', 'devnet'),
                   help='network whose constants and code paths the nodes use (addresses always point at the localnet)')
  # Container apps: nodes with their own Docker daemon, as production nodes have.
  one.add_argument('--docker-nodes', metavar='NODE,NODE',
                   help='nodes that run their own Docker daemon and can run container apps (privileged, internal network only)')
  # A smaller cluster: full nodes that keep only some web plugins (each costs about 1.3 GB).
  one.add_argument('--web-plugins', metavar='SIG,SIG',
                   help='web plugins every non-headless node keeps (default: all); seeds must keep DAUTH_MANAGER')
  # Per node, repeatable; overrides --web-plugins for that node.
  one.add_argument('--web-of', action='append', metavar='NODE=SIG,SIG', help='web plugins one node keeps')
  # A shorter period resolves the pauses of a node's loops; the default is the probe's own 5 s.
  one.add_argument('--probe-period', type=float, help='seconds between two samples of the in-node probe (default 5)')
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

  one = sub.add_parser('collect', help='measure a time window of the running localnet')
  one.add_argument('--last', type=float, default=300, help='window length in seconds, ending now (default 300)')
  one.add_argument('--start', type=float, help='window start (epoch seconds)')
  one.add_argument('--end', type=float, help='window end (epoch seconds)')
  one.add_argument('--out', help='write the full measurements as JSON to this file')
  one.add_argument('--no-logs', action='store_true', help='skip the node log scan')
  one.set_defaults(func=cmd_collect)

  one = sub.add_parser('profile', help='sample which threads and functions hold the interpreter lock of running nodes')
  one.add_argument('nodes', nargs='*', help='node names (default: the seed oracles)')
  one.add_argument('--seconds', type=int, default=30)
  one.add_argument('--rate', type=int, default=20, help='samples per second')
  one.add_argument('--out', help='write the report as JSON to this file')
  one.set_defaults(func=cmd_profile)

  one = sub.add_parser('scenario', help='run a scripted experiment and measure each of its phases')
  one.add_argument('file', help='scenario JSON file (see scenarios/)')
  one.add_argument('--tag', help='label of this run in the results folder (default: the code version of the nodes)')
  one.set_defaults(func=cmd_scenario)

  one = sub.add_parser('replicas', help='compare the chain-store replicas of the oracles')
  one.add_argument('--out', help='write the comparison as JSON to this file')
  # For example the five signed namespaces.
  one.add_argument('--namespaces', metavar='NAME,NAME', help='also count per hash namespace')
  one.set_defaults(func=cmd_replicas)

  # The chain store's own statistics and census lines.
  one = sub.add_parser('cstats', help='the chain store\'s statistics and census lines of nodes, with named namespaces')
  # Every node unless some are named.
  one.add_argument('nodes', nargs='*', help='node names (default: every node)')
  # A window in epoch seconds; open on a side that is not given.
  one.add_argument('--since', type=float, help='window start (epoch seconds)')
  # The window's end.
  one.add_argument('--until', type=float, help='window end (epoch seconds)')
  # A test namespace, for example.
  one.add_argument('--namespaces', metavar='NAME,NAME', help='more namespaces to name')
  # The full summary as JSON.
  one.add_argument('--out', help='write the summary as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_cstats)

  # Pauses of a node's loops, from its probe.
  one = sub.add_parser('loops', help='pauses of a node\'s main loop and chain-store loop, from its probe')
  # The node measured.
  one.add_argument('node', help='node name')
  # The window, epoch seconds; it ends now by default.
  one.add_argument('--start', type=float, required=True, help='window start (epoch seconds)')
  # The window's end.
  one.add_argument('--end', type=float, help='window end (epoch seconds, default now)')
  # The slow-stretch rule: an average under this rate for longer than the window.
  one.add_argument('--floor-hz', type=float, default=1.0, help='lowest acceptable average loop rate')
  # The window of that rule.
  one.add_argument('--window-s', type=float, default=10.0, help='shortest stretch a rate is averaged over')
  # The report as JSON.
  one.add_argument('--out', help='write the report as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_loops)

  # When the other oracles see a request in one oracle's request trace.
  one = sub.add_parser('trace', help='time when every oracle sees a Deeploy request in another oracle\'s request trace')
  # The oracle whose Deeploy API received the request.
  one.add_argument('node', help='oracle that received the request')
  # The request's endpoint.
  one.add_argument('--endpoint', default='create_pipeline', help='endpoint of the request (default create_pipeline)')
  # The request is the first one of the endpoint received at or after this time.
  one.add_argument('--since', type=float, required=True, help='epoch seconds before the request was sent')
  # How long to keep reading.
  one.add_argument('--timeout', type=float, default=90, help='seconds to keep reading')
  # The report as JSON.
  one.add_argument('--out', help='write the report as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_trace)

  one = sub.add_parser('compare', help='put runs of one scenario on different code versions side by side')
  one.add_argument('scenario', help='scenario name, for example incident')
  one.add_argument('tags', nargs='+', help='run labels to compare, for example base new')
  one.add_argument('--focus', default='r1s-04', help='node reported in detail (default: r1s-04, the one scenarios starve)')
  one.add_argument('--curve', action='store_true', help='one line per phase for the focus node (for stepped scenarios such as resource_floor)')
  one.add_argument('--out', help='also write the tables to this file')
  one.set_defaults(func=cmd_compare)

  one = sub.add_parser('ctl', help='run a command in the control container (on the isolated network)')
  one.add_argument('--timeout', type=float, default=600)
  one.add_argument('cmd', nargs=argparse.REMAINDER)
  one.set_defaults(func=cmd_ctl)

  # Load an app image without any pull, then prove the nodes stay isolated.
  one = sub.add_parser('image', help='load an image of this machine into the Docker daemon of nodes (no pull)')
  # The source: an image the host's Docker already has.
  one.add_argument('image', help='an image of the host Docker, for example redis:7-alpine')
  # The name the apps use inside the nodes.
  one.add_argument('--tag', help='name of the image inside the nodes, for example localnet/syncapp:1')
  # Where it goes.
  one.add_argument('nodes', nargs='*', help='nodes (default: every node that runs Docker)')
  # Run by main().
  one.set_defaults(func=cmd_image)

  # Check a container-sync set.
  one = sub.add_parser('sync', help='check a container-sync set: record, applies, delays, files')
  # The set and its nodes.
  one.add_argument('key', help='the sync key of the set')
  # The provider app's node.
  one.add_argument('provider', help='node of the provider app')
  # Every consumer app's node that must apply; none when every consumer must refuse.
  one.add_argument('consumers', nargs='*', help='nodes of the consumer apps that must apply every publish')
  # Consumers that must refuse every record before any download, with the text their refusal must hold.
  one.add_argument('--refusing', action='append', metavar='NODE[=TEXT]',
                   help='a consumer node that must refuse the set\'s records (TEXT: part of its refusal reason)')
  # To find the app containers inside the nodes.
  one.add_argument('--image', default='localnet/syncapp:1', help='image of the apps')
  # The pass values: publishes expected and the delay bound.
  one.add_argument('--publishes', type=int, default=1, help='archives the provider should have published')
  # Seconds per publish (default: poll 10 s + chain-store refresh 60 s + apply).
  one.add_argument('--within', type=float, default=150, help='seconds a consumer may take per publish')
  # How long to wait before measuring anyway.
  one.add_argument('--timeout', type=float, default=900, help='seconds to wait for the set to converge')
  # The record format the code under test must publish: r1fs-set-v1 (with a 64-hex mac) or r1fs-default (none).
  one.add_argument('--encryption', choices=('r1fs-default', 'r1fs-set-v1'),
                   help='format tag the latest record must carry on the oracles (r1fs-set-v1 also needs a 64-hex mac)')
  # The full report as JSON.
  one.add_argument('--out', help='write the full report as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_sync)

  # Custody of a set's secret for one job: stored redacted in R1FS, delivered (or not) to the app.
  one = sub.add_parser('custody', help='check that a job\'s stored copy holds the dAuth placeholder, not the secret')
  # The Deeploy job.
  one.add_argument('job', type=int, help='Deeploy job id')
  # The set's name, as given to sync-app --secret.
  one.add_argument('--secret', required=True, metavar='NAME', help='name of the set\'s secret (as sync-app --secret)')
  # Where the pointer and the stored documents are read.
  one.add_argument('--oracle', default='r1s-01', help='oracle whose replica and IPFS repository are read')
  # The job's app, for its count of the variable's bytes.
  one.add_argument('--node', help='node of the job\'s app (reads /data/secret_len)')
  # To find that app among the node's apps.
  one.add_argument('--key', help='sync key of the app\'s set')
  # The apps' image.
  one.add_argument('--image', default='localnet/syncapp:1', help='image of the apps')
  # 65: the secret reached the container; 0: it did not (code that hides it).
  one.add_argument('--secret-len', type=int, help='expected count in /data/secret_len')
  # How long the pointer may take to reach the saved replica.
  one.add_argument('--timeout', type=float, default=180, help='seconds to wait for the job\'s pointer')
  # The full report as JSON.
  one.add_argument('--out', help='write the full report as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_custody)

  # Scan every node for a set's secret.
  one = sub.add_parser('scan', help='search node logs, plugin data and store files for a set\'s secret')
  # The set's name, as given to sync-app --secret.
  one.add_argument('secret', metavar='NAME', help='name of the set\'s secret (as sync-app --secret)')
  # The full report as JSON.
  one.add_argument('--out', help='write the full report as JSON to this file')
  # Run by main().
  one.set_defaults(func=cmd_scan)

  # One step of a rolling update or rollback.
  one = sub.add_parser('switch', help='recreate one node on another staged source tree (rolling update / rollback)')
  # The node to move.
  one.add_argument('node', help='node name')
  # The staged tree it moves to.
  one.add_argument('arm', help='staged source tree')
  # Default: the stop an update uses (SIGTERM, then the grace period).
  one.add_argument('--kill', action='store_true', help='kill the node instead of stopping it with its grace period')
  # How long the node may take to come back.
  one.add_argument('--timeout', type=float, default=600, help='seconds to wait for the node to come back')
  # Run by main().
  one.set_defaults(func=cmd_switch)

  args = parser.parse_args()
  try:
    return args.func(args)
  except LocalnetError as exc:
    die(exc)


if __name__ == '__main__':
  sys.exit(main())
