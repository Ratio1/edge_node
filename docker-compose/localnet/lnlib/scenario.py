"""
Run a scripted experiment on a running localnet and measure each of its phases.

A scenario is a JSON file: a name and a list of steps. The same file is run on
every code version being compared, so the versions see the same load and the
same faults at the same times.

Steps (``{"do": ..., ...}``)
----------------------------
load      start a load generator in the background: generator, args, tag
run       run a load generator to completion: generator, args, timeout
unload    stop a load generator: generator (or "all"), tag
wait      let the localnet run: seconds
phase     start a named measurement phase; the previous phase ends here
node      act on a real node: node, action = stop | start | restart | kill |
          interrupt | pause | unpause; "cpus": n limits its CPU instead
chain     change the behaviour of the local chain or dApp API: any of
          latency_ms, jitter_ms, fail, hang_s, dapp_latency_ms, dapp_hang_s
profile   sample the interpreter lock of nodes: nodes, seconds
replicas  compare the chain-store replicas of all oracles
pin       send the dAuth requests of one load generator to one oracle: generator, node
          (mainnet keeps a client on one oracle's tunnel); node null clears it
note      write a line into the run log
image     load an image of this machine into the Docker daemon of nodes: image, tag, nodes
isolation prove that nodes running Docker and their inner containers reach nothing public:
          image, nodes; a node that does fails the scenario
sync      check a container-sync set: key, provider, consumers, image, publishes, within,
          timeout, name, refusing ({node: text} of consumers that must refuse), encryption
          (format tag the latest record must carry); writes sync_<name>.json and .txt, and a
          FAIL fails the scenario
switch    recreate one node on another staged source tree (rolling update, rollback):
          node, arm, kill
custody   check that a job's stored copy holds the dAuth placeholder, not the set's secret,
          and what its app's environment holds: job, secret (name), oracle, node, key,
          secret_len; writes custody_<job>.json and .txt, and a FAIL fails the scenario
scan      search every node for a set's secret: secret (name), name; writes scan_<name>.json
          and .txt, and a finding fails the scenario
seed_history  give a job's container app the received history of a long-lived consumer: node,
          job, count (entries written into the app's history folder before the run)
mark      remember the current time under a name (``marks.json`` in the result folder); later steps
          time themselves from it
wait      with ``until`` (a mark): sleep until that mark plus ``seconds``, not ``seconds`` from now
replicas  with ``namespaces``: also count, per named hash namespace, what each oracle lacks or holds
          otherwise; the report carries the reading's epoch times
cstats    the chain store's statistics and census lines of nodes (default: every node) since a mark
          (``from``, default the scenario's start): cstats_<name>.json and .txt
loops     pauses of a node's main loop and chain-store loop since a mark (``from``), from its probe:
          loops_<name>.json; ``floor_hz`` and ``window_s`` set the slow-stretch rule (1 Hz, 10 s)
trace     wait until every oracle's saved replica holds the Deeploy request trace of ``node`` for a
          request of ``endpoint`` received after a mark (``from``): trace_<name>.json and .txt
pin       with ``client`` (a node) and ``to`` (a load generator with a fixed address, such as
          ``slowdauth``): send that node's dAuth calls through the front to that generator
held      the fields of one hash namespace (``namespace``) and some plain keys (``keys``) each node's
          saved replica holds, with their sizes (default nodes: the oracles): held_<name>.json

Every phase is measured with ``metrics.collect`` when it ends; the result goes
to ``<results>/<run>/<phase>.json`` and a summary table to ``summary.txt``.
"""

import json
# The interpreter that runs this tool, for the "switch" step's call of the tool itself.
import sys
import time
from pathlib import Path

# apps: images, isolation probe and sync check of the container-app steps.
from . import apps as applib, infra, load as loadlib, metrics, profile as profilelib, replicas as replicalib
# The statistics line reader and the request-trace watcher of the cstats and trace steps.
from . import cstats as cstatslib, trace as tracelib
# HERE: where localnet.py lives, for the "switch" step; sync_secret: a set's secret from its name (custody, scan).
from .common import HERE, PYTHON, LocalnetError, container, ctl_exec, log, sh, sync_secret


def _chain_control(settings):
  code = ("import json,sys,urllib.request\n"
          "req=urllib.request.Request('http://rpc.localnet:8545/_control',data=sys.argv[1].encode(),"
          "headers={'Content-Type':'application/json'})\n"
          "print(urllib.request.urlopen(req,timeout=10).read().decode())\n")
  return ctl_exec(PYTHON, '-c', code, json.dumps(settings), check=False, timeout=60).stdout


def _node(step):
  name = container(step['node'])
  if 'cpus' in step:
    sh('docker', 'update', '--cpus', str(step['cpus']), name)
    return 'cpu limit {}'.format(step['cpus'])
  action = step['action']
  if action == 'stop':
    sh('docker', 'stop', '-t', str(step.get('grace', 90)), name, timeout=300)
  elif action == 'kill':
    sh('docker', 'kill', name)
  elif action == 'interrupt':
    # SIGINT: the node leaves through its exception path, as it does after an error in its main loop.
    sh('docker', 'kill', '-s', 'INT', name)
  elif action == 'start':
    sh('docker', 'start', name)
  elif action == 'restart':
    sh('docker', 'restart', '-t', str(step.get('grace', 90)), name, timeout=300)
  elif action in ('pause', 'unpause'):
    sh('docker', action, name)
  else:
    raise LocalnetError('unknown node action {}'.format(action))
  return action


def run(home, path, tag=None):
  """
  Run one scenario file on the running localnet and keep its results.

  Parameters
  ----------
  home : Home
    Folder layout of the localnet.
  path : str or Path
    The scenario JSON file.
  tag : str, optional
    Label of the run in its result folder's name (default: the code versions of the nodes).

  Returns
  -------
  Path
    The result folder ``<home>/results/<time>_<scenario>_<tag>/``.

  Raises
  ------
  LocalnetError
    When a node is not running at the start, or a step fails (the run's journal says which).

  Examples
  --------
  >>> run(home, 'docker-compose/localnet/scenarios/restart.json', tag='next')
  PosixPath('.../results/20261115T030000_restart_next')
  """
  spec = json.loads(Path(path).read_text())
  manifest = home.manifest()
  arms = sorted({node['arm'] for node in manifest['nodes']})
  run_name = '{}_{}_{}'.format(time.strftime('%Y%m%dT%H%M%S'), spec['name'], tag or '+'.join(arms))
  out = home.results / run_name
  out.mkdir(parents=True, exist_ok=True)
  (out / 'scenario.json').write_text(json.dumps(spec, indent=1))
  (out / 'manifest.json').write_text(json.dumps(
    {key: val for key, val in manifest.items() if key not in ('fleet',)}, indent=1, sort_keys=True))
  journal = open(out / 'journal.txt', 'at', buffering=1)

  def note(msg):
    log(msg)
    journal.write('{} {}\n'.format(time.strftime('%H:%M:%S'), msg))
    return

  phase = {'name': None, 'start': None}
  summary = []

  def close_phase():
    if phase['name'] is None:
      return
    end = time.time()
    result = metrics.collect(home, phase['start'], end)
    (out / (phase['name'] + '.json')).write_text(json.dumps(result, indent=1, sort_keys=True))
    text = '## {} ({} s)\n{}\n'.format(phase['name'], round(end - phase['start']), metrics.table(result))
    summary.append(text)
    (out / 'summary.txt').write_text('\n'.join(summary))
    note('phase {} measured'.format(phase['name']))
    phase['name'] = None
    return

  note('scenario {} on code {} -> {}'.format(spec['name'], arms, out))
  # A scenario that stops or kills nodes leaves the cluster changed: start each one on a cluster where all nodes run.
  down = [node['name'] for node in manifest['nodes']
          if sh('docker', 'inspect', '-f', '{{.State.Running}}', container(node['name']), check=False).stdout.strip() != 'true']
  if down:
    note('scenario not started: nodes not running: {}'.format(', '.join(down)))
    journal.close()
    raise LocalnetError('scenario {} needs every node running; not running: {} (start them or initialise the cluster again)'.format(
      spec['name'], ', '.join(down)))
  try:
    # Named times of the run; "scenario" is its start, the default "from" of the steps that read since a mark.
    _steps(home, spec, manifest, out, phase, note, close_phase, {'scenario': time.time()})
  except BaseException as exc:
    note('scenario failed: {}'.format(str(exc)[:300]))
    loadlib.stop(None)
    journal.close()
    raise
  close_phase()
  note('scenario finished: {}'.format(out))
  journal.close()
  return out


def _steps(home, spec, manifest, out, phase, note, close_phase, marks):
  """
  Run the steps of a scenario in order (see the module docstring for the step types).

  Parameters
  ----------
  home : Home
    Folder layout of the localnet.
  spec : dict
    The scenario: ``name`` and ``steps``.
  manifest : dict
    The localnet manifest when the scenario started.
  out : Path
    Result folder of this run.
  phase : dict
    The open measurement phase (``name``, ``start``), shared with ``run``.
  note : callable
    Writes a line to the log and the run journal.
  close_phase : callable
    Measures and closes the open phase.
  marks : dict
    Mark name -> epoch seconds; ``mark`` steps add to it and it is kept as ``marks.json``.

  Returns
  -------
  None

  Raises
  ------
  LocalnetError
    An unknown step, a node that is not isolated, or a container-sync, custody or secret-scan check that
    failed.

  Examples
  --------
  >>> _steps(home, {'name': 'x', 'steps': [{'do': 'note', 'text': 'hello'}]}, manifest, out, phase, note, close_phase,
  ...        {'scenario': time.time()})
  """
  for step in spec['steps']:
    do = step['do']
    if do == 'mark':
      # The time a later step counts from, kept with the run in epoch seconds.
      marks[step['name']] = time.time()
      # Every mark so far, kept with the run.
      (out / 'marks.json').write_text(json.dumps(marks, indent=1, sort_keys=True))
      # The mark in the run journal too.
      note('mark {} at {:.3f}'.format(step['name'], marks[step['name']]))
    elif do == 'wait' and 'until' in step:
      # Sleep to a fixed time after a mark, so a reading lands at its intended second whatever came before it.
      left = marks[step['until']] + step['seconds'] - time.time()
      # The wait in the run journal.
      note('waiting until {} + {} s ({:.1f} s from now)'.format(step['until'], step['seconds'], left))
      # A time already past is not waited for.
      time.sleep(max(0.0, left))
    elif do == 'cstats':
      # Names the report files.
      label = step.get('name') or 'cstats'
      # Every node unless the step names some.
      names = step.get('nodes') or [node['name'] for node in manifest['nodes']]
      # Each node's statistics and census lines since the mark, with named buckets.
      report = {name: cstatslib.summary(cstatslib.node_lines(name, since=marks[step.get('from', 'scenario')]),
                                        extra=step.get('namespaces') or ()) for name in names}
      # The full summary, kept with the run.
      (out / 'cstats_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The readable view next to it.
      (out / 'cstats_{}.txt'.format(label)).write_text(cstatslib.text(report) + '\n')
      # How many lines were read, in the run journal.
      note('cstats {}: {} statistics lines from {} nodes'.format(label, sum(len(item['lines']) for item in report.values()),
                                                              len(report)))
    elif do == 'loops':
      # Names the report file.
      label = step.get('name') or step['node']
      # Pauses of the node's main loop and chain-store loop since the mark, from its probe file.
      report = metrics.loop_gaps(home, step['node'], marks[step.get('from', 'scenario')], time.time(),
                                 floor_hz=step.get('floor_hz', 1.0), window_s=step.get('window_s', 10.0))
      # Kept with the run.
      (out / 'loops_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The figures in the run journal too.
      note('loops {}: {}'.format(label, json.dumps(report, sort_keys=True)[:600]))
    elif do == 'trace':
      # Names the report files.
      label = step.get('name') or 'trace'
      # Polls every oracle until each holds the request, answered, or the time is up.
      report = tracelib.watch(manifest, step['node'], step.get('endpoint', 'create_pipeline'), marks[step['from']],
                              timeout=step.get('timeout', 90), period=step.get('period', 1.0))
      # The full report, kept with the run.
      (out / 'trace_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The readable view next to it.
      (out / 'trace_{}.txt'.format(label)).write_text(tracelib.text(report) + '\n')
      # Each line of the view.
      for line in tracelib.text(report).splitlines():
        # The delays per oracle in the run journal.
        note('trace {}: {}'.format(label, line))
    elif do == 'held':
      # Names the report file.
      label = step.get('name') or 'held'
      # Every oracle unless the step names nodes (a worker's own replica, for example).
      names = step.get('nodes') or [node['name'] for node in manifest['nodes'] if node['role'] in ('seed', 'oracle')]
      # The namespace's fields and the plain keys each node's saved replica holds.
      report = replicalib.held(names, step.get('namespace'), step.get('keys') or ())
      # Kept with the run.
      (out / 'held_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # Each node's holdings.
      for name, item in report.items():
        # Fields and plain keys each node holds, with their sizes.
        note('held {}: {} {}'.format(label, name, json.dumps(item, sort_keys=True)))
    elif do == 'pin' and 'client' in step:
      # A node's dAuth calls to a load generator's fixed address (the relay listens on dAuth's port), or back.
      target = '{}:31301'.format(loadlib.ADDRESS[step['to']]) if step.get('to') else None
      # The node's address on the localnet network, which the front sees as the client.
      client_ip = next(node['ip'] for node in manifest['nodes'] if node['name'] == step['client'])
      # One pin, or none when the target is cleared.
      infra.pin_dauth(home, client_ip if target else None, address=target)
      # The change in the run journal.
      note('dAuth calls of {} go to {}'.format(step['client'], step.get('to') or 'any oracle'))
    elif do == 'load':
      loadlib.start(home, step['generator'], step.get('args', []), tag=step.get('tag'))
      note('load {} started {}'.format(step['generator'], ' '.join(str(a) for a in step.get('args', []))))
    elif do == 'run':
      text = loadlib.start(home, step['generator'], step.get('args', []), tag=step.get('tag') or 'run', detach=False,
                           timeout=step.get('timeout', 900))
      lines = [line for line in (text or '').splitlines() if line.startswith('{')]
      note('run {} {}: {}'.format(step['generator'], ' '.join(str(a) for a in step.get('args', [])),
                                  (lines[-1] if lines else (text or '').strip()[-300:])[:600]))
    elif do == 'unload':
      loadlib.stop(None if step.get('generator', 'all') == 'all' else step['generator'], tag=step.get('tag'))
      note('load {} stopped'.format(step.get('generator', 'all')))
    elif do == 'wait':
      note('waiting {} s'.format(step['seconds']))
      time.sleep(step['seconds'])
    elif do == 'phase':
      close_phase()
      phase.update(name=step['name'], start=time.time())
      note('phase {} begins'.format(step['name']))
    elif do == 'node':
      note('node {}: {}'.format(step['node'], _node(step)))
    elif do == 'chain':
      settings = {key: val for key, val in step.items() if key != 'do'}
      note('chain control {} -> {}'.format(settings, (_chain_control(settings) or '').strip()[:200]))
    elif do == 'profile':
      names = step.get('nodes') or [node['name'] for node in manifest['nodes'] if node['role'] == 'seed']
      report = profilelib.profile(names, seconds=step.get('seconds', 30), rate=step.get('rate', 20))
      label = step.get('name') or (phase['name'] or 'profile')
      (out / ('profile_' + label + '.json')).write_text(json.dumps(report, indent=1, sort_keys=True))
      (out / ('profile_' + label + '.txt')).write_text(profilelib.text(report))
      note('profile {} taken'.format(label))
    elif do == 'pin':
      infra.pin_dauth(home, loadlib.ADDRESS[step['generator']] if step.get('node') else None, step.get('node'))
      note('dAuth requests of {} go to {}'.format(step['generator'], step.get('node') or 'any oracle'))
    elif do == 'replicas':
      # Totals, and per namespace when the step names some.
      report = replicalib.compare(manifest, namespaces=step.get('namespaces'))
      label = step.get('name') or (phase['name'] or 'replicas')
      (out / ('replicas_' + label + '.json')).write_text(json.dumps(report, indent=1, sort_keys=True))
      (out / ('replicas_' + label + '.txt')).write_text(replicalib.text(report))
      worst = max((item.get('missing', 0) + item.get('different', 0) for item in report['nodes'].values()), default=0)
      note('replicas {} compared: at most {} records missing or different on one oracle'.format(label, worst))
    elif do == 'note':
      note(step['text'])
    elif do == 'image':
      # From the host's image store into each node's inner daemon: no registry, no pull.
      ids = applib.load_image(manifest, step['image'], step.get('nodes'), tag=step.get('tag'))
      # Which image went where, in the run journal.
      note('image {} loaded as {} into {}'.format(step['image'], step.get('tag') or step['image'], ', '.join(ids)))
    elif do == 'isolation':
      # Every named node, or every node that runs Docker.
      for name in step.get('nodes') or applib.docker_nodes(manifest):
        # Probe from a throwaway inner container of the given image.
        report = applib.isolation(manifest, name, step['image'])
        # Kept with the run as evidence.
        (out / 'isolation_{}.json'.format(name)).write_text(json.dumps(report, indent=1, sort_keys=True))
        # The verdict and its evidence in the run journal.
        note('isolation {}: {}'.format(name, json.dumps(report, sort_keys=True)))
        # A node or inner container that reaches anything public ends the scenario at once.
        if not report['ok']:
          # Stops here: nothing else runs on a cluster that reaches outside.
          raise LocalnetError('node {} or its inner containers are not isolated: {}'.format(name, report))
    elif do == 'sync':
      # Names the report files, for scenarios with several checks.
      label = step.get('name') or 'sync'
      # Waits for the set to converge, then measures it.
      # Consumers that must refuse, with the text of their refusal, are optional.
      report = applib.sync_check(manifest, step['provider'], step['consumers'], step['key'],
                                 step.get('image', 'localnet/syncapp:1'), publishes=step.get('publishes', 1),
                                 # The delay bound and the wait, as before.
                                 within=step.get('within', 150), timeout=step.get('timeout', 900),
                                 # None when the step names no refusing consumer.
                                 refusing=step.get('refusing'),
                                 # The latest record's expected format tag; None when the step names none.
                                 encryption=step.get('encryption'))
      # The full report, kept with the run.
      (out / 'sync_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The short summary next to it.
      (out / 'sync_{}.txt'.format(label)).write_text(applib.sync_text(report) + '\n')
      # The summary also goes into the run journal, one line at a time.
      for line in applib.sync_text(report).splitlines():
        # Prefixed with the check's name.
        note('sync {}: {}'.format(label, line))
      # A failed check fails the scenario (exit code 2), after its report is written.
      if not report['ok']:
        # The reasons become the scenario's error message.
        raise LocalnetError('sync check {} failed: {}'.format(label, '; '.join(report['failures'])))
    elif do == 'switch':
      # The tool's own "switch" command: it rewrites the manifest and compose file and recreates the node.
      cmd = [sys.executable, str(HERE / 'localnet.py'), '--home', str(home.root), 'switch', step['node'], step['arm']]
      # Runs until the node is back on the new tree; a failure raises and ends the scenario.
      proc = sh(*(cmd + (['--kill'] if step.get('kill') else [])), timeout=900)
      # The command's own last line: trees, stop kind and time away.
      note('switch {}'.format((proc.stdout or '').strip().splitlines()[-1]))
    elif do == 'custody':
      # Stored redacted in R1FS (read on the oracle), and what the job's app environment holds.
      report = applib.custody(step['job'], sync_secret(home.secrets(), step['secret']), step.get('oracle', 'r1s-01'),
                              node=step.get('node'), key=step.get('key'), image=step.get('image', 'localnet/syncapp:1'),
                              secret_len=step.get('secret_len'), timeout=step.get('timeout', 180))
      # The full report (kinds and counts only, no secret), kept with the run.
      (out / 'custody_{}.json'.format(step['job'])).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The short summary next to it.
      (out / 'custody_{}.txt'.format(step['job'])).write_text(applib.custody_text(report) + '\n')
      # The summary also goes into the run journal, one line at a time.
      for line in applib.custody_text(report).splitlines():
        # Prefixed with the job.
        note('custody {}: {}'.format(step['job'], line))
      # A failed check fails the scenario (exit code 2), after its report is written.
      if not report['ok']:
        # The reasons become the scenario's error message.
        raise LocalnetError('custody check of job {} failed: {}'.format(step['job'], '; '.join(report['failures'])))
    elif do == 'scan':
      # Names the report files, for scenarios with several scans.
      label = step.get('name') or 'scan'
      # Every node's log and cache folder.
      report = applib.scan(manifest, sync_secret(home.secrets(), step['secret']))
      # The full report (paths and kinds only, no secret), kept with the run.
      (out / 'scan_{}.json'.format(label)).write_text(json.dumps(report, indent=1, sort_keys=True))
      # The short summary next to it.
      (out / 'scan_{}.txt'.format(label)).write_text(applib.scan_text(report) + '\n')
      # The summary also goes into the run journal, one line at a time.
      for line in applib.scan_text(report).splitlines():
        # Prefixed with the scan's name.
        note('scan {}: {}'.format(label, line))
      # A finding fails the scenario (exit code 2), after its report is written.
      if not report['ok']:
        # The findings become the scenario's error message.
        raise LocalnetError('secret scan {} failed: {}'.format(label, '; '.join(report['failures'])))
    elif do == 'seed_history':
      # The app's folder and its file count afterwards; a failed seed raises and ends the scenario.
      report = applib.seed_history(step['node'], step['job'], step['count'])
      # What was written, in the run journal.
      note('seed_history {} job {}: {} files in {}'.format(step['node'], step['job'], report['files'], report['folder']))
    else:
      raise LocalnetError('unknown scenario step {}'.format(do))
  return
