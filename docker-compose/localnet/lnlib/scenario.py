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
    _steps(home, spec, manifest, out, phase, note, close_phase)
  except BaseException as exc:
    note('scenario failed: {}'.format(str(exc)[:300]))
    loadlib.stop(None)
    journal.close()
    raise
  close_phase()
  note('scenario finished: {}'.format(out))
  journal.close()
  return out


def _steps(home, spec, manifest, out, phase, note, close_phase):
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
  >>> _steps(home, {'name': 'x', 'steps': [{'do': 'note', 'text': 'hello'}]}, manifest, out, phase, note, close_phase)
  """
  for step in spec['steps']:
    do = step['do']
    if do == 'load':
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
      report = replicalib.compare(manifest)
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
    else:
      raise LocalnetError('unknown scenario step {}'.format(do))
  return
