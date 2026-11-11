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

Every phase is measured with ``metrics.collect`` when it ends; the result goes
to ``<results>/<run>/<phase>.json`` and a summary table to ``summary.txt``.
"""

import json
import time
from pathlib import Path

from . import infra, load as loadlib, metrics, profile as profilelib, replicas as replicalib
from .common import PYTHON, LocalnetError, container, ctl_exec, log, sh


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
    else:
      raise LocalnetError('unknown scenario step {}'.format(do))
  return
