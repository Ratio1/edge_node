"""
Put runs of one scenario on different code versions side by side.

``compare(home, scenario, tags)`` takes the latest run of the scenario for each
tag (the label given to ``scenario --tag``, by default the code version) and
returns a text table per phase: one row per measurement, one column per tag.
"""

import json
import re
from pathlib import Path
from statistics import median


def latest(home, scenario, tag):
  runs = sorted(Path(home.results).glob('*_{}_{}'.format(scenario, tag)))
  return runs[-1] if runs else None


def _med(values):
  values = [value for value in values if isinstance(value, (int, float))]
  return round(median(values), 2) if values else None


def _phase_rows(result, focus):
  nodes = result['nodes']
  seconds = max(1.0, result['window']['seconds'])
  seeds = [name for name, node in nodes.items() if node['role'] == 'seed']
  headless = [name for name, node in nodes.items() if node['role'] == 'oracle']
  store = lambda name: (nodes[name].get('plugins') or {}).get('CHAIN_STORE_BASE') or {}
  users = result.get('chain_store_users') or {}
  rows = []
  rows.append(('seed oracles: CPU cores used by the node process (median)', _med([nodes[name].get('cpu_cores') for name in seeds])))
  rows.append(('seed oracles: CPU cores used by the whole container (median)', _med([nodes[name].get('container_cores') for name in seeds])))
  rows.append(('seed oracles: memory of the whole container, MB (median)', _med([nodes[name].get('container_mb') for name in seeds])))
  rows.append(('other oracles: CPU cores used by the whole container (median)', _med([nodes[name].get('container_cores') for name in headless])))
  rows.append(('other oracles: memory of the whole container, MB (median)', _med([nodes[name].get('container_mb') for name in headless])))
  rows.append(('seed oracles: main loop rate, Hz (median; target 10)', _med([(nodes[name].get('log') or {}).get('main_loop_hz_p50') for name in seeds])))
  rates = sorted((store(name).get('received') or 0) / seconds for name in seeds)
  rows.append(('chain-store inputs per second: busiest seed', round(rates[-1], 2) if rates else None))
  rows.append(('chain-store inputs per second: median seed', _med(rates)))
  rows.append(('chain-store inputs per second: median other oracle', _med([(store(name).get('received') or 0) / seconds for name in headless])))
  rows.append(('chain-store inputs dropped, all nodes', sum((store(name).get('dropped') or 0) for name in nodes)))
  rows.append(('network-monitor save, seconds (p95, worst seed)', max([(nodes[name].get('log') or {}).get('netmon_save_s', {}).get('p95') or 0 for name in seeds] or [0])))
  others = [name for name in users if name != focus and nodes.get(name, {}).get('role') == 'seed']
  rows.append(('writes confirmed, other seeds', '{}/{}'.format(sum(users[n]['writes_confirmed'] for n in others), sum(users[n]['writes'] for n in others))))
  rows.append(('write confirmation, seconds, other seeds (median of p50 / worst p95)', '{} / {}'.format(
    _med([users[n]['write_s']['p50'] for n in others]), max([users[n]['write_s']['p95'] or 0 for n in others] or [0]))))
  if focus in nodes:
    mine = users.get(focus) or {}
    log = nodes[focus].get('log') or {}
    rows.append(('{}: chain-store loop rate, Hz (median)'.format(focus), store(focus).get('loop_hz_p50')))
    rows.append(('{}: chain-store queue, most inputs waiting'.format(focus), store(focus).get('queue_max')))
    if mine:
      rows.append(('{}: writes confirmed'.format(focus), '{}/{}'.format(mine['writes_confirmed'], mine['writes'])))
      rows.append(('{}: write confirmation, seconds (p50 / p95)'.format(focus), '{} / {}'.format(mine['write_s']['p50'], mine['write_s']['p95'])))
      rows.append(('{}: namespace refreshes that succeeded'.format(focus), '{}/{}'.format(mine['refresh_ok'], mine['refresh'])))
    rows.append(('{}: network-monitor save, seconds (p95)'.format(focus), (log.get('netmon_save_s') or {}).get('p95')))
    rows.append(('{}: main loop rate, Hz (median)'.format(focus), log.get('main_loop_hz_p50')))
  for key, item in sorted((result.get('front') or {}).items()):
    name = key.split(' ')[-1]
    if name in ('/get_auth_data', '/get_secrets', '/create_pipeline', '/delete_pipeline', '/reconcile_job_secrets'):
      total = sum(item['status'].values())
      rows.append(('{}: answered with 200'.format(name), '{}/{}'.format(item['status'].get('200', 0), total)))
      rows.append(('{}: seconds (p50 / p95)'.format(name), '{} / {}'.format(item['s']['p50'], item['s']['p95'])))
  probe = (result.get('dauth_probe') or {}).get('get_auth_data')
  if probe:
    rows.append(('start-up request of a licensed node: answered / sent', '{}/{}'.format(probe['ok'], probe['sent'])))
    rows.append(('start-up request: seconds when answered (p50 / p95)', '{} / {}'.format(probe['ok_s']['p50'], probe['ok_s']['p95'])))
  dauth = [(nodes[name].get('plugins') or {}).get('DAUTH_MANAGER', {}).get('loop_hz_p50') for name in seeds]
  rows.append(('dAuth plugin loop rate on seeds, Hz (median)', _med(dauth)))
  return rows


def compare(home, scenario, tags, focus='r1s-04'):
  runs = {tag: latest(home, scenario, tag) for tag in tags}
  missing = [tag for tag, run in runs.items() if run is None]
  tags = [tag for tag in tags if runs[tag] is not None]
  out = ['scenario {}: {}'.format(scenario, ', '.join('{} = {}'.format(tag, runs[tag].name) for tag in tags))]
  if missing:
    out.append('no run found for: {}'.format(', '.join(missing)))
  phases = []
  for tag in tags:
    for path in sorted(runs[tag].glob('[0-9]*_*.json')):
      if path.stem not in phases:
        phases.append(path.stem)
  for phase in sorted(phases):
    table = {}
    for tag in tags:
      path = runs[tag] / (phase + '.json')
      if not path.exists():
        continue
      for label, value in _phase_rows(json.loads(path.read_text()), focus):
        table.setdefault(label, {})[tag] = value
    width = max(len(label) for label in table) if table else 10
    out += ['', '## ' + phase, '{:<{w}}  {}'.format('', '  '.join('{:>16}'.format(tag) for tag in tags), w=width)]
    for label, values in table.items():
      out.append('{:<{w}}  {}'.format(label, '  '.join('{:>16}'.format(str(values.get(tag, '-'))) for tag in tags), w=width))
  # Deeploy operation rewrites and replica differences are reported by scenario steps, in the journal.
  for tag in tags:
    journal = runs[tag] / 'journal.txt'
    if not journal.exists():
      continue
    text = journal.read_text()
    sequences = re.findall(r'"phase": "([a-z_]+)", "recovery": ("?[a-z]*"?|null), "sequence": (\d+)', text)
    if sequences:
      out.append('')
      out.append('{}: open Deeploy operation, snapshot rewrites at each check: {}'.format(tag, ', '.join(item[2] for item in sequences)))
    for line in text.splitlines():
      if 'replicas ' in line and 'compared' in line:
        out.append('{}: {}'.format(tag, line.split(' ', 1)[1]))
  return '\n'.join(out)


CURVE = ('cores', 'main Hz', 'store Hz', 'store drop', 'writes', 'write s', 'refresh', 'dAuth Hz', 'start-up', 'p50 s', 'p95 s')


def _curve_row(result, focus):
  node = result['nodes'].get(focus) or {}
  plugins = node.get('plugins') or {}
  store = plugins.get('CHAIN_STORE_BASE') or {}
  user = (result.get('chain_store_users') or {}).get(focus) or {}
  probe = (result.get('dauth_probe') or {}).get('get_auth_data') or {}
  cores = node.get('container_cores')
  return (
    node.get('cpu_cores') if cores is None else cores,
    (node.get('log') or {}).get('main_loop_hz_p50'),
    store.get('loop_hz_p50'), store.get('dropped'),
    '{}/{}'.format(user['writes_confirmed'], user['writes']) if user else '-',
    (user.get('write_s') or {}).get('p50'),
    '{}/{}'.format(user['refresh_ok'], user['refresh']) if user else '-',
    (plugins.get('DAUTH_MANAGER') or {}).get('loop_hz_p50'),
    '{}/{}'.format(probe['ok'], probe['sent']) if probe else '-',
    (probe.get('ok_s') or {}).get('p50'), (probe.get('ok_s') or {}).get('p95'),
  )


def curve(home, scenario, tags, focus='r1s-04'):
  """One line per phase and code version for the focus node: how it degrades as a scenario squeezes it."""
  out = ['scenario {}, node {}: CPU cores used, main and chain-store loop rate, chain-store inputs dropped, writes and'.format(scenario, focus),
         'refreshes through it (confirmed/sent, median seconds), dAuth loop rate, start-up requests pinned to it (answered/sent, seconds)']
  for tag in tags:
    run = latest(home, scenario, tag)
    if run is None:
      out += ['', '{}: no run found'.format(tag)]
      continue
    out += ['', '## {} ({})'.format(tag, run.name), '{:<18}'.format('phase') + ''.join('{:>11}'.format(name) for name in CURVE)]
    for path in sorted(run.glob('[0-9]*_*.json')):
      row = _curve_row(json.loads(path.read_text()), focus)
      out.append('{:<18}'.format(path.stem) + ''.join('{:>11}'.format('-' if value is None else str(value)) for value in row))
  return '\n'.join(out)
