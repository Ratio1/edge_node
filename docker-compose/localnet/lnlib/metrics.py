"""
Measurements of a localnet run over a time window.

Everything is measured the same way for every code version:

  * the in-process sampler of each node (``node/probe.py``): inputs received,
    handled and dropped per plugin, queue depth, loop rate, CPU time, memory;
  * the load generators' own records: what a user of the chain store and of
    dAuth saw (confirmed writes, replication delay, refreshes, refusals);
  * the service front's access log: status and duration of every dAuth and
    Deeploy request;
  * the brokers' counters and the local chain's call counters;
  * a few log lines that exist in every code version (main loop rate, queue
    overflow warnings, snapshot save times).
"""

import json
import re
import time
from datetime import datetime, timezone

from .common import container, ctl_exec, sh, PYTHON

KEY_PLUGINS = ('CHAIN_STORE_BASE', 'NET_MON_01', 'NET_CONFIG_MONITOR', 'ORACLE_SYNC_01', 'DAUTH_MANAGER',
               'DEEPLOY_MANAGER_API', 'CSTORE_MANAGER_API', 'R1FS_MANAGER_API', 'CHAIN_DIST_MONITOR')
ANSI = re.compile(r'\x1b\[[0-9;]*m')
RE_MAIN = re.compile(r"hb:\d+ .*?itr (\d+) \((\d+) void\), Hz: ([\d.]+)/(\d+)")
RE_OVERFLOW = re.compile(r'\[BP:[^>\]]+>([^>\]]+)>([^\]]+)\] .*Queue ovrflw (\d+) \(q:(\d+)\), Lps (\S+) .* lost: (\d+)')
RE_NETMON_SAVE = re.compile(r'Network map status saved in ([\d.]+) seconds')
RE_EPOCH_SAVE = re.compile(r'Epochs status saved in ([\d.]+) seconds')
RE_CS_SET_ERR = re.compile(r'Error in chainstore_set: (.*) after ([\d.]+)s')
RE_CS_HSYNC_ERR = re.compile(r'Error in chainstore_hsync: (.*) after ([\d.]+)s')
RE_DISPATCH_FULL = re.compile(r'Admin pipeline async dispatcher queue is full')
BROKER_COUNTERS = ('messages.received', 'messages.sent', 'messages.dropped', 'delivery.dropped', 'delivery.dropped.queue_full',
                   'bytes.received', 'bytes.sent', 'messages.qos1.received', 'messages.publish')


def pct(values, quantile):
  if not values:
    return None
  ordered = sorted(values)
  return ordered[min(len(ordered) - 1, int(round(quantile / 100.0 * (len(ordered) - 1))))]


def rnd(value, digits=2):
  return None if value is None else round(value, digits)


def dist(values):
  return {'n': len(values), 'p50': rnd(pct(values, 50), 3), 'p95': rnd(pct(values, 95), 3), 'max': rnd(max(values), 3) if values else None}


def read_jsonl(path, start, end):
  rows = []
  if not path.exists():
    return rows
  with open(path, 'rt') as fh:
    for line in fh:
      try:
        row = json.loads(line)
      except ValueError:
        continue
      if start <= row.get('t', 0) <= end:
        rows.append(row)
  return rows


def node_probe(home, name, start, end):
  rows = read_jsonl(home.run / 'out' / name / 'probe.jsonl', start, end)
  if len(rows) < 2:
    return {'samples': len(rows)}
  first, last = rows[0], rows[-1]
  span = max(1e-9, last['t'] - first['t'])
  restarted = any(later['up'] < earlier['up'] for earlier, later in zip(rows, rows[1:]))
  result = {
    'samples': len(rows),
    'restarted': restarted,
    'cpu_cores': rnd((last['cpu'] - first['cpu']) / span) if not restarted else None,
    'rss_mb': rnd(last.get('VmRSS', 0) / 1024.0, 0),
    'threads': last.get('Threads'),
    # Whole container, from its control group: what the host has to provide for this node.
    'container_mb': rnd(last['cg_mem'] / 1048576.0, 0) if 'cg_mem' in last else None,
    'container_cores': rnd((last['cg_usage_usec'] - first['cg_usage_usec']) / 1e6 / span)
                       if 'cg_usage_usec' in last and 'cg_usage_usec' in first and not restarted else None,
    'throttled_share': rnd((last['cg_throttled_usec'] - first['cg_throttled_usec']) / 1e6 / span)
                       if 'cg_throttled_usec' in last and 'cg_throttled_usec' in first and not restarted else None,
    'plugins': {},
  }
  for key in sorted(last.get('plugins') or {}):
    signature = key.split('|')[1]
    if signature not in KEY_PLUGINS:
      continue
    series = [row['plugins'][key] for row in rows if key in (row.get('plugins') or {})]
    if len(series) < 2:
      continue
    b = series[-1]
    rates = [item['hz'] for item in series if isinstance(item.get('hz'), (int, float))]

    def grown(field):
      # Counters start again from zero when the node restarts: add up the increases only.
      return sum(max(0, later[field] - earlier[field]) if later[field] >= earlier[field] else later[field]
                 for earlier, later in zip(series, series[1:]))

    result['plugins'][signature] = {
      'received': grown('recv'),
      'handled': grown('handled'),
      'dropped': grown('dropped'),
      'queue_end': b['queue'],
      'queue_max': max(item['queue'] for item in series),
      'queue_cap': b['qmax'],
      'loop_hz_p50': rnd(pct(rates, 50), 1),
      'loop_hz_min': rnd(min(rates), 1) if rates else None,
      'errors': (b.get('errors') or 0) - (series[0].get('errors') or 0),
    }
  return result


def _loop_series(times, counts, floor_hz, window_s):
  """
  Pauses and slow stretches of one loop, from its iteration counter sampled over time.

  Parameters
  ----------
  times : list of float
    Sample times, epoch seconds, increasing, from one run of the process (the counter never goes back).
  counts : list of int
    The loop's iterations so far at each sample.
  floor_hz : float
    The lowest acceptable average rate.
  window_s : float
    Length of the shortest stretch the rate is averaged over.

  Returns
  -------
  dict
    ``stall_s``: the longest time the counter did not move, at least (first to last of equal samples) and
    ``stall_bound_s`` at most (one sample more on each side), with ``stall_at`` (epoch seconds, its start);
    ``under_floor_s``: the longest stretch whose average rate stayed under ``floor_hz``, with ``under_floor_at``;
    ``min_rate_hz``: the lowest average rate over any stretch of at least ``window_s``; ``p50_hz``: the median rate
    between two samples.

  Examples
  --------
  >>> _loop_series([0, 1, 2, 3, 4], [0, 10, 10, 10, 20], 1.0, 2.0)['stall_s']
  2
  """
  # No stall found yet.
  best = {'stall_s': 0, 'stall_bound_s': 0, 'stall_at': None}
  # Walk the samples, one run of equal counts at a time.
  idx = 1
  # Until the last sample.
  while idx < len(times):
    if counts[idx] != counts[idx - 1]:
      # The loop moved between these two samples.
      idx += 1
      continue
    # A run of equal samples starts at idx - 1; find its last sample.
    last = idx
    # Up to the last sample with the same count.
    while last + 1 < len(times) and counts[last + 1] == counts[idx - 1]:
      # The run goes on.
      last += 1
    # At least the span of the equal samples, at most one sample more on each side.
    low = times[last] - times[idx - 1]
    # The upper bound reaches the samples just outside the run (or the ends of the series).
    high = times[min(last + 1, len(times) - 1)] - times[max(idx - 2, 0)]
    if low > best['stall_s']:
      # The longest stall so far, with its bounds and start.
      best = {'stall_s': round(low, 1), 'stall_bound_s': round(high, 1), 'stall_at': times[idx - 1]}
    # On to the sample after the run.
    idx = last + 1
  # The longest stretch whose average rate stayed under the floor (every pair of samples; a few thousand at most).
  under, under_at = 0.0, None
  # From each sample as the stretch's start.
  for first in range(len(times)):
    # Longest stretch first, so the first one under the floor is the longest from this start.
    for later in range(len(times) - 1, first, -1):
      # The stretch's length.
      span = times[later] - times[first]
      if span <= under:
        break
      if (counts[later] - counts[first]) / span < floor_hz:
        # The longest under-floor stretch that starts at this sample.
        under, under_at = span, times[first]
        break
  # The lowest average over the shortest stretch of at least window_s from each sample.
  rates = []
  # From each sample as the stretch's start.
  for first in range(len(times)):
    # The first later sample at least window_s away.
    later = next((k for k in range(first + 1, len(times)) if times[k] - times[first] >= window_s), None)
    if later is not None:
      # That stretch's average rate.
      rates.append((counts[later] - counts[first]) / (times[later] - times[first]))
  # The rate between each two neighbouring samples.
  steps = [(counts[k] - counts[k - 1]) / (times[k] - times[k - 1]) for k in range(1, len(times)) if times[k] > times[k - 1]]
  # The stall, the slow stretch, the lowest windowed rate and the median rate.
  return dict(best, under_floor_s=round(under, 1), under_floor_at=under_at,
              min_rate_hz=rnd(min(rates), 2) if rates else None, p50_hz=rnd(pct(steps, 50), 1))


def loop_gaps(home, name, start, end, floor_hz=1.0, window_s=10.0):
  """
  How the main loop and the chain-store plugin loop of one node kept going in a window, from its probe.

  Parameters
  ----------
  home : Home
    Folder layout of the localnet; the node's ``probe.jsonl`` is read.
  name : str
    Node name.
  start : float
    Window start, epoch seconds.
  end : float
    Window end, epoch seconds.
  floor_hz : float, optional
    Lowest acceptable average loop rate (default 1 Hz).
  window_s : float, optional
    Shortest stretch the rate is averaged over (default 10 s).

  Returns
  -------
  dict
    ``samples``, ``period_s`` (median spacing of the samples, the resolution of every figure) and, for ``main``
    (the node's main loop, probe field ``main_iter``) and ``chain_store`` (the chain-store plugin's own loop),
    what ``_loop_series`` returns, taken over the longest part of the window without a restart of the node.

  Examples
  --------
  >>> loop_gaps(home, 'r1s-db', time.time() - 900, time.time())['main']['stall_s']
  1.0
  """
  # The probe's samples in the window.
  rows = read_jsonl(home.run / 'out' / name / 'probe.jsonl', start, end)
  # Split at a restart of the node (the probe's uptime goes back); keep the longest part.
  parts, current = [], []
  # Each sample in order.
  for row in rows:
    if current and row['up'] < current[-1]['up']:
      # A new process: the part before it is closed.
      parts.append(current)
      # And a new part begins.
      current = []
    # The sample joins the current part.
    current.append(row)
  # The last part.
  parts.append(current)
  # The longest part: its counters never go back.
  rows = max(parts, key=len)
  if len(rows) < 3:
    # Too few samples for any figure.
    return {'samples': len(rows)}
  # Sample times.
  times = [row['t'] for row in rows]
  # The resolution of every figure below, and when the part starts.
  result = {'samples': len(rows), 'period_s': rnd(pct([b - a for a, b in zip(times, times[1:])], 50), 2),
            'from_utc': datetime.fromtimestamp(times[0], timezone.utc).strftime('%H:%M:%S')}
  # The main loop, in samples that carry its counter (a probe of an earlier tool version has none).
  main = [(row['t'], row['main_iter']) for row in rows if 'main_iter' in row]
  if len(main) >= 3:
    # Its stall, slow stretch and rates.
    result['main'] = _loop_series([item[0] for item in main], [item[1] for item in main], floor_hz, window_s)
  # The chain-store plugin's loop: its instance key carries the signature as the middle part.
  key = next((key for key in (rows[-1].get('plugins') or {}) if key.split('|')[1] == 'CHAIN_STORE_BASE'), None)
  # Its iteration counter in each sample that has it.
  store = [(row['t'], row['plugins'][key]['iter']) for row in rows
           if key in (row.get('plugins') or {}) and isinstance(row['plugins'][key].get('iter'), int)]
  if len(store) >= 3:
    # Its stall, slow stretch and rates.
    result['chain_store'] = _loop_series([item[0] for item in store], [item[1] for item in store], floor_hz, window_s)
  # Each loop measured.
  for loop in ('main', 'chain_store'):
    # Each time field.
    for field in ('stall_at', 'under_floor_at'):
      if result.get(loop, {}).get(field):
        # Times also as UTC clock times, for reading against node logs.
        result[loop][field + '_utc'] = datetime.fromtimestamp(result[loop][field], timezone.utc).strftime('%H:%M:%S')
  # Both loops.
  return result


def node_log(name, start, end):
  stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
  out = sh('docker', 'logs', '--since', stamp(start), '--until', stamp(end), container(name), check=False, timeout=180).stdout or ''
  text = ANSI.sub('', out)
  main = [float(match.group(3)) for match in RE_MAIN.finditer(text)]
  overflow = {}
  for match in RE_OVERFLOW.finditer(text):
    overflow[match.group(2)] = {'events': int(match.group(3)), 'loop_hz': match.group(5), 'lost': int(match.group(6))}
  netmon = [float(value) for value in RE_NETMON_SAVE.findall(text)]
  epochs = [float(value) for value in RE_EPOCH_SAVE.findall(text)]
  return {
    'main_loop_hz_p50': rnd(pct(main, 50), 1),
    'main_loop_hz_min': rnd(min(main), 1) if main else None,
    'queue_overflow': overflow,
    'netmon_save_s': dist(netmon),
    'epochs_save_s': dist(epochs),
    'chainstore_set_errors': len(RE_CS_SET_ERR.findall(text)),
    'chainstore_hsync_errors': len(RE_CS_HSYNC_ERR.findall(text)),
    'dispatcher_full': len(RE_DISPATCH_FULL.findall(text)),
    'restarts_in_window': text.count('[launch] isolation check passed'),
    'log_lines': text.count('\n'),
  }


def cstore_load(home, start, end):
  rows = read_jsonl(home.run / 'out' / 'load-cstore' / 'cstore.jsonl', start, end)
  result = {}
  for node in sorted({row['node'] for row in rows}):
    mine = [row for row in rows if row['node'] == node]
    writes = [row for row in mine if row['op'] == 'write']
    hsync = [row for row in mine if row['op'] == 'hsync']
    repl = [row for row in mine if row['op'] == 'replicated']
    result[node] = {
      'writes': len(writes),
      'writes_confirmed': sum(1 for row in writes if row['ok']),
      'write_s': dist([row['s'] for row in writes if row['ok']]),
      'refresh': len(hsync),
      'refresh_ok': sum(1 for row in hsync if row['ok']),
      'refresh_s': dist([row['s'] for row in hsync if row['ok']]),
      'replicated': sum(1 for row in repl if row['ok']),
      'replication_missed': sum(1 for row in repl if not row['ok']),
      'replication_s': dist([row['s'] for row in repl if row['ok']]),
    }
  return result


def fleet_load(home, start, end):
  rows = read_jsonl(home.run / 'out' / 'load-fleet' / 'dauth.jsonl', start, end)
  stats = read_jsonl(home.run / 'out' / 'load-fleet' / 'stats.jsonl', start, end)
  result = {'dauth': {}}
  for outcome in sorted({row['outcome'] for row in rows}):
    result['dauth'][outcome] = dist([row['s'] for row in rows if row['outcome'] == outcome])
  if len(stats) >= 2:
    span = max(1e-9, stats[-1]['t'] - stats[0]['t'])
    result['heartbeats_per_s'] = rnd((stats[-1]['hb_sent'] - stats[0]['hb_sent']) / span, 1)
    result['heartbeats_late'] = stats[-1]['hb_late'] - stats[0]['hb_late']
    result['nodes_connected'] = stats[-1].get('connected')
  return result


def dauth_probe(home, start, end):
  """What the dAuth load generator saw: the start-up probe of a licensed node and the secret requests."""
  rows = read_jsonl(home.run / 'out' / 'load-dauth' / 'dauth.jsonl', start, end)
  result = {}
  for kind in sorted({row.get('kind') for row in rows if row.get('kind')}):
    mine = [row for row in rows if row.get('kind') == kind]
    result[kind] = {'sent': len(mine), 'ok': sum(1 for row in mine if row['outcome'] == 'ok'),
                    'ok_s': dist([row['s'] for row in mine if row['outcome'] == 'ok' and row.get('s') is not None]),
                    'outcomes': {key: sum(1 for row in mine if row['outcome'] == key) for key in sorted({row['outcome'] for row in mine})}}
  return result


def edge_log(home, start, end):
  path = home.run / 'out' / 'edge' / 'access.log'
  groups = {}
  if not path.exists():
    return groups
  with open(path, 'rt', errors='replace') as fh:
    for line in fh:
      parts = line.split(' ', 8)
      try:
        stamp = float(parts[0])
      except (ValueError, IndexError):
        continue
      if not start <= stamp <= end:
        continue
      request = line.rsplit('"', 2)[-2] if line.count('"') >= 2 else ''
      endpoint = request.split(' ')[1].split('?')[0] if ' ' in request else request
      status_field = [item for item in line.split(' ') if item.isdigit() and len(item) == 3]
      status = status_field[0] if status_field else '?'
      # $request_time is the field after the status
      fields = line.split(' ')
      try:
        took = float(fields[fields.index(status) + 1])
      except (ValueError, IndexError):
        took = None
      group = groups.setdefault('{} {}'.format(parts[1], endpoint), {'status': {}, 's': []})
      group['status'][status] = group['status'].get(status, 0) + 1
      if took is not None:
        group['s'].append(took)
  return {key: {'status': val['status'], 's': dist(val['s'])} for key, val in sorted(groups.items())}


def chain_stats():
  out = ctl_exec(PYTHON, '-c', "import urllib.request;print(urllib.request.urlopen('http://rpc.localnet:8545/_stats',timeout=10).read().decode())",
                 check=False, timeout=60).stdout or ''
  try:
    data = json.loads(out.strip().splitlines()[-1])
  except (ValueError, IndexError):
    return {}
  return {'rpc': data.get('rpc'), 'calls': data.get('calls'), 'unhandled': data.get('unhandled'),
          'transactions': data.get('transactions'), 'uptime': rnd(data.get('uptime'), 0)}


def broker_stats(manifest):
  result = {}
  for broker in manifest['mesh']['brokers']:
    out = sh('docker', 'exec', container(broker), 'emqx', 'ctl', 'metrics', check=False, timeout=60).stdout or ''
    counters = {}
    for line in out.splitlines():
      parts = line.split(':')
      if len(parts) == 2 and parts[0].strip() in BROKER_COUNTERS:
        counters[parts[0].strip()] = int(parts[1].strip())
    stats = sh('docker', 'exec', container(broker), 'emqx', 'ctl', 'broker', 'stats', check=False, timeout=60).stdout or ''
    for line in stats.splitlines():
      parts = line.split(':')
      if len(parts) == 2 and parts[0].strip() in ('connections.count', 'sessions.count', 'subscriptions.count'):
        counters[parts[0].strip()] = int(parts[1].strip())
    result[broker] = counters
  return result


def containers():
  out = sh('docker', 'stats', '--no-stream', '--format', '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}', check=False, timeout=120).stdout or ''
  result = {}
  for line in out.splitlines():
    parts = line.split('\t')
    if len(parts) == 3 and parts[0].startswith('r1ln-'):
      result[parts[0][5:]] = {'cpu_pct': parts[1], 'mem': parts[2].split(' / ')[0]}
  return result


def collect(home, start, end, logs=True):
  manifest = home.manifest()
  result = {
    'window': {'start': start, 'end': end, 'seconds': rnd(end - start, 1),
               'start_utc': datetime.fromtimestamp(start, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')},
    'nodes': {},
  }
  for node in manifest['nodes']:
    entry = {'role': node['role'], 'arm': node['arm'], 'headless': bool(node.get('headless'))}
    entry.update(node_probe(home, node['name'], start, end))
    if logs:
      entry['log'] = node_log(node['name'], start, end)
    result['nodes'][node['name']] = entry
  result['chain_store_users'] = cstore_load(home, start, end)
  result['fleet'] = fleet_load(home, start, end)
  result['dauth_probe'] = dauth_probe(home, start, end)
  result['front'] = edge_log(home, start, end)
  result['chain'] = chain_stats()
  result['brokers'] = broker_stats(manifest)
  result['containers'] = containers()
  return result


def table(result):
  """A compact text view of the chain-store and dAuth health of every real node."""
  lines = ['window: {} UTC, {} s'.format(result['window']['start_utc'], result['window']['seconds']), '']
  head = '{:<10} {:<7} {:<5} {:>5} {:>6} | {:>6} {:>6} {:>5} {:>5} {:>6} | {:>7} {:>7}'.format(
    'node', 'role', 'code', 'cpu', 'mainHz', 'cs_in', 'cs_out', 'drop', 'qmax', 'csHz', 'nm_save', 'writes')
  lines += [head, '-' * len(head)]
  users = result.get('chain_store_users') or {}
  for name, node in result['nodes'].items():
    store = (node.get('plugins') or {}).get('CHAIN_STORE_BASE') or {}
    log = node.get('log') or {}
    mine = users.get(name) or {}
    lines.append('{:<10} {:<7} {:<5} {:>5} {:>6} | {:>6} {:>6} {:>5} {:>5} {:>6} | {:>7} {:>7}'.format(
      name, node['role'] + ('*' if node.get('headless') else ''), node['arm'], str(node.get('cpu_cores')),
      str(log.get('main_loop_hz_p50')), str(store.get('received', '-')), str(store.get('handled', '-')),
      str(store.get('dropped', '-')), str(store.get('queue_max', '-')), str(store.get('loop_hz_p50', '-')),
      str((log.get('netmon_save_s') or {}).get('p95')),
      '{}/{}'.format(mine.get('writes_confirmed'), mine.get('writes')) if mine else '-'))
  lines += ['', '(* headless: no web plugins; cs_in/cs_out: chain-store inputs received/handled; nm_save: network-monitor save p95 s)']
  return '\n'.join(lines)
