"""
Where a node's interpreter time goes: a sampling profile of running nodes.

Python runs one thread at a time (the interpreter lock, GIL). On a saturated
oracle the question is which thread holds it. ``py-spy`` samples the node
from inside its container without pausing it, once counting only the thread
that holds the lock and once counting every thread, and this module turns
the samples into shares per thread and per function.

py-spy is not part of the node image. Put a ``py-spy`` binary in
``<home>/tools/py-spy`` before ``init``; it is mounted read-only into every
node container. The containers carry the capability it needs (SYS_PTRACE).
"""

import re
import threading

from .common import LocalnetError, container, sh

PYSPY = '/opt/tools/py-spy'
THREAD = re.compile(r'^(?:process \d+:"[^"]*";)?thread (?:\(([^)]*)\))?:? ?(?:"([^"]*)")?|^thread[^;]*')


def _record(name, mode, seconds, rate, results):
  target = '/tmp/pyspy_{}.raw'.format(mode)
  cmd = ['docker', 'exec', container(name), PYSPY, 'record', '--nonblocking', '--idle', '--threads', '--full-filenames',
         '--format', 'raw', '--rate', str(rate), '--duration', str(seconds), '--pid', '1', '--output', target]
  if mode == 'gil':
    cmd.insert(5, '--gil')
  sh(*cmd, check=False, timeout=seconds + 120)
  results[(name, mode)] = sh('docker', 'exec', container(name), 'cat', target, check=False, timeout=120).stdout or ''
  return


def _fold(raw):
  """Return (total samples, {thread: samples}, {leaf function: samples}, {function anywhere on stack: samples})."""
  total, threads, leaves, anywhere = 0, {}, {}, {}
  for line in raw.splitlines():
    stack, _, count = line.rpartition(' ')
    try:
      count = int(count)
    except ValueError:
      continue
    frames = stack.split(';')
    if not frames:
      continue
    thread = frames[0]
    match = re.search(r'"([^"]+)"', thread)
    thread = match.group(1) if match else thread
    total += count
    threads[thread] = threads.get(thread, 0) + count
    body = frames[1:]
    if body:
      leaves[body[-1]] = leaves.get(body[-1], 0) + count
      for frame in set(body):
        anywhere[frame] = anywhere.get(frame, 0) + count
  return total, threads, leaves, anywhere


def _short(frame):
  frame = re.sub(r'/opt/r1src/(core|sdk)/', '', frame)
  frame = re.sub(r'/opt/python/lib/python3\.\d+/', 'py/', frame)
  return frame.replace('/edge_node/', '')[:110]


def profile(names, seconds=30, rate=20, top=8):
  probe = sh('docker', 'exec', container(names[0]), PYSPY, '--version', check=False, timeout=30)
  if probe.returncode != 0:
    raise LocalnetError('py-spy is not available in the node containers: put a py-spy binary in <home>/tools/py-spy '
                        'and run "up" again ({})'.format((probe.stdout or '').strip()[:200]))
  results, threads = {}, []
  for mode in ('gil', 'all'):
    threads = [threading.Thread(target=_record, args=(name, mode, seconds, rate, results)) for name in names]
    for thread in threads:
      thread.start()
    for thread in threads:
      thread.join()
  report = {}
  ticks = float(seconds * rate)
  for name in names:
    gil_total, gil_threads, gil_leaves, gil_any = _fold(results.get((name, 'gil'), ''))
    all_total, _all_threads, _all_leaves, _all_any = _fold(results.get((name, 'all'), ''))
    pick = lambda table: [{'name': _short(key), 'pct_of_time': round(100.0 * val / ticks, 1)}
                          for key, val in sorted(table.items(), key=lambda item: -item[1])[:top]]
    report[name] = {
      'seconds': seconds, 'rate': rate,
      'gil_held_pct': round(100.0 * gil_total / ticks, 1),
      'threads_alive': round(all_total / ticks, 1),
      'gil_by_thread': pick(gil_threads),
      'gil_by_function_on_stack': pick({key: val for key, val in gil_any.items()
                                        if '/threading.py' not in key and 'launch.py' not in key}),
      'gil_by_leaf_function': pick(gil_leaves),
    }
  return report


def text(report):
  lines = []
  for name, item in report.items():
    lines.append('{}: interpreter lock held {} % of the time ({} s at {} Hz)'.format(
      name, item['gil_held_pct'], item['seconds'], item['rate']))
    lines.append('  by thread:   ' + ', '.join('{} {}%'.format(row['name'], row['pct_of_time']) for row in item['gil_by_thread'][:6]))
    for row in item['gil_by_function_on_stack'][:8]:
      lines.append('  {:>5}%  {}'.format(row['pct_of_time'], row['name']))
  return '\n'.join(lines)
