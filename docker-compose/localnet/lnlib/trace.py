"""
When the other oracles see a Deeploy request in the request trace of the oracle that received it.

The Deeploy API of an oracle records the requests of its tracked endpoints (create, update, delete and a few
more) in the chain store, under its own node name in ``DEEPLOY_REQUESTS``: up to two requests, each with its
endpoint, the time it was received (``date_start``, UTC, to the second) and the time it was answered
(``date_complete``, None until then). The record shows the other oracles which oracle holds a request that
was not answered.

``watch`` reads the replica every oracle last saved, about once a second, until each one holds a request of
the given endpoint received at or after a given time, and records when each one first held it unanswered
and answered. A node saves its replica a few seconds after a change, so a time read here is when the saved
file showed the request; the file's own time (``mtime``) bounds when the request had arrived.
"""

# The request a report shows is printed as JSON.
import json
# Rounds are timed on the wall clock, which the trace's own times share.
import time
# The oracles of one round are read in parallel.
from concurrent.futures import ThreadPoolExecutor
# The trace keeps its times as UTC text.
from datetime import datetime, timezone

# Replicas are copied out with docker cp and read on the host; bucket and field compose and decode a key.
from .replicas import bucket, field, load

# The namespace of the request trace.
HKEY = 'DEEPLOY_REQUESTS'


def trace_of(replica, writer):
  """
  The request trace one oracle's replica holds for a writer.

  Parameters
  ----------
  replica : dict
    Key -> record, as ``replicas.load`` returns it.
  writer : str
    Node name of the oracle that wrote the trace (its key in ``DEEPLOY_REQUESTS``).

  Returns
  -------
  list
    The trace's requests (dicts with ``endpoint``, ``date_start``, ``date_complete``), empty when none is held.

  Examples
  --------
  >>> trace_of(load('r1s-02')[0], 'r1s-01')[0]['endpoint']
  'create_pipeline'
  """
  # The key prefix of the trace's namespace.
  prefix = bucket(HKEY)
  # Every record; the writer's is the one whose field is its name.
  for key, record in replica.items():
    if field(key, prefix) == writer:
      # The value is the list of requests; a record of another shape holds none.
      value = record.get('value') if isinstance(record, dict) else None
      # The requests, or none.
      return value if isinstance(value, list) else []
  # No record of that writer.
  return []


def watch(manifest, writer, endpoint, since, timeout=90.0, period=1.0, oracles=None):
  """
  Poll every oracle's saved replica until each holds the request, and time when it showed it.

  Parameters
  ----------
  manifest : dict
    The localnet manifest; its seeds and oracles are read unless ``oracles`` names them.
  writer : str
    Node name of the oracle whose Deeploy API received the request.
  endpoint : str
    The request's endpoint, for example ``create_pipeline``.
  since : float
    Epoch seconds: a request of that endpoint whose ``date_start`` is at or after this time, less 1 s (the
    trace keeps whole seconds), is the one watched.
  timeout : float, optional
    Seconds after ``since`` to keep polling (default 90).
  period : float, optional
    Seconds between two rounds of reads (default 1).
  oracles : list of str, optional
    Oracles to read; default every seed and oracle of the manifest, the writer included.

  Returns
  -------
  dict
    ``since``, ``request`` (the watched request as the writer's own replica first showed it, or as another
    oracle did), ``rounds`` and, per oracle under ``nodes``: ``open_s`` / ``answered_s`` (seconds from the
    request's ``date_start`` to the first round that read it unanswered / answered), ``open_mtime_s`` /
    ``answered_mtime_s`` (the same, to the saved file's time, which bounds the arrival) and ``reads``.

  Examples
  --------
  >>> report = watch(manifest, 'r1s-01', 'create_pipeline', time.time() - 1, timeout=60)
  >>> report['nodes']['r1s-02']['open_s'] < 35
  True
  """
  # Every oracle, or the ones named.
  names = oracles or [node['name'] for node in manifest['nodes'] if node['role'] in ('seed', 'oracle')]
  # Per oracle: nothing seen yet.
  nodes = {name: {'open_s': None, 'answered_s': None, 'open_mtime_s': None, 'answered_mtime_s': None, 'reads': 0}
           for name in names}
  # The trace's whole-second time of the earliest request that counts.
  floor = datetime.fromtimestamp(since - 1, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
  # The report; the oracles' entries fill in as rounds read them.
  report = {'since': since, 'writer': writer, 'endpoint': endpoint, 'request': None, 'rounds': 0, 'nodes': nodes}
  # Rounds until every oracle showed the request answered, or the time is up.
  while time.time() < since + timeout:
    # The round's start, for its pace.
    began = time.time()
    # Rounds made, in the report.
    report['rounds'] += 1
    # The oracles still to watch, read at the same time so one round stays near the period.
    pending = [name for name, state in nodes.items() if state['answered_s'] is None]
    # One thread per oracle still watched.
    with ThreadPoolExecutor(max_workers=max(1, len(pending))) as pool:
      # Name -> (saved replica, its save time).
      reads = dict(zip(pending, pool.map(load, pending)))
    # Each oracle read in this round.
    for name in pending:
      # Its entry in the report.
      state = nodes[name]
      # The saved replica and its save time.
      replica, mtime = reads[name]
      # Reads made of it.
      state['reads'] += 1
      if replica is None:
        continue
      # The first request of the endpoint received at or after the floor ("YYYY-mm-dd HH:MM:SS" sorts as time).
      found = next((item for item in trace_of(replica, writer) if isinstance(item, dict)
                    and item.get('endpoint') == endpoint and str(item.get('date_start') or '') >= floor), None)
      if found is None:
        continue
      if report['request'] is None or name == writer:
        # The request as one replica holds it: its receipt time is the reference of every delay.
        report['request'] = dict(found)
      # Seconds of the trace's receipt time, from the trace's own text (UTC).
      received = datetime.strptime(found['date_start'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
      # This round's time and the file's time, as delays from the receipt.
      seen, saved = round(time.time() - received, 1), round(mtime - received, 1)
      if state['open_s'] is None:
        # First round that read the request, answered or not: the trace reached this oracle.
        state['open_s'], state['open_mtime_s'] = seen, saved
        # Whether it was still open when first read.
        state['first_read_open'] = found.get('date_complete') is None
      if found.get('date_complete') is not None:
        # First round that read it answered.
        state['answered_s'], state['answered_mtime_s'] = seen, saved
    if all(state['answered_s'] is not None for state in nodes.values()):
      break
    # One round about every period.
    time.sleep(max(0.0, period - (time.time() - began)))
  # What each oracle showed, and when.
  return report


def text(report):
  """
  A readable view of a ``watch`` report.

  Parameters
  ----------
  report : dict
    What ``watch`` returned.

  Returns
  -------
  str
    The request watched and one line per oracle with its delays.

  Examples
  --------
  >>> print(text(report))   # doctest: +SKIP
  """
  # The request watched, as a replica held it.
  lines = ['trace of {} on {}: request {}'.format(report['endpoint'], report['writer'], json.dumps(report['request']))]
  # One line per oracle.
  for name, state in report['nodes'].items():
    # Read time and file time of the first open and first answered reading.
    lines.append('{:<10} seen {} s (file {} s, open at first read: {}), answered {} s (file {} s), reads {}'.format(
      name, state['open_s'], state['open_mtime_s'], state.get('first_read_open'), state['answered_s'],
      state['answered_mtime_s'], state['reads']))
  # One string.
  return '\n'.join(lines)
