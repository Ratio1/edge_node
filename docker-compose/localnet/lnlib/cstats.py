"""
The chain store's own statistics, read from a node's log.

Every 300 s the chain-store plugin writes one ``CSTORE_STATS`` line (counters of the period, by label), and
in the first lap after each full UTC hour one ``CSTORE_CENSUS`` line (per namespace bucket: records and a
digest of them). Labels and census rows name a hash namespace by its bucket, ``hs:`` and 10 hex digits of
the namespace's SHA-256; this module names the buckets of the namespaces the tests look at, and sums what a
reader of the plan's gates needs: the refusal labels, the resync counters per namespace, lost inputs and the
queue peak. Labels and rows of other buckets are kept as they are.

Lines are read from ``docker logs --timestamps``, so each one carries the time Docker received it.
"""

# Each statistics and census line carries one JSON object.
import json
# Colour codes and Docker's time stamps are matched by pattern.
import re
# docker logs is read as bytes, without the newline translation of a text-mode pipe.
import subprocess
# Docker's time stamps are UTC.
from datetime import datetime, timezone

# The node container's name.
from .common import container
# The bucket of a namespace, composed as the chain store composes it.
from .replicas import bucket

# Colour codes of the node's console log.
ANSI = re.compile(r'\x1b\[[0-9;]*m')
# Docker's RFC 3339 time at the start of each line of "docker logs --timestamps".
STAMP = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z')
# The JSON object of a statistics or census line starts after the marker word.
MARKERS = ('CSTORE_STATS ', 'CSTORE_CENSUS ')
# Namespaces named in reports: the five signed ones, dAuth's secret revisions and the Deeploy request trace.
NAMESPACES = ('DEEPLOY_OPERATIONS', 'DEEPLOY_NODE_OPERATIONS', 'DEEPLOY_DEPLOYED_JOBS', 'DAUTH_JOB_SECRETS',
              'NODE_KEY_ROTATIONS', 'DAUTH_JOB_SECRET_REVISIONS', 'DEEPLOY_REQUESTS')


def names(extra=()):
  """
  Bucket -> namespace name, for the namespaces reports name.

  Parameters
  ----------
  extra : iterable of str, optional
    More namespace names, for example a test namespace.

  Returns
  -------
  dict
    ``{"hs:<10 hex>:": name}``.

  Examples
  --------
  >>> names()[bucket('DEEPLOY_OPERATIONS')]
  'DEEPLOY_OPERATIONS'
  """
  # Every known name and every extra one.
  return {bucket(name): name for name in tuple(NAMESPACES) + tuple(extra)}


def parse(text):
  """
  The statistics and census lines of a node log.

  Parameters
  ----------
  text : str
    Output of ``docker logs --timestamps``: each line starts with Docker's RFC 3339 time.

  Returns
  -------
  dict
    ``stats`` and ``census``: lists of ``{"time": epoch seconds, "utc": "HH:MM:SS", "data": object}`` in log
    order. A line whose JSON does not decode is skipped.

  Examples
  --------
  >>> line = '2026-11-15T01:00:00.5Z [EE] CSTORE_STATS {"counts":{"saves":3},"lost_inputs":0}'
  >>> parse(line)['stats'][0]['data']['counts']
  {'saves': 3}
  """
  # The two kinds of line, each in log order.
  found = {'stats': [], 'census': []}
  # One JSON decoder reads the object that starts after the marker and ignores what follows it.
  decoder = json.JSONDecoder()
  # Every line, without colour codes; split at newlines only and the carriage returns dropped, because the node
  # starts each console line with one and splitlines() would cut Docker's time stamp off its line.
  for line in ANSI.sub('', text).replace('\r', '').split('\n'):
    # A line is of at most one kind; both markers are tried.
    for marker, kind in zip(MARKERS, ('stats', 'census')):
      # Where the object starts, or -1 for a line of another kind.
      at = line.find(marker)
      if at < 0:
        continue
      try:
        # The object alone; a colour reset or other text after it is left.
        data, _end = decoder.raw_decode(line, at + len(marker))
      except ValueError:
        continue
      # Docker's time stamp: whole seconds and a fraction whose trailing zeros Docker drops.
      match = STAMP.match(line)
      if not match:
        continue
      # The whole seconds, in UTC.
      stamp = datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
      # Epoch seconds with the fraction added back.
      epoch = stamp.timestamp() + (float('0.' + match.group(2)) if match.group(2) else 0.0)
      # The line's time, its clock time for reading against logs, and its object.
      found[kind].append({'time': round(epoch, 3), 'utc': stamp.strftime('%H:%M:%S'), 'data': data})
  # Both kinds of line.
  for kind in found:
    # In time order, also when the text joined two streams.
    found[kind].sort(key=lambda item: item['time'])
  # Both kinds.
  return found


def node_lines(name, since=None, until=None):
  """
  The statistics and census lines one node logged in a time window.

  Parameters
  ----------
  name : str
    Node name.
  since : float, optional
    Window start in epoch seconds; None leaves it open.
  until : float, optional
    Window end in epoch seconds; None leaves it open.

  Returns
  -------
  dict
    What ``parse`` returns for that node's log.

  Notes
  -----
  ``docker logs`` keeps the lines of earlier starts of the same container (a kill and start), not of a
  container that was recreated (``switch``).

  Examples
  --------
  >>> len(node_lines('r1s-db', since=time.time() - 600)['stats'])
  2
  """
  # Docker's own window options, in UTC.
  window = []
  # The start and the end, each only when given.
  for option, value in (('--since', since), ('--until', until)):
    if value is not None:
      # RFC 3339 in UTC, which docker logs accepts.
      window += [option, datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')]
  # Time stamps on, so each line carries the time Docker received it. Read as bytes: a text-mode pipe turns the
  # carriage return the node puts after Docker's time stamp into a newline, which cuts the stamp off its line.
  proc = subprocess.run(['docker', 'logs', '--timestamps', *window, container(name)], capture_output=True,
                        timeout=300, check=False)
  # Both streams (the node logs to both), decoded without any newline translation.
  out = (proc.stdout + proc.stderr).decode('utf-8', errors='replace')
  # The two kinds of line in that output.
  return parse(out)


def label_name(label, known):
  """
  A counter label with its bucket replaced by the namespace's name, when the bucket is known.

  Parameters
  ----------
  label : str
    A label of the ``counts`` object, for example ``hs:1a2b3c4d5e:/resync/asked``.
  known : dict
    Bucket -> name, from ``names``.

  Returns
  -------
  str
    The label with ``hs:<hash>:`` replaced by the name (``DEEPLOY_OPERATIONS/resync/asked``), or as it was.

  Examples
  --------
  >>> label_name(bucket('DAUTH_JOB_SECRETS') + '/remote/changed', names())
  'DAUTH_JOB_SECRETS/remote/changed'
  """
  # A bucket is the first 14 characters of the label.
  head = label[:14]
  # The bucket's name and the rest of the label, or the label as it is.
  return known[head] + label[14:] if head in known else label


def summary(found, extra=()):
  """
  What each statistics line says that the plan's gates read, per line.

  Parameters
  ----------
  found : dict
    What ``parse`` or ``node_lines`` returned.
  extra : iterable of str, optional
    More namespace names to name in the labels.

  Returns
  -------
  dict
    ``lines``: per statistics line its ``utc`` and ``time``, ``period_s``, ``lost_inputs``, ``queue_peak``,
    ``modes``, ``refusals`` (every label whose last word starts with ``refused`` or is ``error``, by named label,
    with its count), ``refusal_sum`` (their sum, less remote ``refused_not_member`` as gate G0 counts it),
    ``resync`` (per namespace: ``asked``, ``answered``, ``merged``) and ``saves``; ``census``: per census line its
    ``utc`` and its rows with named buckets.

  Examples
  --------
  >>> rows = summary(parse(text))['lines']
  >>> rows[0]['resync']['DEEPLOY_OPERATIONS']['asked']
  1
  """
  # Bucket -> name of every namespace named here.
  known = names(extra)
  # One summary per statistics line.
  lines = []
  # Every statistics line, in log order.
  for item in found['stats']:
    # The line's object.
    data = item['data']
    # Counts with named buckets.
    counts = {label_name(label, known): value for label, value in (data.get('counts') or {}).items()}
    # Every refusal word and error (a wave 02 node has one "refused" label per bucket and origin).
    refusals = {label: value for label, value in counts.items()
                if label.rsplit('/', 1)[-1].startswith('refused') or label.rsplit('/', 1)[-1] == 'error'}
    # Namespace -> its resync counters in this line.
    resync = {}
    # Every label, for the three resync counters.
    for label, value in counts.items():
      # "<namespace>/resync/<asked|answered|merged>".
      parts = label.rsplit('/', 2)
      if len(parts) == 3 and parts[1] == 'resync':
        # Under the namespace, by counter.
        resync.setdefault(parts[0], {})[parts[2]] = value
    # The line's summary.
    lines.append({
      'utc': item['utc'], 'time': item['time'], 'period_s': data.get('period_s'),
      'lost_inputs': data.get('lost_inputs'), 'queue_peak': data.get('queue_peak'), 'modes': data.get('modes'),
      'refusals': refusals,
      # Gate G0 leaves out remote refused_not_member, which a wave 02 node dropped uncounted.
      'refusal_sum': sum(value for label, value in refusals.items() if not label.endswith('/remote/refused_not_member')),
      'resync': resync, 'saves': counts.get('saves'),
    })
  # Census rows with named buckets.
  census = [{'utc': item['utc'], 'time': item['time'],
             'rows': {known.get(key, key): row for key, row in item['data'].items()}} for item in found['census']]
  # Both, for one node.
  return {'lines': lines, 'census': census}


def text(report):
  """
  A readable view of ``summary`` for several nodes.

  Parameters
  ----------
  report : dict
    Node name -> what ``summary`` returned.

  Returns
  -------
  str
    Per node, one line per statistics line (time, lost inputs, queue peak, refusals, resync counters), then
    its census lines (records and digest per named namespace).

  Examples
  --------
  >>> print(text({'r1s-db': summary(node_lines('r1s-db'))}))   # doctest: +SKIP
  """
  # The text, line by line.
  out = []
  # One block per node.
  for name, item in report.items():
    # The block's heading.
    out.append('== {}'.format(name))
    # One line per statistics line.
    for line in item['lines']:
      # Resync counters as namespace:asked/answered/merged.
      resync = ' '.join('{}:{}/{}/{}'.format(ns, val.get('asked', 0), val.get('answered', 0), val.get('merged', 0))
                        for ns, val in sorted(line['resync'].items()))
      # Time, lost inputs, queue peak, refusal sum and labels, and the resync counters when there are any.
      out.append('{} UTC period {}s lost {} qpeak {} refusals {} {}{}'.format(
        line['utc'], line['period_s'], line['lost_inputs'], line['queue_peak'], line['refusal_sum'],
        json.dumps(line['refusals'], sort_keys=True), (' resync ' + resync) if resync else ''))
    # One line per census line.
    for census in item['census']:
      # Records and digest of each named namespace; other buckets are only counted.
      named = {key: row for key, row in census['rows'].items() if not key.startswith('hs:') and key != 'plain'}
      # Name:records:digest per named namespace, and how many other buckets the line has.
      out.append('{} UTC census {} ({} other buckets)'.format(
        census['utc'], ' '.join('{}:{}:{}'.format(key, row[0], row[5]) for key, row in sorted(named.items())),
        len(census['rows']) - len(named)))
  # One string.
  return '\n'.join(out)
