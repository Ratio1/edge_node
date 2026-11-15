"""
Compare the chain-store replicas of the oracles.

Every oracle should hold the same records. This reads the replica file each
oracle last saved, reduces every record to a short digest of its value and
reports, per oracle, how many records are missing or differ from what most
oracles hold, in all and, when asked, per hash namespace. A node saves its
replica a few seconds after a change, so two healthy oracles can differ by the
records of the last seconds; run it twice when a small difference matters.

The file is copied out of the container by the Docker daemon (``docker cp``)
and read on the host, so a reading costs the node nothing: a node under a CPU
limit is measured without being slowed by the measurement.
"""

# A hash namespace's field is stored URL-safe base64 encoded.
import base64
# The replica file comes out of "docker cp" as a tar stream.
import io
# A value's digest is taken over its sorted-key JSON.
import json
# The per-namespace bucket of a key: "hs:" and the first 10 hex digits of the namespace's SHA-256.
import hashlib
# The node saves its replica with pickle; the host reads the same file.
import pickle
# "docker cp" writes bytes, which the tool's text-mode shell helper would decode.
import subprocess
# The tar stream that holds the copied file.
import tarfile
# When a reading was taken, for readings timed against a node's start.
import time
from collections import Counter

# The node container's name, for docker cp.
from .common import container

# Where the chain-store plugin of every node saves its replica.
PICKLE = '/edge_node/_local_cache/_data/cache_plugins/admin_pipeline__chain_store_base__chain_store_base_inst/object.pickle'
# A file copied while the node rewrites it does not unpickle: read it again, up to this many times in all.
READ_ATTEMPTS = 3


def bucket(name):
  """
  Key prefix of one hash namespace in a replica.

  Parameters
  ----------
  name : str
    The namespace as its callers name it, for example ``DEEPLOY_OPERATIONS``.

  Returns
  -------
  str
    ``"hs:"``, the first 10 hex digits of the SHA-256 of the name, and ``":"`` (14 characters), as the chain
    store composes every field key of that namespace.

  Examples
  --------
  >>> len(bucket('DEEPLOY_OPERATIONS'))
  14
  """
  # The same composition as the chain store's __hset_index.
  return 'hs:' + hashlib.sha256(name.encode('utf-8')).hexdigest()[:10] + ':'


def load(name):
  """
  Copy one node's saved replica out of its container and unpickle it on the host.

  Parameters
  ----------
  name : str
    Node name, for example ``r1s-db``.

  Returns
  -------
  tuple of (dict, float) or (None, None)
    The replica (key -> record) and the file's modification time (epoch seconds), or ``(None, None)`` when
    the node has no replica file (not saved yet, or the container is gone).

  Raises
  ------
  pickle.UnpicklingError, EOFError
    When every one of ``READ_ATTEMPTS`` copies fails to unpickle.

  Notes
  -----
  The Docker daemon reads the file, not a process in the node's control group, so the node's CPU limit is
  not charged for it. The node may rewrite the file while it is copied; such a copy is read again.

  Examples
  --------
  >>> replica, mtime = load('r1s-01')
  >>> isinstance(replica, dict)
  True
  """
  # A few copies at most, for a file the node rewrote while it was copied.
  for attempt in range(READ_ATTEMPTS):
    # The daemon streams the file as a one-member tar archive on stdout.
    proc = subprocess.run(['docker', 'cp', '{}:{}'.format(container(name), PICKLE), '-'],
                          capture_output=True, timeout=120, check=False)
    if proc.returncode != 0:
      # No such file (never saved) or no such container: nothing to read.
      return None, None
    # The archive's only member is the replica file.
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
      # Its header carries the file's modification time: when the node last saved.
      member = tar.getmembers()[0]
      # The file's bytes.
      raw = tar.extractfile(member).read()
    try:
      # A dict of key -> record, as the node saved it.
      return pickle.loads(raw), float(member.mtime)
    except (pickle.UnpicklingError, EOFError):
      # A copy taken while the node rewrote the file: copy it again, unless this was the last attempt.
      if attempt == READ_ATTEMPTS - 1:
        # The last copy failed too: the reading fails loudly.
        raise
  # Not reached: every attempt returns or raises.
  return None, None


def field(key, prefix):
  """
  The field name of a hash-namespace key (its URL-safe base64 part decoded).

  Parameters
  ----------
  key : str
    A replica key, ``hs:<10 hex>:<url-safe base64 of the field>``.
  prefix : str
    The namespace's bucket.

  Returns
  -------
  str or None
    The field, or None when the key is not in that namespace or its field part does not decode.

  Examples
  --------
  >>> field(bucket('DEEPLOY_REQUESTS') + 'cjFzLTAx', bucket('DEEPLOY_REQUESTS'))
  'r1s-01'
  """
  if not key.startswith(prefix):
    # A key of another namespace has no field here.
    return None
  # The writer leaves out the padding; add it back.
  part = key[len(prefix):]
  try:
    # URL-safe alphabet, as the chain store composes it.
    return base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)).decode('utf-8')
  except ValueError:
    # Not base64, or not UTF-8 text: no field name.
    return None


def held(names, namespace=None, keys=()):
  """
  What each named node's saved replica holds in one hash namespace, and under some plain keys.

  Parameters
  ----------
  names : list of str
    Nodes to read (oracles or workers).
  namespace : str, optional
    A hash namespace: each of its fields is listed with the size of its value.
  keys : iterable of str, optional
    Plain keys: each is listed with the size of its value, or None when it is not held.

  Returns
  -------
  dict
    Node name -> ``{"fields": {field: bytes}, "keys": {key: bytes or None}, "file_age_s": s}``, or None for a
    node with no replica file. Sizes are the value's compact JSON in UTF-8 bytes.

  Examples
  --------
  >>> held(['r1s-02'], 'LNET_CAP_TEST')['r1s-02']['fields']
  {'under': 523002}
  """
  # The namespace's key prefix, or None when only plain keys are asked for.
  prefix = bucket(namespace) if namespace else None

  def size(record):
    """
    Bytes of a record's value as compact JSON.

    Parameters
    ----------
    record : dict or object
      A replica record (or a bare value from an older replica).

    Returns
    -------
    int
      The size.

    Examples
    --------
    >>> size({'value': 'ab'})
    4
    """
    # The value, from a record or as it is.
    value = record.get('value') if isinstance(record, dict) else record
    # Compact JSON in UTF-8 bytes, the form the chain store measures.
    return len(json.dumps(value, separators=(',', ':'), default=str).encode('utf-8'))

  # Node name -> what it holds.
  out = {}
  # Each named node in turn.
  for name in names:
    # Its saved replica, copied out.
    data, mtime = load(name)
    if data is None:
      # No replica file on that node.
      out[name] = None
      continue
    # The fields of the namespace, the plain keys asked for, and the file's age.
    out[name] = {
      # Each field of the namespace, by its decoded name.
      'fields': {field(key, prefix): size(record) for key, record in data.items() if prefix and key.startswith(prefix)},
      # Each plain key asked for, or None.
      'keys': {key: size(data[key]) if key in data else None for key in keys},
      'file_age_s': round(time.time() - mtime, 1),
    }
  # Every node read.
  return out


def read(name):
  """
  Digest of every record value one node's saved replica holds.

  Parameters
  ----------
  name : str
    Node name.

  Returns
  -------
  dict or None
    ``age_s`` (seconds since the node saved the file), ``mtime`` (epoch seconds of that save) and ``records``
    (key -> first 12 hex digits of the SHA-256 of the value as sorted-key JSON); None when the node has no
    replica file.

  Examples
  --------
  >>> sorted(read('r1s-01'))
  ['age_s', 'mtime', 'records']
  """
  # Copied out and unpickled on the host.
  data, mtime = load(name)
  if data is None:
    # No replica file on that node.
    return None
  # The same digest the earlier in-node reader computed, so readings stay comparable.
  records = {key: hashlib.sha256(json.dumps(record.get('value') if isinstance(record, dict) else record,
                                            sort_keys=True, default=str).encode()).hexdigest()[:12]
             for key, record in data.items()}
  # The file's age at the time of this reading.
  return {'age_s': round(time.time() - mtime, 1), 'mtime': mtime, 'records': records}


def _counts(majority, records, prefix=''):
  """
  Records one oracle lacks, holds with another value, or holds alone, among the keys that start with a prefix.

  Parameters
  ----------
  majority : dict
    Key -> the digest most oracles hold, for every key held by more than half of the oracles read.
  records : dict
    Key -> digest of one oracle's replica.
  prefix : str, optional
    Only keys that start with it are counted (a namespace's bucket); empty counts every key.

  Returns
  -------
  dict
    ``records`` (held here), ``missing``, ``different`` and ``only_here`` (held here, held by no majority).

  Examples
  --------
  >>> _counts({'a': '1', 'b': '2'}, {'a': '1', 'b': '3', 'c': '4'})
  {'records': 3, 'missing': 0, 'different': 1, 'only_here': 1}
  """
  # The majority's keys under the prefix.
  wanted = {key: digest for key, digest in majority.items() if key.startswith(prefix)}
  # This oracle's keys under the prefix.
  held = {key: digest for key, digest in records.items() if key.startswith(prefix)}
  # The four counts of this oracle under the prefix.
  return {
    'records': len(held),
    # A record most oracles hold and this one does not.
    'missing': sum(1 for key in wanted if key not in held),
    # A record this oracle holds with another value than most.
    'different': sum(1 for key, digest in wanted.items() if key in held and held[key] != digest),
    # A record no majority holds (written here only, or held by half of the oracles or fewer).
    'only_here': sum(1 for key in held if key not in wanted),
  }


def compare(manifest, ignore_prefixes=(), namespaces=None):
  """
  Compare the saved replicas of all oracles against the records most of them hold.

  Parameters
  ----------
  manifest : dict
    The localnet manifest; its seeds and oracles are read.
  ignore_prefixes : tuple of str, optional
    Not used; kept for the callers that pass it.
  namespaces : list of str, optional
    Hash namespaces to report apart, for example the five signed ones; None reports only the totals.

  Returns
  -------
  dict
    ``oracles_read``, ``records_most_hold``, ``read_at`` (epoch seconds when the reading started and ended),
    ``nodes`` (per oracle: ``records``, ``file_age_s``, ``missing``, ``different``, ``only_here`` and, with
    ``namespaces``, the same counts per namespace under ``namespaces``) and, with ``namespaces``,
    ``namespaces`` (records most oracles hold per namespace).

  Examples
  --------
  >>> report = compare(manifest, namespaces=['DEEPLOY_OPERATIONS'])
  >>> report['nodes']['r1s-db']['namespaces']['DEEPLOY_OPERATIONS']['missing']
  0
  """
  # When the reading began: the readings of a restart are timed against the node's start.
  began = time.time()
  oracles = [node['name'] for node in manifest['nodes'] if node['role'] in ('seed', 'oracle')]
  replicas = {name: read(name) for name in oracles}
  present = {name: rep['records'] for name, rep in replicas.items() if rep}
  votes = {}
  for records in present.values():
    for key, digest in records.items():
      votes.setdefault(key, Counter())[digest] += 1
  majority = {key: counter.most_common(1)[0][0] for key, counter in votes.items()
              if sum(counter.values()) > len(present) / 2.0}
  # The buckets of the namespaces reported apart, by name.
  buckets = {name: bucket(name) for name in (namespaces or [])}
  # The report's header; one entry per oracle follows.
  report = {'oracles_read': len(present), 'records_most_hold': len(majority), 'nodes': {},
            # The window of the reading, epoch seconds.
            'read_at': [round(began, 1), round(time.time(), 1)]}
  if buckets:
    # Records most oracles hold, per namespace: the size each count is out of.
    report['namespaces'] = {name: sum(1 for key in majority if key.startswith(prefix)) for name, prefix in buckets.items()}
  for name in oracles:
    rep = replicas.get(name)
    if not rep:
      report['nodes'][name] = {'error': 'no replica read'}
      continue
    # The totals over every key.
    entry = dict(_counts(majority, rep['records']), file_age_s=rep['age_s'])
    if buckets:
      # The same counts per namespace.
      entry['namespaces'] = {ns: _counts(majority, rep['records'], prefix) for ns, prefix in buckets.items()}
    # This oracle's counts.
    report['nodes'][name] = entry
  return report


def text(report):
  """
  A readable table of a ``compare`` report.

  Parameters
  ----------
  report : dict
    What ``compare`` returned.

  Returns
  -------
  str
    One line per oracle with the totals and, when the report has namespaces, one block per namespace with
    missing / different / only-here per oracle.

  Examples
  --------
  >>> print(text(compare(manifest)))   # doctest: +SKIP
  """
  lines = ['records held by most of the {} oracles read: {}'.format(report['oracles_read'], report['records_most_hold']),
           '{:<10} {:>8} {:>8} {:>10} {:>10} {:>9}'.format('oracle', 'records', 'missing', 'different', 'only here', 'saved s ago')]
  for name, item in report['nodes'].items():
    if 'error' in item:
      lines.append('{:<10} {}'.format(name, item['error']))
    else:
      lines.append('{:<10} {:>8} {:>8} {:>10} {:>10} {:>9}'.format(
        name, item['records'], item['missing'], item['different'], item['only_here'], item['file_age_s']))
  # The namespaces reported apart, if any.
  for namespace, held in (report.get('namespaces') or {}).items():
    # One block per namespace: what most hold, then missing/different/only-here per oracle.
    lines.append('{} (most hold {}): {}'.format(namespace, held, ', '.join(
      '{} {}/{}/{}'.format(name, item['namespaces'][namespace]['missing'], item['namespaces'][namespace]['different'],
                           item['namespaces'][namespace]['only_here'])
      for name, item in report['nodes'].items() if 'namespaces' in item)))
  if report.get('namespaces'):
    # How to read the blocks above.
    lines.append('(per namespace: oracle missing/different/only-here)')
  return '\n'.join(lines)
