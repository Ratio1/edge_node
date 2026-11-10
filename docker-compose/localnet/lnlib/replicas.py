"""
Compare the chain-store replicas of the oracles.

Every oracle should hold the same records. This reads the replica file each
oracle last saved, reduces every record to a short digest of its value and
reports, per oracle, how many records are missing or differ from what most
oracles hold. A node saves its replica a few seconds after a change, so two
healthy oracles can differ by the records of the last seconds; run it twice
when a small difference matters.
"""

import json
from collections import Counter

from .common import PYTHON, container, sh

READER = r'''
import hashlib, json, os, pickle, sys
path = '/edge_node/_local_cache/_data/cache_plugins/admin_pipeline__chain_store_base__chain_store_base_inst/object.pickle'
out = {}
if os.path.exists(path):
  with open(path, 'rb') as fh:
    data = pickle.load(fh)
  for key, record in data.items():
    value = record.get('value') if isinstance(record, dict) else record
    out[key] = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12]
print('REPLICA ' + json.dumps({'age_s': round(__import__('time').time() - os.path.getmtime(path), 1) if os.path.exists(path) else None, 'records': out}))
'''


def read(name):
  proc = sh('docker', 'exec', '-i', container(name), PYTHON, '-I', '-', stdin=READER, check=False, timeout=120)
  line = [item for item in (proc.stdout or '').splitlines() if item.startswith('REPLICA ')]
  return json.loads(line[-1][8:]) if line else None


def compare(manifest, ignore_prefixes=()):
  oracles = [node['name'] for node in manifest['nodes'] if node['role'] in ('seed', 'oracle')]
  replicas = {name: read(name) for name in oracles}
  present = {name: rep['records'] for name, rep in replicas.items() if rep}
  votes = {}
  for records in present.values():
    for key, digest in records.items():
      votes.setdefault(key, Counter())[digest] += 1
  majority = {key: counter.most_common(1)[0][0] for key, counter in votes.items()
              if sum(counter.values()) > len(present) / 2.0}
  report = {'oracles_read': len(present), 'records_most_hold': len(majority), 'nodes': {}}
  for name in oracles:
    rep = replicas.get(name)
    if not rep:
      report['nodes'][name] = {'error': 'no replica read'}
      continue
    records = rep['records']
    report['nodes'][name] = {
      'records': len(records),
      'file_age_s': rep['age_s'],
      'missing': sum(1 for key in majority if key not in records),
      'different': sum(1 for key, digest in majority.items() if key in records and records[key] != digest),
      'only_here': sum(1 for key in records if key not in majority),
    }
  return report


def text(report):
  lines = ['records held by most of the {} oracles read: {}'.format(report['oracles_read'], report['records_most_hold']),
           '{:<10} {:>8} {:>8} {:>10} {:>10} {:>9}'.format('oracle', 'records', 'missing', 'different', 'only here', 'saved s ago')]
  for name, item in report['nodes'].items():
    if 'error' in item:
      lines.append('{:<10} {}'.format(name, item['error']))
    else:
      lines.append('{:<10} {:>8} {:>8} {:>10} {:>10} {:>9}'.format(
        name, item['records'], item['missing'], item['different'], item['only_here'], item['file_age_s']))
  return '\n'.join(lines)
