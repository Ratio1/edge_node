"""
Give stopped oracles a chain-store replica of production size.

A fresh oracle starts with an empty replica, and an empty replica hides the
cost that matters in production: every accepted write makes the node rewrite
its whole replica (about 5.5 MB and 3,657 records on mainnet), and several
plugin calls scan every record. This writes the same synthetic replica into
each oracle's data folder before the first start. The content is made up:
job-configuration-like values in namespaces that no node code interprets.
Nothing is copied from production, whose replica holds job secrets.

On-disk format (the same in every code version): a pickle of
``{storage_key: {'key', 'value', 'owner', 'readonly', 'token', 'confirms',
'min_confirms'}}`` at ``_data/cache_plugins/<plugin id>/object.pickle``.
The node loads it without any check.
"""

import base64
import hashlib
import json
import os
import pickle
import random
import sys

FOLDER = os.path.join('_data', 'cache_plugins', 'admin_pipeline__chain_store_base__chain_store_base_inst')


def storage_key(hkey, field):
  return 'hs:{}:{}'.format(hashlib.sha256(hkey.encode()).hexdigest()[:10], base64.urlsafe_b64encode(field.encode()).decode())


def value(rnd, size):
  rows, total = [], 0
  while total < size:
    row = {
      'node': '0xai_%040x' % rnd.getrandbits(160), 'image': 'repo/app:1.%d' % rnd.randrange(99),
      'env': {'KEY_%d' % idx: 'value-%d' % rnd.randrange(9999) for idx in range(6)},
      'cid': 'Qm%044x' % rnd.getrandbits(176),
    }
    rows.append(row)
    total += len(json.dumps(row))
  return json.loads(json.dumps({'data': rows}))


def build(keys, namespaces, value_bytes, seed, owner):
  rnd = random.Random(seed)
  store = {}
  for idx in range(keys):
    key = storage_key('LOCALNET_NS_%02d' % (idx % namespaces), 'field-%d' % idx)
    store[key] = {'key': key, 'value': value(rnd, value_bytes), 'owner': owner, 'readonly': False, 'token': None,
                  'confirms': -1, 'min_confirms': 0}
  return store


B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def unknown_cid(rnd):
  """A well-formed IPFS content id (CIDv0) of content that does not exist anywhere."""
  number = int.from_bytes(b'\x12\x20' + hashlib.sha256(rnd.getrandbits(256).to_bytes(32, 'big')).digest(), 'big')
  text = ''
  while number:
    number, rest = divmod(number, 58)
    text = B58[rest] + text
  return text


def legacy_jobs(count, first_job, owner_address, seed):
  """
  Deployed-job pointers in the format used before secret revisions: the bare content id of the job's
  pipeline document. dAuth must read that document from R1FS to answer a secret request for such a job.
  The documents do not exist, so every read runs into its time limit.
  """
  rnd = random.Random(seed + 1)
  owner = [owner_address, 'admin_pipeline', 'DEEPLOY_MANAGER_API', 'DEEPLOY_MANAGER_API_INST']
  records = {}
  for job_id in range(first_job, first_job + count):
    key = storage_key('DEEPLOY_DEPLOYED_JOBS', str(job_id))
    records[key] = {'key': key, 'value': unknown_cid(rnd), 'owner': owner, 'readonly': False, 'token': None,
                    'confirms': -1, 'min_confirms': 0}
  return records


def write(path, data):
  tmp = path + '.tmp'
  with open(tmp, 'wb') as fh:
    fh.write(data)
    fh.flush()
    os.fsync(fh.fileno())
  os.replace(tmp, path)
  return


def main():
  root, keys, value_bytes, owner_address = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
  legacy_count, legacy_first = int(sys.argv[5]), int(sys.argv[6])
  owner = [owner_address, 'admin_pipeline', 'CSTORE_MANAGER_API', 'CSTORE_MANAGER_API_INST']
  store = build(keys, 40, value_bytes, 11, owner)
  store.update(legacy_jobs(legacy_count, legacy_first, owner_address, 11))
  data = pickle.dumps(store, protocol=pickle.HIGHEST_PROTOCOL)
  for name in sys.argv[7:]:
    folder = os.path.join(root, name, '_local_cache', FOLDER)
    os.makedirs(folder, exist_ok=True)
    write(os.path.join(folder, 'object.pickle'), data)
    write(os.path.join(folder, 'metadata.json'), json.dumps({'SERIALIZATION_SIGNATURE': None}).encode())
  print('SEEDED ' + json.dumps({
    'keys': len(store), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()[:16], 'nodes': len(sys.argv[7:]),
    'legacy_jobs': list(range(legacy_first, legacy_first + legacy_count)),
  }), flush=True)
  return 0


if __name__ == '__main__':
  sys.exit(main())
