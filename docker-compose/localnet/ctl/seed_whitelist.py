"""
Give stopped seed oracles the list of allowed senders that a long-running seed has.

A seed does not ask dAuth for its settings; its list of allowed senders (the file ``authorized_addrs``
in its data folder, kept between starts) is filled from the on-chain oracle list by one refresh right
after start-up and then every 15 minutes. That refresh can only name oracles whose heartbeats the seed
has already registered. On mainnet the file and the epoch data are months old and complete. On a
network that starts for the first time the seeds come up together, so the first refresh finds between
one and four of them (itself always) and nothing changes for the next 15 minutes: until then a seed
replicates chain-store writes only to the peers on that partial list, and a seed whose list holds only
itself gets no write confirmed at all. This writes the complete oracle list into each seed's file
before the first start, which is the state a mainnet seed starts from.

File format (ratio1 ``bc/base.py``): one sender per line, ``<address>  <alias>``.
"""

import json
import os
import sys

FILE = 'authorized_addrs'


def lines(oracles):
  """``oracles``: list of ``[address, alias]``; returns the file content."""
  return ''.join('{}  {}\n'.format(address, alias) for address, alias in oracles)


def main():
  root, oracles, names = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
  content = lines(oracles)
  for name in names:
    path = os.path.join(root, name, '_local_cache', FILE)
    tmp = path + '.tmp'
    with open(tmp, 'wt') as fh:
      fh.write(content)
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(tmp, path)
  print('WHITELISTED ' + json.dumps({'nodes': len(names), 'senders': len(oracles)}), flush=True)
  return 0


if __name__ == '__main__':
  sys.exit(main())
