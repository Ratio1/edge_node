"""
Create node identities for a localnet before any node starts.

Each name gets a fresh key written where the node expects it
(``<root>/<name>/_local_cache/_data/e2.pem``), and its two addresses are
printed. The registry of the localnet is built from this output. Runs in a
throwaway container without network.
"""

import json
import os
import sys


def main():
  root = sys.argv[1]
  names = sys.argv[2:]
  from ratio1 import Logger
  from ratio1.bc import DefaultBlockEngine
  result = {}
  for name in names:
    folder = os.path.join(root, name)
    os.makedirs(folder, exist_ok=True)
    os.chdir(folder)
    log = Logger('KG', base_folder='.', app_folder='_local_cache', silent=True)
    engine = DefaultBlockEngine(
      log=log, name=name, config={'PEM_FILE': 'e2.pem', 'PASSWORD': None, 'PEM_LOCATION': 'data'},
    )
    result[name] = {'address': engine.address, 'eth_address': engine.eth_address}
  print('KEYS ' + json.dumps(result), flush=True)
  return 0


if __name__ == '__main__':
  sys.exit(main())
