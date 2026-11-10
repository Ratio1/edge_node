"""
Start-up guard for localnet processes (test bed only).

A localnet node runs production node code with fresh keys. It must never
reach a public Ratio1 network, so every localnet process calls ``enforce``
before it imports any node code. The guard refuses to continue unless:

  * the process was started by the test bed (``R1_LOCALNET=1``),
  * the network name is a known one (its public addresses are replaced by
    chain_shim afterwards, which refuses to continue if any is left),
  * the container has no default route,
  * a connection to public addresses fails,
  * public host names do not resolve.

Only the standard library is used, so the guard itself cannot trigger any
import side effect of the node.
"""

import os
import socket
import sys

EXIT_NOT_ISOLATED = 97

PUBLIC_PROBES = (
  ('1.1.1.1', 443),
  ('8.8.8.8', 53),
  ('140.82.121.4', 443),
)
PUBLIC_NAMES = ('dauth.ratio1.ai', 'devnet-dauth.ratio1.ai', 'github.com')
ALLOWED_EVM_NETS = ('mainnet', 'testnet', 'devnet')


def _default_routes():
  routes = []
  try:
    with open('/proc/net/route', 'rt') as fh:
      lines = fh.read().strip().splitlines()[1:]
    for line in lines:
      parts = line.split()
      if len(parts) > 2 and parts[1] == '00000000':
        routes.append(parts[0])
  except Exception as exc:
    routes.append('unreadable: {}'.format(exc))
  return routes


def _can_connect(host, port, timeout=2.0):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.settimeout(timeout)
  try:
    sock.connect((host, port))
    return True
  except Exception:
    return False
  finally:
    sock.close()


def _resolves(name):
  try:
    socket.getaddrinfo(name, 443)
    return True
  except Exception:
    return False


def check():
  """Return the list of reasons why this process is not safely isolated."""
  problems = []
  if os.environ.get('R1_LOCALNET') != '1':
    problems.append('R1_LOCALNET=1 is not set: not started by the test bed')
  evm_net = os.environ.get('EE_EVM_NET')
  if evm_net not in ALLOWED_EVM_NETS:
    problems.append('EE_EVM_NET={!r} is not allowed here (allowed: {})'.format(evm_net, ALLOWED_EVM_NETS))
  routes = _default_routes()
  if routes:
    problems.append('default route present via {}'.format(routes))
  for host, port in PUBLIC_PROBES:
    if _can_connect(host, port):
      problems.append('public address {}:{} is reachable'.format(host, port))
  for name in PUBLIC_NAMES:
    if _resolves(name):
      problems.append('public name {} resolves'.format(name))
  return problems


def enforce(who='localnet'):
  problems = check()
  if problems:
    print('[{}] REFUSING TO START: this container is not isolated:'.format(who), flush=True)
    for problem in problems:
      print('[{}]   - {}'.format(who, problem), flush=True)
    sys.stdout.flush()
    os._exit(EXIT_NOT_ISOLATED)
  print('[{}] isolation check passed: no default route, public addresses unreachable, public names do not resolve'.format(who), flush=True)
  return True


if __name__ == '__main__':
  enforce(who='guard')
