#!/usr/bin/env python3
"""
Chain-store user traffic and the measurements that matter to a user of it.

For every node that serves the local CStore API this process:

  * writes a small record every ``--period`` seconds (the way a plugin or an
    operator writes) and records whether the write was confirmed and how
    long the caller waited;
  * checks how long that record takes to become readable on every other
    node that serves the API (replication delay);
  * asks for a namespace refresh (``hsync``) every ``--hsync`` seconds and
    records outcome and duration.

These are the three symptoms of the production incident: writes that are not
confirmed, records that do not arrive, refreshes that time out.

Output: ``/out/cstore.jsonl``, one line per operation.
"""

import argparse
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import common

WHO = 'cstore'
PORT = 31234


def call(host, endpoint, method='GET', timeout=60, **params):
  url = 'http://{}:{}/{}'.format(host, PORT, endpoint)
  data = None
  if method == 'GET':
    url += '?' + urllib.parse.urlencode(params)
  else:
    data = json.dumps(params).encode()
  req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method=method)
  try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      return resp.status, json.loads(resp.read() or b'{}')
  except urllib.error.HTTPError as err:
    body = err.read()
    try:
      return err.code, json.loads(body) if body else {}
    except ValueError:
      return err.code, {'raw': body[:200].decode(errors='replace')}
  except Exception as exc:
    return 0, {'error': '{}: {}'.format(type(exc).__name__, exc)[:200]}


def writer(node, others, args, out, stop):
  hkey = 'LOCALNET_PROBE_' + node['name'].upper().replace('-', '_')
  count = 0
  next_hsync = time.time() + args.hsync
  while not stop.is_set():
    started = time.time()
    count += 1
    key = 'p-{}'.format(count % args.keys)
    value = {'n': count, 't': started, 'pad': 'x' * args.bytes}
    code, body = call(node['ip'], 'hset', 'POST', timeout=args.timeout, hkey=hkey, key=key, value=value)
    took = time.time() - started
    ok = code == 200 and body.get('result') is True
    out.write(op='write', node=node['name'], ok=ok, s=round(took, 3), code=code,
              error=None if ok else str(body.get('error') or body.get('detail') or body.get('result'))[:160])
    if ok and others:
      threading.Thread(target=watch, args=(node, others, hkey, key, count, started, args, out), daemon=True).start()
    if time.time() >= next_hsync:
      next_hsync = time.time() + args.hsync
      began = time.time()
      code, body = call(node['ip'], 'hsync', 'POST', timeout=args.timeout, hkey=hkey)
      result = body.get('result') if isinstance(body, dict) else None
      out.write(op='hsync', node=node['name'], ok=code == 200 and isinstance(result, dict), s=round(time.time() - began, 3),
                code=code, merged=(result or {}).get('merged_fields') if isinstance(result, dict) else None)
    stop.wait(max(0.0, args.period - (time.time() - started)))
  return


def watch(node, others, hkey, key, count, started, args, out):
  """Record when the write becomes visible on each other node."""
  pending = {other['name']: other for other in others}
  deadline = started + args.replication_timeout
  while pending and time.time() < deadline:
    for name, other in list(pending.items()):
      code, body = call(other['ip'], 'hget', timeout=10, hkey=hkey, key=key)
      value = body.get('result') if isinstance(body, dict) else None
      if code == 200 and isinstance(value, dict) and value.get('n', -1) >= count:
        out.write(op='replicated', node=node['name'], to=name, ok=True, s=round(time.time() - started, 3))
        pending.pop(name)
    time.sleep(0.5)
  for name in pending:
    out.write(op='replicated', node=node['name'], to=name, ok=False, s=round(time.time() - started, 3))
  return


def main():
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  parser.add_argument('--period', type=float, default=20.0, help='seconds between writes of one node')
  parser.add_argument('--hsync', type=float, default=120.0, help='seconds between refreshes of one node')
  parser.add_argument('--bytes', type=int, default=600, help='size of the written value')
  parser.add_argument('--keys', type=int, default=50, help='distinct keys each writer cycles through')
  parser.add_argument('--timeout', type=float, default=60.0, help='client timeout of a write or refresh')
  parser.add_argument('--replication-timeout', type=float, default=60.0)
  parser.add_argument('--nodes', nargs='*', help='writer nodes (default: every node with the API)')
  parser.add_argument('--duration', type=float, default=0, help='stop after this many seconds (0: run until stopped)')
  args = parser.parse_args()

  manifest, _secrets = common.start(WHO)
  out = common.Recorder('cstore.jsonl')
  serving = [node for node in manifest['nodes'] if not node.get('headless')]
  writers = [node for node in serving if not args.nodes or node['name'] in args.nodes]
  stop = threading.Event()
  threads = []
  for idx, node in enumerate(writers):
    others = [other for other in serving if other['name'] != node['name']]
    thread = threading.Thread(target=writer, args=(node, others, args, out, stop), daemon=True)
    threads.append(thread)
    thread.start()
    time.sleep(args.period / max(1, len(writers)))  # spread the writers over the period
  common.say(WHO, 'writers on {}'.format(', '.join(node['name'] for node in writers)))
  started = time.time()
  try:
    while not args.duration or time.time() - started < args.duration:
      time.sleep(1)
  finally:
    stop.set()
  return


if __name__ == '__main__':
  main()
