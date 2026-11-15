#!/usr/bin/env python3
"""
One write through a node's own CStore API: a value of a given size or nesting depth.

For the record size cap and the depth bound of the chain store: the value is built here (random printable
text of ``--bytes`` characters, or dicts nested ``--depth`` levels deep, the outermost counted as the first)
and written with the API's ``hset`` (or ``set`` for a plain key) on the named node, which must run the CStore
API. The API's answer is printed as one JSON line with the value's size, and the line is kept in
``/out/cstore_put.jsonl``.
"""

# The command line.
import argparse
# The value's size is measured as compact JSON, and the answer is printed as JSON.
import json
# Random text compresses little, like real configuration text.
import random
# The alphabet of that text.
import string
# The exit code.
import sys
# How long the API took to answer.
import time

# Isolation proof, manifest and the JSON-lines recorder shared by the generators.
import common
# The API call and port of the chain-store load generator.
from cstore import PORT, call

# This generator's name in its log lines and isolation proof.
WHO = 'cstore_put'


def nested(depth):
  """
  A value of dicts nested ``depth`` levels deep, the outermost counted as the first.

  Parameters
  ----------
  depth : int
    Levels, at least 1.

  Returns
  -------
  dict
    ``{"d": {"d": ... {"leaf": 1}}}`` with ``depth`` dicts.

  Examples
  --------
  >>> nested(2)
  {'d': {'leaf': 1}}
  """
  # The innermost dict is the first level counted from inside.
  value = {'leaf': 1}
  # One more level per pass.
  for _level in range(depth - 1):
    # One more dict around it.
    value = {'d': value}
  # The outermost dict.
  return value


def main():
  """
  Command line: one write, its answer printed.

  Returns
  -------
  int
    0 when the API answered (whatever the result), 1 when it could not be reached.

  Examples
  --------
  >>> sys.argv = ['cstore_put.py', '--node', 'r1w-01', '--hkey', 'LNET_CAP_TEST', '--key', 'under', '--bytes', '523000']
  >>> main()
  0
  """
  # The options of one write.
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  # The writer: a node that runs the CStore API.
  parser.add_argument('--node', required=True, help='node whose CStore API writes')
  # A hash namespace and field, or a plain key with --plain.
  parser.add_argument('--hkey', help='hash namespace (hset); leave out with --plain')
  # The field of the namespace, or the plain key.
  parser.add_argument('--key', required=True, help='field of the namespace, or the plain key')
  # A plain key goes through the API's set.
  parser.add_argument('--plain', action='store_true', help='write a plain key with set')
  # The value: a size or a depth.
  parser.add_argument('--bytes', type=int, default=0, help='random printable text of this many characters')
  # A nested value instead of text.
  parser.add_argument('--depth', type=int, default=0, help='dicts nested this many levels instead')
  # Long enough for a write that waits for its confirmations three times.
  parser.add_argument('--timeout', type=float, default=120.0, help='client timeout of the write')
  # The options given.
  args = parser.parse_args()
  # Isolation proven first; the manifest gives the writer's address.
  manifest, _secrets = common.start(WHO)
  # Every write's line, kept with the generator's output.
  out = common.Recorder('cstore_put.jsonl')
  # The writer's address in the manifest.
  node = next(item for item in manifest['nodes'] if item['name'] == args.node)
  # Random letters and digits compress little, like real configuration text.
  value = nested(args.depth) if args.depth else ''.join(random.choices(string.ascii_letters + string.digits, k=args.bytes))
  # The value's size as compact JSON, the form the chain store measures.
  size = len(json.dumps(value, separators=(',', ':')).encode('utf-8'))
  # When the write was sent.
  started = time.time()
  if args.plain:
    # A plain key, through the API's set.
    code, body = call(node['ip'], 'set', 'POST', timeout=args.timeout, key=args.key, value=value)
  else:
    # A field of a hash namespace, through hset.
    code, body = call(node['ip'], 'hset', 'POST', timeout=args.timeout, hkey=args.hkey, key=args.key, value=value)
  # The answer, without echoing the value.
  row = dict(node=args.node, port=PORT, hkey=args.hkey, key=args.key, value_json_bytes=size, depth=args.depth or None,
             http=code, s=round(time.time() - started, 3), answer=json.dumps(body)[:400])
  # Kept in the generator's output folder.
  out.write(**row)
  print(json.dumps(row), flush=True)
  # 1 only when the API could not be reached at all.
  return 0 if code else 1


if __name__ == '__main__':
  # The exit code tells the scenario whether the API answered.
  sys.exit(main())
