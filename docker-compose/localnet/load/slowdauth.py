#!/usr/bin/env python3
"""
A dAuth server that answers late: holds each request, then passes it to a real dAuth oracle.

A Deeploy create request calls dAuth ("prepare") on the API oracle's plugin thread, inside its endpoint, and
waits for the answer (the SDK's read timeout is 60 s). With the front's dAuth name pinned to this relay for
that oracle's address (scenario step ``pin`` with ``client`` and ``to``), the endpoint is held for ``--hold``
seconds by a dependency that is slow, as a saturated dAuth oracle is, and no node code is changed. Every
request is passed on unchanged once its hold is over, and the oracle's answer is returned as it came.

Output: one JSON line per request on stdout and in ``/out/slowdauth.jsonl`` (path, arrival, hold, status).
"""

# The command line.
import argparse
# Each request's line, and an error answer.
import json
# The exit code.
import sys
# The hold, and the times in each line.
import time
# An error answer of the oracle is passed back as it came.
import urllib.error
# The request passed on to the oracle.
import urllib.request
# One thread per request: a held request must not hold the next one.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Isolation proof and the JSON-lines recorder shared by the generators.
import common

# This generator's name in its log lines and isolation proof.
WHO = 'slowdauth'
# The port dAuth listens on, so the front's pin can name this relay as it names an oracle.
PORT = 31301


def handler(target, hold, out):
  """
  The request handler class of the relay.

  Parameters
  ----------
  target : str
    ``ip:port`` of the real dAuth oracle every request is passed to.
  hold : float
    Seconds each request is held before it is passed on.
  out : common.Recorder
    Where each request's line is written.

  Returns
  -------
  type
    A ``BaseHTTPRequestHandler`` subclass for ``ThreadingHTTPServer``.

  Examples
  --------
  >>> ThreadingHTTPServer(('0.0.0.0', PORT), handler('172.31.90.52:31301', 45, out))   # doctest: +SKIP
  """

  class Relay(BaseHTTPRequestHandler):
    """Holds a request, passes it to the target oracle and returns its answer."""

    def log_message(self, *args):
      """
      Leave the standard per-request log line out (each request has its JSON line).

      Parameters
      ----------
      *args : tuple
        The standard log arguments, ignored.

      Returns
      -------
      None

      Examples
      --------
      >>> self.log_message('%s', 'x')
      """
      return

    def _relay(self, method):
      """
      Hold, pass on, answer.

      Parameters
      ----------
      method : str
        ``GET`` or ``POST``.

      Returns
      -------
      None

      Examples
      --------
      >>> self._relay('POST')   # held for --hold seconds, then answered as the target answered
      """
      # When the request came in.
      arrived = time.time()
      # The request body, passed on unchanged.
      body = self.rfile.read(int(self.headers.get('Content-Length') or 0)) if method == 'POST' else None
      # The hold: what a dAuth oracle that answers late costs the caller.
      time.sleep(hold)
      # The same path and body, to the real oracle.
      req = urllib.request.Request('http://{}{}'.format(target, self.path), data=body, method=method,
                                   headers={'Content-Type': self.headers.get('Content-Type') or 'application/json'})
      try:
        # The oracle answers as it would have without the hold.
        with urllib.request.urlopen(req, timeout=120) as resp:
          # The oracle's answer, as it came.
          code, raw = resp.status, resp.read()
      except urllib.error.HTTPError as err:
        # An error answer is returned as it came too.
        code, raw = err.code, err.read()
      except OSError as exc:
        # The oracle did not answer: the caller gets 502, as from the front.
        code, raw = 502, json.dumps({'error': '{}: {}'.format(type(exc).__name__, exc)[:200]}).encode()
      # The status line of the answer.
      self.send_response(code)
      # dAuth answers JSON.
      self.send_header('Content-Type', 'application/json')
      # The body's length, so the caller reads it whole.
      self.send_header('Content-Length', str(len(raw)))
      # End of the headers.
      self.end_headers()
      # The oracle's body.
      self.wfile.write(raw)
      # One line per request: what was held, for how long, and how it ended.
      row = dict(path=self.path, method=method, arrived=round(arrived, 3), hold=hold,
                 answered=round(time.time(), 3), status=code)
      # Kept in the generator's output folder.
      out.write(**row)
      print(json.dumps(row), flush=True)
      return

    def do_POST(self):
      """
      A POST request (dAuth's endpoints are POST).

      Returns
      -------
      None

      Examples
      --------
      >>> self.do_POST()
      """
      # Held and passed on.
      return self._relay('POST')

    def do_GET(self):
      """
      A GET request.

      Returns
      -------
      None

      Examples
      --------
      >>> self.do_GET()
      """
      # Held and passed on.
      return self._relay('GET')

  # The class, bound to this target, hold and recorder.
  return Relay


def main():
  """
  Command line of the relay: serve until stopped.

  Returns
  -------
  int
    0 (it runs until the container is removed).

  Examples
  --------
  >>> sys.argv = ['slowdauth.py', '--target', '172.31.90.52:31301', '--hold', '45']
  >>> main()   # doctest: +SKIP
  """
  # The relay's options.
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  # The real dAuth oracle behind the relay.
  parser.add_argument('--target', required=True, help='ip:port of the dAuth oracle requests are passed to')
  # How long each request waits before it is passed on.
  parser.add_argument('--hold', type=float, default=45.0, help='seconds each request is held (default 45)')
  # The options given.
  args = parser.parse_args()
  # Proves isolation first, as every process of the test bed does.
  common.start(WHO)
  # Every request's line, kept with the generator's output.
  out = common.Recorder('slowdauth.jsonl')
  # Every address of this container, dAuth's port.
  server = ThreadingHTTPServer(('0.0.0.0', PORT), handler(args.target, args.hold, out))
  # What the relay does, in its log.
  common.say(WHO, 'holding every request {} s, then passing it to {}'.format(args.hold, args.target))
  # Until the container is removed.
  server.serve_forever()
  # Not reached: serve_forever returns only on shutdown.
  return 0


if __name__ == '__main__':
  # The relay runs until it is stopped.
  sys.exit(main())
