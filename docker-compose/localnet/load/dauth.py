#!/usr/bin/env python3
"""
dAuth traffic of running jobs, and a probe of what a starting node experiences.

Two kinds of requests, both sent through the SDK calls a node uses and
through the public dAuth name:

  * ``get_secrets`` from nodes that ask for the secrets of an old-style job
    they do not run. On mainnet these are the bulk of secret requests. For
    such a job dAuth has to read the job's pipeline document from R1FS
    before it can tell whether the sender runs it. The localnet seeds
    old-style job pointers whose documents no node has (``legacy_jobs`` in
    the manifest), which is the worst case: the read cannot succeed.
  * ``get_auth_data`` from a licensed node, at a slow steady rate, as a
    probe: this is the request every node makes when it starts, and its
    latency and failures are what an operator notices.

Output: ``/out/dauth.jsonl``, one line per request.
"""

import argparse
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import common

WHO = 'dauth'


def main():
  parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
  parser.add_argument('--secrets-rate', type=float, default=0.4, help='old-style get_secrets requests per second (mainnet: about 0.4)')
  parser.add_argument('--probe-period', type=float, default=10.0, help='seconds between start-up probes (0: none)')
  parser.add_argument('--senders', type=int, default=40, help='emulated nodes that send the secret requests')
  parser.add_argument('--timeout', type=float, default=120.0, help='read timeout of one request')
  parser.add_argument('--versions', default='2.10.690,7.7.352,3.5.67')
  parser.add_argument('--keys', default='/fleet')
  parser.add_argument('--duration', type=float, default=0)
  args = parser.parse_args()

  manifest, _secrets = common.start(WHO)
  out = common.Recorder('dauth.jsonl')
  fleet = [item for item in manifest.get('fleet') or [] if not item['revoked']]
  senders = [common.engine(args.keys, item['name']) for item in fleet[-args.senders:]]
  prober = common.engine(args.keys, fleet[0]['name'])
  jobs = list(manifest.get('legacy_jobs') or [])
  app_ver, core_ver, sdk_ver = args.versions.split(',')
  pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix='req')
  pending = {'secrets': 0, 'probe': 0}
  lock = threading.Lock()

  def secrets(engine, job_id):
    started = time.time()
    outcome, detail = 'ok', ''
    try:
      engine.get_dauth_job_secret_bundle(job_id, request_timeout=(10, args.timeout))
    except ValueError as exc:
      outcome, detail = 'refused', str(exc)[:140]
    except Exception as exc:
      outcome, detail = 'unavailable', '{}: {}'.format(type(exc).__name__, exc)[:140]
    out.write(kind='get_secrets', job=job_id, outcome=outcome, s=round(time.time() - started, 3), detail=detail)
    with lock:
      pending['secrets'] -= 1
    return

  def probe():
    started = time.time()
    outcome, detail = 'failed', ''
    try:
      result = prober.dauth_autocomplete(
        add_env=False, debug=False, max_tries=1, return_full_data=True, debug_data=True,
        request_timeout=(10, args.timeout), sender_alias='probe',
        sender_app_ver=app_ver, sender_core_ver=core_ver, sender_sdk_ver=sdk_ver,
      )
      outcome, detail = common.auth_outcome(result)
    except Exception as exc:
      detail = '{}: {}'.format(type(exc).__name__, exc)[:140]
    out.write(kind='get_auth_data', outcome=outcome, s=round(time.time() - started, 3), detail=detail)
    with lock:
      pending['probe'] -= 1
    return

  common.say(WHO, '{} senders, {} old-style jobs, {} secret requests/s, probe every {} s'.format(
    len(senders), len(jobs), args.secrets_rate, args.probe_period))
  started = time.time()
  next_secret = started + 1
  next_probe = started + 2
  last_report = started
  sent = {'secrets': 0, 'probe': 0}
  while not args.duration or time.time() - started < args.duration:
    now = time.time()
    if jobs and args.secrets_rate > 0 and now >= next_secret:
      next_secret += random.expovariate(args.secrets_rate)
      with lock:
        pending['secrets'] += 1
      sent['secrets'] += 1
      pool.submit(secrets, random.choice(senders), random.choice(jobs))
    if args.probe_period > 0 and now >= next_probe:
      next_probe += args.probe_period
      with lock:
        busy = pending['probe']
        pending['probe'] += 1
      sent['probe'] += 1
      if busy < 16:
        pool.submit(probe)
      else:
        out.write(kind='get_auth_data', outcome='failed', s=None, detail='16 probes still waiting')
        with lock:
          pending['probe'] -= 1
    if now - last_report >= 30:
      last_report = now
      common.say(WHO, 'sent {} | waiting for an answer {}'.format(sent, dict(pending)))
    time.sleep(0.05)
  return 0


if __name__ == '__main__':
  raise SystemExit(main())
