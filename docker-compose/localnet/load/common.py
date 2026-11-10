"""Shared helpers of the localnet load generators. They run in containers on the isolated network."""

import json
import os
import sys
import threading
import time

sys.path.insert(0, '/opt/localnet/node')
import guard  # noqa: E402

MANIFEST = '/run/localnet/manifest.json'
SECRETS = '/run/localnet/secrets.json'
OUT = os.environ.get('R1_LOCALNET_OUT', '/out')


def start(who):
  """Prove isolation, point the SDK tables at the localnet, return (manifest, secrets)."""
  guard.enforce(who=who)
  import chain_shim
  chain_shim.install()
  with open(MANIFEST, 'rt') as fh:
    manifest = json.load(fh)
  with open(SECRETS, 'rt') as fh:
    secrets = json.load(fh)
  return manifest, secrets


def say(who, msg):
  print('[{} {}] {}'.format(who, time.strftime('%H:%M:%S'), msg), flush=True)
  return


class Recorder:
  """Append-only JSON lines file shared by threads."""

  def __init__(self, name):
    os.makedirs(OUT, exist_ok=True)
    self._fh = open(os.path.join(OUT, name), 'at', buffering=1)
    self._lock = threading.Lock()
    return

  def write(self, **row):
    row.setdefault('t', round(time.time(), 3))
    line = json.dumps(row, separators=(',', ':'))
    with self._lock:
      self._fh.write(line + '\n')
    return


def engine(root, name):
  """Load the identity ``name`` created by ctl/keygen.py under ``root``."""
  from ratio1 import Logger
  from ratio1.bc import DefaultBlockEngine
  folder = os.path.join(root, name)
  cwd = os.getcwd()
  os.chdir(folder)
  try:
    log = Logger('LG', base_folder='.', app_folder='_local_cache', silent=True)
    return DefaultBlockEngine(
      log=log, name=name, config={'PEM_FILE': 'e2.pem', 'PASSWORD': None, 'PEM_LOCATION': 'data'},
    )
  finally:
    os.chdir(cwd)


def mqtt_client(client_id, host, secrets, on_message=None, keepalive=60):
  import paho.mqtt.client as mqtt
  client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=True)
  client.username_pw_set(secrets['mesh']['client_username'], secrets['mesh']['client_password'])
  client.tls_set('/run/localnet/mqtt-ca.crt')
  if on_message is not None:
    client.on_message = on_message
  client.connect_async(host, 8883, keepalive)
  return client


def percentile(values, pct):
  if not values:
    return None
  ordered = sorted(values)
  return ordered[min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))]


def auth_outcome(result):
  """Classify what ``dauth_autocomplete(return_full_data=True)`` returned: ('ok' | 'refused' | 'failed', detail)."""
  if not isinstance(result, dict) or not result:
    return 'failed', 'no answer'
  inner = result.get('result') if isinstance(result.get('result'), dict) else result
  auth = inner.get('auth') if isinstance(inner.get('auth'), dict) else inner
  if any(str(key).startswith('EE_') and str(key) not in ('EE_SIGN', 'EE_SENDER', 'EE_ETH_SENDER', 'EE_ETH_SIGN', 'EE_HASH')
         for key in auth):
    return 'ok', ''
  error = auth.get('error') or inner.get('error')
  if error:
    return 'refused', str(error)[:120]
  return 'failed', str(result)[:120]
