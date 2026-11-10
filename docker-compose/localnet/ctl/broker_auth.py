"""
Create the MQTT authenticator and users on every localnet broker, the way the
mainnet install playbook does: a built-in password database with one bridge
user and one client user. Runs inside the control container.
"""

import base64
import json
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, '/opt/localnet/node')
import guard  # noqa: E402


def api(host, secrets, method, path, body=None, timeout=5):
  req = urllib.request.Request(
    'http://{}:18083/api/v5{}'.format(host, path), method=method,
    data=json.dumps(body).encode() if body is not None else None)
  token = base64.b64encode('{}:{}'.format(secrets['api_key'], secrets['api_secret']).encode()).decode()
  req.add_header('Authorization', 'Basic ' + token)
  req.add_header('Content-Type', 'application/json')
  try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      raw = resp.read()
      try:
        return resp.status, (json.loads(raw) if raw else None)
      except ValueError:
        return resp.status, raw.decode(errors='replace')
  except urllib.error.HTTPError as exc:
    return exc.code, None


def wait_api(host, secrets, timeout=120):
  end = time.time() + timeout
  while time.time() < end:
    try:
      code, _ = api(host, secrets, 'GET', '/status')
      if code == 200:
        return
    except Exception:
      pass
    time.sleep(2)
  raise RuntimeError('EMQX API on {} not ready'.format(host))


def main():
  guard.enforce(who='broker_auth')
  manifest = json.load(open('/run/localnet/manifest.json'))
  secrets = json.load(open('/run/localnet/secrets.json'))['mesh']
  users_path = '/authentication/password_based%3Abuilt_in_database/users'
  for broker in manifest['mesh']['brokers']:
    wait_api(broker, secrets)
    api(broker, secrets, 'POST', '/authentication', {
      'mechanism': 'password_based', 'backend': 'built_in_database', 'user_id_type': 'username',
      'password_hash_algorithm': {'name': 'sha256'}})
    for user, pwd in ((secrets['bridge_username'], secrets['bridge_password']),
                      (secrets['client_username'], secrets['client_password'])):
      code, _ = api(broker, secrets, 'POST', users_path, {'user_id': user, 'password': pwd})
      if code not in (200, 201, 204, 409):
        api(broker, secrets, 'PUT', '{}/{}'.format(users_path, user), {'password': pwd})
    print('broker {}: authenticator and users ready'.format(broker), flush=True)
  return 0


if __name__ == '__main__':
  sys.exit(main())
