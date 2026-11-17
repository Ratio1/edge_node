"""Shared helpers of the localnet host tool: paths, shell, docker."""

# SHA-256, the hash under the HMAC of sync_secret.
import hashlib
# The container-sync secret of a named set is an HMAC-SHA256 (sync_secret).
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # docker-compose/localnet

PROJECT = 'r1ln'
LABEL = 'r1.localnet'
SUBNET_PREFIX = '172.31.90'
SUBNET = SUBNET_PREFIX + '.0/24'

NODE_IMAGE = os.environ.get('R1_LOCALNET_NODE_IMAGE', 'ratio1/edge_node_gpu:mainnet')
EMQX_IMAGE = os.environ.get('R1_LOCALNET_EMQX_IMAGE', 'emqx/emqx:5.8.7')
NGINX_IMAGE = os.environ.get('R1_LOCALNET_NGINX_IMAGE', 'nginx:1.24')
PYTHON = '/opt/python/bin/python3'  # the production interpreter inside the node image


class LocalnetError(RuntimeError):
  pass


def log(msg):
  print('[localnet {}] {}'.format(time.strftime('%H:%M:%S'), msg), flush=True)
  return


def sh(*args, check=True, timeout=600, capture=True, stdin=None, env=None):
  proc = subprocess.run(
    [str(arg) for arg in args], check=False, timeout=timeout, text=True, errors='replace', input=stdin,
    stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None, env=env,
  )
  if check and proc.returncode != 0:
    raise LocalnetError('command failed ({}): {}\n{}'.format(
      proc.returncode, ' '.join(str(arg) for arg in args)[:400], (proc.stdout or '')[-3000:]))
  return proc


def ip(last):
  return '{}.{}'.format(SUBNET_PREFIX, last)


def container(name):
  return '{}-{}'.format(PROJECT, name)


class Home:
  """Folder layout of one localnet on the host."""

  def __init__(self, path=None):
    path = path or os.environ.get('R1_LOCALNET_HOME') or (Path.home() / '.cache' / 'r1-localnet')
    self.root = Path(path).resolve()
    self.src = self.root / 'src'
    self.run = self.root / 'run'
    self.results = self.root / 'results'
    return

  @property
  def manifest_path(self):
    return self.run / 'manifest.json'

  @property
  def secrets_path(self):
    return self.run / 'secrets.json'

  @property
  def compose_path(self):
    return self.run / 'compose.json'

  def load(self, path, default=None):
    path = Path(path)
    if not path.exists():
      if default is not None:
        return default
      raise LocalnetError('missing {} (run "init" first)'.format(path))
    return json.loads(path.read_text())

  def save(self, path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True))
    if private:
      os.chmod(path, 0o600)
    return

  def manifest(self):
    return self.load(self.manifest_path)

  def secrets(self):
    return self.load(self.secrets_path)


def compose(home, *args, timeout=900, check=True):
  return sh('docker', 'compose', '-p', PROJECT, '-f', home.compose_path, *args, timeout=timeout, check=check)


def tool_run(script, *, mounts=(), network='none', user=None, env=None, timeout=600, check=True, image=None, workdir=None):
  """Run a shell script in a throwaway container of the node image (no network unless asked)."""
  cmd = ['docker', 'run', '--rm', '--network', network, '--label', LABEL + '=tool', '--entrypoint', '/bin/sh']
  if user:
    cmd += ['-u', user]
  for src, dst, mode in mounts:
    cmd += ['-v', '{}:{}:{}'.format(src, dst, mode)]
  for key, val in (env or {}).items():
    cmd += ['-e', '{}={}'.format(key, val)]
  if workdir:
    cmd += ['-w', workdir]
  cmd += [image or NODE_IMAGE, '-c', script]
  return sh(*cmd, timeout=timeout, check=check)


def me():
  return '{}:{}'.format(os.getuid(), os.getgid())


def ctl_exec(*args, timeout=600, check=True, stdin=None):
  """Run a command in the control container, which sits on the isolated network."""
  cmd = ['docker', 'exec']
  if stdin is not None:
    cmd.append('-i')
  cmd += [container('ctl')] + [str(arg) for arg in args]
  return sh(*cmd, timeout=timeout, check=check, stdin=stdin)


def die(msg):
  print('localnet: ' + str(msg), file=sys.stderr, flush=True)
  sys.exit(2)


def sync_secret(secrets, name):
  """
  The container-sync secret of a named set on this localnet.

  The host tool (scan, custody check) and the Deeploy load generator (``sync-app --secret NAME``) both
  derive it from the cluster's private settings, so scenarios, journals and reports carry only the name
  and no secret value is ever written down.

  Parameters
  ----------
  secrets : dict
    The localnet's ``secrets.json`` (throwaway keys made by ``init``, readable by the operator only).
  name : str
    Name of the set's secret; another name gives another, equally valid secret.

  Returns
  -------
  str
    64 lowercase hex characters, the format a node accepts as ``R1EN_SYNC_SECRET``.

  Examples
  --------
  >>> len(sync_secret({'relay': {'k': 'v'}}, 's1'))
  64
  >>> sync_secret({'relay': {'k': 'v'}}, 's1') == sync_secret({'relay': {'k': 'v'}}, 's2')
  False
  """
  # The canonical text of the cluster's settings keys the HMAC: the same file gives the same value on both sides.
  material = json.dumps(secrets, sort_keys=True).encode()
  # HMAC-SHA256 of the name, in hex: 32 bytes as 64 lowercase hex characters.
  return hmac.new(material, b'container-sync-secret:' + name.encode(), hashlib.sha256).hexdigest()


# The seed variable of the oracle-only secret (the SDK's ``dAuth.DAUTH_ORACLE_SECRET_ENV_KEY``, from SDK 3.5.72).
ORACLE_SECRET_ENV = 'EE_ORACLE_R1FS_SECRET'


def osec_check(value):
  """
  Oracle secret check: a short hash of an oracle-only secret, so two values can be compared without writing either.

  The node probe (``node/probe.py``, which imports nothing from this package) computes the same hash of the value a
  node holds in memory; the host computes it of the value ``init --oracle-secret NAME`` gave the seeds. The context
  prefix keeps it apart from every form ``sync_needles`` scans for (the value, its SHA-256 and the MAC subkey).

  Parameters
  ----------
  value : str
    The secret.

  Returns
  -------
  str
    12 lowercase hex characters.

  Examples
  --------
  >>> osec_check('ab' * 32) == osec_check('ab' * 32), osec_check('ab' * 32) == osec_check('cd' * 32)
  (True, False)
  """
  # SHA-256 of a fixed context and the value, cut to 48 bits: enough to tell two values apart, useless to find one.
  return hashlib.sha256(b'localnet-osec-check:' + value.encode()).hexdigest()[:12]
