"""Shared helpers of the localnet host tool: paths, shell, docker."""

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
