"""Run the load generators of ``load/`` as containers on the isolated network."""

import os

from .common import HERE, LABEL, NODE_IMAGE, PROJECT, PYTHON, LocalnetError, container, ip, sh
from .nodes import FLEET_VOLUME

# The generators of load/, among them the one-write CStore client and the late-answering dAuth relay.
GENERATORS = ('fleet', 'cstore', 'dauth', 'deeploy', 'probe', 'cstore_put', 'slowdauth')
# Fixed addresses: the front can then send one generator's requests to a chosen oracle (see "pin"), and the
# late-answering dAuth relay has an address the front's pin can name.
ADDRESS = {'fleet': ip(211), 'cstore': ip(212), 'dauth': ip(213), 'deeploy': ip(214), 'slowdauth': ip(215)}


def name_of(generator, tag=None):
  return container('load-{}{}'.format(generator, '-' + tag if tag else ''))


def start(home, generator, args=(), tag=None, cpuset=None, detach=True, timeout=3600):
  manifest = home.manifest()
  script = HERE / 'load' / (generator + '.py')
  if not script.exists():
    raise LocalnetError('unknown load generator "{}" (have: {})'.format(generator, ', '.join(GENERATORS)))
  cname = name_of(generator, tag)
  out = home.run / 'out' / ('load-{}{}'.format(generator, '-' + tag if tag else ''))
  out.mkdir(parents=True, exist_ok=True)
  os.chmod(out, 0o777)
  arm = manifest['nodes'][0]['arm']
  sh('docker', 'rm', '-f', cname, check=False)
  cmd = [
    'docker', 'run', '--name', cname, '--hostname', cname, '--network', PROJECT,
    '--label', LABEL + '=load', '--label', LABEL + '.generator=' + generator,
    '-e', 'R1_LOCALNET=1', '-e', 'EE_EVM_NET=' + manifest['evm_net'], '-e', 'PYTHONDONTWRITEBYTECODE=1',
    '-e', 'PYTHONPATH=/opt/r1src/sdk:/opt/localnet/load', '-e', 'SSL_CERT_FILE=/run/localnet/mqtt-ca.crt',
    '-e', 'PYTHONUNBUFFERED=1',
    '-v', '{}:/opt/localnet:ro'.format(HERE),
    '-v', '{}:/opt/r1src/sdk:ro'.format(home.src / arm / 'sdk'),
    '-v', '{}:/run/localnet/manifest.json:ro'.format(home.manifest_path),
    '-v', '{}:/run/localnet/secrets.json:ro'.format(home.secrets_path),
    '-v', '{}:/run/localnet/registry.json:ro'.format(home.run / 'registry.json'),
    '-v', '{}:/run/localnet/mqtt-ca.crt:ro'.format(home.run / 'brokers' / 'mqtt-ca.crt'),
    '-v', '{}:/fleet'.format(FLEET_VOLUME),
    '-v', '{}:/out'.format(out),
    '--entrypoint', PYTHON,
  ]
  if generator in ADDRESS and tag in (None, 'run'):
    cmd += ['--ip', ADDRESS[generator]]
  if cpuset or manifest.get('cpus', {}).get('infra'):
    cmd += ['--cpuset-cpus', cpuset or manifest['cpus']['infra']]
  cmd.insert(2, '-d' if detach else '--rm')
  cmd += [NODE_IMAGE, '/opt/localnet/load/{}.py'.format(generator)] + [str(arg) for arg in args]
  proc = sh(*cmd, timeout=timeout, check=False)
  if proc.returncode != 0:
    raise LocalnetError('load generator {} failed:\n{}'.format(generator, (proc.stdout or '')[-3000:]))
  return cname if detach else proc.stdout


def stop(generator=None, tag=None):
  if generator:
    sh('docker', 'rm', '-f', name_of(generator, tag), check=False)
    return
  running = sh('docker', 'ps', '-aq', '--filter', 'label=' + LABEL + '=load', check=False).stdout.split()
  if running:
    sh('docker', 'rm', '-f', *running, check=False)
  return


def logs(generator, tag=None, tail=40):
  return sh('docker', 'logs', '--tail', str(tail), name_of(generator, tag), check=False).stdout or ''
