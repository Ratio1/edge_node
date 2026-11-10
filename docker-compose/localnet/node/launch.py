#!/usr/bin/env python3
"""
Start one localnet node (test bed only).

This is ``device.py`` for the localnet. It runs the production entry point
``naeural_core.main.entrypoint.main`` with the production start-up and
application configuration files, and differs from production in four ways:

  1. it refuses to start unless the container is provably cut off from
     every public network (``guard.py``);
  2. the node code comes from three source trees mounted read-only (SDK,
     core, edge_node) instead of the packages baked into the image, so an
     old and a new version can run side by side;
  3. the answers of the blockchain (oracle registry, licences, jobs) and
     the web addresses of the network services come from the localnet
     (``chain_shim.py``), because the real ones are not reachable;
  4. no extra Python package is installed at start (production installs
     ``llama-cpp-python`` from the internet).

A sampler thread (``probe.py``) records plugin queue and loop counters.
"""

import multiprocessing as mp
import os
import shutil
import sys
import warnings

TOOLS = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('R1_LOCALNET_SRC', '/opt/r1src')
APP = '/edge_node'
OUT = os.environ.get('R1_LOCALNET_OUT', '/out')


def say(msg):
  print('[launch] ' + msg, flush=True)
  return


def stage_app_tree():
  """Replace the image's edge_node tree with the mounted one, keeping the data folder."""
  source = os.path.join(SRC, 'edge')
  for item in os.listdir(APP):
    if item == '_local_cache':
      continue
    path = os.path.join(APP, item)
    if os.path.isdir(path) and not os.path.islink(path):
      shutil.rmtree(path)
    else:
      os.remove(path)
  for item in os.listdir(source):
    if item in ('_local_cache', '.git'):
      continue
    src, dst = os.path.join(source, item), os.path.join(APP, item)
    if os.path.isdir(src):
      shutil.copytree(src, dst, symlinks=True)
    else:
      shutil.copy2(src, dst)
  return


def apply_startup_overrides():
  """
  Merge the localnet settings into the production start-up configuration of this source tree.

  The only settings added are fixed ports for the web plugins and "no tunnel": mainnet publishes those
  plugins through Cloudflare tunnels, the localnet through its own front service.
  """
  import json
  try:
    with open('/run/localnet/node.json', 'rt') as fh:
      overrides = json.load(fh).get('startup') or {}
  except FileNotFoundError:
    return
  path = os.path.join(APP, '.config_startup.json')
  with open(path, 'rt') as fh:
    config = json.load(fh)
  for key, value in overrides.items():
    if isinstance(value, dict) and isinstance(config.get(key), dict):
      for sub_key, sub_value in value.items():
        if isinstance(sub_value, dict) and isinstance(config[key].get(sub_key), dict):
          config[key][sub_key].update(sub_value)
        else:
          config[key][sub_key] = sub_value
    else:
      config[key] = value
  with open(path, 'wt') as fh:
    json.dump(config, fh, indent=2)
  # The node keeps the first start-up configuration it saw in its data folder and ignores later
  # changes. Drop that copy so every start uses the file of the source tree it runs.
  cached = os.path.join(APP, '_local_cache', 'config_startup.json')
  if os.path.exists(cached):
    os.remove(cached)
  say('start-up configuration: production file plus localnet overrides for {}'.format(sorted(overrides)))
  return


def check_overlay():
  """Fail loudly if any of the three packages would be imported from the image instead of the overlay."""
  import importlib.util
  expected = {
    'ratio1': os.path.join(SRC, 'sdk'),
    'naeural_core': os.path.join(SRC, 'core'),
    'extensions': APP,
  }
  for name, root in expected.items():
    spec = importlib.util.find_spec(name)
    origin = (spec.origin or (list(spec.submodule_search_locations or [''])[0])) if spec else None
    if not origin or not os.path.abspath(origin).startswith(os.path.abspath(root) + os.sep):
      say('REFUSING TO START: package {} resolves to {} instead of {}'.format(name, origin, root))
      os._exit(96)
  revs = {}
  for part in ('sdk', 'core', 'edge'):
    try:
      with open(os.path.join(SRC, part, '.localnet_rev'), 'rt') as fh:
        revs[part] = fh.read().strip()
    except Exception:
      revs[part] = 'unknown'
  say('source trees: ' + ', '.join('{}={}'.format(key, val) for key, val in sorted(revs.items())))
  return revs


def run():
  warnings.filterwarnings('ignore')
  sys.path.insert(0, TOOLS)
  import guard
  guard.enforce(who='launch')

  stage_app_tree()
  apply_startup_overrides()
  os.chdir(APP)
  # Production runs /edge_node/device.py, so /edge_node is the first import root. Keep that order;
  # the SDK and core overlays follow through PYTHONPATH, ahead of the packages in the image.
  sys.path.remove(TOOLS)
  sys.path.insert(0, APP)
  for part in ('core', 'sdk'):
    root = os.path.join(SRC, part)
    if root in sys.path:
      sys.path.remove(root)
    sys.path.insert(1, root)
  check_overlay()

  sys.path.append(TOOLS)
  import chain_shim
  chain_shim.install()

  # The first node import is the one device.py makes, so that modules load in the production order.
  import naeural_core.main.entrypoint as entrypoint
  chain_shim.verify()

  import probe
  sampler = probe.Probe(out_path=os.path.join(OUT, 'probe.jsonl'), period=float(os.environ.get('R1_LOCALNET_PROBE_PERIOD', '5')))
  sampler.install_counters()
  sampler.start()

  real_orchestrator = entrypoint.Orchestrator

  def orchestrator(*args, **kwargs):
    eng = real_orchestrator(*args, **kwargs)
    sampler.attach(eng)
    return eng

  entrypoint.Orchestrator = orchestrator

  mp.set_start_method('spawn')
  exit_code, _eng = entrypoint.main(additional_packages=[])
  say('node main loop returned {}'.format(exit_code))
  sys.stdout.flush()
  os._exit(exit_code)


if __name__ == '__main__':
  run()
