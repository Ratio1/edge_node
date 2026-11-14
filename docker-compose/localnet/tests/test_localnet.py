"""
Checks of the localnet tool itself. No container is started.

Run from the repository root, inside the node image or any interpreter that
has web3's helper packages (``eth_abi``, ``eth_utils``):

    R1_LOCALNET_SDK=/path/to/ratio1_sdk python3 -m unittest docker-compose/localnet/tests/test_localnet.py

Tests that need the SDK tree or those packages are skipped when they are
missing.
"""

import glob
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
for folder in ('', 'node', 'ctl', 'infra'):
  sys.path.insert(0, str(HERE / folder))

SDK = os.environ.get('R1_LOCALNET_SDK', '/opt/r1src/sdk')
HAS_SDK = os.path.exists(os.path.join(SDK, 'ratio1', 'const', 'evm_net.py'))
try:
  import eth_abi  # noqa: F401
  HAS_ETH = True
except Exception:
  HAS_ETH = False


class TestGuard(unittest.TestCase):

  def test_a_process_not_started_by_the_test_bed_is_refused(self):
    import guard
    saved = os.environ.pop('R1_LOCALNET', None)
    try:
      self.assertTrue(any('R1_LOCALNET' in problem for problem in guard.check()))
    finally:
      if saved is not None:
        os.environ['R1_LOCALNET'] = saved

  def test_unknown_network_name_is_refused(self):
    import guard
    saved = {key: os.environ.get(key) for key in ('R1_LOCALNET', 'EE_EVM_NET')}
    os.environ.update(R1_LOCALNET='1', EE_EVM_NET='somewhere')
    try:
      self.assertTrue(any('EE_EVM_NET' in problem for problem in guard.check()))
    finally:
      for key, val in saved.items():
        os.environ.pop(key, None) if val is None else os.environ.__setitem__(key, val)


class TestTopology(unittest.TestCase):

  def test_mainnet_shape(self):
    from lnlib import nodes
    plan = nodes.plan(oracles=11, workers=2, full_oracles=4)
    self.assertEqual([node['name'] for node in plan[:4]], ['r1s-01', 'r1s-02', 'r1s-03', 'r1s-04'])
    self.assertEqual([node['role'] for node in plan].count('seed'), 4)
    self.assertEqual(sum(1 for node in plan if node['role'] in ('seed', 'oracle')), 11)
    self.assertEqual([node.get('headless', False) for node in plan if node['role'] == 'oracle'], [True] * 7)
    self.assertFalse(any(node.get('headless') for node in plan if node['role'] == 'seed'))
    self.assertEqual(len({node['ip'] for node in plan}), len(plan))
    self.assertEqual([node.get('headless') for node in plan if node['role'] == 'worker'], [False, True])

  def test_only_seeds_carry_their_settings(self):
    from lnlib import nodes
    plan = nodes.plan(oracles=5, workers=1)
    for node in plan:
      node.update(address='0xai_x', eth_address='0x0')
    manifest = {
      'mesh': {'brokers': {name: {'ip': '10.0.0.%d' % idx} for idx, name in enumerate(('emqx-a', 'emqx-b', 'emqx-c', 'emqx-d'))}},
      'relays': {name: {'multiaddr': '/ip4/1/tcp/4001/p2p/x', 'api': 'https://x', 'cert_b64': 'c'} for name in ('relay-03', 'relay-04')},
      'revoked_addresses': ['0xai_r'],
    }
    secrets = {'mesh': {'client_username': 'u', 'client_password': 'p'},
               'relay': {'relay_api_key_b64': 'k', 'swarm_key_b64': 's'}}
    seed_env = nodes.node_env(plan[0], manifest, secrets)
    other_env = nodes.node_env(plan[4], manifest, secrets)
    self.assertEqual(seed_env['EE_DAUTH_URL'], 'seed_node')
    self.assertIn('EE_MQTT_HOST', seed_env)
    self.assertEqual(seed_env['EE_REVOKED_NODE_ADDRESSES'], '0xai_r')
    for key in ('EE_MQTT_HOST', 'EE_MQTT', 'EE_SUPERVISOR', 'EE_DAUTH_URL', 'EE_SWARM_KEY_CONTENT_BASE64'):
      self.assertNotIn(key, other_env)  # a node that is not a seed gets these from dAuth

  def test_headless_nodes_disable_only_web_plugins(self):
    from lnlib import nodes
    overrides = nodes._startup_overrides({'headless': True})['ADMIN_PIPELINE']
    self.assertTrue(all(overrides[name].get('DISABLED') for name in nodes.WEB_PLUGIN_SIGNATURES))
    self.assertNotIn('CHAIN_STORE_BASE', overrides)
    self.assertNotIn('NET_MON_01', overrides)
    full = nodes._startup_overrides({})['ADMIN_PIPELINE']
    self.assertFalse(any(item.get('DISABLED') for item in full.values()))
    self.assertFalse(full['DAUTH_MANAGER']['TUNNEL_ENGINE_ENABLED'])


class TestSeeding(unittest.TestCase):

  def test_replica_is_the_same_for_every_oracle_and_of_production_size(self):
    import seed_cstore
    owner = ['0xai_a', 'admin_pipeline', 'CSTORE_MANAGER_API', 'CSTORE_MANAGER_API_INST']
    first = seed_cstore.build(200, 40, 1400, 11, owner)
    again = seed_cstore.build(200, 40, 1400, 11, owner)
    self.assertEqual(first, again)
    record = next(iter(first.values()))
    self.assertEqual(set(record), {'key', 'value', 'owner', 'readonly', 'token', 'confirms', 'min_confirms'})
    self.assertTrue(record['key'].startswith('hs:'))
    self.assertGreater(len(json.dumps(record['value'])), 1400)

  def test_old_style_pointers_are_well_formed_content_ids(self):
    import seed_cstore
    records = seed_cstore.legacy_jobs(5, 101, '0xai_a', 11)
    self.assertEqual(len(records), 5)
    for record in records.values():
      self.assertTrue(record['value'].startswith('Qm'))
      self.assertEqual(len(record['value']), 46)
    self.assertIn(seed_cstore.storage_key('DEEPLOY_DEPLOYED_JOBS', '101'), records)

  def test_seed_whitelist_names_every_oracle_in_the_format_the_node_reads(self):
    import seed_whitelist
    oracles = [['0xai_A2MGGXwcngd-dVcVh9DVPlP4vzm-q64i03D7tbGsx1kG', 'r1s-01'],
               ['0xai_AjUjU4FbphwuCULJfWNs-BUsss8M6KuXW7BxNKfaJkD5', 'r1o-09']]
    content = seed_whitelist.lines(oracles)
    rows = [line.split() for line in content.splitlines()]
    # ratio1 bc/base.py reads "<address> <alias>" and appends the EVM address itself when a line has two parts.
    self.assertEqual(rows, oracles)
    self.assertTrue(content.endswith('\n'))

  def test_only_seeds_get_the_whitelist_and_it_lists_seeds_and_oracles(self):
    from lnlib import nodes as nodelib
    plan = [{'name': 'r1s-01', 'role': 'seed', 'address': '0xai_s1', 'volume': 'v1'},
            {'name': 'r1o-09', 'role': 'oracle', 'address': '0xai_o9', 'volume': 'v2'},
            {'name': 'r1w-01', 'role': 'worker', 'address': '0xai_w1', 'volume': 'v3'}]
    seen = {}

    def fake_tool_run(script, mounts=(), **kwargs):
      seen['script'], seen['mounts'] = script, list(mounts)

      class Out:
        stdout = 'WHITELISTED {"nodes": 1, "senders": 2}\n'
      return Out()

    real = nodelib.tool_run
    nodelib.tool_run = fake_tool_run
    try:
      result = nodelib.seed_whitelists(None, plan)
    finally:
      nodelib.tool_run = real
    self.assertEqual(result, {'nodes': 1, 'senders': 2})
    self.assertIn('[["0xai_s1", "r1s-01"], ["0xai_o9", "r1o-09"]]', seen['script'])
    self.assertNotIn('0xai_w1', seen['script'])
    self.assertTrue(seen['script'].rstrip().endswith(' r1s-01'))
    self.assertEqual([dst for _src, dst, _mode in seen['mounts'][1:]], ['/nodes/r1s-01/_local_cache'])


class TestScenarios(unittest.TestCase):

  # Every step type lnlib/scenario.py runs, the container-app steps included.
  STEPS = {'load', 'run', 'unload', 'wait', 'phase', 'node', 'chain', 'profile', 'replicas', 'pin', 'note',
           'image', 'isolation', 'sync', 'switch'}

  def test_shipped_scenarios_use_known_steps_and_generators(self):
    """Every shipped scenario names itself, has unique phases, and uses only step types and generators that exist."""
    files = glob.glob(str(HERE / 'scenarios' / '*.json'))
    self.assertTrue(files)
    for path in files:
      spec = json.loads(Path(path).read_text())
      self.assertTrue(spec['name'] and spec['about'], path)
      # Phase names become result file names: two phases of one name would overwrite each other.
      phases = [step['name'] for step in spec['steps'] if step['do'] == 'phase']
      self.assertEqual(len(phases), len(set(phases)), path)
      for step in spec['steps']:
        self.assertIn(step['do'], self.STEPS, path)
        if step['do'] in ('load', 'run'):
          # A load step must name a generator script that exists under load/.
          self.assertTrue((HERE / 'load' / (step['generator'] + '.py')).exists(), step)


class TestContainerApps(unittest.TestCase):

  def _plan(self, **kwargs):
    """
    A small topology with addresses filled in, as ``init`` leaves it.

    Parameters
    ----------
    **kwargs
      Extra arguments of ``nodes.plan``.

    Returns
    -------
    list of dict
      The nodes.

    Examples
    --------
    >>> self._plan(docker_nodes=('r1w-01',))[-2]['docker']
    True
    """
    from lnlib import nodes
    plan = nodes.plan(oracles=4, workers=2, full_workers=0, default_arm='rel', **kwargs)
    for node in plan:
      node.update(address='0xai_' + node['name'], eth_address='0x0')
    return plan

  def test_docker_nodes_run_the_inner_daemon_on_the_internal_network_only(self):
    """A node in --docker-nodes starts the inner daemon privileged, on the localnet network only; other nodes do not."""
    from lnlib import nodes
    from lnlib.common import Home, PROJECT
    plan = self._plan(docker_nodes=('r1w-01', 'r1w-02'))
    with tempfile.TemporaryDirectory() as tmp:
      services = nodes.node_services(Home(tmp), {'nodes': plan})
    worker, seed = services['r1w-01'], services['r1s-01']
    # Started through the guard and cgroup set-up, privileged, in its own cgroup namespace.
    self.assertEqual(worker['entrypoint'], ['/bin/sh', '/opt/localnet/node/dind.sh'])
    self.assertTrue(worker['privileged'])
    self.assertEqual(worker['cgroup'], 'private')
    self.assertIn('r1ln_r1w-01_docker:/var/lib/docker', worker['volumes'])
    # Attached to the internal localnet network only, and no port published.
    self.assertEqual(list(worker['networks']), [PROJECT])
    self.assertNotIn('ports', worker)
    # Every other node is unchanged: not privileged, no inner daemon.
    self.assertNotIn('privileged', seed)
    self.assertNotIn('entrypoint', seed)
    # EE_DD=1 starts the daemon and makes the node report container support; others keep EE_DD=0.
    self.assertEqual(plan[-2]['env']['EE_DD'], '1')
    self.assertNotIn('env', plan[0])
    self.assertIn('r1ln_r1w-02_docker', nodes.node_volumes({'nodes': plan}))

  def test_web_plugin_lists_disable_the_others_and_are_checked(self):
    """--web-plugins and --web-of keep only the named web plugins, and bad names or a seed without dAuth are refused."""
    from lnlib import nodes
    from lnlib.common import LocalnetError
    plan = self._plan(web=['DAUTH_MANAGER'], web_of={'r1s-01': ['DAUTH_MANAGER', 'DEEPLOY_MANAGER_API']})
    first = nodes._startup_overrides(plan[0])['ADMIN_PIPELINE']
    second = nodes._startup_overrides(plan[1])['ADMIN_PIPELINE']
    # r1s-01 serves Deeploy and dAuth; r1s-02 only dAuth; neither runs the oracle API.
    self.assertNotIn('DISABLED', first['DEEPLOY_MANAGER_API'])
    self.assertTrue(second['DEEPLOY_MANAGER_API']['DISABLED'])
    self.assertNotIn('DISABLED', second['DAUTH_MANAGER'])
    self.assertTrue(first['ORACLE_API']['DISABLED'])
    # A seed must serve dAuth; unknown plugin and node names are errors, not silently ignored.
    with self.assertRaises(LocalnetError):
      self._plan(web=['DEEPLOY_MANAGER_API'])
    with self.assertRaises(LocalnetError):
      self._plan(web=['DAUTH_MANAGERS'])
    with self.assertRaises(LocalnetError):
      self._plan(docker_nodes=('r1w-09',))

  def test_front_routes_each_name_only_to_oracles_running_its_plugin(self):
    """The front sends Deeploy only to the oracle that runs it and drops a name no oracle serves."""
    from lnlib import infra
    from lnlib.common import Home
    plan = self._plan(web=['DAUTH_MANAGER'], web_of={'r1s-01': ['DAUTH_MANAGER', 'DEEPLOY_MANAGER_API']})
    with tempfile.TemporaryDirectory() as tmp:
      infra.edge_service(Home(tmp), plan)
      conf = (Path(tmp) / 'run' / 'edge' / 'nginx.conf').read_text()
    # The Deeploy upstream holds r1s-01 alone; dAuth holds the four seeds.
    deeploy = conf.split('upstream deeploy_api {')[1].split('}')[0]
    self.assertEqual(deeploy.count('server '), 1)
    self.assertIn(plan[0]['ip'], deeploy)
    self.assertEqual(conf.split('upstream dauth {')[1].split('}')[0].count('server '), 4)
    # No oracle runs the oracle API: no empty upstream (nginx would refuse it) and no server for the name.
    self.assertNotIn('upstream oracle ', conf)
    self.assertNotIn('server_name oracle.localnet', conf)

  def test_sync_app_request_matches_the_web_app_shape(self):
    """The sync-app request is a generic container job with the web app's SYNC block, a fixed volume and no pull."""
    sys.path.insert(0, str(HERE / 'load'))
    try:
      import deeploy
    finally:
      sys.path.remove(str(HERE / 'load'))
    payload = deeploy.sync_app_payload(3001, '0xai_w1', 'provider', 'lnet-sync-s0', 'localnet/syncapp:1', period=5, publishes=2)
    plugin = payload['plugins'][0]
    self.assertEqual(payload['job_app_type'], 'generic')
    self.assertEqual(plugin['plugin_signature'], 'CONTAINER_APP_RUNNER')
    # The block the web app emits for an enabled set (ENABLED, TYPE, KEY), nothing more.
    self.assertEqual(plugin['SYNC'], {'ENABLED': True, 'TYPE': 'provider', 'KEY': 'lnet-sync-s0'})
    self.assertEqual(plugin['IMAGE_PULL_POLICY'], 'manual')
    self.assertEqual(plugin['FIXED_SIZE_VOLUMES']['data']['MOUNTING_POINT'], '/data')
    # Volume plus container storage equal the micro tier's 2 GB, as the web app reserves it.
    self.assertEqual(int(plugin['FIXED_SIZE_VOLUMES']['data']['SIZE'][:-1]) + int(plugin['CONTAINER_RESOURCES']['storage'][:-1]),
                     int(payload['node_res_req']['storage'][:-1]))
    self.assertEqual(plugin['ENV'], {'SYNC_PERIOD': '5', 'SYNC_PUBLISHES': '2'})
    # Deeploy refuses SECRET_PATHS inside a plugin; the web app sends secret_paths at the top level.
    self.assertNotIn('SECRET_PATHS', plugin)
    self.assertEqual(payload['secret_paths'], [])

  def test_sync_check_measures_delays_and_fails_on_a_different_file(self):
    """The sync check passes a set whose consumer applied every publish in time with the same file, and fails it otherwise."""
    from lnlib import apps
    sent = [{'cid': 'Qm1', 'published_timestamp': 100.0}, {'cid': 'Qm2', 'published_timestamp': 200.0}]
    state = {'r1w-01': {'sent': sent, 'received': [], 'quarantine': 0},
             # The consumer skipped Qm1 and applied Qm2 at 240: Qm1 counts as held at 240 (140 s), Qm2 after 40 s.
             'r1w-02': {'sent': [], 'received': [{'cid': 'Qm2', 'applied_timestamp': 240.0}], 'quarantine': 0}}
    files = {'r1w-01': 'payload 2\n', 'r1w-02': 'payload 2\n'}
    saved = (apps.sync_state, apps.chain_record, apps.app_file, apps.node_log)
    # Node reads replaced by the fixed state above.
    apps.sync_state = lambda name: state[name]
    apps.chain_record = lambda name, key: {'record': {'cid': 'Qm2'}, 'age_s': 1.0}
    apps.app_file = lambda name, image, path: {'container': 'c', 'text': files[name], 'sha256': files[name]}
    apps.node_log = lambda name: ''
    manifest = {'nodes': [{'name': 'r1s-01', 'role': 'seed'}, {'name': 'r1w-01', 'role': 'worker'}]}
    try:
      report = apps.sync_check(manifest, 'r1w-01', ['r1w-02'], 'k', 'img', publishes=2, timeout=0, poll=0)
      self.assertTrue(report['ok'], report['failures'])
      self.assertEqual([row['delay_s']['r1w-02'] for row in report['publishes']], [140.0, 40.0])
      self.assertEqual(report['record_on_oracles'], '1/1')
      # A consumer file that differs from the provider's fails the set.
      files['r1w-02'] = 'payload 1\n'
      self.assertFalse(apps.sync_check(manifest, 'r1w-01', ['r1w-02'], 'k', 'img', publishes=2, timeout=0, poll=0)['ok'])
      # So does a publish held later than the bound.
      files['r1w-02'] = 'payload 2\n'
      self.assertFalse(apps.sync_check(manifest, 'r1w-01', ['r1w-02'], 'k', 'img', publishes=2, within=100, timeout=0, poll=0)['ok'])
    finally:
      apps.sync_state, apps.chain_record, apps.app_file, apps.node_log = saved


class TestMetrics(unittest.TestCase):

  def test_percentiles(self):
    from lnlib import metrics
    self.assertEqual(metrics.dist([]), {'n': 0, 'p50': None, 'p95': None, 'max': None})
    self.assertEqual(metrics.dist([1, 2, 3, 4, 100])['p50'], 3)
    self.assertEqual(metrics.dist([1, 2, 3, 4, 100])['max'], 100)

  def test_probe_window_gives_per_plugin_deltas(self):
    from lnlib import metrics

    class Home:
      run = None

    with tempfile.TemporaryDirectory() as folder:
      Home.run = Path(folder)
      out = Path(folder) / 'out' / 'n1'
      out.mkdir(parents=True)
      rows = []
      for idx in range(4):
        rows.append({'t': 100 + 5 * idx, 'up': 10 + 5 * idx, 'cpu': 2.0 * idx, 'VmRSS': 1024 * 900, 'Threads': 90,
                     'cg_mem': 2048 * 1048576, 'cg_usage_usec': 3000000 * idx, 'cg_throttled_usec': 1500000 * idx, 'plugins': {
          'admin_pipeline|CHAIN_STORE_BASE|X': {'recv': 10 * idx, 'dropped': idx, 'queue': 3 - idx, 'qmax': 1024,
                                               'handled': 10 * idx - idx - (3 - idx), 'hz': 20.0 - idx, 'iter': idx, 'errors': 0}}})
      (out / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows))
      result = metrics.node_probe(Home, 'n1', 100, 200)
    store = result['plugins']['CHAIN_STORE_BASE']
    self.assertEqual((store['received'], store['dropped'], store['queue_max'], store['queue_end']), (30, 3, 3, 0))
    self.assertEqual(result['cpu_cores'], 0.4)
    self.assertFalse(result['restarted'])
    # The whole container: 3 s of CPU and 1.5 s of throttling in every 5 s sample, 2 GiB.
    self.assertEqual((result['container_cores'], result['throttled_share'], result['container_mb']), (0.6, 0.3, 2048))

  def test_curve_gives_one_line_per_phase_for_the_squeezed_node(self):
    from lnlib import compare

    class Home:
      results = None

    def phase(cores, answered):
      return {'window': {'seconds': 240}, 'nodes': {'r1s-04': {'role': 'seed', 'cpu_cores': 9.9, 'container_cores': cores, 'log': {'main_loop_hz_p50': 9.5},
              'plugins': {'CHAIN_STORE_BASE': {'loop_hz_p50': 20.0, 'dropped': 0}, 'DAUTH_MANAGER': {'loop_hz_p50': 5.0}}}},
              'chain_store_users': {'r1s-04': {'writes': 24, 'writes_confirmed': 24, 'write_s': {'p50': 0.3}, 'refresh': 2, 'refresh_ok': 2}},
              'dauth_probe': {'get_auth_data': {'sent': 24, 'ok': answered, 'ok_s': {'p50': 1.5, 'p95': 4.0}}}}

    with tempfile.TemporaryDirectory() as folder:
      Home.results = Path(folder)
      run = Path(folder) / '20260101T000000_resource_floor_base'
      run.mkdir()
      (run / '1_cpu_unlimited.json').write_text(json.dumps(phase(0.55, 24)))
      (run / '2_cpu_0.25.json').write_text(json.dumps(phase(0.2, 3)))
      lines = compare.curve(Home, 'resource_floor', ['base', 'absent']).splitlines()
    rows = {line.split()[0]: line.split() for line in lines if line[:1].isdigit()}
    self.assertEqual(sorted(rows), ['1_cpu_unlimited', '2_cpu_0.25'])
    self.assertEqual((rows['1_cpu_unlimited'][1], rows['1_cpu_unlimited'][9]), ('0.55', '24/24'))
    self.assertEqual((rows['2_cpu_0.25'][1], rows['2_cpu_0.25'][9]), ('0.2', '3/24'))
    self.assertIn('absent: no run found', lines)


@unittest.skipUnless(HAS_SDK, 'SDK source tree not available')
class TestAddressTables(unittest.TestCase):

  def _fresh(self):
    import chain_shim
    chain_shim = importlib.reload(chain_shim)
    sys.modules.pop(chain_shim.MODULE_NAME, None)
    chain_shim.SRC = os.path.dirname(SDK.rstrip('/')) if os.path.basename(SDK.rstrip('/')) == 'sdk' else None
    return chain_shim

  def test_public_addresses_are_replaced_and_seed_list_is_the_local_one(self):
    spec = importlib.util.spec_from_file_location('ratio1.const.evm_net', os.path.join(SDK, 'ratio1', 'const', 'evm_net.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import chain_shim
    sys.modules[chain_shim.MODULE_NAME] = module
    seeds_before = module.EVM_NET_CONSTANTS['mainnet'][module.EvmNetConstants.SEED_NODES_ADDRESSES_KEY]
    self.assertTrue(chain_shim.leaks(module, 'mainnet'))
    with tempfile.NamedTemporaryFile('wt', suffix='.json', delete=False) as fh:
      json.dump({'seed_addresses': ['0xai_local_seed']}, fh)
    saved = (chain_shim.REGISTRY_PATH, os.environ.get('EE_EVM_NET'))
    chain_shim.REGISTRY_PATH = fh.name
    os.environ['EE_EVM_NET'] = 'mainnet'
    try:
      chain_shim.install()
    finally:
      chain_shim.REGISTRY_PATH = saved[0]
      os.environ.pop('EE_EVM_NET', None) if saved[1] is None else os.environ.__setitem__('EE_EVM_NET', saved[1])
      os.unlink(fh.name)
      sys.modules.pop(chain_shim.MODULE_NAME, None)
    self.assertEqual(chain_shim.leaks(module, 'mainnet'), [])
    self.assertEqual(module.EVM_NET_DATA['mainnet']['EE_DAUTH_URL'], 'http://dauth.localnet/get_auth_data')
    self.assertEqual(seeds_before, ['0xai_local_seed'])  # replaced in place: earlier references see it
    self.assertEqual(module.EVM_NET_DATA['mainnet']['EE_EPOCH_INTERVALS'], 24)  # network constants are kept


@unittest.skipUnless(HAS_SDK and HAS_ETH, 'SDK source tree or eth packages not available')
class TestChain(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    os.environ.setdefault('R1_LOCALNET_SDK', SDK)
    import chain_rpc
    cls.chain = chain_rpc
    chain_rpc.SDK_ROOT = SDK
    chain_rpc.NETWORK = 'mainnet'
    cls.folder = tempfile.TemporaryDirectory()
    chain_rpc.STATE_PATH = os.path.join(cls.folder.name, 'chain.json')
    oracle, node = '0x' + '11' * 20, '0x' + '22' * 20
    with open(chain_rpc.STATE_PATH, 'wt') as fh:
      json.dump({'nodes': {
        oracle: {'name': 'o', 'address': '0xai_o', 'oracle': True, 'dauth_oracle': True, 'licensed': True, 'license_id': 1,
                 'owner': '0x' + 'aa' * 20},
        node: {'name': 'n', 'address': '0xai_n', 'oracle': False, 'dauth_oracle': False, 'licensed': True, 'license_id': 2,
               'owner': '0x' + 'aa' * 20},
      }}, fh)
    chain_rpc.load_state()
    chain_rpc.load_contracts()
    cls.oracle, cls.node = oracle, node

  @classmethod
  def tearDownClass(cls):
    cls.folder.cleanup()

  def call(self, contract, name, types=(), values=()):
    from eth_abi import decode, encode
    from eth_utils import keccak
    address = self.chain.STATE['_contracts'][contract]
    item = [found[1] for key, found in self.chain.SELECTORS.items() if found[1]['name'] == name][0]
    selector = keccak(text='{}({})'.format(name, ','.join(self.chain.canonical(inp) for inp in item['inputs'])))[:4].hex()
    data = '0x' + selector + encode(list(types), list(values)).hex()
    raw = self.chain.eth_call([{'to': address, 'data': data}, 'latest'])
    return decode([self.chain.canonical(out) for out in item['outputs']], bytes.fromhex(raw[2:]))

  def test_registries_list_oracles_with_checksummed_addresses(self):
    from eth_utils import to_checksum_address
    self.assertEqual(list(self.call('CONTROLLER_ABI', 'getOracles')[0]), [to_checksum_address(self.oracle)])
    self.assertEqual(list(self.call('DAUTH_ORACLE_REGISTRY_ABI', 'getDAuthOracles')[0]), [to_checksum_address(self.oracle)])

  def test_licence_checks(self):
    self.assertTrue(self.call('CONTROLLER_ABI', 'isNodeActive', ['address'], [self.node])[0])
    self.assertFalse(self.call('CONTROLLER_ABI', 'isNodeActive', ['address'], ['0x' + '33' * 20])[0])
    details = self.call('PROXY_ABI', 'getNodeLicenseDetails', ['address'], [self.node])[0]
    self.assertEqual((details[1], details[2].lower()), (2, '0x' + 'aa' * 20))

  def test_a_bought_job_is_unstarted_until_an_oracle_reports_its_nodes(self):
    escrow, owner = '0x' + 'e5' * 20, '0x' + 'aa' * 20
    self.chain.admin({'op': 'add_escrow', 'escrow': escrow, 'owner': owner})
    self.chain.admin({'op': 'add_job', 'job_id': 7, 'escrow': escrow, 'job_type': 16})
    job = self.call('POAI_MANAGER_ABI', 'getJobDetails', ['uint256'], [7])[0]
    self.assertEqual((job[0], job[3], job[5], job[13].lower()), (7, 0, 16, owner))
    self.assertIn(7, self.call('POAI_MANAGER_ABI', 'getUnvalidatedJobIds', ['address'], [self.oracle])[0])
    self.chain.tx_submitNodeUpdate(self.oracle, (7, [self.node]))
    job = self.call('POAI_MANAGER_ABI', 'getJobDetails', ['uint256'], [7])[0]
    self.assertGreater(job[3], 0)
    self.assertNotIn(7, self.call('POAI_MANAGER_ABI', 'getUnvalidatedJobIds', ['address'], [self.oracle])[0])

  def test_moving_a_licence_emits_the_two_events_nodes_read(self):
    new = '0x' + '44' * 20
    self.chain.admin({'op': 'relink', 'old': self.node, 'new': new, 'name': 'n2', 'address': '0xai_n2'})
    logs = self.chain.get_logs([{'fromBlock': '0x0', 'toBlock': 'latest', 'address': self.chain.STATE['_contracts']['ND_ABI']}])
    self.assertEqual([entry['topics'][0] for entry in logs],
                     [self.chain.EVENT_TOPICS['UnlinkNode'], self.chain.EVENT_TOPICS['LinkNode']])
    self.assertTrue(self.call('CONTROLLER_ABI', 'isNodeActive', ['address'], [new])[0])
    self.assertFalse(self.call('CONTROLLER_ABI', 'isNodeActive', ['address'], [self.node])[0])

  def test_a_function_without_a_handler_answers_zero_of_the_right_shape(self):
    self.assertEqual(self.call('ERC20_ABI', 'transfer', ['address', 'uint256'], ['0x' + '55' * 20, 1])[0], False)
    self.assertIn('transfer', self.chain.STATS['unhandled'])


if __name__ == '__main__':
  unittest.main()
