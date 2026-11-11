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


class TestScenarios(unittest.TestCase):

  STEPS = {'load', 'run', 'unload', 'wait', 'phase', 'node', 'chain', 'profile', 'replicas', 'pin', 'note'}

  def test_shipped_scenarios_use_known_steps_and_generators(self):
    files = glob.glob(str(HERE / 'scenarios' / '*.json'))
    self.assertTrue(files)
    for path in files:
      spec = json.loads(Path(path).read_text())
      self.assertTrue(spec['name'] and spec['about'], path)
      phases = [step['name'] for step in spec['steps'] if step['do'] == 'phase']
      self.assertEqual(len(phases), len(set(phases)), path)
      for step in spec['steps']:
        self.assertIn(step['do'], self.STEPS, path)
        if step['do'] in ('load', 'run'):
          self.assertTrue((HERE / 'load' / (step['generator'] + '.py')).exists(), step)


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
