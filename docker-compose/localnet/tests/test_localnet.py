"""
Checks of the localnet tool itself. No container is started.

Run from the repository root, inside the node image or any interpreter that
has web3's helper packages (``eth_abi``, ``eth_utils``):

    R1_LOCALNET_SDK=/path/to/ratio1_sdk python3 -m unittest docker-compose/localnet/tests/test_localnet.py

Tests that need the SDK tree or those packages are skipped when they are
missing.
"""

import glob
# The forms of a container-sync secret, computed independently of the tool in its scan test.
import hashlib
import hmac
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

  # Every step type lnlib/scenario.py runs, the container-app steps (custody and secret scan included).
  STEPS = {'load', 'run', 'unload', 'wait', 'phase', 'node', 'chain', 'profile', 'replicas', 'pin', 'note',
           'image', 'isolation', 'sync', 'switch', 'custody', 'scan', 'seed_history'}

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
    # Quarantine and download lists of the whole node, as the reader now returns them.
    state = {'r1w-01': {'sent': sent, 'received': [], 'quarantine': [], 'downloads': []},
             # The consumer skipped Qm1 and applied Qm2 at 240: Qm1 counts as held at 240 (140 s), Qm2 after 40 s.
             'r1w-02': {'sent': [], 'received': [{'cid': 'Qm2', 'applied_timestamp': 240.0}], 'quarantine': [], 'downloads': ['Qm2']}}
    files = {'r1w-01': 'payload 2\n', 'r1w-02': 'payload 2\n'}
    saved = (apps.sync_state, apps.chain_record, apps.app_file, apps.node_log)
    # Node reads replaced by the fixed state above (the reads now name the set's key).
    apps.sync_state = lambda name, key: state[name]
    apps.chain_record = lambda name, key: {'record': {'cid': 'Qm2'}, 'age_s': 1.0}
    apps.app_file = lambda name, image, key, path: {'container': 'c', 'text': files[name], 'sha256': files[name]}
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

  def test_sync_check_waits_while_the_provider_wrote_its_next_file(self):
    """A provider app that keeps publishing writes its next file before that publish is in its history: the check looks again instead of failing, and passes once the provider's history and file and the consumer's agree."""
    from lnlib import apps
    # Each look's provider history: first two publishes, then the third.
    sent = [{'cid': 'Qm1', 'published_timestamp': 100.0}, {'cid': 'Qm2', 'published_timestamp': 200.0}]
    third = {'cid': 'Qm3', 'published_timestamp': 300.0}
    # The consumer applied Qm2 at 230; Qm3 at 320, once the provider published it.
    applied = [{'cid': 'Qm2', 'applied_timestamp': 230.0}]
    # The provider's file in each look: already "payload 3" while only Qm2 is in its history.
    provider_files = ['payload 3\n', 'payload 3\n']
    # The consumer's file in each look: "payload 2", then "payload 3" after the next apply.
    consumer_files = ['payload 2\n', 'payload 3\n']
    looks = []

    def state(name, key):
      """
      The fixed node reads of one look: the second look of the provider sees the third publish.

      Parameters
      ----------
      name : str
        Node name.
      key : str
        Sync key (unused).

      Returns
      -------
      dict
        The node's sent and received history, quarantine and downloads.

      Examples
      --------
      >>> state('r1w-01', 'k')['sent'][-1]['cid']
      'Qm2'
      """
      if name == 'r1w-01':
        # Counted per provider read: the first look and every later one.
        looks.append(1)
        if len(looks) == 2:
          # Between the two looks the provider published Qm3 and the consumer applied it.
          sent.append(third)
          applied.append({'cid': 'Qm3', 'applied_timestamp': 320.0})
        return {'sent': list(sent), 'received': [], 'quarantine': [], 'downloads': []}
      # The consumer's history as it stands.
      return {'sent': [], 'received': list(applied), 'quarantine': [], 'downloads': []}

    def read_file(name, image, key, path):
      """
      The fixed file reads, in call order per node.

      Parameters
      ----------
      name : str
        Node name.
      image, key, path : str
        Unused.

      Returns
      -------
      dict
        The app's file text and its digest (the text itself).

      Examples
      --------
      >>> read_file('r1w-01', 'img', 'k', '/data/payload.txt')['text']
      'payload 3\\n'
      """
      # Provider and consumer files are taken from their own lists, one per read.
      text = (provider_files if name == 'r1w-01' else consumer_files).pop(0)
      return {'container': 'c', 'text': text, 'sha256': text}

    # The real node reads, put back at the end.
    saved = (apps.sync_state, apps.chain_record, apps.app_file, apps.node_log)
    # Node reads replaced by the fixed ones above.
    apps.sync_state, apps.app_file = state, read_file
    # The latest record on the one oracle, and no refusal lines.
    apps.chain_record = lambda name, key: {'record': {'cid': 'Qm3'}, 'age_s': 1.0}
    apps.node_log = lambda name: ''
    # One oracle and the provider's worker.
    manifest = {'nodes': [{'name': 'r1s-01', 'role': 'seed'}, {'name': 'r1w-01', 'role': 'worker'}]}
    try:
      # Two publishes asked for; the first converged-looking look must not end the check.
      report = apps.sync_check(manifest, 'r1w-01', ['r1w-02'], 'k', 'img', publishes=2, timeout=60, poll=0)
      self.assertTrue(report['ok'], report['failures'])
      # It passed on the second look, with the third publish measured and equal files.
      self.assertEqual(len(looks), 2)
      self.assertEqual([row['cid'] for row in report['publishes']], ['Qm1', 'Qm2', 'Qm3'])
      self.assertEqual(report['files']['r1w-02']['text'], 'payload 3\n')
    finally:
      # The real node reads again.
      apps.sync_state, apps.chain_record, apps.app_file, apps.node_log = saved

  def test_sync_check_fails_a_latest_record_in_another_format(self):
    """With an expected format, the sync check passes only when every holding oracle keeps the latest record in it: the set tag with a 64-hex mac, or the shared-key tag with none."""
    from lnlib import apps
    # One publish of the set tag, as the provider's sent history gives it.
    sent = [{'cid': 'Qm1', 'published_timestamp': 100.0, 'encryption': 'r1fs-set-v1'}]
    # The consumer applied it 30 s later.
    state = {'r1w-01': {'sent': sent, 'received': [], 'quarantine': [], 'downloads': []},
             'r1w-02': {'sent': [], 'received': [{'cid': 'Qm1', 'applied_timestamp': 130.0}], 'quarantine': [], 'downloads': []}}
    # The record as the oracle's replica gives it; each case below replaces its tag and mac form.
    record = {'cid': 'Qm1', 'encryption': 'r1fs-set-v1', 'mac': 'hex64'}
    # The real node reads, put back at the end.
    saved = (apps.sync_state, apps.chain_record, apps.app_file, apps.node_log)
    # Node reads replaced by the fixed state above.
    apps.sync_state = lambda name, key: state[name]
    # A copy of the record as it stands when the check reads it.
    apps.chain_record = lambda name, key: {'record': dict(record), 'age_s': 1.0}
    # Equal files on both nodes.
    apps.app_file = lambda name, image, key, path: {'container': 'c', 'text': 'payload 1\n', 'sha256': 'd1'}
    # No refusal lines anywhere.
    apps.node_log = lambda name: ''
    # One oracle and the provider's worker.
    manifest = {'nodes': [{'name': 'r1s-01', 'role': 'seed'}, {'name': 'r1w-01', 'role': 'worker'}]}

    def check(encryption):
      """
      Run the sync check on the fixed set with one expected format, on the record as it stands.

      Parameters
      ----------
      encryption : str or None
        The format tag the latest record must carry, or None for no format check.

      Returns
      -------
      tuple
        The verdict (bool) and the whole report (dict).

      Examples
      --------
      >>> check('r1fs-set-v1')[0]
      True
      """
      # The set's one publish, checked against the expected format.
      report = apps.sync_check(manifest, 'r1w-01', ['r1w-02'], 'k', 'img', timeout=0, poll=0, encryption=encryption)
      return report['ok'], report

    try:
      # The set tag with a 64-hex mac passes.
      ok, report = check('r1fs-set-v1')
      self.assertTrue(ok, report['failures'])
      # The report names the record's form per oracle and the publish's tag.
      self.assertEqual(report['record_forms'], {'r1s-01': ('r1fs-set-v1', 'hex64')})
      self.assertEqual(report['publishes'][0]['encryption'], 'r1fs-set-v1')
      # The set tag with a missing or malformed mac fails, and so does the shared-key tag.
      for tag, mac in (('r1fs-set-v1', None), ('r1fs-set-v1', 'other'), ('r1fs-default', None)):
        # This case's record on the oracle.
        record.update(encryption=tag, mac=mac)
        self.assertFalse(check('r1fs-set-v1')[0], (tag, mac))
      # A shared-key record (no mac) passes the shared-key format.
      record.update(encryption='r1fs-default', mac=None)
      self.assertTrue(check('r1fs-default')[0])
      # The shared-key tag with a mac fails it.
      record.update(mac='hex64')
      self.assertFalse(check('r1fs-default')[0])
      # No expected format: the format is reported, not checked.
      self.assertTrue(check(None)[0])
    finally:
      # The real node reads again.
      apps.sync_state, apps.chain_record, apps.app_file, apps.node_log = saved

  def test_sync_app_sends_a_named_secret_through_secret_paths(self):
    """--secret NAME sends the set's 64-hex secret as ENV.R1EN_SYNC_SECRET with the web app's top-level path, and host and generator derive the same value."""
    sys.path.insert(0, str(HERE / 'load'))
    try:
      import deeploy
    finally:
      sys.path.remove(str(HERE / 'load'))
    from lnlib import common
    # Throwaway cluster settings, as init writes them.
    secrets = {'relay': {'relay_api_key_b64': 'abc'}, 'mesh': {'client_password': 'x'}}
    # The value of set s1.
    value = common.sync_secret(secrets, 's1')
    # The format a node accepts, the same after a JSON round trip of the settings, another value for another
    # name or other settings.
    self.assertRegex(value, r'^[0-9a-f]{64}$')
    self.assertEqual(value, common.sync_secret(json.loads(json.dumps(secrets)), 's1'))
    self.assertNotEqual(value, common.sync_secret(secrets, 'wrong'))
    self.assertNotEqual(value, common.sync_secret({'relay': {}}, 's1'))
    # The load generator calls the host tool's own derivation, so both sides always agree.
    self.assertIs(deeploy.sync_secret, common.sync_secret)
    # A provider request carrying the secret.
    payload = deeploy.sync_app_payload(3001, '0xai_w1', 'provider', 'k1', 'localnet/syncapp:1', secret=value)
    # One ENV entry and one top-level selector, as withSecretPaths of the web app emits them; no plugin SECRET_PATHS.
    self.assertEqual(payload['plugins'][0]['ENV']['R1EN_SYNC_SECRET'], value)
    self.assertEqual(payload['secret_paths'], [['plugins', 0, 'ENV', 'R1EN_SYNC_SECRET']])
    self.assertNotIn('SECRET_PATHS', payload['plugins'][0])
    # The malformed value is not of the accepted format, and the app writes a byte count, never the value.
    self.assertNotRegex(deeploy.MALFORMED_SECRET, r'^[0-9a-f]{64}$')
    self.assertIn('printenv R1EN_SYNC_SECRET | wc -c > "$D/secret_len"', deeploy.SYNC_APP_SCRIPT)

  def _refusal_check(self, log, downloads=(), applied=(), file_after=None, expected=''):
    """
    Run the sync check on a set whose only consumer, r1w-04, must refuse, with fixed node reads.

    Parameters
    ----------
    log : str
      The refusing node's log.
    downloads : tuple of str
      CIDs in its R1FS download folder.
    applied : tuple of str
      CIDs it applied.
    file_after : str or None
      Its app's file at the end of the check (None: still missing, as at the start).
    expected : str
      Text one of its refusal reasons must hold ('' for any).

    Returns
    -------
    dict
      The sync check's report.

    Examples
    --------
    >>> self._refusal_check('[sync] cannot prepare v2 (cid=Qm2): bad')['ok']
    True
    """
    from lnlib import apps
    # Two publishes; the refusing node quarantined the latest.
    sent = [{'cid': 'Qm1', 'published_timestamp': 100.0}, {'cid': 'Qm2', 'published_timestamp': 200.0}]
    state = {'r1w-01': {'sent': sent, 'received': [], 'quarantine': [], 'downloads': []},
             'r1w-04': {'sent': [], 'received': [{'cid': cid, 'applied_timestamp': 250.0} for cid in applied],
                        'quarantine': ['Qm2'], 'downloads': list(downloads)}}
    # File reads in call order: the refusing app's file before the check, then the provider's and its own at the end.
    reads = {'r1w-01': ['payload 2\n'], 'r1w-04': [None, file_after]}
    saved = (apps.sync_state, apps.chain_record, apps.app_file, apps.node_log)
    # Node reads replaced by the fixed state above.
    apps.sync_state = lambda name, key: state[name]
    apps.chain_record = lambda name, key: {'record': {'cid': 'Qm2'}, 'age_s': 1.0}
    apps.app_file = lambda name, image, key, path: (lambda text: {'container': 'c', 'text': text, 'sha256': text})(reads[name].pop(0))
    apps.node_log = lambda name: log
    manifest = {'nodes': [{'name': 'r1s-01', 'role': 'seed'}, {'name': 'r1w-01', 'role': 'worker'}]}
    try:
      # No consumer that must apply; r1w-04 must refuse.
      return apps.sync_check(manifest, 'r1w-01', [], 'k', 'img', publishes=2, timeout=0, poll=0, refusing={'r1w-04': expected})
    finally:
      apps.sync_state, apps.chain_record, apps.app_file, apps.node_log = saved

  def test_sync_check_passes_a_refusal_before_download_and_fails_any_fetch(self):
    """A consumer that must refuse passes only with a refusal of the latest record, its expected reason, no fetch line, no download, nothing applied and an unchanged file."""
    # The refusal line a consumer with a set secret writes for a record whose MAC does not match.
    refusal = "[EE] [sync] cannot prepare v2 (cid=Qm2): record mac does not match this node's sync secret\n"
    # Refused before any download, for the expected reason: PASS, with the reason reported.
    report = self._refusal_check(refusal, expected='record mac does not match')
    self.assertTrue(report['ok'], report['failures'])
    self.assertEqual(report['refusing']['r1w-04']['reasons'], ["record mac does not match this node's sync secret"])
    # Another reason than the expected one fails.
    self.assertFalse(self._refusal_check(refusal, expected='unsupported encryption')['ok'])
    # A refusal after R1FS fetched the archive (its decryption-failure line names the download folder) fails.
    fetched = refusal + 'Error decrypting file /edge_node/_local_cache/_output/ipfs_downloads/Qm2/f.tar.gz: tag\n'
    self.assertFalse(self._refusal_check(fetched)['ok'])
    # So do an archive left in the download folder, an applied record, and a file that took the provider's data.
    self.assertFalse(self._refusal_check(refusal, downloads=('Qm2',))['ok'])
    self.assertFalse(self._refusal_check(refusal, applied=('Qm2',))['ok'])
    self.assertFalse(self._refusal_check(refusal, file_after='payload 2\n')['ok'])
    # A refusal of an older record only (the latest not refused) fails too.
    self.assertFalse(self._refusal_check(refusal.replace('Qm2', 'Qm1'))['ok'])

  def test_history_seeder_writes_old_retired_entries_the_sync_reader_leaves_out(self):
    """The history seeder writes the asked number of readable entries into the app's received folder, each older than any apply, already retired and of another set, so the sync reader of the real set sees none of them."""
    import subprocess
    import time
    from lnlib import apps
    # A throwaway cache folder, removed at the end.
    with tempfile.TemporaryDirectory() as tmp:
      # The app's instance folder as the runner lays it out (its fixed volumes folder marks it).
      os.makedirs(os.path.join(tmp, '_data', 'pipelines_data', 'lnsync3002_ab12', 'CONTAINER_APP_1', 'fixed_volumes'))
      # The seeder as it runs in a node, pointed at this folder.
      code = apps.HISTORY_SEEDER.replace("'/edge_node/_local_cache/_data", repr(tmp + '/_data')[:-1])
      # Fifty entries for job 3002.
      out = subprocess.run([sys.executable, '-I', '-', '3002', '50'], input=code, capture_output=True, text=True, timeout=60).stdout
      # The folder the runner reads that app's received history from.
      folder = os.path.join(tmp, '_data', 'pipelines_data', 'lnsync3002_ab12', 'CONTAINER_APP_1', 'sync_history', 'received')
      # It now holds 50 files, as the seeder reports.
      self.assertEqual(apps._tagged(out, 'SEEDED'), {'folder': folder, 'files': 50})
      # Every entry is readable JSON.
      entries = [json.loads(Path(folder, name).read_text()) for name in os.listdir(folder)]
      # Each is retired and of the set "seed".
      self.assertTrue(all(item['deletion']['deleted_at'] and item['metadata'] == {'key': 'seed'} for item in entries))
      # Each was written ten days ago or earlier: never the last applied entry.
      self.assertLess(max(item['history_written_at_ns'] for item in entries), (time.time() - 9 * 86400) * 10 ** 9)
      # The sync reader, run on the same folder for a real set.
      reader = apps.SYNC_READER.replace("'/edge_node/_local_cache/_data'", repr(tmp + '/_data'))
      # Its view of the set's history.
      state = apps._tagged(subprocess.run([sys.executable, '-I', '-', 'lnet-sync-s0'], input=reader, capture_output=True,
                                          text=True, timeout=60).stdout, 'SYNCSTATE')
      # No received entry of the real set.
      self.assertEqual(state['received'], [])
      # A job without an app: the seeder finds no folder.
      missing = subprocess.run([sys.executable, '-I', '-', '3999', '5'], input=code, capture_output=True, text=True, timeout=60).stdout
      # So the host function raises on its report.
      self.assertEqual(apps._tagged(missing, 'SEEDED'), {'folder': None, 'files': 0})

  def test_scan_reader_finds_every_form_outside_dauth_records_and_prints_none(self):
    """The node-side scan finds each form of the secret in files, reports dAuth's bundle records apart, skips loop images and prints no form."""
    import pickle
    import subprocess
    from lnlib import apps
    # A test secret and its four forms.
    secret = 'ab' * 32
    needles = apps.sync_needles(secret)
    # Forms computed here independently: the archive key is SHA-256 of the text; the subkey an HMAC over the context.
    self.assertEqual(needles['archive_key'], hashlib.sha256(secret.encode()).hexdigest())
    self.assertEqual(needles['archive_key_16'], needles['archive_key'][:32])
    self.assertEqual(needles['mac_subkey'], hmac.new(secret.encode(), b'r1en-volume-sync-record-v1', hashlib.sha256).hexdigest())
    with tempfile.TemporaryDirectory() as tmp:
      # A cache folder as a node keeps it: a log with the archive key, a clean data file, a loop image holding
      # the secret (skipped), and a chain-store replica with dAuth bundle records and another record.
      for folder in ('_logs', '_data/app/fixed_volumes/images', '_data/cache'):
        os.makedirs(os.path.join(tmp, folder))
      Path(tmp, '_logs', 'node.txt').write_text('loaded key ' + needles['archive_key'] + '\n')
      Path(tmp, '_data', 'clean.json').write_text('{"cid": "Qm1"}')
      Path(tmp, '_data', 'app', 'fixed_volumes', 'images', 'data.img').write_text(secret)
      # The replica's record names: "hs:" + 10 hex characters of the hash name's SHA-256 + ":" + the field.
      dauth = 'hs:{}:MzAwMQ=='.format(hashlib.sha256(b'DAUTH_JOB_SECRETS').hexdigest()[:10])
      # dAuth also keeps the bundle per revision, in a second hash.
      revision = 'hs:{}:MzAwMXxvcDpkZXBsb3k='.format(hashlib.sha256(b'DAUTH_JOB_SECRET_REVISIONS').hexdigest()[:10])
      store = {dauth: {'value': {'job_secrets': secret}}, revision: {'value': {'job_secrets': secret}},
               'hs:0123456789:eA==': {'value': {'m': needles['mac_subkey']}}}
      Path(tmp, '_data', 'cache', 'object.pickle').write_bytes(pickle.dumps(store))
      # The reader as it runs in a node, pointed at this folder, with its values in front.
      code = apps._with_values(apps.SCAN_READER.replace("'/edge_node/_local_cache'", repr(tmp)), NEEDLES=needles,
                               CSTORE_PICKLE=os.path.join(tmp, '_data', 'cache', 'object.pickle'))
      out = subprocess.run([sys.executable, '-I', '-'], input=code, capture_output=True, text=True, timeout=60).stdout
    found = apps._tagged(out, 'SCAN')
    # The log (archive key and its 16-byte prefix) and the replica's non-dAuth record (subkey) are hits; the
    # loop image is not read; the dAuth bundle records (both hashes) are reported apart.
    self.assertEqual({os.path.basename(hit['path']): hit['kinds'] for hit in found['hits']},
                     {'node.txt': ['archive_key', 'archive_key_16'], 'object.pickle': ['mac_subkey']})
    self.assertEqual(found['dauth_bundle_kinds'], ['secret'])
    self.assertEqual(found['files'], 3)
    # The output names kinds and paths only.
    self.assertFalse(any(needle in out for needle in needles.values()))

  def test_custody_passes_only_the_placeholder_and_the_expected_count(self):
    """The custody check passes stored documents holding only the placeholder and no secret with the expected app count, fails otherwise, and passes the secret through stdin only."""
    from lnlib import apps
    # What the reader on the oracle prints for a well-redacted job.
    doc = {'cid': 'Qm1', 'readable': True, 'values': ['placeholder'], 'secret_paths': [[['ENV', 'R1EN_SYNC_SECRET']]],
           'secret_in_doc': False}
    answer = {'pointer': 'dict', 'docs': {'pipeline': dict(doc), 'plan': dict(doc, cid='Qm2')}}
    # Command lines of the node programs, to prove the secret is not on them.
    calls = []
    saved = (apps._exec_python, apps.app_file)
    # The oracle's answer, and the app's count of 65 bytes.
    apps._exec_python = lambda name, code, *args: calls.append(args) or 'CUSTODY ' + json.dumps(answer)
    apps.app_file = lambda name, image, key, path: {'container': 'c', 'text': '65\n', 'sha256': None}
    secret = 'ab' * 32

    def check(expected):
      """
      Run the custody check of job 3001 with the fixed reads above.

      Parameters
      ----------
      expected : int
        Expected count of secret bytes in the app's environment.

      Returns
      -------
      bool
        Whether the check passed.

      Examples
      --------
      >>> check(65)
      True
      """
      # One look only: no wait for the pointer.
      return apps.custody(3001, secret, 'r1s-01', node='r1w-01', key='k', secret_len=expected, timeout=0, poll=0)['ok']

    try:
      self.assertTrue(check(65))
      # The secret travelled in the program text (stdin), never as an argument.
      self.assertFalse(any(secret in arg for args in calls for arg in args))
      # A count other than the expected one (the secret reached, or did not reach, the container) fails.
      self.assertFalse(check(0))
      # A stored value other than the placeholder fails.
      answer['docs']['plan']['values'] = ['other']
      self.assertFalse(check(65))
      # The secret inside a stored document fails.
      answer['docs']['plan'] = dict(doc, secret_in_doc=True)
      self.assertFalse(check(65))
      # No pointer for the job fails.
      answer['pointer'] = None
      self.assertFalse(check(65))
    finally:
      apps._exec_python, apps.app_file = saved


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
