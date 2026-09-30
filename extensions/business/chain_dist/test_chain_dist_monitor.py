import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


def load_monitor_class():
  """Load the monitor without optional runtime dependencies such as shapely."""
  path = Path(__file__).with_name('chain_dist_monitor.py')
  tree = ast.parse(path.read_text())
  config = next(node for node in tree.body if isinstance(node, ast.Assign) and any(
    isinstance(target, ast.Name) and target.id == '_CONFIG' for target in node.targets
  ))
  monitor = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ChainDistMonitorPlugin')
  namespace = {
    'BasePlugin': type('BasePlugin', (), {'CONFIG': {}}),
    '_DeeployMixin': type('_DeeployMixin', (), {}),
  }
  exec(compile(ast.Module(body=[config, monitor], type_ignores=[]), str(path), 'exec'), namespace)
  return namespace['ChainDistMonitorPlugin'], namespace['_CONFIG']


class FakeBlockchain:
  eth_address = '0xOracle'

  def __init__(self):
    self.pending = []
    self.all_pending = []
    self.first_closable = None
    self.jobs = {}
    self.submissions = []

  def get_unvalidated_job_ids(self, oracle_address):
    if oracle_address == '0x0000000000000000000000000000000000000000':
      return self.all_pending
    return self.pending

  def get_first_closable_job_id(self):
    return self.first_closable

  def get_job_details(self, job_id):
    return self.jobs[job_id]

  def get_all_active_jobs(self):
    return list(self.jobs.values())

  def node_address_to_eth_address(self, node):
    return f'0x{node}'

  def submit_node_update(self, job_id, nodes):
    self.submissions.append((job_id, nodes))
    return '0xtransaction'


class ChainDistMonitorTests(unittest.TestCase):
  def setUp(self):
    monitor_class, config = load_monitor_class()
    self.monitor = monitor_class()
    self.bc = FakeBlockchain()
    self.now = 10_000
    self.apps = {'other-online-node': {}}
    self.monitor.bc = self.bc
    self.monitor.netmon = SimpleNamespace(network_known_apps=lambda: self.apps)
    self.monitor.time = lambda: self.now
    self.monitor.Pd = lambda *args, **kwargs: None
    self.monitor.cfg_pending_empty_observation_seconds = config['PENDING_EMPTY_OBSERVATION_SECONDS']
    self.monitor.pending_empty_since = {}
    self.monitor.positive_recovery_since = {}
    self.monitor.last_positive_recovery_check = 0

  def job(self, job_id=1, start=0, nodes=None, requested=1000):
    return {
      'jobId': job_id,
      'startTimestamp': start,
      'activeNodes': nodes or [],
      'requestTimestamp': requested,
    }

  def visible(self, job_id=1):
    self.apps['node1'] = {'pipeline': {'deeploy_specs': {'job_id': job_id}}}

  def test_empty_unstarted_job_waits_one_hour_and_positive_observation_resets_timer(self):
    self.bc.pending = [1]
    self.bc.all_pending = [1]
    self.bc.jobs[1] = self.job()

    self.monitor.check_all_jobs()
    self.now += 3599
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])

    self.visible()
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, ['0xnode1'])])
    self.bc.submissions.clear()
    self.apps.pop('node1')

    self.monitor.check_all_jobs()
    self.now += 3599
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])
    self.now += 1
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, [])])

  def test_recently_requested_job_waits_even_after_local_observation(self):
    self.bc.pending = [1]
    self.bc.jobs[1] = self.job(requested=self.now - 60)
    self.monitor.check_all_jobs()
    self.now += 3599
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])
    self.now += 1
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, [])])

  def test_empty_netmon_view_does_not_count_as_observation(self):
    self.bc.pending = [1]
    self.bc.jobs[1] = self.job()
    self.apps = {}
    self.monitor.check_all_jobs()
    self.now += 7200
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])
    self.apps = {'other-online-node': {}}
    self.monitor.check_all_jobs()
    self.now += 3600
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, [])])

  def test_closed_pending_job_votes_zero_without_closable_gate(self):
    self.bc.pending = [1]
    self.bc.jobs[1] = self.job(start=2000)
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, [])])

  def test_started_nonclosable_job_does_not_vote_zero(self):
    self.bc.pending = [1]
    self.bc.jobs[1] = self.job(start=2000, nodes=['0xnode1'])
    self.monitor.check_all_jobs()
    self.now += 7200
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])

  def test_first_closable_job_keeps_existing_zero_vote(self):
    self.bc.pending = [1]
    self.bc.first_closable = 1
    self.bc.jobs[1] = self.job(start=2000, nodes=['0xnode1'])
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, [])])

  def test_visible_late_pipeline_restarts_consensus_once(self):
    self.bc.jobs[1] = self.job()
    self.visible()
    self.monitor.check_all_jobs()
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, ['0xnode1'])])
    self.bc.all_pending = [1]
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(len(self.bc.submissions), 1)

  def test_late_pipeline_does_not_reopen_closed_or_removed_job(self):
    self.visible()
    self.bc.jobs[1] = self.job(start=2000)
    self.monitor.check_all_jobs()
    self.bc.jobs[1] = self.job(job_id=0)
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])


if __name__ == '__main__':
  unittest.main()
