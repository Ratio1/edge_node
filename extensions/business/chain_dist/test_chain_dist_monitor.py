import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


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
    '_DeeployJobMixin': type('_DeeployJobMixin', (), {}),
    'NODE_RELINKS_SHMEM_KEY': 'CHAIN_DIST_NODE_RELINKS',
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
    self.block_number = 50_020
    self.link_events = []
    self.log_ranges = []
    self.active_job_reads = 0

  def get_unvalidated_job_ids(self, oracle_address):
    if oracle_address == '0x0000000000000000000000000000000000000000':
      return self.all_pending
    return self.pending

  def get_first_closable_job_id(self):
    return self.first_closable

  def get_job_details(self, job_id):
    return self.jobs[job_id]

  def get_all_active_jobs(self):
    self.active_job_reads += 1
    return list(self.jobs.values())

  def get_block_number(self):
    return self.block_number

  def get_nd_link_events(self, from_block, to_block):
    self.log_ranges.append((from_block, to_block))
    events = [event for event in self.link_events if from_block <= event['block_number'] <= to_block]
    return events

  def node_address_to_eth_address(self, node):
    return f'0x{node}'

  def eth_addr_to_internal_addr(self, node):
    return '0xai_' + node[2:]

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
    for key in ('RELINK_CHECK_MIN_SECONDS', 'RELINK_CHECK_MAX_SECONDS', 'ND_LINK_LOGS_MAX_BLOCKS', 'ND_LINK_LOGS_CONFIRMATIONS'):
      setattr(self.monitor, 'cfg_' + key.lower(), config[key])
    self.monitor.next_relink_check = 0
    self.monitor.relink_state = {'cursor': 0, 'unlinked': {}, 'links': {}}
    self.monitor.np = SimpleNamespace(random=SimpleNamespace(randint=lambda low, high: low))
    self.saved_states = []
    self.monitor.cacheapi_save_pickle = lambda obj, verbose=True: self.saved_states.append(obj)
    self.monitor.plugins_shmem = {}
    self.placements = {}
    self.pipeline_reads = []
    def get_job_pipeline_from_cstore(job_id, **kwargs):
      self.pipeline_reads.append(job_id)
      nodes = self.placements.get(job_id)
      return None if nodes is None else {'DEEPLOY_SPECS': {'current_target_nodes': ['0xai_' + node for node in nodes]}}
    self.monitor.get_job_pipeline_from_cstore = get_job_pipeline_from_cstore

  def job(self, job_id=1, start=0, nodes=None, requested=1000):
    return {
      'jobId': job_id,
      'startTimestamp': start,
      'activeNodes': nodes or [],
      'requestTimestamp': requested,
    }

  def visible(self, job_id=1):
    self.apps['node1'] = {'pipeline': {'deeploy_specs': {'job_id': job_id}}}

  def link_event(self, event, node, license_id=7, owner='0xOwner', block_number=50_000):
    return {
      'event': event, 'license_id': license_id, 'owner': owner,
      'node_address': f'0x{node}', 'block_number': block_number, 'log_index': 0,
    }

  def relink(self, old='old', new='new', owner='0xOwner', new_owner=None):
    self.bc.link_events += [
      self.link_event('UnlinkNode', old, owner=owner),
      self.link_event('LinkNode', new, owner=new_owner or owner),
    ]

  def run_relink_check(self):
    self.monitor.P = Mock()
    self.monitor.maybe_swap_relinked_nodes()

  def handed_to_deeploy(self):
    return self.monitor.plugins_shmem['CHAIN_DIST_NODE_RELINKS']

  def test_malformed_pipelines_do_not_stop_process_without_pending_jobs(self):
    self.monitor.maybe_update_liveness = Mock()
    self.monitor.check_closable_jobs = Mock()
    self.monitor.maybe_distribute_rewards = Mock()
    self.monitor.P = Mock()
    self.monitor.trace_info = lambda: 'unexpected process error'
    self.monitor.sleep = Mock()
    self.monitor.cfg_sleep_period = 30
    invalid_ids = ([1], {'id': 1}, '1', 1.0, True, False, None, 0, -1)
    invalid_pipelines = [{'deeploy_specs': {'job_id': job_id}} for job_id in invalid_ids]
    invalid_pipelines.extend((None, [], {'deeploy_specs': None}, {'deeploy_specs': []}, {'deeploy_specs': 'invalid'}))
    for pipeline in invalid_pipelines:
      with self.subTest(pipeline=pipeline):
        self.apps = {'node1': {'pipeline': pipeline}}
        self.monitor.check_closable_jobs.reset_mock()
        self.monitor.maybe_distribute_rewards.reset_mock()
        self.monitor.sleep.reset_mock()
        self.monitor.process()
        self.monitor.check_closable_jobs.assert_called_once_with()
        self.monitor.maybe_distribute_rewards.assert_called_once_with()
        self.monitor.sleep.assert_not_called()
    self.assertEqual(self.bc.submissions, [])

  def test_invalid_job_ids_do_not_contaminate_valid_job_node_vote(self):
    self.bc.pending = [1]
    self.bc.all_pending = [1]
    self.bc.jobs[1] = self.job()
    self.apps = {
      'bad-node': {
        str(index): {'deeploy_specs': {'job_id': job_id}}
        for index, job_id in enumerate(([1], {'id': 1}, '1', 1.0, True))
      },
      'good-node': {'pipeline': {'deeploy_specs': {'job_id': 1}}},
    }
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, ['0xgood-node'])])

  def test_malformed_pipeline_does_not_block_valid_pipeline_recovery(self):
    self.bc.jobs[1] = self.job()
    self.monitor.P = Mock()
    self.apps = {
      'node1': {
        'malformed-pipeline': None,
        'malformed-specs': {'deeploy_specs': None},
        'valid-pipeline': {'deeploy_specs': {'job_id': 1}},
      },
    }
    self.monitor.check_all_jobs()
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, ['0xnode1'])])

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

  def test_none_pending_response_still_checks_late_pipeline_recovery(self):
    self.bc.pending = None
    self.bc.jobs[1] = self.job()
    self.visible()
    self.monitor.check_all_jobs()
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [(1, ['0xnode1'])])

  def test_late_pipeline_does_not_reopen_closed_or_removed_job(self):
    self.visible()
    self.bc.jobs[1] = self.job(start=2000)
    self.monitor.check_all_jobs()
    self.bc.jobs[1] = self.job(job_id=0)
    self.now += 300
    self.monitor.check_all_jobs()
    self.assertEqual(self.bc.submissions, [])

  def test_relinked_node_in_stored_placement_is_handed_to_deeploy_before_any_vote(self):
    self.relink()
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold', '0xother'])
    self.placements[5] = ['old', 'other']
    self.run_relink_check()
    self.assertEqual(self.handed_to_deeploy(), {5: ('0xai_old', '0xai_new')})
    self.assertEqual(self.bc.submissions, [])
    self.assertEqual(self.bc.log_ranges, [(40_001, 50_000)])
    self.assertEqual(self.saved_states[-1]['cursor'], 50_000)

  def test_vote_follows_once_deeploy_stored_the_new_node(self):
    self.relink()
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold', '0xother'])
    self.placements[5] = ['new', 'other']
    self.run_relink_check()
    self.assertEqual(self.bc.submissions, [(5, ['0xnew', '0xother'])])
    self.assertEqual(self.handed_to_deeploy(), {})

  def test_relink_in_two_transactions_is_matched_across_checks(self):
    self.bc.link_events = [self.link_event('UnlinkNode', 'old', block_number=49_000)]
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold'])
    self.placements[5] = ['new']
    self.run_relink_check()
    self.assertEqual(self.bc.submissions, [])

    self.bc.link_events.append(self.link_event('LinkNode', 'new', block_number=50_100))
    self.bc.block_number = 50_200
    self.now += 300
    self.run_relink_check()
    self.assertEqual(self.bc.log_ranges[-1], (50_001, 50_180))
    self.assertEqual(self.bc.submissions, [(5, ['0xnew'])])

  def test_license_linked_by_another_owner_is_not_a_relink(self):
    self.relink(new_owner='0xBuyer')
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold'])
    self.placements[5] = ['old']
    self.run_relink_check()
    self.assertEqual(self.bc.submissions, [])
    self.assertEqual(self.handed_to_deeploy(), {})
    self.assertEqual(self.bc.active_job_reads, 0)

  def test_lone_unlink_from_transfer_or_burn_moves_nothing(self):
    self.bc.link_events = [self.link_event('UnlinkNode', 'old')]
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold'])
    self.placements[5] = ['old']
    self.run_relink_check()
    self.assertEqual(self.bc.submissions, [])
    self.assertEqual(self.handed_to_deeploy(), {})
    self.assertEqual((self.bc.active_job_reads, self.pipeline_reads), (0, []))
    self.assertIn('0xold', self.saved_states[-1]['unlinked'])

  def test_jobs_without_a_relinked_node_read_no_stored_job(self):
    self.relink()
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xother'])
    self.run_relink_check()
    self.assertEqual(self.pipeline_reads, [])
    self.assertEqual(self.handed_to_deeploy(), {})

  def test_pending_and_closable_jobs_are_left_to_their_own_checks(self):
    self.relink()
    self.bc.all_pending = [5]
    self.bc.first_closable = 6
    self.bc.jobs[5] = self.job(job_id=5, start=2000, nodes=['0xold'])
    self.bc.jobs[6] = self.job(job_id=6, start=2000, nodes=['0xold'])
    self.placements.update({5: ['new'], 6: ['old']})
    self.run_relink_check()
    self.assertEqual(self.bc.submissions, [])
    self.assertEqual(self.handed_to_deeploy(), {})

  def test_check_waits_for_its_random_interval_and_reports_unread_blocks(self):
    self.run_relink_check()
    self.bc.block_number = 80_020
    self.now += 299
    self.run_relink_check()
    self.assertEqual(len(self.bc.log_ranges), 1)
    self.now += 1
    self.run_relink_check()
    self.assertEqual(self.bc.log_ranges[-1], (70_001, 80_000))
    self.assertIn('50001..70000', self.monitor.P.call_args.args[0])


if __name__ == '__main__':
  unittest.main()
