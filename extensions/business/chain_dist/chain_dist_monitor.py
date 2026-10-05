"""

Job state:
- (requested) but not start
- (pending) started but not validated by consensus
- running
- (in-change) running but needs target nodes validation consensus


Pre-launch:
1.1. select each job type (UI)
1.2. eval nodes (Deeploy API from arbitrary orcle) - @Serban to add request specs
1.3. review project (UI)
1.4. pay all jobs USDC (UI + SC) - we need defined


Launch:
2.1. UI sends to Deeploy API jobs (including job-id and project-id)
2.2. (1 oracle) Deeploy API launches each job on all target nodes after checking via SC the payment (with job-id)
- `getJobDetails` => balance > 0
- `submitNodeUpdate` (target node list)


Post-Launch:
3.1. C=1/3 oracles will see each new job, check if if target nodes are indeed running and confirm via SC
- get all pending or in-change ?????
- confirm via `submitNodeUpdate`
3.2. if less than C oracles confirm => raise some error?



Epoch-end:
4.1. 


"""
from naeural_core.business.base import BasePluginExecutor as BasePlugin
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin


__VER__ = '0.2.1'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  # end of mandatory area
  
  "RUNS_ONLY_ON_SUPERVISOR_NODE" : True,

  "CHAIN_DIST_MONITOR_VERBOSITY": 5,

  # our overwritten props
  'PROCESS_DELAY' : 10,

  # Plugin Sleep period in case of an error.
  'SLEEP_PERIOD' : 30,

  # Random thresholds limits for delaying actions.
  'MIN_THRESHOLD_REWARDS' : 1,
  'MAX_THRESHOLD_REWARDS' : 100,
  'MIN_THRESHOLD_CLOSE_JOB' : 1,
  'MAX_THRESHOLD_CLOSE_JOB' : 250,
  # Observe an unstarted pending job without a visible pipeline before voting zero.
  'PENDING_EMPTY_OBSERVATION_SECONDS' : 3600,
}

class ChainDistMonitorPlugin(BasePlugin, _DeeployMixin):

  def Pd(self, s, *args, verbosity=0, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_chain_dist_monitor_verbosity > verbosity:
      s = "[DEDUG] " + s
      self.P(s, *args, **kwargs)
    return


  def on_init(self):
    self.epochs_closed = {}
    self.jobs_to_close = {}
    self.pending_empty_since = {}
    self.positive_recovery_since = {}
    self.last_positive_recovery_check = 0
    self.chainstore_hset(
      hkey='chain_dist_monitor',
      key=self.node_addr,
      value=self.time(),
    )
    self.last_live_check = self.time()
    
    # check if node in list and add if not
    return
  
  
  def check_all_jobs(self):
    unvalidated_job_ids = self.bc.get_unvalidated_job_ids(oracle_address=self.bc.eth_address) or []
    known_apps = self.netmon.network_known_apps()
    running_nodes_by_job = {}
    for node, apps in known_apps.items():
      for pipeline_name, pipeline in apps.items():
        try:
          job_id = pipeline.get('deeploy_specs', {}).get('job_id')
          if type(job_id) is not int or job_id <= 0:
            continue
          running_nodes_by_job.setdefault(job_id, set()).add(node)
        except Exception as e:
          self.P(
            f"Skipping invalid metadata for pipeline {pipeline_name} on node {node}: {type(e).__name__}",
            color='r',
          )

    now = self.time()
    first_closable_job_id = self.bc.get_first_closable_job_id() if unvalidated_job_ids else None
    self.pending_empty_since = {
      job_id: since for job_id, since in self.pending_empty_since.items()
      if job_id in unvalidated_job_ids
    }
    self.positive_recovery_since = {
      job_id: since for job_id, since in self.positive_recovery_since.items()
      if job_id in running_nodes_by_job and job_id not in unvalidated_job_ids
    }
    submitted_job_ids = set()

    for job_id in unvalidated_job_ids:
      if not job_id:
        continue
      job = self.bc.get_job_details(job_id=job_id)
      running_nodes = running_nodes_by_job.get(job_id, set())
      if running_nodes:
        self.pending_empty_since.pop(job_id, None)

      # A job with a start timestamp and no active nodes has already closed.
      # It can remain pending in PoAIManager even though the escrow no longer
      # returns it as the first closable job.
      already_closed = job['startTimestamp'] > 0 and not job['activeNodes']
      if already_closed:
        nodes = []
      elif first_closable_job_id == job_id:
        if running_nodes:
          continue
        nodes = []
      elif running_nodes:
        nodes = sorted(self.bc.node_address_to_eth_address(node) for node in running_nodes)
      elif job['startTimestamp'] == 0 and not job['activeNodes']:
        if not known_apps:
          self.pending_empty_since.pop(job_id, None)
          continue
        since = self.pending_empty_since.setdefault(job_id, now)
        observation_seconds = self.cfg_pending_empty_observation_seconds
        if now - since < observation_seconds or now - job['requestTimestamp'] < observation_seconds:
          continue
        nodes = []
      else:
        continue

      self.Pd(f"Submitting {len(nodes)} observed node(s) for pending job {job_id}: {nodes}", verbosity=3)
      self.bc.submit_node_update(job_id=job_id, nodes=nodes)
      submitted_job_ids.add(job_id)

    # A zero-node consensus can clear a pending launch before its pipeline
    # becomes visible. Recover that launch if the pipeline appears later.
    if running_nodes_by_job and now - self.last_positive_recovery_check >= 300:
      active_jobs = {
        job['jobId']: job for job in self.bc.get_all_active_jobs()
        if job['startTimestamp'] == 0 and not job['activeNodes']
      }
      self.last_positive_recovery_check = now
      recovery_job_ids = set(running_nodes_by_job) & set(active_jobs) - submitted_job_ids
      if recovery_job_ids:
        # The zero address cannot be a proposer, so this returns every pending job.
        all_pending_job_ids = set(self.bc.get_unvalidated_job_ids(
          oracle_address='0x0000000000000000000000000000000000000000',
        ))
        recovery_job_ids -= all_pending_job_ids
      self.positive_recovery_since = {
        job_id: since for job_id, since in self.positive_recovery_since.items()
        if job_id in recovery_job_ids
      }
      for job_id in recovery_job_ids:
        since = self.positive_recovery_since.setdefault(job_id, now)
        if now - since < 300:
          continue
        # Give PoAIManager's five-minute consensus cooldown time to pass
        # after first observing this visible, nonpending job.
        running_nodes = running_nodes_by_job[job_id]
        nodes = sorted(self.bc.node_address_to_eth_address(node) for node in running_nodes)
        self.Pd(f"Recovering visible launch for job {job_id}: {nodes}", verbosity=3)
        self.bc.submit_node_update(job_id=job_id, nodes=nodes)
        self.positive_recovery_since[job_id] = now
    return
    
    
  def maybe_distribute_rewards(self):
    # v1
    # check if epoch has been closed > 10m < 1h
      # check if current node is the next in line to call rewards distribution (has rewards TOKEN in chainstore)
        # if so call bc.web3_distribute_rewards() THEN move TOKEN to the next oracle in line
    # >1h check if last epoch rewards have been distributed - self.bc.get_is_last_epoch_allocated()    
      # ALL oracles call bc.web3_distribute_rewards() to distribute rewards
      # arbitrary online oracle get TOKEN
      
    # v2:
    last_epoch = self.netmon.epoch_manager.get_current_epoch() - 1
    if last_epoch not in self.epochs_closed:
      # epoch just closed we can start timer
      delay = self.np.random.randint(self.cfg_min_threshold_rewards, self.cfg_max_threshold_rewards)
      self.epochs_closed[last_epoch] = {
        'epoch': last_epoch,
        'start_timer': self.time(),
        'rewards_distributed': False,
        'delay': delay
      }
      self.P(f"Will try to distribute rewards for epoch {last_epoch} in {delay} seconds.")
        
    if not self.epochs_closed[last_epoch]['rewards_distributed']:
      if (self.time() - self.epochs_closed[last_epoch]['start_timer']) > self.epochs_closed[last_epoch]['delay']:
        if self.bc.get_is_last_epoch_allocated():
          self.epochs_closed[last_epoch]['rewards_distributed'] = True
        else:
          self.bc.allocate_rewards_across_all_escrows()
          self.epochs_closed[last_epoch]['rewards_distributed'] = True
        #endif
      #endif
    return
  
  def check_closable_jobs(self):
    # check if there are any jobs that need to be closed with bc.get_first_closable_job_id (returns first job that can be closed or None)

    closable_job_id = self.bc.get_first_closable_job_id()
    if closable_job_id is None:
      return

    if closable_job_id not in self.jobs_to_close:
      delay = self.np.random.randint(self.cfg_min_threshold_close_job, self.cfg_max_threshold_close_job)
      self.jobs_to_close[closable_job_id] = {
        'job_id': closable_job_id,
        'start_timer': self.time(),
        'job_closed': False,
        'delay': delay
      }
      self.P(f"Will try to close job {closable_job_id} in {delay} seconds.")

    if not self.jobs_to_close[closable_job_id]['job_closed']:
      if (self.time() - self.jobs_to_close[closable_job_id]['start_timer']) > self.jobs_to_close[closable_job_id]['delay']:
        self.delete_pipeline_from_nodes(job_id=closable_job_id, allow_missing=True)
        self.bc.submit_node_update(job_id=closable_job_id, nodes=[])
        self.jobs_to_close[closable_job_id]['job_closed'] = True
      #endif
    #endif
    return
  
  def maybe_update_liveness(self):
    # check if last update was more than 10 minutes ago
    # if so, update chainstore with current time
    if (self.time() - self.last_live_check) > 600:
      self.chainstore_hset(
        hkey='chain_dist_monitor',
        key=self.node_addr,
        value=self.time(),
      )
      self.last_live_check = self.time()
    return
  
  def process(self):
    try:
      self.maybe_update_liveness()
      self.check_all_jobs()
      self.check_closable_jobs()
      self.maybe_distribute_rewards()
    except Exception as e:
      self.P(f"Exception during process:\n{self.trace_info()}\nSleeping for {self.cfg_sleep_period} seconds.", color='r')
      self.sleep(self.cfg_sleep_period)
    # endtry-except
    return
