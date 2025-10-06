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


__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  # end of mandatory area
  
  "RUNS_ONLY_ON_SUPERVISOR_NODE" : True,

  "CHAIN_DIST_MONITOR_VERBOSITY": 5,

  # our overwritten props
  'PROCESS_DELAY' : 10,

  # Plugin Sleep period in case of an error.
  'SLEEP_PERIOD' : 0.1,
}

class ChainDistMonitorPlugin(BasePlugin):

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
    self.chainstore_hset(
      hkey='chain_dist_monitor',
      key=self.node_addr,
      value=self.time(),
    )
    self.last_live_check = self.time()
    
    # check if node in list and add if not
    return
  
  
  def check_all_jobs(self):
    # check if there are any jobs that need to be validated bc.web3_get_unvalidated_jobs() (returns PENDING or IN-CHANGE jobs)
    # for each unvalidated job:
      # get all running apps via netmon.network_known_apps
        # find in these apps the one with the same deeploy_specs.job_id -> collect all running nodes
           # bc.web3_submit_node_update
           
    unvalidated_job_ids = self.bc.get_unvalidated_job_ids(oracle_address=self.bc.eth_address)
    if not unvalidated_job_ids or not len(unvalidated_job_ids):
      pass
    else:
      known_apps = self.netmon.network_known_apps()
      for job_id in unvalidated_job_ids:
        if not job_id:
          continue
        
        # find all running apps with the same job_id
        running_nodes = []
        self.Pd(f"Checking for running nodes for job {job_id}...", verbosity=3)

        for node, apps in known_apps.items():
          for pipeline_name, pipeline in apps.items():
            # TODO: Use const from sdk for deeploy_specs.
            deeploy_specs = pipeline.get('deeploy_specs', {})
            if deeploy_specs.get('job_id') == job_id:
              running_nodes.append(node)
        
        # if we have running nodes, submit the update
        if len(running_nodes):
          running_nodes_eth = [self.bc.node_address_to_eth_address(node) for node in running_nodes]
          running_nodes_eth = sorted(running_nodes_eth)
          self.P(f"Found {len(running_nodes)} running nodes for job {job_id}: {running_nodes_eth}", verbosity=3)
          self.bc.submit_node_update( 
            job_id=job_id,
            nodes=running_nodes_eth,
          )
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
    MIN_THRESHOLD = self.cfg_process_delay * 1    # 10 * 1 = 10 seconds
    MAX_THRESHOLD = self.cfg_process_delay * 10   # 10 * 10 = 100 seconds
    last_epoch = self.netmon.epoch_manager.get_current_epoch() - 1
    if last_epoch not in self.epochs_closed:
      # epoch just closed we can start timer
      delay = self.np.random.randint(MIN_THRESHOLD, MAX_THRESHOLD)
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

    MIN_THRESHOLD = self.cfg_process_delay * 1    # 10 * 1 = 10 seconds
    MAX_THRESHOLD = self.cfg_process_delay * 25   # 10 * 25 = 250 seconds
    if closable_job_id not in self.jobs_to_close:
      delay = self.np.random.randint(MIN_THRESHOLD, MAX_THRESHOLD)
      self.jobs_to_close[closable_job_id] = {
        'job_id': closable_job_id,
        'start_timer': self.time(),
        'job_closed': False,
        'delay': delay
      }
      self.P(f"Will try to close job {closable_job_id} in {delay} seconds.")

    if not self.jobs_to_close[closable_job_id]['job_closed']:
      if (self.time() - self.jobs_to_close[closable_job_id]['start_timer']) > self.jobs_to_close[closable_job_id]['delay']:
        #TODO (Vitalii): close the job on the nodes, then submit_node_update with empty nodes list
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
      self.check_all_jobs()
      self.maybe_distribute_rewards()
      self.check_closable_jobs()
      self.maybe_update_liveness()
    except Exception as e:
      self.P(f"Exception during process:\n{self.trace_info()}\nSleeping for {self.cfg_sleep_period} seconds.", color='r')
      self.sleep(self.cfg_sleep_period)
    # endtry-except
    return