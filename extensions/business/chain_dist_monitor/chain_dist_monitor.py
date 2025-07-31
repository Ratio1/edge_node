from naeural_core.business.base import BasePluginExecutor as BasePlugin


__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  # end of mandatory area
  
  "RUNS_ONLY_ON_SUPERVISOR_NODE" : True,

  # our overwritten props
  'PROCESS_DELAY' : 1,
}

class ChainDistMonitorPlugin(BasePlugin):
  
  def on_init(self):
    self.chainstore_hset(
      hkey='chain_dist_monitor',
      key=self.node_addr,
      value=self.time(),
    )
    self.last_live_check = self.time()
    return
  
  
  def check_all_jobs(self):
    #
    return
    
    
  def maybe_distribute_rewards(self):
    # check if epoch has been closed > 10m < 1h
      # check if current node is the next in line to call rewards distribution    
        # if so call bc.web3_distribute_rewards() THEN move token to the next oracle in line
    # >1h check if last epoch rewards have been distributed
      # if not then check if next in line -> then assume token -> call bc.web3_distribute_rewards() THEN move token
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
    return