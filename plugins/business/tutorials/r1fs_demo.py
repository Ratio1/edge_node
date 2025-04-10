"""

```json
{
    "NAME": "r1fs_demo_pipeline",
    "PLUGINS": [

        {
            "INSTANCES": [
                {
                    "INSTANCE_ID": "DEFAULT"
                }
            ],
            "SIGNATURE": "R1FS_DEMO"
        }
        
    ],
    "TYPE": "Void"
}  
```


```python

from ratio1 import Instance, Payload, Pipeline, Session

if __name__ == '__main__':

  session: Session = Session()
  
  # this code assumes the node have "allowed" the SDK to deploy the pipeline
  nodes = [
    '0xai_A2LfyeItL5oEp7nHONlczGgwS3SV8Ims9ujJ0soJ6Anx',
    '0xai_AqgKnJMNvUvq5n1wIin_GD2i1FbZ4FBTUJaCI6cWf7i4',
  ]

  for node in nodes:
    session.wait_for_node(node=node) # we wait for the node to be ready
    pipeline: Pipeline = session.create_pipeline(
      node=node,
      name='r1fs_demo_pipeline',
      data_source='Void',
    )

    instance: Instance = pipeline.create_plugin_instance(
      signature='R1FS_DEMO',
      instance_id='inst01',
    )

    pipeline.deploy()

  session.wait(
    seconds=300,            # we wait the session for 60 seconds
    close_pipelines=True,   # we close the pipelines after the session
    close_session=True,     # we close the session after the session
  )
  session.P("Main thread exiting...")

```
  
"""


from naeural_core.business.base import BasePluginExecutor as BasePlugin

__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  # our overwritten props
  'PROCESS_DELAY' : 15,  
  # due to the fact that we are using a "void" pipeline,
  # we need to allow empty inputs as we are not getting any 
  # data from the pipeline
  'ALLOW_EMPTY_INPUTS': True, 
  'VALIDATION_RULES' : {
    **BasePlugin.CONFIG['VALIDATION_RULES'],    
  },  
}

class R1fsDemoPlugin(BasePlugin):
  
  def on_init(self):
    # we store a unique ID for this worker (instance) asuming it is unique
    self.my_id = f'r1:{self.ee_id}' # node alias is just a naive approach
    self.__file_send_time = 0 # last time we sent a file
    self.__known_cids = [] # keep track of known CIDs
    self.__start_time = self.time() # start time of the plugin
    self.__r1fs_demo_iter = 0 # iteration counter
    self.P(f"Starting R1fsDemoPlugin v{__VER__} with ID: {self.my_id}.")
    self._last_log_show_time = 0 # last time we logged something
    return
  
  def __save_some_data(self):
    """ Save some data to the R1FS """
    self.P("Saving some data...")
    uuid = self.uuid() # generate some random data
    value = self.np.random.randint(1, 100) # even more random data
    data = {
      'some_key': uuid,
      'other_key': value,
      'owner_id' : self.my_id,
      'owner_key' : self.full_id
    }
    filename = f"{self.ee_id}_{self.__r1fs_demo_iter}"
    cid = self.r1fs.add_yaml(data, fn=filename)
    self.P(f"Data saved with CID: {cid}")
    return cid
  
  def __announce_cid(self, cid):
    """ Announce the CID to the network via ChainStore hsets"""
    self.P(f'Announcing CID: {cid} for {self.my_id}')
    self.chainstore_hset(hkey='r1fs-demo', key=self.my_id, value=cid)
    return    
  
  def __get_announced_cids(self):
    """ Get all announced CIDs except our own from ChainStore hsets"""
    cids = []
    self.P("Checking for any announced CIDs...")
    # get full dictionary of all announced CIDs under the key 'r1fs-demo'
    # we assume all demo instances are using the same hkey and their own key
    dct_data = self.chainstore_hgetall('r1fs-demo')
    self.P(f"Extracted hset data ({self.my_id=}):\n {self.json_dumps(dct_data, indent=2)}")
    if dct_data:
      # extract all the CIDs except our own
      cids = [
        v for k, v in dct_data.items() if k != self.my_id
      ]
      # now we filter based on already known CIDs
      cids = [
        cid for cid in cids if cid not in self.__known_cids
      ]
    if len(cids) > 0:
      self.P(f"Found {len(cids)} CIDs ")
      self.__known_cids.extend(cids)
    return cids
  
  def share_local_data(self):
    """ Share some data with the network """
    if self.time() - self.__file_send_time > 3600:
      self.P("Sharing data...")
      cid = self.__save_some_data()
      self.__announce_cid(cid)
    return cid
  
  def show_remote_shared_data(self):
    """ Retrieve and process shared data """
    cids = self.__get_announced_cids()
    self.P(f"Found {len(cids)} shared data...")
    for cid in cids:
      self.P(f"Retrieving: {cid}")
      fn = self.r1fs.get_file(cid)
      self.P(f"Retrieved: {fn}")
      if fn.endswith('.yaml') or fn.endswith('.yml'):
        data = self.diskapi_load_yaml(fn, verbose=False)        
        self.P(f"Loaded:\n {self.json_dumps(data, indent=2)}")
        self.P("Delivering the data to potential consumers...")
        self.add_payload_by_fields(
          r1fs_data=data,
        )
      else:
        self.P(f"Received unsupported file: {fn}", color='r')
    # end for each CID
    return
    


  def process(self):
    if not self.r1fs.is_ipfs_warmed:
      current_time = self.time()
      if current_time - self._last_log_show_time > 60: # log every 60 sec
        self.P(f"Waiting for R1FS to warm up. Time elapsed since plugin start {current_time - self.__start_time:.1f} seconds.")
        self._last_log_show_time= current_time
      return
    self.__r1fs_demo_iter += 1
    self.P(f'R1fsDemoPlugin is processing iter #{self.__r1fs_demo_iter}')
    self.share_local_data()
    self.show_remote_shared_data()
    self.P('R1fsDemoPlugin is done.')
    return