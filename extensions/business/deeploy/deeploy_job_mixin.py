NONCE = 42
R1FS_FILENAME = 'data.json'
DEEPLOY_JOBS_CSTORE_HKEY = "DEEPLOY_DEPLOYED_JOBS"

class _DeeployJobMixin:
  """
  A mixin that provides deep job related functionality.
  For saving a job in R1FS and CStore, etc.
  """
  def __init__(self):
    super(_DeeployJobMixin, self).__init__()
    return

  def extract_invariable_data_from_pipeline(self, pipeline: dict):
    """
    Extract the main invariable data from the pipeline (excluding TIME field).
    
    Example pipeline data:
    {
      "APP_ALIAS":"xxxxxxxxxxxxxxxxxxxxx",
      "DEEPLOY_SPECS":{
        "allow_replication_in_the_wild":false,
        "current_target_nodes":[
          "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"
        ],
        "date_created":1758744914.5231802,
        "date_updated":1758744914.5231802,
        "job_id":66,
        "job_tags":[],
        "nr_target_nodes":1,
        "project_id":null,
        "project_name":null,
        "spare_nodes":[]
      },
      "IS_DEEPLOYED":true,
      "LIVE_FEED":false,
      "NAME":"xxxxxxxxxxxxx_3e02d52",
      "OWNER":"0x311a63B88df90f19cd9bD7D9000B70480d842472",
      "PLUGINS":[
        {
          "INSTANCES":[
            {
              "CHAINSTORE_PEERS":[
                "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"
              ],
              "CHAINSTORE_RESPONSE_KEY":"CONTAINER_APP_2f710e_d4c52d05",
              "CLOUDFLARE_TOKEN":"",
              "CONTAINER_RESOURCES":{
                "cpu":1,
                "memory":"128m"
              },
              "CR":"docker.io",
              "IMAGE":"tvitalii/ratio1-drive",
              "IMAGE_PULL_POLICY":"always",
              "INSTANCE_ID":"CONTAINER_APP_2f710e",
              "NGROK_USE_API":true,
              "PORT":3333,
              "RESTART_POLICY":"always",
              "TUNNEL_ENGINE":"cloudflare"
            }
          ],
          "SIGNATURE":"CONTAINER_APP_RUNNER"
        }
      ],
      "TIME":"2025-09-24 20:15:14.563115",
      "TYPE":"void"
    }
    """

    # Create a copy of the pipeline and remove the TIME field
    extracted_data = pipeline.copy()
    extracted_data.pop("TIME", None)
    extracted_data.pop("SESSION_ID", None)
    extracted_data.pop("LAST_UPDATE_TIME", None)
    extracted_data.pop("plugins", None)

    return extracted_data

  def save_job_pipeline_in_cstore(self, pipeline: dict, job_id: int):
    """
    Save the pipeline to CSTORE.
    Args:
        pipeline (dict): The pipeline to save.
        job_id (int): The job ID.

    Returns:
        None
    """
    result = False
    try: 
      self.P("Saving pipeline to CSTORE...")
      self.P(f"Pipeline: {self.json_dumps(pipeline, indent=2)}")

      sanitized_pipeline = self.extract_invariable_data_from_pipeline(pipeline)
      sorted_pipeline = self._recursively_sort_pipeline_data(sanitized_pipeline)
      cid = self._save_pipeline_to_r1fs(sorted_pipeline)

      self.P(f"Pipeline {job_id} saved to R1FS with CID: {cid}")
      self.P(f"Pipeline: {self.json_dumps(sorted_pipeline)}")
      
      pipeline_key = str(job_id)

      result = self.chainstore_hset(hkey=DEEPLOY_JOBS_CSTORE_HKEY, key=pipeline_key, value=cid)
    except Exception as e:
      self.P(f"Error saving pipeline for job {job_id} to CSTORE: {e}", color='r')
      return False

    return result

  def list_all_deployed_jobs_from_cstore(self):
    """
    Get all the job pipelines from CSTORE.
    """
    return self.chainstore_hgetall(hkey=DEEPLOY_JOBS_CSTORE_HKEY)

  def get_job_pipeline_from_cstore(self, job_id: int):
    """
    Get the pipeline from CSTORE and download it from R1FS.
    """
    cid = self._get_pipeline_from_cstore(job_id)
    if not cid:
      return None
    
    return self.get_pipeline_from_r1fs(cid)
    
  def _get_pipeline_from_cstore(self, job_id: int):
    """
    Get the pipeline from CSTORE.
    """
    return self.chainstore_hget(hkey=DEEPLOY_JOBS_CSTORE_HKEY, key=str(job_id))
  
  def get_pipeline_from_r1fs(self, cid: str):
    """
    Get the pipeline from R1FS.
    """
    return self.r1fs.get_json(cid, show_logs=True)

  def _save_pipeline_to_r1fs(self, pipeline: dict):
    """
    Save the pipeline to R1FS.
    """

    try:
      cid = self.r1fs.add_json(pipeline, nonce=NONCE, fn=R1FS_FILENAME, show_logs=True)
      self.P(f"Pipeline saved to R1FS with CID: {cid}")
      calc_cid = self.r1fs.calculate_json_cid(pipeline, nonce=NONCE, fn=R1FS_FILENAME, show_logs=True)
      self.P(f"Calculated CID: {calc_cid}")
    except Exception as e:
      self.P(f"Error saving pipeline to R1FS: {e}")
      return None
    
    return cid

  def _recursively_sort_pipeline_data(self, data):
    """
    Recursively sort pipeline data including items within arrays.
    
    Args:
        data: The data to sort (dict, list, or primitive)
        
    Returns:
        Sorted data with the same structure
    """
    if isinstance(data, dict):
      # Sort dictionary by keys and recursively sort values
      sorted_dict = {}
      for key in sorted(data.keys()):
        sorted_dict[key] = self._recursively_sort_pipeline_data(data[key])
      return sorted_dict
    elif isinstance(data, list):
      # Sort list items recursively
      sorted_list = []
      for item in data:
        sorted_list.append(self._recursively_sort_pipeline_data(item))
      # Sort the list items themselves if they are comparable
      try:
        sorted_list.sort()
      except TypeError:
        # If items can't be compared (e.g., different types), keep original order
        pass
      return sorted_list
    else:
      # Return primitive values as-is
      return data
