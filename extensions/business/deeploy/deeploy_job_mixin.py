from extensions.business.dauth.dauth_registry import (
  DAUTH_SECRET_PIPELINE_CID_KEY,
  dauth_registry_write_kwargs,
  get_dauth_registry_internal_peers,
  pipeline_registry_write_kwargs,
)

NONCE = 42
R1FS_FILENAME = 'data.json'
DEEPLOY_JOBS_CSTORE_HKEY = "DEEPLOY_DEPLOYED_JOBS"
DAUTH_JOB_SECRETS_CSTORE_HKEY = "DAUTH_JOB_SECRETS"


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

    if pipeline is None:
      return None
    if not isinstance(pipeline, dict):
      return None

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
      if pipeline is None:
        self.P(f"Skipping CSTORE save for job {job_id}: pipeline is None", color='y')
        return False
      if not isinstance(pipeline, dict):
        self.P(f"Skipping CSTORE save for job {job_id}: pipeline is of type {type(pipeline).__name__}", color='y')
        return False

      self.P("Saving pipeline to CSTORE...")

      sanitized_pipeline = self.extract_invariable_data_from_pipeline(pipeline)
      if sanitized_pipeline is None:
        self.P(f"Skipping CSTORE save for job {job_id}: unable to sanitize pipeline payload", color='y')
        return False

      sorted_pipeline = self._recursively_sort_pipeline_data(sanitized_pipeline)
      cid = self._save_pipeline_to_r1fs(sorted_pipeline)

      self.P(f"Pipeline {job_id} saved to R1FS with CID: {cid}")

      pipeline_key = str(job_id)

      result = self.chainstore_hset(
        hkey=DEEPLOY_JOBS_CSTORE_HKEY,
        key=pipeline_key,
        value=cid,
        **pipeline_registry_write_kwargs(self),
      )
    except Exception as e:
      self.P(f"Error saving pipeline for job {job_id} to CSTORE: {e}", color='r')
      return False

    return result

  def _load_dauth_job_secret_bundle(self, job_id):
    return self.chainstore_hget(
      hkey=DAUTH_JOB_SECRETS_CSTORE_HKEY,
      key=str(job_id),
    )

  def _write_dauth_job_secret_bundle(self, job_id, bundle, write_kwargs=None):
    if write_kwargs is None:
      write_kwargs = dauth_registry_write_kwargs(self)
    return self.chainstore_hset(
      hkey=DAUTH_JOB_SECRETS_CSTORE_HKEY,
      key=str(job_id),
      value=bundle,
      **write_kwargs,
    )

  def _write_job_pipeline_cid(self, job_id, cid, write_kwargs=None):
    if write_kwargs is None:
      write_kwargs = pipeline_registry_write_kwargs(self)
    return self.chainstore_hset(
      hkey=DEEPLOY_JOBS_CSTORE_HKEY,
      key=str(job_id),
      value=cid,
      **write_kwargs,
    )

  def stage_job_pipeline_and_secrets(self, pipeline, job_id, secret_bundle):
    """Stage redacted pipeline metadata and its complete dAuth bundle."""
    if job_id in [None, ""]:
      raise ValueError("Cannot stage Deeploy metadata without job_id.")
    if not isinstance(pipeline, dict):
      raise ValueError("Cannot stage invalid Deeploy pipeline metadata.")
    if not isinstance(secret_bundle, dict):
      raise ValueError("Cannot stage invalid dAuth secret bundle.")

    job_id = str(job_id)
    # Resolve both routes before creating an R1FS object, so a missing registry
    # cannot leave an unreferenced staged CID behind.
    registry_peers = get_dauth_registry_internal_peers(self)
    pipeline_write_kwargs = pipeline_registry_write_kwargs(self, peers=registry_peers)
    secret_write_kwargs = dauth_registry_write_kwargs(self, peers=registry_peers)
    prior_cid = self._get_pipeline_from_cstore(job_id)
    prior_bundle = self._load_dauth_job_secret_bundle(job_id)
    sanitized_pipeline = self.extract_invariable_data_from_pipeline(pipeline)
    sorted_pipeline = self._recursively_sort_pipeline_data(sanitized_pipeline)
    staged_cid = self._save_pipeline_to_r1fs(sorted_pipeline)
    if not staged_cid:
      raise ValueError(f"Failed to stage pipeline metadata for job {job_id} in R1FS.")

    bound_secret_bundle = self.deepcopy(secret_bundle)
    bound_secret_bundle[DAUTH_SECRET_PIPELINE_CID_KEY] = staged_cid
    state = {
      "job_id": job_id,
      "prior_cid": prior_cid,
      "prior_bundle": self.deepcopy(prior_bundle),
      "staged_cid": staged_cid,
      "staged_bundle": self.deepcopy(bound_secret_bundle),
      "pipeline_staged": False,
      "bundle_staged": False,
      "pipeline_write_kwargs": pipeline_write_kwargs,
      "secret_write_kwargs": secret_write_kwargs,
    }
    try:
      if not self._write_dauth_job_secret_bundle(
        job_id,
        self.deepcopy(bound_secret_bundle),
        write_kwargs=secret_write_kwargs,
      ):
        raise ValueError(f"Failed to stage dAuth secrets for job {job_id}.")
      state["bundle_staged"] = True
      if not self._write_job_pipeline_cid(
        job_id,
        staged_cid,
        write_kwargs=pipeline_write_kwargs,
      ):
        raise ValueError(f"Failed to stage pipeline CID for job {job_id}.")
      state["pipeline_staged"] = True
    except Exception:
      self.rollback_staged_job_pipeline_and_secrets(state)
      raise
    return state

  def commit_staged_job_pipeline_and_secrets(self, state):
    """Commit a staged transaction by removing its superseded R1FS object."""
    if not isinstance(state, dict):
      return False
    staged_cid = state.get("staged_cid")
    try:
      current_cid = self._get_pipeline_from_cstore(state.get("job_id"))
      current_bundle = self._load_dauth_job_secret_bundle(state.get("job_id"))
    except Exception as exc:
      self.Pd(f"Unable to verify staged pipeline commit: {exc}", color='y')
      return False
    if (
      current_cid != staged_cid
      or current_bundle != state.get("staged_bundle")
    ):
      return False
    prior_cid = state.get("prior_cid")
    if prior_cid and prior_cid != staged_cid:
      self._delete_pipeline_cid_from_r1fs(prior_cid)
    return True

  def rollback_staged_job_pipeline_and_secrets(self, state):
    """Restore matching staged state without disturbing a newer deployment."""
    if not isinstance(state, dict):
      return False
    job_id = state.get("job_id")
    staged_cid = state.get("staged_cid")
    restored = False
    try:
      current_cid = self._get_pipeline_from_cstore(job_id)
      current_bundle = self._load_dauth_job_secret_bundle(job_id)
      expected_cid = (
        staged_cid if state.get("pipeline_staged") else state.get("prior_cid")
      )
      expected_bundle = (
        state.get("staged_bundle") if state.get("bundle_staged")
        else state.get("prior_bundle")
      )
      if current_cid == expected_cid and current_bundle == expected_bundle:
        try:
          pipeline_ok = True
          if state.get("pipeline_staged"):
            pipeline_ok = self._write_job_pipeline_cid(
              job_id,
              state.get("prior_cid"),
              write_kwargs=state.get("pipeline_write_kwargs"),
            )
          bundle_ok = True
          if state.get("bundle_staged"):
            bundle_ok = self._write_dauth_job_secret_bundle(
              job_id,
              self.deepcopy(state.get("prior_bundle")),
              write_kwargs=state.get("secret_write_kwargs"),
            )
          restored = bool(pipeline_ok and bundle_ok)
          if restored:
            self._delete_pipeline_cid_from_r1fs(staged_cid)
        except Exception as exc:
          self.Pd(f"Unable to restore staged Deeploy metadata for job {job_id}: {exc}", color='y')
    except Exception as exc:
      self.Pd(f"Unable to verify staged Deeploy rollback for job {job_id}: {exc}", color='y')
    return restored

  def list_all_deployed_jobs_from_cstore(self):
    """
    Get all the job pipelines from CSTORE.
    """
    return self.chainstore_hgetall(hkey=DEEPLOY_JOBS_CSTORE_HKEY)

  def get_job_pipeline_from_cstore(
    self,
    job_id: int,
    timeout: int = None,
    pin: bool = True,
    raise_on_error: bool = False,
    show_logs: bool = False,
  ):
    """
    Get the pipeline from CSTORE and download it from R1FS.
    """
    cid = self._get_pipeline_from_cstore(job_id)
    if not cid:
      return None
    
    return self.get_pipeline_from_r1fs(
      cid,
      timeout=timeout,
      pin=pin,
      raise_on_error=raise_on_error,
      show_logs=show_logs,
    )
    
  def _get_pipeline_from_cstore(self, job_id: int):
    """
    Get the pipeline from CSTORE.
    """
    return self.chainstore_hget(hkey=DEEPLOY_JOBS_CSTORE_HKEY, key=str(job_id))
  
  def get_pipeline_from_r1fs(
    self,
    cid: str,
    timeout: int = None,
    pin: bool = True,
    raise_on_error: bool = False,
    show_logs: bool = False,
  ):
    """
    Get the pipeline from R1FS.
    """
    return self.r1fs.get_json(
      cid,
      timeout=timeout,
      pin=pin,
      raise_on_error=raise_on_error,
      show_logs=show_logs,
    )

  def _save_pipeline_to_r1fs(self, pipeline: dict):
    """
    Save the pipeline to R1FS.
    """

    try:
      self.Pd(
        "Saving pipeline to R1FS: {}".format(
          self.json_dumps(self._redact_per_node_config_for_log(pipeline))
        )
      )
      cid = self.r1fs.add_json(pipeline, nonce=NONCE, fn=R1FS_FILENAME, show_logs=False)
      self.Pd(f"Pipeline saved to R1FS with CID: {cid}")
      calc_cid = self.r1fs.calculate_json_cid(pipeline, nonce=NONCE, fn=R1FS_FILENAME, show_logs=False)
      self.Pd(f"Calculated CID: {calc_cid}")
    except Exception as e:
      self.Pd(f"Error saving pipeline to R1FS: {e}")
      return None
    
    return cid

  def _delete_pipeline_cid_from_r1fs(self, cid: str):
    """
    Remove a pipeline payload from R1FS by CID.

    Parameters
    ----------
    cid: str
        The CID to remove from R1FS.

    Returns
    -------
    bool
        True when deletion completed without raising, False otherwise.
    """
    if not cid or not isinstance(cid, str):
      return False

    try:
      verbose_logs = getattr(self, "cfg_deeploy_verbose", 0) > 1
      self.Pd(f"Deleting R1FS pipeline CID {cid}", color='y')
      self.r1fs.delete_file(cid, show_logs=verbose_logs, raise_on_error=False)
    except Exception as exc:
      self.Pd(f"Unable to delete R1FS CID {cid}: {exc}", color='y')
      return False

    return True

  def persist_job_pipeline_metadata(
    self,
    pipeline: dict,
    job_id: int,
    previous_cid: str = None,
    delete_previous: bool = False,
  ):
    """
    Persist the latest deployed pipeline metadata after deployment succeeds.

    Parameters
    ----------
    pipeline: dict
        The pipeline payload to persist.
    job_id: int
        Deeploy job identifier.
    previous_cid: str
        Previously stored CID, when available.
    delete_previous: bool
        When True, best-effort delete the previous R1FS object after the new CID
        is committed in CSTORE.

    Returns
    -------
    bool
        True when the new metadata was saved successfully, False otherwise.
    """
    save_result = self.save_job_pipeline_in_cstore(pipeline, job_id)
    if not save_result:
      return False

    if not delete_previous or not previous_cid or not isinstance(previous_cid, str):
      return True

    try:
      current_cid = self._get_pipeline_from_cstore(job_id)
    except Exception as exc:
      self.Pd(f"Unable to read updated CSTORE CID for job {job_id}: {exc}", color='y')
      return True

    if not current_cid or current_cid == previous_cid:
      return True

    self._delete_pipeline_cid_from_r1fs(previous_cid)
    return True

  def delete_job_pipeline_from_r1fs(self, job_id: int, remove_chainstore_entry: bool = False):
    """
    Remove a stored pipeline definition from R1FS (and optionally CSTORE) for the given job.

    Parameters
    ----------
    job_id: int
        The job identifier whose pipeline should be deleted.
    remove_chainstore_entry: bool
        When True, the associated CSTORE hash entry is removed after deleting the CID.

    Notes
    -----
    This helper is best-effort; failures are logged and reported via a boolean result.
    """
    if job_id is None:
      return False

    pipeline_key = str(job_id)
    try:
      cid = self.chainstore_hget(hkey=DEEPLOY_JOBS_CSTORE_HKEY, key=pipeline_key)
    except Exception as exc:
      self.Pd(f"Unable to read pipeline CID for job {job_id} from CSTORE: {exc}", color='y')
      return False

    if not cid or not isinstance(cid, str):
      return False

    if not self._delete_pipeline_cid_from_r1fs(cid):
      return False

    if remove_chainstore_entry:
      try:
        self.chainstore_hset(hkey=DEEPLOY_JOBS_CSTORE_HKEY, key=pipeline_key, value=None)
      except Exception as exc:
        self.Pd(f"Failed to remove CSTORE entry for job {job_id}: {exc}", color='y')

    return True

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
