# from ratio1 import Payload, Session

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from naeural_core.business.mixins_libs.network_processor_mixin import _NetworkProcessorMixin
from extensions.business.ai4e.ai4e_utils import AI4E_CONSTANTS, Job, get_job_config, job_data_to_id

__VER__ = '0.1.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'SAVE_PERIOD': 300,
  'REQUEST_TIMEOUT': 10,
  "PROCESS_DELAY": 0,
  "DEPLOY_NGROK_EDGE_LABEL": None,
  "LOG_REQUESTS": True,
  "DEBUG_WEB_APP": True,

  # 'PORT': 5000,
  'ASSETS': 'extensions/business/ai4e',
  'JINJA_ARGS': {
    'html_files': [
      {
        'name': 'index.html',
        'route': '/',
        'method': 'get'
      }
    ]
  },
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}





class AI4EveryonePlugin(
  BasePlugin, 
  _NetworkProcessorMixin
):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    # self.__init_done = False
    super(AI4EveryonePlugin, self).__init__(**kwargs)
    self.jobs_data = {}
    self.requests_responses = {}
    self.last_persistence_save = self.time()
    self.request_cache = {}
    self.force_persistence = False
    return

  def on_init(self):
    super(AI4EveryonePlugin, self).on_init()
    self.network_processor_init()
    self.jobs_data = self.load_persistence_data()
    # self.__init_done = True
    return

  """PAYLOAD HANDLING SECTION"""
  if True:
    def payload_handler_helper(self, data):
      is_status = data.get('IS_STATUS', False)
      is_final_dataset_status = data.get('IS_FINAL_DATASET_STATUS', False)
      if is_status or is_final_dataset_status:
        try:
          self.maybe_update_job_data(data)
        except Exception as e:
          if self.cfg_debug_web_app:
            self.P(f"[DEBUG_AI4E]Error while updating job data: {e}")
        # endtry
      else:
        try:
          self.register_request_response(data)
        except Exception as e:
          if self.cfg_debug_web_app:
            self.P(f"[DEBUG_AI4E]Error while registering request response: {e}")
        # endtry
      # endif is_status or is_final_dataset_status
      return

    @_NetworkProcessorMixin.payload_handler(signature="AI4E_CROP_DATA")
    def on_payload_crop_data(self, data):
      return self.payload_handler_helper(data)

    @_NetworkProcessorMixin.payload_handler(signature="AI4E_LABEL_DATA")
    def on_payload_label_data(self, data):
      return self.payload_handler_helper(data)

    @_NetworkProcessorMixin.payload_handler(signature="SECOND_STAGE_TRAINING_PROCESS")
    def on_payload_second_stage_training(self, data):
      return self.payload_handler_helper(data)

    @_NetworkProcessorMixin.payload_handler(signature="GENERAL_TRAINING_PROCESS")
    def on_payload_general_training(self, data):
      return self.payload_handler_helper(data)

    @_NetworkProcessorMixin.payload_handler(signature="MINIO_UPLOAD_DATASET")
    def on_payload_minio_upload_dataset(self, data):
      return self.payload_handler_helper(data)

    # def on_payload(self, sess: Session, node_id: str, pipeline: str, signature: str, instance: str, payload: Payload):
    #   if signature.lower() not in AI4E_CONSTANTS.RELEVANT_PLUGIN_SIGNATURES:
    #     return
    #   if not self.__init_done:
    #     sess.P(f"[DEBUG_AI4E]Session not initialized yet, ignoring payload.")
    #     return
    #   is_status = payload.data.get('IS_STATUS', False)
    #   is_final_dataset_status = payload.data.get('IS_FINAL_DATASET_STATUS', False)
    #   if is_status or is_final_dataset_status:
    #     try:
    #       self.maybe_update_job_data(node_id, pipeline, signature, instance, payload)
    #     except Exception as e:
    #       if self.cfg_debug_web_app:
    #         self.P(f"[DEBUG_AI4E]Error while updating job data: {e}")
    #     # endtry
    #   else:
    #     try:
    #       self.register_request_response(node_id, pipeline, signature, instance, payload)
    #     except Exception as e:
    #       if self.cfg_debug_web_app:
    #         self.P(f"[DEBUG_AI4E]Error while registering request response: {e}")
    #     # endtry
    #   return

    def maybe_update_job_data(self, data):
      payload_path = data.get(self.ct.PAYLOAD_DATA.EE_PAYLOAD_PATH)
      if payload_path is None:
        return
      node_id, pipeline, signature, instance = payload_path
      job_id = job_data_to_id(node_id, pipeline, signature, instance)
      if job_id not in self.jobs_data:
        self.jobs_data[job_id] = Job(
          owner=self, job_id=job_id,
          node_id=node_id, pipeline=pipeline,
          signature=signature, instance=instance
        )
      job = self.jobs_data[job_id]
      job.maybe_update_data(
        data=data,
        pipeline=pipeline,
        signature=signature
      )
      return

    def register_request_response(self, data: dict):
      request_id = data.get('REQUEST_ID')
      if request_id is None:
        return
      self.requests_responses[request_id] = data
      return

    def send_request(self, job: Job, **kwargs):
      request_id = self.uuid()
      status, msg = job.send_instance_command(
        REQUEST_ID=request_id,
        **kwargs
      )
      return status, msg, request_id

    def solve_postponed_process_request(
        self, request_id: str, job: Job, request_ts: float, **request_kwargs
    ):
      if request_id in self.requests_responses:
        data = self.requests_responses.pop(request_id)
        return data
      if self.time() - request_ts > self.cfg_request_timeout:
        return {"error": "Request timed out"}
      return self.create_postponed_request(
        solver_method=self.solve_postponed_process_request,
        method_kwargs={
          'request_id': request_id,
          'job': job,
          'request_ts': request_ts,
          **request_kwargs
        }
      )

    def process_request(self, job: Job, **request_kwargs):
      status, msg, request_id = self.send_request(job, **request_kwargs)
      if not status:
        return False, {"error": f"Failed to send request: {msg}"}
      request_ts = self.time()
      return self.create_postponed_request(
        solver_method=self.solve_postponed_process_request,
        method_kwargs={
          'request_id': request_id,
          'job': job,
          'request_ts': request_ts,
          **request_kwargs
        }
      )

    def cache_request_data(self, job_id: str, data_id: str, data: dict):
      if job_id not in self.request_cache:
        self.request_cache[job_id] = {}
      # endif job_id not in cache
      if data_id not in self.request_cache[job_id]:
        self.request_cache[job_id][data_id] = {}
      # endif data_id not in cache
      self.request_cache[job_id][data_id] = {**data}
      return

    def get_cached_request_data(self, job_id: str, data_id: str):
      return self.request_cache.get(job_id, {}).get(data_id)

    def solve_postponed_process_sample_request(
        self, request_id: str, job: Job, request_ts: float, handle_votes: bool = False,
        **request_kwargs
    ):
      if request_id in self.requests_responses:
        response_data = self.requests_responses.pop(request_id)
        sample_filename = response_data.get('SAMPLE_FILENAME')
        if sample_filename is None:
          return {"error": "Sample not found"}
        img = response_data.get('IMG')
        votes = None
        cache_kwargs = {
          'img': img
        }
        if img is not None:
          if handle_votes:
            votes = response_data.get('VOTES')
            cache_kwargs['votes'] = votes
          # endif handle votes
          current_data = self.get_cached_request_data(job.job_id, sample_filename)
          new_data = {} if current_data is None else current_data
          new_data = {**new_data, **cache_kwargs}
          self.cache_request_data(job.job_id, data_id=sample_filename, data=new_data)
        # endif img is not None
        res = {"name": sample_filename, "content": img}
        if handle_votes:
          res['classes'] = job.classes
          if votes is not None:
            res['votes'] = votes
          # endif votes is not None
        # endif handle votes
        return res
      if self.time() - request_ts > self.cfg_request_timeout:
        return {"error": "Request timed out"}
      return self.create_postponed_request(
        solver_method=self.solve_postponed_process_sample_request,
        method_kwargs={
          'request_id': request_id,
          'job': job,
          'request_ts': request_ts,
          'handle_votes': handle_votes,
          **request_kwargs
        }
      )

    def process_sample_request(self, job: Job, handle_votes: bool = False, vote_required: bool = False):
      request_kwargs = {'SAMPLE_DATAPOINT': True} if vote_required else {'SAMPLE': True}
      status, msg, request_id = self.send_request(job, **request_kwargs)
      if not status:
        return False, {"error": f"Failed to send request: {msg}"}
      request_ts = self.time()
      return self.create_postponed_request(
        solver_method=self.solve_postponed_process_sample_request,
        method_kwargs={
          'request_id': request_id,
          'job': job,
          'request_ts': request_ts,
          'handle_votes': handle_votes,
          **request_kwargs
        }
      )

    def data_to_response(self, data: dict, mandatory_fields: list = ['img']):
      processed_data = {k.lower(): v for k, v in data.items()}
      mandatory_fields = [field.lower() for field in mandatory_fields]
      for field in mandatory_fields:
        if field not in processed_data:
          return False, {"error": f"`{field}` not found in data."}
      # endfor mandatory fields

      res = {'content': processed_data.get('img')}
      if 'votes' in processed_data:
        res['votes'] = processed_data.get('votes')
      return True, res

    def process_filename_request(self, job: Job, filename: str, force_refresh: bool = False):
      if not force_refresh:
        # Check if the data is cached
        cached_data = self.get_cached_request_data(
          job_id=job.job_id,
          data_id=filename
        )
        if cached_data is not None:
          return self.data_to_response(cached_data)
      # endif not force_refresh
      res = self.process_request(job, FILENAME=filename, FILENAME_REQUEST=True)
      if isinstance(res, tuple):
        success, response_data = res
        if not success:
          return success, response_data
        return self.data_to_response(response_data)
      return res

    def start_job(self, nodeAddress: str, job_config: dict):
      job_id = self.uuid()
      job_config = get_job_config(job_id, job_config=job_config, creation_date=self.now_str())
      pipeline_name = f'cte2e_{job_id}'
      self.session.create_pipeline(
        node=nodeAddress,
        name=pipeline_name,
        data_source="VOID",
        plugins=[job_config]
      ).deploy()
  """END PAYLOAD HANDLING SECTION"""

  """ENDPOINTS SECTION"""
  if True:
    @BasePlugin.endpoint
    def jobs(self):
      return [job.to_msg() for job in self.jobs_data.values()]

    @BasePlugin.endpoint
    def job(self, job_id: str):
      if job_id in self.jobs_data:
        return self.jobs_data[job_id].to_msg()
      return None

    @BasePlugin.endpoint(method="post")
    def create_job(
        self, name: str, description: str, target: list or str,
        rewards: dict, dataSources: list, dataset: dict,
        nodeAddress: str = None,
    ):
      if not isinstance(target, list):
        target = [target]
      # Pack the job config
      job_config = {
        "name": name,
        "description": description,
        "target": target,
        "rewards": rewards,
        "dataSources": dataSources,
        "dataset": dataset,
        # "classes": classes,
      }
      nodeAddress = nodeAddress or self.e2_addr
      self.P(f'Received job creation request for {nodeAddress}: `{name}` - `{description}`')
      return self.start_job(nodeAddress=nodeAddress, job_config=job_config)

    @BasePlugin.endpoint(method="post")
    def stop_job(self, job_id: str):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].stop_acquisition()
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def publish_job_2(
        self, job_id: str, body: dict

        # self, job_id: str, name: str, description: str, target: list or str,
        # rewards: dict, dataSources: list, dataset: dict,
        # classes: list[dict]
    ):
      classes = body.get('classes')
      rewards = body.get('rewards')
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].publish_job(classes=classes, rewards=rewards)
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def publish_job(
        self, job_id: str, name: str, description: str, target: list or str,
        rewards: dict, dataSources: list, dataset: dict,
        classes: list[dict]
    ):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].publish_job(classes=classes, rewards=rewards)
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    # TODO: receive list of votes
    def vote(self, job_id: str, filename: str, label: str):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].send_vote(filename=filename, label=label)
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def stop_labeling(self, job_id: str):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].stop_labeling()
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def publish_labels(self, job_id: str):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].publish_labels()
        if success:
          self.force_persistence = True
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def train(self, job_id: str, body: dict):
      if job_id in self.jobs_data:
        success, result = self.jobs_data[job_id].start_train(body)
        if success:
          self.force_persistence = True
        return result if success else None
      return None

    @BasePlugin.endpoint(method="post")
    def deploy_job(self, job_id: str, body: dict):
      if job_id in self.jobs_data:
        """
        After starting the deploy the status will change to "Deploying"
        After deploying the status will be "Deployed"
        
        """
        success, result = self.jobs_data[job_id].deploy_job(body)
        if success:
          self.force_persistence = True
        return result if success else None
      return None

    """
    @BasePlugin.endpoint(method="post")
    def delete_job(self, job_id):
      pass  # TODO
    """

    @BasePlugin.endpoint(method="get")
    def job_status(self, job_id: str):
      if job_id in self.jobs_data:
        return self.jobs_data[job_id].get_status()
      return None

    @BasePlugin.endpoint(method="get")
    def labeling_status(self, job_id: str):
      if job_id in self.jobs_data:
        return self.jobs_data[job_id].get_labeling_status()
      return None

    @BasePlugin.endpoint(method="get")
    def training_status(self, job_id: str):
      if job_id in self.jobs_data:
        return self.jobs_data[job_id].get_train_status()
      return None

    @BasePlugin.endpoint(method="get")
    def data_sample(self, job_id: str):
      if job_id in self.jobs_data:
        res = self.process_sample_request(self.jobs_data[job_id])
        if isinstance(res, tuple):
          success, result = res
          return result if success else None
        return res
      return None

    @BasePlugin.endpoint(method="get")
    def data_filename(self, job_id: str, filename: str):
      if job_id in self.jobs_data:
        res = self.process_filename_request(self.jobs_data[job_id], filename=filename)
        if isinstance(res, tuple):
          success, result = res
          return result if success else None
        return res
      return None

    @BasePlugin.endpoint(method="get")
    def datapoint(self, job_id: str):
      if job_id in self.jobs_data:
        res = self.process_sample_request(self.jobs_data[job_id], handle_votes=True)
        if isinstance(res, tuple):
          success, result = res
          return result if success else None
        return res
      return None

    @BasePlugin.endpoint(method="get")
    def datapoint_sample(self, job_id: str):
      if job_id in self.jobs_data:
        res = self.process_sample_request(self.jobs_data[job_id], handle_votes=True, vote_required=True)
        if isinstance(res, tuple):
          success, result = res
          return result if success else None
        return res
      return None

    @BasePlugin.endpoint(method="get")
    def datapoint_filename(self, job_id: str, filename: str):
      if job_id in self.jobs_data:
        res = self.process_filename_request(self.jobs_data[job_id], filename=filename)
        if isinstance(res, tuple):
          success, result = res
          return result if success else None
        return res
      return None

    @BasePlugin.endpoint(method="get")
    def baseclasses(self):
      return self._get_available_first_stage_classes()

    @BasePlugin.endpoint
    def datasourcetypes(self):
      return self._get_available_data_source_types()

    @BasePlugin.endpoint
    def stage2classifiers(self):
      return self._get_available_model_architectures()

    @BasePlugin.endpoint
    def get_job_categories_list(self):
      return self._get_job_categories_list()

  """END ENDPOINTS SECTION"""

  """ADDITIONAL SECTION"""
  if True:
    def _get_available_first_stage_classes(self):
      return AI4E_CONSTANTS.FIRST_STAGE_CLASSES

    def _get_available_model_architectures(self):
      return AI4E_CONSTANTS.AVAILABLE_ARCHITECTURES

    def _get_available_data_source_types(self):
      return AI4E_CONSTANTS.AVAILABLE_DATA_SOURCES
    
    def _get_job_categories_list(self):
      return AI4E_CONSTANTS.JOB_CATEGORIES_LIST
  """END ADDITIONAL SECTION"""

  """PERIODIC SECTION"""
  if True:
    def maybe_persistence_save(self):
      if self.force_persistence or self.time() - self.last_persistence_save > self.cfg_save_period:
        self.last_persistence_save = self.time()
        saved_data = {}
        for job_id, job in self.jobs_data.items():
          saved_data[job_id] = job.get_persistence_data()
        # endfor jobs
        self.persistence_serialization_save(saved_data)
        self.force_persistence = False
      # endif save time
      return

    def load_persistence_data(self):
      res = {**self.jobs_data}
      saved_data = self.persistence_serialization_load()
      if saved_data is None:
        return res
      for key, data in saved_data.items():
        if key not in res:
          node_id, pipeline = data.get('node_id'), data.get('pipeline')
          signature, instance = data.get('signature'), data.get('instance_id')
          res[key] = Job(
            owner=self, job_id=key,
            node_id=node_id, pipeline=pipeline,
            signature=signature, instance=instance
          )
        res[key].load_persistence_data(data)
      # endfor saved_data
      return res
  """END PERIODIC SECTION"""

  def process(self):
    super(AI4EveryonePlugin, self).process()
    self.network_processor_loop()
    self.maybe_persistence_save()
    return

