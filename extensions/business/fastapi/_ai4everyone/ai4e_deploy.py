from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin


_CONFIG = {
  **BasePlugin.CONFIG,

  'SAVE_PERIOD': 60,
  'REQUEST_TIMEOUT': 600,
  "PROCESS_DELAY": 0,

  # 'PORT': 5001,
  'ASSETS': 'extensions/business/fastapi/_ai4everyone',
  'JINJA_ARGS': {
    'html_files': [
      {
        'name': 'deploy_index.html',
        'route': '/models',
        'method': 'get'
      },
      {
        'name': 'deploy_index.html',
        'route': '/',
        'method': 'get'
      }
    ]
  },
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class Ai4eDeployPlugin(BasePlugin):
  def on_init(self):
    super(Ai4eDeployPlugin, self).on_init()
    self.last_persistence_save = self.time()
    custom_instances = self.load_persistence_data()
    self.register_multiple_instances(custom_instances)
    self.requests_start = {}
    return

  def maybe_persistence_save(self):
    if self.time() - self.last_persistence_save > self.cfg_save_period:
      self.last_persistence_save = self.time()
      data = {
        'instances': self.get_instances()
      }
      self.persistence_serialization_save(data)
    # endif save needed
    return

  def load_persistence_data(self):
    res = {}
    saved_data = self.persistence_serialization_load()
    if saved_data is not None:
      res = saved_data.get('instances', {})
    # endif saved data available
    return res

  def get_instances(self):
    self.lock_resource('CUSTOM_MODELS_DATA')
    if 'CUSTOM_MODELS_DATA' not in self.plugins_shmem:
      self.plugins_shmem['CUSTOM_MODELS_DATA'] = {}
    # endif CUSTOM_MODELS_DATA not initialized
    res = self.deepcopy(self.plugins_shmem['CUSTOM_MODELS_DATA'])
    self.unlock_resource('CUSTOM_MODELS_DATA')
    return res

  def register_multiple_instances(self, instances: dict):
    self.lock_resource('CUSTOM_MODELS_DATA')
    if 'CUSTOM_MODELS_DATA' not in self.plugins_shmem:
      self.plugins_shmem['CUSTOM_MODELS_DATA'] = {}
    # endif CUSTOM_MODELS_DATA not initialized
    self.plugins_shmem['CUSTOM_MODELS_DATA'] = {
      **instances,
      **self.plugins_shmem['CUSTOM_MODELS_DATA'],
    }
    self.unlock_resource('CUSTOM_MODELS_DATA')
    return

  def register_custom_instance(self, config):
    instance_id = config['INSTANCE_ID']
    timestamp = self.time()
    self.lock_resource('CUSTOM_MODELS_DATA')
    if 'CUSTOM_MODELS_DATA' not in self.plugins_shmem:
      self.plugins_shmem['CUSTOM_MODELS_DATA'] = {}
    # endif CUSTOM_MODELS_DATA not initialized
    self.plugins_shmem['CUSTOM_MODELS_DATA'][instance_id] = {
      'TIMESTAMP': timestamp,
      'MODEL_ID': instance_id,
      'CONFIG': config
    }
    self.unlock_resource('CUSTOM_MODELS_DATA')
    return

  def on_command(self, data, register=None, config=None, **kwargs):
    if register is not None and register:
      self.register_custom_instance(config)
    # endif register
    return

  def get_response(self, request_id):
    res = None
    self.lock_resource('CUSTOM_MODELS_REQUESTS_DATA')
    if 'CUSTOM_MODELS_REQUESTS_DATA' not in self.plugins_shmem:
      self.plugins_shmem['CUSTOM_MODELS_REQUESTS_DATA'] = {}
    if request_id in self.plugins_shmem['CUSTOM_MODELS_REQUESTS_DATA']:
      res = self.plugins_shmem['CUSTOM_MODELS_REQUESTS_DATA'][request_id]
    # endif request_id registered for responses
    self.unlock_resource('CUSTOM_MODELS_REQUESTS_DATA')
    return res

  def wait_for_response(self, request_id):
    start_time = self.time()
    while self.time() - start_time < self.cfg_request_timeout:
      response = self.get_response(request_id)
      if response is not None:
        return response
      self.sleep(0.05)
    # endwhile
    return f'Request timeout! Took longer than {self.cfg_request_timeout} seconds.'

  def maybe_refresh_model_instance(self, job_id):
    models = self.get_instances()
    if job_id not in models.keys():
      msg = f'Custom model {job_id} not found! You can try the following: {list(models.keys())}'
      self.P(msg)
      return msg
    model = models[job_id]
    model_id = model['MODEL_ID']
    model_config = model['CONFIG']
    self.cmdapi_start_pipeline(
      config={
        'NAME': f'deploy_{job_id}',
        'TYPE': 'ON_DEMAND_INPUT'
      }
    )
    self._cmdapi_update_pipeline_instance(
      pipeline=f'deploy_{job_id}',
      signature='ai4e_custom_inference_agent',
      instance_id=model_id,
      instance_config=model_config
    )
    return

  """ENDPOINT SECTION"""
  if True:
    @BasePlugin.endpoint(method='get')
    def get_models(self):
      return self.get_instances()

    def solve_postponed_inference_request(self, request_id):
      response = self.get_response(request_id)
      if response is not None:
        return response
      if self.time() - self.requests_start[request_id] > self.cfg_request_timeout:
        return f'Request {request_id} timeout! Took longer than {self.cfg_request_timeout} seconds.'
      return self.create_postponed_request(
        solver_method=self.solve_postponed_inference_request,
        method_kwargs={
          'request_id': request_id
        }
      )

    @BasePlugin.endpoint(method='post')
    def inference(self, body):
      self.P(f'Inference request received with body keys: {list(body.keys())}')
      body = {(k.upper() if isinstance(k, str) else k): v for k, v in body.items()}
      job_id = body.get('MODEL_ID')
      if job_id is None:
        return f'Model ID not provided! Please specify it through the "MODEL_ID" key.'
      models = self.get_instances()
      if job_id not in models.keys():
        return f'Custom model {job_id} not found! You can try the following: {list(models.keys())}'
      img = body.get('IMAGE')
      if img is None:
        return f'Image not provided!'
      request_id = self.uuid()
      img_ = self.base64_to_img(img)
      self.P(f'Request {request_id} received for job {job_id} with image of shape {img_.shape}')
      self.maybe_refresh_model_instance(job_id)
      self.cmdapi_send_pipeline_command(
        pipeline_name=f'deploy_{job_id}',
        command={
          'IMG': img,
          'PAYLOAD_CONTEXT': {
            'REQUEST_ID': request_id
          }
        },
      )
      self.requests_start[request_id] = self.time()
      return self.create_postponed_request(
        solver_method=self.solve_postponed_inference_request,
        method_kwargs={
          'request_id': request_id
        }
      )

  """END ENDPOINT SECTION"""
