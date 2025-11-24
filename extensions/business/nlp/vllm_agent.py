# from naeural_core.business.base.network_processor import NetworkProcessorPlugin as BasePlugin
from naeural_core.business.base import BasePluginExecutor as BasePlugin
from extensions.business.mixins.nlp_agent_mixin import _NlpAgentMixin, NLP_AGENT_MIXIN_CONFIG

from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, Any
from concurrent.futures import Future

import psutil


__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  **NLP_AGENT_MIXIN_CONFIG,

  "ALLOW_EMPTY_INPUTS": True,
  "CONTAINER_CHECK_INTERVAL": 60,  # seconds

  "REQUEST_TIMEOUT": 60,  # seconds

  "MODEL_NAME": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
  "HUGGINGFACE_API_TOKEN": None,
  "PROCESS_DELAY": 1,

  "USE_GPU": None,

  "GPU_MEMORY_UTILIZATION": 0.75,  # 75%
  "ALLOCATED_MEMORY": 12,  # in GB
  "CPU_CORES": 2,

  "THREAD_MAX_WORKERS": 4,
  "DEFAULT_TEMPERATURE": 0.7,
  "DEFAULT_TOP_P": 0.9,
  "DEFAULT_MAX_TOKENS": 256,
  "DEFAULT_REPETITION_PENALTY": 1.1,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
    **NLP_AGENT_MIXIN_CONFIG['VALIDATION_RULES'],
  },
}


@dataclass
class _ReqEntry:
  meta: Dict[str, Any]
  future: Future
  request_type: str
  start_time: float = 0.0
  elapsed_time: float = 0.0
# endclass


REQUESTS_MUTEX = "vllm_requests_mutex"
DEFAULT_REQUEST_TIMEOUT = 60  # seconds
DEFAULT_GPU_MEMORY_UTILIZATION = 0.75  # 75%
GPU_MEMORY_UTILIZATION_MIN_VALUE = 0.6  # 60%
GPU_MEMORY_UTILIZATION_MAX_VALUE = 0.98  # 98%
DEFAULT_ALLOCATED_MEMORY = 12  # in GB
DEFAULT_NUM_CORES = 2


class VllmAgentPlugin(BasePlugin, _NlpAgentMixin):
  CONFIG = _CONFIG

  def on_init(self):
    super(VllmAgentPlugin, self).on_init()
    self._pending_requests: Dict[str, Dict] = {}
    self._processing_requests: Dict[str, _ReqEntry] = {}
    self._solved_requests: Dict[str, _ReqEntry] = {}

    self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vllm_agent_executor")
    self._session = self.requests.Session()
    self.container_port = None
    self.launched_container_config = None
    self.launched_container_pipeline_name = None
    self.maybe_persistence_load()
    self.pipeline_name_to_cleanup = None
    self.in_cleanup = self.defaultdict(bool)
    self.delayed_iterations_for_cleanup = 0
    # Check if the container config existed and if so, check any changes
    if self.container_port is not None:
      current_configured_container_pipeline_config = self.compute_vllm_container_pipeline_config()
      if self.launched_container_config != current_configured_container_pipeline_config:
        self.P("Detected change in vLLM container pipeline configuration, resetting launched container config.")
        self.Pd(f"Previous config: {self.json_dumps(self.launched_container_config, indent=2)}\nNew config: {self.json_dumps(current_configured_container_pipeline_config, indent=2)}")
        if isinstance(self.launched_container_config, dict):
          previous_pipeline_name = self.launched_container_config.get("NAME", "")
          if previous_pipeline_name:
            self.pipeline_name_to_cleanup = previous_pipeline_name
            self.delayed_iterations_for_cleanup = 5
            self.P(f"Scheduling cleanup of previous vLLM container pipeline: {previous_pipeline_name}")
          # endif previous pipeline name successfully retrieved
        # endif existent container_pipeline_config
      # endif config changed
    # endif existent container_pipeline_config
    self.last_container_running_ts = 0
    return

  def persistence_save(self):
    self.cacheapi_save_pickle(obj={
      "container_port": self.container_port,
      "launched_container_config": self.launched_container_config,
      "launched_container_pipeline_name": self.launched_container_pipeline_name,
    })
    return

  def maybe_persistence_load(self):
    data = self.cacheapi_load_pickle()
    if not isinstance(data, dict):
      return
    self.container_port = data.get("container_port", None)
    self.launched_container_config = data.get("launched_container_config", None)
    self.launched_container_pipeline_name = data.get("launched_container_pipeline_name", None)
    return

  def get_base_container_url(self):
    return f"http://0.0.0.0:{self.container_port}"

  def get_container_completion_url(self):
    base_url = self.get_base_container_url()
    return f"{base_url}/v1/chat/completions"

  def get_container_models_url(self):
    base_url = self.get_base_container_url()
    return f"{base_url}/v1/models"

  def get_timeout(self):
    configured_timeout = self.cfg_request_timeout
    if isinstance(configured_timeout, (int, float)) and configured_timeout:
      return configured_timeout
    return DEFAULT_REQUEST_TIMEOUT

  def get_hugging_face_api_token(self):
    configured_token = self.cfg_huggingface_api_token
    env_token = self.os_environ.get("EE_HF_TOKEN", None)
    return configured_token or env_token or ""

  def get_gpu_memory_utilization(self, show_logs: bool = False):
    configured_utilization = self.cfg_gpu_memory_utilization
    if isinstance(configured_utilization, (int, float)):
      if GPU_MEMORY_UTILIZATION_MIN_VALUE <= configured_utilization <= GPU_MEMORY_UTILIZATION_MAX_VALUE:
        return configured_utilization
      else:
        log_str = f"Invalid GPU_MEMORY_UTILIZATION value: {configured_utilization}. "
        log_str += f"Must be between {GPU_MEMORY_UTILIZATION_MIN_VALUE} and {GPU_MEMORY_UTILIZATION_MAX_VALUE}."
        if show_logs:
          self.P(log_str)
      # endif valid range
    # endif valid type
    return DEFAULT_GPU_MEMORY_UTILIZATION

  def get_allocated_memory(self):
    configured_memory = self.cfg_allocated_memory
    if isinstance(configured_memory, (int, float)) and configured_memory > 0:
      return configured_memory
    return DEFAULT_ALLOCATED_MEMORY  # in GB

  def get_num_cpu_cores(self):
    configured_cores = self.cfg_cpu_cores
    if isinstance(configured_cores, int) and configured_cores > 0:
      return configured_cores
    return DEFAULT_NUM_CORES

  """VLLM CONTAINER MANAGEMENT METHODS"""
  if True:
    def __get_all_used_ports(self):
      res = set()
      for conn in psutil.net_connections(kind='all'):
        # Local address is not always a tuple.
        if not isinstance(conn.laddr, str):
          res.add(conn.laddr.port)  # Local port
      # endfor
      return sorted(res)

    def get_start_command(self, port: int, model_name: str, use_gpu: bool):
      """
      Method to get the start command for the vLLM server container.
      Parameters
      ----------
      port : int
        The port on which the vLLM server will listen.
      model_name : str
        The name of the model to load.
      use_gpu : bool
        Whether to use GPU or not.
      Returns
      -------
      command : str
        The command string to start the vLLM server.
      """
      base_command = f"--host 0.0.0.0 --port {port} --model {model_name}"
      cpu_cmd_suffix = f"--dtype float16 --disable-frontend-multiprocessing --disable-async-output-proc"
      gpu_mem_util = self.get_gpu_memory_utilization(show_logs=False)
      gpu_cmd_suffix = f"--kv-cache-dtype fp8 --gpu-memory-utilization {gpu_mem_util} --quantization bitsandbytes"
      cmd_suffix = gpu_cmd_suffix if use_gpu else cpu_cmd_suffix
      return f"{base_command} {cmd_suffix}"

    def compute_vllm_container_instance_config(self):
      """
      Method for computing plugin instance configuration of a ContainerAppRunner
      that will run the vLLM server for the current plugin instance.
      Returns
      -------
      res : dict
        The configuration dictionary for the vLLM container instance.
      """
      # TODO: design a framework/algorithm/templates to configure the container based on resources
      #  and or preferences of the user(e.g. use GPU or not)
      res = {
        "INSTANCE_ID": f"{self.get_instance_id()}",
      }

      if self.container_port is None:
        used_ports = self.__get_all_used_ports()
        chosen_port = self.np.random.randint(16000, 32000)
        while chosen_port in used_ports:
          chosen_port = self.np.random.randint(16000, 32000)
        # endwhile used_port
        self.container_port = chosen_port
      # endif container_port is None
      use_gpu = self.cfg_use_gpu
      if use_gpu is None:
        gpu_info = self.log.gpu_info()
        use_gpu = len(gpu_info) > 0
      # endif use_gpu is None

      res["PORT"] = self.container_port
      # TODO: review this
      allocated_memory = self.get_allocated_memory()
      res["CONTAINER_RESOURCES"] = {
        "cpu": self.get_num_cpu_cores(),
        "gpu": 1 if use_gpu else 0,
        "memory": f"{allocated_memory}g",
        "ports": {
          str(self.container_port): str(self.container_port),
        }
      }
      res["IMAGE"] = "vllm/vllm-openai:latest" if use_gpu else "substratusai/vllm:main-cpu"
      res["ENV"] = {
        "HUGGING_FACE_HUB_TOKEN": self.get_hugging_face_api_token(),
      }
      if use_gpu:
        res["ENV"]["NVIDIA_VISIBLE_DEVICES"] = "all"
        res["ENV"]["VLLM_ATTENTION_BACKEND"] = "FLASHINFER"
      # endif use_gpu
      res["TUNNEL_ENGINE_ENABLED"] = False
      res["CONTAINER_START_COMMAND"] = self.get_start_command(
        port=self.container_port,
        model_name=self.cfg_model_name,
        use_gpu=use_gpu,
      )
      return res

    def check_vllm_container_running(self, skip_logs=False):
      """
      Method to check if the vLLM container is already running for this plugin instance.
      Returns
      -------
      is_running : bool
        True if the vLLM container is running, False otherwise.
      """
      if self.time() - self.last_container_running_ts < self.cfg_container_check_interval:
        return True
      if not skip_logs:
        self.Pd(f"Checking if vLLM container is running at port: {self.container_port}")
      is_running = False
      if self.container_port is None:
        return is_running

      health_err = ""
      health_msg = ""
      models_msg = ""
      try:
        res = self.requests.get(
          f"{self.get_base_container_url()}/health",
          timeout=3
        )
        if res.status_code == 200:
          is_running = True
        health_msg = f"vLLM container health endpoint response status code: {res.status_code}"
      except Exception as e:
        health_err = f"vLLM container health endpoint check failed: {str(e)}"

      try:
        res = self.get_models_request(
          request_id="vllm_container_health_check",
          timeout=3
        )
        models_msg = f"vLLM container models endpoint response: {self.json_dumps(res, indent=2)}"

        is_running = res.get("ok", False)
      except Exception as e:
        err_log = f"vLLM container models endpoint check failed: {str(e)}"
        if health_err:
          err_log = f"{health_err}; {err_log}"
        health_err = err_log
      # endtry
      if not skip_logs:
        if health_err:
          self.Pd(health_err)
        if not is_running:
          if health_msg:
            self.Pd(health_msg)
          if models_msg:
            self.Pd(models_msg)
        # endif not is_running
      # endif skip_logs
      if is_running:
        self.last_container_running_ts = self.time()
      return is_running

    def check_vllm_container_pipeline_started(self):
      return self.launched_container_config is not None

    def compute_vllm_container_pipeline_config(self):
      car_config = self.compute_vllm_container_instance_config()
      car_pipeline_config = {
        "NAME": f"{self.get_stream_id()}__vllm",
        "PLUGINS": [
          {
            "INSTANCES": [
              car_config
            ],
            "SIGNATURE": "CONTAINER_APP_RUNNER"
          }
        ],
        "TYPE": "VOID"
      }
      return car_pipeline_config

    def maybe_start_vllm_container(self):
      if self.check_vllm_container_running(skip_logs=True):
        return
      if self.check_vllm_container_pipeline_started():
        return
      car_pipeline_config = self.compute_vllm_container_pipeline_config()
      self.Pd(f"Starting vLLM container with config: {self.json_dumps(car_pipeline_config, indent=2)}")
      self.cmdapi_start_pipeline(self.deepcopy(car_pipeline_config))
      self.launched_container_config = car_pipeline_config
      self.launched_container_pipeline_name = car_pipeline_config.get("NAME", None)
      self.persistence_save()
      return

    def reset_container_state(self):
      self.container_port = None
      self.launched_container_config = None
      self.launched_container_pipeline_name = None
      self.persistence_save()
      return

    def maybe_clean_old_container_pipeline(self, pipeline_name: str = None):
      deletion_started = False
      pipeline_name = pipeline_name or self.pipeline_name_to_cleanup
      if pipeline_name is None:
        return deletion_started
      if self.in_cleanup[pipeline_name]:
        return deletion_started
      current_node_pipeline = self.node_pipelines
      current_pipeline_names = [p["NAME"] for p in current_node_pipeline]
      if pipeline_name not in current_pipeline_names:
        self.P(f"vLLM container pipeline: {pipeline_name} not found among current pipelines, assuming already deleted.")
        self.reset_container_state()
        return deletion_started
      self.P(f"Stopping vLLM container pipeline: {pipeline_name}")
      self.cmdapi_stop_pipeline(
        node_address=None,
        name=pipeline_name
      )
      self.in_cleanup[pipeline_name] = True
      launched_pipeline_name = self.launched_container_pipeline_name
      extracted_pipeline_name = (self.launched_container_config or {}).get("NAME", None)
      launched_pipeline_name = launched_pipeline_name or extracted_pipeline_name
      if pipeline_name == launched_pipeline_name:
        self.reset_container_state()
      # endif launched container
      deletion_started = True
      return deletion_started
  """END VLLM CONTAINER MANAGEMENT METHODS"""

  """REQUEST HANDLING METHODS"""
  if True:
    # TODO: maybe validate signature, model name or other aspects of payload
    def check_relevant_data(self, data):
      return True

    def check_relevant_request_type(self, request_type):
      return True

    def extract_and_register_request(self, data):
      added = False
      self.Pd(f"Extracting and registering request from data: {self.json_dumps(data, indent=2)}")
      if not self.check_relevant_data(data):
        return added

      jeeves_content = data.get("JEEVES_CONTENT")
      if not isinstance(jeeves_content, dict):
        self.P(f"Invalid JEEVES_CONTENT type in data: expected dict, got {type(jeeves_content)}")
        return added

      jeeves_content = {
        k.upper() if isinstance(k, str) else k: v
        for k, v in jeeves_content.items()
      }
      request_id = jeeves_content.get("REQUEST_ID", None)
      if request_id is None:
        self.P("Missing REQUEST_ID in JEEVES_CONTENT.")
        return added
      if not isinstance(request_id, str):
        self.P(f"Invalid REQUEST_ID in JEEVES_CONTENT: expected str, got {type(request_id)}")
        return added
      # Maybe not mandatory?
      request_id = request_id.strip()
      request_type = jeeves_content.get("REQUEST_TYPE", "unknown")
      if not self.check_relevant_request_type(request_type):
        self.P(f"Irrelevant REQUEST_TYPE: {request_type}, skipping.")
        return added
      request_messages = jeeves_content.get("MESSAGES", [])
      if not isinstance(request_messages, list) or len(request_messages) == 0:
        self.P(f"Invalid or empty MESSAGES in JEEVES_CONTENT for request ID {request_id}. MESSAGES must be a non-empty list.")
        return added

      request_temperature = jeeves_content.get("TEMPERATURE", self.cfg_default_temperature)
      request_top_p = jeeves_content.get("TOP_P", self.cfg_default_top_p)
      request_max_tokens = jeeves_content.get("MAX_TOKENS", self.cfg_default_max_tokens)
      request_repetition_penalty = jeeves_content.get("REPETITION_PENALTY", self.cfg_default_repetition_penalty)
      request_seed = jeeves_content.get("SEED", None)
      # TODO: add tools support

      request_meta = {
        "REQUEST_ID": request_id,
        "REQUEST_TYPE": request_type,
        "MESSAGES": request_messages,
        "TEMPERATURE": request_temperature,
        "TOP_P": request_top_p,
        "MAX_TOKENS": request_max_tokens,
        "REPETITION_PENALTY": request_repetition_penalty,
        "SEED": request_seed,
      }
      self._pending_requests[request_id] = request_meta
      added = True
      return added

    def get_meta_from_request_data(self, request_data: Dict) -> Dict:
      request_id = request_data["REQUEST_ID"]
      request_type = request_data["REQUEST_TYPE"]
      request_messages = request_data["MESSAGES"]
      request_temperature = request_data["TEMPERATURE"]
      request_top_p = request_data["TOP_P"]
      request_max_tokens = request_data["MAX_TOKENS"]
      request_repetition_penalty = request_data["REPETITION_PENALTY"]
      request_seed = request_data["SEED"]

      payload = {
        "model": self.cfg_model_name,
        "messages": request_messages,
        "stream": False,
      }
      additionals = {
        "temperature": request_temperature,
        "top_p": request_top_p,
        "max_tokens": request_max_tokens,
        "repetition_penalty": request_repetition_penalty,
        "seed": request_seed,
      }
      normalized_additionals = {
        k: v for k, v in additionals.items() if v is not None
      }
      payload.update(normalized_additionals)

      return {
        "payload": payload,
      }

    def _run_request(self, request_id: str, request_meta: Dict):
      headers = {"Content-Type": "application/json"}
      headers["X-Request-Id"] = request_id  # echoed by vLLM if server flag enabled

      resp = self._session.post(
        self.get_container_completion_url(),
        headers=headers,
        data=self.json_dumps(request_meta["payload"]),
        timeout=self.get_timeout()
      )
      resp.raise_for_status()
      data = resp.json()

      # OpenAI-compatible shape: choices[0].message.content
      content = data.get("choices", [{}])[0].get("message", {}).get("content")
      return {
        "request_id": request_id,
        "ok": True,
        "content": content,
        "raw": data,
      }

    def get_models_request(self, request_id: str, timeout: int = 5):
      headers = {"Content-Type": "application/json"}
      resp = self._session.get(
        self.get_container_models_url(),
        headers=headers,
        timeout=timeout
      )
      resp.raise_for_status()
      data = resp.json()
      return {
        "request_id": request_id,
        "ok": resp.status_code == 200,
        "models": data.get("data", []),
        "raw": data,
      }

    def start_request(self, request_id: str, request_data: Dict, request_type: str):
      self.P(f"Starting request ID: {request_id} with data: {self.json_dumps(request_data, indent=2)}")
      start_time = self.time()
      if request_type == "chat.completions":
        request_meta = self.get_meta_from_request_data(request_data)
        req_future = self._executor.submit(
          self._run_request,
          request_id,
          request_meta,
        )
      elif request_type == "models":
        req_future = self._executor.submit(
          self.get_models_request,
          request_id,
        )
      else:
        self.P(f"Unknown request type: {request_type} for request ID: {request_id}")
        return None
      # endif request_type
      req_entry = _ReqEntry(
        meta=request_data,
        future=req_future,
        request_type=request_type,
        start_time=start_time,
      )
      self._processing_requests[request_id] = req_entry
      return req_entry

    def maybe_start_pending_requests(self):
      removed_ids = []
      for request_id, request_data in self._pending_requests.items():
        self.start_request(
          request_id=request_id,
          request_data=request_data,
          request_type="chat.completions",
        )
        removed_ids.append(request_id)
      # endfor pending requests
      for rid in removed_ids:
        self._pending_requests.pop(rid, None)
      # endfor removed_ids
      return

    def check_request_finished(self, req_entry: _ReqEntry) -> bool:
      if req_entry.future.done():
        req_entry.elapsed_time = self.time() - req_entry.start_time
      return bool(req_entry.future.done())

    def extract_request_result(self, request_id: str, req_entry: _ReqEntry) -> Dict:
      try:
        res = req_entry.future.result()
        res = {
          "MODEL_NAME": self.cfg_model_name,
          "REQUEST_ID": request_id,
          "IS_VALID": True,
          "text": res.get("content", None),
          "RAW": res.get("raw", None),
          "ELAPSED_TIME": req_entry.elapsed_time,
        }
      except Exception as e:
        res = {
          "MODEL_NAME": self.cfg_model_name,
          "REQUEST_ID": request_id,
          "IS_VALID": False,
          "ERROR": str(e),
          "ELAPSED_TIME": req_entry.elapsed_time,
        }
      return res

    def maybe_handle_finished_requests(self):
      removed_ids = []
      inferences = []
      datas = []
      for request_id, req_entry in self._processing_requests.items():
        if not self.check_request_finished(req_entry):
          continue
        result = self.extract_request_result(request_id=request_id, req_entry=req_entry)
        removed_ids.append(request_id)
        self._solved_requests[request_id] = result
        inferences.append(result)
        datas.append(req_entry.meta)
      # endfor processing requests
      self.handle_inferences(inferences=inferences, data=datas)
      for rid in removed_ids:
        self._processing_requests.pop(rid, None)
      # endfor removed_ids
      return

  """END REQUEST HANDLING METHODS"""

  def on_config(self):
    new_container_config = self.compute_vllm_container_pipeline_config()
    if isinstance(self.launched_container_config, dict) and self.launched_container_config != new_container_config:
      self.P("Detected change in vLLM container pipeline configuration, resetting launched container config.")
      debug_log = f"Previous config: {self.json_dumps(self.launched_container_config, indent=2)}\n"
      debug_log += f"New config: {self.json_dumps(new_container_config, indent=2)}"
      self.Pd(debug_log)
      previous_pipeline_name = self.launched_container_config.get("NAME", "")
      if previous_pipeline_name:
        self.pipeline_name_to_cleanup = previous_pipeline_name
        self.delayed_iterations_for_cleanup = 5
        self.P(f"Scheduling cleanup of previous vLLM container pipeline: {previous_pipeline_name}")
      # endif previous pipeline name successfully retrieved
    # endif config changed
    return

  def on_close(self):
    # Clean up the launched vLLM container pipeline if any
    if self.launched_container_pipeline_name is not None:
      self.P(f"Cleaning up launched vLLM container pipeline: {self.launched_container_pipeline_name} on plugin shutdown.")
      self.cmdapi_stop_pipeline(
        node_address=None,
        name=self.launched_container_pipeline_name
      )
      self.reset_container_state()
    # endif launched container pipeline
    super(VllmAgentPlugin, self).on_close()
    return

  def _process(self):
    # 1. Check if previous container needs cleanup
    if self.pipeline_name_to_cleanup:
      if self.delayed_iterations_for_cleanup > 0:
        in_cleanup = self.in_cleanup[self.pipeline_name_to_cleanup]
        log_prefix = "In cleanup of " if in_cleanup else "Will delete "
        log_msg = log_prefix + f"vLLM container pipeline: {self.pipeline_name_to_cleanup}"
        log_msg += f"[{self.delayed_iterations_for_cleanup} iterations left]."
        self.P(log_msg)
        self.delayed_iterations_for_cleanup -= 1
        return
      # endif delayed_iterations_for_cleanup
      if self.maybe_clean_old_container_pipeline():
        self.delayed_iterations_for_cleanup = 5
        log_str = f"Started deletion of vLLM container pipeline: {self.pipeline_name_to_cleanup}"
        log_str += f", delaying further processing for cleanup."
        self.P(log_str)
      # endif started pipeline deletion
      if self.delayed_iterations_for_cleanup == 0:
        self.pipeline_name_to_cleanup = None
      return
    # endif deletion scheduled

    # 2. Ensure vLLM container is running
    self.maybe_start_vllm_container()

    # 3. Check if container is ready
    if not self.check_vllm_container_running():
      sleep_period = 10
      self.P(f"vLLM container not running yet, will retry after {sleep_period} seconds...")
      self.sleep(sleep_period)
      return

    # 4. Process incoming data and add to pending requests
    datas = self.dataapi_struct_datas()
    if datas:
      self.P(f"Received {self.json_dumps(datas)}")
    for d_key, data in datas.items():
      self.extract_and_register_request(data)
    # endfor data

    # 5. Start pending requests if any
    self.maybe_start_pending_requests()

    # 6. Collect finished requests if any
    self.maybe_handle_finished_requests()
    return


