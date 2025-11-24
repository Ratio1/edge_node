"""
LOCAL_SERVING_API Plugin

This plugin creates a FastAPI server for local-only access (localhost) that works with
a loopback data capture pipeline.
It can work with both async and sync requests.
In case of sync requests, they will be processed using PostponedRequest objects.
Otherwise, the request_id will be returned immediately, and the client can poll for results.

Key Features:
- Loopback mode: Outputs return to DCT queue for processing
- No token authentication (localhost only)
- Designed for general inference tasks(e.g. image analysis or text processing)

Available Endpoints:
- POST /predict - Submit image for analysis (returns result via PostponedRequest)
- GET /list_results - Get all processed image results
- GET /status - Get system status and statistics
- GET /health - Health check

Example pipeline configuration:
{
  "NAME": "local_inference_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "BASE_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_interface",
          "AI_ENGINE": "llama_cpp",
          "STARTUP_AI_ENGINE_PARAMS": {
            "HF_TOKEN": "<hf_token_if_needed>",
            "MODEL_FILENAME": "llama-3.2-1b-instruct-q4_k_m.gguf",
            "MODEL_NAME": "hugging-quants/Llama-3.2-1B-Instruct-Q4_K_M-GGUF",
            "SERVER_COLLECTOR_TIMEDELTA": 360000
          }
        }
      ]
    }
  ]
}
"""
from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from extensions.business.mixins.nlp_agent_mixin import _NlpAgentMixin, NLP_AGENT_MIXIN_CONFIG


__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  **NLP_AGENT_MIXIN_CONFIG,

  "ALLOW_EMPTY_INPUTS": True,  # allow processing even when no input data is present

  "IS_LOOPBACK_PLUGIN": True,
  "TUNNEL_ENGINE_ENABLED": False,
  "API_TITLE": "Local Inference API",
  "API_SUMMARY": "FastAPI server for local-only inference.",

  "PROCESS_DELAY": 0,
  "REQUEST_TIMEOUT": 600,  # 10 minutes
  "SAVE_PERIOD": 300,  # 5 minutes

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  }
}


class BaseInferenceApiPlugin(
  BasePlugin,
  _NlpAgentMixin
):
  CONFIG = _CONFIG

  def on_init(self):
    super(BaseInferenceApiPlugin, self).on_init()
    self._requests = {}
    self._api_errors = {}
    # This is different from self.last_error_time in BasePlugin
    # self.last_error_time tracks unhandled errors that occur in the plugin loop
    # This one tracks all errors that occur during API request handling
    self.last_handled_error_time = None
    self.last_persistence_save = 0
    self.load_persistence_data()
    return

  """UTIL METHODS"""
  if True:
    def load_persistence_data(self):
      cached_data = self.cacheapi_load_pickle()
      if cached_data is not None:
        # Useful only for debugging purposes
        self._requests = cached_data.get('_requests', {})
        self._api_errors = cached_data.get('_api_errors', {})
        self.last_handled_error_time = cached_data.get('last_handled_error_time', None)
      # endif cached_data is not None
      return

    def maybe_save_persistence_data(self, force=False):
      if force or (self.time() - self.last_persistence_save) > self.cfg_save_period:
        data_to_save = {
          '_requests': self._requests,
          '_api_errors': self._api_errors,
          'last_handled_error_time': self.last_handled_error_time,
        }
        self.cacheapi_save_pickle(data_to_save)
        self.last_persistence_save = self.time()
      # endif needs saving
      return

    def get_status(self):
      last_error_time = self.last_handled_error_time
      status = "ok"
      if last_error_time is not None:
        delta_seconds = (self.time() - last_error_time)
        if delta_seconds < 300:
          status = f"degraded (last error {int(delta_seconds)}s ago)"
        # endif enough time has passed since last error
      # endif last_error_time is not None
      return status

    def solve_postponed_request(self, request_id: str):
      if request_id in self._requests:
        self.Pd(f"Checking status of request ID {request_id}...")
        request_data = self._requests[request_id]
        start_time = request_data.get("start_time", None)
        timeout = request_data.get("timeout", self.cfg_request_timeout)
        is_finished = request_data.get("finished", False)
        if is_finished:
          return request_data["result"]
        elif start_time is not None and (self.time() - start_time) > timeout:
          self.Pd(f"Request ID {request_id} has timed out after {timeout} seconds.")
          error_response = f"Request ID {request_id} has timed out after {timeout} seconds."
          request_data['result'] = {
            "error": error_response,
            "request_id": request_id,
          }
          request_data["finished"] = True
          return request_data['result']
        # endif check finished or timeout
      else:
        self.Pd(f"Request ID {request_id} not found in requests.")
        return {
          "error": f"Request ID {request_id} not found."
        }
      # endif request exists
      return self.create_postponed_request(
        solver_method=self.solve_postponed_request,
        method_kwargs={
          "request_id": request_id
        }
      )

    def register_request(
        self,
        **kwargs
    ):
      request_id = self.uuid()
      start_time = self.time()
      request_data = {
        **kwargs,
        "request_id": request_id,
        "start_time": start_time,
        "finished": None,
        "error": None,
      }
      self._requests[request_id] = request_data
      return request_id, request_data
  """END UTIL METHODS"""

  """GENERIC API ENDPOINTS"""
  if True:
    @BasePlugin.endpoint(method="GET")
    def health(self):
      return {
        "status": self.get_status(),
        "pipeline": self.get_stream_id(),
        "plugin": self.get_signature(),
        "instance_id": self.get_instance_id(),
        "loopback_enabled": self.cfg_is_loopback_plugin,
        "uptime": self.get_alive_time(),
        "last_error_time": self.last_handled_error_time,
        "total_errors": len(self._api_errors),
      }

    @BasePlugin.endpoint(method="GET")
    def poll_request(self, request_id: str):
      res = {
        "error": f"Request ID {request_id} not found."
      }
      if request_id in self._requests:
        request_data = self._requests[request_id]
        is_finished = request_data.get("finished", False)
        if is_finished:
          res = request_data["result"]
        else:
          res = {
            "status": "pending",
            "request_id": request_id,
          }
      # endif request exists
      return res
  """END GENERIC API ENDPOINTS"""

  """CHAT COMPLETION SECTION"""
  if True:
    """VALIDATION SECTION"""
    if True:
      def check_messages(self, messages: list[dict]):
        err_msg = None
        if not isinstance(messages, list) or len(messages) == 0:
          err_msg = "`messages` must be a non-empty list of message dicts."
        if err_msg is None and not all(isinstance(m, dict) for m in messages):
          err_msg = "Each message in `messages` must be a dict."
        if err_msg is not None:
          all_messages_valid = all(
            isinstance(m, dict) and
            'role' in m and isinstance(m['role'], str) and
            'content' in m and isinstance(m['content'], str)
            for m in messages
          )
          if err_msg is None and not all_messages_valid:
            err_msg = "Each message dict must contain 'role' (str) and 'content' (str) keys."
        # endif err_msg is not None
        return err_msg

      def check_chat_completion_params(
          self,
          messages: list[dict],
          temperature: float = 0.7,
          max_tokens: int = 512,
          repeat_penalty: float = 1.0,
          **kwargs
      ):
        err_msg = None
        err_msg = self.check_messages(messages)

        return err_msg
    """END VALIDATION SECTION"""

    def create_chat_completion_helper(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 512,
        repeat_penalty: float = 1.0,
        async_request=False,
        **kwargs
    ):
      err_msg = self.check_chat_completion_params(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        repeat_penalty=repeat_penalty,
        **kwargs
      )
      if err_msg is not None:
        return {
          "error": err_msg
        }
      # endif invalid params
      request_id, request_data = self.register_request(
        async_request=async_request,
        **kwargs
      )
      jeeves_content = {
        'REQUEST_ID': request_id,
        **kwargs,
        'messages': messages,
        'temperature': temperature,
        'max_tokens': max_tokens,
        'repeat_penalty': repeat_penalty,
        'request_type': 'LLM',
      }
      self.Pd(f"Creating chat completion request {request_id} with data:\n{self.json_dumps(jeeves_content, indent=2)}")
      self.add_payload_by_fields(
        jeeves_content=jeeves_content,
        signature=self.get_signature(),
      )
      if async_request:
        return {
          "request_id": request_id,
          "poll_url": f"/poll_request?request_id={request_id}"
        }
      return self.solve_postponed_request(request_id=request_id)

    @BasePlugin.endpoint(method="POST")
    def create_chat_completion(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 512,
        repeat_penalty: float = 1.0,
        **kwargs
    ):
      return self.create_chat_completion_helper(
        async_request=False,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        repeat_penalty=repeat_penalty,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def create_chat_completion_async(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 512,
        repeat_penalty: float = 1.0,
        **kwargs
    ):
      return self.create_chat_completion_helper(
        async_request=True,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        repeat_penalty=repeat_penalty,
        **kwargs
      )
  """END CHAT COMPLETION SECTION"""

  def filter_valid_inference(self, inference):
    is_valid = super(BaseInferenceApiPlugin, self).filter_valid_inference(inference=inference)
    if is_valid:
      request_id = inference.get('REQUEST_ID', None)
      if request_id is None or request_id not in self._requests:
        is_valid = False
    # endif not is_valid
    return is_valid

  def handle_single_inference(self, inference, model_name=None):
    request_id = inference.get('REQUEST_ID', None)
    self.Pd(f"Processing inference for request ID: {request_id}, model: {model_name}")
    if request_id is None:
      self.Pd("No REQUEST_ID found in inference; skipping.")
      return
    text_response = inference.get('text', None)
    self._requests[request_id]['result'] = {
      'REQUEST_ID': request_id,
      'MODEL_NAME': model_name,
      'TEXT_RESPONSE': text_response,
    }
    self._requests[request_id]['finished'] = True
    return

  def process(self):
    self.maybe_save_persistence_data()
    inferences = self.dataapi_struct_data_inferences()
    self.handle_inferences(inferences=inferences)
    return


