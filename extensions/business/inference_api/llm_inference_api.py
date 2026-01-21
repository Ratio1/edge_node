"""
LLM_INFERENCE_API Plugin

Production-Grade LLM Inference API

This plugin exposes a hardened, FastAPI-powered interface for chat-completion
style LLM workloads.  It keeps the lightweight loopback data flow used by the
Ratio1 node while adding security, observability, and request lifecycle
management that mirrors hosted LLM APIs.

It can work with both async and sync requests.
In case of sync requests, they will be processed using PostponedRequest objects.
Otherwise, the request_id will be returned immediately, and the client can poll for results.

Highlights
- Bearer-token authentication with optional anonymous fallback (env driven)
- Per-subject rate limiting and structured audit logging with request metrics
- Durable, restart-safe request tracking with health/metrics/list endpoints
- Async + sync chat completions with OpenAI-compatible payload layout
- Automatic timeout handling, TTL-based eviction, and persistence to cacheapi

Export `LLM_API_TOKEN` (comma-separated values for multiple clients) to enforce token
checks or provide the tokens through the `PREDEFINED_AUTH_TOKENS` config parameter.

Available Endpoints:
- POST /predict - Predict endpoint (sync)
- POST /predict_async - Predict endpoint (async)
- POST /create_chat_completion - Alias for predict and replicating the OpenAI standard (sync)
- POST /create_chat_completion_async - Alias for predict and replicating the OpenAI standard (async)
- GET /health - Health check
- GET /metrics - Retrieve API metrics endpoint
- GET /status_request - Check for current status of async request results

Example pipeline configuration:
{
  "NAME": "llm_inference_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LLM_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_interface",
          "AI_ENGINE": "llama_cpp",
          "PORT": <chosen_api_port>,
          "STARTUP_AI_ENGINE_PARAMS": {
            "HF_TOKEN": "<hf_token_if_needed>",
            "MODEL_FILENAME": "llama-3.2-1b-instruct-q4_k_m.gguf",
            "MODEL_NAME": "hugging-quants/Llama-3.2-1B-Instruct-Q4_K_M-GGUF",
            "SERVER_COLLECTOR_TIMEDELTA": 360000
          }
        }
      ]
    },
    {
      "SIGNATURE": "WORKER_APP_RUNNER",
      "INSTANCES": [
        {
          "INSTANCE_ID": "third_party_app",
          "PORT": <chosen_app_port>,
          "BUILD_AND_RUN_COMMANDS": [
            "npm install",
            "npm run dev"
          ],
          "VCS_DATA": {
            "PROVIDER": "github",
            "USERNAME": "<your_github_username>",
            "TOKEN": "<your_github_token_if_needed>",
            "REPO_URL": "<your_repo_url>",
            "BRANCH": "main",
            "POLL_INTERVAL": 60
          },
          "AUTOUPDATE": true,
          "TUNNEL_ENGINE_ENABLED": true,
          "CLOUDFLARE_TOKEN": "<your_cloudflare_token_if_tunneled>",
          "ENV": {
            "INFERENCE_API_HOST": "$R1EN_HOST_IP",
            "INFERENCE_API_PORT": "<chosen_api_port>"
          },
          "HEALTH_CHECK": {
            "PATH": "/health",
          }
        }
      ]
    }
  ]
}
"""

from extensions.business.inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin
from extensions.serving.mixins_llm.llm_utils import LlmCT

from typing import Any, Dict, List, Optional


_CONFIG = {
  **BasePlugin.CONFIG,
  "AI_ENGINE": "llama_cpp_small",

  "API_TITLE": "LLM Inference API",

  "TEMPERATURE_MIN": 0.0,
  "TEMPERATURE_MAX": 1.5,
  "MIN_COMPLETION_TOKENS": 16,
  "MAX_COMPLETION_TOKENS": 4096,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class LLMInferenceApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  """VALIDATION SECTION"""
  if True:
    def check_messages(self, messages: list[dict]):
      """
      Validate chat messages payload structure.

      Parameters
      ----------
      messages : list of dict
        Sequence of chat messages including role and content fields.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      if not isinstance(messages, list) or len(messages) == 0:
        return "`messages` must be a non-empty list of message dicts."
      for idx, message in enumerate(messages):
        if not isinstance(message, dict):
          return f"Message at index {idx} from `messages` must be a dict."
        role = message.get('role', None)
        content = message.get('content', None)
        if role not in {'system', 'user', 'assistant', 'tool'}:
          return f"Message {idx} has invalid role '{role}'."
        if not isinstance(content, str) or not content.strip():
          return f"Message {idx} content must be a non-empty string."
      return None

    def check_generation_params(
        self,
        temperature: float,
        max_tokens: int,
        top_p: float = 1.0,
        **kwargs
    ):
      """
      Validate generation hyperparameters.

      Parameters
      ----------
      temperature : float
        Sampling temperature requested by the client.
      max_tokens : int
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling cutoff between 0 and 1.
      **kwargs
        Additional unused parameters.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      if not self.cfg_temperature_min <= temperature <= self.cfg_temperature_max:
        return (
          f"temperature must be between {self.cfg_temperature_min} and "
          f"{self.cfg_temperature_max}."
        )
      if not self.cfg_min_completion_tokens <= max_tokens <= self.cfg_max_completion_tokens:
        return (
          f"max_tokens must be between {self.cfg_min_completion_tokens} and "
          f"{self.cfg_max_completion_tokens}."
        )
      if not 0 < top_p <= 1:
        return "top_p must be between 0 and 1."
      return None

    def normalize_messages(self, messages: List[Dict[str, Any]]):
      """
      Normalize chat messages by trimming content.

      Parameters
      ----------
      messages : list of dict
        Original messages payload provided by the client.

      Returns
      -------
      list of dict
        Messages with whitespace-trimmed content fields.
      """
      normalized = []
      for message in messages:
        normalized.append({
          'role': message['role'],
          'content': message['content'].strip(),
        })
      return normalized
  """END VALIDATION SECTION"""

  """API ENDPOINTS"""
  if True:
    @BasePlugin.endpoint(method="POST")
    def predict(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: Optional[float] = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Synchronous chat completion prediction endpoint.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float, optional
        Sampling temperature.
      max_tokens : int, optional
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float or None, optional
        Penalty for repeated tokens if supported by the backend.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Result payload for synchronous processing or an error message.
      """
      return super(LLMInferenceApiPlugin, self).predict(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def predict_async(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Asynchronous chat completion prediction endpoint.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float, optional
        Sampling temperature.
      max_tokens : int, optional
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float, optional
        Penalty for repeated tokens if supported by the backend.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Tracking payload for asynchronous processing or an error message.
      """
      return super(LLMInferenceApiPlugin, self).predict_async(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def create_chat_completion(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: Optional[float] = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Alias for predict endpoint, replicating the OpenAI chat completion interface.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float, optional
        Sampling temperature.
      max_tokens : int, optional
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float or None, optional
        Penalty for repeated tokens if supported by the backend.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Result payload for synchronous processing or an error message.
      """
      return self.predict(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def create_chat_completion_async(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Asynchronous alias mirroring OpenAI's chat completion API.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float, optional
        Sampling temperature.
      max_tokens : int, optional
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float, optional
        Penalty for repeated tokens if supported by the backend.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Tracking payload for asynchronous processing or an error message.
      """
      return self.predict_async(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )
  """END API ENDPOINTS"""

  """PREDICT ENDPOINT HANDLING"""
  if True:
    def check_predict_params(
        self,
        messages: List[Dict[str, Any]],
        temperature: float,
        max_tokens: int,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        **kwargs
    ):
      """
      Validate request parameters for LLM predictions.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float
        Sampling temperature.
      max_tokens : int
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float, optional
        Penalty for repeated tokens if supported by the backend.
      **kwargs
        Additional parameters not validated here.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      err = self.check_messages(messages)
      if err is not None:
        return err
      err = self.check_generation_params(
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        **kwargs
      )
      if err is not None:
        return err
      return None

    def process_predict_params(
        self,
        messages: List[Dict[str, Any]],
        temperature: float,
        max_tokens: int,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        **kwargs
    ):
      """
      Normalize and forward parameters for request registration.

      Parameters
      ----------
      messages : list of dict
        Chat history for the model to complete.
      temperature : float
        Sampling temperature.
      max_tokens : int
        Maximum number of tokens to generate.
      top_p : float, optional
        Nucleus sampling probability threshold.
      repeat_penalty : float, optional
        Penalty for repeated tokens if supported by the backend.
      **kwargs
        Additional parameters to include as-is.

      Returns
      -------
      dict
        Processed parameters ready for dispatch.
      """
      normalized_messages = self.normalize_messages(messages)
      return {
        'messages': normalized_messages,
        'temperature': temperature,
        'max_tokens': max_tokens,
        'top_p': top_p,
        'repeat_penalty': repeat_penalty,
        **kwargs
      }

    def compute_payload_kwargs_from_predict_params(
        self,
        request_id: Optional[str],
        request_data: Dict[str, Any]
    ):
      """
      Prepare payload fields for the loopback inference engine.

      Parameters
      ----------
      request_id : str or None
        Identifier of the registered request.
      request_data : dict
        Stored request record containing processed parameters.

      Returns
      -------
      dict
        Payload keyed for downstream LLM handling.
      """
      request_parameters = request_data['parameters']
      return {
        'jeeves_content': {
          'REQUEST_ID': request_id,
          'request_type': 'LLM',
          **request_parameters,
        }
      }
  """END PREDICT ENDPOINT HANDLING"""

  """INFERENCE HANDLING"""
  if True:
    def inference_to_response(self, inference, model_name, input_data=None):
      """
      Convert inference output into a lightweight response structure.

      Parameters
      ----------
      inference : dict
        Inference payload produced by the model.
      model_name : str
        Name of the model that generated the inference.
      input_data : Any, optional
        Optional original input for context.

      Returns
      -------
      dict
        Simplified response containing identifiers and text output.
      """
      return {
        'REQUEST_ID': inference.get('REQUEST_ID'),
        'MODEL_NAME': model_name,
        'TEXT_RESPONSE': inference.get('text'),
      }

    def handle_single_inference(self, inference, model_name=None, input_data=None):
      """
      Handle a single inference result and update tracked request state.

      Parameters
      ----------
      inference : dict
        Inference payload produced by the model.
      model_name : str or None, optional
        Model name reported with the inference.
      input_data : Any, optional
        Optional original input for context.

      Returns
      -------
      None
        Updates request tracking and stores the completion payload.
      """
      request_id = inference.get('REQUEST_ID', None)
      self.Pd(f"Processing inference for request ID: {request_id}, model: {model_name}")
      if request_id is None:
        self.Pd("No REQUEST_ID found in inference. Skipping.")
        return
      request_data = self._requests.get(request_id)
      if request_data is None:
        self.Pd(f"Received inference for unknown request_id {request_id}.")
        return
      if request_data['status'] != self.STATUS_PENDING:
        return

      response_payload = self.build_completion_response(
        request_id=request_id,
        model_name=model_name or request_data['model'],
        inference=inference,
        request_data=request_data
      )
      request_data['result'] = response_payload
      request_data['status'] = self.STATUS_COMPLETED
      request_data['finished_at'] = self.time()
      request_data['updated_at'] = request_data['finished_at']
      self._metrics['requests_completed'] += 1
      self._metrics['requests_active'] -= 1

      text_response = inference.get(LlmCT.TEXT, None)
      full_output = inference.get(LlmCT.FULL_OUTPUT, None)
      # TODO: adapt this to match OpenAI-style response structure if flag active
      self._requests[request_id]['result'] = {
        'REQUEST_ID': request_id,
        'MODEL_NAME': model_name,
        'TEXT_RESPONSE': text_response,
        LlmCT.FULL_OUTPUT: full_output,
      }
      self._requests[request_id]['finished'] = True
      return

    def build_completion_response(
        self,
        request_id: str,
        model_name: str,
        inference: dict,
        request_data: dict
    ):
      """
      Build a completion-style response payload from an inference result.
      TODO: adapt default response structure to match OpenAI-style APIs:
      {
        'id': request_id,
        'object': 'chat.completion',
        'created': int(self.time()),
        'model': model_name,
        'choices': [
          {
            'index': 0,
            'message': {
              'role': 'assistant',
              'content': text_response,
            },
            'finish_reason': inference.get('finish_reason', 'stop'),
          }
        ],
        'usage': {
          'prompt_tokens': usage.get('prompt_tokens'),
          'completion_tokens': usage.get('completion_tokens'),
          'total_tokens': usage.get('total_tokens'),
        },
        'metadata': request_data.get('metadata') or {},
      }
      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      model_name : str
        Name of the model producing the inference.
      inference : dict
        Inference payload containing text and optional full output.
      request_data : dict
        Stored request record with metadata and parameters.

      Returns
      -------
      dict
        Chat-completion shaped response enriched with metadata and timestamps.
      """
      text_response = inference.get(LlmCT.TEXT, None)
      full_output = inference.get(LlmCT.FULL_OUTPUT, None)

      response_payload = {
        'REQUEST_ID': request_id,
        'MODEL_NAME': model_name,
        'TEXT_RESPONSE': text_response,
      }
      # Check if full_output is already an API-friendly dict.
      # TODO: enhance this check based on expected structure.
      if isinstance(full_output, dict):
        response_payload = {
          **response_payload,
          **full_output,
        }
      else:
        response_payload[LlmCT.FULL_OUTPUT] = full_output
      # endif full_output is dict
      response_payload['metadata'] = request_data.get('metadata') or {}
      response_payload['object'] = 'chat.completion'
      response_payload['created'] = int(self.time())
      response_payload['id'] = request_id
      response_payload['model'] = model_name
      return response_payload
  """END INFERENCE HANDLING"""

