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
          "AI_ENGINE": "cybersec_qwen_4b",
          "PORT": <chosen_api_port>,
          "STARTUP_AI_ENGINE_PARAMS": {
            "HF_TOKEN": "<hf_token_if_needed>",
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

from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin
from extensions.business.edge_inference_api.serving_handles import (
  configured_engines,
  serving_handle,
  serving_name,
  startup_params_for_engine,
)
from extensions.serving.mixins_llm.llm_utils import LlmCT

from typing import Any, Dict, List, Optional, Tuple


_CONFIG = {
  **BasePlugin.CONFIG,
  "AI_ENGINE": "llama_cpp_small",
  "SERVED_MODELS": [],

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

  @staticmethod
  def _model_ids_from_params(params):
    """Collect model identifiers declared in an engine's startup params."""
    model_ids = set()
    pending = [params]
    while pending:
      current = pending.pop()
      if not isinstance(current, dict):
        continue
      for key, value in current.items():
        if isinstance(value, dict):
          pending.append(value)
        elif key in {'MODEL_NAME', 'MODEL_INSTANCE_ID'} and isinstance(value, str) and value.strip():
          model_ids.add(value.strip())
        elif key == 'MODEL_PATH' and isinstance(value, str) and value.strip():
          model_ids.add(value.rstrip('/').rsplit('/', 1)[-1])
    return model_ids

  def _serving_name_for_engine(self, engine):
    """The serving-manager name of the process that runs ``engine``, derived
    with the orchestrator's rules so LLM servings can match it against their
    own ``server_name``."""
    handle = serving_handle(
      getattr(self, 'cfg_ai_engine', None), engine, getattr(self, 'cfg_startup_ai_engine_params', None),
    )
    resolver = getattr(self, 'get_serving_process_given_ai_engine', None)
    resolved = handle
    if callable(resolver):
      try:
        resolved = resolver(handle)
      except Exception:
        resolved = handle
    return serving_name(resolved)

  def _get_local_engine_routes(self):
    """Return one route per configured AI engine.

    Each route carries the serving name the inference bus will see and the set
    of model identifiers (engine name, startup ids, public aliases) that select
    it. Only identifiers that resolve to exactly one serving are routable.
    ``SERVED_MODELS`` may be a list of aliases (they belong to the instance's
    single engine) or a mapping ``{engine_name: [aliases]}`` that names the
    engine explicitly, which is required on a multi-engine instance.
    """
    ai_engine = getattr(self, 'cfg_ai_engine', None)
    startup_params = getattr(self, 'cfg_startup_ai_engine_params', None)
    routes = []
    for engine in configured_engines(ai_engine):
      params = startup_params_for_engine(ai_engine, engine, startup_params)
      model_ids = {engine}
      model_ids.update(self._model_ids_from_params(params))
      routes.append({
        'engine': engine,
        'serving_name': self._serving_name_for_engine(engine),
        'model_ids': model_ids,
      })

    self._attach_served_model_aliases(routes, getattr(self, 'cfg_served_models', []))

    if len(routes) > 1 and not getattr(self, '_warned_ambiguous_model_ids', False):
      owners = {}
      for route in routes:
        for model_id in route['model_ids']:
          owners.setdefault(model_id, []).append(route['engine'])
      ambiguous = sorted(model_id for model_id, engines in owners.items() if len(engines) > 1)
      if ambiguous:
        self._warned_ambiguous_model_ids = True
        self.P(
          f"Model ids {ambiguous} are declared by more than one engine on this LLM_INFERENCE_API "
          "instance; requests for them go to the first configured engine.",
          color='r',
        )
    return routes

  @staticmethod
  def _clean_aliases(values):
    if isinstance(values, str):
      values = [values]
    if not isinstance(values, (list, tuple, set)):
      return []
    return [str(value).strip() for value in values if isinstance(value, str) and value.strip()]

  def _attach_served_model_aliases(self, routes, served_models):
    """Attach SERVED_MODELS aliases to the engine route they belong to.

    A mapping ``{engine_name: [aliases]}`` names the engine explicitly and works
    on any instance. A plain list is unambiguous only when the instance runs a
    single engine; on a multi-engine instance it is ignored with a warning,
    because accepting it would let whichever serving polls first execute the
    request.
    """
    if isinstance(served_models, dict):
      unknown = []
      for engine_name, values in served_models.items():
        route = next(
          (item for item in routes
           if isinstance(engine_name, str) and item['engine'].lower() == engine_name.strip().lower()),
          None,
        )
        if route is None:
          unknown.append(engine_name)
          continue
        route['model_ids'].update(self._clean_aliases(values))
      if unknown and not getattr(self, '_warned_unknown_served_model_engines', False):
        self._warned_unknown_served_model_engines = True
        self.P(
          f"SERVED_MODELS names engines {unknown} that this LLM_INFERENCE_API instance does not run; "
          "their aliases are ignored.",
          color='r',
        )
      return
    aliases = self._clean_aliases(served_models)
    if not aliases:
      return
    if len(routes) == 1:
      routes[0]['model_ids'].update(aliases)
    elif not getattr(self, '_warned_ambiguous_served_models', False):
      self._warned_ambiguous_served_models = True
      self.P(
        "SERVED_MODELS is a plain list on a multi-engine LLM_INFERENCE_API instance, so its aliases "
        "are ignored: use the mapping form {engine_name: [aliases]} to name the engine.",
        color='r',
      )

  def _get_local_model_ids(self):
    """Return normalized model identifiers this instance can route to a serving."""
    model_ids = set()
    for route in self._get_local_engine_routes():
      model_ids.update(route['model_ids'])
    return sorted(model_ids)

  def _resolve_target_serving_name(self, requested_model):
    """Map a requested model identifier to the serving that owns it, or None.

    The match is exact (case-sensitive), the same contract peer capability
    matching applies, so a request selects the same model locally and remotely.
    """
    if not isinstance(requested_model, str) or not requested_model.strip():
      return None
    wanted = requested_model.strip()
    for route in self._get_local_engine_routes():
      if wanted in route['model_ids']:
        return route['serving_name']
    return None

  def _get_balancing_capabilities(self):
    return {'models': self._get_local_model_ids()}

  @staticmethod
  def _get_requested_model(request_data):
    if not isinstance(request_data, dict):
      return None
    parameters = request_data.get('parameters')
    if not isinstance(parameters, dict):
      return None
    model = parameters.get('model')
    if not isinstance(model, str):
      return None
    return model.strip() or None

  def _can_execute_request(self, request_data):
    requested_model = self._get_requested_model(request_data)
    return requested_model is None or self._resolve_target_serving_name(requested_model) is not None

  def _capacity_record_can_execute_request(self, record, request_data):
    requested_model = self._get_requested_model(request_data)
    if requested_model is None:
      return True
    if not isinstance(record, dict):
      return False
    capabilities = record.get('capabilities')
    if not isinstance(capabilities, dict):
      return False
    models = capabilities.get('models')
    return isinstance(models, list) and requested_model in models

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

    def check_and_normalize_response_format(self, response_format) -> Tuple[Optional[Dict[str, Any]], str]:
      """
      Validate and normalize the value received for response_format in an inference request.

      Supported inputs:
      - None  -> returns None
      - dict  -> validates and normalizes
      - str   -> if it looks like JSON, parses to dict then validates

      Accepted forms:
        A) llama-cpp-python documented forms:
          - {"type": "json_object"}
          - {"type": "json_object", "schema": {<json-schema>}}

        B) llama.cpp server alternative form:
          - {"type": "json_schema", "json_schema": {"schema": {<json-schema>}, ...}}

      Parameters
      ----------
      response_format : dict or str, optional
        Controls structured output constraints for the model response.

      Returns
      -------
      (result, err_msg), where
      result: dict or None
        The normalized value of response_format
      err_msg: str or None
        Error message when validation fails, otherwise None.
      """
      result = None
      err_msg = ""
      if not response_format:
        return result, err_msg
      # endif response_format not provided

      # Accept JSON string input (common in REST APIs).
      if isinstance(response_format, str):
        s = response_format.strip()
        if not s:
          # Treat empty string as "no response_format"
          return result, err_msg
        try:
          response_format = self.json.loads(s)
        except Exception as e:
          err_msg = f"response_format is a string but not valid JSON: {e}"
          return result, err_msg
      # endif response_format received as string

      if not isinstance(response_format, dict):
        err_msg = f"response_format expected as a dict, but received {type(response_format)} instead."
        return result, err_msg
      # endif invalid type

      if "type" not in response_format:
        err_msg = f"response_format missing required key 'type'."
        return result, err_msg
      fmt_type = response_format['type']
      if not isinstance(fmt_type, str):
        err_msg = f"Key 'type' from response_format should be a string, but received {type(fmt_type)} instead."
        return result, err_msg
      # endif type checking

      def _check_schema(_schema: Any, where: str):
        """Validate an optional JSON schema inside `response_format`.

        Parameters
        ----------
        _schema : Any
          Candidate schema value.
        where : str
          Human-readable schema location used in error messages.

        Returns
        -------
        tuple[dict or None, str]
          Normalized schema and an error message, empty when valid.
        """
        if _schema is None:
          return None, ""
        if not isinstance(_schema, dict):
          return None, f"{where} from response_format must be an object/dict (JSON Schema) if provided, but received{type(_schema)} instead."
        try:
          # Check if schema is JSON-serializable
          self.json.dumps(_schema)
        except Exception as e:
          return None, f"{where} from response_format must be JSON-serializable if provided: {e}"
        return _schema, ""
      # enddef _check_schema

      fmt_type = fmt_type.strip()
      if fmt_type == 'json_object':
        schema = response_format.get('schema')
        schema, err_msg = _check_schema(_schema=schema, where="'schema'")
        result = {"type": "json_object"}
        if schema is not None:
          result["schema"] = schema
      elif fmt_type == 'json_schema':
        # Check for both 'json_schema' and 'schema'
        schema = response_format.get('json_schema')
        if schema is not None:
          if not isinstance(schema, dict):
            err_msg = f"'json_schema' from response_format must be an object/dict."
            return result, err_msg
          schema = schema.get('schema')
          schema, err_msg = _check_schema(_schema=schema, where="'json_schema.schema'")
        else:
          schema = response_format.get('schema')
          schema, err_msg = _check_schema(_schema=schema, where="'schema'")
        # endif json_schema specified
        if schema is None:
          err_msg = "json_schema response_format requires a schema (missing 'schema'/'json_schema.schema')"
        # Here, "json_object" is put as type, since it is the more reliable one according to llama.cpp documentation.
        result = {"type": "json_object", "schema": schema}
      # endif response_format type
      if result is None and not err_msg:
        err_msg = f"Unsupported response_format type '{fmt_type}'. Supported: 'json_object', 'json_schema'."
      return result, err_msg

    def check_generation_params(
        self,
        temperature: float,
        max_tokens: int,
        top_p: float = 1.0,
        response_format: Any = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
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
      _, err_msg = self.check_and_normalize_response_format(response_format=response_format)
      return err_msg

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
    # Override only to attach balanced endpoint metadata to the inherited handler.
    @BasePlugin.balanced_endpoint
    @BasePlugin.endpoint(method="POST")
    def predict(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: Optional[float] = 1.0,
        response_format: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      model : str or None, optional
        Requested model identifier used for local execution or peer routing.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Result payload for synchronous processing or an error message.
      """
      return super(LLMInferenceApiPlugin, self).predict(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        response_format=response_format,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    # Override only to attach balanced endpoint metadata to the inherited handler.
    @BasePlugin.balanced_endpoint
    @BasePlugin.endpoint(method="POST")
    def predict_async(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        response_format: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        request_id: Optional[str] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      request_id : str or None, optional
        Caller-provided id to use for request tracking. If omitted, the API
        keeps the legacy generated-id behavior.
      model : str or None, optional
        Requested model identifier used for local execution or peer routing.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Tracking payload for asynchronous processing or an error message.
      """
      return super(LLMInferenceApiPlugin, self).predict_async(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        response_format=response_format,
        metadata=metadata,
        authorization=authorization,
        request_id=request_id,
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
        response_format: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      model : str or None, optional
        Requested model identifier used for local execution or peer routing.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Result payload for synchronous processing or an error message.
      """
      return self.predict(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        response_format=response_format,
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
        response_format: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      metadata : dict or None, optional
        Additional metadata to store with the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      model : str or None, optional
        Requested model identifier used for local execution or peer routing.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Tracking payload for asynchronous processing or an error message.
      """
      return self.predict_async(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        repeat_penalty=repeat_penalty,
        response_format=response_format,
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
        response_format: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      model : str or None, optional
        Requested model identifier used for capability-aware routing.
      **kwargs
        Additional parameters not validated here.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      if model is not None and (not isinstance(model, str) or not model.strip()):
        return "`model` must be a non-empty string when provided."
      err = self.check_messages(messages)
      if err is not None:
        return err
      err = self.check_generation_params(
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        response_format=response_format,
        **kwargs
      )
      if err:
        return err
      return None

    def process_predict_params(
        self,
        messages: List[Dict[str, Any]],
        temperature: float,
        max_tokens: int,
        top_p: float = 1.0,
        repeat_penalty: float = 1.0,
        response_format: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
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
      response_format : dict or None, optional
        Controls structured output constraints for the model response.
      model : str or None, optional
        Requested model identifier retained in the tracked request.
      **kwargs
        Additional parameters to include as-is.

      Returns
      -------
      dict
        Processed parameters ready for dispatch.
      """
      normalized_messages = self.normalize_messages(messages)
      # No need to capture err_msg here, already validated in check_predict_params
      response_format, _ = self.check_and_normalize_response_format(response_format=response_format)
      parameters = {
        'messages': normalized_messages,
        'temperature': temperature,
        'max_tokens': max_tokens,
        'top_p': top_p,
        'repeat_penalty': repeat_penalty,
        'response_format': response_format,
        **kwargs
      }
      if model is not None:
        parameters['model'] = model.strip()
      return parameters

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
      jeeves_content = {
        (key.upper() if isinstance(key, str) else key): value
        for key, value in request_parameters.items()
      }
      repeat_penalty = request_parameters.get('repeat_penalty')
      if repeat_penalty is not None:
        jeeves_content['REPETITION_PENALTY'] = repeat_penalty
      jeeves_content.pop('REPEAT_PENALTY', None)
      jeeves_content.pop('MODEL', None)
      # Tag the request with the serving that owns the requested model: every
      # LLM serving sees every 'LLM' request, so without this tag whichever
      # serving polls first executes it regardless of the model the caller
      # asked for. Admission already guaranteed the model resolves locally.
      target_serving = self._resolve_target_serving_name(request_parameters.get('model'))
      if target_serving:
        jeeves_content['TARGET_SERVING_NAME'] = target_serving
      jeeves_content[LlmCT.REQUEST_ID] = request_id
      jeeves_content[LlmCT.REQUEST_TYPE] = 'LLM'
      return {
        'JEEVES_CONTENT': jeeves_content
      }
  """END PREDICT ENDPOINT HANDLING"""

  """INFERENCE HANDLING"""
  if True:
    def _extract_request_id_from_inference(self, inference):
      """
      Extract request id from LLM serving outputs while tolerating legacy key
      casing and nested additional metadata.
      """
      if not isinstance(inference, dict):
        return None
      for key in [LlmCT.REQUEST_ID, 'request_id', 'id']:
        value = inference.get(key)
        if isinstance(value, str) and value:
          return value
      additional = inference.get(LlmCT.ADDITIONAL) or inference.get('additional')
      if isinstance(additional, dict):
        for key in [LlmCT.REQUEST_ID, 'request_id', 'id']:
          value = additional.get(key)
          if isinstance(value, str) and value:
            return value
      return None

    def _get_single_pending_request_id(self):
      """
      Return the only pending request id when attribution is unambiguous.

      Some LLM serving backends can produce a valid text result while omitting
      the request metadata. The API dispatches one local LLM request at a time
      for this flow, so a single pending request is a safe fallback target.
      """
      pending_status = getattr(self, "STATUS_PENDING", "pending")
      pending_ids = [
        request_id
        for request_id, request_data in self._requests.items()
        if request_data.get("status") == pending_status
      ]
      return pending_ids[0] if len(pending_ids) == 1 else None

    def _has_text_result(self, inference):
      text_value = inference.get(LlmCT.TEXT, None)
      if isinstance(text_value, str) and len(text_value.strip()) > 0:
        return True
      full_output = inference.get(LlmCT.FULL_OUTPUT, None)
      if isinstance(full_output, list) and len(full_output) == 1:
        full_output = full_output[0]
      if not isinstance(full_output, dict):
        return False
      choices = full_output.get("choices")
      if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return False
      first = choices[0]
      message = first.get("message")
      if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and len(content.strip()) > 0:
          return True
      text = first.get("text")
      return isinstance(text, str) and len(text.strip()) > 0

    def _fail_invalid_empty_inference(self, inference):
      request_id = self._extract_request_id_from_inference(inference)
      if request_id is None:
        return False
      if request_id not in self._requests:
        return False
      return self._fail_request(
        request_id=request_id,
        error_message="Local LLM returned an invalid empty response.",
      )

    def filter_valid_inference(self, inference):
      if not isinstance(inference, dict):
        return False
      if not inference.get("IS_VALID", True):
        if not self._has_text_result(inference=inference):
          self.P("Rejected invalid LLM inference without text output.")
          self._fail_invalid_empty_inference(inference)
          return False
        self.P("Accepting text-bearing LLM inference despite IS_VALID=False.")
      request_id = self._extract_request_id_from_inference(inference)
      if request_id is None:
        request_id = self._get_single_pending_request_id()
        if request_id is None:
          self.P("Rejected text-bearing LLM inference without an unambiguous request id.")
          return False
        self.P(f"Mapped request-id-less LLM inference to pending request {request_id}.")
      inference[LlmCT.REQUEST_ID] = request_id
      is_known = request_id in self._requests
      if not is_known:
        fallback_request_id = self._get_single_pending_request_id()
        if fallback_request_id is not None:
          self.P(
            f"Mapped LLM inference with unknown request id {request_id} "
            f"to pending request {fallback_request_id}."
          )
          inference[LlmCT.REQUEST_ID] = fallback_request_id
          return True
        self.P(f"Rejected text-bearing LLM inference for unknown request id {request_id}.")
      return is_known

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

      resolved_model_name = model_name or request_data.get('parameters', {}).get('model')
      response_payload = self.build_completion_response(
        request_id=request_id,
        model_name=resolved_model_name,
        inference=inference,
        request_data=request_data
      )
      request_data['result'] = response_payload
      request_data['status'] = self.STATUS_COMPLETED
      request_data['finished_at'] = self.time()
      request_data['updated_at'] = request_data['finished_at']
      self._metrics['requests_completed'] += 1
      self._decrement_active_requests()

      text_response = inference.get(LlmCT.TEXT, None)
      full_output = inference.get(LlmCT.FULL_OUTPUT, None)
      # TODO: adapt this to match OpenAI-style response structure if flag active
      self._requests[request_id]['result'] = {
        'REQUEST_ID': request_id,
        'MODEL_NAME': resolved_model_name,
        'TEXT_RESPONSE': text_response,
        LlmCT.FULL_OUTPUT: full_output,
      }
      self._annotate_result_with_node_roles(
        result_payload=self._requests[request_id]['result'],
        request_data=request_data,
      )
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
      self._annotate_result_with_node_roles(
        result_payload=response_payload,
        request_data=request_data,
      )
      return response_payload
  """END INFERENCE HANDLING"""
