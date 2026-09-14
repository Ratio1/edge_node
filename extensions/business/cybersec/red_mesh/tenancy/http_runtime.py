"""Import-time compatibility checks for native generated execution requests."""

import inspect
import re
import json


_ROUTES = (
  "launch_network_scan", "launch_webapp_scan", "launch_test",
  "launch_model_test", "preflight_model_test_provider",
)
_ERROR = "Incompatible generated execution API"
_SELECTORS = ("tenant_id", "asset_id", "expected_target_digest")


def _validate_model(model, base_model, validation_error, field_info):
  if (not inspect.isclass(model) or model.__bases__ != (base_model,)
      or not isinstance(model.model_fields, dict)
      or not callable(model.model_validate)
      or model.__pydantic_complete__ is not True):
    raise RuntimeError(_ERROR)
  for selector in _SELECTORS:
    field = model.model_fields.get(selector)
    if (not isinstance(field, field_info)
        or field.annotation is not str or field.default is not None
        or field.default_factory is not None or field.is_required()):
      raise RuntimeError(_ERROR)
  omitted = model.model_validate({})
  if any(getattr(omitted, selector) is not None for selector in _SELECTORS):
    raise RuntimeError(_ERROR)
  for selector in _SELECTORS:
    for value in ("", " ", " \tMiXeD-é\n", "selector-probe"):
      supplied = model.model_validate({selector: value})
      if getattr(supplied, selector) != value:
        raise RuntimeError(_ERROR)
    for value in (None, True, False, 0, 1, 1.5, [], ["probe"], {}, {"key": "probe"}):
      try:
        model.model_validate({selector: value})
      except validation_error as error:
        if not any(item.get("loc") == (selector,) for item in error.errors()):
          raise RuntimeError(_ERROR) from None
      else:
        raise RuntimeError(_ERROR)


def validate_generated_execution_api(app, model_namespace) -> None:
  """Refuse an unverifiable execution transport before the HTTP app can serve."""
  try:
    from fastapi.routing import APIRoute
    from pydantic import BaseModel, ValidationError
    from pydantic.fields import FieldInfo

    for name in _ROUTES:
      endpoint = model_namespace.get(name)
      routes = [route for route in app.routes
                if route.path == "/" + name or (
                  endpoint is not None and getattr(route, "endpoint", None) is endpoint
                )]
      model = model_namespace.get(name + "Model")
      if len(routes) != 1 or not isinstance(routes[0], APIRoute):
        raise RuntimeError(_ERROR)
      route = routes[0]
      parameters = inspect.signature(route.endpoint).parameters
      body_params = route.dependant.body_params
      if (route.path != "/" + name or route.methods != {"POST"}
          or route.endpoint is not endpoint
          or "request_model" not in parameters
          or parameters["request_model"].annotation is not model
          or model is None or model.__name__ != name + "Model"
          or model.__module__ != route.endpoint.__module__
          or route.body_field is None
          or route.body_field.field_info.annotation is not model
          or len(body_params) != 1 or body_params[0].name != "request_model"
          or body_params[0].field_info.annotation is not model):
        raise RuntimeError(_ERROR)
      _validate_model(model, BaseModel, ValidationError, FieldInfo)
  except Exception:
    # Framework errors can include request examples; none belong in startup logs.
    raise RuntimeError(_ERROR) from None


_READ_ERROR = "Incompatible generated read API"
_REQUIRED = inspect.Parameter.empty
_REQUESTER_FIELDS = (("request_actor", dict, None), ("tenant_id", str, None))
_JOB_FIELD = (("job_id", str, _REQUIRED),)
_READ_FIELDS = {
  "get_job_status": _JOB_FIELD + _REQUESTER_FIELDS,
  "get_job_data": _JOB_FIELD + _REQUESTER_FIELDS,
  "get_job_archive": _JOB_FIELD + (("summary_only", bool, False), ("pass_offset", int, 0),
                                  ("pass_limit", int, 0)) + _REQUESTER_FIELDS,
  "get_job_triage": _JOB_FIELD + (("finding_id", str, ""),) + _REQUESTER_FIELDS,
  "get_job_progress": _JOB_FIELD + _REQUESTER_FIELDS,
  "list_network_jobs": _REQUESTER_FIELDS,
  "list_local_jobs": _REQUESTER_FIELDS,
  "get_report": (("cid", str, _REQUIRED), ("job_id", str, "")) + _REQUESTER_FIELDS,
  "get_audit_log": (("limit", int, 100),) + _REQUESTER_FIELDS,
  "get_analysis": (("job_id", str, ""), ("cid", str, ""), ("pass_nr", int, None)) + _REQUESTER_FIELDS,
  "get_detection_correlation": _JOB_FIELD + (("request_actor", dict, None),),
  "get_misp_export_status": _JOB_FIELD + (("request_actor", dict, None),),
  "get_stix_export_status": _JOB_FIELD + (("request_actor", dict, None),),
  "get_opencti_export_status": _JOB_FIELD + (("request_actor", dict, None),),
  "get_taxii_export_status": _JOB_FIELD + (("request_actor", dict, None),),
  "get_rulebook_assessment_status": _JOB_FIELD + (("profile_id", str, None), ("request_actor", dict, None)),
  "get_rulebook_review": _JOB_FIELD + (("profile_id", str, None), ("request_actor", dict, None)),
  "get_misp_export_config_status": (("request_actor", dict, None),),
  "llm_health": (("request_actor", dict, None),),
  "update_finding_triage": (("request_actor", dict, None),),
  "export_misp_json": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  "get_integration_status": (("request_actor", dict, None),),
}
# Effect-bearing endpoints (RM-026 I1b).
#
# Listing them here has two effects, and both matter:
#   1. `_ReadApiGuard` enforces POST-only, no query string, exact field names and exact types on
#      these paths -- real validation, not decoration. Removing an entry silently loses it.
#   2. `_read_path` shapes transport errors as JSON with `no-store` instead of the framework's HTML
#      default, and carries the typed effect_incomplete passthrough.
# What they do NOT get is the install-time generated-model pinning, which iterates `_READ_FIELDS`
# only. Converting them to generated routes is separate work.
_EFFECT_FIELDS = {
  "dry_run_opencti_export": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  "dry_run_taxii_export": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  "export_stix_bundle": _JOB_FIELD + (("pass_nr", int, None), ("persist", bool, True),
                                      ("request_actor", dict, None)),
  "test_event_export": (("integration_id", str, "event_export"), ("request_actor", dict, None)),
  # B2 external delivery.
  "push_to_opencti": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  "publish_to_taxii": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  "export_misp": _JOB_FIELD + (("pass_nr", int, None), ("request_actor", dict, None)),
  # B3 ingest.
  "correlate_suricata_eve": _JOB_FIELD + (("eve_jsonl", str, ""), ("pass_nr", int, None),
                                          ("source_ips", list, None), ("sensor_id", str, ""),
                                          ("request_actor", dict, None)),
  "upload_authorization": (("filename", str, ""), ("content_b64", str, ""),
                           ("request_actor", dict, None)),
  # B4 rulebook review mutations.
  "save_rulebook_review_draft": _JOB_FIELD + (("profile_id", str, None), ("answers", dict, None),
                                              ("note", str, ""),
                                              ("expected_review_revision", int, None),
                                              ("request_actor", dict, None)),
  "submit_rulebook_review": _JOB_FIELD + (("profile_id", str, None),
                                          ("expected_review_revision", int, None),
                                          ("expected_pass_nr", int, None),
                                          ("expected_profile_version", str, None),
                                          ("idempotency_key", str, ""),
                                          ("request_actor", dict, None)),
  "reopen_rulebook_review": _JOB_FIELD + (("profile_id", str, None),
                                          ("expected_review_revision", int, None),
                                          ("idempotency_key", str, ""),
                                          ("request_actor", dict, None)),
  "update_rulebook_review": _JOB_FIELD + (("profile_id", str, None), ("answers", dict, None),
                                          ("note", str, ""), ("review_state", str, "draft"),
                                          ("request_actor", dict, None)),
  # B5 assessment generation.
  "generate_rulebook_assessment": _JOB_FIELD + (("profile_id", str, None), ("pass_nr", int, None),
                                                ("persist", bool, True), ("force", bool, True),
                                                ("request_actor", dict, None)),
}
# "unknown" exists only for RAW responses, where the framework discards the state before the
# guard sees it. It still tells the caller an effect may have landed.
# Conservative shape check: typed codes only, never prose.
_PUBLISHABLE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_PUBLIC_EFFECT_STATES = ("persisted", "delivered")
_PUBLISHABLE_EFFECT_STATES = _PUBLIC_EFFECT_STATES + ("unknown",)

_READ_PATHS = {"/" + name: fields
               for name, fields in {**_READ_FIELDS, **_EFFECT_FIELDS}.items()}
# RM-026 I1b B6/B7: admitted endpoints that must NOT enter the strict transport, because
# `_read_error_response` rebuilds the body and allowlists only {400,401,403,404,405,503}, which
# would destroy their typed codes (`analysis_busy` 409 and its five siblings; `unsupported_job_type`
# and the three `raw_evidence_*` codes). They still need the one thing the guard gives every other
# read -- `Cache-Control: no-store` -- and `get_raw_model_test_evidence` needs it most of all: it
# returns the decrypted restricted artifact, the raw prompts and model responses of a model test.
# Header-only: no field validation, no error rebuild, no status rewriting.
_NO_STORE_PATHS = ("/analyze_job", "/get_raw_model_test_evidence")
_LIST_METHODS = ("list_network_jobs", "list_local_jobs")
_RULEBOOK_READ_ERRORS = {
  "/get_rulebook_assessment_status": {(400, "invalid_profile"), (400, "unsupported_job_type")},
  "/get_rulebook_review": {(400, "invalid_profile"), (400, "unsupported_job_type"),
                           (409, "job_not_finalized"), (503, "submission_contract_unsupported")},
}
READ_LIST_CAPSULE = "__redmesh_checked_job_list_v1"


def _job_mapping(value):
  return isinstance(value, dict) and all(isinstance(key, str) and isinstance(row, dict)
                                        for key, row in value.items())


def protect_read_response(method, response, response_format):
  """Hide successful list aliases from native response-control keys before IPC serialization."""
  if method not in _LIST_METHODS or not isinstance(response, dict):
    return
  value = response.get("value")
  if response_format == "RAW":
    jobs = value
  elif isinstance(value, dict):
    jobs = value.get("result")
  else:
    return
  if not _job_mapping(jobs):
    return
  capsule = {READ_LIST_CAPSULE: {"version": 1, "jobs": jobs}}
  if response_format == "RAW":
    response["value"] = capsule
  else:
    # Native WRAPPED formatting promotes this exact alias row before invoking the hook.
    if "status_code" in jobs and value.get("status_code") is jobs["status_code"]:
      del value["status_code"]
    value["result"] = capsule


def _restore_job_mapping(body):
  value = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object,
                     parse_constant=_invalid_json_constant)
  if not isinstance(value, dict):
    raise ValueError("Invalid list response")
  if READ_LIST_CAPSULE in value:
    if isinstance(value.get("result"), dict) and READ_LIST_CAPSULE in value["result"]:
      raise ValueError("Contradictory list capsules")
    capsule = value[READ_LIST_CAPSULE]
    wrapped = False
  elif isinstance(value.get("result"), dict) and set(value["result"]) == {READ_LIST_CAPSULE}:
    capsule = value["result"][READ_LIST_CAPSULE]
    wrapped = True
  else:
    raise ValueError("Missing list capsule")
  if (not isinstance(capsule, dict) or set(capsule) != {"version", "jobs"}
      or type(capsule["version"]) is not int or capsule["version"] != 1
      or not _job_mapping(capsule["jobs"])):
    raise ValueError("Invalid list capsule")
  if wrapped:
    value["result"] = capsule["jobs"]
  else:
    # RAW is the checked mapping, not the renderer's deployment metadata merged into it.
    value = capsule["jobs"]
  return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _read_path(path):
  return isinstance(path, str) and path.rstrip("/") in _READ_PATHS


def _read_error_response(status, *, code=None, effect_state=None, configuration_error=None):
  from starlette.responses import JSONResponse
  errors = {400: "invalid_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
            405: "method_not_allowed", 503: "unavailable"}
  known_rulebook_error = (type(status) is int and (status, code) in _RULEBOOK_READ_ERRORS["/get_rulebook_review"])
  # RM-026 I1b: a partially completed effect must survive the guard. Collapsing it to 503
  # "unavailable" would tell the caller nothing happened after a bundle was written or a SOC
  # event delivered, and invite a retry that duplicates it.
  known_effect_error = (status == 500 and code == "effect_incomplete"
                        and effect_state in _PUBLISHABLE_EFFECT_STATES)
  if known_effect_error:
    body = {"success": False, "error": code, "effect_state": effect_state, "status_code": 500}
    # The reason must survive the rebuild. Without it every post-persist delivery failure -- which
    # for OpenCTI and TAXII is all of them, since the persist always precedes the outbound call --
    # reaches the panel with no code at all, and "delivery codes are published" is inert over HTTP.
    if isinstance(configuration_error, str) and _PUBLISHABLE_CODE.match(configuration_error):
      body["configuration_error"] = configuration_error
    return JSONResponse(body, status_code=500, headers={"Cache-Control": "no-store"})
  status = status if type(status) is int and (status in errors or known_rulebook_error) else 503
  error = code if known_rulebook_error else errors[status]
  headers = {"Cache-Control": "no-store"}
  if status == 405:
    headers["Allow"] = "POST"
  return JSONResponse({"success": False, "error": error, "status_code": status},
                       status_code=status, headers=headers)


def _unique_json_object(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ValueError("Duplicate JSON key")
    result[key] = value
  return result


def _invalid_json_constant(_value):
  raise ValueError("Invalid JSON constant")


class _ReadApiGuard:
  """Body validation precedes Pydantic; unrelated HTTP paths keep native behavior."""
  def __init__(self, app):
    self.app = app

  @staticmethod
  def _no_store_send(send):
    async def stamped(event):
      if event["type"] == "http.response.start":
        event = {**event, "headers": [(key, value) for key, value in event.get("headers", [])
                                      if key.lower() != b"cache-control"]
                          + [(b"cache-control", b"no-store")]}
      return await send(event)
    return stamped

  async def __call__(self, scope, receive, send):
    path = scope.get("path", "")
    if scope.get("type") != "http" or not _read_path(path):
      if scope.get("type") == "http" and path.rstrip("/") in _NO_STORE_PATHS:
        return await self.app(scope, receive, self._no_store_send(send))
      return await self.app(scope, receive, send)
    if scope.get("method") != "POST":
      return await _read_error_response(405)(scope, receive, send)
    if path not in _READ_PATHS or scope.get("query_string"):
      return await _read_error_response(400)(scope, receive, send)
    try:
      chunks = []
      while True:
        event = await receive()
        if event.get("type") != "http.request":
          raise ValueError("Invalid request stream")
        chunks.append(event.get("body", b""))
        if not event.get("more_body", False):
          break
      body = b"".join(chunks)
      payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object,
                           parse_constant=_invalid_json_constant)
      fields = {name: annotation for name, annotation, _default in _READ_PATHS[path]}
      if not isinstance(payload, dict) or any(key not in fields for key in payload):
        raise ValueError("Invalid request fields")
      if any(type(value) is not fields[key] for key, value in payload.items()):
        raise ValueError("Invalid request field type")
      if "tenant_id" in payload and not payload["tenant_id"].strip():
        raise ValueError("Invalid tenant selector")
    except Exception:
      return await _read_error_response(400)(scope, receive, send)

    replayed = False
    started = False
    list_start = None
    list_chunks = []
    list_complete = False

    async def replay_receive():
      nonlocal replayed
      if not replayed:
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}
      return await receive()

    async def protected_send(event):
      nonlocal started, list_start, list_complete
      if event["type"] == "http.response.start":
        if list_start is not None:
          raise ValueError("Repeated list response start")
        if path[1:] in _LIST_METHODS and 200 <= event["status"] < 300:
          list_start = event
          return
        started = True
        event = {**event, "headers": [(key, value) for key, value in event.get("headers", [])
                                     if key.lower() != b"cache-control"] + [(b"cache-control", b"no-store")]}
      elif list_start is not None:
        if event["type"] != "http.response.body" or list_complete:
          raise ValueError("Invalid list response stream")
        list_chunks.append(event.get("body", b""))
        list_complete = not event.get("more_body", False)
        return
      await send(event)

    try:
      result = await self.app(scope, replay_receive, protected_send)
      if list_start is not None:
        if not list_complete:
          raise ValueError("Incomplete list response")
        headers = list_start.get("headers", [])
        if any(key.lower() == b"content-encoding" for key, _value in headers):
          raise ValueError("Unexpected encoded list response")
        restored = _restore_job_mapping(b"".join(list_chunks))
        headers = [(key, value) for key, value in headers
                   if key.lower() not in (b"content-length", b"cache-control")]
        headers.extend(((b"content-length", str(len(restored)).encode()), (b"cache-control", b"no-store")))
        started = True
        await send({**list_start, "headers": headers})
        await send({"type": "http.response.body", "body": restored, "more_body": False})
      return result
    except Exception:
      if started:
        raise
      return await _read_error_response(503)(scope, receive, send)


def _validate_read_model(model, fields, base_model, field_info):
  if (not inspect.isclass(model) or model.__bases__ != (base_model,)
      or model.__pydantic_complete__ is not True or not callable(model.model_validate)
      or tuple(model.model_fields) != tuple(name for name, _annotation, _default in fields)):
    raise RuntimeError(_READ_ERROR)
  probe = {}
  for name, annotation, default in fields:
    field = model.model_fields[name]
    if (not isinstance(field, field_info) or field.annotation is not annotation
        or field.default_factory is not None or field.alias is not None
        or field.validation_alias is not None or field.serialization_alias is not None
        or field.is_required() != (default is _REQUIRED)
        or default is not _REQUIRED and (type(field.default) is not type(default) or field.default != default)):
      raise RuntimeError(_READ_ERROR)
    probe[name] = {str: " \tMiXeD-é\n", dict: {"account_id": "Reader.Mixed"}, int: 7, bool: True}[annotation]
  value = model.model_validate(probe)
  if any(getattr(value, key) != supplied or type(getattr(value, key)) is not type(supplied)
         for key, supplied in probe.items()):
    raise RuntimeError(_READ_ERROR)
  required = {name: probe[name] for name, _annotation, default in fields if default is _REQUIRED}
  omitted = model.model_validate(required)
  if any(getattr(omitted, name) != default for name, _annotation, default in fields if default is not _REQUIRED):
    raise RuntimeError(_READ_ERROR)


def install_generated_read_api(app, model_namespace) -> None:
  """Validate the generated ordinary routes, then install their HTTP-only protection."""
  try:
    from fastapi.exceptions import RequestValidationError
    from fastapi.routing import APIRoute
    from pydantic import BaseModel
    from pydantic.fields import FieldInfo
    from starlette.exceptions import HTTPException

    if (not callable(app.add_middleware) or not callable(app.add_exception_handler)
        or not isinstance(app.exception_handlers, dict) or app.middleware_stack is not None):
      raise RuntimeError(_READ_ERROR)
    original_http = app.exception_handlers.get(HTTPException)
    original_validation = app.exception_handlers.get(RequestValidationError)
    if not callable(original_http) or not callable(original_validation):
      raise RuntimeError(_READ_ERROR)
    for name, fields in _READ_FIELDS.items():
      endpoint = model_namespace.get(name)
      model = model_namespace.get(name + "Model")
      routes = [route for route in app.routes if route.path == "/" + name
                or endpoint is not None and getattr(route, "endpoint", None) is endpoint]
      if len(routes) != 1 or not isinstance(routes[0], APIRoute):
        raise RuntimeError(_READ_ERROR)
      route = routes[0]
      parameters = inspect.signature(route.endpoint).parameters
      body_params = route.dependant.body_params
      if (route.path != "/" + name or route.methods != {"POST"} or route.endpoint is not endpoint
          or tuple(parameters) != ("request_model",) or parameters["request_model"].annotation is not model
          or model is None or model.__name__ != name + "Model" or model.__module__ != endpoint.__module__
          or route.body_field is None or route.body_field.field_info.annotation is not model
          or len(body_params) != 1 or body_params[0].name != "request_model"
          or body_params[0].field_info.annotation is not model or route.dependant.dependencies):
        raise RuntimeError(_READ_ERROR)
      _validate_read_model(model, fields, BaseModel, FieldInfo)

    async def protected_http(request, error):
      if _read_path(request.scope.get("path")):
        detail = error.detail
        if isinstance(detail, dict):
          for status, code in _RULEBOOK_READ_ERRORS.get(request.scope.get("path"), ()):
            typed = (detail.get("success") is False and type(detail.get("status_code")) is int
                     and detail["status_code"] == status and detail.get("error") == code)
            raw = (detail.get("detail") == code and not any(
              key in detail for key in ("success", "error", "status_code", "result")))
            if error.status_code == status and (typed or raw):
              return _read_error_response(status, code=code)
        if (request.scope.get("path") in ("/get_detection_correlation", "/get_misp_export_status",
            "/get_stix_export_status", "/get_opencti_export_status", "/get_taxii_export_status", "/export_misp_json")
            and error.status_code == 400
            and isinstance(detail, dict)):
          typed = (detail.get("success") is False and type(detail.get("status_code")) is int
                   and detail["status_code"] == 400 and detail.get("error") == "unsupported_job_type")
          # Native RAW errors collapse the typed payload to its literal error string.
          raw = (detail.get("detail") == "unsupported_job_type"
                 and not any(key in detail for key in ("success", "error", "status_code", "result")))
          if typed or raw:
            return _read_error_response(400, code="unsupported_job_type")
        if error.status_code == 500:
          # WRAPPED keeps the typed dict; RAW unwraps it, so `detail` is the bare error string and
          # the effect_state is destroyed by the framework before we ever see it. Both shapes must
          # survive, or the control is live in one deployment format and inert in the other.
          typed = (isinstance(detail, dict) and detail.get("success") is False
                   and detail.get("error") == "effect_incomplete"
                   and detail.get("status_code") == 500
                   and detail.get("effect_state") in _PUBLIC_EFFECT_STATES)
          if typed:
            return _read_error_response(500, code="effect_incomplete",
                                        effect_state=detail["effect_state"],
                                        configuration_error=detail.get("configuration_error"))
          raw = (detail == "effect_incomplete" or (isinstance(detail, dict)
                 and detail.get("detail") == "effect_incomplete"
                 and not any(key in detail for key in ("success", "error", "status_code", "result"))))
          if raw:
            # RAW cannot carry the state. "Something landed, do not blindly retry" is the
            # safety-critical half and it survives; the persisted/delivered distinction does not.
            return _read_error_response(500, code="effect_incomplete", effect_state="unknown")
        return _read_error_response(error.status_code)
      return await original_http(request, error)

    async def protected_validation(request, error):
      if _read_path(request.scope.get("path")):
        return _read_error_response(400)
      return await original_validation(request, error)

    app.add_exception_handler(HTTPException, protected_http)
    app.add_exception_handler(RequestValidationError, protected_validation)
    app.add_middleware(_ReadApiGuard)
    if (app.exception_handlers.get(HTTPException) is not protected_http
        or app.exception_handlers.get(RequestValidationError) is not protected_validation
        or not any(item.cls is _ReadApiGuard for item in app.user_middleware)):
      raise RuntimeError(_READ_ERROR)
  except Exception:
    raise RuntimeError(_READ_ERROR) from None
