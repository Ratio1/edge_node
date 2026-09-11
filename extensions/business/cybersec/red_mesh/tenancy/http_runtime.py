"""Import-time compatibility checks for native generated execution requests."""

import inspect


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
