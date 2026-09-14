"""Exercise the native HTTP renderer without executing target or provider effects."""

import ast
import asyncio
import inspect
import json
import os
import shutil
import subprocess
import sys
import types
from copy import copy, deepcopy
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch

import pytest
from jinja2 import Environment, FileSystemLoader


REPO_ROOT = Path(__file__).resolve().parents[5]
PLUGIN_PATH = REPO_ROOT / "extensions/business/cybersec/red_mesh/pentester_api_01.py"
FRAMEWORK_ROOT = REPO_ROOT / "naeural_core/naeural_core"
ROUTES = (
  "launch_network_scan", "launch_webapp_scan", "launch_test",
  "launch_model_test", "preflight_model_test_provider",
)
LEGACY_STATUS_ROUTES = (
  "get_detection_correlation", "get_misp_export_status", "get_stix_export_status",
  "get_opencti_export_status", "get_taxii_export_status",
)
LEGACY_RULEBOOK_ROUTES = ("get_rulebook_assessment_status", "get_rulebook_review")
ACTOR_ONLY_READ_ROUTES = ("get_misp_export_config_status", "llm_health", "update_finding_triage",
                          "get_integration_status")
LEGACY_JSON_EXPORT_ROUTES = ("export_misp_json",)
# RM-026 I1b B1: effect endpoints sharing the strict read transport.
EFFECT_ROUTES = ("dry_run_opencti_export", "dry_run_taxii_export", "export_stix_bundle",
                 "test_event_export", "push_to_opencti", "publish_to_taxii")
# export_misp joins these in B2's MISP phase, once it is converted from GET to POST: the native
# renderer looks for a decorator Call, and a bare @BasePlugin.endpoint makes it raise.
LEGACY_READ_ROUTES = LEGACY_STATUS_ROUTES + LEGACY_RULEBOOK_ROUTES + ACTOR_ONLY_READ_ROUTES + LEGACY_JSON_EXPORT_ROUTES
READ_ROUTES = (
  "get_job_status", "get_job_data", "get_job_archive", "get_job_triage", "get_job_progress",
  "list_network_jobs", "list_local_jobs", "get_report", "get_audit_log", "get_analysis",
) + LEGACY_READ_ROUTES
SELECTORS = ("tenant_id", "asset_id", "expected_target_digest")
ERROR = "Incompatible generated execution API"


class _Comms:
  def __init__(self, **_kwargs):
    self.calls = []

  async def call_plugin(self, name, *args, **kwargs):
    self.calls.append((name, args, kwargs))
    if name in ("list_network_jobs", "list_local_jobs"):
      return {"__redmesh_checked_job_list_v1": {"version": 1, "jobs": {}}}
    return {"success": True}


@lru_cache(maxsize=4)
def _render_native(default_route=None):
  """Reuse actual endpoint assembly and template; only method effects are removed."""
  plugin = next(node for node in ast.parse(PLUGIN_PATH.read_text()).body
                if isinstance(node, ast.ClassDef) and node.name == "PentesterApi01Plugin")
  methods = []
  endpoint_options = {}
  for original in plugin.body:
    if not isinstance(original, ast.FunctionDef) or original.name not in ROUTES + READ_ROUTES + EFFECT_ROUTES:
      continue
    method = deepcopy(original)
    decorator = next(item for item in method.decorator_list
                     if isinstance(item, ast.Call) and getattr(item.func, "attr", None) == "endpoint")
    endpoint_options[method.name] = {
      keyword.arg: ast.literal_eval(keyword.value) for keyword in decorator.keywords
    }
    method.body, method.decorator_list = [ast.Pass()], []
    if method.name in ROUTES:
      assert tuple(arg.arg for arg in method.args.args)[-3:] == SELECTORS
      if method.name == "preflight_model_test_provider":
        assert method.args.args[-4].arg == "actor"
    elif method.name in LEGACY_STATUS_ROUTES:
      assert tuple(arg.arg for arg in method.args.args) == ("self", "job_id", "request_actor")
    elif method.name in LEGACY_RULEBOOK_ROUTES:
      assert tuple(arg.arg for arg in method.args.args) == ("self", "job_id", "profile_id", "request_actor")
    elif method.name in ACTOR_ONLY_READ_ROUTES:
      assert tuple(arg.arg for arg in method.args.args) == ("self", "request_actor")
    elif method.name in LEGACY_JSON_EXPORT_ROUTES:
      assert tuple(arg.arg for arg in method.args.args) == ("self", "job_id", "pass_nr", "request_actor")
    elif method.name in EFFECT_ROUTES:
      # Effect endpoints keep their original positional parameters and append request_actor last,
      # so existing callers are unaffected by admission being added.
      expected = {
        "dry_run_opencti_export": ("self", "job_id", "pass_nr", "request_actor"),
        "dry_run_taxii_export": ("self", "job_id", "pass_nr", "request_actor"),
        "export_stix_bundle": ("self", "job_id", "pass_nr", "persist", "request_actor"),
        "test_event_export": ("self", "integration_id", "request_actor"),
        "push_to_opencti": ("self", "job_id", "pass_nr", "request_actor"),
        "publish_to_taxii": ("self", "job_id", "pass_nr", "request_actor"),
      }[method.name]
      assert tuple(arg.arg for arg in method.args.args) == expected
    else:
      assert tuple(arg.arg for arg in method.args.args)[-2:] == ("request_actor", "tenant_id")
    methods.append(method)
  native_path = FRAMEWORK_ROOT / "business/default/web_app/fast_api_web_app.py"
  native = next(node for node in ast.parse(native_path.read_text()).body
                if isinstance(node, ast.ClassDef) and node.name == "FastApiWebAppPlugin")
  methods.append(deepcopy(next(node for node in native.body
                             if isinstance(node, ast.FunctionDef)
                             and node.name == "_init_endpoints")))
  harness = ast.ClassDef(
    name="Harness", bases=[], keywords=[], body=methods, decorator_list=[],
  )
  namespace = {}
  exec(compile(ast.fix_missing_locations(ast.Module(
    body=[harness], type_ignores=[],
  )), "<native-execution-signatures>", "exec"), namespace)
  instance = namespace["Harness"]()
  instance.cfg_endpoints = []
  instance.P = lambda *_args, **_kwargs: None
  for name in ROUTES + READ_ROUTES + EFFECT_ROUTES:
    method = getattr(namespace["Harness"], name)
    method.__endpoint__ = True
    method.__http_method__ = endpoint_options[name]["method"]
    method.__require_token__ = endpoint_options[name].get("require_token", False)
  instance._init_endpoints()
  template_dir = FRAMEWORK_ROOT / "business/base/uvicorn_templates"
  instance.render_args = dict(
    additional_fastapi_data={}, manager_port=1, manager_auth=repr(b"fixture-only"),
    request_timeout=1, api_title=repr("execution fixture"), api_summary=repr("fixture"),
    api_description=repr("fixture"), api_version=repr("fixture"), static_directory=".",
    debug_web_app=False, debug_timings=False, debug_timings_steps=False,
    default_route=default_route, profile_rate=0, profile_log_per_request=False,
    node_comm_params=instance._node_comms_jinja_args, html_files=[],
  )
  source = Environment(loader=FileSystemLoader(str(template_dir))).get_template(
    "basic_server.j2",
  ).render(instance.render_args)
  return source, instance


@pytest.fixture
def native_api():
  source, harness = _render_native()
  module = types.ModuleType("_rm026_execution_native_fixture")
  comms = types.ModuleType("naeural_core.utils.uvicorn_fast_api_ipc_manager")
  comms.UvicornPluginComms = _Comms
  with patch.dict(sys.modules, {comms.__name__: comms, module.__name__: module}):
    exec(compile(source, "<native-execution-server>", "exec"), module.__dict__)
    yield module, harness


def _validate(module):
  from extensions.business.cybersec.red_mesh.tenancy.http_runtime import (
    validate_generated_execution_api,
  )
  validate_generated_execution_api(module.app, module.__dict__)


def test_actual_native_models_are_supported(native_api):
  module, _harness = native_api
  _validate(module)
  assert module.eng.calls == []


def test_missing_protected_route_denies(native_api):
  module, _harness = native_api
  module.app.router.routes = [
    route for route in module.app.routes if route.path != "/launch_network_scan"
  ]
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)


@pytest.mark.parametrize("fault", (
  "duplicate", "wrong_method", "wrong_path", "namespace_model", "namespace_endpoint",
  "endpoint", "endpoint_annotation", "body_field", "body_annotation",
  "dependant", "missing_body_param", "extra_body_param", "body_param_name",
  "body_param_annotation", "non_api_route", "endpoint_alias",
))
def test_route_model_metadata_must_agree(native_api, fault):
  module, _harness = native_api
  name = "launch_network_scan"
  route = next(route for route in module.app.routes if route.path == "/" + name)
  if fault == "duplicate":
    module.app.router.routes.append(route)
  elif fault == "endpoint_alias":
    alias = copy(route)
    alias.path = "/execution_alias"
    module.app.router.routes.append(alias)
  elif fault == "wrong_method":
    route.methods = {"GET"}
  elif fault == "wrong_path":
    route.path = "/launch_network_scan/"
  elif fault == "namespace_model":
    module.__dict__.pop(name + "Model")
  elif fault == "namespace_endpoint":
    module.__dict__.pop(name)
  elif fault == "endpoint":
    route.endpoint = lambda request_model: None
  elif fault == "endpoint_annotation":
    route.endpoint.__annotations__["request_model"] = object
  elif fault == "body_field":
    route.body_field = None
  elif fault == "body_annotation":
    route.body_field = copy(route.body_field)
    route.body_field.field_info = copy(route.body_field.field_info)
    route.body_field.field_info.annotation = object
  elif fault == "dependant":
    route.dependant = None
  elif fault == "missing_body_param":
    route.dependant.body_params = []
  elif fault == "extra_body_param":
    route.dependant.body_params *= 2
  elif fault == "body_param_name":
    route.dependant.body_params[0].name = "other"
  elif fault == "body_param_annotation":
    route.dependant.body_params = [copy(route.dependant.body_params[0])]
    route.dependant.body_params[0].field_info = copy(route.dependant.body_params[0].field_info)
    route.dependant.body_params[0].field_info.annotation = object
  elif fault == "non_api_route":
    module.app.router.routes = [
      types.SimpleNamespace(**vars(route)) if item is route else item
      for item in module.app.routes
    ]
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)
  assert module.eng.calls == []


@pytest.mark.parametrize("name", ROUTES)
@pytest.mark.parametrize("fault", ("missing", "nullable", "number", "required", "default"))
def test_actual_model_selector_declarations_must_match(native_api, name, fault):
  module, _harness = native_api
  field = module.__dict__[name + "Model"].model_fields["tenant_id"]
  if fault == "missing":
    del module.__dict__[name + "Model"].model_fields["tenant_id"]
  elif fault == "nullable":
    field.annotation = str | None
  elif fault == "number":
    field.annotation = int
  elif fault == "required":
    from pydantic_core import PydanticUndefined
    field.default = PydanticUndefined
  elif fault == "default":
    field.default = ""
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)


@pytest.mark.parametrize("config", (
  {"coerce_numbers_to_str": True}, {"str_strip_whitespace": True},
  {"str_to_lower": True}, {"validate_default": True},
))
def test_actual_model_validation_behavior_is_required(native_api, config):
  module, _harness = native_api
  model = module.launch_network_scanModel
  model.model_config.update(config)
  model.model_rebuild(force=True)
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)


def test_missing_runtime_surface_is_sanitized(native_api):
  module, _harness = native_api
  module.app = object()
  with pytest.raises(RuntimeError, match=f"^{ERROR}$") as caught:
    _validate(module)
  assert caught.value.__suppress_context__


def test_non_pydantic_field_metadata_is_rejected(native_api):
  module, _harness = native_api
  module.launch_network_scanModel.model_fields["tenant_id"] = types.SimpleNamespace(
    annotation=str, default=None, default_factory=None, is_required=lambda: False,
  )
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)


def test_framework_validation_exception_does_not_escape_into_startup_logs(native_api):
  module, _harness = native_api
  with patch.object(module.launch_network_scanModel, "model_validate",
                    side_effect=ValueError("fixture-private-validation-detail")):
    with pytest.raises(RuntimeError, match=f"^{ERROR}$") as caught:
      _validate(module)
  assert caught.value.__suppress_context__


def test_pydantic_v1_actual_rendered_model_is_not_a_supported_fixture(native_api):
  from pydantic.v1 import BaseModel

  module, _harness = native_api
  source, _harness = _render_native()
  model_ast = next(node for node in ast.parse(source).body
                   if isinstance(node, ast.ClassDef)
                   and node.name == "launch_network_scanModel")
  namespace = {"BaseModel": BaseModel, "__name__": module.__name__}
  exec(compile(ast.Module(body=[model_ast], type_ignores=[]),
               "<native-v1-negative-model>", "exec"), namespace)
  model = namespace["launch_network_scanModel"]
  assert model(tenant_id=None).tenant_id is None
  assert model(tenant_id=123).tenant_id == "123"
  route = next(route for route in module.app.routes if route.path == "/launch_network_scan")
  module.launch_network_scanModel = model
  route.endpoint.__annotations__["request_model"] = model
  route.body_field.field_info.annotation = model
  route.dependant.body_params[0].field_info.annotation = model
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    _validate(module)


async def _request(module, name, payload, *, with_token=True):
  events = []
  body = json.dumps(payload).encode()
  headers = [(b"content-type", b"application/json")]
  if with_token and name in ROUTES[-2:]:
    headers.append((b"authorization", b"Bearer fixture-only-token"))
  scope = {
    "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
    "method": "POST", "scheme": "http", "path": "/" + name,
    "raw_path": ("/" + name).encode(), "query_string": b"", "root_path": "",
    "headers": headers, "server": ("fixture", 80), "client": ("fixture", 0),
  }

  async def receive():
    return {"type": "http.request", "body": body, "more_body": False}

  async def send(event):
    events.append(event)

  before = len(module.eng.calls)
  await module.app(scope, receive, send)
  status = next(event["status"] for event in events if event["type"] == "http.response.start")
  return status, len(module.eng.calls) - before


@pytest.mark.parametrize("name", ROUTES)
def test_raw_json_preserves_positional_dispatch_and_rejects_malformed_selectors(native_api, name):
  module, harness = native_api
  _validate(module)
  parameters = inspect.signature(getattr(harness, name)).parameters
  assert tuple(parameters)[-3:] == SELECTORS
  for selector in SELECTORS:
    assert parameters[selector].annotation is str
    assert parameters[selector].default is None

  async def checks():
    for payload in ({}, dict(zip(SELECTORS, ("tenant-A", "asset-A", "digest-A"))),
                    {"tenant_id": ""}, {"tenant_id": " \t "},
                    {"tenant_id": "tenant-A"}, {"asset_id": "asset-A"},
                    {"expected_target_digest": "digest-A"}):
      assert await _request(module, name, payload) == (200, 1)
      expected_args = tuple(
        "fixture-only-token" if key == "token" else payload.get(key, parameter.default)
        for key, parameter in parameters.items()
      )
      assert module.eng.calls[-1] == (name, expected_args, {"profile": None})
    for selector in SELECTORS:
      for value in (None, True, False, 0, 1, 1.5, [], ["tenant-A"], {}, {"id": "tenant-A"}):
        assert await _request(module, name, {selector: value}) == (422, 0)
    assert await _request(module, name, dict.fromkeys(SELECTORS)) == (422, 0)
    assert await _request(module, name, None) == (422, 0)
    assert await _request(module, name, {**dict.fromkeys(SELECTORS), "actor": None}) == (422, 0)

  asyncio.run(checks())


def test_only_the_two_existing_model_token_dependencies_are_required(native_api):
  module, _harness = native_api
  async def checks():
    for name in ROUTES:
      route = next(route for route in module.app.routes if route.path == "/" + name)
      if name in ROUTES[-2:]:
        assert len(route.dependant.dependencies) == 1
        assert route.dependant.dependencies[0].call is module.get_bearer_token
        status, calls = await _request(module, name, {}, with_token=False)
        assert status in (401, 403)
        assert calls == 0
      else:
        assert route.dependant.dependencies == []
        assert await _request(module, name, {}, with_token=False) == (200, 1)
  asyncio.run(checks())


@pytest.mark.parametrize("optimized", (False, True))
@pytest.mark.parametrize("fault", ("missing_route", "missing_guard"))
def test_import_rejection_precedes_uvicorn_load_with_lifespan_disabled(tmp_path, optimized, fault):
  source, _harness = _render_native()
  footer = (
    "\nfrom extensions.business.cybersec.red_mesh.tenancy.http_runtime "
    "import validate_generated_execution_api\n"
    "validate_generated_execution_api(app, globals())\n"
  )
  # The child imports a genuinely rendered module; no server socket is opened.
  mutation = ("\napp.router.routes = [route for route in app.routes "
              "if route.path != '/launch_network_scan']\n") if fault == "missing_route" else ""
  (tmp_path / "main.py").write_text(
    source + mutation + footer, encoding="utf-8",
  )
  guard_name = "extensions.business.cybersec.red_mesh.tenancy.http_runtime"
  missing_import = f"sys.modules[{guard_name!r}] = None\n" if fault == "missing_guard" else ""
  exception_check = (f"  if str(error) != {ERROR!r}: raise\n" if fault == "missing_route"
                     else f"  if getattr(error, 'name', None) != {guard_name!r}: raise\n")
  child = (
    "import sys, types\n"
    f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
    "from uvicorn import Config\n"
    "stub = types.ModuleType('naeural_core.utils.uvicorn_fast_api_ipc_manager')\n"
    "class Comms:\n"
    "  def __init__(self, **kwargs): pass\n"
    "stub.UvicornPluginComms = Comms\n"
    "sys.modules[stub.__name__] = stub\n"
    + missing_import +
    "try:\n"
    "  Config('main:app', lifespan='off', log_level='critical').load()\n"
    "except (RuntimeError, ModuleNotFoundError) as error:\n"
    + exception_check +
    "  print('rejected before serving')\n"
    "else:\n"
    "  raise SystemExit('incompatible app was loaded')\n"
    "prefix = 'extensions.business.cybersec.red_mesh.'\n"
    "if any(name.startswith(prefix + part) for name in sys.modules\n"
    "       for part in ('services', 'tenancy.administration', 'tenancy.identity')):\n"
    "  raise SystemExit('HTTP guard imported plugin services')\n"
  )
  result = subprocess.run(
    [sys.executable, *(["-O"] if optimized else []), "-c", child],
    cwd=tmp_path, capture_output=True, text=True, timeout=20,
  )
  assert result.returncode == 0, result.stderr
  assert result.stdout.strip() == "rejected before serving"


def _assembly_harness(tmp_path):
  """Run actual native asset/loop methods, replacing only external runtime hooks."""
  base_path = FRAMEWORK_ROOT / "business/base/web_app/base_web_app_plugin.py"
  fastapi_path = FRAMEWORK_ROOT / "business/default/web_app/fast_api_web_app.py"
  base_methods = {
    "initialize_assets", "_process", "__maybe_init_assets", "_reload_server",
    "__maybe_run_all_setup_commands", "__maybe_run_all_start_commands",
    "__maybe_run_nth_start_command",
  }

  class Lifecycle:
    def _process(self):
      self.lifecycle_calls += 1

  namespace = {
    "Lifecycle": Lifecycle, "os": os, "shutil": shutil, "Path": Path,
    "Environment": Environment, "FileSystemLoader": FileSystemLoader,
  }
  classes = []
  for path, name, parent, names in (
    (base_path, "BaseWebAppPlugin", "Lifecycle", base_methods),
    (fastapi_path, "FastApiWebAppPlugin", "BaseWebAppPlugin", {"initialize_assets", "jinja_args"}),
    (PLUGIN_PATH, "PentesterApi01Plugin", "FastApiWebAppPlugin", {"initialize_assets"}),
  ):
    original = next(node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.ClassDef) and node.name == name)
    methods = [deepcopy(node) for node in original.body
               if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {method.name for method in methods} == names
    classes.append(ast.ClassDef(
      name=name, bases=[ast.Name(id=parent, ctx=ast.Load())], keywords=[],
      body=methods, decorator_list=[],
    ))
  exec(compile(ast.fix_missing_locations(ast.Module(body=classes, type_ignores=[])),
               "<actual-native-asset-lifecycle>", "exec"), namespace)

  class Harness(namespace["PentesterApi01Plugin"]):
    @property
    def jinja_args(self):
      return self.fixture_jinja_args

  harness = Harness()
  _source, endpoints = _render_native()
  harness.fixture_jinja_args = deepcopy(endpoints.render_args)
  harness.cfg_template, harness.cfg_jinja_args = "basic_server", {}
  harness.script_temp_dir, harness.os_path = str(tmp_path), os.path
  harness.prepared_env, harness.base_env = {}, {}
  harness.failed = harness.assets_initialized = harness.setup_complete = False
  harness.lifecycle_calls = 0
  harness.command_calls, harness.logs = [], []
  harness.can_run_start_commands = True
  harness.P = lambda text, **_kwargs: harness.logs.append(text)
  harness.time = lambda: 0
  harness.deepcopy = deepcopy
  harness.get_output_folder = lambda: str(tmp_path)
  harness.plugin_id = "fixture-only"
  harness.get_package_base_path = lambda _package: str(FRAMEWORK_ROOT.parent)
  harness.get_setup_commands = lambda: ["fixture setup"]
  harness.get_start_commands = lambda: ["fixture start"]
  for name in (
    "_BaseWebAppPlugin__maybe_setup_commands", "_BaseWebAppPlugin__maybe_forced_reload",
    "_BaseWebAppPlugin__prepare_env", "maybe_init_tunnel_engine", "maybe_start_tunnel_engine",
    "_BaseWebAppPlugin__maybe_print_all_logs", "maybe_tunnel_engine_ping",
    "_maybe_close_setup_commands", "_maybe_close_start_commands", "_maybe_read_and_stop_all_log_readers",
    "maybe_stop_tunnel_engine", "_BaseWebAppPlugin__init_temp_dir", "_BaseWebAppPlugin__deallocate_port",
    "_allocate_port",
  ):
    setattr(harness, name, lambda *_args, **_kwargs: None)
  harness._BaseWebAppPlugin__maybe_download_assets = lambda: None
  harness._BaseWebAppPlugin__check_new_repo_version = lambda: False
  harness._BaseWebAppPlugin__has_finished_setup_commands = lambda: harness.setup_complete
  harness._BaseWebAppPlugin__has_finished_start_commands = lambda: False
  harness._BaseWebAppPlugin__all_start_running = lambda: False

  def setup(_index):
    harness.command_calls.append("setup")
    harness.setup_complete = True

  harness._BaseWebAppPlugin__maybe_run_nth_setup_command = setup
  harness._BaseWebAppPlugin__maybe_run_nth_start_command = lambda _index: harness.command_calls.append("start")
  return harness, namespace


def test_actual_asset_initializer_adds_guard_on_each_render_and_reload(tmp_path):
  harness, _namespace = _assembly_harness(tmp_path)
  harness._process()
  assert harness.failed is False
  assert harness.command_calls == ["setup", "start"]
  assert harness.lifecycle_calls == 1
  generated = tmp_path / "main.py"
  source = generated.read_text()
  assert source.count("validate_generated_execution_api(app, globals())") == 1
  assert source.count("install_generated_read_api(app, globals())") == 1
  module = types.ModuleType("_rm026_assembled_native_fixture")
  comms = types.ModuleType("naeural_core.utils.uvicorn_fast_api_ipc_manager")
  comms.UvicornPluginComms = _Comms
  with patch.dict(sys.modules, {comms.__name__: comms, module.__name__: module}):
    exec(compile(source, str(generated), "exec"), module.__dict__)
  assert module.eng.calls == []
  harness._reload_server()
  assert harness.failed is False
  assert generated.read_text().count("validate_generated_execution_api(app, globals())") == 1
  assert generated.read_text().count("install_generated_read_api(app, globals())") == 1


@pytest.mark.parametrize("fault", (
  "template", "jinja_override", "malformed_jinja", "render", "missing_main", "append", "unlink",
))
def test_entered_assembly_failure_preserves_native_lifecycle_and_blocks_commands(tmp_path, fault):
  harness, namespace = _assembly_harness(tmp_path)
  if fault == "template":
    harness.cfg_template = "unsupported"
  elif fault == "jinja_override":
    harness.cfg_jinja_args = {"node_comm_params": []}
  elif fault == "malformed_jinja":
    harness.cfg_jinja_args = []
  from contextlib import ExitStack
  with ExitStack() as patches:
    if fault == "render":
      patches.enter_context(patch.object(Environment, "get_template", side_effect=OSError("private render detail")))
    elif fault == "missing_main":
      patches.enter_context(patch.object(namespace["FastApiWebAppPlugin"], "initialize_assets", return_value=None))
    elif fault == "append":
      patches.enter_context(patch.object(Path, "open", side_effect=OSError("private append detail")))
    elif fault == "unlink":
      patches.enter_context(patch.object(Path, "unlink", side_effect=OSError("private unlink detail")))
    calls = patches.enter_context(patch.object(type(harness), "initialize_assets", wraps=harness.initialize_assets))
    harness._process()
    assert harness.failed is True and harness.assets_initialized is True
    assert (calls.call_count, harness.lifecycle_calls, harness.command_calls) == (1, 1, [])
    harness._process()
    assert (calls.call_count, harness.lifecycle_calls, harness.command_calls) == (1, 2, [])
    harness._reload_server()
    harness._process()
    assert harness.failed is True and harness.assets_initialized is True
    assert (calls.call_count, harness.lifecycle_calls, harness.command_calls) == (2, 3, [])
  assert harness.logs.count("Execution API assembly unavailable") == 2
  assert all("private" not in entry for entry in harness.logs)


def test_successful_assembly_does_not_authorize_a_failed_reload(tmp_path):
  harness, _namespace = _assembly_harness(tmp_path)
  harness.initialize_assets(None, str(tmp_path), harness.jinja_args)
  assert harness.failed is False
  harness.cfg_template = None
  harness._reload_server()
  harness._process()
  assert harness.failed is True
  assert harness.command_calls == []
  assert harness.lifecycle_calls == 1


def test_old_generated_file_cannot_stand_in_for_a_missing_render(tmp_path):
  harness, namespace = _assembly_harness(tmp_path)
  (tmp_path / "main.py").write_text("# stale unguarded assembly\n", encoding="utf-8")
  with patch.object(namespace["FastApiWebAppPlugin"], "initialize_assets", return_value=None):
    harness._process()
  assert harness.failed is True
  assert harness.command_calls == []
  assert harness.lifecycle_calls == 1


@pytest.mark.parametrize("fault", ("duplicate_route", "model_shadow", "html_shadow"))
def test_actual_asset_output_rejects_shadowed_native_route_or_model(tmp_path, fault):
  harness, _namespace = _assembly_harness(tmp_path)
  endpoints = harness.fixture_jinja_args["node_comm_params"]
  descriptor = deepcopy(next(item for item in endpoints if item["name"] == "launch_network_scan"))
  if fault == "model_shadow":
    descriptor["name"] = "launch_network_scanModel"
    endpoints.append(descriptor)
  elif fault == "duplicate_route":
    endpoints.append(descriptor)
  else:
    harness.fixture_jinja_args["html_files"] = [
      {"name": "fixture.html", "route": "/launch_network_scan", "method": "get"},
    ]
  harness.initialize_assets(None, str(tmp_path), harness.jinja_args)
  assert harness.failed is False
  module = types.ModuleType("_rm026_shadow_native_fixture")
  comms = types.ModuleType("naeural_core.utils.uvicorn_fast_api_ipc_manager")
  comms.UvicornPluginComms = _Comms
  generated = tmp_path / "main.py"
  with patch.dict(sys.modules, {comms.__name__: comms, module.__name__: module}):
    with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
      exec(compile(generated.read_text(), str(generated), "exec"), module.__dict__)
  assert module.eng.calls == []


def test_native_jinja_failure_before_override_remains_outside_containment(tmp_path):
  harness, namespace = _assembly_harness(tmp_path)
  harness.cfg_jinja_args, harness.cfg_pages = {"html_files": None}, []
  with patch.object(type(harness), "jinja_args", namespace["FastApiWebAppPlugin"].jinja_args):
    with patch.object(type(harness), "initialize_assets", wraps=harness.initialize_assets) as initialize:
      with pytest.raises(TypeError):
        harness._process()
      assert initialize.call_count == 0
  assert harness.lifecycle_calls == 0
  assert harness.command_calls == []


@pytest.mark.parametrize("failure", ("immediate_exit", "delayed_exit", "live_supervisor"))
def test_native_start_monitor_does_not_equate_parent_status_with_http_health(tmp_path, failure):
  harness, namespace = _assembly_harness(tmp_path)
  monitor = namespace["BaseWebAppPlugin"]._BaseWebAppPlugin__maybe_run_nth_start_command
  harness.assets_initialized = True
  harness.start_commands_started, harness.start_commands_finished = [False], [False]
  harness.start_commands_processes, harness.start_commands_start_time = [None], [None]
  harness.dct_logs_reader, harness.dct_err_logs_reader = {}, {}
  harness._redact_tunnel_command_for_log = lambda command: command
  harness._BaseWebAppPlugin__maybe_read_and_stop_key_log_readers = lambda _key: None
  harness.clock, harness.polls, harness.payloads = 0, [], []
  harness.time = lambda: harness.clock
  harness.add_payload_by_fields = lambda **fields: harness.payloads.append(fields)
  # Child import failure is proven separately; this is the parent's reported state.
  parent = types.SimpleNamespace(exited=failure == "immediate_exit", http_loaded=False)
  harness._BaseWebAppPlugin__run_command = lambda *_args: (parent, None, None)

  def wait_for_parent(*, process, timeout):
    harness.polls.append(harness.clock)
    return process.exited, None

  harness._BaseWebAppPlugin__wait_for_command = wait_for_parent
  monitor(harness, 0)
  if failure == "immediate_exit":
    assert harness.failed is True
    assert harness.payloads[-1]["command_status"] == "failed"
    harness._process()
    assert harness.lifecycle_calls == 1
    assert harness.command_calls == []
  else:
    harness.clock = 6
    monitor(harness, 0)
    assert harness.failed is False
    assert harness.payloads[-1]["command_status"] == "success"
    parent.exited = failure == "delayed_exit"
    harness.clock = 10
    monitor(harness, 0)
    assert harness.polls == [0, 6]
    assert harness.failed is False
  assert parent.http_loaded is False
