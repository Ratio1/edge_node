"""Real generated ordinary HTTP routes reject ambiguous transport before native IPC."""
import asyncio
import inspect
import json
import queue
import subprocess
import sys
import types
from copy import copy, deepcopy
from functools import partial
from unittest.mock import patch

import pytest

from .test_tenant_execution_native import ACTOR_ONLY_READ_ROUTES, LEGACY_READ_ROUTES, LEGACY_RULEBOOK_ROUTES, READ_ROUTES, REPO_ROOT, ROUTES, _Comms, _render_native


ERROR = "Incompatible generated read API"
LIST_ROUTES = ("list_network_jobs", "list_local_jobs")
LIST_CAPSULE = "__redmesh_checked_job_list_v1"


def test_read_installation_entrypoint_exists():
  from extensions.business.cybersec.red_mesh.tenancy.http_runtime import install_generated_read_api
  assert callable(install_generated_read_api)


@pytest.fixture
def read_native(request):
  # Keep lazy Pydantic/FastAPI class imports outside the sys.modules rollback below.
  __import__("fastapi")
  source, harness = _render_native(getattr(request, "param", None))
  module = types.ModuleType("_rm026_read_native_fixture")
  comms = types.ModuleType("naeural_core.utils.uvicorn_fast_api_ipc_manager")
  comms.UvicornPluginComms = _Comms
  with patch.dict(sys.modules, {comms.__name__: comms, module.__name__: module}):
    exec(compile(source, "<native-read-server>", "exec"), module.__dict__)
    yield module, harness


def install(module):
  from extensions.business.cybersec.red_mesh.tenancy.http_runtime import install_generated_read_api
  install_generated_read_api(module.app, module.__dict__)


async def request(module, name, payload=None, *, raw=None, method="POST", query=b"", suffix=""):
  events = []
  body = json.dumps(payload).encode() if raw is None else raw
  path = "/" + name + suffix
  scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
    "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": query, "root_path": "",
    "headers": [(b"content-type", b"application/json")],
    "server": ("fixture", 80), "client": ("fixture", 0)}

  async def receive():
    return {"type": "http.request", "body": body, "more_body": False}

  async def send(event):
    events.append(event)

  before = len(module.eng.calls)
  await module.app(scope, receive, send)
  start = next(event for event in events if event["type"] == "http.response.start")
  raw_body = b"".join(event.get("body", b"") for event in events if event["type"] == "http.response.body")
  headers = dict(start["headers"])
  return start["status"], headers, raw_body, len(module.eng.calls) - before


def body_for(name):
  payload = {"request_actor": {"account_id": "Reader.Mixed"}, "tenant_id": "tenant-1"}
  if name in LEGACY_READ_ROUTES:
    payload.pop("tenant_id")
  if name in LEGACY_RULEBOOK_ROUTES:
    payload["profile_id"] = "nis2.eu_baseline.v1"
  if name not in ("list_network_jobs", "list_local_jobs", "get_audit_log") + ACTOR_ONLY_READ_ROUTES:
    payload["job_id"] = "job-1"
  if name == "get_report":
    payload["cid"] = "report-1"
  return payload


def assert_json_response(result, status):
  actual_status, headers, body, calls = result
  assert actual_status == status
  assert headers[b"cache-control"] == b"no-store"
  assert headers[b"content-type"].startswith(b"application/json")
  assert b"location" not in headers
  return json.loads(body), calls


def test_actual_twenty_route_installation_preserves_launch_contract(read_native):
  from extensions.business.cybersec.red_mesh.tenancy.http_runtime import validate_generated_execution_api
  module, _ = read_native
  install(module)
  validate_generated_execution_api(module.app, module.__dict__)
  for name in READ_ROUTES:
    route = next(route for route in module.app.routes if route.path == "/" + name)
    assert route.methods == {"POST"}
    assert route.dependant.dependencies == []
  for name in ROUTES[-2:]:
    route = next(route for route in module.app.routes if route.path == "/" + name)
    assert [dependency.call for dependency in route.dependant.dependencies] == [module.get_bearer_token]
  assert module.eng.calls == []


@pytest.mark.parametrize("name", READ_ROUTES)
def test_raw_body_preserves_actual_positional_dispatch_and_omitted_requester(read_native, name):
  module, harness = read_native
  install(module)
  parameters = inspect.signature(getattr(harness, name)).parameters
  payload = body_for(name)

  async def checks():
    for supplied in (payload, {key: value for key, value in payload.items() if key not in ("tenant_id", "request_actor")}):
      result, calls = assert_json_response(await request(module, name, supplied), 200)
      assert result == ({} if name in LIST_ROUTES else {"success": True})
      assert calls == 1
      assert module.eng.calls[-1] == (name, tuple(supplied.get(key, param.default)
        for key, param in parameters.items()), {"profile": None})
  asyncio.run(checks())


@pytest.mark.parametrize("name", READ_ROUTES)
def test_raw_faults_are_400_without_ipc_or_body_echo(read_native, name):
  module, _ = read_native
  install(module)
  valid = body_for(name)
  faults = [None, [], "private", True, 1, {**valid, "tenantId": "private"},
    {**valid, "actor": {"account_id": "private"}}, {**valid, "snapshot_mode": "legacy_unbound"},
    {**valid, "extra": "private"}]
  if name in LEGACY_READ_ROUTES:
    faults.extend({**valid, key: value} for key, value in (
      ("tenant_id", "tenant-1"), ("asset_id", "asset"), ("execution_binding", {})))
  if name in ACTOR_ONLY_READ_ROUTES:
    faults.extend({**valid, key: "private"} for key in ("job_id", "profile_id"))
  for field in valid:
    faults.extend({**valid, field: value} for value in (None, True, 1, [], "" if field == "request_actor" else {}))

  async def checks():
    for payload in faults:
      response, calls = assert_json_response(await request(module, name, payload), 400)
      assert response == {"success": False, "error": "invalid_request", "status_code": 400}
      assert calls == 0
    for raw in (b'{"tenant_id":"private","tenant_id":"other"}', b'{"request_actor":{"account_id":"a","account_id":"b"}}',
                b'{', b'', b'{"tenant_id": NaN}', b'\xff'):
      response, calls = assert_json_response(await request(module, name, raw=raw), 400)
      assert response["error"] == "invalid_request"
      assert calls == 0
  asyncio.run(checks())


@pytest.mark.parametrize("name", READ_ROUTES)
def test_query_and_method_faults_never_redirect_even_with_default_route(read_native, name):
  module, _ = read_native
  module.DEFAULT_ROUTE = "/workspace"
  install(module)

  async def checks():
    for query in (b"tenant_id=tenant-1", b"tenantId=tenant-1", b"job_id=job-1", b"irrelevant=1"):
      response, calls = assert_json_response(await request(module, name, body_for(name), query=query), 400)
      assert response["error"] == "invalid_request" and calls == 0
    for method in ("GET", "PUT", "DELETE", "HEAD", "OPTIONS"):
      response, calls = assert_json_response(await request(module, name, body_for(name), method=method), 405)
      assert response["status_code"] == 405 and calls == 0
    response, calls = assert_json_response(await request(module, name, body_for(name), suffix="/"), 400)
    assert response["error"] == "invalid_request" and calls == 0
  asyncio.run(checks())


@pytest.mark.parametrize("name", READ_ROUTES)
@pytest.mark.parametrize("fault", ("missing", "method", "alias", "model", "extra_field", "nullable_actor", "actor_default", "body_annotation", "dependency"))
def test_route_model_contract_corruption_fails_at_install(read_native, name, fault):
  module, _ = read_native
  route = next(route for route in module.app.routes if route.path == "/" + name)
  model = module.__dict__[name + "Model"]
  if fault == "missing":
    module.app.router.routes.remove(route)
  elif fault == "method":
    route.methods = {"GET"}
  elif fault == "alias":
    alias = copy(route)
    alias.path = "/read-alias"
    module.app.router.routes.append(alias)
  elif fault == "model":
    module.__dict__.pop(name + "Model")
  elif fault == "extra_field":
    model.model_fields["extra"] = model.model_fields[
      "request_actor" if name in LEGACY_READ_ROUTES else "tenant_id"]
  elif fault == "nullable_actor":
    model.model_fields["request_actor"].annotation = dict | None
  elif fault == "actor_default":
    model.model_fields["request_actor"].default = {}
  elif fault == "body_annotation":
    route.dependant.body_params[0].field_info.annotation = object
  elif fault == "dependency":
    route.dependant.dependencies = [object()]
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    install(module)
  assert module.eng.calls == []


@pytest.mark.parametrize("fault", ("middleware", "exceptions", "started", "noop_middleware", "noop_handler"))
def test_unverifiable_installation_seam_fails_closed(read_native, fault):
  module, _ = read_native
  if fault == "middleware":
    module.app.add_middleware = None
  elif fault == "exceptions":
    module.app.exception_handlers = None
  elif fault == "started":
    module.app.middleware_stack = object()
  elif fault == "noop_middleware":
    module.app.add_middleware = lambda *args, **kwargs: None
  else:
    module.app.add_exception_handler = lambda *args, **kwargs: None
  with pytest.raises(RuntimeError, match=f"^{ERROR}$"):
    install(module)


def test_unrelated_not_found_retains_original_redirect(read_native):
  module, _ = read_native
  module.DEFAULT_ROUTE = "/workspace"
  install(module)
  status, headers, _, calls = asyncio.run(request(module, "unrelated", {}, method="GET"))
  assert status == 307 and headers[b"location"] == b"/workspace" and calls == 0


def scheduler_comms(fixture, response_format, metadata=None):
  """The actual native dispatcher and response wrapper call actual stored-account endpoints."""
  from .test_postponed_analyze_native_ipc import _SchedulerHarness
  scheduler = _SchedulerHarness.__new__(_SchedulerHarness)
  scheduler.cfg_log_requests = False
  scheduler.cfg_response_format = response_format
  scheduler.get_additional_fastapi_data = lambda: dict(metadata or {})
  fixture.owner.cfg_response_format = response_format
  scheduler.on_response = partial(fixture.Plugin.on_response, fixture.owner)
  scheduler._client_queue = queue.Queue()
  scheduler._endpoints = {name: partial(getattr(fixture.Plugin, name), fixture.owner) for name in READ_ROUTES}

  class Comms:
    def __init__(self):
      self.calls = []

    async def call_plugin(self, name, *args, **kwargs):
      self.calls.append((name, args, kwargs))
      scheduler._process_incoming_request({"id": "read-fixture", "value": [name, *args]})
      return scheduler._client_queue.get_nowait()["value"]

  return Comms()


@pytest.mark.parametrize("name", LIST_ROUTES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("aliases", (
  (), ("error",), ("exception_metadata",), ("status_code",), ("result",),
  (LIST_CAPSULE,), ("server_node_addr",),
  ("ordinary", "error", "exception_metadata", "status_code", "result", LIST_CAPSULE, "server_node_addr"),
))
def test_actual_scheduler_list_aliases_and_empty_mapping_preserve_public_shape(read_native, name, response_format, aliases):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  module.ADDITIONAL_FASTAPI_DATA = {"server_node_addr": "renderer-node", "renderer_metadata": {"source": "native"}}
  install(module)
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.store.jobs.clear()
    fixture.owner.scan_jobs.clear()
    for index, alias in enumerate(aliases):
      row = {**deepcopy(fixture.job), "job_id": f"job-list-{index}"}
      fixture.store.jobs[alias] = row
      fixture.owner.scan_jobs[row["job_id"]] = {}
    expected = getattr(fixture.Plugin, name)(fixture.owner, request_actor=fixture.actor)
    assert set(expected) == set(aliases)
    metadata = {"server_node_addr": "scheduler-node", "scheduler_metadata": {"source": "plugin"}}
    module.eng = scheduler_comms(fixture, response_format, metadata)
    response = asyncio.run(request(module, name, {"request_actor": fixture.actor}))
    result, calls = assert_json_response(response, 200)
    assert calls == 1
    if response_format == "WRAPPED":
      assert result == {**module.ADDITIONAL_FASTAPI_DATA, **metadata, "result": expected}
    else:
      assert result == expected
    assert int(response[1][b"content-length"]) == len(response[2])
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name", LIST_ROUTES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("capsule", (
  {}, {"ordinary": {"job_id": "job-1"}},
  {LIST_CAPSULE: None}, {LIST_CAPSULE: {"version": True, "jobs": {}}},
  {LIST_CAPSULE: {"version": 2, "jobs": {}}},
  {LIST_CAPSULE: {"version": 1, "jobs": []}},
  {LIST_CAPSULE: {"version": 1, "jobs": {"private": None}}},
  {LIST_CAPSULE: {"version": 1, "jobs": {}, "extra": "private"}},
))
def test_generated_list_success_requires_valid_capsule(read_native, name, response_format, capsule):
  module, _ = read_native
  install(module)

  async def supplied_response(*args, **kwargs):
    module.eng.calls.append((args, kwargs))
    return {"result": capsule} if response_format == "WRAPPED" else capsule
  module.eng.call_plugin = supplied_response
  result, calls = assert_json_response(asyncio.run(request(module, name, body_for(name))), 503)
  assert result == {"success": False, "error": "unavailable", "status_code": 503}
  assert calls == 1


@pytest.mark.parametrize("name", LIST_ROUTES)
def test_contradictory_raw_and_wrapped_list_capsules_fail_closed(read_native, name):
  module, _ = read_native
  install(module)

  async def supplied_response(*args, **kwargs):
    module.eng.calls.append((args, kwargs))
    return {LIST_CAPSULE: {"version": 1, "jobs": {}},
            "result": {LIST_CAPSULE: {"version": 1, "jobs": {"other": {"job_id": "private"}}}}}
  module.eng.call_plugin = supplied_response
  result, calls = assert_json_response(asyncio.run(request(module, name, body_for(name))), 503)
  assert result == {"success": False, "error": "unavailable", "status_code": 503}
  assert calls == 1


@pytest.mark.parametrize("name", LIST_ROUTES)
@pytest.mark.parametrize("response_format", (None, "wrapped"))
def test_nonraw_native_format_keeps_native_wrapped_semantics(read_native, name, response_format):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.jobs["status_code"] = fixture.store.jobs.pop("legacy-alias")
    expected = getattr(fixture.Plugin, name)(fixture.owner, request_actor=fixture.actor)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, name, {"request_actor": fixture.actor})), 200)
    assert result == {"result": expected} and calls == 1


@pytest.mark.parametrize("name", LIST_ROUTES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_list_hook_and_chunked_serialization_preserve_headers(read_native, name, response_format):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  chunks = []

  class ChunkedNativeResponse:
    def __init__(self, app):
      self.app = app

    async def __call__(self, scope, receive, send):
      async def chunked_send(event):
        if event["type"] == "http.response.start":
          event = {**event, "headers": event["headers"] + [(b"x-native-test", b"preserved")]}
        elif event["type"] == "http.response.body":
          body = event.get("body", b"")
          split = body.find("é".encode()) + 1
          assert split > 0
          for fragment in (body[:split], body[split:]):
            chunks.append(fragment)
            await send({"type": "http.response.body", "body": fragment, "more_body": True})
          event = {"type": "http.response.body", "body": b"", "more_body": False}
        await send(event)
      await self.app(scope, receive, chunked_send)

  module.app.add_middleware(ChunkedNativeResponse)
  install(module)
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.job["target"] = "café.example"
    expected = getattr(fixture.Plugin, name)(fixture.owner, request_actor=fixture.actor)
    with patch.object(fixture.Plugin, "on_response", wraps=fixture.Plugin.on_response) as hook:
      module.eng = scheduler_comms(fixture, response_format)
      response = asyncio.run(request(module, name, {"request_actor": fixture.actor}))
      result, calls = assert_json_response(response, 200)
      hook.assert_called_once()
      assert hook.call_args.args[:2] == (fixture.owner, name)
    assert result == ({"result": expected} if response_format == "WRAPPED" else expected)
    assert calls == 1 and len(chunks) == 2
    assert LIST_CAPSULE.encode() in b"".join(chunks)
    assert response[1][b"x-native-test"] == b"preserved"
    assert int(response[1][b"content-length"]) == len(response[2])
    assert len(response[2]) < sum(len(chunk) for chunk in chunks)


@pytest.mark.parametrize("name", LIST_ROUTES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("outcome", ("forbidden", "not_found", "unavailable"))
def test_actual_list_denials_are_not_capsuled_or_relabelled(read_native, name, response_format, outcome):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  module.DEFAULT_ROUTE = "/workspace"
  install(module)
  with read_endpoint_fixture() as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    if outcome == "forbidden":
      payload.pop("tenant_id")
    elif outcome == "not_found":
      payload["request_actor"] = {"account_id": "missing"}
    else:
      fixture.job["execution_binding"]["asset_target_digest"] = "private corruption"
    expected = {"forbidden": 403, "not_found": 404, "unavailable": 503}[outcome]
    result, calls = assert_json_response(asyncio.run(request(module, name, payload)), expected)
    assert result == {"success": False, "error": outcome, "status_code": expected}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("name", READ_ROUTES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("bound", (False, True))
def test_actual_scheduler_and_real_authority_succeed_without_changing_wire_identity(read_native, name, response_format, bound):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=bound) as fixture:
    if name == "get_misp_export_config_status":
      fixture.owner._get_misp_export_config = lambda: fixture.Plugin._get_misp_export_config(fixture.owner)
    module.eng = scheduler_comms(fixture, response_format)
    payload = body_for(name)
    payload["request_actor"] = fixture.actor
    if bound and name not in LEGACY_READ_ROUTES:
      payload["tenant_id"] = fixture.tenant_id
    else:
      payload.pop("tenant_id", None)
    if name == "llm_health":
      result, calls = assert_json_response(asyncio.run(request(module, name, payload)), 503)
      assert result == {"success": False, "error": "unavailable", "status_code": 503}
      assert calls == 1 and fixture.artifact_reads == [] and fixture.store.reads == []
      return
    if bound and name in LEGACY_READ_ROUTES:
      result, calls = assert_json_response(asyncio.run(request(module, name, payload)), 403)
      assert result == {"success": False, "error": "forbidden", "status_code": 403}
      assert calls == 1 and fixture.artifact_reads == []
      return
    if name == "get_report":
      payload["cid"] = "worker"
    result, calls = assert_json_response(asyncio.run(request(module, name, payload)), 200)
    assert calls == 1
    actual = result["result"] if response_format == "WRAPPED" else result
    assert isinstance(actual, dict)
    if name == "get_report":
      assert actual["job_id"] == "job-1" and actual["cid"] == "worker"
      assert actual["report"]["job_id"] == "job-1"
      assert fixture.artifact_reads == [("archive", {"pin": False}), ("worker", {"pin": False})]
    if name not in ("list_network_jobs", "list_local_jobs", "get_audit_log") + ACTOR_ONLY_READ_ROUTES:
      assert actual["job_id"] == "job-1"
      assert ("execution_binding" in actual) == (bound and name != "get_job_data")


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
@pytest.mark.parametrize("outcome", ("forbidden", "not_found", "unavailable", "missing_requester"))
def test_actual_scheduler_denials_survive_native_wrapping_and_default_redirect(read_native, response_format, outcome):
  from .read_endpoint_fixtures import read_endpoint_fixture
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    expected = {"forbidden": 403, "not_found": 404, "unavailable": 503, "missing_requester": 404}[outcome]
    if outcome == "forbidden":
      payload.pop("tenant_id")
    elif outcome == "not_found":
      fixture.store.jobs.clear()
    elif outcome == "unavailable":
      fixture.artifacts["archive"] = RuntimeError("private storage detail")
    else:
      payload.pop("request_actor")
    result, calls = assert_json_response(asyncio.run(request(module, "get_job_archive", payload)), expected)
    assert calls == 1 and result["success"] is False and result["status_code"] == expected
    assert result["error"] == ("not_found" if outcome == "missing_requester" else outcome)
    assert "private" not in json.dumps(result)
    if outcome != "unavailable":
      assert fixture.artifact_reads == []


def test_optional_fields_are_not_pydantic_coerced(read_native):
  module, _ = read_native
  install(module)
  faults = (("get_job_archive", "summary_only", 1), ("get_job_archive", "summary_only", "true"),
            ("get_job_archive", "pass_offset", True), ("get_job_archive", "pass_limit", "1"),
            ("get_audit_log", "limit", True), ("get_audit_log", "limit", "1"),
            ("get_analysis", "pass_nr", "1"), ("get_analysis", "pass_nr", None),
            ("get_analysis", "tenant_id", " \t"))
  async def checks():
    for name, field, value in faults:
      result, calls = assert_json_response(await request(module, name, {**body_for(name), field: value}), 400)
      assert result["error"] == "invalid_request" and calls == 0
  asyncio.run(checks())


def test_validation_and_unexpected_transport_errors_are_json_with_html_default(read_native, tmp_path):
  module, _ = read_native
  (tmp_path / "fallback.html").write_text("private fallback HTML", encoding="utf-8")
  module.DEFAULT_ROUTE = "/workspace"
  module.DEFAULT_ROUTE_FILE = "fallback.html"
  module.STATIC_DIR = str(tmp_path)
  install(module)
  result, calls = assert_json_response(asyncio.run(request(module, "get_job_status", {})), 400)
  assert result["error"] == "invalid_request" and calls == 0

  async def failed_ipc(*args, **kwargs):
    raise RuntimeError("private transport detail")
  module.eng.call_plugin = failed_ipc
  result, calls = assert_json_response(asyncio.run(request(module, "get_job_status", body_for("get_job_status"))), 503)
  assert result == {"success": False, "error": "unavailable", "status_code": 503}
  assert calls == 0


@pytest.mark.parametrize("optimized", (False, True))
@pytest.mark.parametrize("fault", ("missing_route", "missing_installer"))
def test_actual_import_rejects_missing_read_protection_before_uvicorn_serves(tmp_path, optimized, fault):
  source, _ = _render_native()
  mutation = ("\napp.router.routes = [route for route in app.routes if route.path != '/get_job_status']\n"
              if fault == "missing_route" else
              "\nimport extensions.business.cybersec.red_mesh.tenancy.http_runtime as guard\ndel guard.install_generated_read_api\n")
  footer = ("\nfrom extensions.business.cybersec.red_mesh.tenancy.http_runtime import "
            "validate_generated_execution_api, install_generated_read_api\n"
            "validate_generated_execution_api(app, globals())\ninstall_generated_read_api(app, globals())\n")
  (tmp_path / "main.py").write_text(source + mutation + footer, encoding="utf-8")
  child = (
    "import sys, types\n"
    f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
    "from uvicorn import Config\n"
    "stub = types.ModuleType('naeural_core.utils.uvicorn_fast_api_ipc_manager')\n"
    "class Comms:\n"
    "  def __init__(self, **kwargs): pass\n"
    "stub.UvicornPluginComms = Comms\n"
    "sys.modules[stub.__name__] = stub\n"
    "try:\n"
    "  Config('main:app', lifespan='off', log_level='critical').load()\n"
    "except (RuntimeError, ImportError):\n"
    "  print('rejected before serving')\n"
    "else:\n"
    "  raise SystemExit('unprotected read API was loaded')\n"
  )
  result = subprocess.run([sys.executable, *(["-O"] if optimized else []), "-c", child],
    cwd=tmp_path, capture_output=True, text=True, timeout=20)
  assert result.returncode == 0, result.stderr
  assert result.stdout.strip() == "rejected before serving"
