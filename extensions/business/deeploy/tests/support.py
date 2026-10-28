import copy
import importlib.util
from collections import defaultdict
from pathlib import Path
import sys
import types
from types import SimpleNamespace

# Stub heavy optional dependencies so naeural_core can be imported in lightweight test environments
for _mod_name in ("torch", "torch.nn", "torch.nn.functional"):
  sys.modules.setdefault(_mod_name, types.ModuleType(_mod_name))

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin


def _load_deeploy_chainstore_response_mixin():
  """
  Load only the chainstore-response mixin module for lightweight Deeploy tests.

  Importing `naeural_core.business.mixins_base` executes package-level imports
  that require optional runtime dependencies such as cv2, which are unrelated
  to these focused tests.
  """
  required_helpers = {
    "_get_chainstore_response_local_reset_peers",
    "_get_chainstore_response_local_reset_write_kwargs",
    "_reset_chainstore_response_key",
  }
  checked_paths = []
  rejected = []
  for module_path in _iter_deeploy_chainstore_response_mixin_paths():
    if module_path in checked_paths:
      continue
    checked_paths.append(module_path)
    if not module_path.is_file():
      continue
    spec = importlib.util.spec_from_file_location(
      "deeploy_chainstore_response_mixin_for_tests",
      module_path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for class_name in ("_DeeployChainstoreResponseMixin", "_ChainstoreResponseMixin"):
      candidate = getattr(module, class_name, None)
      if candidate is None:
        continue
      missing = sorted(
        helper for helper in required_helpers
        if not callable(getattr(candidate, helper, None))
      )
      if not missing:
        return candidate
      rejected.append(f"{module_path}: {class_name} missing {missing}")

  formatted_paths = "\n".join(f"- {path}" for path in checked_paths)
  formatted_rejected = "\n".join(f"- {item}" for item in rejected)
  rejected_section = f"\nRejected:\n{formatted_rejected}" if formatted_rejected else ""
  raise FileNotFoundError(
    "Could not locate a Deeploy-capable chainstore response mixin for tests. "
    f"Checked:\n{formatted_paths}{rejected_section}"
  )


def _iter_deeploy_chainstore_response_mixin_paths():
  """
  Yield likely source paths for the installed, nested, or sibling naeural_core.
  """
  constants_file = getattr(ct, "__file__", None)
  edge_root = Path(__file__).resolve().parents[4]
  yield (
    edge_root
    / "extensions"
    / "business"
    / "deeploy"
    / "deeploy_chainstore_response_mixin.py"
  )

  if constants_file:
    yield (
      Path(constants_file).resolve().parent
      / "business"
      / "mixins_base"
      / "deeploy_chainstore_response_mixin.py"
    )
    yield (
      Path(constants_file).resolve().parent
      / "business"
      / "mixins_base"
      / "chainstore_response_mixin.py"
    )

  yield (
    edge_root
    / "naeural_core"
    / "naeural_core"
    / "business"
    / "mixins_base"
    / "deeploy_chainstore_response_mixin.py"
  )
  yield (
    edge_root
    / "naeural_core"
    / "naeural_core"
    / "business"
    / "mixins_base"
    / "chainstore_response_mixin.py"
  )
  yield (
    edge_root.parent
    / "naeural_core"
    / "naeural_core"
    / "business"
    / "mixins_base"
    / "deeploy_chainstore_response_mixin.py"
  )
  yield (
    edge_root.parent
    / "naeural_core"
    / "naeural_core"
    / "business"
    / "mixins_base"
    / "chainstore_response_mixin.py"
  )

  for entry in sys.path:
    if not entry:
      continue
    yield (
      Path(entry).resolve()
      / "naeural_core"
      / "business"
      / "mixins_base"
      / "deeploy_chainstore_response_mixin.py"
    )
    yield (
      Path(entry).resolve()
      / "naeural_core"
      / "business"
      / "mixins_base"
      / "chainstore_response_mixin.py"
    )


_DeeployChainstoreResponseMixin = _load_deeploy_chainstore_response_mixin()


class InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError as exc:
      raise AttributeError(item) from exc


class _TestDeeployPlugin(_DeeployMixin, _DeeployChainstoreResponseMixin):
  pass


def make_deeploy_plugin():
  plugin = _TestDeeployPlugin.__new__(_TestDeeployPlugin)
  plugin.ct = ct
  plugin.cfg_deeploy_verbose = 10
  plugin.deepcopy = copy.deepcopy
  plugin.defaultdict = defaultdict
  plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.json_dumps = lambda obj, **kwargs: str(obj)

  def build_pipeline_config(**kwargs):
    config = {
      "NAME": kwargs["name"],
      "TYPE": kwargs["stream_type"],
    }
    if kwargs.get("url") is not None:
      config["URL"] = kwargs["url"]
    if kwargs.get("plugins") is not None:
      config["PLUGINS"] = copy.deepcopy(kwargs["plugins"])
    ignored = {"name", "stream_type", "url", "plugins", "node_address", "send_immediately"}
    config.update({
      key.upper(): copy.deepcopy(value)
      for key, value in kwargs.items()
      if key not in ignored
    })
    return config

  plugin.cmdapi_build_pipeline_config = build_pipeline_config

  def dispatch_pipeline_config(config, node_address=None):
    config = copy.deepcopy(config)
    name = config.pop("NAME")
    pipeline_type = config.pop("TYPE")
    url = config.pop("URL", None)
    plugins = config.pop("PLUGINS", None)
    return plugin.cmdapi_start_pipeline_by_params(
      name=name,
      pipeline_type=pipeline_type,
      node_address=node_address,
      url=url,
      plugins=plugins,
      **{key.lower(): value for key, value in config.items()},
    )

  plugin.cmdapi_start_pipeline = dispatch_pipeline_config

  uuid_counter = {'value': 0}

  def uuid(size=6):
    uuid_counter['value'] += 1
    return f"{uuid_counter['value']:0{size}d}"[-size:]

  plugin.uuid = uuid
  plugin.const = SimpleNamespace()
  return plugin


def make_inputs(**kwargs):
  return InputsStub(kwargs)


def make_plugin_entry(signature, instance_id=None, **config):
  entry = {
    DEEPLOY_KEYS.PLUGIN_SIGNATURE: signature,
  }
  if instance_id is not None:
    entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] = instance_id
  entry.update(config)
  return entry


def submit_deployment(plugin, request, is_create=True):
  """Submit a preparation fixture with the mandatory signed intent fields."""
  request = copy.deepcopy(request)
  request.setdefault("request_id", "preparation-fixture-request")
  if not is_create:
    request.setdefault("expected_revision", 0)
  return plugin._process_pipeline_request(request, is_create=is_create)


def capture_deployment_admission(plugin, captured, counters=None):
  """Isolate HTTP preparation from durable execution, recording the exact plan.

  Admission persistence and eventual effects are tested independently by
  test_deployment_operations. These fixtures exercise real normalization,
  authorization, validation, planning and secret extraction before admission.
  """
  plugin._operation_records = lambda: {}
  build = plugin._build_create_pipeline_configs
  pending = {}
  def build_and_capture(**kwargs):
    pending.clear()
    pending.update(kwargs)
    return build(**kwargs)
  plugin._build_create_pipeline_configs = build_and_capture
  def admit(request, auth_result, app_id, configs, prior_pipeline, is_create, **kwargs):
    # This preparation fixture substitutes the custodian, not durable admission.
    # Flat legacy fixture bundles deliberately do not exercise the real RPC.
    prior_bundle = plugin._load_dauth_job_secret_bundle(request['job_id']) if not is_create else None
    configs, bundle = plugin._redact_pipeline_configs_and_build_secret_bundle(
      request['job_id'], configs, prior_bundle, prior_pipeline=prior_pipeline,
      current_identity_aliases=kwargs.get('identity_aliases'),
    )
    captured.update(
      inputs=copy.deepcopy(dict(pending['inputs'])),
      job_app_type=pending['inputs'].get(DEEPLOY_KEYS.JOB_APP_TYPE),
      prepared_create_deploy_plan=copy.deepcopy(pending['prepared_deploy_plan']),
      prepared_pipeline_configs=copy.deepcopy(configs), new_nodes=list(configs),
      bundle=copy.deepcopy(bundle),
    )
    captured['prepared_create_deploy_plan']['node_plugins_by_addr'] = {
      node: copy.deepcopy(config['PLUGINS']) for node, config in configs.items()
    }
    if counters is not None:
      assert counters['delete'] == counters['stage'] == counters['bc_update'] == 0
      counters['admitted'] += 1
      counters['admission_kwargs'] = captured
      counters['admitted_pipeline'] = copy.deepcopy(next(iter(configs.values())))
      counters['admitted_secret_bundle'] = copy.deepcopy(bundle)
    return {
      'status_code': 202, 'status': 'accepted', 'operation_id': 'operation-fixture',
      'request_id': request['request_id'], 'job_id': request['job_id'],
      'app_id': app_id, 'revision': 1,
    }
  plugin._admit_prepared_deployment = admit


class LifecycleCustodyDouble:
  """Substitute only dAuth for existing flat-bundle lifecycle fault fixtures.

  The scenario fixtures keep their inspectable storage and quorum-failure
  controls. Production coordinator methods reach this object exclusively by
  RPC; actual SDK, signatures and physically separate stores are covered by
  ``test_lifecycle_dauth_custody`` instead.
  """

  def __init__(self, plugin):
    self.plugin = plugin
    self.target_bundle = {'job_secrets': {'secret': 'protected-value'}}
    self.previous_bundle = None
    self.calls = []

  def _write(self, namespace, key, value, message):
    if not self.plugin.chainstore_hset(namespace, key, copy.deepcopy(value)):
      raise RuntimeError(message)

  def _plan(self, operation):
    if hasattr(self.plugin, 'plans'):
      return copy.deepcopy(self.plugin.plans[operation['plan_cid']])
    return copy.deepcopy(self.plugin.plan)

  def _revision(self, job_id, revision, bundle, configs):
    namespace = 'DAUTH_JOB_SECRET_REVISIONS'
    key = job_id + '|' + revision
    if self.plugin.storage.get((namespace, key + '|revoked')):
      raise RuntimeError('Secret revision is revoked.')
    value = dict(copy.deepcopy(bundle), job_id=job_id, revision=revision,
                 pipelines=copy.deepcopy(configs))
    self._write(namespace, key, value, 'Could not persist deployment secret revision.')

  def _revoke(self, operation, plan, active_attempt):
    namespace = 'DAUTH_JOB_SECRET_REVISIONS'
    references = []
    if (active_attempt or operation['kind'] == 'delete') and operation.get('previous_secret_revision'):
      references.append(operation['previous_secret_revision'])
    if operation['kind'] != 'delete':
      for attempt, field in (('deploy', 'configs'), ('restore', 'previous_configs')):
        if attempt != active_attempt and plan[field]:
          references.append(next(iter(plan[field].values()))['DEEPLOY_SPECS']['secret_revision'])
    for revision in references:
      key = str(operation['job_id']) + '|' + revision
      marker = {'job_id': str(operation['job_id']), 'revision': revision}
      self._write(namespace, key + '|revoked', marker, 'Secret revocation is pending.')
      self._write(namespace, key, dict(marker, revoked=True), 'Secret cleanup is pending.')

  def __call__(self, payload):
    operation = payload['operation']
    action = payload['action']
    job_id = str(operation['job_id'])
    namespace = 'DAUTH_JOB_SECRET_REVISIONS'
    self.calls.append(copy.deepcopy(payload))
    result = {'status': 'success', 'operation_id': operation['operation_id'], 'job_id': job_id}
    if action == 'commit':
      return self._publish(operation, payload['pointer'], False)
    plan = self._plan(operation)
    if action == 'prepare':
      for field, bundle in (('previous_configs', self.previous_bundle), ('configs', self.target_bundle)):
        configs = plan[field]
        if configs:
          revision = next(iter(configs.values()))['DEEPLOY_SPECS']['secret_revision']
          self._revision(job_id, revision, bundle or self.target_bundle, configs)
      result['prepared'] = True
    elif action == 'status':
      prepared = []
      for configs in (plan['previous_configs'], plan['configs']):
        if not configs:
          continue
        revision = next(iter(configs.values()))['DEEPLOY_SPECS']['secret_revision']
        record = self.plugin.storage.get((namespace, job_id + '|' + revision))
        if (not isinstance(record, dict) or record.get('revoked')
            or record.get('pipelines') != configs
            or self.plugin.storage.get((namespace, job_id + '|' + revision + '|revoked'))):
          return dict(result, prepared=False)
        prepared.append((revision, record, configs))
      for revision, record, configs in prepared:
        self._revision(job_id, revision, record, configs)
      result['prepared'] = True
    elif action == 'revoke':
      self._revoke(operation, plan, payload.get('active_attempt'))
    elif action == 'delete':
      pointer = payload['pointer']
      current = self.plugin.storage.get(('DEEPLOY_DEPLOYED_JOBS', job_id))
      if current != plan['canonical_record'] and current != pointer:
        raise RuntimeError('Deletion metadata no longer matches the retired revision.')
      self._revoke(operation, plan, None)
      return self._publish(operation, pointer, True, plan['canonical_cid'])
    else:
      raise AssertionError('Unexpected custody action: ' + action)
    return result

  def _publish(self, operation, pointer, deleted, previous_cid=None):
    job_id = str(operation['job_id'])
    current = self.plugin.storage.get(('DEEPLOY_DEPLOYED_JOBS', job_id))
    if previous_cid is None:
      previous_cid = current.get('pipeline_cid') if isinstance(current, dict) else current
    bundle = {} if deleted else self.target_bundle
    bundle = dict(copy.deepcopy(bundle), job_id=job_id, deployment_revision=operation['target_revision'],
                  operation_id=operation['operation_id'], coordinator=operation['coordinator'],
                  pipeline_cid=pointer['pipeline_cid'], deleted=deleted,
                  EE_SIGN='custodian-signature', EE_SENDER='fixture-dauth')
    if deleted:
      bundle['job_secrets'] = {}
    self._write('DAUTH_JOB_SECRETS', job_id, bundle, 'Deployment secret publication is pending.')
    message = 'Deletion metadata cleanup is pending.' if deleted else 'Deployment metadata publication is pending.'
    self._write('DEEPLOY_DEPLOYED_JOBS', job_id, pointer, message)
    if previous_cid and previous_cid != pointer['pipeline_cid']:
      self.plugin._delete_pipeline_cid_from_r1fs(previous_cid)
    return {'status': 'success', 'pipeline_cid': pointer['pipeline_cid'], 'job_id': job_id}
