import copy
import importlib.util
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
  module_path = (
    Path(__file__).resolve().parents[4]
    / "naeural_core"
    / "naeural_core"
    / "business"
    / "mixins_base"
    / "chainstore_response_mixin.py"
  )
  spec = importlib.util.spec_from_file_location(
    "deeploy_chainstore_response_mixin_for_tests",
    module_path,
  )
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module._DeeployChainstoreResponseMixin


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
  plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.json_dumps = lambda obj, **kwargs: str(obj)

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
