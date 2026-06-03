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
  checked_paths = []
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
    if hasattr(module, "_DeeployChainstoreResponseMixin"):
      return module._DeeployChainstoreResponseMixin

  formatted_paths = "\n".join(f"- {path}" for path in checked_paths)
  raise FileNotFoundError(
    "Could not locate _DeeployChainstoreResponseMixin for Deeploy tests. "
    f"Checked:\n{formatted_paths}"
  )


def _iter_deeploy_chainstore_response_mixin_paths():
  """
  Yield likely source paths for the installed, nested, or sibling naeural_core.
  """
  constants_file = getattr(ct, "__file__", None)
  if constants_file:
    yield (
      Path(constants_file).resolve().parent
      / "business"
      / "mixins_base"
      / "deeploy_chainstore_response_mixin.py"
    )

  edge_root = Path(__file__).resolve().parents[4]
  yield (
    edge_root
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
    / "deeploy_chainstore_response_mixin.py"
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
