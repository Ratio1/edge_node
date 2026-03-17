import copy
from types import SimpleNamespace

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin


class InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError as exc:
      raise AttributeError(item) from exc


class _TestDeeployPlugin(_DeeployMixin):
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
