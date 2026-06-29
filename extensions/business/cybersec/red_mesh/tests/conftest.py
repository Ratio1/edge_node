import json
import sys
import struct
import types
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

from xperimental.utils import color_print

MANUAL_RUN = False



def install_pymisp_stub():
  """Install a small PyMISP stand-in when the optional test dependency is absent."""
  if "pymisp" in sys.modules:
    return
  try:
    __import__("pymisp")
    return
  except ModuleNotFoundError:
    pass

  class FakeMISPTag:
    def __init__(self, name):
      self.name = name

    def to_dict(self):
      return {"name": self.name}

  class FakeMISPAttribute:
    def __init__(self, attribute_type=None, value=None, object_relation=None, comment=None, **kwargs):
      self.type = attribute_type
      self.value = value
      self.object_relation = object_relation or attribute_type
      self.comment = comment
      self.tags = []
      for key, val in kwargs.items():
        setattr(self, key, val)

    def add_tag(self, tag):
      tag_obj = tag if hasattr(tag, "name") else FakeMISPTag(tag)
      self.tags.append(tag_obj)
      return tag_obj

    def to_dict(self):
      return {
        "type": self.type,
        "value": self.value,
        "object_relation": self.object_relation,
        "comment": self.comment,
        "tags": [tag.to_dict() for tag in self.tags],
      }

  class FakeMISPObject:
    def __init__(self, name=None, *args, **kwargs):
      self.name = name
      self.attributes = []
      self.tags = []
      self.comment = kwargs.get("comment", "")

    def add_attribute(self, object_relation, value=None, **kwargs):
      attr = FakeMISPAttribute(
        kwargs.pop("type", object_relation),
        value,
        object_relation=object_relation,
        **kwargs,
      )
      self.attributes.append(attr)
      return attr

    def add_tag(self, tag):
      tag_obj = tag if hasattr(tag, "name") else FakeMISPTag(tag)
      self.tags.append(tag_obj)
      return tag_obj

    def to_dict(self):
      return {
        "name": self.name,
        "attributes": [attr.to_dict() for attr in self.attributes],
        "tags": [tag.to_dict() for tag in self.tags],
        "comment": self.comment,
      }

  class FakeMISPEvent(FakeMISPObject):
    def __init__(self, *args, **kwargs):
      super().__init__("event", *args, **kwargs)
      self.info = ""
      self.distribution = None
      self.threat_level_id = None
      self.analysis = None
      self.objects = []
      self.uuid = ""
      self.id = None

    def add_object(self, obj):
      self.objects.append(obj)
      return obj

    def to_dict(self):
      data = super().to_dict()
      data.update({
        "info": self.info,
        "distribution": self.distribution,
        "threat_level_id": self.threat_level_id,
        "analysis": self.analysis,
        "objects": [obj.to_dict() for obj in self.objects],
        "uuid": self.uuid,
        "id": self.id,
      })
      return data

  pymisp_stub = types.ModuleType("pymisp")
  pymisp_stub.MISPEvent = FakeMISPEvent
  pymisp_stub.MISPObject = FakeMISPObject
  pymisp_stub.MISPAttribute = FakeMISPAttribute
  pymisp_stub.PyMISP = MagicMock
  sys.modules["pymisp"] = pymisp_stub


class DummyOwner:
  def __init__(self):
    self.messages = []

  def P(self, message, **kwargs):
    self.messages.append(message)
    if MANUAL_RUN:
      if "VULNERABILITY" in message:
        color = 'r'
      elif any(x in message for x in ["WARNING", "findings:"]):
        color = 'y'
      else:
        color = 'd'
      color_print(f"[DummyOwner] {message}", color=color)
    return


def mock_plugin_modules():
  """Install mock modules so pentester_api_01 can be imported without naeural_core."""
  install_pymisp_stub()
  if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
    return  # Already imported successfully

  # Build a real class to avoid metaclass conflicts
  def endpoint_decorator(*args, **kwargs):
    if args and callable(args[0]):
      return args[0]
    def wrapper(fn):
      return fn
    return wrapper

  class FakeBasePlugin:
    CONFIG = {'VALIDATION_RULES': {}}
    endpoint = staticmethod(endpoint_decorator)

  mock_module = MagicMock()
  mock_module.FastApiWebAppPlugin = FakeBasePlugin

  modules_to_mock = {
    'naeural_core': MagicMock(),
    'naeural_core.business': MagicMock(),
    'naeural_core.business.default': MagicMock(),
    'naeural_core.business.default.web_app': MagicMock(),
    'naeural_core.business.default.web_app.fast_api_web_app': mock_module,
  }
  for mod_name, mod in modules_to_mock.items():
    sys.modules.setdefault(mod_name, mod)
