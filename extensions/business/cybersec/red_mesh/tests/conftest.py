import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

from xperimental.utils import color_print

MANUAL_RUN = False



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
