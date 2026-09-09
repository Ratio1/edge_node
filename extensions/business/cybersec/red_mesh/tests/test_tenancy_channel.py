"""Channel-token decorator (RM-075 Phase 2): value check, marker, and framework compatibility."""
import inspect
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.channel import (
  MARKER,
  channel_token_required,
  is_channel_guarded,
)

_TOKEN = "navigator-backend-token-material-32-bytes"


def _fake_endpoint(func, method="get", require_token=True):
  """Mirror what the real ``BasePlugin.endpoint`` does: set attributes, return the function."""
  func.__endpoint__ = True
  func.__http_method__ = method
  func.__require_token__ = require_token
  return func


class _Plugin:
  @channel_token_required
  def echo(self, token, value="", **extras):
    return {"ok": True, "value": value, "extras": extras}


class TestChannelTokenRequired(unittest.TestCase):
  def test_wrong_value_is_denied_and_body_never_runs(self):
    body = unittest.mock.Mock(side_effect=AssertionError("body must not run"))
    guarded = channel_token_required(lambda self, token: body())
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": _TOKEN}, clear=True):
      result = guarded(object(), "not-the-token")
    self.assertEqual(result["status_code"], 403)
    self.assertEqual(result["error_class"], "backend_auth_invalid")
    body.assert_not_called()

  def test_missing_value_is_401(self):
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": _TOKEN}, clear=True):
      result = _Plugin().echo("")
    self.assertEqual(result["status_code"], 401)
    self.assertEqual(result["error_class"], "backend_auth_required")

  def test_unconfigured_deployment_fails_closed(self):
    with patch.dict("os.environ", {}, clear=True):
      result = _Plugin().echo(_TOKEN)
    self.assertEqual(result["status_code"], 401)
    self.assertEqual(result["error_class"], "backend_auth_unavailable")

  def test_correct_value_passes_token_and_arguments_through(self):
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": _TOKEN}, clear=True):
      result = _Plugin().echo(_TOKEN, value="v", extra=1)
    self.assertEqual(result, {"ok": True, "value": "v", "extras": {"extra": 1}})

  def test_denial_never_echoes_token_material(self):
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": _TOKEN}, clear=True):
      result = _Plugin().echo("presented-secret-value")
    self.assertNotIn(_TOKEN, str(result))
    self.assertNotIn("presented-secret-value", str(result))

  def test_marker_and_framework_attributes_survive_in_either_decorator_order(self):
    # Innermost (the documented order): endpoint attributes land on the wrapper directly.
    @_fake_endpoint
    @channel_token_required
    def inner_first(self, token, x=1):
      return x

    self.assertTrue(is_channel_guarded(inner_first))
    self.assertTrue(getattr(inner_first, "__endpoint__", False))
    self.assertTrue(getattr(inner_first, "__require_token__", False))

    # Outer-most by mistake: wraps must still carry the endpoint attributes through __dict__.
    def bare(self, token, x=1):
      return x

    _fake_endpoint(bare)
    outer = channel_token_required(bare)
    self.assertTrue(getattr(outer, "__endpoint__", False))
    self.assertTrue(getattr(outer, MARKER, False))

  def test_signature_seen_by_the_framework_is_the_original_with_token_first(self):
    # fast_api_web_app registration calls inspect.signature(method) and requires
    # all_params[0] == 'token' under require_token=True; signature follows __wrapped__.
    params = list(inspect.signature(_Plugin.echo).parameters)
    self.assertEqual(params[:2], ["self", "token"])
    self.assertIn("extras", params)  # has_kwargs is recomputed from this at dispatch



class TestDeployedTokenWhitespace(unittest.TestCase):
  def test_trailing_newline_in_the_deployed_secret_does_not_reject_navigator(self):
    # Navigator trims its copy; the plugin must compare the same bytes.
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": _TOKEN + "\n"}, clear=True):
      self.assertEqual(_Plugin().echo(_TOKEN), {"ok": True, "value": "", "extras": {}})


if __name__ == "__main__":
  unittest.main()
