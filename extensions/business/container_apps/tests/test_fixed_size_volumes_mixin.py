"""Tests for _FixedSizeVolumesMixin."""

import types
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.container_apps.mixins.fixed_size_volumes import (
  _FixedSizeVolumesMixin,
)


def _make_mixin_instance(fixed_size_volumes):
  """Minimal harness: a bare _FixedSizeVolumesMixin with the attributes the
  _configure_fixed_size_volumes method actually touches before provisioning
  begins. We never reach the real provisioning path in these tests."""
  obj = _FixedSizeVolumesMixin.__new__(_FixedSizeVolumesMixin)
  obj.cfg_fixed_size_volumes = fixed_size_volumes
  obj.logged = []

  def _P(msg, *a, **k):
    obj.logged.append(str(msg))

  obj.P = _P
  return obj


def _make_owner_instance(image_user, image_ref="test/image:latest"):
  """Harness for _resolve_image_owner: mocks docker_client.images.get to
  return an image whose attrs['Config']['User'] is `image_user`."""
  obj = _FixedSizeVolumesMixin.__new__(_FixedSizeVolumesMixin)
  obj.logged = []
  obj._throwaway_calls = []

  def _P(msg, *a, **k):
    obj.logged.append(str(msg))

  obj.P = _P
  obj._get_full_image_ref = lambda: image_ref

  mock_image = MagicMock()
  mock_image.attrs = {"Config": {"User": image_user}}
  obj.docker_client = MagicMock()
  obj.docker_client.images.get.return_value = mock_image
  # Fail loudly if anything tries to run a container during ownership probe.
  obj.docker_client.containers.run.side_effect = AssertionError(
    "ownership probe must not execute the image"
  )
  return obj


class CollisionDetectionTests(unittest.TestCase):

  def test_distinct_sanitized_names_do_not_raise(self):
    obj = _make_mixin_instance({
      "data_a": {"SIZE": "1G", "MOUNTING_POINT": "/a"},
      "data_b": {"SIZE": "1G", "MOUNTING_POINT": "/b"},
    })
    # _require_tools will fail fast in the test env, but the collision check
    # runs before it -- that's the only part we care about here.
    with patch(
      "extensions.business.container_apps.fixed_volume._require_tools",
      side_effect=RuntimeError("not available"),
    ):
      obj._configure_fixed_size_volumes()
    self.assertEqual(
      [m for m in obj.logged if "normalize to the same" in m],
      [],
      "should not log collision for distinct logicals",
    )

  def test_collision_raises_value_error(self):
    obj = _make_mixin_instance({
      "a/b": {"SIZE": "1G", "MOUNTING_POINT": "/x"},
      "a?b": {"SIZE": "1G", "MOUNTING_POINT": "/y"},
    })
    with self.assertRaises(ValueError) as ctx:
      obj._configure_fixed_size_volumes()
    msg = str(ctx.exception)
    self.assertIn("normalize to the same", msg)
    self.assertIn("a_b", msg)

  def test_missing_config_returns_early(self):
    obj = _make_mixin_instance({})
    obj._configure_fixed_size_volumes()  # empty dict -- no-op path


class ResolveImageOwnerTests(unittest.TestCase):
  """Ownership is resolved from image metadata only -- never by running
  the user-supplied image."""

  def test_empty_user_is_root_owned(self):
    obj = _make_owner_instance("")
    self.assertEqual(obj._resolve_image_owner(), (None, None))

  def test_root_string_is_root_owned(self):
    for u in ["root", "0", "0:0", "root:root"]:
      obj = _make_owner_instance(u)
      self.assertEqual(
        obj._resolve_image_owner(), (None, None), f"USER={u!r}",
      )

  def test_numeric_uid_only(self):
    obj = _make_owner_instance("1000")
    self.assertEqual(obj._resolve_image_owner(), (1000, 1000))

  def test_numeric_uid_and_gid(self):
    obj = _make_owner_instance("1000:2000")
    self.assertEqual(obj._resolve_image_owner(), (1000, 2000))

  def test_symbolic_user_falls_back_to_root_with_warning(self):
    obj = _make_owner_instance("appuser")
    self.assertEqual(obj._resolve_image_owner(), (None, None))
    obj.docker_client.containers.run.assert_not_called()
    self.assertTrue(
      any("symbolic" in m for m in obj.logged),
      "expected a 'symbolic' warning in logs",
    )

  def test_symbolic_user_with_group_still_no_execution(self):
    obj = _make_owner_instance("appuser:appgroup")
    self.assertEqual(obj._resolve_image_owner(), (None, None))
    obj.docker_client.containers.run.assert_not_called()

  def test_inspect_failure_is_root_owned(self):
    obj = _make_owner_instance("1000")
    obj.docker_client.images.get.side_effect = Exception("pull failed")
    self.assertEqual(obj._resolve_image_owner(), (None, None))
    obj.docker_client.containers.run.assert_not_called()
    self.assertTrue(
      any("Could not inspect" in m for m in obj.logged),
      "expected an inspect-failure warning in logs",
    )


if __name__ == "__main__":
  unittest.main()
