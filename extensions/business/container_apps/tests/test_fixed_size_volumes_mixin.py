"""Tests for _FixedSizeVolumesMixin."""

import types
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
  unittest.main()
