"""Tests for ContainerAppRunnerPlugin._compute_container_name.

Covers the fix for cross-pipeline container-name collisions: two plugin
instances sharing the same INSTANCE_ID but living under different pipelines
must not produce the same Docker container name, because the startup path
force-removes any existing container with that name.
"""

import os
import re
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
  sys.path.insert(0, REPO_ROOT)

from extensions.business.container_apps.tests import support  # noqa: F401 -- installs dummy base plugin
from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin


# Docker container names must match this charset per the engine.
_DOCKER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


class ContainerNameTests(unittest.TestCase):

  def test_pipelines_with_same_instance_id_get_distinct_names(self):
    a = ContainerAppRunnerPlugin._compute_container_name("pipeA", "worker1")
    b = ContainerAppRunnerPlugin._compute_container_name("pipeB", "worker1")
    self.assertNotEqual(a, b)
    self.assertIn("pipeA", a)
    self.assertIn("pipeB", b)
    self.assertIn("worker1", a)
    self.assertIn("worker1", b)

  def test_slashes_and_special_chars_are_sanitized(self):
    name = ContainerAppRunnerPlugin._compute_container_name("team/app", "inst?1")
    self.assertNotIn("/", name)
    self.assertNotIn("?", name)
    self.assertTrue(_DOCKER_NAME_RE.match(name), f"not a valid docker name: {name!r}")

  def test_traversal_attempt_is_neutralized(self):
    name = ContainerAppRunnerPlugin._compute_container_name("pipe", "../../evil")
    self.assertNotIn("/", name)
    self.assertTrue(_DOCKER_NAME_RE.match(name), f"not a valid docker name: {name!r}")

  def test_empty_inputs_still_produce_valid_docker_name(self):
    for sid, iid in [("", ""), (".", "."), ("..", ".."), ("", "inst"), ("pipe", "")]:
      name = ContainerAppRunnerPlugin._compute_container_name(sid, iid)
      self.assertTrue(name, f"empty name for ({sid!r}, {iid!r})")
      self.assertTrue(
        _DOCKER_NAME_RE.match(name),
        f"not a valid docker name for ({sid!r}, {iid!r}): {name!r}",
      )

  def test_name_is_deterministic(self):
    a = ContainerAppRunnerPlugin._compute_container_name("pipe", "inst")
    b = ContainerAppRunnerPlugin._compute_container_name("pipe", "inst")
    self.assertEqual(a, b)


if __name__ == "__main__":
  unittest.main()
