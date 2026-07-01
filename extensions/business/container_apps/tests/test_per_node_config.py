import unittest

from extensions.business.container_apps.tests import support  # noqa: F401
from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin


def make_runner(cls=ContainerAppRunnerPlugin, node_addr="0xai_node_b"):
  plugin = cls.__new__(cls)
  plugin.ee_addr = node_addr
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  return plugin


class TestContainerRunnerPerNodeConfig(unittest.TestCase):

  def test_container_runner_applies_per_node_config_by_index_and_node(self):
    plugin = make_runner()
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_a", "0xai_node_b"],
      "ENV": {"CLUSTER": "crdb", "ROLE": "base"},
      "CONTAINER_START_COMMAND": ["start-base"],
      "PER_NODE_CONFIG": {
        "default": {"ENV": {"ROLE": "replica"}},
        "byIndex": {
          "1": {"ENV": {"NODE_ID": "2"}},
        },
        "byNode": {
          "0xai_node_b": {
            "ENV": {"ROLE": "node-b"},
            "CONTAINER_START_COMMAND": ["start-node-b"],
          },
        },
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertTrue(applied)
    self.assertEqual(plugin.config_data["ENV"], {
      "CLUSTER": "crdb",
      "ROLE": "node-b",
      "NODE_ID": "2",
    })
    self.assertEqual(plugin.config_data["CONTAINER_START_COMMAND"], ["start-node-b"])
    self.assertNotIn("PER_NODE_CONFIG", plugin.config_data)

  def test_container_runner_accepts_compact_node_selector(self):
    plugin = make_runner(node_addr="0xai_node_b")
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_a", "0xai_node_b"],
      "ENV": {"CLUSTER": "crdb"},
      "PER_NODE_CONFIG": {
        "node_b": {"ENV": {"NODE_ID": "2"}},
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertTrue(applied)
    self.assertEqual(plugin.config_data["ENV"], {
      "CLUSTER": "crdb",
      "NODE_ID": "2",
    })

  def test_container_runner_uses_full_per_node_target_order(self):
    plugin = make_runner(node_addr="0xai_node_b")
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_b"],
      "PER_NODE_TARGET_NODES": ["0xai_node_a", "0xai_node_b"],
      "ENV": {"CLUSTER": "crdb"},
      "PER_NODE_CONFIG": {
        "byIndex": {
          "1": {"ENV": {"NODE_ID": "2"}},
        },
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertTrue(applied)
    self.assertEqual(plugin.config_data["ENV"], {
      "CLUSTER": "crdb",
      "NODE_ID": "2",
    })

  def test_container_runner_skips_by_index_when_node_cannot_be_matched(self):
    plugin = make_runner(node_addr="0xai_node_c")
    plugin.config_data = {
      "PER_NODE_TARGET_NODES": ["0xai_node_a", "0xai_node_b"],
      "ENV": {"CLUSTER": "crdb"},
      "PER_NODE_CONFIG": {
        "default": {"ENV": {"ROLE": "replica"}},
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "1"}},
        },
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertTrue(applied)
    self.assertEqual(plugin.config_data["ENV"], {
      "CLUSTER": "crdb",
      "ROLE": "replica",
    })

  def test_container_runner_consumes_sparse_per_node_config_without_local_overlay(self):
    plugin = make_runner(node_addr="0xai_node_c")
    plugin.config_data = {
      "PER_NODE_TARGET_NODES": ["0xai_node_a", "0xai_node_b"],
      "ENV": {"CLUSTER": "crdb"},
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_a": {"ENV": {"NODE_ID": "1"}},
        },
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertFalse(applied)
    self.assertEqual(plugin.config_data["ENV"], {"CLUSTER": "crdb"})
    self.assertNotIn("PER_NODE_CONFIG", plugin.config_data)

  def test_container_runner_consumes_empty_per_node_config_map(self):
    plugin = make_runner(node_addr="0xai_node_c")
    plugin.config_data = {
      "ENV": {"CLUSTER": "crdb"},
      "PER_NODE_CONFIG": {},
    }

    applied = plugin._apply_per_node_config()

    self.assertFalse(applied)
    self.assertEqual(plugin.config_data["ENV"], {"CLUSTER": "crdb"})
    self.assertNotIn("PER_NODE_CONFIG", plugin.config_data)

  def test_container_runner_rejects_malformed_structured_per_node_config_sections(self):
    plugin = make_runner()

    with self.assertRaisesRegex(ValueError, "default must be a dictionary"):
      plugin._normalize_per_node_config({"default": []})
    with self.assertRaisesRegex(ValueError, "byIndex must be a dictionary"):
      plugin._normalize_per_node_config({"byIndex": ""})
    with self.assertRaisesRegex(ValueError, "duplicate aliases"):
      plugin._normalize_per_node_config({"byIndex": {}, "BY_INDEX": {}})

  def test_container_runner_applies_first_matching_node_selector(self):
    plugin = make_runner(node_addr="0xai_node_b")
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_b"],
      "ENV": {},
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_b": {"ENV": {"NODE_ID": "full"}},
          "node_b": {"ENV": {"NODE_ID": "compact"}},
        },
      },
    }

    plugin._apply_per_node_config()

    self.assertEqual(plugin.config_data["ENV"], {"NODE_ID": "full"})

  def test_worker_runner_inherits_per_node_config_for_vcs_data(self):
    plugin = make_runner(WorkerAppRunnerPlugin, node_addr="0xai_node_b")
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "BRANCH": "main",
    }
    plugin.cfg_env = {}
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_a", "0xai_node_b"],
      "VCS_DATA": {
        "REPO_OWNER": "ratio1",
        "REPO_NAME": "demo",
        "BRANCH": "main",
      },
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_b": {
            "VCS_DATA": {"BRANCH": "develop"},
            "ENV": {"WORKER_NODE": "node-b"},
          },
        },
      },
    }

    applied = plugin._apply_per_node_config()

    self.assertTrue(applied)
    self.assertEqual(plugin.config_data["VCS_DATA"], {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "BRANCH": "develop",
    })
    self.assertEqual(plugin.cfg_vcs_data, {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "BRANCH": "develop",
    })
    self.assertEqual(plugin.config_data["ENV"], {"WORKER_NODE": "node-b"})
    self.assertEqual(plugin.cfg_env, {"WORKER_NODE": "node-b"})

  def test_per_node_config_rejects_system_overrides(self):
    plugin = make_runner()
    plugin.config_data = {
      "CHAINSTORE_PEERS": ["0xai_node_b"],
      "ENV": {},
      "PER_NODE_CONFIG": {
        "0xai_node_b": {"IMAGE": "postgres:latest"},
      },
    }

    with self.assertRaisesRegex(ValueError, "IMAGE"):
      plugin._apply_per_node_config()


if __name__ == "__main__":
  unittest.main()
