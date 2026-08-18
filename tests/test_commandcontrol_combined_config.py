import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestCombinedCommandControlConfig(unittest.TestCase):

  def _load(self, relative_path):
    return json.loads((REPO_ROOT / relative_path).read_text())

  def _assert_regrouped(self, config):
    instances = config["COMMUNICATION"]["INSTANCES"]
    self.assertEqual(instances["COMMANDCONTROL"]["RECV_FROM"], "CONFIG_CHANNEL")
    self.assertEqual(instances["COMMANDCONTROL"]["SEND_TO"], "CONFIG_CHANNEL")
    self.assertEqual(instances["HEARTBEATS"]["RECV_FROM"], "CTRL_CHANNEL")
    self.assertEqual(instances["HEARTBEATS"]["SEND_TO"], "CTRL_CHANNEL")

  def _assert_combined_params(self, config, mirror_enabled):
    params = config["COMMUNICATION"]["PARAMS"]
    self.assertTrue(params["HEARTBEAT_INGRESS_WORKER_ENABLED"])
    self.assertEqual(params["HEARTBEAT_INGRESS_QUEUE_SIZE"], 10000)
    self.assertEqual(params["HEARTBEAT_AUTH_WORKERS"], 4)
    self.assertEqual(params["HEARTBEAT_AUTH_MAX_IN_FLIGHT"], 32)
    self.assertEqual(params["HEARTBEAT_AUTH_MODE"], "shadow")
    self.assertIn("{}", params["CTRL_CHANNEL"]["TARGETED_TOPIC"])
    self.assertFalse(params["CTRL_CHANNEL"]["SUBSCRIBE_TARGETED"])
    self.assertEqual(
      params["HEARTBEAT_TARGETED_MIRROR_ENABLED"],
      mirror_enabled,
    )

  def test_comms_testbed_is_regrouped_with_opt_in_targeted_mirror(self):
    config = self._load(".config_app_comms.json")
    self._assert_regrouped(config)
    self._assert_combined_params(config, mirror_enabled=True)

  def test_tracked_runtime_defaults_are_regrouped_but_mirror_off(self):
    for relative_path in (
      ".config_app.json",
      ".config_app_cluster.json",
      "docker-compose/deeploy-testbed/config_app_deeploy_testbed.json",
    ):
      with self.subTest(relative_path=relative_path):
        config = self._load(relative_path)
        self._assert_regrouped(config)
        self._assert_combined_params(config, mirror_enabled=False)

  def test_legacy_fixture_preserves_crossed_roles_for_config_rollback(self):
    fixture = self._load("tests/fixtures/config_app_comms_legacy.json")
    instances = fixture["COMMUNICATION"]["INSTANCES"]
    self.assertEqual(instances["COMMANDCONTROL"]["RECV_FROM"], "CTRL_CHANNEL")
    self.assertEqual(instances["HEARTBEATS"]["RECV_FROM"], "CONFIG_CHANNEL")
    self._assert_combined_params(fixture, mirror_enabled=False)

  def test_rollout_docs_name_seed_and_persisted_config_boundaries(self):
    ingress = (REPO_ROOT / "docs" / "heartbeat-ingress-rollout.md").read_text()
    observation = (
      REPO_ROOT / "docs" / "heartbeat-observation-rollout.md"
    ).read_text()

    for text in (ingress, observation):
      self.assertIn("config_app.txt", text)
      self.assertIn(".config_app_comms.json", text)
      self.assertIn("rollback", text.lower())

  def test_live_testbed_enables_mirror_and_has_broker_fanout_probe(self):
    compose = (REPO_ROOT / "docker-compose_comms.yaml").read_text()
    probe = (REPO_ROOT / "tests" / "validate_sdk_heartbeat_fanout.py").read_text()

    self.assertIn('EE_HEARTBEAT_TARGETED_MIRROR_ENABLED: "1"', compose)
    self.assertIn("/api/v5/subscriptions", probe)
    self.assertIn("send_msg", probe)
    self.assertIn("send_oct", probe)
    self.assertIn("post_delivery_filter", probe)
    self.assertIn("heartbeat_observation_mode", probe)


if __name__ == "__main__":
  unittest.main()
