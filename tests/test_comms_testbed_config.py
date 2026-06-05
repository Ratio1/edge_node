import json
import importlib.util
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestCommunicationComposeTestbed(unittest.TestCase):

  def test_compose_uses_local_broker_and_no_cluster_env_file(self):
    compose_text = (REPO_ROOT / "docker-compose_comms.yaml").read_text()

    self.assertIn("emqx:", compose_text)
    self.assertIn("r1_comms_emqx", compose_text)
    self.assertIn("r1_comms_local", compose_text)
    self.assertIn("127.0.0.1:18883:1883", compose_text)
    self.assertIn("127.0.0.1:18083:18083", compose_text)
    self.assertIn("http://127.0.0.1:18083/status", compose_text)
    self.assertIn("INSTALL_LOCAL_REQUIREMENTS", compose_text)
    self.assertIn("EE_ETH_ENABLED: \"false\"", compose_text)
    self.assertIn("EE_DAUTH_URL: N/A", compose_text)
    self.assertIn("known EVM selector", compose_text)
    self.assertNotIn("env_file:", compose_text)
    self.assertNotIn(".env_cluster", compose_text)
    self.assertNotIn("naeural_test", compose_text)
    self.assertNotIn("naeural/ctrl", compose_text)
    self.assertIn("starts an inner Docker daemon", compose_text)
    self.assertIn("privileged: true", compose_text)
    self.assertNotIn("EE_EVM_NET: testnet", compose_text)
    self.assertNotIn("EE_EVM_NET: mainnet", compose_text)

  def test_compose_has_supervisors_and_normal_nodes(self):
    compose_text = (REPO_ROOT / "docker-compose_comms.yaml").read_text()

    self.assertEqual(compose_text.count("EE_SUPERVISOR: \"true\""), 2)
    self.assertEqual(compose_text.count("EE_SUPERVISOR: \"false\""), 2)
    self.assertIn("EE_NETMON_ORACLE_ONLY_HEARTBEAT_RECEIVE: \"1\"", compose_text)
    self.assertIn("EE_ENABLE_NETMON_API_PROBE: \"1\"", compose_text)
    self.assertIn("EE_NETMON_ACCEPT_LOCAL_SUPERVISOR_SUMMARY: \"1\"", compose_text)
    self.assertEqual(compose_text.count("EE_NETMON_USE_SUMMARY_STATUS: \"1\""), 2)

  def test_app_config_has_isolated_topics_and_channel_qos(self):
    config = json.loads((REPO_ROOT / ".config_app_comms.json").read_text())
    instances = config["COMMUNICATION"]["INSTANCES"]
    params = config["COMMUNICATION"]["PARAMS"]

    self.assertEqual(instances["COMMANDCONTROL"]["RECV_FROM"], "CTRL_CHANNEL")
    self.assertEqual(instances["COMMANDCONTROL"]["SEND_TO"], "CONFIG_CHANNEL")
    self.assertEqual(instances["HEARTBEATS"]["RECV_FROM"], "CONFIG_CHANNEL")
    self.assertEqual(instances["HEARTBEATS"]["SEND_TO"], "CTRL_CHANNEL")
    self.assertEqual(params["HOST"], "emqx")
    self.assertEqual(params["PORT"], 1883)
    self.assertEqual(params["SECURED"], 0)
    self.assertEqual(params["CTRL_CHANNEL"]["TOPIC"], "naeural_comms_local/ctrl")
    self.assertEqual(params["CTRL_CHANNEL"]["QOS"], 1)
    self.assertEqual(params["CONFIG_CHANNEL"]["TOPIC"], "naeural_comms_local/{}/config")
    self.assertEqual(params["CONFIG_CHANNEL"]["QOS"], 2)
    self.assertEqual(params["PAYLOADS_CHANNEL"]["QOS"], 0)
    self.assertEqual(params["NOTIF_CHANNEL"]["QOS"], 0)

  def test_default_app_config_enables_segregated_heartbeat_and_command_qos(self):
    config = json.loads((REPO_ROOT / ".config_app.json").read_text())
    params = config["COMMUNICATION"]["PARAMS"]

    self.assertEqual(params["CTRL_CHANNEL"]["TOPIC"], "naeural/ctrl")
    self.assertEqual(params["CTRL_CHANNEL"]["QOS"], 1)
    self.assertEqual(params["CONFIG_CHANNEL"]["TOPIC"], "naeural/{}/config")
    self.assertEqual(params["CONFIG_CHANNEL"]["QOS"], 2)
    self.assertEqual(params["QOS"], 2)

  def test_startup_config_keeps_required_admin_pipeline_only(self):
    config = json.loads((REPO_ROOT / ".config_startup_comms.json").read_text())
    admin_pipeline = config["ADMIN_PIPELINE"]

    self.assertEqual(config["EE_ID"], "E2dkr")
    self.assertIn("NET_CONFIG_MONITOR", admin_pipeline)
    self.assertIn("NET_MON_01", admin_pipeline)
    self.assertIn("NETMON_API_PROBE", admin_pipeline)
    self.assertTrue(admin_pipeline["NET_MON_01"]["SAVE_STATUS_SNAPSHOT"])
    self.assertEqual(admin_pipeline["NET_MON_01"]["STATUS_SNAPSHOT_FILE"], "netmon_status.json")
    self.assertEqual(admin_pipeline["NETMON_API_PROBE"]["PORT"], 3000)
    self.assertFalse(admin_pipeline["NETMON_API_PROBE"]["TUNNEL_ENGINE_ENABLED"])
    self.assertNotIn("UPDATE_MONITOR_01", admin_pipeline)
    self.assertNotIn("ORACLE_SYNC_01", admin_pipeline)

  def test_oracle_sync_overlay_is_opt_in_and_epoch_coherent(self):
    compose_text = (REPO_ROOT / "docker-compose_comms_oracle_sync.yaml").read_text()

    self.assertIn("Optional OracleSync overlay", compose_text)
    self.assertIn("EE_COMMS_ORACLE_SYNC_GENESIS", compose_text)
    self.assertIn("EE_GENESIS_EPOCH_DATE", compose_text)
    self.assertIn("EE_EPOCH_INTERVALS", compose_text)
    self.assertIn("EE_EPOCH_INTERVAL_SECONDS", compose_text)
    self.assertEqual(compose_text.count("EE_ENABLE_LOCAL_ORACLE_SYNC"), 1)
    self.assertEqual(compose_text.count("EE_ORACLE_SYNC_DEBUG_MODE"), 1)
    self.assertEqual(compose_text.count("EE_ORACLE_SYNC_BOOTSTRAP_PREVIOUS_EPOCH"), 1)
    self.assertIn("ratio1_comm_oracle_01", compose_text)
    self.assertIn("ratio1_comm_oracle_02", compose_text)
    self.assertIn("ratio1_comm_node_01", compose_text)
    self.assertIn("ratio1_comm_node_02", compose_text)

  def test_local_entrypoint_has_oracle_sync_opt_in_only(self):
    comms_entrypoint = (REPO_ROOT / "cmds" / "device_comms.py").read_text()
    oracle_constants = (
      REPO_ROOT / "extensions" / "business" / "oracle_sync" /
      "sync_mixins" / "ora_sync_constants.py"
    ).read_text()
    oracle_plugin = (
      REPO_ROOT / "extensions" / "business" / "oracle_sync" / "oracle_sync_01.py"
    ).read_text()

    self.assertIn("EE_ENABLE_LOCAL_ORACLE_SYNC", comms_entrypoint)
    self.assertIn("\"ORACLE_SYNC_01\"", comms_entrypoint)
    self.assertIn("\"USE_R1FS\": False", comms_entrypoint)
    self.assertIn("set(_COMMS_ADMIN_PIPELINE)", comms_entrypoint)
    self.assertIn("EE_ORACLE_SYNC_DEBUG_MODE", oracle_constants)
    self.assertIn("derive", oracle_constants)
    self.assertIn("EE_ORACLE_SYNC_BOOTSTRAP_PREVIOUS_EPOCH", oracle_plugin)
    self.assertIn("DEBUG_MODE and", oracle_plugin)
    self.assertIn("fake history", oracle_plugin)
    self.assertIn("run only once", oracle_plugin)

  def test_localdeps_image_build_files_are_present(self):
    self.assertTrue((REPO_ROOT / "Dockerfile_devnet_local").is_file())
    self.assertTrue((REPO_ROOT / "Dockerfile_devnet_local.dockerignore").is_file())
    self.assertTrue((REPO_ROOT / "requirements_local.txt").is_file())
    dockerfile = (REPO_ROOT / "Dockerfile_devnet_local").read_text()
    self.assertIn("ARG INSTALL_KUBO=1", dockerfile)
    self.assertIn("ARG INSTALL_CLOUDFLARED=1", dockerfile)
    self.assertIn("ARG INSTALL_LOCAL_REQUIREMENTS=1", dockerfile)
    self.assertIn("ENV EE_EVM_NET=devnet", dockerfile)
    self.assertIn("ENV EE_CONFIG=.config_startup_comms.json", dockerfile)
    self.assertIn("ENV EE_ETH_ENABLED=false", dockerfile)
    self.assertIn("ENV EE_DAUTH_URL=N/A", dockerfile)
    self.assertIn("ENV EE_ENABLE_NETMON_API_PROBE=1", dockerfile)
    self.assertIn("CMD [\"python3\", \"/usr/local/bin/device_comms.py\"]", dockerfile)

  def test_runtime_images_enable_oracle_only_heartbeat_receive_by_default(self):
    for dockerfile_name in [
      "Dockerfile_devnet",
      "Dockerfile_testnet",
      "Dockerfile_mainnet",
      "Dockerfile_devnet_local",
    ]:
      with self.subTest(dockerfile_name=dockerfile_name):
        dockerfile = (REPO_ROOT / dockerfile_name).read_text()
        self.assertIn("ENV EE_NETMON_ORACLE_ONLY_HEARTBEAT_RECEIVE=1", dockerfile)

  def test_read_only_netmon_status_dump_command_is_present(self):
    command_path = REPO_ROOT / "cmds" / "dump_netmon_status"

    self.assertTrue(command_path.is_file())
    self.assertIn("netmon_status.json", command_path.read_text())

  def test_local_only_netmon_fastapi_probe_is_present(self):
    plugin_path = REPO_ROOT / "plugins" / "business" / "netmon_api_probe.py"

    self.assertTrue(plugin_path.is_file())
    plugin_text = plugin_path.read_text()
    self.assertIn("class NetmonApiProbePlugin", plugin_text)
    self.assertIn("local ECOMMS testbed only", plugin_text)
    self.assertIn("EE_ENABLE_NETMON_API_PROBE", plugin_text)
    self.assertIn("probe_nodes", plugin_text)
    self.assertIn("probe_node", plugin_text)

  def test_live_validation_scripts_are_present(self):
    broker_probe = REPO_ROOT / "tests" / "validate_comms_broker_state.py"
    netmon_probe = REPO_ROOT / "tests" / "validate_comms_netmon_snapshots.py"
    netmon_matrix = REPO_ROOT / "tests" / "validate_comms_netmon_command_matrix.py"
    netmon_fastapi = REPO_ROOT / "tests" / "validate_comms_netmon_fastapi_api.py"
    oracle_sync_probe = REPO_ROOT / "tests" / "validate_comms_oracle_sync_state.py"

    self.assertTrue(broker_probe.is_file())
    self.assertIn("/api/v5/subscriptions", broker_probe.read_text())
    self.assertIn("mqueue_len", broker_probe.read_text())
    self.assertTrue(netmon_probe.is_file())
    self.assertIn("dump_netmon_status", netmon_probe.read_text())
    self.assertIn("netmon_data_source", netmon_probe.read_text())
    self.assertTrue(netmon_matrix.is_file())
    self.assertIn("SESSION_ID", netmon_matrix.read_text())
    self.assertIn("_restore_whitelists", netmon_matrix.read_text())
    self.assertTrue(netmon_fastapi.is_file())
    self.assertIn("probe_node", netmon_fastapi.read_text())
    self.assertIn("summary-only peer", netmon_fastapi.read_text())
    self.assertIn("wrong observer eeid", netmon_fastapi.read_text())
    self.assertIn("direct-heartbeat accessible", netmon_fastapi.read_text())
    self.assertTrue(oracle_sync_probe.is_file())
    self.assertIn("ORACLE_CONTAINERS", oracle_sync_probe.read_text())
    self.assertIn("LAST_SYNC_EPOCH", oracle_sync_probe.read_text())
    self.assertIn("--require-synced", oracle_sync_probe.read_text())

  def test_broker_probe_fails_closed_when_emqx_metric_keys_are_missing(self):
    broker_probe = REPO_ROOT / "tests" / "validate_comms_broker_state.py"
    spec = importlib.util.spec_from_file_location("_ecomms_broker_probe", broker_probe)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    self.assertEqual(module._metric({"clientid": "node", "mqueue_len": "3"}, "mqueue_len"), 3)
    with self.assertRaises(KeyError):
      module._metric({"clientid": "node"}, "mqueue_len", "message_queue_len")

  def test_broker_probe_requires_expected_managed_clients(self):
    broker_probe = REPO_ROOT / "tests" / "validate_comms_broker_state.py"
    spec = importlib.util.spec_from_file_location("_ecomms_broker_probe", broker_probe)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    failures = []

    module._assert_managed_clients_present([], failures)

    self.assertTrue(any("expected 5 managed clients" in failure for failure in failures))

  def test_broker_probe_requires_exact_managed_subscriptions(self):
    broker_probe = REPO_ROOT / "tests" / "validate_comms_broker_state.py"
    spec = importlib.util.spec_from_file_location("_ecomms_broker_probe", broker_probe)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    clients = []
    for alias in module.EXPECTED_NODES:
      for marker in module.EXPECTED_CLIENT_MARKERS:
        clients.append({
          "clientid": f"{alias}_{marker}_test",
          "mqueue_len": 0,
          "inflight_cnt": 0,
        })

    failures, _ = module._validate_state([], clients)

    self.assertTrue(any("expected exactly 14 managed subscriptions" in failure for failure in failures))

  def test_local_comms_entrypoint_skips_optional_additional_packages(self):
    device_text = (REPO_ROOT / "device.py").read_text()
    comms_entrypoint = (REPO_ROOT / "cmds" / "device_comms.py").read_text()

    self.assertIn("llama-cpp-python", device_text)
    self.assertNotIn("EE_SKIP_ADDITIONAL_PACKAGES", device_text)
    self.assertIn("main(additional_packages=[])", comms_entrypoint)
    self.assertIn("local LLM serving", comms_entrypoint)
    self.assertIn("ct.ADMIN_PIPELINE = _COMMS_ADMIN_PIPELINE", comms_entrypoint)
    self.assertIn("OracleSync", comms_entrypoint)


if __name__ == "__main__":
  unittest.main()
