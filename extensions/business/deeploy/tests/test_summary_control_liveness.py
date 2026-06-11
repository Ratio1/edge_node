import copy
from datetime import datetime
import unittest

from extensions.business.deeploy.deeploy_const import (
  CONTAINER_APP_RUNNER_SIGNATURE,
  DEEPLOY_RESOURCES,
  JOB_APP_TYPES,
)
from extensions.business.deeploy.tests.support import make_inputs, make_plugin_entry
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.deeploy_target_nodes_mixin import _DeeployTargetNodesMixin


class _SummaryControlDeeployPlugin(_DeeployMixin, _DeeployTargetNodesMixin):
  pass


class _BcStub:
  @staticmethod
  def is_valid_eth_address(addr):
    return False

  @staticmethod
  def is_valid_internal_address(addr):
    return str(addr).startswith("0xai_")

  @staticmethod
  def eth_addr_to_internal_addr(addr):
    return addr

  @staticmethod
  def maybe_add_prefix(addr):
    return addr if str(addr).startswith("0xai_") else f"0xai_{addr}"


class _NetmonStub:
  def __init__(
    self,
    avail_cpu=None,
    avail_mem=None,
    avail_disk=None,
    total_cpu=None,
    total_mem=None,
    has_did=True,
    is_supervisor=False,
    online_for_control=None,
    supervisor_by_addr=None,
    status_by_addr=None,
  ):
    self.direct_calls = []
    self.control_calls = []
    self.avail_cpu = avail_cpu
    self.avail_mem = avail_mem
    self.avail_disk = avail_disk
    self.total_cpu = total_cpu
    self.total_mem = total_mem
    self.has_did = has_did
    self.is_supervisor = is_supervisor
    self.online_for_control = set(online_for_control or ["0xai_node_gamma"])
    self.supervisor_by_addr = dict(supervisor_by_addr or {})
    self.status_by_addr = dict(status_by_addr or {})

  def _value_for_addr(self, value, addr):
    if not isinstance(value, dict):
      return value

    keys = [addr]
    if isinstance(addr, str):
      if addr.startswith("0xai_"):
        keys.append(addr[5:])
      else:
        keys.append(f"0xai_{addr}")

    for key in keys:
      if key in value:
        return value[key]
    return None

  def network_node_is_supervisor(self, addr):
    return self.supervisor_by_addr.get(addr, self.is_supervisor)

  def network_nodes_status(self):
    return copy.deepcopy(self.status_by_addr)

  def network_node_is_online(self, addr):
    self.direct_calls.append(addr)
    return False

  def network_node_is_online_for_control(self, addr):
    self.control_calls.append(addr)
    return addr in self.online_for_control

  def network_node_get_cpu_avail_cores(self, addr):
    return self._value_for_addr(self.avail_cpu, addr)

  def network_node_available_memory(self, addr):
    return self._value_for_addr(self.avail_mem, addr)

  def network_node_available_disk(self, addr):
    return self._value_for_addr(self.avail_disk, addr)

  def network_node_total_cpu_cores(self, addr):
    return self._value_for_addr(self.total_cpu, addr)

  def network_node_total_mem(self, addr):
    return self._value_for_addr(self.total_mem, addr)

  def network_node_has_did(self, addr):
    return self.has_did

  def get_network_node_tags(self, addr):
    return []


def _plugin():
  plugin = _SummaryControlDeeployPlugin.__new__(_SummaryControlDeeployPlugin)
  plugin.cfg_deeploy_verbose = 0
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.deepcopy = copy.deepcopy
  plugin.bc = _BcStub()
  plugin.netmon = _NetmonStub()
  return plugin


class DeeploySummaryControlLivenessTests(unittest.TestCase):

  def test_target_node_validation_uses_control_liveness(self):
    plugin = _plugin()
    inputs = make_inputs(target_nodes=["0xai_node_gamma"])

    nodes = plugin._check_nodes_availability(inputs, skip_resource_check=True)

    self.assertEqual(nodes, ["0xai_node_gamma"])
    self.assertEqual(plugin.netmon.direct_calls, [])
    self.assertEqual(plugin.netmon.control_calls, ["0xai_node_gamma"])

  def test_string_true_supervisor_flag_rejects_target_node(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(is_supervisor="true")
    inputs = make_inputs(target_nodes=["0xai_node_gamma"])

    with self.assertRaisesRegex(ValueError, "supervisor node"):
      plugin._check_nodes_availability(inputs, skip_resource_check=True)

  def test_unknown_supervisor_flag_rejects_target_node(self):
    for value in (None, "", "maybe", object()):
      with self.subTest(value=type(value).__name__):
        plugin = _plugin()
        plugin.netmon = _NetmonStub(is_supervisor=value)
        inputs = make_inputs(target_nodes=["0xai_node_gamma"])

        with self.assertRaisesRegex(ValueError, "unknown supervisor state"):
          plugin._check_nodes_availability(inputs, skip_resource_check=True)

  def test_auto_selection_uses_summary_liveness_and_rejects_unknown_supervisors(self):
    plugin = _plugin()
    plugin.datetime = datetime
    plugin.json_dumps = lambda obj, **kwargs: str(obj)
    plugin._get_online_apps = lambda: {
      "0xai_node_alpha": {},
      "0xai_node_beta": {},
      "0xai_node_gamma": {},
    }
    plugin.netmon = _NetmonStub(
      total_cpu=8,
      total_mem=32,
      has_did=True,
      online_for_control={"0xai_node_alpha", "0xai_node_beta", "0xai_node_gamma"},
      supervisor_by_addr={
        "0xai_node_alpha": False,
        "0xai_node_beta": "",
        "0xai_node_gamma": True,
      },
      status_by_addr={
        "node_alpha": {"SCORE": 20},
        "node_beta": {"SCORE": 99},
        "node_gamma": {"SCORE": 100},
      },
    )
    inputs = make_inputs(
      target_nodes=None,
      target_nodes_count=1,
      plugin_signature=CONTAINER_APP_RUNNER_SIGNATURE,
      app_params={
        DEEPLOY_RESOURCES.CONTAINER_RESOURCES: {
          DEEPLOY_RESOURCES.CPU: 1,
          DEEPLOY_RESOURCES.MEMORY: "512m",
        },
      },
    )

    nodes = plugin._check_nodes_availability(inputs)

    self.assertEqual(nodes, ["node_alpha"])
    self.assertEqual(
      plugin.netmon.control_calls,
      ["0xai_node_alpha", "0xai_node_beta", "0xai_node_gamma"],
    )

  def test_missing_summary_resources_fail_closed_without_crashing(self):
    plugin = _plugin()
    inputs = make_inputs(
      target_nodes=["0xai_node_gamma"],
      plugin_signature=CONTAINER_APP_RUNNER_SIGNATURE,
      app_params={
        DEEPLOY_RESOURCES.CONTAINER_RESOURCES: {
          DEEPLOY_RESOURCES.CPU: 1,
          DEEPLOY_RESOURCES.MEMORY: "512m",
        },
      },
    )

    result = plugin.check_node_available_resources("0xai_node_gamma", inputs)

    self.assertFalse(result[DEEPLOY_RESOURCES.STATUS])
    self.assertEqual(
      [item[DEEPLOY_RESOURCES.RESOURCE] for item in result[DEEPLOY_RESOURCES.DETAILS]],
      [DEEPLOY_RESOURCES.CPU, DEEPLOY_RESOURCES.MEMORY],
    )

  def test_malformed_summary_resources_fail_closed_without_crashing(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(
      avail_cpu=float("inf"),
      avail_mem="not-a-memory-value",
      avail_disk=float("nan"),
    )
    inputs = make_inputs(
      target_nodes=["0xai_node_gamma"],
      plugin_signature=CONTAINER_APP_RUNNER_SIGNATURE,
      app_params={
        DEEPLOY_RESOURCES.CONTAINER_RESOURCES: {
          DEEPLOY_RESOURCES.CPU: 1,
          DEEPLOY_RESOURCES.MEMORY: "512m",
        },
      },
    )

    result = plugin.check_node_available_resources("0xai_node_gamma", inputs)

    self.assertFalse(result[DEEPLOY_RESOURCES.STATUS])
    self.assertEqual(
      [item[DEEPLOY_RESOURCES.RESOURCE] for item in result[DEEPLOY_RESOURCES.DETAILS]],
      [DEEPLOY_RESOURCES.CPU, DEEPLOY_RESOURCES.MEMORY],
    )

  def test_stack_target_node_disk_uses_selected_volume_storage(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(
      avail_cpu=2,
      avail_mem=4,
      avail_disk=4 * 1024 * 1024 * 1024,
    )
    inputs = make_inputs(
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          CONTAINER_APP_RUNNER_SIGNATURE,
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "4g"},
          FIXED_SIZE_VOLUMES={"data": {"SIZE": "1G", "MOUNTING_POINT": "/data"}},
        ),
      ],
    )

    result = plugin.check_node_available_resources("0xai_node_gamma", inputs)

    self.assertTrue(result[DEEPLOY_RESOURCES.STATUS])

  def test_stack_target_node_disk_rejects_selected_storage_over_available(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(
      avail_cpu=2,
      avail_mem=4,
      avail_disk=3 * 1024 * 1024 * 1024,
    )
    inputs = make_inputs(
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          CONTAINER_APP_RUNNER_SIGNATURE,
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "4g"},
        ),
      ],
    )

    result = plugin.check_node_available_resources("0xai_node_gamma", inputs)

    self.assertFalse(result[DEEPLOY_RESOURCES.STATUS])
    self.assertEqual(
      [item[DEEPLOY_RESOURCES.RESOURCE] for item in result[DEEPLOY_RESOURCES.DETAILS]],
      [DEEPLOY_RESOURCES.STORAGE],
    )

  def test_stack_auto_selection_disk_uses_selected_volume_storage(self):
    plugin = _plugin()
    plugin.datetime = datetime
    plugin.json_dumps = lambda obj, **kwargs: str(obj)
    plugin._get_online_apps = lambda: {
      "0xai_node_alpha": {},
      "0xai_node_beta": {},
    }
    plugin.netmon = _NetmonStub(
      total_cpu={"node_alpha": 8, "node_beta": 8},
      total_mem={"node_alpha": 32, "node_beta": 32},
      avail_disk={
        "node_alpha": 4 * 1024 * 1024 * 1024,
        "node_beta": 5 * 1024 * 1024 * 1024,
      },
      has_did=True,
      online_for_control={"0xai_node_alpha", "0xai_node_beta"},
      supervisor_by_addr={
        "0xai_node_alpha": False,
        "0xai_node_beta": False,
      },
      status_by_addr={
        "node_alpha": {"SCORE": 100},
        "node_beta": {"SCORE": 80},
      },
    )
    inputs = make_inputs(
      target_nodes_count=1,
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          CONTAINER_APP_RUNNER_SIGNATURE,
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "4g"},
          FIXED_SIZE_VOLUMES={"data": {"SIZE": "1G", "MOUNTING_POINT": "/data"}},
        ),
      ],
    )

    nodes = plugin._find_nodes_for_deeployment(inputs)

    self.assertEqual(nodes, ["node_alpha"])

  def test_stack_auto_selection_disk_rejects_selected_storage_over_available(self):
    plugin = _plugin()
    plugin.datetime = datetime
    plugin.json_dumps = lambda obj, **kwargs: str(obj)
    plugin._get_online_apps = lambda: {
      "0xai_node_alpha": {},
      "0xai_node_beta": {},
    }
    plugin.netmon = _NetmonStub(
      total_cpu={"node_alpha": 8, "node_beta": 8},
      total_mem={"node_alpha": 32, "node_beta": 32},
      avail_disk={
        "node_alpha": 3 * 1024 * 1024 * 1024,
        "node_beta": 5 * 1024 * 1024 * 1024,
      },
      has_did=True,
      online_for_control={"0xai_node_alpha", "0xai_node_beta"},
      supervisor_by_addr={
        "0xai_node_alpha": False,
        "0xai_node_beta": False,
      },
      status_by_addr={
        "node_alpha": {"SCORE": 100},
        "node_beta": {"SCORE": 80},
      },
    )
    inputs = make_inputs(
      target_nodes_count=1,
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          CONTAINER_APP_RUNNER_SIGNATURE,
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "4g"},
        ),
      ],
    )

    nodes = plugin._find_nodes_for_deeployment(inputs)

    self.assertEqual(nodes, ["node_beta"])

  def test_malformed_total_resources_fail_closed_without_crashing(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(total_cpu=float("nan"), total_mem="bad-memory")
    inputs = make_inputs(
      plugin_signature=CONTAINER_APP_RUNNER_SIGNATURE,
      node_res_req={
        DEEPLOY_RESOURCES.CPU: 1,
        DEEPLOY_RESOURCES.MEMORY: "1g",
      },
    )

    result = plugin._DeeployTargetNodesMixin__check_nodes_capabilities_and_extract_resources(
      ["0xai_node_gamma"],
      inputs,
    )

    self.assertEqual(result, {})

  def test_string_false_did_rejects_container_capability(self):
    plugin = _plugin()
    plugin.netmon = _NetmonStub(
      has_did="false",
      total_cpu=16,
      total_mem=64,
    )
    inputs = make_inputs(
      plugin_signature=CONTAINER_APP_RUNNER_SIGNATURE,
    )

    result = plugin._DeeployTargetNodesMixin__check_nodes_capabilities_and_extract_resources(
      ["0xai_node_gamma"],
      inputs,
    )

    self.assertEqual(result, {})


if __name__ == "__main__":
  unittest.main()
