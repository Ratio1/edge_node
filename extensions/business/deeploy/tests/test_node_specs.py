import unittest
from types import SimpleNamespace

from extensions.business.deeploy.tests.support import make_deeploy_plugin


class _NetmonStub:

  def __init__(self):
    self.nodes = {
      "0xai_node_alpha": {
        "alias": "alpha",
        "online": True,
        "cpu_total": 8,
        "cpu_avail": 6.5,
        "mem_total": 32,
        "mem_avail": 24.25,
        "disk_total": 512,
        "disk_avail": 420.5,
      },
      "0xai_node_beta": {
        "alias": "beta",
        "online": False,
        "cpu_total": 4,
        "cpu_avail": 1,
        "mem_total": 16,
        "mem_avail": 8,
        "disk_total": 256,
        "disk_avail": 120,
      },
    }

  def _get(self, addr, key):
    if addr not in self.nodes:
      raise ValueError(f"unknown node {addr}")
    return self.nodes[addr][key]

  def network_node_eeid(self, addr):
    return self._get(addr, "alias")

  def network_node_is_online(self, addr):
    return self._get(addr, "online")

  def network_node_total_cpu_cores(self, addr):
    return self._get(addr, "cpu_total")

  def network_node_avail_cpu_cores(self, addr):
    return self._get(addr, "cpu_avail")

  def network_node_total_mem(self, addr):
    return self._get(addr, "mem_total")

  def network_node_avail_mem(self, addr):
    return self._get(addr, "mem_avail")

  def network_node_total_disk(self, addr):
    return self._get(addr, "disk_total")

  def network_node_avail_disk(self, addr):
    return self._get(addr, "disk_avail")


class DeeployNodeSpecsTests(unittest.TestCase):

  def test_builds_node_specs_for_unique_requested_nodes(self):
    plugin = make_deeploy_plugin()
    plugin.netmon = _NetmonStub()
    plugin.bc = SimpleNamespace(
      maybe_add_prefix=lambda addr: addr if str(addr).startswith("0xai_") else f"0xai_{addr}"
    )

    specs = plugin._get_node_specs(["node_alpha", "0xai_node_beta", "node_alpha"])

    self.assertEqual(list(specs.keys()), ["0xai_node_alpha", "0xai_node_beta"])
    self.assertEqual(
      specs["0xai_node_alpha"],
      {
        "node_alias": "alpha",
        "node_is_online": True,
        "cpu": {"total": 8, "available": 6.5},
        "memory": {"total": 32, "available": 24.25},
        "disk": {"total": 512, "available": 420.5},
      },
    )
    self.assertEqual(specs["0xai_node_beta"]["node_is_online"], False)

  def test_returns_per_node_error_without_failing_entire_specs_request(self):
    plugin = make_deeploy_plugin()
    plugin.netmon = _NetmonStub()
    plugin.bc = SimpleNamespace(
      maybe_add_prefix=lambda addr: addr if str(addr).startswith("0xai_") else f"0xai_{addr}"
    )

    specs = plugin._get_node_specs(["node_missing", "node_alpha"])

    self.assertIn("unknown node 0xai_node_missing", specs["0xai_node_missing"]["error"])
    self.assertEqual(specs["0xai_node_alpha"]["node_alias"], "alpha")

  def test_node_specs_numbers_are_json_safe(self):
    plugin = make_deeploy_plugin()

    self.assertEqual(plugin._node_specs_number("6.25"), 6.25)
    self.assertIsNone(plugin._node_specs_number(float("inf")))
    self.assertIsNone(plugin._node_specs_number(-1))


if __name__ == "__main__":
  unittest.main()
