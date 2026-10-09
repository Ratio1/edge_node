"""RM-127: each node publishes its own public IP to `<instance_id>:node_info`, and the deployment
node registry reads it back."""
import unittest
from datetime import datetime, timezone

from extensions.business.cybersec.red_mesh.tenancy.deployment_nodes import published_ip

PUBLIC = "34.62.240.212"


class TestNodeInfoPublish(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_instance_id = "jobs"
    self.plugin.ee_addr = "0xai_rm3"
    self.plugin.global_shmem = {"location_data": {"ip": PUBLIC}}
    self.now = 1000.0
    self.plugin.time = lambda: self.now
    self.logged = []
    self.plugin.P = lambda message, **kwargs: self.logged.append(message)
    self.writes = []
    self.fail = False

    def hset(hkey, key, value, **kwargs):
      if self.fail:
        raise RuntimeError("cstore down")
      self.writes.append((hkey, key, value, kwargs))
      return self.confirmed
    self.confirmed = True
    self.plugin.chainstore_hset = hset

  def tick(self, seconds=0):
    self.now += seconds
    self.plugin._maybe_publish_node_ip()

  def test_publishes_on_the_first_tick_then_hourly_and_on_a_change(self):
    self.tick()
    (hkey, key, value, kwargs), = self.writes
    self.assertEqual((hkey, key, value["ip"]), ("jobs:node_info", "0xai_rm3", PUBLIC))
    self.assertEqual(published_ip(value, datetime.now(timezone.utc)), PUBLIC)
    # A single short attempt: the publish runs inside `process()`.
    self.assertEqual(kwargs, {"timeout": 2, "max_retries": 0})
    self.tick(60)
    self.tick(1800)
    self.assertEqual(len(self.writes), 1)
    self.tick(1800)
    self.assertEqual(len(self.writes), 2)
    self.plugin.global_shmem["location_data"]["ip"] = "34.62.240.213"
    self.tick(60)
    self.assertEqual([write[2]["ip"] for write in self.writes], [PUBLIC, PUBLIC, "34.62.240.213"])

  def test_a_local_or_missing_ip_publishes_nothing(self):
    for location_data in ({"ip": "172.17.0.2"}, {"ip": "10.132.0.2"}, {"ip": "127.0.0.1"}, {"ip": None}, {},
                          None, "34.62.240.212"):
      with self.subTest(location_data=location_data):
        self.plugin.global_shmem = {"location_data": location_data}
        self.tick(3600)
    self.plugin.global_shmem = {}
    self.tick(3600)
    self.assertEqual(self.writes, [])

  def test_a_failed_publish_is_logged_and_retried_later(self):
    self.fail = True
    self.tick()
    self.assertEqual(len(self.logged), 1)
    self.fail = False
    self.tick(30)
    self.assertEqual(self.writes, [])
    self.tick(30)
    self.assertEqual(len(self.writes), 1)

  def test_an_unconfirmed_write_is_retried_after_the_short_delay(self):
    self.confirmed = False
    self.tick()
    self.assertEqual((len(self.writes), len(self.logged)), (1, 1))
    self.confirmed = True
    self.tick(30)
    self.assertEqual(len(self.writes), 1)
    self.tick(30)
    self.assertEqual(len(self.writes), 2)
    self.tick(60)
    self.assertEqual(len(self.writes), 2)

  def test_the_registry_reads_the_hash_and_keeps_the_names_when_it_cannot(self):
    self.plugin.chainstore_hgetall = lambda hkey: {"0xai_rm3": {"ip": PUBLIC, "published_at":
                                                                datetime.now(timezone.utc).isoformat()}}
    self.assertEqual(self.plugin._read_node_info()["0xai_rm3"]["ip"], PUBLIC)

    def explode(hkey):
      raise RuntimeError("cstore down")
    self.plugin.chainstore_hgetall = explode
    self.assertIsNone(self.plugin._read_node_info())
