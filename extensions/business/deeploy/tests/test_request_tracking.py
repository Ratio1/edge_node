"""Every oracle must know which one holds an unanswered deployment request; a read must cost nothing."""
import unittest
from datetime import datetime, timezone

from extensions.business.dauth.dauth_manager import _CONFIG as DAUTH_CONFIG
from extensions.business.deeploy.deeploy_manager_api import _CONFIG as DEEPLOY_CONFIG
from extensions.business.mixins.request_tracking_mixin import _RequestTrackingMixin


class _Api(_RequestTrackingMixin):
  """The mixin on the smallest host that has what it uses, with a clock the test moves."""
  datetime = datetime
  timezone = timezone
  ee_id = "oracle-1"

  def __init__(self, config):
    self.cfg_requests_cstore_hkey = config["REQUESTS_CSTORE_HKEY"]
    self.cfg_requests_tracked_endpoints = config["REQUESTS_TRACKED_ENDPOINTS"]
    self.cfg_requests_save_interval = config["REQUESTS_SAVE_INTERVAL"]
    self.cfg_requests_max_records = config["REQUESTS_MAX_RECORDS"]
    self.cfg_requests_log_interval = config["REQUESTS_LOG_INTERVAL"]
    self.now = 1_000_000.0
    self.writes = []
    self._init_request_tracking()

  def time(self):
    return self.now

  def P(self, *args, **kwargs):
    return

  def json_dumps(self, value, **kwargs):
    return str(value)

  def chainstore_hset(self, hkey, key, value, **kwargs):
    # what the other oracles would now hold: (request id, answered or not) per record
    self.writes.append([(record["id"], record["date_complete"] is not None) for record in value])
    return True

  def chainstore_hgetall(self, hkey):
    return {}

  def receive(self, request_id, endpoint):
    self._track_request({"id": request_id, "value": [endpoint, {}]})
    self._maybe_log_and_save_tracked_requests()

  def answer(self, request_id, endpoint):
    self._track_response(endpoint, {"id": request_id})
    self._maybe_log_and_save_tracked_requests()

  def lap(self, seconds=0):
    self.now += seconds
    self._maybe_log_and_save_tracked_requests()


class RequestTrackingTests(unittest.TestCase):

  def test_the_deeploy_api_records_the_requests_that_start_something_and_no_read(self):
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_CSTORE_HKEY"], "DEEPLOY_REQUESTS")
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_TRACKED_ENDPOINTS"],
                     ["create_pipeline", "update_pipeline", "scale_up_job_workers", "delete_pipeline"])
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_SAVE_INTERVAL"], 30)
    self.assertEqual(DAUTH_CONFIG["REQUESTS_TRACKED_ENDPOINTS"], [])

  def test_a_status_poll_every_two_seconds_writes_nothing(self):
    # One client polled get_deployment_status about 25 times a minute for hours. Each poll was a
    # chain-store write that every oracle stored, confirmed and saved its whole replica for.
    api = _Api(DEEPLOY_CONFIG)
    for index in range(300):
      api.receive("poll-%d" % index, "get_deployment_status")
      api.answer("poll-%d" % index, "get_deployment_status")
      api.lap(2)
    for endpoint in ("get_apps", "node_specs", "get_preferred_nodes", "get_r1fs_job_pipeline", "reveal_job_secrets"):
      api.receive("read", endpoint)
      api.answer("read", endpoint)
    self.assertEqual(api.writes, [])

  def test_a_deployment_request_is_known_at_once_and_its_answer_one_interval_later(self):
    api = _Api(DEEPLOY_CONFIG)
    api.receive("create-1", "create_pipeline")
    self.assertEqual(api.writes, [[("create-1", False)]])  # every oracle knows who holds it, unanswered
    api.lap(2)
    api.answer("create-1", "create_pipeline")
    api.lap(27)
    self.assertEqual(len(api.writes), 1)  # the answer waits for the end of the 30 s interval
    api.lap(1)
    self.assertEqual(api.writes[1:], [[("create-1", True)]])
    api.lap(600)
    self.assertEqual(len(api.writes), 2)  # nothing changed: nothing written

  def test_a_burst_of_requests_is_one_write_now_and_one_after_the_interval(self):
    # The request is recorded before it is authenticated: a caller must not be able to buy one
    # replicated write per call.
    api = _Api(DEEPLOY_CONFIG)
    for index in range(100):
      api.receive("burst-%d" % index, "create_pipeline")
      api.answer("burst-%d" % index, "create_pipeline")
      api.lap(0.2)
    self.assertEqual(len(api.writes), 1)
    api.lap(30)
    self.assertEqual(len(api.writes), 2)

  def test_a_request_that_was_never_answered_is_not_pushed_out_by_later_ones(self):
    api = _Api(DEEPLOY_CONFIG)  # the record holds two requests
    api.receive("hung", "update_pipeline")
    for index in range(5):
      api.lap(60)
      api.receive("later-%d" % index, "create_pipeline")
      api.answer("later-%d" % index, "create_pipeline")
    api.lap(60)
    self.assertEqual(api.writes[-1], [("hung", False), ("later-4", True)])

  def test_when_no_request_was_answered_the_oldest_one_leaves(self):
    api = _Api(DEEPLOY_CONFIG)
    for name in ("first", "second", "third"):
      api.receive(name, "delete_pipeline")
      api.lap(60)
    self.assertEqual(api.writes[-1], [("second", False), ("third", False)])

  def test_dauth_records_nothing(self):
    api = _Api(DAUTH_CONFIG)
    for index in range(50):
      api.receive("auth-%d" % index, "get_auth_data")
      api.answer("auth-%d" % index, "get_auth_data")
      api.lap(1)
    self.assertEqual(api.writes, [])


if __name__ == "__main__":
  unittest.main()
