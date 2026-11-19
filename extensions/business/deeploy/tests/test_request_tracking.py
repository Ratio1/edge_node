"""Every oracle must see the state-changing requests the others received; a read must cost nothing."""
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
    # Something the monitor thread does while the next write waits for the other oracles.
    self.during_write = None
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
    # The monitor thread keeps recording requests while the write waits for confirmations.
    during_write, self.during_write = self.during_write, None
    if during_write:
      during_write()
    return True

  def chainstore_hgetall(self, hkey):
    return {}

  def receive(self, request_id, endpoint):
    # The request monitor thread records the request as it queues it; nothing is written here.
    self._track_request({"id": request_id, "value": [endpoint, {}]})

  def answer(self, request_id, endpoint):
    # The plugin lap runs the endpoint and stamps the answer, before its process() call.
    self._track_response(endpoint, {"id": request_id})

  def lap(self, seconds=0):
    # The end of a plugin lap: process() writes the record when it is due.
    self.now += seconds
    self._maybe_log_and_save_tracked_requests()


class RequestTrackingTests(unittest.TestCase):

  def test_the_deeploy_api_records_the_requests_that_change_state_and_no_read(self):
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_CSTORE_HKEY"], "DEEPLOY_REQUESTS")
    # The commands to running apps, the CSP escrow reconciliation and the preferred-node save change
    # state too, and were recorded before the record was limited to a list.
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_TRACKED_ENDPOINTS"],
                     ["create_pipeline", "update_pipeline", "scale_up_job_workers", "delete_pipeline",
                      "send_instance_command", "send_app_command", "reconcile_csp_escrow_jobs",
                      "save_preferred_nodes"])
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
      api.lap(2)
    self.assertEqual(api.writes, [])

  def test_a_request_answered_in_its_lap_is_first_written_answered(self):
    # The lap runs the queued requests first and calls process() afterwards, so the first write of a
    # request answered in that lap already holds its answer. A request whose endpoint hangs holds the
    # plugin thread, so nothing is written while it hangs.
    api = _Api(DEEPLOY_CONFIG)
    api.receive("create-1", "create_pipeline")
    api.answer("create-1", "create_pipeline")
    api.lap()
    self.assertEqual(api.writes, [[("create-1", True)]])

  def test_a_request_still_queued_when_a_lap_ends_is_written_unanswered_and_its_answer_one_interval_later(self):
    # A request that still waits in the queue when a lap ends is published as not answered, for
    # example when the lap ran out of time on an earlier request.
    api = _Api(DEEPLOY_CONFIG)
    api.receive("create-1", "create_pipeline")
    api.lap()
    self.assertEqual(api.writes, [[("create-1", False)]])
    api.lap(2)
    api.answer("create-1", "create_pipeline")
    api.lap(27)
    self.assertEqual(len(api.writes), 1)  # the answer waits for the end of the 30 s interval
    api.lap(1)
    self.assertEqual(api.writes[1:], [[("create-1", True)]])
    api.lap(600)
    self.assertEqual(len(api.writes), 2)  # nothing changed: nothing written

  def test_a_request_recorded_during_a_write_is_written_by_the_next_one(self):
    # The write waits for the other oracles while the monitor thread keeps recording. The changed flag is
    # cleared before the record is copied, so that request sets it again and is not forgotten.
    api = _Api(DEEPLOY_CONFIG)
    api.receive("create-1", "create_pipeline")
    api.during_write = lambda: api.receive("create-2", "create_pipeline")
    api.lap()
    self.assertEqual(api.writes, [[("create-1", False)]])
    api.lap(30)
    self.assertEqual(api.writes[1:], [[("create-1", False), ("create-2", False)]])

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

  def test_when_the_record_is_full_the_oldest_request_leaves_answered_or_not(self):
    # First in, first out. A request refused with a 503 before it ran is never stamped; a rule that kept
    # unanswered requests first kept such a refusal in the record while any answered request was there
    # to leave in its place.
    api = _Api(DEEPLOY_CONFIG)  # the record holds two requests
    api.receive("refused", "update_pipeline")
    for index in range(2):
      api.lap(60)
      api.receive("later-%d" % index, "create_pipeline")
      api.answer("later-%d" % index, "create_pipeline")
    api.lap(60)
    self.assertEqual(api.writes[-1], [("later-0", True), ("later-1", True)])

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
