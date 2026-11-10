"""Legacy get_secrets must not pay an R1FS fetch per refused request (flood regression)."""
import inspect
import json
import os
import threading
import time
import types
import unittest
from copy import deepcopy
from pathlib import Path

from ratio1.const.base import dAuth

from extensions.business.dauth import deployment_secrets
from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY, DAUTH_PIPELINE_CACHE_NEGATIVE_TTL, DAUTH_R1FS_PIN_QUEUE_MAX,
  DAUTH_R1FS_PIN_RETRY_DELAY, DEEPLOY_JOBS_CSTORE_HKEY,
)
from extensions.business.dauth.dauth_revoked_nodes import _DauthRevokedNodesMixin
from extensions.business.dauth.test_dauth_registry_gating import _make_dauth_harness

ROOT = Path(__file__).resolve().parents[3]
MIXIN_PATH = "extensions/business/dauth/dauth_mixin.py"
# Optional path to the pre-change module when git cannot run (e.g. inside the node image).
BASELINE_ENV = "DAUTH_BASELINE_MIXIN"
LIVE_COST = 0.5      # seconds per fetch of a reachable CID (production: 0.2-1.1 s)
COMMAND_TIMEOUT = 90  # ratio1 R1FS default subprocess timeout, also the fixed `ipfs pin add` timeout


class _Clock:
  def __init__(self):
    self.now = 1_700_000_000.0


class _TimedR1FS:
  """R1FS cost model of ratio1 `get_file`.

  A reachable CID costs LIVE_COST per call. An unreachable CID blocks each
  subprocess until it times out: with pin=True the 90 s `ipfs pin add`, retried
  once after a relay self-heal; with pin=False the `ipfs get` under the caller's
  timeout, also retried once. The relay self-heal itself is counted as free.
  """

  def __init__(self, clock, docs, dead=()):
    self.clock, self.docs, self.dead = clock, docs, set(dead)
    self.calls, self.busy = [], 0.0

  def get_json(self, cid, timeout=None, pin=True, show_logs=True, **kwargs):  # pylint: disable=unused-argument
    self.calls.append({"cid": cid, "timeout": timeout, "pin": pin})
    if cid in self.dead:
      spent = 2 * COMMAND_TIMEOUT if pin else 2 * min(timeout or COMMAND_TIMEOUT, COMMAND_TIMEOUT)
      if kwargs.get("max_seconds"):
        spent = min(spent, kwargs["max_seconds"])  # an SDK with an overall budget stops there
      result = None
    else:
      spent, result = LIVE_COST, deepcopy(self.docs[cid])
    self.clock.now += spent
    self.busy += spent
    return result


def _baseline_mixin_class():
  """The dAuth mixin before this change, from the file named by the environment, or None."""
  # Only an explicitly named older copy is a baseline: HEAD already contains the change under test.
  path = os.environ.get(BASELINE_ENV)
  if not path or not os.path.isfile(path):
    return None
  source = Path(path).read_text(encoding="utf-8")
  module = types.ModuleType("extensions.business.dauth._baseline_dauth_mixin")
  module.__package__ = "extensions.business.dauth"
  exec(compile(source, "baseline:" + MIXIN_PATH, "exec"), module.__dict__)  # noqa: S102
  return type("_BaselineHarness", (module._DauthMixin, _DauthRevokedNodesMixin), {})


def _flood_plugin(clock, jobs=25, dead_jobs=(0,), senders=16):
  plugin = _make_dauth_harness()
  plugin.time = lambda: clock.now
  docs = {}
  for job in range(jobs):
    cid = f"cid-{job}"
    docs[cid] = {"NAME": f"app-{job}", "OWNER": "owner",
                 "DEEPLOY_SPECS": {"job_id": job, "current_target_nodes": [f"runner-{job}"]}}
    plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, str(job)] = cid
    plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, str(job)] = {
      "job_id": str(job), "pipeline_cid": cid, "job_secrets": {"TOKEN": f"value-{job}"},
    }
    plugin.bc.node_eth[f"runner-{job}"] = f"0xRUNNER{job}"
  for index in range(senders):
    plugin.bc.node_eth[f"stale-{index}"] = f"0xSTALE{index}"
  plugin.r1fs = _TimedR1FS(clock, docs, dead=[f"cid-{job}" for job in dead_jobs])
  return plugin


def _request(clock, sender, job_id, eth=None):
  return {"EE_SENDER": sender, "EE_ETH_SENDER": eth, "job_id": str(job_id),
          "nonce": hex(int(clock.now * 1000))}


def run_flood(harness_class=None, requests=1000, senders=16, jobs=25, spacing=2.0):
  """Replay `requests` refused legacy get_secrets, one every `spacing` s, on one serial thread."""
  clock = _Clock()
  plugin = _flood_plugin(clock, jobs=jobs, senders=senders)
  if harness_class is not None:
    plugin.__class__ = harness_class
  start = clock.now
  outcomes = {}
  for index in range(requests):
    clock.now = max(clock.now, start + index * spacing)  # arrival; earlier work delays it
    sender = f"stale-{index % senders}"
    body = _request(clock, sender, (index * 7) % jobs, eth=plugin.bc.node_eth[sender])
    try:
      plugin.process_dauth_get_secret_request(body)
      outcome = "served"
    except Exception as exc:  # pylint: disable=broad-except
      outcome = f"{type(exc).__name__}: {exc}"
    outcomes[outcome] = outcomes.get(outcome, 0) + 1
  return {
    "plugin": plugin, "clock": clock, "outcomes": outcomes,
    "fetches": len(plugin.r1fs.calls), "busy": plugin.r1fs.busy,
    "dead_fetches": sum(call["cid"] == "cid-0" for call in plugin.r1fs.calls),
    "duration": clock.now - start,
  }


class LegacySecretFloodTests(unittest.TestCase):
  def test_refusal_flood_is_bounded_and_authorization_still_works(self):
    after = run_flood()
    plugin, clock = after["plugin"], after["clock"]
    refused = after["outcomes"].get("ValueError: Sender is not running the existing job.", 0)
    unavailable = after["outcomes"].get("RuntimeError: Existing pipeline configuration is unavailable.", 0)
    self.assertEqual(refused + unavailable, 1000, after["outcomes"])
    # One fetch per live CID, plus one per negative-cache window for the dead CID.
    live_fetches = after["fetches"] - after["dead_fetches"]
    self.assertEqual(live_fetches, 24)
    self.assertLessEqual(after["dead_fetches"], after["duration"] // DAUTH_PIPELINE_CACHE_NEGATIVE_TTL + 1)
    self.assertLessEqual(after["busy"], 24 * LIVE_COST + after["dead_fetches"] * 15)
    # The fake SDK accepts the overall read budget, so each read gets it whole and never pins.
    self.assertTrue(all(call["pin"] is False and call["timeout"] == 15 for call in plugin.r1fs.calls))

    # A listed runner is still served, from the cached facts and the bound bundle.
    fetches = len(plugin.r1fs.calls)
    plugin.process_dauth_get_secret_request(_request(clock, "runner-5", 5, eth="0xRUNNER5"))
    self.assertEqual(json.loads(plugin.bc.encrypt_calls[-1][0])["job_secrets"], {"TOKEN": "value-5"})
    self.assertEqual(len(plugin.r1fs.calls), fetches)

    # A redeploy publishes a new CID: the new placement applies at once, the old runner is refused.
    plugin.r1fs.docs["cid-5-v2"] = {"NAME": "app-5", "OWNER": "owner",
                                    "DEEPLOY_SPECS": {"job_id": 5, "current_target_nodes": ["stale-3"]}}
    plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "5"] = "cid-5-v2"
    plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "5"]["pipeline_cid"] = "cid-5-v2"
    with self.assertRaisesRegex(ValueError, "not running the existing job"):
      plugin.process_dauth_get_secret_request(_request(clock, "runner-5", 5, eth="0xRUNNER5"))
    plugin.process_dauth_get_secret_request(_request(clock, "stale-3", 5, eth="0xSTALE3"))
    self.assertEqual(json.loads(plugin.bc.encrypt_calls[-1][0])["pipeline_cid"], "cid-5-v2")
    self.assertEqual(len(plugin.r1fs.calls), fetches + 1)

  def test_flood_before_the_change_fetched_on_every_refusal(self):
    baseline = _baseline_mixin_class()
    if baseline is None:
      self.skipTest(f"pre-change module unavailable (no git; set {BASELINE_ENV})")
    before = run_flood(harness_class=baseline)
    after = run_flood()
    self.assertEqual(before["fetches"], 1000)
    self.assertTrue(all(call["pin"] is True for call in before["plugin"].r1fs.calls))
    self.assertGreater(before["busy"], 50 * after["busy"])


class LegacyPipelineCacheTests(unittest.TestCase):
  def setUp(self):
    self.clock = _Clock()
    self.plugin = _flood_plugin(self.clock, jobs=6, dead_jobs=(0,), senders=2)

  def _get(self, sender, job_id, **extra):
    body = _request(self.clock, sender, job_id, eth=self.plugin.bc.node_eth[sender])
    body.update(extra)
    return self.plugin.process_dauth_get_secret_request(body)

  def test_dead_cid_is_negatively_cached_then_retried(self):
    for _ in range(3):
      with self.assertRaisesRegex(RuntimeError, "unavailable"):
        self._get("runner-0", 0)
    self.assertEqual(len(self.plugin.r1fs.calls), 1)
    self.clock.now += DAUTH_PIPELINE_CACHE_NEGATIVE_TTL
    with self.assertRaisesRegex(RuntimeError, "unavailable"):
      self._get("runner-0", 0)
    self.assertEqual(len(self.plugin.r1fs.calls), 2)

  def test_entries_expire_and_the_cache_is_bounded(self):
    self.plugin.cfg_dauth_pipeline_cache_max_entries = 3
    for job in range(1, 6):
      with self.assertRaises(ValueError):
        self._get("stale-0", job)
    self.assertEqual(list(self.plugin._dauth_legacy_pipeline_cache), ["cid-3", "cid-4", "cid-5"])
    self.clock.now += 3600
    with self.assertRaises(ValueError):
      self._get("stale-0", 5)
    self.assertEqual(len(self.plugin.r1fs.calls), 6)

  def test_request_fields_cannot_seed_or_change_cached_facts(self):
    forged = {"pipeline_cid": "cid-2", "DEEPLOY_SPECS": {"current_target_nodes": ["stale-0"]},
              "current_target_nodes": ["stale-0"]}
    with self.assertRaisesRegex(ValueError, "not running"):
      self._get("stale-0", 1, **forged)
    self.assertEqual(list(self.plugin._dauth_legacy_pipeline_cache), ["cid-1"])
    facts = self.plugin._dauth_legacy_pipeline_cache["cid-1"][1]
    self.assertEqual(facts["nodes"], frozenset({"0xai_runner-1"}))
    self.assertNotIn("job_secrets", str(self.plugin._dauth_legacy_pipeline_cache))

  def test_cache_hit_fetches_document_only_to_bind_a_pre_cid_bundle(self):
    doc = self.plugin.r1fs.docs["cid-1"]
    doc["PLUGINS"] = [{"INSTANCES": [{"ENV": {"TOKEN": dAuth.DAUTH_SECRET_PLACEHOLDER}}]}]
    self.plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "1"] = {
      "job_id": "1", "job_secrets": {"PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "bound-value"}}]}]},
    }
    with self.assertRaises(ValueError):
      self._get("stale-0", 1)  # warms the cache without the document
    self._get("runner-1", 1)
    self.assertEqual(len(self.plugin.r1fs.calls), 2)
    self.assertEqual(self.plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "1"]["pipeline_cid"], "cid-1")
    self._get("runner-1", 1)  # now bound: no further fetch
    self.assertEqual(len(self.plugin.r1fs.calls), 2)

  def test_shape_and_job_checks_still_apply_from_cached_facts(self):
    self.plugin.r1fs.docs["cid-2"]["DEEPLOY_SPECS"]["secret_revision"] = "op:deploy"
    for _ in range(2):
      with self.assertRaisesRegex(ValueError, "Secret revision is required"):
        self._get("runner-2", 2)
    self.plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "4"] = "cid-3"  # pointer to another job's CID
    with self.assertRaisesRegex(ValueError, "Secret revision is required"):
      self._get("runner-3", 4)
    self.assertEqual(self.plugin.bc.encrypt_calls, [])


class _PinR1FS:
  """Reads (pin=False) answer at once; pins (pin=True) may block or fail."""

  download_folder = "/r1fs/downloads"

  def __init__(self, docs):
    self.docs, self.reads, self.pins = docs, [], []
    self.release, self.block, self.fail = threading.Event(), False, set()

  def get_json(self, cid, timeout=None, pin=True, show_logs=True, local_folder=None, **kwargs):  # pylint: disable=unused-argument
    if not pin:
      self.reads.append(cid)
      return deepcopy(self.docs.get(cid))
    self.pins.append((cid, threading.current_thread().name, local_folder))
    if self.block:
      self.release.wait(90)  # an `ipfs pin add` stuck until its 90 s timeout
    if cid in self.fail:
      raise RuntimeError("pin add timed out")
    return deepcopy(self.docs.get(cid))


def _wait_for(predicate, timeout=5.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return True
    time.sleep(0.01)
  return predicate()


class DauthBackgroundPinTests(unittest.TestCase):
  def setUp(self):
    self.clock = _Clock()
    self.plugin = _flood_plugin(self.clock, jobs=6, dead_jobs=(), senders=2)
    self.r1fs = self.plugin.r1fs = _PinR1FS(self.plugin.r1fs.docs)
    self.plugin.cfg_dauth_r1fs_background_pin = True
    self.messages = []
    self.plugin.P = lambda msg, *args, **kwargs: self.messages.append(msg)
    self.addCleanup(self.r1fs.release.set)
    self.addCleanup(self.plugin._stop_dauth_r1fs_pinner)

  def _get(self, sender, job_id):
    body = _request(self.clock, sender, job_id, eth=self.plugin.bc.node_eth[sender])
    return self.plugin.process_dauth_get_secret_request(body)

  def test_request_returns_while_the_pin_is_still_blocked(self):
    self.r1fs.block = True
    started = time.monotonic()
    self.assertEqual(self._get("runner-1", 1)["status"], "success")
    self.assertLess(time.monotonic() - started, 1.0)
    self.assertTrue(_wait_for(lambda: self.r1fs.pins))
    self.assertEqual(self.r1fs.pins, [("cid-1", "dauth-r1fs-pin", "/r1fs/downloads/_dauth_pin")])
    self.assertEqual(self.r1fs.reads, ["cid-1"])

  def test_each_cid_is_pinned_once_across_many_reads(self):
    for _ in range(20):
      for job in range(1, 6):
        self.plugin._dauth_r1fs_get_json(f"cid-{job}")
        try:
          self._get("stale-0", job)
        except ValueError:
          pass
    self.assertTrue(_wait_for(lambda: len(self.r1fs.pins) == 5 and not self.plugin._dauth_r1fs_pinner["queue"]))
    time.sleep(0.05)
    self.assertEqual(sorted(cid for cid, _, _ in self.r1fs.pins), [f"cid-{job}" for job in range(1, 6)])

  def test_negative_results_and_disabled_config_do_not_pin(self):
    self.assertIsNone(self.plugin._dauth_r1fs_get_json("cid-missing"))
    self.plugin.cfg_dauth_r1fs_background_pin = False
    self.plugin._dauth_r1fs_get_json("cid-1")
    self.assertIsNone(getattr(self.plugin, "_dauth_r1fs_pinner", None))

  def test_failing_pin_is_isolated_logged_once_and_retried_once(self):
    self.r1fs.fail.add("cid-1")
    self.assertEqual(self._get("runner-1", 1)["status"], "success")
    self.plugin._dauth_r1fs_get_json("cid-2")
    self.assertTrue(_wait_for(lambda: len(self.r1fs.pins) == 2))
    self.plugin._dauth_r1fs_get_json("cid-1")  # no new attempt before the retry is due
    self.clock.now += DAUTH_R1FS_PIN_RETRY_DELAY
    self.plugin._dauth_r1fs_pinner["wake"].set()
    self.assertTrue(_wait_for(lambda: len(self.r1fs.pins) == 3))
    self.clock.now += 2 * DAUTH_R1FS_PIN_RETRY_DELAY
    self.plugin._dauth_r1fs_get_json("cid-1")
    self.plugin._dauth_r1fs_pinner["wake"].set()
    time.sleep(0.1)
    self.assertEqual([cid for cid, _, _ in self.r1fs.pins], ["cid-1", "cid-2", "cid-1"])
    self.assertEqual(len([m for m in self.messages if "could not pin" in m]), 1)
    self.assertTrue(self.plugin._dauth_r1fs_pinner["thread"].is_alive())

  def test_queue_is_bounded_and_drops_the_oldest(self):
    self.r1fs.block = True
    self.plugin._dauth_r1fs_get_json("cid-1")
    self.assertTrue(_wait_for(lambda: self.r1fs.pins))  # the pinner is stuck on cid-1
    for index in range(300):
      self.r1fs.docs[f"extra-{index}"] = {}
      self.plugin._dauth_r1fs_get_json(f"extra-{index}")
    queue = list(self.plugin._dauth_r1fs_pinner["queue"])
    self.assertEqual(len(queue), DAUTH_R1FS_PIN_QUEUE_MAX)
    self.assertEqual(queue[0], f"extra-{300 - DAUTH_R1FS_PIN_QUEUE_MAX}")

  def test_pinner_stops_when_the_plugin_closes(self):
    self.plugin._dauth_r1fs_get_json("cid-1")
    thread = self.plugin._dauth_r1fs_pinner["thread"]
    self.assertTrue(_wait_for(lambda: self.r1fs.pins))
    self.plugin._stop_dauth_r1fs_pinner()
    thread.join(2)
    self.assertFalse(thread.is_alive())


class DauthR1FSReadTests(unittest.TestCase):
  def test_every_dauth_read_skips_the_pin_and_uses_the_read_budget(self):
    plugin = _make_dauth_harness()
    calls = []
    plugin.r1fs = types.SimpleNamespace(get_json=lambda cid, **kwargs: calls.append(kwargs) or {})
    plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = "cid-7"
    plugin._load_dauth_job_pipeline_record("7")
    plugin.cfg_dauth_r1fs_read_timeout = 10
    plugin._dauth_r1fs_get_json("cid-7")
    self.assertEqual(calls, [{"timeout": 15, "pin": False, "show_logs": False, "max_seconds": 15},
                             {"timeout": 10, "pin": False, "show_logs": False, "max_seconds": 10}])
    self.assertNotIn("r1fs.get_json", inspect.getsource(deployment_secrets))

  def test_sdk_without_a_read_budget_gets_half_the_budget_per_attempt(self):
    plugin = _make_dauth_harness()
    calls = []

    def old_get_json(cid, timeout=None, pin=True, show_logs=True):
      calls.append({"timeout": timeout, "pin": pin})
      return {}
    plugin.r1fs = types.SimpleNamespace(get_json=old_get_json)
    plugin._dauth_r1fs_get_json("cid-7")
    plugin._dauth_r1fs_get_json("cid-8")
    self.assertEqual(calls, [{"timeout": 7.5, "pin": False}, {"timeout": 7.5, "pin": False}])
    self.assertFalse(plugin._dauth_r1fs_has_max_seconds)

  def test_type_error_from_the_read_itself_is_not_swallowed(self):
    plugin = _make_dauth_harness()

    def broken(cid, **kwargs):
      raise TypeError("unsupported operand")
    plugin.r1fs = types.SimpleNamespace(get_json=broken)
    with self.assertRaises(TypeError):
      plugin._dauth_r1fs_get_json("cid-7")

  def test_installed_r1fs_engine_accepts_pin_and_timeout(self):
    from ratio1.ipfs.r1fs import R1FSEngine
    inner = R1FSEngine.get_json
    for cell in inner.__closure__ or ():
      if inspect.isfunction(cell.cell_contents):
        inner = cell.cell_contents  # unwrap @require_ipfs_started
    parameters = inspect.signature(inner).parameters
    self.assertIn("pin", parameters)
    self.assertIn("timeout", parameters)


if __name__ == "__main__":
  unittest.main()
