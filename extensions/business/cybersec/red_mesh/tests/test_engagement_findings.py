"""RM-121: the engagement finding ledger (continuous-monitoring.md §2-§5, §2.1, §11).

Most cases drive the pure fold (`apply_pass`, `fold`) with pass-changes artifacts built by
`pass_changes`; a few drive the hkey adapter over an in-memory chainstore; the hook wiring runs the
real `maybe_finalize_pass` with fake runtime boundaries.
"""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.models.cstore import PassReportRef
from extensions.business.cybersec.red_mesh.models.finding_identity import dedup_key
from extensions.business.cybersec.red_mesh.repositories import ArtifactRepository
from extensions.business.cybersec.red_mesh.services.engagement_ledger import (
  apply_pass, fold, pass_changes,
)
from extensions.business.cybersec.red_mesh.services.engagement_ledger_store import (
  EngagementLedgerRecorder, EngagementLedgerStore, LedgerStoreError,
)
from extensions.business.cybersec.red_mesh.services.finalization import maybe_finalize_pass

from .asset_fixture import pick, register_asset
from .contract_fixture import install_contract
from .test_tenant_execution_finalization import FinalizationOwner, MemoryArtifacts, execution_binding

ASSET = "ea_1"
ENGAGEMENT = "en_33333333-3333-4333-8333-333333333333"
OTHER_ENGAGEMENT = "en_44444444-4444-4444-8444-444444444444"
TENANT = "tn_11111111-1111-4111-8111-111111111111"
HTTP = "_service_info_http"


def finding(fid="f1", sig="s1", port=8080, probe=HTTP, severity="HIGH", scenario_id=None):
  return {"finding_id": fid, "finding_signature": sig, "title": f"title {fid}", "severity": severity,
          "port": port, "probe": probe, "scenario_id": scenario_id}


def net(job, nr, at, findings=(), *, completed_tests=("scan_ports_step_completed",),
        outcomes={"connected": 3}, port_range=(1, 10000), completed_ranges=((1, 10000),),
        enabled=(HTTP, "_service_info_ssh"), excluded=(), abort_state=None):
  return pass_changes(
    job_id=job, pass_nr=nr, date_completed=at, scan_type="network", pass_report_cid=f"pr-{job}-{nr}",
    flat_findings=list(findings), aggregated={"completed_tests": list(completed_tests)},
    pass_metrics=None if outcomes is None else {"connection_outcomes": outcomes}, abort_state=abort_state,
    job_config={"start_port": port_range[0], "end_port": port_range[1], "enabled_features": list(enabled),
                "excluded_features": list(excluded)},
    completed_ranges=[list(r) for r in completed_ranges])


def web(job, nr, at, findings=(), *, abort_state=None, excluded=(), assigned=None):
  return pass_changes(
    job_id=job, pass_nr=nr, date_completed=at, scan_type="webapp", pass_report_cid=f"pr-{job}-{nr}",
    flat_findings=list(findings), aggregated={"completed_tests": ["graybox_probes"]}, pass_metrics=None,
    abort_state=abort_state, job_config={"excluded_features": list(excluded), "assigned_scenario_ids": assigned},
    completed_ranges=[])


def gbx(fid="g1", sig="gs1", scenario="S1"):
  return finding(fid, sig, port=443, probe="_graybox_access_control", scenario_id=scenario)


def run(*passes, grace=1, state=None, late=False):
  events = []
  for changes in passes:
    state, new = apply_pass(state, changes, asset_id=ASSET, grace=grace, late=late)
    events.append(new)
  return state, events


def kinds(events):
  return [event["kind"] for event in events]


def ref(job, nr, at):
  return {"job_id": job, "pass_nr": nr, "at": at}


F = finding()
F_KEY = "f1:0"
G = finding("f2", "s2", port=22, probe="_service_info_ssh")


class TestWorkedCases(unittest.TestCase):
  """continuous-monitoring.md §11, N = 1 unless stated. J network continuous, K another job."""

  def setUp(self):
    self.base, _ = run(net("J", 1, 1, [F]))

  def row(self, state, key=F_KEY):
    return state["rows"][key]

  def test_1_first_sighting_is_new(self):
    state, events = run(net("J", 1, 1, [F]))
    row = self.row(state)
    self.assertEqual((row["first_seen"], row["last_seen"], row["times_seen"]), (ref("J", 1, 1), ref("J", 1, 1), 1))
    self.assertEqual(kinds(events[0]), ["new"])

  def test_2_monitor_advances_last_seen_and_times_seen_every_pass_without_events(self):
    state, events = run(net("J", 2, 2, [F]), net("J", 3, 3, [F]), state=self.base)
    row = self.row(state)
    self.assertEqual((row["last_seen"], row["last_tested"], row["times_seen"]), (ref("J", 3, 3), ref("J", 3, 3), 3))
    self.assertEqual(events, [[], []])

  def test_3_new_signature_is_a_new_version_and_resets_nothing(self):
    state, events = run(net("J", 2, 2, [F]), net("J", 3, 3, [finding(sig="s1b", severity="CRITICAL")]),
                        state=self.base)
    row = self.row(state)
    self.assertEqual(row["current_version"]["finding_signature"], "s1b")
    self.assertEqual(row["current_version"]["first_pass_report_cid"], "pr-J-3")
    self.assertEqual((row["first_seen"], row["episode_opened"], row["times_seen"]),
                     (ref("J", 1, 1), ref("J", 1, 1), 3))
    self.assertEqual(kinds(events[1]), ["changed"])
    self.assertEqual(events[1][0]["detail"], {"old_severity": "HIGH", "new_severity": "CRITICAL"})

  def test_4_covered_miss_with_n_1_sets_not_observed_since(self):
    state, events = run(net("J", 4, 4), state=self.base)
    row = self.row(state)
    self.assertEqual((row["missed_streak"], row["not_observed_since"], row["last_tested"]),
                     (1, ref("J", 4, 4), ref("J", 4, 4)))
    self.assertEqual(kinds(events[0]), ["not_observed"])

  def test_5_with_n_2_one_miss_is_a_missed_event(self):
    state, events = run(net("J", 4, 4), state=self.base, grace=2)
    self.assertEqual((self.row(state)["missed_streak"], self.row(state)["not_observed_since"]), (1, None))
    self.assertEqual(kinds(events[0]), ["missed"])

  def test_6_reported_again_clears_the_marker_and_counts_reappeared(self):
    state, events = run(net("J", 4, 4), net("J", 5, 5, [F]), state=self.base)
    row = self.row(state)
    self.assertEqual((row["missed_streak"], row["not_observed_since"], row["reappeared_count"], row["episode_opened"]),
                     (0, None, 1, ref("J", 5, 5)))
    self.assertEqual(kinds(events[1]), ["reappeared"])
    self.assertEqual(events[1][0]["alert_id"], f"{ASSET}|reappeared|{F_KEY}|1")

  def test_7_aborted_pass_applies_no_miss(self):
    aborted = {"aborted": True, "abort_reason_class": "unknown"}
    state, events = run(net("J", 6, 6, abort_state=aborted), state=self.base)
    row = self.row(state)
    self.assertEqual((row["missed_streak"], row["not_observed_since"], row["last_tested"]), (0, None, ref("J", 1, 1)))
    self.assertEqual(row["last_coverage_gap"], ref("J", 6, 6))
    # An aborted pass is a gap cause (§3, §11 case 7), so the gap state starts.
    self.assertEqual(kinds(events[0]), ["coverage_gap"])

  def test_8_port_outside_the_configured_range_is_out_of_scope(self):
    state, events = run(net("J", 7, 7, port_range=(1, 1000)), state=self.base)
    self.assertEqual((state["rows"], state["gap"]), (self.base["rows"], self.base["gap"]))
    self.assertEqual(events, [[]])

  def test_8a_failed_worker_slice_is_a_gap_for_its_ports_only(self):
    base, _ = run(net("J", 1, 1, [F, G]))
    state, events = run(net("J", 2, 2, completed_ranges=((1, 1000),)), state=base)
    self.assertEqual(self.row(state)["last_coverage_gap"], ref("J", 2, 2))
    self.assertIsNone(self.row(state)["not_observed_since"])
    self.assertEqual(state["rows"]["f2:0"]["not_observed_since"], ref("J", 2, 2))
    self.assertEqual(state["gap"]["network"]["state"]["cause"], "port_scan_incomplete")
    gap = [e for e in events[0] if e["kind"] == "coverage_gap"]
    self.assertEqual(gap[0]["detail"], {"scan_type": "network", "cause": "port_scan_incomplete"})
    self.assertEqual(sorted(kinds(events[0])), ["coverage_gap", "not_observed"])

  def test_9_host_timing_out_everywhere_continues_the_gap_without_an_event(self):
    state, _ = run(net("J", 2, 2, completed_ranges=((1, 1000),)), state=self.base)
    state, events = run(net("J", 3, 3, outcomes={"timeout": 50}), state=state)
    self.assertEqual(state["gap"]["network"]["state"]["streak"], 2)
    self.assertEqual(self.row(state)["last_coverage_gap"], ref("J", 3, 3))
    self.assertEqual(events, [[]])

  def test_10_another_scan_type_is_out_of_scope(self):
    state, events = run(web("K", 1, 2), state=self.base)
    self.assertEqual(state["rows"], self.base["rows"])
    self.assertEqual(events, [[]])

  def test_12_late_pass_only_adds_a_sighting(self):
    state, _ = run(net("J", 9, 9, [F]), state=self.base)
    state, events = run(net("K", 1, 0.5, [F]), state=state, late=True)
    row = self.row(state)
    self.assertEqual((row["first_seen"], row["last_seen"], row["times_seen"], row["job_ids"]),
                     (ref("K", 1, 0.5), ref("J", 9, 9), 3, ["J", "K"]))
    self.assertEqual(state["through"], 9)
    self.assertEqual(events, [[]])

  def test_12a_late_pass_with_another_signature_keeps_the_version(self):
    state, events = run(net("K", 1, 0.5, [finding(sig="other")]), state=self.base, late=True)
    self.assertEqual(self.row(state)["current_version"], self.row(self.base)["current_version"])
    self.assertEqual(events, [[]])

  def test_12f_late_pass_with_a_never_seen_finding_inserts_it_digest_only(self):
    state, events = run(net("K", 1, 0.5, [G]), state=self.base, late=True)
    row = state["rows"]["f2:0"]
    self.assertEqual((row["first_seen"], row["not_observed_since"]), (ref("K", 1, 0.5), None))
    self.assertEqual(kinds(events[0]), ["new"])
    self.assertTrue(events[0][0]["digest_only"])

  def test_12b_late_sighting_leaves_a_not_observed_row_not_observed(self):
    state, _ = run(net("J", 2, 2), state=self.base)
    state, events = run(net("K", 1, 1.5, [F]), state=state, late=True)
    self.assertEqual(self.row(state)["not_observed_since"], ref("J", 2, 2))
    self.assertEqual(events, [[]])

  def test_12c_covered_pass_on_a_not_observed_row_applies_no_further_miss(self):
    state, _ = run(net("J", 2, 2), state=self.base)
    state, events = run(net("J", 3, 3), state=state)
    self.assertEqual((self.row(state)["missed_streak"], self.row(state)["not_observed_since"]), (1, ref("J", 2, 2)))
    self.assertEqual(events, [[]])

  def test_12d_covered_pass_after_a_gap_restores_coverage(self):
    state, events = run(net("J", 2, 2, outcomes={"timeout": 9}), net("J", 3, 3, [F]), state=self.base)
    self.assertIsNone(state["gap"]["network"]["state"])
    self.assertEqual(kinds(events[0]), ["coverage_gap"])
    self.assertEqual(kinds(events[1]), ["coverage_restored"])
    self.assertEqual(events[1][0]["detail"], {"scan_type": "network"})

  def test_12e_single_scan_with_fewer_features_leaves_the_row_alone(self):
    state, events = run(net("K", 1, 2, enabled=("_service_info_ssh",), excluded=(HTTP,)), state=self.base)
    self.assertEqual(state["rows"], self.base["rows"])
    self.assertEqual(events, [[]])

  def test_12g_webapp_pass_leaves_the_network_gap_state_alone(self):
    gw = gbx()
    base, _ = run(net("J", 1, 1, [F]), web("W", 1, 2, [gw]))
    state, _ = run(net("J", 2, 3, outcomes={"timeout": 1}), web("W", 2, 4, [gw]), state=base)
    self.assertEqual(state["gap"]["network"]["state"]["cause"], "host_unresponsive")
    self.assertIsNone(state["gap"].get("webapp", {}).get("state"))
    state, events = run(net("J", 3, 5, [F]), state=state)
    self.assertEqual(kinds(events[0]), ["coverage_restored"])

  def test_13_successor_job_carries_on_with_the_same_row(self):
    state, events = run(net("J2", 1, 2, [F]), state=self.base)
    row = self.row(state)
    self.assertEqual((row["last_seen"], row["times_seen"], row["job_ids"]), (ref("J2", 1, 2), 2, ["J", "J2"]))
    self.assertEqual(events, [[]])


class TestCoverageRule(unittest.TestCase):
  """§3 per unreported row: out of scope, coverage gap, or covered miss."""

  def after(self, changes, base_pass=None):
    base, _ = run(base_pass or net("J", 1, 1, [F]))
    state, events = run(changes, state=base)
    return base, state, events[0]

  def test_network_pass_where_the_port_is_now_refused_is_a_covered_miss(self):
    _, state, events = self.after(net("J", 2, 2, outcomes={"refused": 1, "timeout": 40}))
    self.assertEqual(state["rows"][F_KEY]["not_observed_since"], ref("J", 2, 2))
    self.assertEqual(kinds(events), ["not_observed"])

  def test_unreachable_host_is_a_host_unresponsive_gap_and_not_the_marker(self):
    for outcomes in ({"timeout": 12}, {}, None, {"connected": 0, "refused": 0}):
      with self.subTest(outcomes=outcomes):
        _, state, events = self.after(net("J", 2, 2, outcomes=outcomes))
        self.assertIsNone(state["rows"][F_KEY]["not_observed_since"])
        self.assertEqual(state["gap"]["network"]["state"]["cause"], "host_unresponsive")

  def test_missing_port_scan_step_is_a_port_scan_incomplete_gap(self):
    _, state, _ = self.after(net("J", 2, 2, completed_tests=()))
    self.assertEqual(state["gap"]["network"]["state"]["cause"], "port_scan_incomplete")

  def test_disabled_probe_and_port_exception_are_out_of_scope(self):
    exception = net("J", 2, 2)
    exception["coverage"]["port_exceptions"] = [8080]
    for changes in (net("J", 2, 2, excluded=(HTTP,)), exception):
      base, state, events = self.after(changes)
      self.assertEqual((state["rows"], events), (base["rows"], []))

  def test_probe_outside_the_feature_list_is_in_scope_only_when_nothing_was_excluded(self):
    odd = finding(probe="_sub_probe")
    _, state, _ = self.after(net("J", 2, 2), base_pass=net("J", 1, 1, [odd]))
    self.assertIsNotNone(state["rows"][F_KEY]["not_observed_since"])
    base, state, _ = self.after(net("J", 2, 2, excluded=("_service_info_ssh",)), base_pass=net("J", 1, 1, [odd]))
    self.assertEqual(state["rows"], base["rows"])

  def test_correlation_finding_is_in_scope_on_every_completed_network_pass(self):
    corr = finding(port=0, probe="_post_scan_correlate")
    _, state, _ = self.after(net("J", 2, 2, excluded=(HTTP,)), base_pass=net("J", 1, 1, [corr]))
    self.assertIsNotNone(state["rows"][F_KEY]["not_observed_since"])

  def test_clean_graybox_pass_without_the_finding_is_a_covered_miss(self):
    _, state, events = self.after(web("W", 2, 2), base_pass=web("W", 1, 1, [gbx()]))
    self.assertEqual(state["rows"]["g1:0"]["not_observed_since"], ref("W", 2, 2))
    self.assertEqual(kinds(events), ["not_observed"])

  def test_partial_graybox_abort_and_auth_failure_are_gaps(self):
    for abort, cause in (({"aborted": True, "abort_reason_class": "session_lost", "empty": False}, "aborted"),
                         ({"aborted": True, "abort_reason_class": "auth_failed", "empty": True}, "graybox_auth_failed")):
      with self.subTest(cause=cause):
        _, state, events = self.after(web("W", 2, 2, abort_state=abort), base_pass=web("W", 1, 1, [gbx()]))
        self.assertIsNone(state["rows"]["g1:0"]["not_observed_since"])
        self.assertEqual(state["rows"]["g1:0"]["last_coverage_gap"], ref("W", 2, 2))
        self.assertEqual(state["gap"]["webapp"]["state"]["cause"], cause)
        self.assertEqual(events[0]["alert_id"], f"{ASSET}|coverage_gap|webapp|1")

  def test_graybox_gates_take_rows_out_of_scope(self):
    for changes in (web("W", 2, 2, excluded=("graybox",)), web("W", 2, 2, excluded=("_graybox_access_control",)),
                    web("W", 2, 2, assigned=["S9"])):
      base, state, events = self.after(changes, base_pass=web("W", 1, 1, [gbx()]))
      self.assertEqual((state["rows"], events), (base["rows"], []))

  def test_pass_with_no_in_scope_rows_leaves_the_gap_state_unchanged(self):
    base, state, events = self.after(net("J", 2, 2, outcomes={"timeout": 1}, port_range=(1, 100)))
    self.assertEqual((state["gap"], events), (base["gap"], []))


class TestMatching(unittest.TestCase):
  def test_same_finding_id_matches_by_signature_then_position(self):
    a, b = finding(sig="sa"), finding(sig="sb")
    state, _ = run(net("J", 1, 1, [a, b]))
    self.assertEqual({k: r["current_version"]["finding_signature"] for k, r in state["rows"].items()},
                     {"f1:0": "sa", "f1:1": "sb"})
    state, events = run(net("J", 2, 2, [b, a, finding(sig="sc")]), state=state)  # reordered, plus a third
    self.assertEqual(state["rows"]["f1:0"]["current_version"]["finding_signature"], "sa")
    self.assertEqual(state["rows"]["f1:1"]["times_seen"], 2)
    self.assertEqual(kinds(events[0]), ["new"])
    state, events = run(net("J", 3, 3, [finding(sig="sd")]), state=state)  # no signature match: position
    self.assertEqual(state["rows"]["f1:0"]["current_version"]["finding_signature"], "sd")
    self.assertEqual(sorted(kinds(events[0])), ["changed", "not_observed", "not_observed"])


class _Loader:
  def __init__(self):
    self.artifacts = {}
    self.reads = 0

  def add(self, changes, *, late=False, skipped=False):
    if skipped:
      return {"skipped": True}
    cid = f"pc-{changes['job_id']}-{changes['pass_nr']}"
    self.artifacts[cid] = changes
    return {"date_completed": changes["date_completed"], "scan_type": changes["scan_type"],
            "pass_report_cid": changes["pass_report_cid"], "pass_changes_cid": cid, "late": late}

  def __call__(self, cid):
    self.reads += 1
    return deepcopy(self.artifacts.get(cid))


def in_order(*passes):
  state, events = run(*sorted(passes, key=lambda p: (p["date_completed"], p["job_id"], p["pass_nr"])))
  return state, events


class TestFold(unittest.TestCase):
  """§2.1: write-once pass entries and a derived checkpoint, no compare-and-set."""

  def setUp(self):
    self.load = _Loader()
    self.entries = {}

  def put(self, changes, **kwargs):
    self.entries[(changes["job_id"], changes["pass_nr"])] = self.load.add(changes, **kwargs)

  def fold(self, checkpoint, **kwargs):
    return fold(checkpoint, self.entries, self.load, asset_id=ASSET, **kwargs)

  def passes(self):
    return [net("J", 1, 1, [F]), net("K", 1, 2, [F, G]), net("J", 2, 3, [G]),
            net("K", 2, 4, [F]), net("J", 3, 5, [F, G]), net("K", 3, 6, [G])]

  def test_interleaved_jobs_folded_pass_by_pass_equal_the_in_order_result(self):
    checkpoint, events = None, []
    for changes in self.passes():
      self.put(changes)
      result = self.fold(checkpoint)
      self.assertFalse(result.replayed)
      checkpoint = result.checkpoint
      events.append(result.events[(changes["job_id"], changes["pass_nr"])])
    expected, expected_events = in_order(*self.passes())
    self.assertEqual((checkpoint["rows"], checkpoint["gap"]), (expected["rows"], expected["gap"]))
    self.assertEqual(events, expected_events)
    self.assertEqual(checkpoint["included"], {"J": 3, "K": 3})

  def test_replaced_checkpoint_is_replayed_to_the_in_order_result(self):
    first, j2, k1 = net("J", 1, 1, [F, G]), net("J", 2, 10, [G]), net("K", 1, 11, [F])
    self.put(first)
    base = self.fold(None).checkpoint
    self.put(j2)
    j_result = self.fold(base)  # J's writer folds its own pass
    del self.entries[("J", 2)]
    self.put(k1)
    k_checkpoint = self.fold(base).checkpoint  # K's writer did not see J/2 yet ...
    self.put(j2)                               # ... and its checkpoint replaces J's
    self.assertNotIn("J", {j for j, n in k_checkpoint["included"].items() if n >= 2})
    result = self.fold(k_checkpoint)
    expected, expected_events = in_order(first, j2, k1)
    self.assertTrue(result.replayed)
    self.assertEqual(result.checkpoint["rows"], expected["rows"])
    self.assertEqual(result.checkpoint["rows"][F_KEY]["times_seen"], 2)
    self.assertEqual(result.events[("J", 2)], expected_events[1])
    self.assertEqual(result.events[("J", 2)], j_result.events[("J", 2)])
    self.assertFalse(self.fold(result.checkpoint).replayed)  # repaired: the next fold replays nothing

  def test_pass_marked_late_by_its_writer_is_applied_as_a_late_pass(self):
    self.put(net("J", 1, 5, [F]))
    checkpoint = self.fold(None).checkpoint
    self.put(net("K", 1, 3, [G]), late=True)
    result = self.fold(checkpoint)
    self.assertFalse(result.replayed)
    self.assertIsNone(result.checkpoint["rows"][F_KEY]["not_observed_since"])
    self.assertTrue(result.events[("K", 1)][0]["digest_only"])
    self.assertEqual(result.checkpoint["through"], 5)

  def test_later_pass_of_a_job_waits_for_the_missing_one(self):
    self.put(net("J", 1, 1, [F]))
    checkpoint = self.fold(None).checkpoint
    self.put(net("J", 3, 3, [F]))
    result = self.fold(checkpoint)
    self.assertEqual((result.checkpoint["included"], result.events), ({"J": 1}, {}))
    self.put(net("J", 2, 2))
    result = self.fold(result.checkpoint)
    self.assertEqual(result.checkpoint["included"], {"J": 3})
    self.assertEqual(result.checkpoint["rows"], in_order(net("J", 1, 1, [F]), net("J", 2, 2), net("J", 3, 3, [F]))[0]["rows"])

  def test_skipped_entry_advances_included_and_later_passes_fold(self):
    self.put(net("J", 1, 1, [F]))
    self.put(net("J", 2, 2), skipped=True)
    self.put(net("J", 3, 3, [F]))
    result = self.fold(None)
    self.assertEqual((result.checkpoint["included"], result.checkpoint["skipped"]), ({"J": 3}, [["J", 2]]))
    self.assertEqual(result.checkpoint["rows"][F_KEY]["times_seen"], 2)
    self.assertNotIn(("J", 2), result.events)

  def test_real_entry_replacing_a_folded_skipped_entry_is_folded_once(self):
    self.put(net("J", 1, 1), skipped=True)
    checkpoint = self.fold(None).checkpoint
    self.put(net("J", 1, 1, [F]))
    result = self.fold(checkpoint)
    self.assertTrue(result.replayed)
    self.assertEqual(result.checkpoint["rows"][F_KEY]["times_seen"], 1)
    self.assertEqual(result.checkpoint["skipped"], [])
    self.assertFalse(self.fold(result.checkpoint).replayed)

  def test_replay_over_the_read_cap_is_left_pending(self):
    first, j2, k1 = net("J", 1, 1, [F]), net("J", 2, 10), net("K", 1, 11, [F])
    self.put(first)
    self.put(k1)
    checkpoint = self.fold(None).checkpoint
    self.put(j2)
    result = self.fold(checkpoint, read_cap=2)
    self.assertTrue(result.pending)
    self.assertFalse(result.replayed)
    self.assertIsNone(result.checkpoint["rows"][F_KEY]["not_observed_since"])  # J/2 applied as late

  def test_two_folds_crediting_new_to_different_passes_give_one_alert_id(self):
    j1, k1 = net("J", 1, 1, [F]), net("K", 1, 1, [F])
    self.put(j1)
    self.put(k1)
    both = self.fold(None)
    del self.entries[("J", 1)]
    k_first = self.fold(None)
    credited = [(key, e["alert_id"]) for r in (both, k_first) for key, evs in r.events.items() for e in evs]
    self.assertEqual({key for key, _ in credited}, {("J", 1), ("K", 1)})
    self.assertEqual({alert for _, alert in credited}, {f"{ASSET}|new|{F_KEY}"})


class ChainstoreOwner:
  """JSON round-trip chainstore and tenancy records; enough for the ledger adapter."""

  def __init__(self, *, tenant=True, deleting=False, engagement=True):
    self.store = {}
    self.logs = []
    tenancy = json.dumps(["redmesh", "tenancy", 1, "deployment"], separators=(",", ":"))
    if tenant:
      record = {"tenant_id": TENANT, "active": not deleting}
      if deleting:
        record["deleting"] = {"deleted_refs": []}
      self.store[(tenancy, json.dumps(["tenant", "deployment", TENANT], separators=(",", ":")))] = json.dumps(record)
    if engagement:
      key = json.dumps(["engagement", "deployment", TENANT, ENGAGEMENT], separators=(",", ":"))
      self.store[(tenancy, key)] = json.dumps({"engagement_id": ENGAGEMENT})

  def P(self, *args, **kwargs):
    self.logs.append(args)

  def chainstore_hget(self, hkey, key):
    raw = self.store.get((hkey, key))
    return json.loads(raw) if raw else None

  def chainstore_hgetall(self, hkey):
    return {k: json.loads(v) for (h, k), v in self.store.items() if h == hkey and v}

  def chainstore_hset(self, hkey, key, value, **kwargs):
    self.store[(hkey, key)] = json.dumps(value) if value is not None else None
    return True

  def fields(self, hkey):
    return self.chainstore_hgetall(hkey)


def bound_job(job_id="J", *, engagement=ENGAGEMENT, asset=ASSET, scan_type="network"):
  binding = execution_binding()
  binding.update(engagement_id=engagement, engagement_asset_id=asset)
  return {"job_id": job_id, "scan_type": scan_type, "execution_binding": binding}


class TestLedgerStore(unittest.TestCase):
  def setUp(self):
    self.owner = ChainstoreOwner()
    self.artifacts = ArtifactRepository(type("Owner", (), {"r1fs": MemoryArtifacts({})})())

  def record(self, job, changes):
    recorder = EngagementLedgerRecorder.for_job(self.owner, job)
    facts = {k: changes[k] for k in ("job_id", "pass_nr", "date_completed", "pass_report_cid")}
    cid = self.artifacts.put_json(changes)
    recorder.record_pass(self.artifacts, **facts, pass_changes_cid=cid)
    return recorder.store

  def test_hook_writes_nothing_outside_an_engagement_or_for_a_gone_tenant_or_engagement(self):
    self.assertIsNone(EngagementLedgerRecorder.for_job(self.owner, {"job_id": "J", "scan_type": "network"}))
    self.assertIsNone(EngagementLedgerRecorder.for_job(self.owner, bound_job(scan_type="model_test")))
    for owner in (ChainstoreOwner(deleting=True), ChainstoreOwner(tenant=False), ChainstoreOwner(engagement=False)):
      self.assertIsNone(EngagementLedgerRecorder.for_job(owner, bound_job()))

  def test_pass_entry_checkpoint_and_events_are_written(self):
    store = self.record(bound_job(), net("J", 1, 1, [F]))
    fields = self.owner.fields(store.hkey)
    self.assertEqual(store.hkey, f"deployment:engagement_findings:{TENANT}:{ENGAGEMENT}:{ASSET}")
    self.assertEqual(set(fields), {"pass:J:1", "checkpoint", "events:J:1"})
    self.assertFalse(fields["pass:J:1"]["late"])
    self.assertEqual(fields["checkpoint"]["rows"][F_KEY]["times_seen"], 1)
    self.assertEqual(kinds(fields["events:J:1"]), ["new"])
    store = self.record(bound_job(), net("J", 2, 2, [F]))
    self.assertNotIn("events:J:2", self.owner.fields(store.hkey))  # a persisting finding writes no event

  def test_writer_marks_its_entry_late_against_the_checkpoint_it_read(self):
    self.record(bound_job(), net("J", 1, 5, [F]))
    store = self.record(bound_job("K"), net("K", 1, 3, [G]))
    fields = self.owner.fields(store.hkey)
    self.assertTrue(fields["pass:K:1"]["late"])
    self.assertTrue(fields["events:K:1"][0]["digest_only"])

  def test_entries_are_write_once_except_a_real_entry_over_a_skipped_one(self):
    store = EngagementLedgerStore(self.owner, "deployment", TENANT, ENGAGEMENT, ASSET)
    real = {"date_completed": 1, "scan_type": "network", "pass_report_cid": "pr", "pass_changes_cid": "pc", "late": False}
    self.assertTrue(store.put_entry("J", 1, {"skipped": True}))
    self.assertFalse(store.put_entry("J", 1, {"skipped": True}))
    self.assertTrue(store.put_entry("J", 1, real))
    self.assertFalse(store.put_entry("J", 1, {**real, "pass_report_cid": "other"}))
    self.assertFalse(store.put_entry("J", 1, {"skipped": True}))
    self.assertEqual(store.entry("J", 1), real)
    with self.assertRaises(LedgerStoreError):
      store.put_entry("J", 2, {**real, "scan_type": "model_test"})

  def test_locationless_finding_on_two_assets_is_two_rows_in_two_records(self):
    locationless = {"probe": "_web_test_xss", "title": "Reflected XSS", "severity": "HIGH", "cwe_id": "CWE-79"}
    ids = {dedup_key({**locationless, "affected_assets": [{"host": host, "port": 80}]}) for host in ("a.test", "b.test")}
    self.assertEqual(len(ids), 1)
    same = finding(fid=ids.pop(), port=80, probe="_web_test_xss")
    stores = [self.record(bound_job(asset=asset), net("J", 1, 1, [same])) for asset in ("ea_1", "ea_2")]
    self.assertNotEqual(stores[0].hkey, stores[1].hkey)
    for store in stores:
      self.assertEqual(len(self.owner.fields(store.hkey)["checkpoint"]["rows"]), 1)

  def test_same_target_in_another_engagement_is_another_record(self):
    other = ChainstoreOwner()
    other.store.update({(h, k.replace(ENGAGEMENT, OTHER_ENGAGEMENT)): v for (h, k), v in other.store.items()})
    self.owner.store.update(other.store)
    first = self.record(bound_job(), net("J", 1, 1, [F]))
    second = self.record(bound_job("K", engagement=OTHER_ENGAGEMENT), net("K", 1, 2, [F]))
    self.assertNotEqual(first.hkey, second.hkey)
    self.assertEqual(self.owner.fields(first.hkey)["checkpoint"]["rows"][F_KEY]["job_ids"], ["J"])
    self.assertEqual(self.owner.fields(second.hkey)["checkpoint"]["rows"][F_KEY]["job_ids"], ["K"])


class LedgerFinalizationOwner(FinalizationOwner):
  """A bound network job finalized for real; the chainstore also keeps tenancy and ledger hkeys."""

  def __init__(self, findings, **kwargs):
    super().__init__(**kwargs)
    self.cfg_llm_agent = {"ENABLED": False}
    self.ledger = ChainstoreOwner()
    self.findings = findings
    self.now = 100
    report = self.r1fs.values["worker-report"]
    report.update(completed_tests=["scan_ports_step_completed"],
                  scan_metrics={"connection_outcomes": {"connected": 1}})
    self.r1fs.values["config"].update(enabled_features=[HTTP], excluded_features=[])

  def time(self):
    return self.now

  def start(self, job_id):
    self.job = {**deepcopy(self.job), "job_id": job_id, "job_status": "RUNNING", "pass_reports": [],
                "timeline": []}

  def _compute_risk_and_findings(self, aggregated, triage=None):
    return {"score": 10, "breakdown": {}}, deepcopy(self.findings)

  def chainstore_hgetall(self, hkey):
    if hkey == self.cfg_instance_id:
      return {self.job["job_id"]: deepcopy(self.job)}
    return self.ledger.chainstore_hgetall(hkey)

  def chainstore_hget(self, hkey, key):
    if hkey == self.cfg_instance_id:
      return deepcopy(self.job) if key == self.job["job_id"] else None
    return self.ledger.chainstore_hget(hkey, key)

  def chainstore_hset(self, hkey, key, value, **kwargs):
    return self.ledger.chainstore_hset(hkey, key, value)

  def ledger_fields(self):
    return self.ledger.fields(f"deployment:engagement_findings:{TENANT}:{ENGAGEMENT}:{ASSET}")


class TestPostPassHook(unittest.TestCase):
  def test_two_single_pass_jobs_on_one_asset_are_one_row_with_both_job_ids(self):
    owner = LedgerFinalizationOwner([finding(port=443)])
    maybe_finalize_pass(owner)
    ref_j = owner.job["pass_reports"][0]
    owner.start("job-2")
    owner.now = 200
    maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    fields = owner.ledger_fields()
    self.assertEqual(fields["checkpoint"]["rows"][F_KEY]["job_ids"], ["job-1", "job-2"])
    self.assertEqual(fields["pass:job-1:1"]["pass_changes_cid"], ref_j["pass_changes_cid"])
    changes = owner.r1fs.values[ref_j["pass_changes_cid"]]
    self.assertEqual((changes["pass_report_cid"], changes["findings"][0]["finding_id"]), (ref_j["report_cid"], "f1"))
    self.assertEqual(PassReportRef.from_dict(ref_j).pass_changes_cid, ref_j["pass_changes_cid"])

  def test_job_outside_an_engagement_writes_nothing(self):
    owner = LedgerFinalizationOwner([finding(port=443)], bound=False)
    maybe_finalize_pass(owner)
    self.assertEqual(owner.ledger_fields(), {})
    self.assertNotIn("pass_changes_cid", owner.job["pass_reports"][0])

  def test_failing_hook_does_not_fail_the_pass_and_leaves_a_skipped_entry(self):
    owner = LedgerFinalizationOwner([finding(port=443)])
    with patch.object(EngagementLedgerRecorder, "store_pass_changes", side_effect=RuntimeError("r1fs down")):
      maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    self.assertEqual(len(owner.job["pass_reports"]), 1)
    self.assertEqual(owner.ledger_fields(), {"pass:job-1:1": {"skipped": True, "date_completed": 100}})

  def test_pass_report_stored_on_retry_replaces_the_skipped_entry_and_is_folded_once(self):
    owner = LedgerFinalizationOwner([finding(port=443)])
    with patch.object(ArtifactRepository, "put_pass_report", return_value=None):
      maybe_finalize_pass(owner)
    self.assertEqual(owner.ledger_fields(), {"pass:job-1:1": {"skipped": True, "date_completed": 100}})
    maybe_finalize_pass(owner)
    fields = owner.ledger_fields()
    self.assertFalse(fields["pass:job-1:1"].get("skipped"))
    self.assertEqual(fields["checkpoint"]["rows"][F_KEY]["times_seen"], 1)


class TestArchiveCarriesPassChangesCid(unittest.TestCase):
  def test_archive_builder_copies_the_cid_from_each_ref(self):
    from . import test_api
    helper = test_api.TestPhase3Archive("test_archive_written_to_r1fs")
    Plugin = helper._get_plugin_class()
    plugin, job_specs, _, _ = helper._build_archive_plugin(pass_count=2)
    job_specs["pass_reports"][1]["pass_changes_cid"] = "QmChanges2"
    Plugin._build_job_archive(plugin, "test-job", job_specs)
    passes = plugin.r1fs.add_json.call_args[0][0]["passes"]
    self.assertNotIn("pass_changes_cid", passes[0])
    self.assertEqual(passes[1]["pass_changes_cid"], "QmChanges2")


# -- dispatch 2b: exposure, the read endpoint, tenant delete, job purge, data maintenance -------------

class TestPassChangesExposure(unittest.TestCase):
  def test_network_pass_records_its_open_ports_and_services_and_webapp_none(self):
    changes = pass_changes(
      job_id="J", pass_nr=1, date_completed=1, scan_type="network", pass_report_cid="pr", flat_findings=[],
      aggregated={"open_ports": [443, 22, 22], "port_protocols": {"22": "ssh"}, "completed_tests": []},
      pass_metrics=None, abort_state=None, job_config={}, completed_ranges=[])
    self.assertEqual(changes["exposure"], [{"port": 22, "service": "ssh"}, {"port": 443, "service": None}])
    self.assertEqual(web("J", 1, 1)["exposure"], [])


def cid(number):
  return "Qm" + str(number).rjust(44, "1").replace("0", "A")


class LedgerFiles:
  """R1FS as the artifact repository sees it."""

  def __init__(self):
    self.json = {}
    self.deleted = []
    self.refuse = set()
    self.reads = 0

  def get_json(self, reference, **kwargs):
    self.reads += 1
    return deepcopy(self.json.get(reference))

  def delete(self, reference, **kwargs):
    if reference in self.refuse:
      return False
    self.deleted.append(reference)
    return self.json.pop(reference, None) is not None


class _EngagementPlugin(unittest.TestCase):
  """The real plugin endpoints over the tenancy fixture of `test_tenant_delete` (one network engagement
  asset `ea_1` at 192.0.2.10); ledger passes are written by the recorder as the post-pass hook does."""

  @classmethod
  def setUpClass(cls):
    from . import test_tenant_delete
    cls.fixture = test_tenant_delete.TestTenantDelete
    cls.fixture.setUpClass.__func__(cls)

  def upload(self, *args, **kwargs):
    return self.fixture.upload(self, *args, **kwargs)

  def refused(self, result, status, error):
    self.fixture.refused(self, result, status, error)

  def setUp(self):
    self.fixture.setUp(self)
    self.plugin.time = lambda: 10 * 86400
    self.files = LedgerFiles()
    self.plugin._get_artifact_repository = lambda: self.files
    self.engagement = self.plugin.list_engagements(self.actor, self.tenant)["data"]["engagements"][0]["engagementId"]
    self.cids = 0

  def store(self, asset="ea_1", engagement=None, tenant=None):
    return EngagementLedgerStore(self.plugin, "deployment", tenant or self.tenant, engagement or self.engagement, asset)

  def put_changes(self, changes):
    self.cids += 1
    self.files.json[cid(self.cids)] = changes
    return cid(self.cids)

  def other_tenant(self, request_id=None):
    """A second tenant with one network engagement on the same target; `(tenant_id, engagement_id)`.
    The engagement id comes from the request id, so the same `request_id` gives the same id."""
    self.storage.account("initial2")
    request = str(uuid4())
    terms = {**install_contract(self.plugin, ref="doc-other"), "contract_ref": "doc-other"}
    prepared = self.plugin.prepare_tenant(self.actor, request, "Other", "other", "initial2", **terms)
    self.assertTrue(prepared["success"], prepared)
    other = prepared["data"]["tenantId"]
    self.storage.grant("initial2", other)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    asset = register_asset(self.plugin, self.actor, other, {"kind": "network", "address": "192.0.2.10"})
    created = self.plugin.create_engagement(self.actor, other, request_id or str(uuid4()), "Other",
                                            "2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z",
                                            {"client_name": "Other"}, [pick(asset)], [])
    self.assertTrue(created["success"], created)
    return other, created["data"]["engagementId"]

  def record(self, changes, **kwargs):
    """Entry and fold, as the hook writes them."""
    store = self.store(**kwargs)
    EngagementLedgerRecorder(self.plugin, store, changes["scan_type"]).record_pass(
      self.files, job_id=changes["job_id"], pass_nr=changes["pass_nr"], date_completed=changes["date_completed"],
      pass_report_cid=changes["pass_report_cid"], pass_changes_cid=self.put_changes(changes))
    return store

  def entry_only(self, changes, late=False, **kwargs):
    """A pass entry whose writer has not folded yet."""
    self.store(**kwargs).put_entry(changes["job_id"], changes["pass_nr"], {
      "date_completed": changes["date_completed"], "scan_type": changes["scan_type"],
      "pass_report_cid": changes["pass_report_cid"], "pass_changes_cid": self.put_changes(changes), "late": late})

  def fields(self, store=None):
    hkey = (store or self.store()).hkey
    return {key: value for (bucket, key), value in self.storage.data.items() if bucket == hkey}

  def read(self, actor=None, tenant=None, engagement=None, **kwargs):
    return self.plugin.list_engagement_findings(actor or self.actor, tenant or self.tenant,
                                                engagement or self.engagement, **kwargs)

  def rows(self, **kwargs):
    result = self.read(**kwargs)
    self.assertTrue(result["success"], result)
    return result["data"]


class TestListEngagementFindings(_EngagementPlugin):
  def test_rows_in_the_contract_shape_with_triage_joined_at_read_and_null_when_none(self):
    from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
    self.record(net("J", 1, 1, [F, G]))
    repo = JobStateRepository(self.plugin)
    self.storage.data[(repo.host_triage_hkey(self.tenant), repo.host_triage_key("192.0.2.10", "f1"))] = {
      "tenant_id": self.tenant, "host": "192.0.2.10", "finding_id": "f1", "status": "accepted_risk", "review_at": 5}
    data = self.rows()
    self.assertEqual((data["tenantId"], data["engagementId"], data["nextCursor"], data["replayPending"]),
                     (self.tenant, self.engagement, None, []))
    self.assertEqual(data["gapState"], {"ea_1": None})
    first, second = data["rows"]
    self.assertEqual(first, {
      "engagementAssetId": "ea_1", "findingId": "f1", "occurrence": 0,
      "firstSeen": {"jobId": "J", "passNr": 1, "at": 1}, "episodeOpened": {"jobId": "J", "passNr": 1, "at": 1},
      "lastSeen": {"jobId": "J", "passNr": 1, "at": 1}, "lastTested": {"jobId": "J", "passNr": 1, "at": 1},
      "timesSeen": 1, "jobIds": ["J"], "missedStreak": 0, "notObservedSince": None, "lastCoverageGap": None,
      "reappearedCount": 0,
      "currentVersion": {"findingSignature": "s1", "title": "title f1", "severity": "HIGH",
                         "firstPassReportCid": "pr-J-1", "lastPassReportCid": "pr-J-1"},
      "triage": {"status": "accepted_risk", "effectiveStatus": "reopened"}})
    self.assertEqual((second["findingId"], second["triage"]), ("f2", None))

  def test_cross_tenant_and_cross_engagement_reads_are_refused_with_one_code(self):
    self.record(net("J", 1, 1, [F]))
    other, foreign = self.other_tenant()
    self.record(net("K", 1, 2, [G]), engagement=foreign, tenant=other)
    self.refused(self.read(tenant=other), 404, "not_found")                   # this engagement, other tenant
    self.refused(self.read(engagement=foreign), 404, "not_found")             # other tenant's engagement
    # A tenant the caller is no member of reads as absent, as `get_engagement` answers it.
    self.refused(self.read(actor={"account_id": "initial2"}), 404, "not_found")
    self.assertEqual([row["jobIds"] for row in self.rows(actor={"account_id": "initial"})["rows"]], [["J"]])
    self.assertEqual([row["jobIds"] for row in self.rows(tenant=other, engagement=foreign)["rows"]], [["K"]])

  def test_an_asset_outside_the_engagement_is_not_found_and_malformed_filters_are_invalid(self):
    self.refused(self.read(engagement_asset_id="ea_2"), 404, "not_found")
    self.assertEqual(self.rows(engagement_asset_id="ea_1")["rows"], [])
    for bad in ({"limit": 0}, {"limit": 501}, {"limit": "5"}, {"state": "fixed"}, {"severity": "HIGH"},
                {"cursor": "not-a-cursor"}, {"engagement_asset_id": 1}):
      self.refused(self.read(**bad), 400, "invalid_request")

  def test_paging_cursor_stays_stable_while_rows_change(self):
    self.record(net("J", 1, 1, [finding("f1"), finding("f2"), finding("f3")]))
    page = self.rows(limit=2)
    self.assertEqual([row["findingId"] for row in page["rows"]], ["f1", "f2"])
    self.record(net("J", 2, 2, [finding("f0")]))  # a row sorting before the cursor appears
    rest = self.rows(limit=2, cursor=page["nextCursor"])
    self.assertEqual(([row["findingId"] for row in rest["rows"]], rest["nextCursor"]), (["f3"], None))

  def test_state_and_severity_filters(self):
    self.record(net("J", 1, 1, [F, G]))
    self.record(net("J", 2, 2, [finding("f2", "s2b", port=22, probe="_service_info_ssh", severity="LOW")]))
    self.assertEqual([r["findingId"] for r in self.rows(state="not_observed")["rows"]], ["f1"])
    self.assertEqual([r["findingId"] for r in self.rows(state="active")["rows"]], ["f2"])
    self.assertEqual([r["findingId"] for r in self.rows(severity=["HIGH"])["rows"]], ["f1"])
    self.assertEqual(self.rows(state="active", severity=["HIGH"])["rows"], [])

  def test_a_read_folds_entries_not_yet_in_the_checkpoint_and_writes_nothing(self):
    self.record(net("J", 1, 1, [F]))
    self.entry_only(net("J", 2, 2, [F]))
    writes = len(self.storage.writes)
    first, second = self.rows(), self.rows()
    self.assertEqual(first["rows"][0]["timesSeen"], 2)
    self.assertEqual(first, second)
    self.assertEqual(len(self.storage.writes), writes)
    self.assertEqual(self.fields()["checkpoint"]["included"], {"J": 1})

  def test_an_overtaken_final_pass_is_repaired_by_the_first_read_and_the_next_replays_nothing(self):
    self.record(net("J", 1, 1, [F, G]))
    self.record(net("K", 1, 3, [F]))      # K's checkpoint moves `through` to 3 ...
    self.entry_only(net("J", 2, 2, [G]))  # ... past J/2, whose writer saw `through` 1 and never folded
    expected, _ = in_order(net("J", 1, 1, [F, G]), net("J", 2, 2, [G]), net("K", 1, 3, [F]))
    reads = self.files.reads
    data = self.rows()
    self.assertEqual(self.files.reads - reads, 3)  # one replay, its result written as the repair
    self.assertEqual(self.fields()["checkpoint"]["rows"], expected["rows"])
    self.assertEqual(self.fields()["checkpoint"]["included"], {"J": 2, "K": 1})
    self.assertEqual([row["timesSeen"] for row in data["rows"]], [2, 2])
    writes, reads = len(self.storage.writes), self.files.reads
    self.assertEqual(self.rows(), data)
    self.assertEqual((len(self.storage.writes), self.files.reads), (writes, reads))

  def test_a_replay_over_the_cap_is_reported_pending_writes_nothing_and_data_maintenance_runs_it(self):
    from extensions.business.cybersec.red_mesh.services import engagement_findings
    self.record(net("J", 1, 1, [F]))
    self.record(net("K", 1, 3, [F]))
    self.entry_only(net("J", 2, 2))
    writes = len(self.storage.writes)
    with patch.object(engagement_findings, "REPLAY_READ_CAP", 1):
      data = self.rows()
    self.assertEqual(data["replayPending"], ["ea_1"])
    self.assertIsNone(data["rows"][0]["notObservedSince"])  # J/2 served as a late pass meanwhile
    self.assertEqual(len(self.storage.writes), writes)
    reads = self.files.reads
    done = self.plugin.maintain_redmesh_engagement_ledgers(self.actor, True)
    self.assertEqual(done["data"]["outcomes"], [{"hkey": self.store().hkey, "outcome": "folded", "skipped_filled": 0}])
    self.assertEqual(self.files.reads - reads, 3)  # one uncapped replay, reused for the write
    with patch.object(engagement_findings, "REPLAY_READ_CAP", 1):
      data = self.rows()
    self.assertEqual(data["replayPending"], [])
    self.assertEqual(self.fields()["checkpoint"]["included"], {"J": 2, "K": 1})

  def test_revoked_and_superseded_engagements_keep_their_records_and_stay_readable(self):
    self.record(net("J", 1, 1, [F]))
    before = self.fields()
    asset = self.plugin.get_engagement(self.actor, self.tenant, self.engagement)["data"]["engagement"]["assets"][0]
    successor = self.plugin.create_engagement(
      self.actor, self.tenant, str(uuid4()), "Q4 bis", "2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z",
      {"client_name": "Example"}, [pick(asset["assetId"])], [self.upload("Rules v2", raw=b"%PDF-1.7\n%v2\n%%EOF\n")],
      supersedes=self.engagement)
    self.assertTrue(successor["success"], successor)
    self.assertTrue(self.plugin.revoke_engagement(self.actor, self.tenant, self.engagement, "replaced")["success"])
    self.assertEqual(self.fields(), before)
    self.assertEqual([row["jobIds"] for row in self.rows()["rows"]], [["J"]])
    self.assertEqual(self.rows(engagement=successor["data"]["engagementId"])["rows"], [])


class TestTenantDeleteCascade(_EngagementPlugin):
  def test_tenant_delete_deletes_the_pass_changes_files_then_tombstones_every_field(self):
    store = self.record(net("J", 1, 1, [F]))
    self.record(net("J", 2, 2))
    store.put_entry("J", 3, {"skipped": True})
    files = [entry["pass_changes_cid"] for key, entry in self.fields().items() if key.startswith("pass:J:") and "late" in entry]
    order = []
    real_hset, real_delete = self.plugin.chainstore_hset, self.files.delete
    self.plugin.chainstore_hset = lambda **kw: order.append(("hset", kw["key"])) or real_hset(**kw)
    self.files.delete = lambda ref, **kw: order.append(("delete", ref)) or real_delete(ref, **kw)
    self.fixture.remove_members(self)
    self.assertTrue(self.plugin.delete_tenant(self.actor, self.tenant)["success"])
    self.assertEqual(sorted(self.files.deleted), sorted(files))
    self.assertTrue(set(self.fields()) >= {"checkpoint", "pass:J:1", "pass:J:2", "pass:J:3", "events:J:1"})
    self.assertEqual({value for value in self.fields().values()}, {None})
    ledger = [step for step in order if step[0] == "delete" or step[1] in self.fields()]
    self.assertEqual([step[0] for step in ledger], ["delete"] * 2 + ["hset"] * len(self.fields()))
    self.assertNotIn("engagement", self.fixture.tenancy_rows(self))

  def test_a_failed_file_delete_stops_before_the_tombstones_and_a_retry_finishes(self):
    self.record(net("J", 1, 1, [F]))
    changes_cid = self.fields()["pass:J:1"]["pass_changes_cid"]
    self.files.refuse = {changes_cid}
    self.fixture.remove_members(self)
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    self.assertIsNotNone(self.fields()["checkpoint"])
    self.assertIn("engagement", self.fixture.tenancy_rows(self))
    self.files.refuse = set()
    self.assertTrue(self.plugin.delete_tenant(self.actor, self.tenant)["success"])
    self.assertEqual(self.files.deleted, [changes_cid])
    self.assertEqual({value for value in self.fields().values()}, {None})


class TestForcePurgeKeepsPassChanges(unittest.TestCase):
  def test_force_purge_deletes_the_jobs_files_but_not_its_pass_changes_artifacts(self):
    from extensions.business.cybersec.red_mesh.services.control import _force_purge_job_locked
    files = LedgerFiles()
    files.json.update({"QmReport": {}, "QmChanges": {}, "QmConfig": {}})

    class Owner(ChainstoreOwner):
      cfg_instance_id = "jobs"

      def _get_artifact_repository(self):
        return files

    raw = {"job_id": "J", "job_config_cid": "QmConfig",
           "pass_reports": [{"pass_nr": 1, "report_cid": "QmReport", "pass_changes_cid": "QmChanges"}]}
    _force_purge_job_locked(Owner(), "J", raw, [])
    self.assertEqual(sorted(files.deleted), ["QmConfig", "QmReport"])


class TestLedgerDataMaintenance(_EngagementPlugin):
  def scan(self):
    rows, cursor = {}, {"hkey_index": 0, "offset": 0}
    while cursor:
      page = self.plugin.export_redmesh_records(self.actor, cursor["hkey_index"], cursor["offset"], 50)
      self.assertTrue(page["success"], page)
      rows.update({(row["hkey"], row["field"]): row for row in page["data"]["rows"]})
      cursor = page["data"]["next"]
    return rows

  def test_ledger_fields_are_registered_current_and_keep_only_their_pass_changes_files(self):
    from extensions.business.cybersec.red_mesh.services.data_maintenance import Inventory
    self.record(net("J", 1, 1, [F]))
    hkey = self.store().hkey
    rows = self.scan()
    ledger = {field: row for (name, field), row in rows.items() if name == hkey}
    self.assertEqual(set(ledger), {"pass:J:1", "checkpoint", "events:J:1"})
    self.assertEqual({row["class"] for row in ledger.values()}, {"current"})
    changes_cid = self.fields()["pass:J:1"]["pass_changes_cid"]
    self.assertEqual(ledger["pass:J:1"]["cids"], [{"cid": changes_cid, "role": "pass_changes_cid", "withheld": False}])
    kept, complete = Inventory(self.plugin, "deployment", self.files.get_json).kept_files()
    self.assertTrue(complete)
    self.assertIn(changes_cid, kept)

  def test_maintenance_fills_a_missing_pass_once_a_later_entry_is_a_day_old_then_folds(self):
    self.record(net("J", 1, 1, [F]))
    self.entry_only(net("J", 3, 9 * 86400 + 1, [F]))  # J/2 never written: its launcher died
    self.entry_only(net("K", 2, 9 * 86400 + 100))      # K/1 missing too, and K/2 stays younger than a day
    done = self.plugin.maintain_redmesh_engagement_ledgers(self.actor, True)
    self.assertEqual(done["data"]["outcomes"], [{"hkey": self.store().hkey, "outcome": "current", "skipped_filled": 0}])
    self.plugin.time = lambda: 10 * 86400 + 2
    done = self.plugin.maintain_redmesh_engagement_ledgers(self.actor, True)
    self.assertEqual(done["data"]["outcomes"][0]["skipped_filled"], 1)
    fields = self.fields()
    self.assertEqual(fields["pass:J:2"], {"skipped": True})
    self.assertNotIn("pass:K:1", fields)
    self.assertEqual((fields["checkpoint"]["included"], fields["checkpoint"]["rows"][F_KEY]["times_seen"]),
                     ({"J": 3}, 2))
    self.refused(self.plugin.maintain_redmesh_engagement_ledgers(self.actor, False), 400, "invalid_request")


class TestFixRound1(_EngagementPlugin):
  """Findings round 1 (RM-121 phase 2)."""

  def test_the_same_engagement_id_in_two_tenants_keeps_two_ledgers(self):
    request = self.engagement[3:]  # the id derives from the request id: reuse it in tenant B
    other, same = self.other_tenant(request_id=request)
    self.assertEqual(same, self.engagement)
    self.record(net("J", 1, 1, [F]))
    self.record(net("K", 1, 2, [G]), tenant=other)
    self.assertNotEqual(self.store().hkey, self.store(tenant=other).hkey)
    self.assertEqual([r["jobIds"] for r in self.rows()["rows"]], [["J"]])
    self.assertEqual([r["jobIds"] for r in self.rows(tenant=other)["rows"]], [["K"]])
    self.storage.account("initial2", memberships=[])
    self.assertTrue(self.plugin.delete_tenant(self.actor, other)["success"])
    self.assertEqual({v for v in self.fields(self.store(tenant=other)).values()}, {None})
    self.assertEqual(self.fields()["checkpoint"]["rows"][F_KEY]["job_ids"], ["J"])
    self.assertEqual([r["jobIds"] for r in self.rows()["rows"]], [["J"]])

  def unreadable(self, changes):
    """A pass entry whose artifact R1FS answers None for (gone, or a transient failure); returns the CID
    and the artifact so a test can make it readable again."""
    self.entry_only(changes)
    cid_ = self.fields()[f"pass:{changes['job_id']}:{changes['pass_nr']}"]["pass_changes_cid"]
    return cid_, self.files.json.pop(cid_)

  def test_an_unreadable_artifact_on_read_serves_the_stored_checkpoint_as_pending(self):
    self.record(net("J", 1, 1, [F]))
    self.unreadable(net("J", 2, 2, [F]))
    writes = len(self.storage.writes)
    data = self.rows()
    self.assertEqual((data["replayPending"], data["rows"][0]["timesSeen"]), (["ea_1"], 1))
    self.assertEqual(len(self.storage.writes), writes)

  def test_a_transient_none_in_the_hook_fails_the_fold_and_the_next_fold_counts_the_pass_once(self):
    from extensions.business.cybersec.red_mesh.services.engagement_ledger import LedgerFoldError
    self.record(net("J", 1, 1, [F]))
    store = self.store()
    recorder = EngagementLedgerRecorder(self.plugin, store, "network")
    j2 = net("J", 2, 2, [F])
    self.files.json[cid(99)] = None
    with self.assertRaises(LedgerFoldError):  # the hook's wrapper logs it; the pass still finalizes
      recorder.record_pass(self.files, job_id="J", pass_nr=2, date_completed=2, pass_report_cid="pr-J-2",
                           pass_changes_cid=cid(99))
    self.assertEqual(self.fields()["checkpoint"]["included"], {"J": 1})
    self.files.json[cid(99)] = j2  # R1FS answers again
    self.record(net("J", 3, 3, [F]))
    checkpoint = self.fields()["checkpoint"]
    self.assertEqual((checkpoint["included"], checkpoint["rows"][F_KEY]["times_seen"]), ({"J": 3}, 3))

  def test_only_data_maintenance_declares_an_artifact_lost_and_only_after_24_hours(self):
    logs = []
    self.plugin.P = lambda *args, **kwargs: logs.append(args[0])
    self.record(net("J", 1, 1, [F]))
    self.unreadable(net("J", 2, 10 * 86400 - 100, [F]))  # completed 100 s before `now`
    done = self.plugin.maintain_redmesh_engagement_ledgers(self.actor, True)
    self.assertEqual(done["data"]["outcomes"][0]["outcome"], "failed")
    self.assertEqual(self.fields()["checkpoint"]["included"], {"J": 1})
    self.plugin.time = lambda: 11 * 86400
    done = self.plugin.maintain_redmesh_engagement_ledgers(self.actor, True)
    self.assertEqual(done["data"]["outcomes"][0]["outcome"], "folded")
    checkpoint = self.fields()["checkpoint"]
    self.assertEqual((checkpoint["included"], checkpoint["rows"][F_KEY]["times_seen"]), ({"J": 2}, 1))
    self.assertTrue(any("declared lost" in line for line in logs))
    self.assertEqual(self.rows()["replayPending"], [])  # unwedged

  def test_a_transient_artifact_read_error_still_fails_the_fold(self):
    from extensions.business.cybersec.red_mesh.services.engagement_ledger import LedgerFoldError
    entries = {("J", 1): {"date_completed": 1, "scan_type": "network", "pass_report_cid": "pr",
                          "pass_changes_cid": "pc", "late": False}}
    def down(cid):
      raise TimeoutError("r1fs")
    with self.assertRaises(LedgerFoldError):
      fold(None, entries, down, asset_id=ASSET)


class TestFailedWorkerPortSet(unittest.TestCase):
  def test_a_port_in_a_failed_workers_non_contiguous_slice_is_a_gap(self):
    from extensions.business.cybersec.red_mesh.services.finalization import _completed_port_ranges
    workers = {"a": {"start_port": 22, "end_port": 8080, "target_ports": [22, 443]},
               "b": {"start_port": 22, "end_port": 8080, "target_ports": [80, 8080]}}
    reports = {"a": {"start_port": 22, "end_port": 8080}}  # b's report never came
    ranges = _completed_port_ranges(reports, workers)
    self.assertEqual(ranges, [[22, 22], [443, 443]])
    on_80, on_443 = finding("f80", "s80", port=80), finding("f443", "s443", port=443)
    state, _ = run(net("J", 1, 1, [on_80, on_443]))
    state, _ = run(net("J", 2, 2, completed_ranges=ranges), state=state)
    self.assertEqual(state["rows"]["f80:0"]["last_coverage_gap"], ref("J", 2, 2))
    self.assertEqual(state["rows"]["f443:0"]["not_observed_since"], ref("J", 2, 2))
    self.assertEqual(_completed_port_ranges({"a": {"start_port": 1, "end_port": 9}}, {"a": {}}), [[1, 9]])


class TestHookPaths(unittest.TestCase):
  def test_an_unconfirmed_job_record_write_keeps_the_job_specs_and_the_pass_finalizes(self):
    owner = LedgerFinalizationOwner([finding(port=443)])
    real = FinalizationOwner._write_job_record

    def write(self, key, value, context=None, **kwargs):
      return None if context == "finalize_engagement_ledger" else real(self, key, value, **kwargs)
    with patch.object(LedgerFinalizationOwner, "_write_job_record", write):
      maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    self.assertEqual(owner.ledger_fields()["checkpoint"]["rows"][F_KEY]["job_ids"], ["job-1"])

  def test_failed_aggregation_and_an_unstored_aggregated_report_leave_skipped_entries(self):
    owner = LedgerFinalizationOwner([finding(port=443)])
    with patch.object(LedgerFinalizationOwner, "_get_aggregated_report", return_value={}):
      maybe_finalize_pass(owner)
    self.assertEqual(owner.ledger_fields(), {"pass:job-1:1": {"skipped": True, "date_completed": 100}})
    owner = LedgerFinalizationOwner([finding(port=443)])
    with patch.object(ArtifactRepository, "put_json", return_value=None):
      maybe_finalize_pass(owner)
    self.assertEqual(owner.ledger_fields(), {"pass:job-1:1": {"skipped": True, "date_completed": 100}})

  def test_engagement_redaction_leaves_the_ledger_unchanged(self):
    from extensions.business.cybersec.red_mesh.services.engagement_deletion import delete_engagement_data
    owner = LedgerFinalizationOwner([finding(port=443)])
    maybe_finalize_pass(owner)
    before = owner.ledger_fields()
    delete_engagement_data(job_id="job-1", job_specs=deepcopy(owner.job), artifact_repo=ArtifactRepository(owner))
    self.assertEqual(owner.ledger_fields(), before)


if __name__ == "__main__":
  unittest.main()


class TestLedgerArtifactReadTimeout(unittest.TestCase):

  def test_ledger_artifact_reads_pass_a_short_r1fs_timeout(self):
    from extensions.business.cybersec.red_mesh.repositories.artifacts import ArtifactRepository
    from extensions.business.cybersec.red_mesh.services.engagement_ledger_store import (
      ARTIFACT_READ_TIMEOUT, artifact_loader,
    )
    calls = []

    class _R1fs:
      def get_json(self, cid, **kwargs):
        calls.append((cid, kwargs))
        return None

    owner = type("Owner", (), {"r1fs": _R1fs()})()
    self.assertIsNone(artifact_loader(ArtifactRepository(owner))("Qm1"))
    self.assertEqual(calls, [("Qm1", {"timeout": ARTIFACT_READ_TIMEOUT})])
    self.assertLess(ARTIFACT_READ_TIMEOUT, 90)
