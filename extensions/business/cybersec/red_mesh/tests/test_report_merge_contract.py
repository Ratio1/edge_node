"""RM-214: the report merge is total over every declared aggregation field.

`_get_aggregated_report` merges thread reports (worker close) and node
reports (finalize) with one rule. These tests build realistic, non-empty
values for every field a worker class declares, so a field whose shape the
merge cannot handle fails here before it ships. They also pin the
all-or-nothing contract: a merge failure yields no report, a worker close
publishes `report_unavailable`, and finalize fails the job.
"""

import json
import unittest
from copy import deepcopy
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

from .test_finalization_aggregation import _Host


def _finding(title, severity="HIGH"):
  return {"title": title, "severity": severity, "evidence": f"synthetic evidence for {title}"}


def _thread(idx, ports, open_ports, with_correlation=True):
  """A thread status in `get_status()` key order, correlation findings before metrics."""
  status = {
    "start_port": ports[0],
    "end_port": ports[-1],
    "ports_scanned": len(ports),
    "open_ports": list(open_ports),
    "service_info": {
      str(p): {"_service_info_x": {"findings": [_finding(f"svc-{idx}-{p}")]}} for p in open_ports
    },
    "web_tests_info": {
      str(p): {"_web_test_x": {"findings": [_finding(f"web-{idx}-{p}")]}} for p in open_ports
    },
    "completed_tests": [f"test-{idx}", "shared-test"],
    "port_protocols": {str(p): "http" for p in open_ports},
    "scan_metadata": {"banner_unverified": {str(p): True for p in open_ports}},
    "correlation_findings": [_finding(f"corr-{idx}")] if with_correlation else [],
    "reference_data": {"note": f"thread-{idx}"},
    "scan_metrics": {
      "probes_attempted": 2,
      "coverage": {"ports_in_range": len(ports), "ports_scanned": len(ports)},
    },
  }
  return status


def _per_thread(statuses):
  return {f"RM-{i}": s for i, s in enumerate(statuses)}


class TestThreadMerge(unittest.TestCase):

  def _merge(self, statuses, **kwargs):
    host = _Host()
    report = host._get_aggregated_report(_per_thread(statuses), **kwargs)
    # The merge swallows exceptions into a log line; a clean merge never logs one.
    errors = [c for c in host.P.call_args_list if "Error during report aggregation" in str(c)]
    self.assertEqual(errors, [], "merge raised and was swallowed")
    return report

  def test_three_threads_all_with_correlation_findings(self):
    statuses = [
      _thread(0, range(1, 11), [22]),
      _thread(1, range(11, 21), [25]),
      _thread(2, range(21, 31), [587]),
    ]
    report = self._merge(statuses)
    self.assertEqual(report["ports_scanned"], 30)
    self.assertEqual(report["open_ports"], [22, 25, 587])
    self.assertEqual(report["start_port"], 1)
    self.assertEqual(report["end_port"], 30)
    self.assertEqual(sorted(f["title"] for f in report["correlation_findings"]),
                     ["corr-0", "corr-1", "corr-2"])
    self.assertEqual(set(report["service_info"]), {"22", "25", "587"})
    self.assertEqual(len(report["local_worker_ids"]), 3)
    self.assertNotIn("local_worker_id", report)

  def test_first_thread_holds_the_dict_later_threads_empty(self):
    statuses = [
      _thread(0, range(1, 11), [22]),
      _thread(1, range(11, 21), [25], with_correlation=False),
      _thread(2, range(21, 31), [587], with_correlation=False),
    ]
    report = self._merge(statuses)
    self.assertEqual(report["ports_scanned"], 30)
    self.assertEqual(report["open_ports"], [22, 25, 587])
    self.assertEqual([f["title"] for f in report["correlation_findings"]], ["corr-0"])

  def test_two_sort_keyed_node_reports_keep_both_nodes(self):
    nodes = [
      _thread(0, range(1, 11), [22]),
      _thread(1, range(11, 21), [25]),
    ]
    # R1FS stores node reports with sorted keys: correlation_findings sorts early.
    nodes = [json.loads(json.dumps(n, sort_keys=True)) for n in nodes]
    report = self._merge([nodes[0], nodes[1]])
    self.assertEqual(report["open_ports"], [22, 25])
    self.assertEqual(report["ports_scanned"], 20)
    self.assertEqual(set(report["service_info"]), {"22", "25"})
    self.assertEqual(set(report["web_tests_info"]), {"22", "25"})
    self.assertEqual(sorted(f["title"] for f in report["correlation_findings"]), ["corr-0", "corr-1"])

  def test_merge_failure_returns_no_report(self):
    host = _Host()
    statuses = [_thread(0, range(1, 11), [22]), _thread(1, range(11, 21), [25])]
    with patch.object(host, "merge_objects_deep", side_effect=RuntimeError("boom")):
      report = host._get_aggregated_report(_per_thread(statuses))
    self.assertEqual(report, {})

  def test_null_field_does_not_erase_merged_findings(self):
    # A peer report with `correlation_findings: null` has no data for the field.
    host = _Host()
    bad = _thread(1, range(11, 21), [25])
    bad["correlation_findings"] = None
    report = host._get_aggregated_report(_per_thread([_thread(0, range(1, 11), [22]), bad]))
    self.assertEqual([f["title"] for f in report["correlation_findings"]], ["corr-0"])

  def test_type_mismatch_fails_instead_of_overwriting(self):
    host = _Host()
    bad = _thread(1, range(11, 21), [25])
    bad["correlation_findings"] = "not-a-list"
    report = host._get_aggregated_report(_per_thread([_thread(0, range(1, 11), [22]), bad]))
    self.assertEqual(report, {})

  def test_nested_null_does_not_erase_findings(self):
    # Same port and probe in two threads (MIRROR), the second with `findings: null`.
    host = _Host()
    a = _thread(0, range(1, 11), [22])
    b = _thread(1, range(11, 21), [])
    b["service_info"] = {"22": {"_service_info_x": {"findings": None}}}
    report = host._get_aggregated_report(_per_thread([a, b]))
    titles = [f["title"] for f in report["service_info"]["22"]["_service_info_x"]["findings"]]
    self.assertEqual(titles, ["svc-0-22"])

  def test_nested_type_mismatch_fails_instead_of_overwriting(self):
    host = _Host()
    a = _thread(0, range(1, 11), [22])
    b = _thread(1, range(11, 21), [])
    b["service_info"] = {"22": {"_service_info_x": {"findings": "oops"}}}
    report = host._get_aggregated_report(_per_thread([a, b]))
    self.assertEqual(report, {})

  def test_merge_failure_log_carries_no_report_content(self):
    # Thread reports are merged before credential redaction, so the failure
    # log names the field and types only, never report bodies.
    host = _Host()
    good = _thread(0, range(1, 11), [22])
    good["accepted_credentials"] = ["admin:hunter2-secret"]
    bad = _thread(1, range(11, 21), [25])
    bad["correlation_findings"] = "not-a-list"
    host._get_aggregated_report(_per_thread([good, bad]))
    logged = " ".join(str(c) for c in host.P.call_args_list)
    self.assertIn("correlation_findings", logged)
    self.assertNotIn("hunter2-secret", logged)
    self.assertNotIn("svc-0-22", logged)


def _graybox_status(idx):
  return {
    "graybox_results": {f"/p{idx}": {"_graybox_t": {"findings": [_finding(f"gb-{idx}")]}}},
    "service_info": {f"80{idx}": {"_svc": {"findings": [_finding(f"gsvc-{idx}")]}}},
    "web_tests_info": {f"80{idx}": {"_web": {"findings": [_finding(f"gweb-{idx}")]}}},
    "open_ports": [80 + idx],
    "completed_tests": [f"gt-{idx}", "shared"],
    "port_protocols": {f"80{idx}": "http"},
    "correlation_findings": [_finding(f"gcorr-{idx}")],
    "scan_metrics": {"probes_attempted": 1},
    "ports_scanned": [80 + idx, 90 + idx],
    "aborted": idx == 1,
    "abort_reason": "" if idx == 0 else f"reason-{idx}",
    "abort_phase": "" if idx == 0 else f"phase-{idx}",
    "abort_reason_class": "" if idx == 0 else f"class-{idx}",
  }


def _network_status(idx):
  s = _thread(idx, range(1 + idx * 10, 11 + idx * 10), [20 + idx])
  s["catch_all_withheld"] = {str(20 + idx): {"reason": f"r{idx}"}}
  s["cves_not_applicable"] = {f"CVE-2000-{idx}": {"why": "synthetic"}}
  s["port_banners"] = {str(20 + idx): f"banner-{idx}"}
  return s


class TestFieldMapContract(unittest.TestCase):
  """Every declared field, non-empty, merged in both orders, raw and R1FS-roundtripped."""

  CASES = {
    "network": (PentestLocalWorker, _network_status),
    "graybox": (GrayboxLocalWorker, _graybox_status),
  }
  # Replaced by a dedicated metrics merge after the loop; shape is checked there.
  REBUILT_AFTER_LOOP = {"scan_metrics"}

  def _assert_field(self, name, func, inputs, output):
    self.assertIn(name, output, f"{name} missing from merged report")
    out = output[name]
    values = [i[name] for i in inputs]
    if name in self.REBUILT_AFTER_LOOP:
      self.assertTrue(out)
    elif func is min:
      self.assertEqual(out, min(values))
    elif func is max:
      self.assertEqual(out, max(values))
    elif func is sum:
      self.assertEqual(out, sum(values))
    elif func is any:
      self.assertEqual(out, any(values))
    elif func is list:
      for value in values:
        for item in value:
          if isinstance(item, dict):
            self.assertIn(item["title"], [o["title"] for o in out if isinstance(o, dict)], name)
          else:
            self.assertIn(item, out, name)
    elif func is dict:
      for value in values:
        for key in value:
          self.assertIn(key, out, f"{name}.{key}")
    else:  # first-non-empty string
      self.assertEqual(out, next(v for v in values if v))

  def _run(self, worker_cls, make, *, roundtrip, reverse):
    fields = worker_cls.get_worker_specific_result_fields()
    statuses = [make(i) for i in range(3)]
    if roundtrip:
      statuses = [json.loads(json.dumps(s, sort_keys=True)) for s in statuses]
    if reverse:
      statuses.reverse()
    inputs = deepcopy(statuses)
    report = _Host()._get_aggregated_report(_per_thread(statuses), worker_cls=worker_cls)
    self.assertTrue(report, "merge returned no report")
    for name, func in fields.items():
      with self.subTest(field=name):
        self._assert_field(name, func, inputs, report)

  def test_every_declared_field_merges(self):
    for label, (worker_cls, make) in self.CASES.items():
      for roundtrip in (False, True):
        for reverse in (False, True):
          with self.subTest(worker=label, roundtrip=roundtrip, reverse=reverse):
            self._run(worker_cls, make, roundtrip=roundtrip, reverse=reverse)


class TestWorkerCloseOnMergeFailure(unittest.TestCase):

  def test_close_job_publishes_report_unavailable(self):
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    helper = TestPhase2PassFinalization()
    Plugin = helper._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "node-A"
    plugin.cfg_instance_id = "test-instance"
    plugin.global_shmem = {}
    plugin.P = MagicMock()
    plugin.json_dumps.return_value = "{}"
    plugin._normalize_job_record = MagicMock(side_effect=lambda job_id, raw: (job_id, raw))
    plugin._log_audit_event = MagicMock()
    plugin._count_all_findings = lambda report: Plugin._count_all_findings(plugin, report)
    plugin._count_nested_findings = lambda section: Plugin._count_nested_findings(section)

    host = _Host()
    statuses = [_thread(0, range(1, 11), [22]), _thread(1, range(11, 21), [25])]
    workers = {}
    for i, status in enumerate(statuses):
      w = MagicMock()
      w.get_status.return_value = status
      workers[f"RM-{i}"] = w
    plugin.scan_jobs = {"job-1": workers}

    def failing_aggregate(*args, **kwargs):
      with patch.object(host, "merge_objects_deep", side_effect=RuntimeError("boom")):
        return host._get_aggregated_report(*args, **kwargs)
    plugin._get_aggregated_report = failing_aggregate

    job_specs = {"job_id": "job-1", "target": "example.com",
                 "workers": {"node-A": {"start_port": 1, "end_port": 20}}}
    plugin.chainstore_hget.return_value = job_specs

    with patch.object(Plugin, "_mark_worker_terminal_error") as mark:
      Plugin._close_job(plugin, "job-1")

    mark.assert_called_once()
    self.assertEqual(mark.call_args.args[3], "report_unavailable")
    plugin.r1fs.add_json.assert_not_called()
    entry = job_specs["workers"]["node-A"]
    self.assertTrue(entry["finished"])
    self.assertIsNone(entry["report_cid"])


class TestFinalizeOnMergeFailure(unittest.TestCase):

  def test_empty_merge_with_node_reports_fails_job(self):
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    helper = TestPhase2PassFinalization()
    Plugin = helper._get_plugin_class()
    plugin, job_specs = helper._build_finalize_plugin()
    plugin._collect_node_reports = MagicMock(return_value={
      "worker-A": helper._sample_node_report(1, 512, [80]),
      "worker-B": helper._sample_node_report(513, 1024, [443]),
    })
    plugin._get_aggregated_report = MagicMock(return_value={})
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()
    plugin._build_job_archive = MagicMock()
    plugin._clear_live_progress = MagicMock()

    Plugin._maybe_finalize_pass(plugin)

    self.assertEqual(job_specs["job_status"], "FAILED")
    self.assertEqual(job_specs["failure_class"], "report_aggregation_failed")
    self.assertEqual(job_specs["pass_reports"], [])
    event_types = [c.args[1] for c in plugin._emit_timeline_event.call_args_list]
    self.assertIn("report_aggregation_failed", event_types)
    self.assertNotIn("finalized", event_types)
    plugin._compute_risk_and_findings.assert_not_called()


if __name__ == "__main__":
  unittest.main()


class TestWarmupRepairOnMergeFailure(unittest.TestCase):

  def test_failed_repair_keeps_the_stored_thread_reports(self):
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    Plugin = TestPhase2PassFinalization()._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "node-A"
    plugin.cfg_instance_id = "test-instance"
    raw = _per_thread([_thread(0, range(1, 11), [22])])
    raw["RM-0"]["local_worker_id"] = "RM-0"
    spec = {"job_id": "job-1", "launcher": "node-A", "workers": {"node-A": {"result": deepcopy(raw)}}}
    plugin.chainstore_hgetall.return_value = {"job-1": spec}
    plugin._normalize_job_record = MagicMock(side_effect=lambda key, value: (key, value))
    plugin._get_aggregated_report = MagicMock(return_value={})

    with patch.object(Plugin, "_write_job_record") as write:
      Plugin._PentesterApi01Plugin__post_init(plugin)

    write.assert_not_called()
    self.assertEqual(spec["workers"]["node-A"]["result"], raw)

  def _warmup_logs(self, spec, normalize=None):
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    Plugin = TestPhase2PassFinalization()._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "node-A"
    plugin.cfg_instance_id = "test-instance"
    plugin.json_dumps = lambda obj, indent=None: json.dumps(obj, default=str, indent=indent)
    plugin.trace_info.return_value = ""
    plugin.chainstore_hgetall.return_value = {"job-1": spec}
    plugin._normalize_job_record = normalize or MagicMock(side_effect=lambda key, value: (key, value))
    plugin._get_aggregated_report = MagicMock(return_value={})
    with patch.object(Plugin, "_write_job_record"):
      Plugin._PentesterApi01Plugin__post_init(plugin)
    return " ".join(str(c) for c in plugin.P.call_args_list)

  def test_warmup_log_carries_no_job_record_content(self):
    raw = {"RM-0": {"local_worker_id": "RM-0", "accepted_credentials": ["admin:hunter2-secret"]}}
    spec = {"job_id": "job-1", "launcher": "node-A", "workers": {"node-A": {"result": raw}}}
    logged = self._warmup_logs(spec)
    self.assertIn("job-1", logged)
    self.assertNotIn("hunter2-secret", logged)

  def test_warmup_invalid_record_log_carries_no_job_record_content(self):
    # The real normalizer rejects a record without a launcher: (None, None).
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    Plugin = TestPhase2PassFinalization()._get_plugin_class()
    spec = {"job_id": "job-1", "workers": {"node-A": {"result": {"accepted_credentials": ["admin:hunter2-secret"]}}}}
    plugin_normalize = lambda key, value: Plugin._normalize_job_record(MagicMock(), key, value)
    self.assertEqual(plugin_normalize("job-1", spec), (None, None))
    logged = self._warmup_logs(spec, normalize=MagicMock(side_effect=plugin_normalize))
    self.assertIn("job-1", logged)
    self.assertNotIn("hunter2-secret", logged)

  def test_warmup_error_log_carries_no_job_record_content(self):
    spec = {"job_id": "job-1", "workers": {"node-A": {"result": {"accepted_credentials": ["admin:hunter2-secret"]}}}}
    logged = self._warmup_logs(spec, normalize=MagicMock(side_effect=RuntimeError("bad record")))
    self.assertIn("bad record", logged)
    self.assertNotIn("hunter2-secret", logged)


class TestRuntimeLogsCarryNoReportContent(unittest.TestCase):
  """Thread reports are unredacted until `_close_job` persists them, and job
  records can hold raw legacy results: runtime logs carry identifiers only."""

  def _plugin(self):
    from .test_api import TestPhase2PassFinalization  # local: a module import would collect it twice
    Plugin = TestPhase2PassFinalization()._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "node-A"
    plugin.cfg_instance_id = "test-instance"
    plugin.global_shmem = {}
    plugin.json_dumps = lambda obj, indent=None: json.dumps(obj, default=str, indent=indent)
    plugin.trace_info.return_value = ""
    return Plugin, plugin

  def _logged(self, plugin):
    return " ".join(str(c) for c in plugin.P.call_args_list + plugin.Pd.call_args_list)

  def test_close_job_log_omits_job_record(self):
    Plugin, plugin = self._plugin()
    plugin._normalize_job_record = MagicMock(side_effect=lambda job_id, raw: (job_id, raw))
    plugin._count_all_findings = MagicMock(return_value=0)
    plugin._get_aggregated_report = MagicMock(return_value={})
    w = MagicMock()
    w.get_status.return_value = {"local_worker_id": "RM-0"}
    plugin.scan_jobs = {"job-1": {"RM-0": w}}
    job_specs = {"job_id": "job-1", "target": "example.com", "workers": {
      "node-A": {"start_port": 1, "end_port": 20},
      "node-B": {"result": {"accepted_credentials": ["admin:hunter2-secret"]}},
    }}
    plugin._get_job_state_repository.return_value.get_job.return_value = job_specs
    plugin.chainstore_hget.return_value = job_specs
    with patch.object(Plugin, "_mark_worker_terminal_error"):
      Plugin._close_job(plugin, "job-1")
    logged = self._logged(plugin)
    self.assertIn("job-1", logged)
    self.assertNotIn("hunter2-secret", logged)

  def test_finished_thread_log_omits_thread_report(self):
    Plugin, plugin = self._plugin()
    w = MagicMock()
    w.thread.is_alive.return_value = False
    w.get_status.return_value = {"target": "example.com", "accepted_credentials": ["admin:hunter2-secret"]}
    plugin.scan_jobs = {"job-1": {"RM-0": w}}
    plugin.completed_jobs_reports = {}
    plugin.lst_completed_jobs = []
    Plugin._maybe_close_jobs(plugin)
    logged = self._logged(plugin)
    self.assertIn("RM-0", logged)
    self.assertNotIn("hunter2-secret", logged)

  def test_foreign_job_debug_log_omits_worker_entries(self):
    Plugin, plugin = self._plugin()
    plugin._foreign_jobs_logged = set()
    spec = {"workers": {"node-B": {"result": {"accepted_credentials": ["admin:hunter2-secret"]}}}}
    Plugin._get_worker_entry(plugin, "job-1", spec)
    logged = self._logged(plugin)
    self.assertIn("job-1", logged)
    self.assertNotIn("hunter2-secret", logged)
