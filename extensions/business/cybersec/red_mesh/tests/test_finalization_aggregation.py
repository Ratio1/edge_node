"""Phase 3 of PR 388 remediation — correct worker class for aggregation
and worker-level source attribution stamping.

Covers audit #4: maybe_finalize_pass must resolve the worker class
from the job's scan_type so graybox-specific fields
(graybox_results, completed_tests, aborted/abort_reason/abort_phase)
aggregate correctly across multiple graybox workers. Also verifies
the _stamp_worker_source helper stamps every finding-bearing
structure in both nested and legacy flat shapes.
"""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.graybox.worker import (
  GrayboxLocalWorker,
)
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker


class _Host(_ReportMixin):
  def __init__(self):
    super().__init__()
    self.P = MagicMock()
    self.Pd = MagicMock()

  def trace_info(self):
    return ""

  def json_dumps(self, obj, indent=None):
    import json
    return json.dumps(obj, default=str, indent=indent)

  def _deduplicate_items(self, items):
    # Stub for _get_aggregated_report unit tests — deduplicates by repr.
    seen = set()
    out = []
    for x in items:
      key = repr(x)
      if key not in seen:
        seen.add(key)
        out.append(x)
    return out


class TestStampWorkerSource(unittest.TestCase):

  def test_stamps_nested_service_info_findings(self):
    host = _Host()
    state = {
      "service_info": {
        "443": {
          "_service_info_https": {
            "findings": [{"title": "A", "severity": "HIGH"}],
          },
        },
      },
    }
    host._stamp_worker_source(state, "w-1", "0xaddr")
    f = state["service_info"]["443"]["_service_info_https"]["findings"][0]
    self.assertEqual(f["_source_worker_id"], "w-1")
    self.assertEqual(f["_source_node_addr"], "0xaddr")

  def test_stamps_legacy_flat_service_info_findings(self):
    """Findings directly on the port entry (not under a probe key)
    still get stamped. Production uses nested only but the stamper
    is shape-robust for migrated data and tests.
    """
    host = _Host()
    state = {
      "service_info": {
        "22": {
          "port": 22,
          "findings": [{"title": "SSH", "severity": "HIGH"}],
        },
      },
    }
    host._stamp_worker_source(state, "w-2", "0xbeef")
    f = state["service_info"]["22"]["findings"][0]
    self.assertEqual(f["_source_worker_id"], "w-2")
    self.assertEqual(f["_source_node_addr"], "0xbeef")

  def test_stamps_graybox_results(self):
    host = _Host()
    state = {
      "graybox_results": {
        "443": {
          "_graybox_access_control": {
            "findings": [{"title": "IDOR", "severity": "HIGH"}],
          },
        },
      },
    }
    host._stamp_worker_source(state, "gw-1", "0xgray")
    f = state["graybox_results"]["443"]["_graybox_access_control"]["findings"][0]
    self.assertEqual(f["_source_worker_id"], "gw-1")
    self.assertEqual(f["_source_node_addr"], "0xgray")

  def test_stamps_correlation_and_top_level(self):
    host = _Host()
    state = {
      "findings": [{"title": "Top", "severity": "LOW"}],
      "correlation_findings": [{"title": "Corr", "severity": "MEDIUM"}],
    }
    host._stamp_worker_source(state, "w", "addr")
    self.assertEqual(state["findings"][0]["_source_worker_id"], "w")
    self.assertEqual(state["correlation_findings"][0]["_source_node_addr"], "addr")

  def test_stamping_is_idempotent(self):
    """Existing Phase 2 stamps survive — setdefault does not overwrite."""
    host = _Host()
    state = {
      "service_info": {
        "443": {
          "_service_info_https": {
            "findings": [{
              "title": "A",
              "severity": "HIGH",
              "_source_worker_id": "phase2-original",
            }],
          },
        },
      },
    }
    host._stamp_worker_source(state, "phase3-new", "0xaddr")
    f = state["service_info"]["443"]["_service_info_https"]["findings"][0]
    # Phase 2's stamp wins; phase 3 only fills gaps.
    self.assertEqual(f["_source_worker_id"], "phase2-original")
    # node_addr wasn't stamped by phase 2, so phase 3 fills it.
    self.assertEqual(f["_source_node_addr"], "0xaddr")


class TestGrayboxMultiWorkerAggregation(unittest.TestCase):

  def test_graybox_results_merge_across_workers(self):
    """Two graybox workers with disjoint graybox_results port entries
    aggregate into the union, not the first-worker's data only.
    """
    host = _Host()
    reports = {
      "node-a": {
        "job_id": "j1", "scan_type": "webapp",
        "service_info": {},
        "graybox_results": {
          "443": {
            "_graybox_access_control": {
              "findings": [{"title": "IDOR", "severity": "HIGH"}],
              "outcome": "completed",
            },
          },
        },
        "completed_tests": ["graybox_probes"],
        "aborted": False, "abort_reason": "", "abort_phase": "",
      },
      "node-b": {
        "job_id": "j1", "scan_type": "webapp",
        "service_info": {},
        "graybox_results": {
          "8080": {
            "_graybox_injection": {
              "findings": [{"title": "XSS", "severity": "HIGH"}],
              "outcome": "completed",
            },
          },
        },
        "completed_tests": ["graybox_probes", "graybox_weak_auth"],
        "aborted": False, "abort_reason": "", "abort_phase": "",
      },
    }
    agg = host._get_aggregated_report(reports, worker_cls=GrayboxLocalWorker)
    # Both ports survive — this was the bug (#4): previously only
    # the first worker's graybox_results would land in agg.
    self.assertIn("443", agg["graybox_results"])
    self.assertIn("8080", agg["graybox_results"])
    # completed_tests becomes the union.
    self.assertIn("graybox_probes", agg["completed_tests"])
    self.assertIn("graybox_weak_auth", agg["completed_tests"])

  def test_abort_state_merges_any_semantics(self):
    """One worker aborted → aggregate aborted=True; abort_reason /
    abort_phase come from the aborted worker (first non-empty wins).
    """
    host = _Host()
    reports = {
      "node-a": {
        "job_id": "j1", "scan_type": "webapp",
        "service_info": {}, "graybox_results": {}, "completed_tests": [],
        "aborted": False, "abort_reason": "", "abort_phase": "",
      },
      "node-b": {
        "job_id": "j1", "scan_type": "webapp",
        "service_info": {}, "graybox_results": {}, "completed_tests": [],
        "aborted": True, "abort_reason": "unauthorized target",
        "abort_phase": "preflight",
      },
    }
    agg = host._get_aggregated_report(reports, worker_cls=GrayboxLocalWorker)
    self.assertTrue(agg["aborted"])
    self.assertEqual(agg["abort_reason"], "unauthorized target")
    self.assertEqual(agg["abort_phase"], "preflight")

  def test_findings_carry_worker_and_node_attribution(self):
    """Every finding in the aggregated report has the four stamp
    fields (_source_probe/_source_port stamped in Phase 2 at
    extraction, _source_worker_id/_source_node_addr stamped in
    Phase 3 at aggregation).
    """
    host = _Host()
    reports = {
      "0xnode_a": {
        "job_id": "j1", "scan_type": "webapp",
        "local_worker_id": "RM-1-aaaa",
        "service_info": {},
        "graybox_results": {
          "443": {
            "_graybox_idor": {
              "findings": [{"title": "IDOR", "severity": "HIGH"}],
              "outcome": "completed",
            },
          },
        },
        "completed_tests": [],
      },
    }
    host._get_aggregated_report(reports, worker_cls=GrayboxLocalWorker)
    # Stamping happens in place on reports during aggregation.
    f = reports["0xnode_a"]["graybox_results"]["443"]["_graybox_idor"]["findings"][0]
    self.assertEqual(f["_source_worker_id"], "RM-1-aaaa")
    self.assertEqual(f["_source_node_addr"], "0xnode_a")


class TestNetworkAggregationRegression(unittest.TestCase):

  def test_network_aggregation_still_works_without_worker_cls(self):
    """Default-path regression: when worker_cls is None (or omitted),
    aggregation falls back to PentestLocalWorker fields — matching
    pre-Phase 3 behavior for the network scan path.
    """
    host = _Host()
    reports = {
      "node-a": {
        "job_id": "j1",
        "open_ports": [22, 80],
        "ports_scanned": [22, 80],
        "service_info": {"22": {"port": 22, "findings": []}},
      },
      "node-b": {
        "job_id": "j1",
        "open_ports": [80, 443],
        "ports_scanned": [80, 443],
        "service_info": {"443": {"port": 443, "findings": []}},
      },
    }
    agg = host._get_aggregated_report(reports)
    # open_ports/ports_scanned unioned + sorted (union behavior from
    # _get_aggregated_report list-handling).
    self.assertIn(22, agg["open_ports"])
    self.assertIn(80, agg["open_ports"])
    self.assertIn(443, agg["open_ports"])
    self.assertIn("22", agg["service_info"])
    self.assertIn("443", agg["service_info"])


if __name__ == '__main__':
  unittest.main()
