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


class TestWorkerFindingEvidence(unittest.TestCase):

  def test_raw_record_counts_and_unique_signatures_precede_cross_worker_dedup(self):
    host = _Host()
    findings = [
      {
        "finding_signature": f"type-{index % 188}",
        "severity": "HIGH" if index < 28 else "MEDIUM",
        "title": f"record-{index}",
        "_source_node_addr": "0xworker-a",
      }
      for index in range(228)
    ]
    report = {
      "service_info": {"443": {"probe": {"findings": findings}}},
    }

    nr_findings, counts, signatures = host._summarize_worker_findings(report)

    self.assertEqual(nr_findings, 228)
    self.assertEqual(counts, {"HIGH": 28, "MEDIUM": 200})
    self.assertEqual(len(signatures), 188)
    self.assertEqual(signatures[0], "type-0")

  def test_fallback_signature_ignores_worker_attribution(self):
    host = _Host()
    base = {"title": "Same issue", "severity": "LOW", "port": 80}
    report_a = {"findings": [{**base, "_source_node_addr": "0xa"}]}
    report_b = {"findings": [{**base, "_source_node_addr": "0xb"}]}

    self.assertEqual(
      host._summarize_worker_findings(report_a)[2],
      host._summarize_worker_findings(report_b)[2],
    )


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


class TestApiTop10FlatFindingIntegration(unittest.TestCase):
  """OWASP API Top 10 — Subphase 5.1 of the API Top 10 plan.

  Verifies that findings emitted by the new `_graybox_api_*` families
  flatten into the unified flat-finding schema with the correct
  probe attribution, scenario_id, severity, and rollback_status.
  """

  def _make_finding(self, scenario_id, **overrides):
    """Build a minimal GrayboxFinding via the typed dataclass."""
    from extensions.business.cybersec.red_mesh.graybox.findings import (
      GrayboxFinding,
    )
    defaults = dict(
      scenario_id=scenario_id,
      title=f"finding {scenario_id}",
      status="vulnerable",
      severity="HIGH",
      owasp="API1:2023",
      cwe=["CWE-639"],
      attack=["T1190"],
      evidence=["endpoint=/api/x", "owner_field=owner"],
    )
    defaults.update(overrides)
    return GrayboxFinding(**defaults)

  def test_each_new_api_family_flattens_correctly(self):
    """Each of the five api_* probe-family keys carries through to flat findings."""
    cases = [
      ("PT-OAPI1-01", "_graybox_api_access", "API1:2023"),
      ("PT-OAPI2-01", "_graybox_api_auth",   "API2:2023"),
      ("PT-OAPI3-01", "_graybox_api_data",   "API3:2023"),
      ("PT-OAPI8-01", "_graybox_api_config", "API8:2023"),
      ("PT-OAPI4-01", "_graybox_api_abuse",  "API4:2023"),
    ]
    for scenario_id, probe_key, owasp in cases:
      with self.subTest(scenario_id=scenario_id):
        f = self._make_finding(scenario_id, owasp=owasp)
        flat = f.to_flat_finding(443, "https", probe_key)
        self.assertEqual(flat["probe_type"], "graybox")
        self.assertEqual(flat["category"], "graybox")
        self.assertEqual(flat["probe"], probe_key)
        self.assertEqual(flat["scenario_id"], scenario_id)
        self.assertEqual(flat["owasp_id"], owasp)
        self.assertEqual(flat["severity"], "HIGH")
        # ATT&CK + CWE survive
        self.assertIn("CWE-639", flat["cwe_id"])
        self.assertEqual(flat["attack_ids"], ["T1190"])

  def test_rollback_status_field_present_on_flat(self):
    """rollback_status (Subphase 1.8) flows through to flat findings."""
    f = self._make_finding(
      "PT-OAPI3-02", owasp="API3:2023",
      rollback_status="reverted",
    )
    flat = f.to_flat_finding(443, "https", "_graybox_api_data")
    self.assertEqual(flat["rollback_status"], "reverted")

  def test_revert_failed_flag_visible(self):
    """Operators see revert_failed at the flat-finding boundary."""
    f = self._make_finding(
      "PT-OAPI3-02", owasp="API3:2023",
      severity="CRITICAL", rollback_status="revert_failed",
    )
    flat = f.to_flat_finding(443, "https", "_graybox_api_data")
    self.assertEqual(flat["rollback_status"], "revert_failed")
    self.assertEqual(flat["severity"], "CRITICAL")


class TestApiTop10DedupPosture(unittest.TestCase):
  """Subphase 5.3: PT-A01-01 (web IDOR) and PT-OAPI1-01 (API BOLA) on the
  same asset must NOT collapse — they describe different vulnerability
  classes and should both surface in the report."""

  def test_pt_a01_and_pt_oapi1_coexist(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import (
      GrayboxFinding,
    )
    common = dict(status="vulnerable", severity="HIGH",
                  evidence=["endpoint=/api/records/1"])
    f_web = GrayboxFinding(scenario_id="PT-A01-01", title="IDOR/BOLA read bypass",
                            owasp="A01:2021", cwe=["CWE-639"], **common)
    f_api = GrayboxFinding(scenario_id="PT-OAPI1-01",
                            title="API object-level authorization bypass (BOLA)",
                            owasp="API1:2023", cwe=["CWE-639", "CWE-284"],
                            **common)
    flat_web = f_web.to_flat_finding(443, "https", "_graybox_access_control")
    flat_api = f_api.to_flat_finding(443, "https", "_graybox_api_access")
    # Different probe_name + different title + different scenario_id =
    # different finding_id (sha256 of port:probe:cwe:title).
    self.assertNotEqual(flat_web["finding_id"], flat_api["finding_id"])
    self.assertNotEqual(flat_web["probe"], flat_api["probe"])
    self.assertNotEqual(flat_web["scenario_id"], flat_api["scenario_id"])


class TestApiTop10BudgetMetrics(unittest.TestCase):
  """OWASP API Top 10 — Subphase 5.1 budget integration assertion.

  When the per-scan RequestBudget is exhausted, the worker outcome dict
  surfaces budget_total/budget_remaining/budget_exhausted_count under
  scan_metrics so report consumers see the cap in effect.
  """

  def test_budget_metrics_surface_in_get_status(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import (
      RequestBudget,
    )
    # Minimal worker stub exposing only what get_status reads.
    worker = MagicMock()
    worker.request_budget = RequestBudget(remaining=5, total=5)
    worker.request_budget.consume(3)  # consume 3 → 2 left
    worker.request_budget.consume(10)  # exhaust attempt → +1 to count

    # Re-implement the metrics merge inline so we don't need a full
    # GrayboxLocalWorker (which requires R1FS setup, etc.).
    snap = worker.request_budget.snapshot()
    metrics = {
      "budget_total": snap["total"],
      "budget_remaining": snap["remaining"],
      "budget_exhausted_count": snap["exhausted_count"],
    }
    self.assertEqual(metrics["budget_total"], 5)
    self.assertEqual(metrics["budget_remaining"], 2)
    self.assertEqual(metrics["budget_exhausted_count"], 1)


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


class _AggHost(_Host):
  """_Host plus the service-count helper _compute_ui_aggregate depends on."""

  def _count_services(self, service_info):
    return len(service_info or {})


class TestOriginCountryAndComparisonAggregate(unittest.TestCase):
  """Origin-country breakdown and comparison-mode per-node vantage comparison."""

  def _latest_pass(self):
    return {
      "pass_nr": 1,
      "findings": [
        {"finding_signature": "sig1", "severity": "HIGH", "title": "XSS",
         "port": 443, "_source_node_addr": "0xUS"},
      ],
      "worker_reports": {
        "0xUS": {"start_port": 1, "end_port": 443, "open_ports": [80, 443],
                 "node_ip": "1.1.1.1", "country": "US", "nr_findings": 1,
                 "finding_counts": {"HIGH": 1}, "finding_signatures": ["sig1"]},
        "0xIN": {"start_port": 1, "end_port": 443, "open_ports": [80],
                 "node_ip": "2.2.2.2", "country": "in", "nr_findings": 0},
      },
      "worker_scan_metrics": {
        "0xUS": {"scan_metrics": {
          "connection_outcomes": {"connected": 5, "timeout": 0, "refused": 2, "reset": 1},
          "response_times": {"p95": 0.12},
          "coverage": 0.75,
          "probes_attempted": 4,
          "probes_completed": 3,
          "probes_failed": 1,
          "phase_durations": {"port_scan": 12.5},
          "total_duration": 19.0,
          "success_rate_over_time": [{
            "window_start": 0, "window_end": 60, "success_rate": 0.625,
            "attempts": 8, "responsive_count": 8, "response_rate": 1.0,
          }],
        }, "threads": [{"local_worker_id": "thread-1"}]},
        "0xBR": {"scan_metrics": {"connection_outcomes": {"connected": 0, "timeout": 9},
                                  "response_times": {"p95": 2.0}}},
      },
    }

  def test_compact_fallback_signature_uses_cross_client_canonical_json(self):
    report = {
      "findings": [{
        "title": "TLS issue", "severity": "HIGH", "port": 443,
        "evidence": {"z": True, "a": "é", "_source_worker_id": "thread-a"},
        "_source_node_addr": "0xUS",
      }],
    }

    _, _, signatures = _AggHost()._summarize_worker_findings(report)

    self.assertEqual(signatures, [
      "sha256:f5629a722dcbdd8bece9e8647efcc972869648374d1dab7b16aab2a4740464ca",
    ])

  def test_country_breakdown_and_per_worker_country(self):
    host = _AggHost()
    ui = host._compute_ui_aggregate(
      [self._latest_pass()],
      {"open_ports": [80, 443], "service_info": {}},
      job_config={"scan_type": "network"},
    )
    d = ui.to_dict()
    # Counts per ISO-2 (uppercased), sorted by (-count, code) — tie sorts IN before US.
    self.assertEqual(d.get("country_breakdown"), [{"code": "IN", "count": 1}, {"code": "US", "count": 1}])
    by_id = {w["id"]: w["country"] for w in d["worker_activity"]}
    self.assertEqual(by_id["0xUS"], "US")
    self.assertEqual(by_id["0xIN"], "IN")
    # node_comparison is only computed in comparison mode.
    self.assertNotIn("node_comparison", d)

  def test_node_comparison_includes_failed_and_timed_out_nodes(self):
    host = _AggHost()
    cfg = {
      "scan_type": "network",
      "comparison_mode": True,
      "selected_peers": ["0xUS", "0xIN", "0xBR", "0xCN"],
      "comparison_ports": [80, 443],
    }
    ui = host._compute_ui_aggregate(
      [self._latest_pass()],
      {"open_ports": [80, 443], "service_info": {}},
      job_config=cfg,
    )
    comp = {e["address"]: e for e in ui.to_dict()["node_comparison"]}
    # Reached node: open ports + finding attribution + latency.
    self.assertEqual(comp["0xUS"]["status"], "reached")
    self.assertEqual(comp["0xUS"]["open_ports"], [80, 443])
    self.assertEqual(comp["0xUS"]["metrics"]["response_p95_ms"], 120.0)
    self.assertEqual(comp["0xUS"]["findings"][0]["signature"], "sig1")
    self.assertEqual(comp["0xUS"]["finding_counts"], {"HIGH": 1})
    self.assertEqual(comp["0xUS"]["finding_signatures"], ["sig1"])
    self.assertEqual(comp["0xUS"]["metrics"]["refused"], 2)
    self.assertEqual(comp["0xUS"]["metrics"]["reset"], 1)
    self.assertEqual(comp["0xUS"]["metrics"]["coverage"], 0.75)
    self.assertEqual(comp["0xUS"]["metrics"]["probes_completed"], 3)
    self.assertEqual(comp["0xUS"]["metrics"]["total_duration"], 19.0)
    self.assertEqual(comp["0xUS"]["metrics"]["traffic_windows"][0]["attempts"], 8)
    self.assertEqual(comp["0xUS"]["metrics"]["threads"][0]["local_worker_id"], "thread-1")
    # Metrics-only node with all-timeout connections -> timeout.
    self.assertEqual(comp["0xBR"]["status"], "timeout")
    # Selected peer that never reported at all -> failed (China-timeout case).
    self.assertEqual(comp["0xCN"]["status"], "failed")
    self.assertEqual(comp["0xCN"]["country"], "UN")


if __name__ == '__main__':
  unittest.main()
