"""Phase 0 PR-0.1 — finding dedup at the aggregation boundary.

Two workers running the same probe set against overlapping targets
emit the same vulnerability twice. Each copy carries a different
_source_worker_id / _source_node_addr stamp from
_stamp_worker_source, so the JSON-key fallback in
merge_objects_deep cannot dedup them. The Phase 0 fix is a post-
merge dedup walking the known finding-bearing paths in the
aggregated report and collapsing duplicates by a stable signature
that excludes per-worker chain-of-custody fields.

Acceptance criteria for this PR:
  - same finding seen by two workers collapses to one entry
  - one of the worker stamps is preserved (chain-of-custody intact)
  - distinct findings (different titles, severity, evidence) remain
  - non-finding lists are unaffected (no false collapses)
  - top-level correlation_findings dedups
  - graybox_results, service_info, web_tests_info all deduped
"""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.mixins.report import (
  _ReportMixin,
  _dedup_finding_list,
  _dedup_findings_in_aggregated,
  _finding_dedup_key,
)
from extensions.business.cybersec.red_mesh.graybox.worker import (
  GrayboxLocalWorker,
)


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
    seen = set()
    out = []
    for x in items:
      key = repr(x)
      if key not in seen:
        seen.add(key)
        out.append(x)
    return out


class TestFindingDedupKey(unittest.TestCase):
  """The signature helper must collapse stamp variants and
  preserve all other content."""

  def test_same_finding_with_different_worker_stamps_same_key(self):
    a = {
      "title": "IDOR",
      "severity": "HIGH",
      "_source_worker_id": "w-1",
      "_source_node_addr": "0xaaa",
    }
    b = {
      "title": "IDOR",
      "severity": "HIGH",
      "_source_worker_id": "w-2",
      "_source_node_addr": "0xbbb",
    }
    self.assertEqual(_finding_dedup_key(a), _finding_dedup_key(b))

  def test_different_findings_different_keys(self):
    a = {"title": "IDOR", "severity": "HIGH"}
    b = {"title": "CSRF", "severity": "MEDIUM"}
    self.assertNotEqual(_finding_dedup_key(a), _finding_dedup_key(b))

  def test_same_title_different_evidence_different_keys(self):
    a = {"title": "Open port", "severity": "INFO", "evidence": "port 80"}
    b = {"title": "Open port", "severity": "INFO", "evidence": "port 443"}
    self.assertNotEqual(_finding_dedup_key(a), _finding_dedup_key(b))


class TestDedupFindingList(unittest.TestCase):

  def test_collapses_duplicate_with_different_stamps(self):
    findings = [
      {"title": "IDOR", "severity": "HIGH", "_source_worker_id": "w-1"},
      {"title": "IDOR", "severity": "HIGH", "_source_worker_id": "w-2"},
    ]
    out = _dedup_finding_list(findings)
    self.assertEqual(len(out), 1)
    # First-occurrence wins — w-1 stamp preserved
    self.assertEqual(out[0]["_source_worker_id"], "w-1")

  def test_keeps_distinct_findings(self):
    findings = [
      {"title": "IDOR", "severity": "HIGH"},
      {"title": "CSRF", "severity": "MEDIUM"},
      {"title": "XSS", "severity": "HIGH"},
    ]
    out = _dedup_finding_list(findings)
    self.assertEqual(len(out), 3)

  def test_preserves_order(self):
    findings = [
      {"title": "A", "severity": "INFO", "_source_worker_id": "w-1"},
      {"title": "B", "severity": "INFO", "_source_worker_id": "w-1"},
      {"title": "A", "severity": "INFO", "_source_worker_id": "w-2"},  # dup of [0]
      {"title": "C", "severity": "INFO", "_source_worker_id": "w-1"},
    ]
    out = _dedup_finding_list(findings)
    titles = [f["title"] for f in out]
    self.assertEqual(titles, ["A", "B", "C"])

  def test_handles_none_and_non_list(self):
    self.assertIsNone(_dedup_finding_list(None))
    self.assertEqual(_dedup_finding_list("not-a-list"), "not-a-list")

  def test_empty_list_returns_empty_list(self):
    self.assertEqual(_dedup_finding_list([]), [])


class TestDedupFindingsInAggregated(unittest.TestCase):
  """Walks the canonical paths and confirms each is deduped."""

  def test_dedups_graybox_results(self):
    aggregated = {
      "graybox_results": {
        "10000": {
          "_graybox_access_control": {
            "findings": [
              {"title": "IDOR", "severity": "HIGH",
               "_source_worker_id": "gw-1", "_source_node_addr": "0xaaa"},
              {"title": "IDOR", "severity": "HIGH",
               "_source_worker_id": "gw-2", "_source_node_addr": "0xbbb"},
            ]
          }
        }
      }
    }
    _dedup_findings_in_aggregated(aggregated)
    findings = aggregated["graybox_results"]["10000"]["_graybox_access_control"]["findings"]
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["_source_worker_id"], "gw-1")

  def test_dedups_nested_service_info(self):
    aggregated = {
      "service_info": {
        "22": {
          "_service_info_ssh": {
            "findings": [
              {"title": "CVE-2018-10933", "severity": "CRITICAL",
               "_source_worker_id": "w-1"},
              {"title": "CVE-2018-10933", "severity": "CRITICAL",
               "_source_worker_id": "w-2"},
            ]
          }
        }
      }
    }
    _dedup_findings_in_aggregated(aggregated)
    findings = aggregated["service_info"]["22"]["_service_info_ssh"]["findings"]
    self.assertEqual(len(findings), 1)

  def test_dedups_web_tests_info(self):
    aggregated = {
      "web_tests_info": {
        "80": {
          "_web_test_xss": {
            "findings": [
              {"title": "Reflected XSS", "severity": "HIGH",
               "_source_worker_id": "w-1"},
              {"title": "Reflected XSS", "severity": "HIGH",
               "_source_worker_id": "w-2"},
            ]
          }
        }
      }
    }
    _dedup_findings_in_aggregated(aggregated)
    self.assertEqual(
      len(aggregated["web_tests_info"]["80"]["_web_test_xss"]["findings"]), 1
    )

  def test_dedups_top_level_correlation_findings(self):
    aggregated = {
      "correlation_findings": [
        {"title": "Honeypot signature", "severity": "MEDIUM",
         "_source_worker_id": "w-1"},
        {"title": "Honeypot signature", "severity": "MEDIUM",
         "_source_worker_id": "w-2"},
      ]
    }
    _dedup_findings_in_aggregated(aggregated)
    self.assertEqual(len(aggregated["correlation_findings"]), 1)

  def test_dedups_legacy_flat_service_info_findings(self):
    aggregated = {
      "service_info": {
        "22": {
          "port": 22,
          "findings": [
            {"title": "SSH banner", "severity": "INFO",
             "_source_worker_id": "w-1"},
            {"title": "SSH banner", "severity": "INFO",
             "_source_worker_id": "w-2"},
          ],
        }
      }
    }
    _dedup_findings_in_aggregated(aggregated)
    self.assertEqual(len(aggregated["service_info"]["22"]["findings"]), 1)

  def test_does_not_collapse_distinct_findings_on_same_port(self):
    """Two real findings at the same port (e.g. open redirect + CORS)
    must not collapse just because they share metadata fields."""
    aggregated = {
      "graybox_results": {
        "10000": {
          "_graybox_misconfig": {
            "findings": [
              {"title": "Permissive CORS", "severity": "MEDIUM",
               "_source_worker_id": "w-1"},
              {"title": "Open redirect", "severity": "MEDIUM",
               "_source_worker_id": "w-1"},
            ]
          }
        }
      }
    }
    _dedup_findings_in_aggregated(aggregated)
    self.assertEqual(
      len(aggregated["graybox_results"]["10000"]["_graybox_misconfig"]["findings"]), 2
    )

  def test_no_op_on_empty_aggregated(self):
    aggregated = {}
    _dedup_findings_in_aggregated(aggregated)
    self.assertEqual(aggregated, {})

  def test_no_op_on_non_dict(self):
    # Should not raise
    _dedup_findings_in_aggregated(None)
    _dedup_findings_in_aggregated("string")
    _dedup_findings_in_aggregated([])


class TestDedupIntegratesWithAggregateReport(unittest.TestCase):
  """End-to-end — two-worker graybox aggregation produces deduped
  findings."""

  def test_two_workers_same_finding_collapses_after_aggregate(self):
    host = _Host()
    base_finding = {
      "title": "Object-level authorization bypass",
      "severity": "HIGH",
      "scenario_id": "_graybox_access_control",
      "evidence": {"endpoint": "/api/records/1"},
    }
    reports = {
      "worker-a": {
        "node_addr": "0xaaa",
        "local_worker_id": "worker-a",
        "graybox_results": {
          "10000": {
            "_graybox_access_control": {
              "findings": [dict(base_finding)],
            }
          }
        },
      },
      "worker-b": {
        "node_addr": "0xbbb",
        "local_worker_id": "worker-b",
        "graybox_results": {
          "10000": {
            "_graybox_access_control": {
              "findings": [dict(base_finding)],
            }
          }
        },
      },
    }
    agg = host._get_aggregated_report(reports, worker_cls=GrayboxLocalWorker)
    findings = (
      agg.get("graybox_results", {}).get("10000", {})
      .get("_graybox_access_control", {}).get("findings", [])
    )
    self.assertEqual(len(findings), 1, f"expected 1 finding, got {len(findings)}: {findings}")
    self.assertIn("_source_worker_id", findings[0])

  def test_two_workers_distinct_findings_both_kept(self):
    host = _Host()
    reports = {
      "worker-a": {
        "node_addr": "0xaaa",
        "local_worker_id": "worker-a",
        "graybox_results": {
          "10000": {
            "_graybox_access_control": {
              "findings": [
                {"title": "IDOR", "severity": "HIGH"},
              ],
            }
          }
        },
      },
      "worker-b": {
        "node_addr": "0xbbb",
        "local_worker_id": "worker-b",
        "graybox_results": {
          "10000": {
            "_graybox_misconfig": {
              "findings": [
                {"title": "Permissive CORS", "severity": "MEDIUM"},
              ],
            }
          }
        },
      },
    }
    agg = host._get_aggregated_report(reports, worker_cls=GrayboxLocalWorker)
    gr = agg.get("graybox_results", {}).get("10000", {})
    self.assertEqual(len(gr.get("_graybox_access_control", {}).get("findings", [])), 1)
    self.assertEqual(len(gr.get("_graybox_misconfig", {}).get("findings", [])), 1)


if __name__ == "__main__":
  unittest.main()
