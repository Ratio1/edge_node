"""EG-018 phase 3b: explanation spec v0.3 -- source timestamps and ids,
event URL template, public `misp_citations`, value-free gate reason codes.

Synthetic fixtures only (CVE-2000-0001, 203.0.113.x, MISP ids in the 900s);
no network.
"""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.edgeguard.tests.test_api import (  # noqa: E402
  _DriverRecord,
  _GraphNode,
  _Result,
  _make_api,
)
from extensions.business.cybersec.edgeguard.tests import test_analyst_brief as eab_tests  # noqa: E402
from extensions.business.cybersec.edgeguard.tests import test_egx2 as egx2_tests  # noqa: E402
from extensions.business.cybersec.edgeguard import egx2, misp_enrichment as misp  # noqa: E402
from extensions.business.cybersec.edgeguard.egx2 import brief_gates, field_catalog, insights  # noqa: E402
from extensions.business.cybersec.edgeguard.egx2 import insight_brief as runtime  # noqa: E402
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError  # noqa: E402

VECTOR_PATH = Path(__file__).parent / "fixtures" / "misp_citation_cases.json"
TEMPLATE_VECTOR_PATH = Path(__file__).parent / "fixtures" / "misp_event_url_template_cases.json"
ENRICHMENT_QUERY_MARKER = "$element_ids"  # only the internal MISP enrichment query uses it
CUSTOM_TEMPLATE = "https://misp.example.test/misp/events/view/{event_id}"


def _row(label="Indicator", source_id="alienvault_otx", raw=None, element_id="e-1", event_ids=("902",)):
  return {
    "element_id": element_id, "labels": [label], "misp_event_ids": list(event_ids),
    "misp_attribute_ids": ["attr-1"], "source": source_id, "last_imported_from": None,
    "sourced": [{"source_id": source_id, "raw_data": json.dumps(raw or {})}],
  }


def _fields(label, source_id, raw):
  block = misp.build_misp_enrichment_block([_row(label, source_id, raw)], {"e-1": "N0"})
  return block["nodes"][0]["fields"] if block else None


class TimestampRuleTests(unittest.TestCase):
  def test_parse_accepts_iso_forms_and_normalises_to_utc(self):
    cases = {
      "2026-03-04": "2026-03-04T00:00:00Z",
      "2026-03-04T05:06:07": "2026-03-04T05:06:07Z",
      "2026-03-04 05:06:07": "2026-03-04T05:06:07Z",
      "2026-03-04T05:06:07.987654": "2026-03-04T05:06:07Z",
      "2026-03-04T05:06:07Z": "2026-03-04T05:06:07Z",
      "2026-03-04T05:06:07+02:00": "2026-03-04T03:06:07Z",
      "2026-03-04T05:06:07-0130": "2026-03-04T06:36:07Z",
      "2026-03-04T05:06": "2026-03-04T05:06:00Z",
      "  2026-03-04  ": "2026-03-04T00:00:00Z",
    }
    for raw, expected in cases.items():
      with self.subTest(raw=raw):
        self.assertEqual(misp._format_source_timestamp(misp.parse_source_timestamp(raw)), expected)

  def test_parse_rejects_everything_else(self):
    for raw in ("", "   ", "garbage", "1700000000", 1700000000, 1.5, None, True, ["2026-03-04"],
                "2026-13-01", "2026-02-30", "2026-03-04T25:00:00",
                "2026-03-04T05:06:07Zjunk", "2026-03-04T05:06:07+24:00", "2026-03-04T05:06:07+02:60", "2026-03-04T05:06:07+99:99", "٢٠٢٦-٠٣-٠٤", "2026-3-4"):
      with self.subTest(raw=raw):
        self.assertIsNone(misp.parse_source_timestamp(raw))

  def test_every_label_gets_earliest_first_and_latest_last_across_entries(self):
    row = _row("Malware", "mitre_attck", {"first_seen_at_source": "2026-02-01", "last_seen_at_source": "2026-02-02"})
    row["sourced"].append({"source_id": "other", "raw_data": json.dumps({
      "first_seen_at_source": "2026-01-15T10:00:00+00:00", "last_seen_at_source": "2026-03-01 00:00:00",
    })})
    row["sourced"].append({"source_id": "third", "raw_data": json.dumps({
      "first_seen_at_source": "junk", "last_seen_at_source": 1700000000,
    })})
    block = misp.build_misp_enrichment_block([row], {"e-1": "N0"})
    self.assertEqual(block["nodes"][0]["fields"]["first_seen_at_source"], "2026-01-15T10:00:00Z")
    self.assertEqual(block["nodes"][0]["fields"]["last_seen_at_source"], "2026-03-01T00:00:00Z")
    self.assertTrue(misp.validate_misp_enrichment_block(block))

  def test_unparseable_empty_or_absent_means_no_key(self):
    for raw in ({}, {"first_seen_at_source": "", "last_seen_at_source": "nope"},
                {"first_seen_at_source": 1700000000, "last_seen_at_source": None}):
      with self.subTest(raw=raw):
        fields = _fields("Tool", "mitre_attck", raw)
        self.assertNotIn("first_seen_at_source", fields)
        self.assertNotIn("last_seen_at_source", fields)
        self.assertNotIn("", fields.values())

  def test_one_parseable_value_is_enough(self):
    fields = _fields("CVE", "nvd", {"first_seen_at_source": "2026-05-05", "last_seen_at_source": ""})
    self.assertEqual(fields["first_seen_at_source"], "2026-05-05T00:00:00Z")
    self.assertNotIn("last_seen_at_source", fields)

  def test_validator_rejects_a_malformed_timestamp_field(self):
    block = misp.build_misp_enrichment_block([_row("CVE", "nvd", {"first_seen_at_source": "2026-05-05"})], {"e-1": "N0"})
    block["nodes"][0]["fields"]["first_seen_at_source"] = "2026-05-05"
    block["sha256"] = hashlib.sha256(json.dumps(
      block["nodes"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    self.assertFalse(misp.validate_misp_enrichment_block(block))

  def test_pulse_id_and_ioc_id_appear_on_their_sources_only(self):
    raw = {"pulse_id": "pulse-77", "ioc_id": 123456}
    self.assertEqual(_fields("Indicator", "alienvault_otx", raw)["pulse_id"], "pulse-77")
    self.assertNotIn("ioc_id", _fields("Indicator", "alienvault_otx", raw))
    for source in ("threatfox", "urlhaus"):
      fields = _fields("Indicator", source, raw)
      self.assertEqual(fields["ioc_id"], 123456)
      self.assertNotIn("pulse_id", fields)
    self.assertIsNone(_fields("CVE", "nvd", raw) and _fields("CVE", "nvd", raw).get("pulse_id"))
    self.assertEqual(_fields("Indicator", "threatfox", {"ioc_id": "88"})["ioc_id"], "88")
    self.assertEqual(_fields("Indicator", "alienvault_otx", {"pulse_id": 5})["pulse_id"], "5")
    for bad in (True, 1.5, ["x"], {"a": 1}, ""):
      self.assertNotIn("ioc_id", _fields("Indicator", "threatfox", {"ioc_id": bad, "threat_type": "t"}))

  def test_fullest_node_stays_within_the_twenty_field_cap(self):
    raw = {
      "pulse_name": "P", "pulse_references": ["https://otx.test/p"], "pulse_tlp": "white",
      "otx_industries": ["x"], "indicator_role": "c2", "pulse_id": "1", "ioc_id": 2,
      "threat_type": "t", "threat_type_desc": "d", "tf_tags": ["a"], "reference": "https://r.test/x",
      "malware_alias": "m", "first_seen_at_source": "2026-01-01", "last_seen_at_source": "2026-01-02",
    }
    row = _row("Indicator", "alienvault_otx", raw)
    row["sourced"].append({"source_id": "threatfox", "raw_data": json.dumps(raw)})
    row["source"], row["last_imported_from"] = "feed", "2026-01-01"
    block = misp.build_misp_enrichment_block([row], {"e-1": "N0"})
    self.assertLessEqual(len(block["nodes"][0]["fields"]), 20)
    self.assertTrue(misp.validate_misp_enrichment_block(block))
    node = block["nodes"][0]
    self.assertEqual(len(node["misp_event_urls"]), len(node["misp_event_ids"]))


def _block_with_ui_fields(with_ui=True):
  cve_raw = {"cwe": ["CWE-79"], "reference_urls": ["https://example.test/advisory/1"]}
  ind_raw = {"pulse_name": "Synthetic Pulse Alpha", "pulse_references": ["https://otx.test/pulse/1"]}
  if with_ui:
    cve_raw.update({"first_seen_at_source": "2026-01-01", "last_seen_at_source": "2026-02-02"})
    ind_raw.update({"first_seen_at_source": "2026-01-01", "last_seen_at_source": "2026-02-02", "pulse_id": "pulse-9"})
  rows = [_row("CVE", "nvd", cve_raw, "e-c1", ("901",)), _row("Indicator", "alienvault_otx", ind_raw, "e-i1", ("902",))]
  rows[0]["source"], rows[0]["last_imported_from"] = "nvd", "2026-09-01T00:00:00Z"
  rows[1]["source"] = "alienvault_otx"
  return misp.build_misp_enrichment_block(rows, {"e-c1": "N0", "e-i1": "N1"})


class ModelExposureTests(unittest.TestCase):
  def test_blocks_differ_but_new_fields_are_only_in_the_block(self):
    with_ui, without = _block_with_ui_fields(True), _block_with_ui_fields(False)
    self.assertNotEqual(with_ui["sha256"], without["sha256"])
    self.assertIn("pulse_id", with_ui["nodes"][1]["fields"])

  def test_model_view_equal_with_and_without_the_four_fields(self):
    for kwargs in ({}, {"entity_by_ref": {"N0": "a", "N1": "b"}}):
      with self.subTest(kwargs=kwargs):
        left = misp.build_model_view(_block_with_ui_fields(True), max_bytes=4096, **kwargs)
        right = misp.build_model_view(_block_with_ui_fields(False), max_bytes=4096, **kwargs)
        self.assertEqual(left, right)
        for node in left["nodes"]:
          self.assertFalse(misp.UI_ONLY_FIELDS & set(node["fields"]))

  def test_egx2_view_catalog_and_sha_do_not_carry_the_fields(self):
    for label, spec in field_catalog.MISP_ENRICHMENT_CATALOG.items():
      self.assertFalse(misp.UI_ONLY_FIELDS & set(spec), label)
    self.assertEqual(field_catalog.CATALOG_SHA256, egx2_tests.PINNED_CATALOG_SHA256)
    self.assertEqual(egx2.PROFILE_SHA256, egx2_tests.PINNED_PROFILE_SHA256)
    view = egx2_tests._view(_block_with_ui_fields(True))
    self.assertEqual(view, egx2_tests._view(_block_with_ui_fields(False)))

  def test_eab1_request_sha256_and_prompt_bytes_are_identical(self):
    runs = {flag: eab_tests._brief_run(eab_tests.GROUNDED_TEXT, block=_block_with_ui_fields(flag)) for flag in (True, False)}
    self.assertEqual(runs[True][1][0]["messages"], runs[False][1][0]["messages"])
    # The whole result, which carries the request hash, is identical too.
    self.assertEqual(
      json.dumps(runs[True][0], sort_keys=True), json.dumps(runs[False][0], sort_keys=True),
    )

  def test_egx2_prompt_and_request_sha256_are_identical(self):
    traces = []
    for flag in (True, False):
      result, payloads = _egx2_run(block=_block_with_ui_fields(flag))
      traces.append((payloads[0]["messages"], result["explanation_trace"]["calls"][0]["request_sha256"]))
    self.assertEqual(traces[0], traces[1])

  def test_model_request_bytes_without_a_block_are_the_pre_change_value(self):
    # Value measured on the base commit (b505f06) with the same fixture.
    result, payloads = _egx2_run(block=None)
    self.assertEqual(result["explanation_trace"]["calls"][0]["request_sha256"], PRE_CHANGE_NO_BLOCK_SHA)
    self.assertNotIn("misp_citations", json.dumps(result["case_explanation"]))


# Re-pin only when the EGX/2 prompt or profile changes on purpose (EG-018 phase 4
# prompt wording); any other change to this value means the no-block request bytes moved.
PRE_CHANGE_NO_BLOCK_SHA = "79a32e4840ba69e09043efbca9bb82506a5f9309211f4f54aa1654aeb431f70d"


def _egx2_run(brief_factory=None, *, block="default", node_ids=None, template=None, graph=None):
  graph = graph or egx2_tests.enrichment_graph()
  sheet = insights.build_insight_sheet(graph)
  payloads = []
  factory = brief_factory or egx2_tests.enrichment_brief

  def provider(payload):
    payloads.append(payload)
    return {"finish_reason": "stop", "completion_tokens": 90, "content": json.dumps(factory(sheet))}

  kwargs = {}
  if block is not None:
    kwargs = {
      "misp_enrichment": egx2_tests.enrichment_block() if block == "default" else block,
      "misp_node_ids": node_ids or egx2_tests.ENRICHMENT_NODE_IDS,
    }
  if template:
    kwargs["event_url_template"] = template
  return egx2.run_insight_brief(question="q", graph=graph, model=None, provider_call=provider, **kwargs), payloads


class EventUrlTemplateTests(unittest.TestCase):
  def test_shared_template_vector(self):
    """The same file drives the playground validator test (spec v0.3 §4)."""
    cases = json.loads(TEMPLATE_VECTOR_PATH.read_text())["cases"]
    self.assertGreaterEqual(len(cases), 45)
    for case in cases:
      with self.subTest(case=case["name"]):
        self.assertIs(misp.validate_event_url_template(case["template"]), case["valid"])

  def test_non_string_templates_are_rejected(self):
    for value in (None, 5, b"https://m.test/{event_id}", ["https://m.test/{event_id}"]):
      with self.subTest(value=value):
        self.assertFalse(misp.validate_event_url_template(value))

  def test_template_flows_through_build_validate_and_view(self):
    rows = [_row("CVE", "nvd", {"cwe": ["CWE-79"]}, "e-1", ("901", "902"))]
    block = misp.build_misp_enrichment_block(rows, {"e-1": "N0"}, event_url_template=CUSTOM_TEMPLATE)
    self.assertEqual(block["nodes"][0]["misp_event_urls"], [
      "https://misp.example.test/misp/events/view/901", "https://misp.example.test/misp/events/view/902",
    ])
    self.assertTrue(misp.validate_misp_enrichment_block(block, CUSTOM_TEMPLATE))
    self.assertFalse(misp.validate_misp_enrichment_block(block))  # default template: parity fails
    self.assertFalse(misp.validate_misp_enrichment_block(block, "http://x.test/{event_id}"))
    self.assertTrue(misp.contains_raw_misp_payload(block))
    self.assertFalse(misp.contains_raw_misp_payload(block, CUSTOM_TEMPLATE))
    self.assertIsNone(misp.build_model_view(block, max_bytes=2048))
    self.assertIsNotNone(misp.build_model_view(block, max_bytes=2048, event_url_template=CUSTOM_TEMPLATE))
    with self.assertRaises(ValueError):
      misp.build_misp_enrichment_block(rows, {"e-1": "N0"}, event_url_template="http://x.test/{event_id}")

  def test_default_template_output_is_unchanged(self):
    rows = [_row("CVE", "nvd", {"cwe": ["CWE-79"]}, "e-1", ("901",))]
    block = misp.build_misp_enrichment_block(rows, {"e-1": "N0"})
    self.assertEqual(block["nodes"][0]["misp_event_urls"], ["https://misp.edgeguard.org/events/view/901"])

  def test_api_config_default_is_the_old_host(self):
    from extensions.business.cybersec.edgeguard.edgeguard_api import EdgeguardApiPlugin
    self.assertEqual(
      EdgeguardApiPlugin.CONFIG["MISP_ENRICHMENT_EVENT_URL_TEMPLATE"], misp.DEFAULT_EVENT_URL_TEMPLATE,
    )


class ApiTemplateTests(unittest.TestCase):
  """Invalid template => no block, counter + 1, last error name, API answers;
  a custom template reaches build, admission and the brief runner in one
  request; a changed config applies on the next request."""

  MISP_ROWS = [{
    "element_id": "indicator-1", "labels": ["Indicator"], "misp_event_ids": ["901"],
    "misp_attribute_ids": ["attr-1"], "source": "alienvault_otx", "last_imported_from": None,
    "sourced": [{"source_id": "alienvault_otx", "raw_data": json.dumps({"pulse_name": "Synthetic Pulse"})}],
  }]

  def _explain(self, plugin):
    indicator = _GraphNode("indicator-1", ["Indicator"], {
      "value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
    })
    source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
    record = _DriverRecord({"i": indicator, "s": source}, {"i": {"value": "203.0.113.7"}, "s": {"name": "AlienVault OTX"}})
    session = MagicMock()
    session.__enter__.return_value = session

    def run(query, **_params):
      if ENRICHMENT_QUERY_MARKER in str(getattr(query, "text", query)):
        return self.MISP_ROWS
      return _Result([record], keys=["i", "s"])

    session.run.side_effect = run
    driver = MagicMock()
    driver.session.return_value = session
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=driver):
        result = plugin.explain_graph(
          uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
          request="Explain the indicator",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
        )
    return result, session

  @staticmethod
  def _template_log_lines(plugin):
    return sum("MISP_ENRICHMENT_EVENT_URL_TEMPLATE" in str(call) for call in plugin.P.call_args_list)

  def _plugin(self, template, strategy="eel_compatibility"):
    plugin = _make_api(edgeguard_explanation_strategy=strategy)
    plugin.cfg_misp_enrichment_enabled = True
    plugin.cfg_misp_enrichment_event_url_template = template
    plugin.P = MagicMock()

    def no_model(_payload):
      raise GraphFirstRuntimeError("model_not_ready", "completion", "no model in tests")

    plugin._graph_first_provider_for_tests = no_model
    return plugin

  def test_invalid_template_turns_enrichment_off_counts_and_api_answers(self):
    for strategy in ("eel_compatibility", "one_call", "insight_brief"):
      with self.subTest(strategy=strategy):
        plugin = self._plugin("http://user:secret@misp.test/e/{event_id}", strategy)
        result, session = self._explain(plugin)
        self.assertEqual(result.get("status", result.get("result", {}).get("status")), "ok")
        self.assertNotIn("misp_enrichment", json.dumps(result))
        self.assertFalse(any(
          ENRICHMENT_QUERY_MARKER in str(getattr(call.args[0], "text", call.args[0]))
          for call in session.run.call_args_list
        ))  # the internal enrichment query never ran
        self.assertEqual(plugin._misp_enrichment_error_count, 1)
        self.assertEqual(plugin._misp_enrichment_last_error, "invalid_event_url_template")
        logged = " ".join(str(call) for call in plugin.P.call_args_list)
        self.assertNotIn("secret", logged)
        self.assertEqual(self._template_log_lines(plugin), 1)

  def test_bad_value_is_logged_once_but_counted_every_request(self):
    plugin = self._plugin("not a template")
    for _ in range(3):
      self._explain(plugin)
    self.assertEqual(plugin._misp_enrichment_error_count, 3)
    self.assertEqual(self._template_log_lines(plugin), 1)

  def test_disabled_enrichment_ignores_a_bad_template(self):
    plugin = self._plugin("garbage")
    plugin.cfg_misp_enrichment_enabled = False
    self._explain(plugin)
    self.assertEqual(plugin._misp_enrichment_error_count, 0)

  def test_custom_template_and_config_change_apply_per_request(self):
    plugin = self._plugin(CUSTOM_TEMPLATE)
    result, _session = self._explain(plugin)
    self.assertEqual(
      result["misp_enrichment"]["nodes"][0]["misp_event_urls"],
      ["https://misp.example.test/misp/events/view/901"],
    )
    plugin.cfg_misp_enrichment_event_url_template = "https://other.example.test/e/{event_id}"
    result, _session = self._explain(plugin)
    self.assertEqual(
      result["misp_enrichment"]["nodes"][0]["misp_event_urls"], ["https://other.example.test/e/901"],
    )
    self.assertEqual(plugin._misp_enrichment_error_count, 0)

  def test_template_reaches_admission_and_both_brief_runners(self):
    deterministic = egx2.run_insight_brief(
      question="q", graph=egx2_tests.enrichment_graph(), model=None, provider_call=lambda _payload: {},
      allow_model=False,
    )
    for strategy, target, outcome in (
      ("one_call", "run_analyst_brief", {"side_effect": GraphFirstRuntimeError("model_not_ready", "completion", "x")}),
      ("insight_brief", "egx2.run_insight_brief", {"return_value": deterministic}),
    ):
      for template in (CUSTOM_TEMPLATE, misp.DEFAULT_EVENT_URL_TEMPLATE):
        with self.subTest(strategy=strategy, template=template):
          plugin = self._plugin(template, strategy)
          with patch(f"extensions.business.cybersec.edgeguard.edgeguard_api.{target}", **outcome) as fake_call:
            self._explain(plugin)
          self.assertEqual(fake_call.call_count, 1)
          kwargs = fake_call.call_args.kwargs
          self.assertEqual(kwargs["event_url_template"], template)
          self.assertTrue(misp.validate_misp_enrichment_block(kwargs["misp_enrichment"], template))
          self.assertEqual(plugin._misp_enrichment_error_count, 0)  # admission accepted the host

  def test_citation_drop_counter_is_reported(self):
    plugin = self._plugin(misp.DEFAULT_EVENT_URL_TEMPLATE, "insight_brief")
    result = egx2.run_insight_brief(
      question="q", graph=egx2_tests.enrichment_graph(), model=None, provider_call=lambda _payload: {},
      allow_model=False,
    )
    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief",
      return_value={**result, "citation_drops": 2},
    ):
      self._explain(plugin)
    self.assertEqual(plugin._misp_citation_drop_count, 2)

  def test_ref_drop_counter_is_reported(self):
    # Spec v0.4 §4.2: the value-free drop map folds into one plugin counter.
    plugin = self._plugin(misp.DEFAULT_EVENT_URL_TEMPLATE, "insight_brief")
    result = egx2.run_insight_brief(
      question="q", graph=egx2_tests.enrichment_graph(), model=None, provider_call=lambda _payload: {},
      allow_model=False,
    )
    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief",
      return_value={**result, "misp_ref_drops": {"ref_unknown": 2, "ref_over_cap": 1}},
    ):
      self._explain(plugin)
    self.assertEqual(plugin._misp_ref_drop_count, 3)

  def test_prepared_execution_path_carries_no_block_and_no_citations(self):
    from extensions.business.cybersec.edgeguard.graph_first_explanation import resolve_mode

    cypher = "MATCH (c:CVE) RETURN c.cve_id AS cve_id, c.cvss AS cvss ORDER BY c.cvss DESC LIMIT 5"
    plan = {
      "accepted_cypher": cypher, "executed_cypher": cypher, "result_columns": ["cve_id", "cvss"],
      "projection_descriptors": [],
      "limit_policy": {
        "generated_limit": 5, "executed_limit": 5, "transport_row_cap": 25,
        "server_max_rows": 50, "limit_adjusted": False, "query_rewritten": False,
      },
      "broadening": {"enabled": False, "cypher": None, "strategy": None, "result_columns": None},
      "validation": {"result_shape": "ranked_projection"},
    }
    execution_result = {
      "executed_cypher": cypher, "primary_row_count": 1, "row_count": 1, "truncated": False, "broadened": False,
      "graph": {"nodes": [], "relationships": [], "truncated": False},
      "query_result_evidence": {
        "schema_version": "edgeguard.query_result_evidence.v1", "columns": ["cve_id", "cvss"],
        "rows": [{"ordinal": 0, "values": [{"type": "string", "value": "CVE-2000-0001"}, {"type": "float", "value": 9.8}]}],
      },
      "execution_trace": {"selected": "primary", "executions": []},
    }
    plugin = self._plugin(misp.DEFAULT_EVENT_URL_TEMPLATE, "one_call")
    plugin._graph_first_provider_for_tests = lambda _payload: {
      "content": json.dumps({"text": "CVE-2000-0001 ranks highest."}), "finish_reason": "stop", "completion_tokens": 8,
    }
    result = plugin._explain_prepared_execution(
      plan=plan, execution_result=execution_result, request="Which CVE ranks highest?",
      mode_plan=resolve_mode("balanced"), deadline=1e20,
    )
    self.assertTrue(result["explained"])
    self.assertNotIn("misp_enrichment", result)
    self.assertNotIn("misp_citations", json.dumps(result))
    self.assertFalse(result["packet"]["redaction"]["contains_raw_misp_payload"])


class SharedCitationVectorTests(unittest.TestCase):
  """The same file drives the playground validator test (spec v0.3 §2.3)."""

  @classmethod
  def setUpClass(cls):
    cls.vector = json.loads(VECTOR_PATH.read_text())

  def test_every_case_outcome_matches(self):
    graph_ids, entity_ids = set(self.vector["graph_node_ids"]), self.vector["observation_entity_ids"]
    self.assertGreaterEqual(len(self.vector["cases"]), 20)
    for case in self.vector["cases"] + [self.vector["same_name_case"]]:
      with self.subTest(case=case["name"]):
        self.assertIs(runtime.public_citation_is_valid(case["citation"], entity_ids, graph_ids), case["valid"])

  def test_list_cases_follow_the_server_cap(self):
    view = {"nodes": [{"entity": "CVE-2000-0001", "node_ref": "N0"}]}
    for case in self.vector["list_cases"]:
      with self.subTest(case=case["name"]):
        item = {"misp_citations": [
          {"entity": "CVE-2000-0001", "field": "cwe", "value": f"CWE-{i}"} for i in range(case["count"])
        ]}
        public, dropped = runtime._public_citations(item, ["c1"], view, {"N0": "c1"}, {"c1"})
        self.assertEqual((len(public), dropped), (min(case["count"], runtime.MAX_PUBLIC_CITATIONS), 0))
        # A list the client accepts is non-empty and at most the cap; the server never emits more.
        self.assertEqual(case["valid"], 1 <= case["count"] <= runtime.MAX_PUBLIC_CITATIONS)

  def test_non_finite_numbers_are_rejected(self):
    base = {"entity": "A", "field": "cwe", "node_ref": "N0", "entity_id": "n:a"}
    for value in (float("nan"), float("inf"), 10**400, 2**53 + 1, -(2**53) - 1):
      with self.subTest(value=value):
        self.assertFalse(runtime.public_citation_is_valid({**base, "value": value}, ["n:a"], {"n:a"}))
    self.assertTrue(runtime.public_citation_is_valid({**base, "value": 2**53}, ["n:a"], {"n:a"}))


def _graph_with_same_name():
  graph = egx2_tests.enrichment_graph()
  # A second CVE node sharing the display name of c1, listed before it in the view order.
  graph["nodes"].append({"id": "c2", "labels": ["CVE"], "properties": {"cve_id": "CVE-2000-0001", "cvss_score": 9.8}})
  return graph


class PublicCitationTests(unittest.TestCase):
  def _case(self, **kwargs):
    result, payloads = _egx2_run(**kwargs)
    return result, payloads

  def test_graded_citation_becomes_public_with_node_ref_and_entity_id(self):
    result, _ = self._case()
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    observations = result["case_explanation"]["observations"]
    self.assertEqual(observations[0]["misp_citations"], [
      {"entity": "CVE-2000-0001", "field": "cwe", "value": "CWE-79", "node_ref": "N0", "entity_id": "c1"},
    ])
    self.assertEqual(observations[1]["misp_citations"][0]["node_ref"], "N1")
    self.assertEqual(observations[1]["misp_citations"][0]["entity_id"], "i1")
    for observation in observations:
      for citation in observation["misp_citations"]:
        self.assertIn(citation["entity_id"], observation["entity_ids"])

  def test_string_values_are_stripped_numbers_stay_numbers(self):
    brief = lambda sheet: egx2_tests.enrichment_brief(  # noqa: E731
      sheet, cve_citation={"entity": "CVE-2000-0001", "field": "cwe", "value": " CWE-79 "},
    )
    result, _ = _egx2_run(brief)
    self.assertEqual(result["case_explanation"]["observations"][0]["misp_citations"][0]["value"], "CWE-79")
    cited = runtime._public_citations(
      {"misp_citations": [{"entity": "A", "field": "n", "value": 7}]},
      ["n:a"], {"nodes": [{"entity": "A", "node_ref": "N0"}]}, {"N0": "n:a"}, {"n:a"},
    )
    self.assertEqual(cited[0][0]["value"], 7)
    self.assertIsInstance(cited[0][0]["value"], int)

  def test_list_valued_citation_yields_one_per_item_and_dedupes(self):
    brief = lambda sheet: egx2_tests.enrichment_brief(  # noqa: E731
      sheet, cve_citation={"entity": "CVE-2000-0001", "field": "cwe", "value": ["CWE-79", "CWE-79"]},
    )
    result, _ = _egx2_run(brief)
    self.assertEqual(len(result["case_explanation"]["observations"][0]["misp_citations"]), 1)

  def test_over_eight_is_cut_after_dedupe_in_model_order(self):
    entries = [{"entity": "A", "field": "f", "value": f"v{i % 10}"} for i in range(12)]
    entries.insert(1, {"entity": "a", "field": "f", "value": "V0"})  # duplicate, case-insensitive
    public, dropped = runtime._public_citations(
      {"misp_citations": entries}, ["n:a"], {"nodes": [{"entity": "A", "node_ref": "N0"}]},
      {"N0": "n:a"}, {"n:a"},
    )
    self.assertEqual([c["value"] for c in public], [f"v{i}" for i in range(8)])
    self.assertEqual(dropped, 0)

  def test_no_citation_no_key_and_no_block_is_byte_identical(self):
    brief = lambda sheet: {  # noqa: E731
      **egx2_tests.enrichment_brief(sheet),
      "observations": [
        {k: v for k, v in o.items() if k != "misp_citations"} for o in egx2_tests.enrichment_brief(sheet)["observations"]
      ],
    }
    result, _ = _egx2_run(brief)
    self.assertNotIn("misp_citations", json.dumps(result["case_explanation"]))
    self.assertNotIn("citation_drops", result)
    plain, _ = _egx2_run(egx2_tests.enrichment_brief, block=None)
    self.assertEqual(plain["explanation_trace"]["outcome"]["status"], "fallback")  # ungrounded without a view
    self.assertNotIn("misp_citations", json.dumps(plain["case_explanation"]))

  def test_failed_attempt_citations_never_appear(self):
    attempts = []

    def brief(sheet):
      attempts.append(1)
      good = egx2_tests.enrichment_brief(sheet)
      if len(attempts) == 1:  # bad value on attempt one
        return egx2_tests.enrichment_brief(
          sheet, cve_citation={"entity": "CVE-2000-0001", "field": "cwe", "value": "CWE-1111"},
        )
      return {**good, "observations": [
        {k: v for k, v in o.items() if k != "misp_citations"} for o in good["observations"]
      ]}

    result, payloads = _egx2_run(brief)
    self.assertEqual(len(payloads), 2)
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertNotIn("CWE-1111", json.dumps(result["case_explanation"]))
    self.assertNotIn("misp_citations", json.dumps(result["case_explanation"]))

  def test_fallback_after_two_failed_attempts_has_no_citations(self):
    brief = lambda sheet: egx2_tests.enrichment_brief(  # noqa: E731
      sheet, cve_citation={"entity": "CVE-2000-0001", "field": "cwe", "value": "CWE-1111"},
    )
    result, _ = _egx2_run(brief)
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "fallback")
    self.assertNotIn("misp_citations", json.dumps(result["case_explanation"]))

  def test_same_name_nodes_with_disagreeing_ids_drop_the_citation_keep_the_observation(self):
    graph = _graph_with_same_name()
    # entity_ids come from the first graph node named CVE-2000-0001 (c1); the view resolved N0 to c2.
    result, _ = _egx2_run(graph=graph, node_ids={"N0": "c2", "N1": "i1"})
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    first = result["case_explanation"]["observations"][0]
    self.assertEqual(first["entity_ids"], ["c1"])
    self.assertIn("text", first)
    self.assertNotIn("misp_citations", first)
    self.assertIn("misp_citations", result["case_explanation"]["observations"][1])
    self.assertEqual(result["citation_drops"], 1)
    agreeing, _ = _egx2_run(graph=graph, node_ids={"N0": "c1", "N1": "i1"})
    self.assertEqual(agreeing["case_explanation"]["observations"][0]["misp_citations"][0]["entity_id"], "c1")
    self.assertNotIn("citation_drops", agreeing)

  def test_each_client_rule_drops_the_citation_not_the_observation(self):
    view = {"nodes": [{"entity": "A", "node_ref": "N0"}]}
    cases = {
      "entity_too_long": ({"entity": "A" * 257, "field": "cwe", "value": "x"}, {"nodes": [{"entity": "A" * 257, "node_ref": "N0"}]}),
      "field_uppercase": ({"entity": "A", "field": "Cwe", "value": "x"}, view),
      "field_too_long": ({"entity": "A", "field": "f" * 65, "value": "x"}, view),
      "value_too_long": ({"entity": "A", "field": "cwe", "value": "v" * 501}, view),
      "value_non_finite": ({"entity": "A", "field": "cwe", "value": float("inf")}, view),
      "bad_node_ref": ({"entity": "A", "field": "cwe", "value": "x"}, {"nodes": [{"entity": "A", "node_ref": "n0"}]}),
    }
    for name, (citation, node_view) in cases.items():
      with self.subTest(name=name):
        node_ref = node_view["nodes"][0]["node_ref"]
        public, dropped = runtime._public_citations(
          {"misp_citations": [citation]}, ["n:a"], node_view, {node_ref: "n:a"}, {"n:a"},
        )
        self.assertEqual((public, dropped), ([], 1))
    for name, ids, graph_ids in (("entity_id_not_in_graph", ["n:a"], set()), ("entity_id_not_in_observation", [], {"n:a"})):
      with self.subTest(name=name):
        public, dropped = runtime._public_citations(
          {"misp_citations": [{"entity": "A", "field": "cwe", "value": "x"}]}, ids, view, {"N0": "n:a"}, graph_ids,
        )
        self.assertEqual((public, dropped), ([], 1))
    public, dropped = runtime._public_citations(
      {"misp_citations": [{"entity": "A", "field": "cwe", "value": "x"}]}, ["n:a"], view, {}, {"n:a"},
    )
    self.assertEqual((public, dropped), ([], 1))  # node_ref has no packet id

  def test_deterministic_cases_carry_none(self):
    graph = egx2_tests.enrichment_graph()
    result = egx2.run_insight_brief(
      question="q", graph=graph, model=None, provider_call=lambda p: {}, allow_model=False,
      misp_enrichment=egx2_tests.enrichment_block(), misp_node_ids=egx2_tests.ENRICHMENT_NODE_IDS,
    )
    self.assertNotIn("misp_citations", json.dumps(result["case_explanation"]))


def _failing_brief(sheet, **kwargs):
  return egx2_tests.enrichment_brief(sheet, **kwargs)


SENTINEL_ENTITY = "SENTINEL-ENTITY-ZQX"
SENTINEL_VALUE = "SENTINEL-VALUE-ZQX"


class GateFailureCodeTests(unittest.TestCase):
  def _codes(self, brief_edit, block="default"):
    graph = egx2_tests.enrichment_graph()
    sheet = insights.build_insight_sheet(graph)
    brief = egx2_tests.enrichment_brief(sheet)
    brief_edit(brief)
    view = egx2_tests._view(None if block == "default" else block)
    return brief, sheet, view, brief_gates.failure_codes(brief, sheet, view)

  def test_citation_entity_not_exemplar(self):
    def edit(brief):
      brief["observations"][0]["misp_citations"][0]["entity"] = "203.0.113.7"
    _b, _s, _v, codes = self._codes(edit)
    self.assertIn("citation_entity_not_exemplar", codes["enrichment_grounding"])

  def test_citation_entity_no_enrichment(self):
    def edit(brief):
      brief["observations"][1]["misp_citations"][0]["entity"] = "quietsieve"
    _b, _s, _v, codes = self._codes(edit)
    self.assertIn("citation_entity_no_enrichment", codes["enrichment_grounding"])

  def test_citation_field_not_in_node(self):
    def edit(brief):
      brief["observations"][1]["misp_citations"][0]["field"] = "pulse_tlp"
    _b, _s, _v, codes = self._codes(edit)
    self.assertIn("citation_field_not_in_node", codes["enrichment_grounding"])

  def test_citation_value_mismatch(self):
    def edit(brief):
      brief["observations"][0]["misp_citations"][0]["value"] = "CWE-80"
    _b, _s, _v, codes = self._codes(edit)
    self.assertIn("citation_value_mismatch", codes["enrichment_grounding"])

  def test_lexical_codes(self):
    cases = {
      "unsafe_url_scheme": "Open javascript:alert(1) to triage this.",
      "ungrounded_url": "See https://unlisted.example.test/x for CVE-2000-0001.",
      "ungrounded_cwe": "CVE-2000-0001 is also CWE-999.",
      "enrichment_node_mismatch": "CVE-2000-0001 is listed in Synthetic Pulse Alpha.",
    }
    for code, text in cases.items():
      with self.subTest(code=code):
        def edit(brief, text=text):
          brief["observations"][0]["text"] = text
          brief["observations"][0]["misp_citations"] = []
        _b, _s, _v, codes = self._codes(edit)
        self.assertEqual(codes["enrichment_grounding"], [code])

  def test_codes_are_sorted_deduped_and_value_free(self):
    def edit(brief):
      brief["observations"][0]["misp_citations"] = [
        {"entity": SENTINEL_ENTITY, "field": "cwe", "value": SENTINEL_VALUE},
        {"entity": SENTINEL_ENTITY, "field": "cwe", "value": SENTINEL_VALUE + "2"},
        {"entity": "CVE-2000-0001", "field": "cwe", "value": SENTINEL_VALUE},
      ]
    _b, _s, _v, codes = self._codes(edit)
    self.assertEqual(codes["enrichment_grounding"], ["citation_entity_not_exemplar", "citation_value_mismatch"])
    rendered = json.dumps(codes)
    self.assertNotIn("SENTINEL", rendered)
    self.assertLessEqual(len(codes["enrichment_grounding"]), brief_gates.MAX_FAILURE_CODES_PER_GATE)

  def test_other_gates_each_have_one_fixed_code(self):
    graph = egx2_tests.sample_graph()
    sheet = insights.build_insight_sheet(graph)
    base = egx2_tests.valid_brief(sheet)
    self.assertEqual(brief_gates.failure_codes(base, sheet), {})
    edits = {
      "entity_linking": lambda b: b["observations"][0].update(exemplar_entities=[SENTINEL_ENTITY]),
      "insight_id_validity": lambda b: b["observations"][0].update(insight_ids=["I999"]),
      "count_claims": lambda b: b["observations"][0].update(text="There are 4242 indicators."),
      "confidence_comparisons": lambda b: b["observations"][0].update(text="Its confidence is the highest."),
    }
    for gate, edit in edits.items():
      with self.subTest(gate=gate):
        brief = json.loads(json.dumps(base))
        edit(brief)
        codes = brief_gates.failure_codes(brief, sheet)
        self.assertEqual(codes[gate], [brief_gates.GATE_FAILURE_CODES[gate]])
        self.assertNotIn("SENTINEL", json.dumps(codes))

  def test_failure_codes_agree_with_grade_over_every_fixture(self):
    fixtures = []
    graph = egx2_tests.enrichment_graph()
    sheet = insights.build_insight_sheet(graph)
    view = egx2_tests._view()
    good = egx2_tests.enrichment_brief(sheet)
    fixtures.append((good, sheet, view))
    fixtures.append((good, sheet, None))
    for edit in (
      lambda b: b["observations"][0]["misp_citations"][0].update(value="CWE-80"),
      lambda b: b["observations"][0]["misp_citations"][0].update(entity="203.0.113.7"),
      lambda b: b["observations"][1]["misp_citations"][0].update(field="pulse_tlp"),
      lambda b: b["observations"][1]["misp_citations"][0].update(entity="quietsieve"),
      lambda b: b["observations"][0].update(text="CWE-999 appears at https://x.example.test/a"),
      lambda b: b["observations"][0].update(insight_ids=["I999"]),
      lambda b: b["observations"][0].update(exemplar_entities=["nobody"]),
      lambda b: b["observations"][0].update(text="9999 indicators and the highest confidence"),
    ):
      brief = json.loads(json.dumps(good))
      edit(brief)
      fixtures.append((brief, sheet, view))
    plain_graph = egx2_tests.sample_graph()
    plain_sheet = insights.build_insight_sheet(plain_graph)
    fixtures.append((egx2_tests.valid_brief(plain_sheet), plain_sheet, None))
    failing = 0
    for index, (brief, fixture_sheet, fixture_view) in enumerate(fixtures):
      with self.subTest(index=index):
        results = brief_gates.grade(brief, fixture_sheet, fixture_view)
        hard_failed = {name for name, (passed, _detail, tier) in results.items() if tier == "hard" and not passed}
        failing += bool(hard_failed)
        self.assertEqual(hard_failed, set(brief_gates.failure_codes(brief, fixture_sheet, fixture_view)))
    self.assertGreaterEqual(failing, 6)

  def test_grade_output_shape_is_unchanged(self):
    sheet = insights.build_insight_sheet(egx2_tests.sample_graph())
    results = brief_gates.grade(egx2_tests.valid_brief(sheet), sheet)
    self.assertEqual(set(results), set(brief_gates.HARD_GATES) | set(brief_gates.ADVISORY_GATES))
    for name, value in results.items():
      self.assertEqual(len(value), 3)
      self.assertIsInstance(value[0], bool)
      self.assertIsInstance(value[1], str)
      self.assertEqual(value[2], "hard" if name in brief_gates.HARD_GATES else "advisory")


class TraceGateFailureTests(unittest.TestCase):
  def test_failed_calls_carry_codes_passed_calls_do_not(self):
    attempts = []

    def brief(sheet):
      attempts.append(1)
      if len(attempts) == 1:
        return egx2_tests.enrichment_brief(
          sheet, cve_citation={"entity": SENTINEL_ENTITY, "field": "cwe", "value": SENTINEL_VALUE},
        )
      good = egx2_tests.enrichment_brief(sheet)
      return good

    result, _ = _egx2_run(brief)
    calls = result["explanation_trace"]["calls"]
    self.assertEqual([c["status"] for c in calls], ["failed", "supported"])
    self.assertEqual(calls[0]["gate_failures"], {"enrichment_grounding": ["citation_entity_not_exemplar"]})
    self.assertNotIn("gate_failures", calls[1])
    self.assertEqual(calls[0]["gates"]["enrichment_grounding"], False)
    self.assertNotIn("SENTINEL", json.dumps(result["explanation_trace"]))
    self.assertNotIn("SENTINEL", json.dumps(result["case_explanation"]))

  def test_codes_are_present_without_a_block(self):
    graph = egx2_tests.sample_graph()
    sheet_holder = {}

    def brief(sheet):
      sheet_holder["sheet"] = sheet
      value = egx2_tests.valid_brief(sheet)
      value["observations"][0]["insight_ids"] = ["I999"]
      return value

    payloads = []
    result = egx2.run_insight_brief(
      question="q", graph=graph, model=None,
      provider_call=lambda payload: payloads.append(payload) or {
        "finish_reason": "stop", "completion_tokens": 9,
        "content": json.dumps(brief(insights.build_insight_sheet(graph))),
      },
    )
    calls = result["explanation_trace"]["calls"]
    self.assertEqual(calls[0]["gate_failures"], {"insight_id_validity": ["unknown_insight_id"]})

  def test_first_attempt_success_trace_has_no_gate_failures_key(self):
    result, _ = _egx2_run()
    self.assertNotIn("gate_failures", json.dumps(result["explanation_trace"]))
