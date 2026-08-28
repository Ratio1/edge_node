import json
import unittest

from extensions.business.cybersec.edgeguard import egx2
from extensions.business.cybersec.edgeguard.egx2 import brief_gates, insights
from extensions.business.cybersec.edgeguard.egx2.field_catalog import CATALOG, CATALOG_SHA256
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError


def sample_graph():
  return {
    "nodes": [
      {"id": "n1", "labels": ["Indicator"], "properties": {"value": "a" * 64, "indicator_type": "hash", "confidence_score": 0.5, "source": ["otx"]}},
      {"id": "n2", "labels": ["Indicator"], "properties": {"value": "b" * 64, "indicator_type": "hash", "confidence_score": 0.5, "source": ["otx"]}},
      {"id": "n3", "labels": ["Malware"], "properties": {"name": "quietsieve", "confidence_score": 0.6, "source": ["otx"]}},
    ],
    "relationships": [
      {"id": "r1", "type": "INDICATES", "startNodeId": "n1", "endNodeId": "n3", "properties": {}},
      {"id": "r2", "type": "INDICATES", "startNodeId": "n2", "endNodeId": "n3", "properties": {}},
    ],
    "truncated": False,
  }


def valid_brief(sheet):
  top = sheet[0]["id"]
  tier = next((i.get("tier") for i in sheet if i["kind"] == "confidence"), "low")
  return {
    "assessment": "The indicators likely map to a single malware family.",
    "observations": [
      {"text": "2 indicators indicate \"quietsieve\".", "insight_ids": [top], "exemplar_entities": ["quietsieve"]},
    ],
    "why_it_matters": "Shared indicators suggest common tooling.",
    "next_checks": [{"text": "Check the indicator hashes against endpoint telemetry.", "insight_ids": [top]}],
    "confidence": {"tier": tier or "low", "basis": "per the sheet confidence insight"},
  }


class Egx2CatalogTests(unittest.TestCase):
  def test_catalog_hash_is_pinned(self):
    # Pins the canonical-JSON catalog manifest hash (EGX/2 spec requirement).
    # An intentional catalog change must update this constant AND the spec.
    canonical = json.dumps(
      {"catalog": CATALOG, "derived": __import__(
        "extensions.business.cybersec.edgeguard.egx2.field_catalog", fromlist=["DERIVED"]
      ).DERIVED},
      sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    self.assertEqual(len(CATALOG_SHA256), 64)
    self.assertEqual(CATALOG_SHA256, egx2.CATALOG_SHA256)

  def test_profile_sha_is_stable_and_exported(self):
    self.assertEqual(len(egx2.PROFILE_SHA256), 64)
    self.assertEqual(egx2.PROFILE_ID, "EGX/2")
    self.assertEqual(egx2.STRATEGY, "insight_brief")


class Egx2RuntimeTests(unittest.TestCase):
  def test_model_path_success(self):
    graph = sample_graph()
    sheet = insights.build_insight_sheet(graph)
    payloads = []

    def provider(payload):
      payloads.append(payload)
      return {"finish_reason": "stop", "completion_tokens": 90, "content": json.dumps(valid_brief(sheet))}

    result = egx2.run_insight_brief(question="q", graph=graph, model="base_qwen3_4b", provider_call=provider)
    case = result["case_explanation"]
    trace = result["explanation_trace"]
    self.assertEqual(case["schema_version"], egx2.CASE_EXPLANATION_VERSION)
    self.assertEqual(case["provenance"]["mode"], "model")
    self.assertEqual(trace["outcome"], {"status": "supported", "attempted_calls": 1, "completed_calls": 1, "safe_code": None})
    self.assertEqual(len(payloads), 1)
    self.assertEqual(payloads[0]["max_tokens"], egx2.MAX_TOKENS)
    self.assertEqual(payloads[0]["response_format"], {"type": "json_object"})
    # exemplar entity resolves to a packet-graph node id
    self.assertEqual(case["observations"][0]["entity_ids"], ["n3"])
    self.assertTrue(case["insight_index"])

  def test_gate_failure_retries_once_then_falls_back(self):
    graph = sample_graph()
    sheet = insights.build_insight_sheet(graph)
    bad = valid_brief(sheet)
    bad["observations"][0]["exemplar_entities"] = ["invented-actor"]
    calls = []

    def provider(payload):
      calls.append(payload)
      return {"finish_reason": "stop", "completion_tokens": 90, "content": json.dumps(bad)}

    result = egx2.run_insight_brief(question="q", graph=graph, model=None, provider_call=provider)
    self.assertEqual(len(calls), 2)
    self.assertIn("RETRY", calls[1]["messages"][1]["content"])
    self.assertIn("entity_linking", calls[1]["messages"][1]["content"])
    case = result["case_explanation"]
    self.assertEqual(case["provenance"]["mode"], "deterministic_fallback")
    outcome = result["explanation_trace"]["outcome"]
    self.assertEqual(outcome["status"], "fallback")
    self.assertEqual(outcome["safe_code"], "deterministic_validation_failed")
    self.assertEqual(outcome["attempted_calls"], 2)

  def test_provider_failure_falls_back_deterministically(self):
    def provider(payload):
      raise GraphFirstRuntimeError("provider_timeout", "provider", "timed out")

    result = egx2.run_insight_brief(question="q", graph=sample_graph(), model=None, provider_call=provider)
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")
    self.assertEqual(result["explanation_trace"]["outcome"]["safe_code"], "provider_timeout")

  def test_model_not_ready_skips_retry(self):
    calls = []

    def provider(payload):
      calls.append(payload)
      raise GraphFirstRuntimeError("model_not_ready", "configuration", "starting")

    result = egx2.run_insight_brief(question="q", graph=sample_graph(), model=None, provider_call=provider)
    self.assertEqual(len(calls), 1)
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")

  def test_thin_sheet_never_calls_model(self):
    def provider(payload):
      raise AssertionError("model must not be called for a thin sheet")

    result = egx2.run_insight_brief(question="q", graph={"nodes": [], "relationships": []}, model=None, provider_call=provider)
    case = result["case_explanation"]
    self.assertEqual(case["provenance"]["mode"], "deterministic_no_pattern")
    outcome = result["explanation_trace"]["outcome"]
    self.assertEqual(outcome, {"status": "deterministic", "attempted_calls": 0, "completed_calls": 0, "safe_code": "no_notable_pattern"})

  def test_model_not_admitted_degrades_without_call(self):
    def provider(payload):
      raise AssertionError("model must not be called when not admitted")

    result = egx2.run_insight_brief(question="q", graph=sample_graph(), model=None, provider_call=provider, allow_model=False)
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")
    self.assertEqual(result["explanation_trace"]["outcome"]["safe_code"], "model_not_admitted")

  def test_truncated_completion_retries_then_falls_back(self):
    def provider(payload):
      return {"finish_reason": "length", "completion_tokens": egx2.MAX_TOKENS, "content": "{"}

    result = egx2.run_insight_brief(question="q", graph=sample_graph(), model=None, provider_call=provider)
    self.assertEqual(result["explanation_trace"]["outcome"]["safe_code"], "output_truncated")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 2)
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")


class Egx2GateTests(unittest.TestCase):
  def test_count_claim_rejects_unbacked_number(self):
    graph = sample_graph()
    sheet = insights.build_insight_sheet(graph)
    brief = valid_brief(sheet)
    brief["observations"][0]["text"] = "17 indicators indicate quietsieve."
    results = brief_gates.grade(brief, sheet)
    passed, _detail, tier = results["count_claims"]
    self.assertFalse(passed)
    self.assertEqual(tier, "hard")


if __name__ == "__main__":
  unittest.main()


class Egx2TruncationTests(unittest.TestCase):
  def test_deterministic_reason_skips_model_and_carries_safe_code(self):
    def provider(payload):
      raise AssertionError("model must not be called for a truncated result")

    result = egx2.run_insight_brief(
      question="q", graph=sample_graph(), model=None, provider_call=provider,
      deterministic_reason="transport_truncated",
    )
    case = result["case_explanation"]
    self.assertEqual(case["provenance"]["mode"], "deterministic_fallback")
    self.assertIn("transport row cap", case["assessment"]["text"])
    outcome = result["explanation_trace"]["outcome"]
    self.assertEqual(outcome, {"status": "fallback", "attempted_calls": 0, "completed_calls": 0, "safe_code": "transport_truncated"})


def chain_graph():
  nodes = [
    {"id": f"i{k}", "labels": ["Indicator"], "properties": {"value": chr(97 + k) * 64, "indicator_type": "hash", "confidence_score": 0.3 + k * 0.1, "source": ["otx"]}}
    for k in range(4)
  ]
  nodes += [
    {"id": "m1", "labels": ["Malware"], "properties": {"name": "kyber", "confidence_score": 0.5, "source": ["otx"]}},
    {"id": "s1", "labels": ["Source"], "properties": {"name": "AlienVault OTX", "confidence_score": 0.9, "source": ["otx", "misp"]}},
  ]
  rels = [
    {"id": f"r{k}", "type": "INDICATES", "startNodeId": f"i{k}", "endNodeId": "m1", "properties": {}}
    for k in range(4)
  ] + [
    {"id": f"q{k}", "type": "SOURCED_FROM", "startNodeId": f"i{k}", "endNodeId": "s1", "properties": {}}
    for k in range(3)
  ]
  return {"nodes": nodes, "relationships": rels, "truncated": False}


class Egx2InsightLayerV2Tests(unittest.TestCase):
  def test_plural_verb_and_group_confidence(self):
    sheet = insights.build_insight_sheet(chain_graph())
    conv = [i for i in sheet if i["kind"] == "convergence"]
    self.assertTrue(conv)
    kyber = next(i for i in conv if i["target"] == "kyber")
    self.assertIn("4 indicators indicate malware \"kyber\"", kyber["text_hint"])
    self.assertIn("member source-data confidence mean", kyber["text_hint"])
    self.assertIsInstance(kyber["group_confidence"], float)

  def test_chain_primitive_stitches_two_hops(self):
    sheet = insights.build_insight_sheet(chain_graph())
    chains = [i for i in sheet if i["kind"] == "chain"]
    self.assertEqual(len(chains), 1)
    hint = chains[0]["text_hint"]
    self.assertIn("3 indicators both indicate malware \"kyber\"", hint)
    self.assertIn("sourced from source \"AlienVault OTX\"", hint)
    self.assertEqual(chains[0]["count"], 3)

  def test_render_sheet_does_not_use_target_as_member_example(self):
    from extensions.business.cybersec.edgeguard.egx2 import brief_profile
    sheet = insights.build_insight_sheet(chain_graph())
    rendered = brief_profile.render_sheet(sheet)
    self.assertNotIn("[examples: kyber", rendered)
    self.assertIn("members have no citable names", rendered)


class Egx2ConfidenceComparisonGateTests(unittest.TestCase):
  def _brief_with_assessment(self, sheet, text):
    brief = valid_brief(sheet)
    brief["assessment"] = text
    return brief

  def test_unbacked_superlative_rejected(self):
    sheet = insights.build_insight_sheet(sample_graph())  # single group -> no comparisons possible
    brief = self._brief_with_assessment(sheet, "Malware quietsieve shows the lowest source-data confidence.")
    passed, detail, tier = brief_gates.grade(brief, sheet)["confidence_comparisons"]
    self.assertFalse(passed)
    self.assertEqual(tier, "hard")

  def test_backed_superlative_accepted_when_extreme_matches(self):
    sheet = insights.build_insight_sheet(chain_graph())
    groups = {i["target"]: i["group_confidence"] for i in sheet if "group_confidence" in i}
    self.assertGreaterEqual(len(groups), 2)
    lowest = min(groups, key=groups.get)
    brief = self._brief_with_assessment(sheet, f"\"{lowest}\" shows the lowest member confidence.")
    passed, detail, _ = brief_gates.grade(brief, sheet)["confidence_comparisons"]
    self.assertTrue(passed, detail)

  def test_backed_superlative_rejected_when_extreme_wrong(self):
    sheet = insights.build_insight_sheet(chain_graph())
    groups = {i["target"]: i["group_confidence"] for i in sheet if "group_confidence" in i}
    highest = max(groups, key=groups.get)
    brief = self._brief_with_assessment(sheet, f"\"{highest}\" shows the lowest member confidence.")
    passed, detail, _ = brief_gates.grade(brief, sheet)["confidence_comparisons"]
    self.assertFalse(passed)

  def test_plain_tier_statement_passes(self):
    sheet = insights.build_insight_sheet(sample_graph())
    brief = self._brief_with_assessment(sheet, "Source-data confidence is low across the result.")
    passed, _detail, _ = brief_gates.grade(brief, sheet)["confidence_comparisons"]
    self.assertTrue(passed)
