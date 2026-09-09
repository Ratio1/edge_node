"""Offline tests for the EGX/1 explain pipeline (`explain_notation.py`,
`explain_selection.py`, `explain_gates.py`, `explain_profile.py`,
`explain_runtime_v2.py`).

Ported from `workbooks/egm-047-notation-bakeoff/tests/test_offline.py`
(EGM-047 Phase 2/3) plus new edge-node-specific coverage: `resolve_mode_v2`
drift rejections, retry topology with a scripted provider stub, coverage v2
math, the profile-manifest SHA pin, sentinel non-leakage across failure
traces, the response byte cap, and fact -> entity mapping correctness.

No network, no model calls, no service restarts -- pure functions and
scripted stubs only.
"""
from __future__ import annotations

import copy
import json
import re
import unittest

from extensions.business.cybersec.edgeguard import explain_gates as gates
from extensions.business.cybersec.edgeguard import explain_notation as notation
from extensions.business.cybersec.edgeguard import explain_profile as profile
from extensions.business.cybersec.edgeguard import explain_runtime_v2 as runtime
from extensions.business.cybersec.edgeguard import explain_selection as selection
from extensions.business.cybersec.edgeguard.graph_first_explanation import GraphFirstContractError
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError


def tiny_graph():
  """A small but representative graph: two labels, a relationship, a
  forbidden-looking property, and an oversized list property."""
  return {
    "nodes": [
      {
        "id": "n:ind-1",
        "labels": ["Indicator"],
        "caption": "paylock-updates.com",
        "properties": {
          "value": "paylock-updates.com",
          "type": "domain",
          "embedding_vector": [0.1, 0.2, 0.3],
          "uses_techniques": [f"T{i}" for i in range(15)],
        },
      },
      {
        "id": "n:mal-1",
        "labels": ["Malware"],
        "caption": "LockBit 4.0",
        "properties": {"name": "LockBit 4.0"},
      },
      {
        "id": "n:actor-1",
        "labels": ["ThreatActor"],
        "caption": "FIN13",
        "properties": {"name": "FIN13"},
      },
    ],
    "relationships": [
      {
        "id": "r:1",
        "type": "INDICATES",
        "startNodeId": "n:ind-1",
        "endNodeId": "n:mal-1",
        "properties": {"confidence": "medium"},
      },
      {
        "id": "r:2",
        "type": "ATTRIBUTED_TO",
        "startNodeId": "n:mal-1",
        "endNodeId": "n:actor-1",
        "properties": {},
      },
    ],
  }


def duplicated_graph():
  g = tiny_graph()
  g["nodes"] = g["nodes"] + [copy.deepcopy(g["nodes"][0])]
  g["relationships"] = g["relationships"] + [copy.deepcopy(g["relationships"][0])]
  return g


def word_counter(text: str) -> int:
  """Deterministic, dependency-free token-count stand-in for offline tests."""
  return max(1, len(str(text).split()))


# ==========================================================================
# explain_notation
# ==========================================================================

class NotationDeterminismTests(unittest.TestCase):
  def test_same_input_twice_is_byte_identical(self):
    graph = tiny_graph()
    for notation_id in notation.NOTATIONS:
      with self.subTest(notation=notation_id):
        first = notation.render(notation_id, graph, "question")
        second = notation.render(notation_id, graph, "question")
        self.assertEqual(first.text, second.text)
        self.assertEqual(first.text.encode("utf-8"), second.text.encode("utf-8"))

  def test_numbered_facts_first_encounter_order(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    self.assertEqual(list(rendered.fact_ids[:2]), ["F1", "F2"])
    self.assertIn('F1: Indicator "paylock-updates.com" INDICATES Malware "LockBit 4.0".', rendered.text)

  def test_real_names_not_opaque_aliases(self):
    graph = tiny_graph()
    for notation_id in notation.NOTATIONS:
      with self.subTest(notation=notation_id):
        text = notation.render(notation_id, graph, "q").text
        self.assertIn("LockBit 4.0", text)
        self.assertIn("FIN13", text)

  def test_list_truncation_marker_is_explicit(self):
    graph = tiny_graph()
    text = notation.render("entity_cards", graph, "q").text
    self.assertIn("more)", text)

  def test_fact_tokens_resolve_in_their_own_universe(self):
    graph = tiny_graph()
    f_pattern = re.compile(r"\b(F\d+):")
    rendered = notation.render("numbered_facts", graph, "q")
    found = set(f_pattern.findall(rendered.text))
    self.assertTrue(found)
    self.assertTrue(found.issubset(rendered.citation_universe()))

  def test_numbered_facts_relationship_fact_members_include_both_endpoints_and_relationship(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    self.assertEqual(rendered.citation_subject("F1"), "n:ind-1")
    self.assertEqual(set(rendered.citation_members("F1")), {"n:ind-1", "r:1", "n:mal-1"})

  def test_numbered_facts_property_fact_members_are_the_node_alone(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    property_fact = next(fid for fid in rendered.fact_ids if rendered.citation_members(fid) == ("n:ind-1",))
    self.assertEqual(rendered.citation_subject(property_fact), "n:ind-1")

  def test_entity_cards_citation_members(self):
    graph = tiny_graph()
    rendered = notation.render("entity_cards", graph)
    self.assertEqual(rendered.citation_subject("E1"), "n:ind-1")
    self.assertEqual(rendered.citation_members("E1"), ("n:ind-1",))
    self.assertEqual(set(rendered.citation_members("L1")), {"n:ind-1", "r:1", "n:mal-1"})


# ==========================================================================
# explain_selection
# ==========================================================================

class SelectionStageTests(unittest.TestCase):
  def test_stage_a_drops_forbidden_properties(self):
    sanitized, trace = selection.stage_a_sanitize(tiny_graph())
    node = next(n for n in sanitized["nodes"] if n["id"] == "n:ind-1")
    self.assertNotIn("embedding_vector", node["properties"])
    self.assertTrue(any(t["action"] == "drop_property" and t["property"] == "embedding_vector" for t in trace))

  def test_stage_a_drops_noise_properties(self):
    graph = tiny_graph()
    graph["nodes"][0]["properties"]["uuid"] = "should-not-survive"
    sanitized, trace = selection.stage_a_sanitize(graph)
    node = next(n for n in sanitized["nodes"] if n["id"] == "n:ind-1")
    self.assertNotIn("uuid", node["properties"])
    self.assertTrue(any(t["property"] == "uuid" and t["reason"] == "noise_property_name" for t in trace))

  def test_stage_a_keeps_first_imported_at(self):
    graph = tiny_graph()
    graph["nodes"][0]["properties"]["first_imported_at"] = "2026-01-01"
    sanitized, _trace = selection.stage_a_sanitize(graph)
    node = next(n for n in sanitized["nodes"] if n["id"] == "n:ind-1")
    self.assertIn("first_imported_at", node["properties"])

  def test_stage_a_truncates_lists_with_explicit_marker(self):
    sanitized, trace = selection.stage_a_sanitize(tiny_graph())
    node = next(n for n in sanitized["nodes"] if n["id"] == "n:ind-1")
    techniques = node["properties"]["uses_techniques"]
    self.assertEqual(len(techniques), 11)  # 10 kept + 1 marker
    self.assertEqual(techniques[-1], "(+5 more)")
    self.assertTrue(any(t["action"] == "truncate_list" for t in trace))

  def test_stage_a_caps_long_strings_at_word_boundary(self):
    graph = tiny_graph()
    graph["nodes"][0]["properties"]["description"] = "word " * 100
    sanitized, trace = selection.stage_a_sanitize(graph)
    node = next(n for n in sanitized["nodes"] if n["id"] == "n:ind-1")
    self.assertTrue(node["properties"]["description"].endswith("(+truncated)"))
    self.assertFalse(node["properties"]["description"].endswith("... (+truncated)"))
    self.assertTrue(any(t["action"] == "cap_string" for t in trace))

  def test_stage_a_deduplicates_nodes_and_relationships(self):
    sanitized, trace = selection.stage_a_sanitize(duplicated_graph())
    self.assertEqual(len(sanitized["nodes"]), 3)
    self.assertEqual(len(sanitized["relationships"]), 2)
    self.assertTrue(any(t["action"] == "dedupe_node" for t in trace))
    self.assertTrue(any(t["action"] == "dedupe_relationship" for t in trace))

  def test_stage_b_identity_properties_are_tier_zero_and_undroppable(self):
    salience, _trace = selection.stage_b_salience(tiny_graph(), question="")
    self.assertEqual(salience[("node", "n:ind-1", "value")], 0)
    self.assertEqual(salience[("node", "n:mal-1", "name")], 0)

  def test_stage_b_projected_columns_are_tier_zero(self):
    salience, _trace = selection.stage_b_salience(tiny_graph(), question="", projected_columns=["type"])
    self.assertEqual(salience[("node", "n:ind-1", "type")], 0)

  def test_stage_b_question_overlap_is_tier_one(self):
    salience, _trace = selection.stage_b_salience(tiny_graph(), question="Which domain indicators are active?")
    self.assertEqual(salience[("node", "n:ind-1", "type")], 1)

  def test_stage_c_ranks_question_matching_node_as_anchor(self):
    ranked_ids, trace = selection.stage_c_structural(tiny_graph(), question="What does FIN13 do?")
    self.assertEqual(ranked_ids[0], "n:actor-1")
    self.assertIn("n:actor-1", trace[0]["anchors"])

  def test_referential_integrity_preserved_through_pipeline(self):
    graph = duplicated_graph()
    render_fn = lambda g: notation.render("numbered_facts", g).text  # noqa: E731
    for budget in (5, 20, 60, 5000):
      with self.subTest(budget=budget):
        final_graph, _trace = selection.run_pipeline(
          graph, question="What does FIN13 do?", token_counter=word_counter,
          budget=budget, render_fn=render_fn,
        )
        self.assertTrue(selection.referential_integrity_ok(final_graph))

  def test_budgeter_converges_under_a_tiny_budget(self):
    graph = tiny_graph()
    render_fn = lambda g: notation.render("numbered_facts", g).text  # noqa: E731
    final_graph, trace = selection.run_pipeline(
      graph, question="What does FIN13 do?", token_counter=word_counter,
      budget=1, render_fn=render_fn,
    )
    final_tokens = word_counter(render_fn(final_graph))
    self.assertLessEqual(final_tokens, 1)
    final_entry = trace[-1]
    self.assertEqual(final_entry["action"], "final")
    self.assertTrue(final_entry["under_budget"])

  def test_budgeter_never_truncates_mid_string(self):
    graph = tiny_graph()
    render_fn = lambda g: notation.render("numbered_facts", g).text  # noqa: E731
    final_graph, _trace = selection.run_pipeline(
      graph, question="q", token_counter=word_counter, budget=10, render_fn=render_fn,
    )
    for node_item in final_graph["nodes"]:
      for value in node_item.get("properties", {}).values():
        if isinstance(value, str):
          self.assertFalse(value.endswith("..."))

  def test_stage_d_tightens_before_dropping_nodes(self):
    graph = tiny_graph()
    render_fn = lambda g: notation.render("numbered_facts", g).text  # noqa: E731
    full_tokens = word_counter(render_fn(selection.stage_a_sanitize(graph)[0]))
    final_graph, trace = selection.run_pipeline(
      graph, question="q", token_counter=word_counter,
      budget=max(1, full_tokens - 1), render_fn=render_fn,
    )
    actions = [t["action"] for t in trace]
    if "drop_low_rank_node" in actions and "tighten_list_cap" in actions:
      self.assertLess(actions.index("tighten_list_cap"), actions.index("drop_low_rank_node"))
    self.assertTrue(selection.referential_integrity_ok(final_graph))


# ==========================================================================
# explain_gates
# ==========================================================================

class GatesTests(unittest.TestCase):
  def setUp(self):
    graph = tiny_graph()
    self.rendered = notation.render("numbered_facts", graph, "q")
    self.universe = self.rendered.citation_universe()

  def test_citation_membership_catches_fabricated_citation(self):
    response = {"citations": ["F1", "F99"], "finding": "does not matter here"}
    passed, detail = gates.citation_membership(response, self.universe)
    self.assertFalse(passed)
    self.assertIn("F99", detail)

  def test_citation_membership_passes_real_citations(self):
    real = list(self.universe)[:2]
    response = {"citations": real, "finding": "does not matter here"}
    passed, _detail = gates.citation_membership(response, self.universe)
    self.assertTrue(passed)

  def test_lexical_grounding_catches_quoted_hallucination(self):
    response = {"citations": [], "finding": 'The actor "GhostAsp" is behind this.'}
    passed, detail = gates.lexical_grounding(response, self.rendered.text)
    self.assertFalse(passed)
    self.assertIn("GhostAsp", detail)

  def test_lexical_grounding_passes_grounded_quote(self):
    response = {"citations": [], "finding": 'The malware "LockBit 4.0" was observed.'}
    passed, _detail = gates.lexical_grounding(response, self.rendered.text)
    self.assertTrue(passed)

  def test_lexical_grounding_rejects_relation_language_absent_from_cited_facts(self):
    response = {
      "citations": ["F2"],
      "finding": "Malware LockBit 4.0 indicates FIN13 via MITRE techniques.",
    }
    passed, detail = gates.lexical_grounding(response, self.rendered.text)
    self.assertFalse(passed)
    self.assertIn("indicates", detail)
    self.assertIn("via", detail)

  def test_lexical_grounding_allows_exact_relation_and_generic_link_words(self):
    exact = {"citations": ["F2"], "finding": "Malware LockBit 4.0 is attributed to ThreatActor FIN13."}
    linked = {"citations": ["F2"], "finding": "Malware LockBit 4.0 is linked to ThreatActor FIN13."}
    self.assertTrue(gates.lexical_grounding(exact, self.rendered.text)[0])
    self.assertTrue(gates.lexical_grounding(linked, self.rendered.text)[0])

  def test_inline_id_validity_catches_unquoted_entity_hallucination(self):
    response = {"citations": ["F1"], "finding": "Indicator paylock-updates.com [F99] indicates Malware LockBit 4.0."}
    lexical_passed, _ = gates.lexical_grounding(response, self.rendered.text)
    self.assertTrue(lexical_passed, "inline IDs are validated by the dedicated gate")
    inline_passed, detail = gates.inline_id_validity(response, self.universe)
    self.assertFalse(inline_passed)
    self.assertIn("F99", detail)

  def test_inline_id_validity_passes_real_inline_ids(self):
    real_id = next(iter(self.universe))
    response = {"citations": [], "finding": f"See the linked entity [{real_id}]."}
    passed, _detail = gates.inline_id_validity(response, self.universe)
    self.assertTrue(passed)

  def test_duplicate_findings_catches_exact_duplicate(self):
    findings = [
      {"citations": ["F1"], "finding": "FIN13 is linked to LockBit."},
      {"citations": ["F2"], "finding": "FIN13 is linked to LockBit."},
    ]
    passed, detail = gates.duplicate_findings(findings)
    self.assertFalse(passed)
    self.assertIn("exact", detail)

  def test_duplicate_findings_catches_near_duplicate_paraphrase(self):
    findings = [
      {"citations": ["F1"], "finding": "FIN13 is linked to the malware LockBit via an indicator."},
      {"citations": ["F2"], "finding": "FIN13 is linked to the malware LockBit through an indicator."},
    ]
    passed, detail = gates.duplicate_findings(findings, jaccard_threshold=0.8)
    self.assertFalse(passed)
    self.assertIn("jaccard", detail)

  def test_duplicate_findings_passes_distinct_findings(self):
    findings = [
      {"citations": ["F1"], "finding": "FIN13 is linked to LockBit."},
      {"citations": ["F3"], "finding": "TA-Quicksand employs phishing techniques."},
    ]
    passed, _detail = gates.duplicate_findings(findings)
    self.assertTrue(passed)

  def test_duplicate_findings_vacuously_passes_a_single_finding(self):
    passed, _detail = gates.duplicate_findings([{"citations": ["F1"], "finding": "x"}])
    self.assertTrue(passed)

  def test_distinct_anchors_catches_redundant_shared_anchor(self):
    findings = [
      {"citations": ["F1", "F2"], "finding": "..."},
      {"citations": ["F1", "F2"], "finding": "..."},
    ]
    passed, detail = gates.distinct_anchors(findings)
    self.assertFalse(passed)
    self.assertIn("F1", detail)

  def test_distinct_anchors_allows_shared_anchor_with_different_citations(self):
    findings = [
      {"citations": ["F1", "F2", "F4"], "finding": "..."},
      {"citations": ["F1", "F3", "F7"], "finding": "..."},
    ]
    passed, _detail = gates.distinct_anchors(findings)
    self.assertTrue(passed)

  def test_distinct_anchors_passes_distinct_first_citations(self):
    findings = [
      {"citations": ["F1", "F2"], "finding": "..."},
      {"citations": ["F3", "F4"], "finding": "..."},
    ]
    passed, _detail = gates.distinct_anchors(findings)
    self.assertTrue(passed)

  def test_distinct_anchors_vacuously_passes_a_single_finding(self):
    passed, _detail = gates.distinct_anchors([{"citations": ["F1"], "finding": "x"}])
    self.assertTrue(passed)

  def test_evaluate_all_runs_all_five_gates(self):
    response = {"citations": ["F1"], "finding": 'The evidence links "paylock-updates.com" [F1] to the malware.'}
    result = gates.evaluate_all(response, self.rendered)
    self.assertEqual(set(result), {
      "citation_membership", "lexical_grounding", "inline_id_validity",
      "duplicate_findings", "distinct_anchors",
    })
    self.assertTrue(all(passed for passed, _detail in result.values()))


# ==========================================================================
# explain_profile
# ==========================================================================

class ProfileTests(unittest.TestCase):
  def test_prompt_caps_appear_in_both_system_and_user_messages(self):
    prompt = profile.build_analyst_prompt("numbered_facts", "EVIDENCE-TEXT", "QUESTION-TEXT")
    for message in (prompt["system"], prompt["user"]):
      self.assertIn("at most 20 words", message)
      self.assertIn("at most 4", message)
    self.assertIn("EVIDENCE-TEXT", prompt["user"])
    self.assertIn("QUESTION-TEXT", prompt["user"])
    self.assertIn('{"citations"', prompt["system"])

  def test_prompt_requires_named_entities_and_exact_ids(self):
    prompt = profile.build_analyst_prompt("numbered_facts", "EVIDENCE-TEXT", "QUESTION-TEXT")
    self.assertIn("Copy one cited fact", prompt["system"])
    self.assertIn("copy one cited fact", prompt["user"])

  def test_retry_prompt_names_failed_checks_only(self):
    prompt = profile.build_retry_prompt("numbered_facts", "EVIDENCE-TEXT", "QUESTION-TEXT", ["citation_membership", "lexical_grounding"])
    self.assertIn("citation_membership, lexical_grounding", prompt["user"])
    self.assertNotIn("EVIDENCE-TEXT" * 2, prompt["user"])  # evidence block appears once

  def test_reduce_prompt_json_braces_are_not_doubled(self):
    prompt = profile.build_reduce_prompt("q", [{"citations": ["F1"], "finding": "x"}])
    self.assertIn('{"findings"', prompt["system"])
    self.assertNotIn("{{", prompt["system"])

  def test_choose_feeding_strategy_thresholds(self):
    self.assertEqual(profile.choose_feeding_strategy(500, 700)["strategy"], "single_shot")
    self.assertEqual(profile.choose_feeding_strategy(5000, 700)["strategy"], "map_reduce")
    self.assertLessEqual(profile.choose_feeding_strategy(5000, 700)["chunks"], profile.MAP_REDUCE_MAX_CHUNKS)

  def test_map_reduce_ships_disabled(self):
    self.assertFalse(profile.MAP_REDUCE_ENABLED)

  def test_sampling_and_token_constants_match_the_egx1_spec(self):
    self.assertEqual(profile.MODEL_CARD_SAMPLING, {"temperature": 0.1, "top_p": 1.0, "top_k": 20})
    self.assertEqual(profile.MAX_TOKENS, 64)
    self.assertEqual(profile.COMPLETION_TOKEN_LIMIT, 127)

  def test_compute_evidence_budget_matches_measured_rate_formula(self):
    total = profile.total_prompt_token_budget()
    self.assertEqual(profile.compute_evidence_budget(0), int(total))
    self.assertEqual(profile.compute_evidence_budget(100), int(total) - 100)

  def test_measure_scaffold_tokens_excludes_evidence_text(self):
    scaffold = profile.measure_scaffold_tokens("numbered_facts", "q", word_counter)
    with_evidence = word_counter(profile.build_analyst_prompt("numbered_facts", "F1: x.", "q")["system"]) + word_counter(
      profile.build_analyst_prompt("numbered_facts", "F1: x.", "q")["user"]
    )
    self.assertLess(scaffold, with_evidence)

  def test_profile_manifest_sha256_is_pinned(self):
    # Recomputing the manifest hash at test time (rather than hardcoding a
    # second literal) would only prove the function is idempotent, not that
    # the manifest has not silently drifted -- so this pins the literal SHA
    # computed once from the checked-in profile.
    self.assertEqual(
      profile.PROFILE_MANIFEST_SHA256,
      "77cdb50d37ef7b26a4d4231dfc3e7b3fa753cce818b49c9bd8e9eb669ffc2369",
    )
    self.assertRegex(profile.PROFILE_MANIFEST_SHA256, r"^[0-9a-f]{64}$")

  def test_profile_manifest_is_canonical_json_serializable(self):
    canonical = json.dumps(profile.PROFILE_MANIFEST, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    import hashlib
    self.assertEqual(hashlib.sha256(canonical.encode("utf-8")).hexdigest(), profile.PROFILE_MANIFEST_SHA256)


# ==========================================================================
# explain_runtime_v2: resolve_mode_v2
# ==========================================================================

class ResolveModeV2Tests(unittest.TestCase):
  def test_default_mode_is_balanced_64_tokens(self):
    plan = runtime.resolve_mode_v2()
    self.assertEqual(plan.mode, "balanced")
    self.assertEqual(plan.row_limit, 25)
    self.assertEqual(plan.call_cap, 1)
    self.assertEqual(plan.max_tokens, 64)

  def test_explicit_modes_resolve_row_limits(self):
    self.assertEqual(runtime.resolve_mode_v2(explanation_mode="fast").row_limit, 10)
    self.assertEqual(runtime.resolve_mode_v2(explanation_mode="balanced").row_limit, 25)
    self.assertEqual(runtime.resolve_mode_v2(explanation_mode="thorough").row_limit, 50)

  def test_invalid_mode_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(explanation_mode="ludicrous")
    self.assertEqual(raised.exception.code, "invalid_explanation_mode")

  def test_matching_sampling_values_are_accepted(self):
    plan = runtime.resolve_mode_v2(temperature=0.1, top_p=1.0, top_k=20, max_tokens=64)
    self.assertEqual(plan.max_tokens, 64)

  def test_temperature_drift_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(temperature=0.7)
    self.assertEqual(raised.exception.code, "explanation_configuration_drift")

  def test_top_p_drift_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(top_p=0.8)
    self.assertEqual(raised.exception.code, "explanation_configuration_drift")

  def test_top_k_drift_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(top_k=40)
    self.assertEqual(raised.exception.code, "explanation_configuration_drift")

  def test_max_tokens_drift_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(max_tokens=128)
    self.assertEqual(raised.exception.code, "explanation_configuration_drift")

  def test_row_limit_exceeds_cap_rejected(self):
    with self.assertRaises(GraphFirstContractError) as raised:
      runtime.resolve_mode_v2(explanation_rows=51)
    self.assertEqual(raised.exception.code, "explanation_limit_exceeded")


# ==========================================================================
# explain_runtime_v2: run_explanation_v2 (scripted provider stub, no network)
# ==========================================================================

def _analyst_response_for(rendered, ok=True, fact_override=None):
  fact_id = fact_override or rendered.fact_ids[0]
  quoted = re.search(r'"([^"]+)"', rendered.text.split("\n", 1)[0]).group(1)
  if ok:
    return {"citations": [fact_id], "finding": f'The evidence links "{quoted}" [{fact_id}] to the malware.'}
  return {"citations": ["F999"], "finding": 'The evidence links "totally-fabricated-name" to nothing.'}


class ScriptedProvider:
  """A scripted provider stub: pops one canned response per call, raising if
  exhausted. Mirrors the pattern in `tests/test_api.py`'s
  `_graph_first_provider_for_tests` seam, adapted for direct
  `run_explanation_v2` unit tests (no HTTP, no plugin)."""

  def __init__(self, responses):
    self._responses = list(responses)
    self.calls = []

  def __call__(self, payload):
    self.calls.append(payload)
    if not self._responses:
      raise AssertionError("provider stub exhausted its scripted responses")
    return self._responses.pop(0)


def _stop(content, completion_tokens=20):
  return {"content": json.dumps(content) if not isinstance(content, str) else content, "finish_reason": "stop", "completion_tokens": completion_tokens, "duration_ms": 1.0}


class RunExplanationV2Tests(unittest.TestCase):
  def setUp(self):
    self.graph = tiny_graph()
    self.mode = runtime.resolve_mode_v2(explanation_mode="fast")

  def _rendered_for(self, graph=None):
    graph = graph or self.graph
    return notation.render("numbered_facts", graph)

  def test_single_pass_success_assembles_case_explanation_and_coverage(self):
    rendered = self._rendered_for()
    provider = ScriptedProvider([_stop(_analyst_response_for(rendered))])
    result = runtime.run_explanation_v2(
      question="Which malware does this indicator indicate?",
      graph=self.graph,
      mode=self.mode,
      token_counter=word_counter,
      provider_call=provider,
      remaining_time=lambda: 500.0,
    )
    self.assertEqual(len(provider.calls), 1)
    response_schema = provider.calls[0]["response_format"]["schema"]
    self.assertEqual(response_schema["properties"]["citations"]["items"]["enum"], ["F1"])
    self.assertEqual(
      response_schema["properties"]["finding"]["enum"],
      [runtime._primary_fact_pair(rendered)[1]],
    )
    self.assertEqual(result["explanation"]["schema_version"], "edgeguard.case_explanation.v1")
    self.assertEqual(len(result["explanation"]["entity_findings"]), 1)
    self.assertEqual(result["coverage"]["schema_version"], "edgeguard.explanation_coverage.v2")
    self.assertEqual(result["explanation_trace"]["schema_version"], "edgeguard.explanation_trace.v2")
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)
    self.assertEqual(result["explanation_trace"]["calls"][0]["kind"], "analyst")
    self.assertIn("raw_output", result["explanation_trace"]["calls"][0])
    self.assertIn("parsed", result["explanation_trace"]["calls"][0])
    self.assertEqual(result["coverage"]["calls"], {"analyst": 1, "retry": 0, "total": 1})

  def test_constrained_finding_canonicalizes_grammar_unsafe_indicator_punctuation(self):
    rendered = notation.RenderedEvidence(
      "numbered_facts",
      'F1: Indicator "T104%WINDIR%\\Management Instrumentation" INDICATES Malware "quietsieve".',
      ("F1",),
      {"F1": "n:indicator"},
      {"F1": ("n:indicator", "r:indicates", "n:malware")},
    )

    response_format = runtime._constrained_response_format(rendered)

    self.assertEqual(
      response_format["schema"]["properties"]["finding"]["enum"],
      ["Indicator T104 WINDIR Management Instrumentation INDICATES Malware quietsieve."],
    )
  def test_call_records_never_carry_full_request_or_messages_success_or_failure(self):
    # UI contract: `configuration` echoes exactly the sampling contract; no
    # `request`/`messages` key ever appears on a trace-v2 call, win or lose.
    rendered = self._rendered_for()
    ok_provider = ScriptedProvider([_stop(_analyst_response_for(rendered))])
    ok_result = runtime.run_explanation_v2(
      question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
      provider_call=ok_provider, remaining_time=lambda: 500.0,
    )
    ok_call = ok_result["explanation_trace"]["calls"][0]
    self.assertNotIn("request", ok_call)
    self.assertNotIn("messages", ok_call)
    self.assertEqual(ok_call["configuration"], {"temperature": 0.1, "top_p": 1.0, "max_tokens": 64})

    bad = _stop(_analyst_response_for(rendered, ok=False))
    bad_provider = ScriptedProvider([bad, bad])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=bad_provider, remaining_time=lambda: 500.0,
      )
    for call in raised.exception.trace["calls"]:
      self.assertNotIn("request", call)
      self.assertNotIn("messages", call)
      self.assertEqual(call["configuration"], {"temperature": 0.1, "top_p": 1.0, "max_tokens": 64})

  def test_completion_token_boundary_accepts_127_and_rejects_128(self):
    rendered = self._rendered_for()
    at_ceiling = _stop(_analyst_response_for(rendered), completion_tokens=127)
    provider = ScriptedProvider([at_ceiling])
    result = runtime.run_explanation_v2(
      question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
      provider_call=provider, remaining_time=lambda: 500.0,
    )
    self.assertEqual(result["explanation_trace"]["calls"][0]["completion_tokens"], 127)

    over_ceiling = _stop(_analyst_response_for(rendered), completion_tokens=128)
    provider = ScriptedProvider([over_ceiling])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(raised.exception.code, "completion_metadata_missing")

  def test_entity_findings_entity_id_is_first_cited_facts_subject(self):
    rendered = self._rendered_for()
    # F2 is the ATTRIBUTED_TO fact (subject: n:mal-1); cite it first.
    response = {"citations": ["F2", "F1"], "finding": 'Malware "LockBit 4.0" [F2] indicates "paylock-updates.com" [F1].'}
    provider = ScriptedProvider([_stop(response)])
    result = runtime.run_explanation_v2(
      question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
      provider_call=provider, remaining_time=lambda: 500.0,
    )
    finding = result["explanation"]["entity_findings"][0]
    self.assertEqual(finding["entity_id"], rendered.citation_subject("F2"))
    self.assertEqual(set(finding["evidence_ids"]), set(rendered.citation_members("F2")) | set(rendered.citation_members("F1")))

  def test_fail_then_pass_retries_once_and_succeeds(self):
    rendered = self._rendered_for()
    bad = _stop(_analyst_response_for(rendered, ok=False))
    good = _stop(_analyst_response_for(rendered, ok=True))
    provider = ScriptedProvider([bad, good])
    result = runtime.run_explanation_v2(
      question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
      provider_call=provider, remaining_time=lambda: 500.0,
    )
    self.assertEqual(len(provider.calls), 2)
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 2)
    self.assertEqual(result["explanation_trace"]["calls"][0]["kind"], "analyst")
    self.assertEqual(result["explanation_trace"]["calls"][0]["status"], "failed")
    self.assertEqual(result["explanation_trace"]["calls"][1]["kind"], "retry")
    self.assertEqual(result["explanation_trace"]["calls"][1]["status"], "supported")
    # the retry prompt names the failed check(s), never raw model output
    retry_request = provider.calls[1]
    retry_user = retry_request["messages"][-1]["content"]
    self.assertIn("Your previous answer failed this check:", retry_user)
    self.assertIn("citation_membership", retry_user)

  def test_fail_then_fail_is_fail_closed_after_one_retry(self):
    rendered = self._rendered_for()
    bad = _stop(_analyst_response_for(rendered, ok=False))
    provider = ScriptedProvider([bad, bad])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(len(provider.calls), 2, "must not exceed one call plus one retry")
    self.assertEqual(raised.exception.code, "deterministic_validation_failed")
    self.assertEqual(raised.exception.stage, "validation")
    self.assertEqual(raised.exception.trace["outcome"]["attempted_calls"], 2)
    self.assertEqual(raised.exception.trace["outcome"]["failure_stage"], "validation")

  def test_malformed_json_retries_then_fails_closed(self):
    provider = ScriptedProvider([_stop("not json"), _stop("still not json")])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(len(provider.calls), 2)
    self.assertEqual(raised.exception.code, "invalid_model_output")
    self.assertEqual(raised.exception.stage, "response_parse")

  def test_length_finish_reason_retries_then_fails_closed(self):
    truncated = {"content": '{"citations": ["F1"', "finish_reason": "length", "completion_tokens": 127, "duration_ms": 1.0}
    provider = ScriptedProvider([truncated, truncated])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(len(provider.calls), 2)
    self.assertEqual(raised.exception.code, "finish_reason")
    self.assertEqual(raised.exception.stage, "completion")

  def test_retry_is_gated_by_remaining_deadline_budget(self):
    rendered = self._rendered_for()
    bad = _stop(_analyst_response_for(rendered, ok=False))
    provider = ScriptedProvider([bad])
    # Enough remaining budget for the first dispatch, but not for a second
    # (retry) dispatch -- exercises the deadline-gated retry, not the
    # first-dispatch deadline check.
    calls = {"count": 0}

    def remaining_time():
      calls["count"] += 1
      return 200.0 if calls["count"] == 1 else 10.0

    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=remaining_time,
      )
    self.assertEqual(len(provider.calls), 1, "insufficient deadline budget must not dispatch a retry")
    self.assertEqual(raised.exception.code, "deterministic_validation_failed")
    self.assertEqual(raised.exception.trace["outcome"]["attempted_calls"], 1)

  def test_insufficient_deadline_before_first_dispatch_fails_closed_with_zero_calls(self):
    provider = ScriptedProvider([])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 1.0,
      )
    self.assertEqual(len(provider.calls), 0)
    self.assertEqual(raised.exception.code, "insufficient_deadline_budget")

  def test_unexpected_finish_reason_fails_closed_without_retry(self):
    weird = {"content": "{}", "finish_reason": "content_filter", "completion_tokens": 1, "duration_ms": 1.0}
    provider = ScriptedProvider([weird])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(len(provider.calls), 1)
    self.assertEqual(raised.exception.code, "finish_reason")

  def test_invalid_completion_tokens_fail_closed(self):
    rendered = self._rendered_for()
    bad_tokens = _stop(_analyst_response_for(rendered), completion_tokens=1000)
    provider = ScriptedProvider([bad_tokens])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="q", graph=self.graph, mode=self.mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    self.assertEqual(raised.exception.code, "completion_metadata_missing")


# ==========================================================================
# Coverage v2 math
# ==========================================================================

class CoverageV2Tests(unittest.TestCase):
  def test_cited_le_admitted_le_returned_invariant_holds(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    response = {"citations": [rendered.fact_ids[0]], "finding": "x"}
    coverage = runtime._build_coverage(graph, graph, rendered, response, attempted_calls=1, completed_calls=1)
    for kind in ("nodes", "relationships", "property_slots"):
      counts = coverage["counts"][kind]
      self.assertLessEqual(counts["cited"], counts["admitted"])
      self.assertLessEqual(counts["admitted"], counts["returned"])

  def test_admitted_reflects_selection_not_full_source_graph(self):
    graph = tiny_graph()
    sel_graph = {"nodes": graph["nodes"][:1], "relationships": []}
    rendered = notation.render("numbered_facts", graph)
    coverage = runtime._build_coverage(graph, sel_graph, rendered, None, attempted_calls=1, completed_calls=0)
    self.assertEqual(coverage["counts"]["nodes"]["returned"], 3)
    self.assertEqual(coverage["counts"]["nodes"]["admitted"], 1)
    self.assertEqual(coverage["counts"]["nodes"]["omitted"], 2)

  def test_no_citations_yields_zero_cited_counts(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    coverage = runtime._build_coverage(graph, graph, rendered, {"citations": [], "finding": "x"}, attempted_calls=1, completed_calls=1)
    self.assertEqual(coverage["counts"]["nodes"]["cited"], 0)
    self.assertEqual(coverage["counts"]["relationships"]["cited"], 0)

  def test_calls_dict_reflects_retry_count(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    coverage = runtime._build_coverage(graph, graph, rendered, None, attempted_calls=2, completed_calls=1)
    self.assertEqual(coverage["calls"], {"analyst": 1, "retry": 1, "total": 2})


# ==========================================================================
# Sentinel non-leakage across failure traces (mirrors tests/test_api.py's
# `EDGEGUARD_GRAPH_FIRST_PROVIDER_RECEIPT`/diagnostics sentinel patterns).
# ==========================================================================

class SentinelNonLeakageTests(unittest.TestCase):
  def test_failure_trace_never_carries_raw_output_or_evidence_text(self):
    graph = tiny_graph()
    graph["nodes"][0]["properties"]["value"] = "sentinel-private-value.example"
    mode = runtime.resolve_mode_v2(explanation_mode="fast")
    provider = ScriptedProvider([
      _stop({"citations": ["F999"], "finding": "sentinel-fabricated-finding-secret"}),
      _stop({"citations": ["F999"], "finding": "sentinel-fabricated-finding-secret"}),
    ])
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_explanation_v2(
        question="sentinel-private-question", graph=graph, mode=mode, token_counter=word_counter,
        provider_call=provider, remaining_time=lambda: 500.0,
      )
    serialized = json.dumps(raised.exception.trace)
    self.assertNotIn("sentinel-private-value.example", serialized)
    self.assertNotIn("sentinel-fabricated-finding-secret", serialized)
    self.assertNotIn("sentinel-private-question", serialized)
    self.assertNotIn("raw_output", serialized)
    self.assertNotIn("parsed", serialized)
    self.assertNotIn("messages", serialized)
    # gate outcome names travel; gate detail strings (which would carry the
    # fabricated citation/finding text) never do.
    self.assertNotIn("detail", serialized)

  def test_empty_failure_trace_before_dispatch_is_content_free(self):
    mode = runtime.resolve_mode_v2(explanation_mode="fast")
    trace = runtime.empty_failure_trace(mode, "configuration", "model_not_configured")
    serialized = json.dumps(trace)
    self.assertEqual(trace["calls"], [])
    self.assertEqual(trace["outcome"]["safe_code"], "model_not_configured")
    self.assertNotIn("raw_output", serialized)

  def test_success_trace_stays_under_1_mib(self):
    graph = tiny_graph()
    rendered = notation.render("numbered_facts", graph)
    mode = runtime.resolve_mode_v2(explanation_mode="fast")
    provider = ScriptedProvider([_stop(_analyst_response_for(rendered))])
    result = runtime.run_explanation_v2(
      question="q", graph=graph, mode=mode, token_counter=word_counter,
      provider_call=provider, remaining_time=lambda: 500.0,
    )
    size = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
    self.assertLess(size, 1_048_576)


# ==========================================================================
# Map-reduce: present, gated off
# ==========================================================================

class MapReduceGateTests(unittest.TestCase):
  def test_map_reduce_raises_when_disabled(self):
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      runtime.run_map_reduce_v2()
    self.assertEqual(raised.exception.code, "map_reduce_disabled")


if __name__ == "__main__":
  unittest.main()
