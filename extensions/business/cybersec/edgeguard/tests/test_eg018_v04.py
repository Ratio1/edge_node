"""EG-018 phase 4d: explanation spec v0.4 -- numbered MISP references in the
EGX/2 model input (`MISP REFERENCES`), model `misp_refs`, server validation and
the public `misp_reference_index`.

Synthetic fixtures only (CVE-2000-0001, 203.0.113.x, MISP ids in the 900s); no network.
"""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.cybersec.edgeguard.tests.test_eg018_v03 import (  # noqa: E402
  PRE_CHANGE_NO_BLOCK_SHA,
  _egx2_run,
  _row,
)
from extensions.business.cybersec.edgeguard.tests import test_egx2 as egx2_tests  # noqa: E402
from extensions.business.cybersec.edgeguard import egx2, misp_enrichment as misp  # noqa: E402
from extensions.business.cybersec.edgeguard.egx2 import brief_gates, brief_profile, field_catalog, insights  # noqa: E402
from extensions.business.cybersec.edgeguard.egx2 import insight_brief as runtime  # noqa: E402

VECTOR_PATH = Path(__file__).parent / "fixtures" / "misp_ref_cases.json"
TEMPLATE = misp.DEFAULT_EVENT_URL_TEMPLATE
# Request hash of the user message for a block whose nodes carry no event id, i.e. USER +
# ENRICHMENT_TEMPLATE only (the `_no_event_block` fixture below). Re-pinned for wording C
# (operator ruling 2026-10-05); with the v0.3 wording on 8c675f4 it was 8587b37e...
NO_LINES_SHA = "8d26454d25d19519b20455676e0ff3356961a019fd28612e9ce47cb584f7696f"
# v0.4 manifest (spec §2.5); CATALOG_SHA256 is not allowed to move.
V03_PROFILE_SHA256 = "962afb38da1fd79bcdd45e5a33cf94768234e8bbd313ca4f1bd69753cc287827"


def _node(ref, entity, events):
  return {"node_ref": ref, "label": "CVE", "misp_event_ids": list(events), "fields": {}, "entity": entity}


def _lines(*nodes):
  return [entry["line"] for entry in runtime._misp_references({"nodes": list(nodes)}, TEMPLATE)]


def _no_event_block():
  return misp.build_misp_enrichment_block([_row("CVE", "nvd", {"cwe": ["CWE-79"]}, event_ids=())], {"e-1": "N0"})


def _many_events_block(count=5):
  row = _row("CVE", "nvd", {"cwe": ["CWE-79"]}, event_ids=[str(900 + i) for i in range(1, count + 1)])
  return misp.build_misp_enrichment_block([row], {"e-1": "N0"})


def _with_refs(refs1=None, refs2=None, only_cve=False):
  def factory(sheet):
    brief = egx2_tests.enrichment_brief(sheet)
    if only_cve:  # for blocks that enrich the CVE node alone
      del brief["observations"][1:]
    for obs, refs in zip(brief["observations"], (refs1, refs2)):
      if refs is not None:
        obs["misp_refs"] = refs
    return brief
  return factory


class ReferenceBuilderTests(unittest.TestCase):
  def test_events_are_numbered_by_integer_order_over_all_nodes(self):
    table = runtime._misp_references({"nodes": [_node("N0", "A", ["10", "9"]), _node("N1", "B", ["100"])]}, TEMPLATE)
    self.assertEqual([(e["id"], e["event_id"]) for e in table], [("M1", "9"), ("M2", "10"), ("M3", "100")])

  def test_line_shape_names_and_more_count(self):
    nodes = [_node(f"N{i}", name, ["101"]) for i, name in enumerate(("A", "B", "C", "D", "E"))]
    self.assertEqual(_lines(*nodes), ['M1 = MISP event 101: entities "A", "B", "C" (+2 more)'])
    self.assertEqual(_lines(nodes[0]), ['M1 = MISP event 101: entities "A"'])

  def test_more_count_includes_unnameable_nodes(self):
    nodes = [_node("N0", "A", ["101"]), _node("N1", "203.0.113.7", ["101"]), _node("N2", "B", ["101"])]
    self.assertEqual(_lines(*nodes), ['M1 = MISP event 101: entities "A", "B" (+1 more)'])

  def test_unnameable_names_are_never_printed_or_truncated(self):
    raw = ["x" * 49, "a" * 64, "example.test", "https://example.test/a", "C:\\WINDOWS\\a", "203.0.113.7"]
    nodes = [_node(f"N{i}", name, ["101"]) for i, name in enumerate(raw)]
    self.assertEqual(_lines(*nodes), ["M1 = MISP event 101: 6 entities, none nameable"])
    self.assertEqual(_lines(_node("N0", "x" * 48, ["101"])), [f'M1 = MISP event 101: entities "{"x" * 48}"'])

  def test_event_without_nameable_name_keeps_its_number(self):
    nodes = [_node("N0", "203.0.113.7", ["101"]), _node("N1", "A", ["102"])]
    self.assertEqual(_lines(*nodes), [
      "M1 = MISP event 101: 1 entities, none nameable", 'M2 = MISP event 102: entities "A"',
    ])

  def test_hostile_names_cannot_start_a_line(self):
    for char in ('"', "\n", "\r", "\u2028", "\u2029", "\u0085"):
      with self.subTest(char=repr(char)):
        lines = _lines(_node("N0", f"A{char}M2 = MISP event 5", ["101"]), _node("N1", "B", ["102"]))
        self.assertEqual(len(lines), 2)
        self.assertEqual(len("\n".join(lines).splitlines()), 2)
        self.assertTrue(lines[0].isascii())

  def test_line_cap_is_eight_and_numbers_have_no_gaps(self):
    nodes = [_node(f"N{i}", f"E{i}", [str(100 + i)]) for i in range(10)]
    table = runtime._misp_references({"nodes": nodes}, TEMPLATE)
    self.assertEqual([e["id"] for e in table], [f"M{i}" for i in range(1, 9)])

  def test_byte_cap_ends_the_list_as_a_prefix(self):
    heavy = "\u2028" * 48  # 288 ASCII bytes once escaped; three per line
    nodes = [_node(f"N{i}{j}", heavy, [str(100 + i)]) for i in range(3) for j in range(3)]
    table = runtime._misp_references({"nodes": nodes}, TEMPLATE)
    self.assertEqual([e["id"] for e in table], ["M1"])
    self.assertLessEqual(len(table[0]["line"].encode("utf-8")), 1_024)

  def test_no_event_ids_yield_no_lines(self):
    self.assertEqual(runtime._misp_references({"nodes": [_node("N0", "A", [])]}, TEMPLATE), [])
    self.assertEqual(runtime._misp_references(None, TEMPLATE), [])

  def test_a_printed_name_copied_by_the_model_passes_the_gates(self):
    result, payloads = _egx2_run(_with_refs(["M1"]))
    self.assertIn('M1 = MISP event 901: entities "CVE-2000-0001"', payloads[0]["messages"][1]["content"])
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertTrue(all(result["explanation_trace"]["calls"][0]["gates"][g] for g in ("entity_linking", "enrichment_grounding")))


class PromptTests(unittest.TestCase):
  def test_section_follows_the_enrichment_block_and_system_prompt_is_untouched(self):
    _result, payloads = _egx2_run(_with_refs())
    system, user = (m["content"] for m in payloads[0]["messages"])
    self.assertEqual(system, brief_profile.SYSTEM + brief_profile.ENRICHMENT_SYSTEM_SENTENCE)
    self.assertNotIn("misp_refs", system)
    self.assertEqual(user.count("MISP REFERENCES"), 1)
    tail = user.split("MISP REFERENCES", 1)[1]
    self.assertTrue(user.index("MISP ENRICHMENT") < user.index("MISP REFERENCES"))
    self.assertTrue(tail.endswith(brief_profile.MISP_REFERENCES_INSTRUCTION))
    self.assertIn("M1 = MISP event 901", tail)
    self.assertIn("M2 = MISP event 902: 1 entities, none nameable", tail)
    self.assertIn('"misp_refs": ["M#"]', brief_profile.MISP_REFERENCES_INSTRUCTION)

  def test_no_block_request_bytes_are_unchanged(self):
    result, payloads = _egx2_run(block=None)
    self.assertEqual(result["explanation_trace"]["calls"][0]["request_sha256"], PRE_CHANGE_NO_BLOCK_SHA)
    self.assertNotIn("MISP", payloads[0]["messages"][1]["content"])

  def test_block_without_lines_sends_only_the_enrichment_template(self):
    result, payloads = _egx2_run(block=_no_event_block(), node_ids={"N0": "c1"})
    user = payloads[0]["messages"][1]["content"]
    self.assertIn("MISP ENRICHMENT", user)
    self.assertNotIn("MISP REFERENCES", user)
    self.assertTrue(user.endswith(brief_profile.ENRICHMENT_TEMPLATE.split("{enrichment}")[1].replace("{{", "{").replace("}}", "}")))
    self.assertEqual(result["explanation_trace"]["calls"][0]["request_sha256"], NO_LINES_SHA)
    self.assertEqual(hashlib.sha256(user.encode("utf-8")).hexdigest(), NO_LINES_SHA)

  def test_enrichment_template_keeps_the_citation_safety_phrases(self):
    for phrase in (
      "Never cite a value that is not listed under that entity",
      "write no URL that is not listed there verbatim",
      "misp_event_ids",
    ):
      self.assertIn(phrase, brief_profile.ENRICHMENT_TEMPLATE)

  def test_profile_pin_moves_and_catalog_pin_does_not(self):
    self.assertNotEqual(egx2.PROFILE_SHA256, V03_PROFILE_SHA256)
    self.assertEqual(egx2.PROFILE_SHA256, egx2_tests.PINNED_PROFILE_SHA256)
    self.assertEqual(field_catalog.CATALOG_SHA256, egx2_tests.PINNED_CATALOG_SHA256)
    manifest = runtime.PROFILE_MANIFEST
    self.assertEqual(
      (manifest["misp_references_max_lines"], manifest["misp_references_max_bytes"], manifest["misp_refs_max_per_observation"]),
      (8, 1_024, 3),
    )


def _direct_case(observation, nodes, node_ids, template=TEMPLATE):
  """`_model_case` on a hand-built view, for rules the gates would not let through an e2e run."""
  view = {"nodes": nodes}
  graph = {"nodes": [{"id": pid, "labels": ["CVE"], "properties": {"cve_id": pid}} for pid in set(node_ids.values())]}
  brief = {
    "assessment": "a", "why_it_matters": "w", "next_checks": [], "confidence": {"tier": "low", "basis": "b"},
    "observations": [{"insight_ids": [], **observation}],
  }
  return runtime._model_case(brief, [], graph, view, node_ids, runtime._misp_references(view, template), template)


class RefValidationTests(unittest.TestCase):
  def _refs(self, result):
    return [o.get("misp_refs") for o in result["case_explanation"]["observations"]]

  def test_exemplar_rule_accepts_and_index_lists_every_input_reference(self):
    result, _ = _egx2_run(_with_refs(["M1"], ["M2"]))
    case = result["case_explanation"]
    self.assertEqual(self._refs(result), [["M1"], ["M2"]])
    self.assertEqual(case["misp_reference_index"], [
      {"id": "M1", "event_id": "901", "event_url": misp._event_url(TEMPLATE, "901"), "node_refs": ["N0"], "entity_ids": ["c1"]},
      {"id": "M2", "event_id": "902", "event_url": misp._event_url(TEMPLATE, "902"), "node_refs": ["N1"], "entity_ids": ["i1"]},
    ])
    self.assertNotIn("misp_ref_drops", result)

  def test_text_mention_rule_accepts_without_exemplar(self):
    def factory(sheet):
      brief = egx2_tests.enrichment_brief(sheet)
      brief["observations"][0].update({"misp_refs": ["M1"], "exemplar_entities": []})
      brief["observations"][0].pop("misp_citations")
      return brief
    result, _ = _egx2_run(factory)
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertEqual(self._refs(result)[0], ["M1"])

  def test_refs_and_index_are_absent_when_no_ref_survives(self):
    for refs in (None, [], "M1", [1], ["M2"]):
      with self.subTest(refs=refs):
        result, _ = _egx2_run(_with_refs(refs))
        self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
        self.assertEqual(self._refs(result), [None, None])
        self.assertNotIn("misp_reference_index", result["case_explanation"])
    self.assertNotIn("misp_refs", json.dumps(_egx2_run(block=None)[0]["case_explanation"]))

  def test_drop_codes_each_once_and_text_stays(self):
    result, _ = _egx2_run(_with_refs(["M9", "m1", "M01", ["M1"], "M2"]))
    # M9/m1/M01 are ref_unknown (the list item is a non-string, dropped by the parse);
    # M2 lists no entity of observation 1.
    self.assertEqual(result["misp_ref_drops"], {"ref_unknown": 3, "ref_entity_not_in_observation": 1})
    self.assertEqual(self._refs(result), [None, None])
    self.assertIn("CVE-2000-0001", result["case_explanation"]["observations"][0]["text"])

  def test_over_cap_keeps_model_order_then_sorts(self):
    result, _ = _egx2_run(_with_refs(["M5", "M4", "M3", "M2", "M1"], only_cve=True), block=_many_events_block(), node_ids={"N0": "c1"})
    self.assertEqual(self._refs(result)[0], ["M3", "M4", "M5"])
    self.assertEqual(result["misp_ref_drops"], {"ref_over_cap": 2})
    self.assertEqual(len(result["case_explanation"]["misp_reference_index"]), 5)

  def test_duplicates_are_removed_silently(self):
    result, _ = _egx2_run(_with_refs(["M1", "M1", "M1"]))
    self.assertEqual(self._refs(result)[0], ["M1"])
    self.assertNotIn("misp_ref_drops", result)

  def test_exemplar_rule_alone_keeps_the_ref(self):
    nodes = [_node("N0", "Alpha", ["101"])]
    obs = {"text": "Nothing named here.", "misp_refs": ["M1"], "exemplar_entities": [" ALPHA "]}
    case, _dropped, drops, _withheld = _direct_case(obs, nodes, {"N0": "n:a"})
    self.assertEqual(case["observations"][0]["misp_refs"], ["M1"])
    self.assertFalse(drops)
    case, _dropped, drops, _withheld = _direct_case({**obs, "exemplar_entities": []}, nodes, {"N0": "n:a"})
    self.assertNotIn("misp_refs", case["observations"][0])
    self.assertEqual(drops, {"ref_entity_not_in_observation": 1})

  def test_fifty_one_nodes_on_one_event_cap_node_refs_at_fifty(self):
    nodes = [_node(f"N{i}", f"E{i}", ["101"]) for i in range(51)]
    node_ids = {f"N{i}": f"n:{i}" for i in range(51)}
    obs = {"text": "E0 appears.", "misp_refs": ["M1"], "exemplar_entities": ["E0"]}
    case, _dropped, _drops, withheld = _direct_case(obs, nodes, node_ids)
    entry = case["misp_reference_index"][0]
    self.assertEqual((len(entry["node_refs"]), len(entry["entity_ids"]), withheld), (50, 50, 0))
    self.assertEqual(case["observations"][0]["misp_refs"], ["M1"])

  def test_unresolved_node_ref_withholds_index_and_refs_and_counts_it(self):
    nodes = [_node("N0", "Alpha", ["101"])]
    obs = {"text": "Alpha appears.", "misp_refs": ["M1"], "exemplar_entities": ["Alpha"]}
    case, _dropped, _drops, withheld = _direct_case(obs, nodes, {})
    self.assertNotIn("misp_reference_index", case)
    self.assertNotIn("misp_refs", case["observations"][0])
    self.assertEqual(withheld, 1)

  def test_event_url_must_equal_the_template_expansion(self):
    nodes = [_node("N0", "Alpha", ["101"])]
    obs = {"text": "Alpha appears.", "misp_refs": ["M1"], "exemplar_entities": ["Alpha"]}
    table = runtime._misp_references({"nodes": nodes}, TEMPLATE)
    table[0]["event_url"] = misp._event_url("https://other.example.test/events/view/{event_id}", "101")
    with patch.object(runtime, "_misp_references", return_value=table):
      case, _dropped, _drops, withheld = _direct_case(obs, nodes, {"N0": "n:a"})
    self.assertNotIn("misp_reference_index", case)
    self.assertEqual(withheld, 1)

  def test_refs_on_a_no_block_run_leave_no_drop_key(self):
    result, _ = _egx2_run(_with_refs(["M9", "M1"]), block=None)
    self.assertNotIn("misp_ref_drops", result)
    self.assertNotIn("misp_ref_withheld", result)
    self.assertNotIn("misp_ref", json.dumps(result["case_explanation"]))

  def test_cut_event_is_unknown(self):
    block = _many_events_block(10)
    result, _ = _egx2_run(_with_refs(["M9", "M8"], only_cve=True), block=block, node_ids={"N0": "c1"})
    self.assertEqual(self._refs(result)[0], ["M8"])
    self.assertEqual(result["misp_ref_drops"], {"ref_unknown": 1})
    self.assertEqual(len(result["case_explanation"]["misp_reference_index"]), 8)

  def test_failed_attempt_refs_never_appear(self):
    graph = egx2_tests.enrichment_graph()
    sheet = insights.build_insight_sheet(graph)
    bad = egx2_tests.enrichment_brief(sheet)
    bad["observations"][0]["insight_ids"] = ["I99"]
    bad["observations"][0]["misp_refs"] = ["M1"]
    briefs = [bad, egx2_tests.enrichment_brief(sheet)]
    result = egx2.run_insight_brief(
      question="q", graph=graph, model=None,
      provider_call=lambda _p: {"finish_reason": "stop", "completion_tokens": 9, "content": json.dumps(briefs.pop(0))},
      misp_enrichment=egx2_tests.enrichment_block(), misp_node_ids=egx2_tests.ENRICHMENT_NODE_IDS,
    )
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertEqual(self._refs(result), [None, None])
    self.assertNotIn("misp_reference_index", result["case_explanation"])

  def test_deterministic_cases_carry_no_refs(self):
    result = egx2.run_insight_brief(
      question="q", graph=egx2_tests.enrichment_graph(), model=None, provider_call=lambda _p: {},
      allow_model=False, misp_enrichment=egx2_tests.enrichment_block(), misp_node_ids=egx2_tests.ENRICHMENT_NODE_IDS,
    )
    self.assertNotIn("misp_ref", json.dumps(result))

  def test_codes_and_counts_are_value_free(self):
    result, _ = _egx2_run(_with_refs(["M9", "M2"]))
    text = json.dumps(result["misp_ref_drops"])
    for sentinel in ("CVE-2000-0001", "quietsieve", "203.0.113.7", "901", "902", "M9", "M2"):
      self.assertNotIn(sentinel, text)
    self.assertLessEqual(set(result["misp_ref_drops"]), {"ref_unknown", "ref_entity_not_in_observation", "ref_over_cap"})
    self.assertNotIn("misp_ref", json.dumps(result["explanation_trace"]))


class SharedRefVectorTests(unittest.TestCase):
  """The same file drives the playground validator test (spec v0.4 §5.2)."""

  @classmethod
  def setUpClass(cls):
    cls.vector = json.loads(VECTOR_PATH.read_text())

  def test_every_case_outcome_matches(self):
    graph_ids = set(self.vector["graph_node_ids"])
    self.assertGreaterEqual(len(self.vector["cases"]), 30)
    for case in self.vector["cases"]:
      with self.subTest(case=case["name"]):
        self.assertIs(
          runtime.public_references_are_valid(case["observation_refs"], case["misp_reference_index"], graph_ids),
          case["valid"],
        )

  def test_invalid_public_references_are_dropped_with_the_text_kept(self):
    result, _ = _egx2_run(_with_refs(["M1"]))
    observations = result["case_explanation"]["observations"]
    index = result["case_explanation"]["misp_reference_index"]
    graph_ids = {"c1", "i1", "m1", "i2"}
    self.assertTrue(runtime.public_references_are_valid([["M1"]], index, graph_ids))
    with patch.object(runtime, "public_references_are_valid", return_value=False):
      broken, _ = _egx2_run(_with_refs(["M1"]))
    self.assertNotIn("misp_reference_index", broken["case_explanation"])
    self.assertNotIn("misp_refs", json.dumps(broken["case_explanation"]))
    self.assertEqual([o["text"] for o in broken["case_explanation"]["observations"]], [o["text"] for o in observations])

  def test_event_url_check(self):
    self.assertTrue(misp.event_url_is_valid(misp._event_url(TEMPLATE, "5"), "5"))
    for url, event_id in ((TEMPLATE.replace("{event_id}", "5"), "6"), ("https://a.test/5?x=1", "5"), (7, "7")):
      self.assertFalse(misp.event_url_is_valid(url, event_id))



BASE_TRUNCATION_NOTE = (
  "\n\nRETRY: your previous brief was cut off at the length limit. Write a shorter brief: "
  "at most 3 observations, one sentence each."
)
MISP_TRUNCATION_NOTE = (
  "\n\nRETRY: your previous brief was cut off at the length limit. Write a shorter brief: "
  "at most 3 observations, one sentence each, at most one misp_citations entry per observation, "
  "and keep the misp_refs rules above."
)


class TruncationRetryTests(unittest.TestCase):
  """Operator ruling 2026-10-06: a length cut gets its own retry note."""

  def _retry_user(self, first, *, block="default"):
    graph = egx2_tests.enrichment_graph()
    sheet = insights.build_insight_sheet(graph)
    payloads = []
    replies = [first, {"finish_reason": "stop", "completion_tokens": 9, "content": json.dumps(egx2_tests.enrichment_brief(sheet))}]

    def provider(payload):
      payloads.append(payload)
      return replies.pop(0)

    kwargs = {} if block is None else {
      "misp_enrichment": egx2_tests.enrichment_block(), "misp_node_ids": egx2_tests.ENRICHMENT_NODE_IDS,
    }
    egx2.run_insight_brief(question="q", graph=graph, model=None, provider_call=provider, **kwargs)
    self.assertEqual(len(payloads), 2)
    return [p["messages"][1]["content"] for p in payloads]

  def test_length_cut_without_a_block_gets_the_base_note(self):
    first, retry = self._retry_user({"finish_reason": "length", "completion_tokens": 768, "content": "{"}, block=None)
    self.assertEqual(retry, first + BASE_TRUNCATION_NOTE)

  def test_length_cut_with_a_block_gets_the_misp_note(self):
    first, retry = self._retry_user({"finish_reason": "length", "completion_tokens": 768, "content": "{"})
    self.assertEqual(retry, first + MISP_TRUNCATION_NOTE)

  def test_other_failures_keep_the_generic_note(self):
    for reply, code in (
      ({"finish_reason": "stop", "completion_tokens": 9, "content": "not json"}, "invalid_brief_json"),
      ({"finish_reason": "stop", "completion_tokens": 9, "content": ""}, "missing_content"),
    ):
      with self.subTest(code=code):
        first, retry = self._retry_user(reply)
        self.assertEqual(retry, first + runtime.RETRY_NOTE_TEMPLATE.format(failures=code))

  def test_notes_are_in_the_manifest_and_fit_the_observation_schema(self):
    self.assertEqual(runtime.PROFILE_MANIFEST["retry_note_truncated"], BASE_TRUNCATION_NOTE)
    self.assertEqual(runtime.PROFILE_MANIFEST["retry_note_truncated_misp"], MISP_TRUNCATION_NOTE)
    self.assertLessEqual(3, runtime.MAX_OBSERVATIONS)  # the parse accepts 1..MAX_OBSERVATIONS
