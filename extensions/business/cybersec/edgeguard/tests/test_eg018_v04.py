"""EG-018 phase 4d: explanation spec v0.4 -- numbered MISP event references and the
public `misp_reference_index`. Since EG-039 phase 4 code attaches them from the entities
an observation names; the model sees no MISP text and writes no `misp_refs`.

Synthetic fixtures only (CVE-2000-0001, 203.0.113.x, MISP ids in the 900s); no network.
"""

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
# v0.4 manifest (spec §2.5); CATALOG_SHA256 is not allowed to move.
V03_PROFILE_SHA256 = "962afb38da1fd79bcdd45e5a33cf94768234e8bbd313ca4f1bd69753cc287827"


def _node(ref, entity, events):
  return {"node_ref": ref, "label": "CVE", "misp_event_ids": list(events), "fields": {}, "entity": entity}


def _many_events_block(count=5):
  row = _row("CVE", "nvd", {"cwe": ["CWE-79"]}, event_ids=[str(900 + i) for i in range(1, count + 1)])
  return misp.build_misp_enrichment_block([row], {"e-1": "N0"})


class ReferenceBuilderTests(unittest.TestCase):
  def test_events_are_numbered_by_integer_order_over_all_nodes(self):
    table = runtime._misp_references({"nodes": [_node("N0", "A", ["10", "9"]), _node("N1", "B", ["100"])]}, TEMPLATE)
    self.assertEqual([(e["id"], e["event_id"]) for e in table], [("M1", "9"), ("M2", "10"), ("M3", "100")])
    self.assertEqual([e["node_refs"] for e in table], [["N0"], ["N0"], ["N1"]])

  def test_line_cap_is_eight_and_numbers_have_no_gaps(self):
    nodes = [_node(f"N{i}", f"E{i}", [str(100 + i)]) for i in range(10)]
    table = runtime._misp_references({"nodes": nodes}, TEMPLATE)
    self.assertEqual([e["id"] for e in table], [f"M{i}" for i in range(1, 9)])

  def test_no_event_ids_yield_no_lines(self):
    self.assertEqual(runtime._misp_references({"nodes": [_node("N0", "A", [])]}, TEMPLATE), [])
    self.assertEqual(runtime._misp_references(None, TEMPLATE), [])


class PromptTests(unittest.TestCase):
  def test_the_block_never_changes_the_request_bytes(self):
    with_block, with_payloads = _egx2_run()
    no_block, no_payloads = _egx2_run(block=None)
    self.assertEqual(with_payloads[0]["messages"], no_payloads[0]["messages"])
    for result in (with_block, no_block):
      self.assertEqual(result["explanation_trace"]["calls"][0]["request_sha256"], PRE_CHANGE_NO_BLOCK_SHA)
    self.assertNotIn("MISP", with_payloads[0]["messages"][1]["content"])

  def test_profile_pin_moves_and_catalog_pin_does_not(self):
    self.assertNotEqual(egx2.PROFILE_SHA256, V03_PROFILE_SHA256)
    self.assertEqual(egx2.PROFILE_SHA256, egx2_tests.PINNED_PROFILE_SHA256)
    self.assertEqual(field_catalog.CATALOG_SHA256, egx2_tests.PINNED_CATALOG_SHA256)
    manifest = runtime.PROFILE_MANIFEST
    self.assertEqual(
      (manifest["misp_references_max_lines"], manifest["misp_refs_max_per_observation"], manifest["misp_attachment"]),
      (8, 3, "code"),
    )
    self.assertNotIn("misp_references_max_bytes", manifest)


def _direct(entity_ids, nodes, node_ids, template=TEMPLATE):
  """`_attach_misp` on a hand-built view: (case, citations dropped, refs withheld)."""
  view = {"nodes": nodes}
  graph = {"nodes": [{"id": pid, "labels": ["CVE"], "properties": {"cve_id": pid}} for pid in set(node_ids.values())]}
  case = {"observations": [{"text": "t", "insight_ids": [], "entity_ids": list(entity_ids)}]}
  dropped, withheld = runtime._attach_misp(case, graph, view, node_ids, runtime._misp_references(view, template), template)
  return case, dropped, withheld


class AttachedRefTests(unittest.TestCase):
  def _refs(self, result):
    return [o.get("misp_refs") for o in result["case_explanation"]["observations"]]

  def test_refs_follow_the_named_entities_and_the_index_lists_every_reference(self):
    result, _ = _egx2_run()
    case = result["case_explanation"]
    self.assertEqual(self._refs(result), [["M1"], ["M2"]])
    self.assertEqual(case["misp_reference_index"], [
      {"id": "M1", "event_id": "901", "event_url": misp._event_url(TEMPLATE, "901"), "node_refs": ["N0"], "entity_ids": ["c1"]},
      {"id": "M2", "event_id": "902", "event_url": misp._event_url(TEMPLATE, "902"), "node_refs": ["N1"], "entity_ids": ["i1"]},
    ])
    self.assertNotIn("misp_ref_withheld", result)

  def test_no_ref_when_no_named_entity_is_enriched_and_none_without_a_block(self):
    def factory(sheet):
      brief = egx2_tests.enrichment_brief(sheet)
      for observation in brief["observations"]:
        observation["exemplar_entities"] = ["quietsieve"]
      return brief
    result, _ = _egx2_run(factory)
    self.assertEqual(self._refs(result), [None, None])
    self.assertNotIn("misp_reference_index", result["case_explanation"])
    plain, _ = _egx2_run(block=None)
    self.assertNotIn("misp_ref", json.dumps(plain["case_explanation"]))
    self.assertNotIn("misp_ref_withheld", plain)

  def test_over_cap_keeps_the_first_three_in_number_order(self):
    def factory(sheet):
      brief = egx2_tests.enrichment_brief(sheet)
      del brief["observations"][1:]
      return brief
    result, _ = _egx2_run(factory, block=_many_events_block(), node_ids={"N0": "c1"})
    self.assertEqual(self._refs(result)[0], ["M1", "M2", "M3"])
    self.assertEqual(len(result["case_explanation"]["misp_reference_index"]), 5)

  def test_deterministic_cases_carry_code_attached_refs(self):
    result = egx2.run_insight_brief(
      question="q", graph=egx2_tests.enrichment_graph(), model=None, provider_call=lambda _p: {},
      allow_model=False, misp_enrichment=egx2_tests.enrichment_block(), misp_node_ids=egx2_tests.ENRICHMENT_NODE_IDS,
    )
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")
    self.assertIn("misp_refs", json.dumps(result["case_explanation"]))
    self.assertIn("misp_reference_index", result["case_explanation"])

  def test_fifty_one_nodes_on_one_event_cap_node_refs_at_fifty(self):
    nodes = [_node(f"N{i}", f"E{i}", ["101"]) for i in range(51)]
    node_ids = {f"N{i}": f"n:{i}" for i in range(51)}
    case, _dropped, withheld = _direct(["n:0"], nodes, node_ids)
    entry = case["misp_reference_index"][0]
    self.assertEqual((len(entry["node_refs"]), len(entry["entity_ids"]), withheld), (50, 50, 0))
    self.assertEqual(case["observations"][0]["misp_refs"], ["M1"])

  def test_an_unresolved_node_ref_in_the_index_withholds_index_and_refs_and_counts_it(self):
    nodes = [_node("N0", "Alpha", ["101"]), _node("N1", "Beta", ["101"])]
    case, _dropped, withheld = _direct(["n:a"], nodes, {"N0": "n:a"})  # N1 has no packet id
    self.assertNotIn("misp_reference_index", case)
    self.assertNotIn("misp_refs", case["observations"][0])
    self.assertEqual(withheld, 1)

  def test_event_url_must_equal_the_template_expansion(self):
    nodes = [_node("N0", "Alpha", ["101"])]
    table = runtime._misp_references({"nodes": nodes}, TEMPLATE)
    table[0]["event_url"] = misp._event_url("https://other.example.test/events/view/{event_id}", "101")
    with patch.object(runtime, "_misp_references", return_value=table):
      case, _dropped, withheld = _direct(["n:a"], nodes, {"N0": "n:a"})
    self.assertNotIn("misp_reference_index", case)
    self.assertEqual(withheld, 1)


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
    result, _ = _egx2_run()
    observations = result["case_explanation"]["observations"]
    index = result["case_explanation"]["misp_reference_index"]
    graph_ids = {"c1", "i1", "m1", "i2"}
    self.assertTrue(runtime.public_references_are_valid([["M1"]], index, graph_ids))
    with patch.object(runtime, "public_references_are_valid", return_value=False):
      broken, _ = _egx2_run()
    self.assertNotIn("misp_reference_index", broken["case_explanation"])
    self.assertNotIn("misp_refs", json.dumps(broken["case_explanation"]))
    self.assertEqual([o["text"] for o in broken["case_explanation"]["observations"]], [o["text"] for o in observations])

  def test_event_url_check(self):
    self.assertTrue(misp.event_url_is_valid(misp._event_url(TEMPLATE, "5"), "5"))
    for url, event_id in ((TEMPLATE.replace("{event_id}", "5"), "6"), ("https://a.test/5?x=1", "5"), (7, "7")):
      self.assertFalse(misp.event_url_is_valid(url, event_id))


def _truncation_note(limit):
  """Operator ruling 2026-10-06 (revised): the retry text after a length cut."""
  return (
    "\n\nRETRY: your previous brief was cut off at the length limit. Write a shorter brief: "
    f"at most {limit} observations, one sentence each."
  )


class TruncationRetryTests(unittest.TestCase):
  CUT = {"finish_reason": "length", "completion_tokens": 640, "content": "{"}

  def _retry_users(self, first, *, block="default", mode=None):
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
    egx2.run_insight_brief(question="q", graph=graph, model=None, provider_call=provider, mode=mode, **kwargs)
    self.assertEqual(len(payloads), 2)
    return [p["messages"][1]["content"] for p in payloads]

  def test_the_retry_note_is_the_same_with_and_without_a_block(self):
    for block in (None, "default"):
      with self.subTest(block=block):
        first, retry = self._retry_users(self.CUT, block=block)
        self.assertEqual(retry, first + _truncation_note(2))

  def test_limit_follows_the_request_budget_and_the_first_prompt(self):
    for mode, limit in ((None, 2), ("thorough", 3)):
      with self.subTest(mode=mode):
        first, retry = self._retry_users(self.CUT, mode=mode)
        self.assertIn(f"at most {limit} observations", first)
        self.assertEqual(retry, first + _truncation_note(limit))

  def test_other_failures_keep_the_generic_note(self):
    for reply, code in (
      ({"finish_reason": "stop", "completion_tokens": 9, "content": "not json"}, "invalid_brief_json"),
      ({"finish_reason": "stop", "completion_tokens": 9, "content": ""}, "missing_content"),
    ):
      with self.subTest(code=code):
        first, retry = self._retry_users(reply)
        self.assertEqual(retry, first + runtime.RETRY_NOTE_TEMPLATE.format(failures=code))

  def test_note_pieces_are_in_the_manifest(self):
    manifest = runtime.PROFILE_MANIFEST
    self.assertEqual("\n\n" + manifest["retry_note_truncated"].lstrip("\n").format(max_observations=4) + ".", _truncation_note(4))
    self.assertNotIn("retry_note_truncated_citations", manifest)
    self.assertNotIn("retry_note_truncated_refs", manifest)
