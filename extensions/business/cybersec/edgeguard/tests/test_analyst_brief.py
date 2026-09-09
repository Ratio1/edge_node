import json
import unittest

from extensions.business.cybersec.edgeguard.analyst_brief import (
  MAX_TOKENS,
  run_analyst_brief,
)
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError


def digest():
  return {
    "schema_version": "edgeguard.result_digest.v1",
    "summary": {"text": "Two branches were returned."},
    "counts": {"returned_rows": 2},
    "coverage": {"complete": True},
    "groups": [{"id": "R0", "relationship_types": ["INDICATES"]}, {"id": "R1", "relationship_types": ["ATTRIBUTED_TO"]}],
    "exact_inventory": {"columns": [], "nodes": [], "relationships": [], "paths": []},
  }


class AnalystBriefTests(unittest.TestCase):
  def test_one_call_owns_every_group_and_reports_actual_cap(self):
    calls = []

    def provider(payload):
      calls.append(payload)
      return {
        "content": json.dumps({"text": "The INDICATES branch connects indicators to malware; the ATTRIBUTED TO branch connects that malware to actors."}),
        "finish_reason": "stop",
        "completion_tokens": 17,
      }

    result = run_analyst_brief(
      question="What does the graph show?",
      digest=digest(),
      model="base_qwen3_4b",
      provider_call=provider,
    )

    self.assertEqual(len(calls), 1)
    self.assertEqual(calls[0]["metadata"]["task"], "edgeguard_result_digest_analyst_brief")
    self.assertEqual(calls[0]["max_tokens"], MAX_TOKENS)
    self.assertEqual(calls[0]["temperature"], 0.1)
    self.assertEqual(calls[0]["top_p"], 1.0)
    self.assertEqual(calls[0]["model"], "base_qwen3_4b")
    self.assertEqual(
      json.loads(calls[0]["messages"][1]["content"])["result_view"]["schema_version"],
      "edgeguard.result_digest_model_view.v1",
    )
    self.assertEqual(result["analyst_brief"]["group_ids"], ["R0", "R1"])
    self.assertEqual(result["analyst_brief"]["completion_tokens"], 17)
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)

  def test_backend_owns_groups_and_rejects_model_supplied_group_list(self):
    calls = 0

    def provider(_payload):
      nonlocal calls
      calls += 1
      return {
        "content": json.dumps({"text": "Only one branch.", "group_ids": ["R0"]}),
        "finish_reason": "stop",
        "completion_tokens": 8,
      }

    with self.assertRaises(GraphFirstRuntimeError) as raised:
      run_analyst_brief(question="Explain.", digest=digest(), model="base_qwen3_4b", provider_call=provider)
    self.assertEqual(calls, 1)
    self.assertEqual(raised.exception.code, "invalid_brief_shape")
    self.assertNotIn("Only one branch", json.dumps(raised.exception.trace))

  def test_malformed_json_and_completion_metadata_fail_closed(self):
    cases = [
      ({"content": "not json", "finish_reason": "stop", "completion_tokens": 2}, "invalid_brief_json"),
      ({"content": "{}", "finish_reason": "length", "completion_tokens": MAX_TOKENS}, "output_truncated"),
      ({"content": "{}", "finish_reason": "stop", "completion_tokens": None}, "completion_metadata_missing"),
    ]
    for response, code in cases:
      with self.subTest(code=code), self.assertRaises(GraphFirstRuntimeError) as raised:
        run_analyst_brief(
          question="Explain.", digest=digest(), model="base_qwen3_4b", provider_call=lambda _payload: response,
        )
      self.assertEqual(raised.exception.code, code)
      self.assertEqual(raised.exception.trace["outcome"]["completed_calls"], 1)
      self.assertEqual(raised.exception.trace["calls"][0]["status"], "completed")

  def test_generic_prose_without_material_branches_fails_grounding(self):
    with self.assertRaises(GraphFirstRuntimeError) as raised:
      run_analyst_brief(
        question="Explain.",
        digest=digest(),
        model="base_qwen3_4b",
        provider_call=lambda _payload: {
          "content": json.dumps({"text": "The result contains both material branches."}),
          "finish_reason": "stop",
          "completion_tokens": 8,
        },
      )
    self.assertEqual(raised.exception.code, "brief_grounding_failed")
    self.assertEqual(raised.exception.trace["outcome"]["completed_calls"], 1)

  def test_model_view_keeps_all_topology_but_omits_operational_properties(self):
    source = digest()
    source["exact_inventory"] = {
      "columns": ["p"],
      "nodes": [{
        "ref": "N0",
        "labels": ["Indicator"],
        "properties": [["value", "example.invalid"], ["uuid", "operational-id"]],
      }],
      "relationships": [{
        "ref": "E0",
        "type": "INDICATES",
        "start_ref": "N0",
        "end_ref": "N1",
        "properties": [["source_id", "operational-edge-id"]],
      }],
      "paths": [{"ref": "P0", "start_ref": "N0", "end_ref": "N1", "steps": [["N0", "E0", "N1"]]}],
    }
    calls = []
    run_analyst_brief(
      question="Explain.",
      digest=source,
      model="base_qwen3_4b",
      provider_call=lambda payload: calls.append(payload) or {
        "content": json.dumps({"text": "The INDICATES branch and ATTRIBUTED TO branch are represented by the returned paths."}),
        "finish_reason": "stop",
        "completion_tokens": 13,
      },
    )
    view = json.loads(calls[0]["messages"][1]["content"])["result_view"]
    self.assertEqual(view["groups"][0][0], "R0")
    self.assertEqual(view["inventory"]["paths"][0], ["P0", "N0", "N1", [["N0", "E0", "N1"]]])
    self.assertEqual(view["inventory"]["nodes"][0][2], [["value", "example.invalid"]])
    self.assertEqual(view["property_view"], {
      "included_slots": 1,
      "omitted_operational_slots": 2,
      "truncated_slots": 0,
    })
    self.assertEqual(view["encoding"]["node_columns"], ["ref", "labels", "properties"])
    self.assertEqual(view["coverage"], {"complete": True})
    self.assertNotIn("operational-id", json.dumps(view))

  def test_model_view_bounds_long_descriptions_and_lists(self):
    source = digest()
    source["exact_inventory"] = {
      "columns": [],
      "nodes": [{
        "ref": "N0",
        "labels": ["ThreatActor"],
        "properties": [
          ["description", {"type": "string", "value": "x" * 200}],
          ["aliases", {"type": "list", "items": list(range(20))}],
        ],
      }],
      "relationships": [],
      "paths": [],
    }
    calls = []
    run_analyst_brief(
      question="Explain.", digest=source, model="base_qwen3_4b",
      provider_call=lambda payload: calls.append(payload) or {
        "content": json.dumps({"text": "The INDICATES branch and ATTRIBUTED TO branch are represented by the returned evidence."}),
        "finish_reason": "stop",
        "completion_tokens": 12,
      },
    )
    view = json.loads(calls[0]["messages"][1]["content"])["result_view"]
    properties = view["inventory"]["nodes"][0][2]
    self.assertEqual(len(properties[0][1]["value"]), 96)
    self.assertTrue(properties[0][1]["truncated"])
    self.assertEqual(len(properties[1][1]["items"]), 12)
    self.assertEqual(properties[1][1]["omitted_items"], 8)
    self.assertEqual(view["property_view"]["truncated_slots"], 2)

  def test_large_view_uses_topology_summary_without_losing_group_ownership(self):
    source = digest()
    source["groups"] = []
    nodes = []
    relationships = []
    paths = []
    for index in range(40):
      source["groups"].append({
        "id": f"R{index}",
        "row_ordinals": [index],
        "occurrences": 1,
        "node_refs": [f"N{index}", "N40"],
        "relationship_refs": [f"E{index}"],
        "path_refs": [f"P{index}"],
        "relationship_types": ["AFFECTS"],
        "path_shapes": [{
          "path_ref": f"P{index}", "start_ref": f"N{index}", "end_ref": "N40",
          "relationship_types": ["AFFECTS"],
        }],
        "values": [],
      })
      nodes.append({
        "ref": f"N{index}", "labels": ["CVE"],
        "properties": [["cve_id", {"type": "string", "value": f"CVE-2026-{index:04d}"}]],
      })
      relationships.append({
        "ref": f"E{index}", "type": "AFFECTS", "start_ref": f"N{index}", "end_ref": "N40",
        "properties": [],
      })
      paths.append({
        "ref": f"P{index}", "start_ref": f"N{index}", "end_ref": "N40",
        "steps": [[f"N{index}", f"E{index}", "N40"]],
      })
    nodes.append({"ref": "N40", "labels": ["Sector"], "properties": [["name", {"type": "string", "value": "healthcare"}]]})
    source["exact_inventory"] = {
      "columns": ["p"], "nodes": nodes, "relationships": relationships, "paths": paths,
    }
    calls = []
    result = run_analyst_brief(
      question="Summarize the affected sector.", digest=source, model="base_qwen3_4b",
      provider_call=lambda payload: calls.append(payload) or {
        "content": json.dumps({"text": "Forty returned CVE paths AFFECTS the healthcare sector."}),
        "finish_reason": "stop",
        "completion_tokens": 14,
      },
    )
    view = json.loads(calls[0]["messages"][1]["content"])["result_view"]
    self.assertEqual(view["view_mode"], "topology_summary")
    self.assertEqual([group[0] for group in view["groups"]], [f"R{index}" for index in range(40)])
    self.assertIn(["Sector", 1], view["inventory"]["node_label_counts"])
    self.assertEqual(result["analyst_brief"]["group_ids"], [f"R{index}" for index in range(40)])


if __name__ == "__main__":
  unittest.main()
