"""EGM-059 phase 3, slice 3a: the `misp_enrichment` block (contract §7).

Fixtures only -- no network, no prod literals. Synthetic identifiers
(`CVE-2000-0001`, `203.0.113.x`, MISP event ids in the 900s) throughout, per
the phase-3 probe report's reproduce-safe convention. Never asserts the
block is fed to a model -- contract §7.4 forbids that until explanation
spec v0.2 is approved (a later slice).

The block validator and its policy regex live in `misp_enrichment.py`, not
`edgeguard_api`. `node_ref` is the digest node ref, not the packet id --
`_misp_enrichment_for_response` takes a `node_source_aliases` map. The
packet-level `contains_raw_misp_payload` flag is the v0.1 hard-coded
`False`; `edgeguard_api` trusts it rather than recomputing it from
`packet["graph"]`.
"""

import hashlib
import json
import time
import unittest
from unittest.mock import MagicMock, patch

# `test_api` fakes the `naeural_core` plugin base before `edgeguard_api` is
# ever imported -- import it first, exactly like every other test module in
# this suite.
from extensions.business.cybersec.edgeguard.tests.test_api import (  # noqa: E402
  _DriverRecord,
  _GraphNode,
  _Result,
  _make_api,
  _run_text,
)

from extensions.business.cybersec.edgeguard import misp_enrichment  # noqa: E402
from extensions.business.cybersec.edgeguard import edgeguard_api as api_module  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import (  # noqa: E402
  RESPONSE_MAX_BYTES,
  EdgeguardApiPlugin,
  _collect_misp_candidate_nodes,
  _validate_graph_evidence_packet,
  _build_graph_evidence_packet,
)
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError  # noqa: E402


def _cve_row(element_id="cve-1", *, event_ids=("901",), attribute_ids=("attr-1",), raw_data=None):
  return {
    "element_id": element_id,
    "labels": ["CVE"],
    "misp_event_ids": list(event_ids),
    "misp_attribute_ids": list(attribute_ids),
    "source": "nvd",
    "last_imported_from": "2026-09-01T00:00:00Z",
    "sourced": [
      {"source_id": "nvd", "raw_data": json.dumps(raw_data if raw_data is not None else {
        "cwe": ["CWE-79"],
        "reference_urls": ["https://example.test/ref"],
        "affected_products": [],
        "cvss_v31_data": {"baseScore": 7.5},
      })},
    ],
  }


def _alias_map_for(records, *, prefix="N"):
  """Test-only helper: assigns arbitrary digest-shaped refs (`N0`, `N1`, ...)
  to every MISP candidate node found in `records`, in encounter order --
  standing in for the real digest's alias assignment (`node_alias_map`) so
  isolated `_misp_enrichment_for_response` tests can exercise the
  packet-id-to-digest-ref join without building a full evidence/digest
  fixture."""
  candidates = _collect_misp_candidate_nodes(records)
  return {info["packet_id"]: f"{prefix}{index}" for index, info in enumerate(candidates.values())}


def _nodes_sha256(nodes):
  canonical = json.dumps(nodes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_BLOCK_LEAK_MARKERS = ("misp_enrichment", "misp.edgeguard.org/events/view", "Synthetic Pulse")


def _assert_no_block_leak(test, mock_call):
  """Every argument of every recorded model call, at any depth, is free of
  the block: its key name, its event URLs and its field values."""
  for call in mock_call.call_args_list:
    rendered = repr(call)
    for marker in _BLOCK_LEAK_MARKERS:
      test.assertNotIn(marker, rendered)


def _valid_block(node_count=1, *, padded=False):
  """A real, validator-valid `misp_enrichment` block, built through the
  actual builder (real sha256, six-key nodes) instead of a hand-written
  dict -- for tests that only need *a* valid block, not any particular
  content. `padded=True` pads a whitelisted CVE field (`cwe`,
  `reference_urls`, `affected_products`) on every node until the whole
  block is well past `RESPONSE_MAX_BYTES` -- sized by field content, never
  by an extra/unknown key."""
  raw_data = None
  if padded:
    padded_text = ["x" * 490 + str(i) for i in range(misp_enrichment.MAX_ARRAY_ITEMS)]
    padded_urls = [
      "https://example.test/" + ("y" * 460) + str(i) for i in range(misp_enrichment.MAX_ARRAY_ITEMS)
    ]
    raw_data = {"cwe": padded_text, "reference_urls": padded_urls, "affected_products": padded_text}
  rows = [
    _cve_row(element_id=f"cve-{i}", event_ids=(str(950 + i),), raw_data=raw_data)
    for i in range(node_count)
  ]
  node_ref_by_element_id = {f"cve-{i}": f"N{i}" for i in range(node_count)}
  block = misp_enrichment.build_misp_enrichment_block(rows, node_ref_by_element_id)
  assert misp_enrichment.validate_misp_enrichment_block(block)
  return block


class BuildBlockTests(unittest.TestCase):
  def test_indicator_block_has_exactly_six_keys_and_whitelisted_fields_only(self):
    row = {
      "element_id": "indicator-1",
      "labels": ["Indicator"],
      "misp_event_ids": ["901", "902"],
      "misp_attribute_ids": ["attr-9"],
      "source": "alienvault_otx",
      "last_imported_from": "2026-09-20T00:00:00Z",
      "sourced": [{
        "source_id": "alienvault_otx",
        "raw_data": json.dumps({
          "pulse_name": "Synthetic Pulse",
          "pulse_references": ["https://otx.test/pulse/1"],
          "pulse_tlp": "",
          "otx_industries": ["finance"],
          "indicator_role": "",
        }),
      }],
    }
    block = misp_enrichment.build_misp_enrichment_block(
      [row], {"indicator-1": "N0"},
      now=__import__("datetime").datetime(2026, 9, 27, 21, 30, 0, tzinfo=__import__("datetime").timezone.utc),
    )
    self.assertIsNotNone(block)
    self.assertEqual(block["schema_version"], "edgeguard.misp_enrichment.v1")
    self.assertEqual(block["source"], "neo4j_raw_data")
    self.assertTrue(block["fetched_at"].endswith("Z"))
    self.assertEqual(len(block["nodes"]), 1)
    node = block["nodes"][0]
    # Contract §7.3: exactly these six keys, always present.
    self.assertEqual(set(node), {
      "node_ref", "label", "misp_event_ids", "misp_attribute_ids", "misp_event_urls", "fields",
    })
    self.assertEqual(node["node_ref"], "N0")
    self.assertEqual(node["label"], "Indicator")
    self.assertEqual(node["misp_event_ids"], ["901", "902"])
    self.assertEqual(
      node["misp_event_urls"],
      [
        "https://misp.edgeguard.org/events/view/901",
        "https://misp.edgeguard.org/events/view/902",
      ],
    )
    # `source`/`last_imported_from` moved into `fields`.
    self.assertEqual(
      set(node["fields"]),
      {"pulse_name", "pulse_references", "otx_industries", "source", "last_imported_from"},
    )
    self.assertEqual(node["fields"]["pulse_name"], "Synthetic Pulse")
    self.assertEqual(node["fields"]["source"], "alienvault_otx")
    self.assertEqual(node["fields"]["last_imported_from"], "2026-09-20T00:00:00Z")
    # Probe finding 2: `pulse_tlp` and `indicator_role` are non-empty on
    # essentially no sampled edge -- empty values are always omitted.
    self.assertNotIn("pulse_tlp", node["fields"])
    self.assertNotIn("indicator_role", node["fields"])
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(block))

  def test_envelope_only_node_still_carries_all_six_keys(self):
    # Ruling R2: a node with no MISP ids but a `SOURCED_FROM` edge from a
    # source that whitelists no `fields` (`abuseipdb`) still qualifies (it
    # has a `SOURCED_FROM` edge) and still emits the full six-key shape,
    # with empty id/`fields` collections where there is nothing to report.
    row = {
      "element_id": "ind-envelope", "labels": ["Indicator"],
      "misp_event_ids": [], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None,
      "sourced": [{"source_id": "abuseipdb", "raw_data": json.dumps({"confidence": 90})}],
    }
    block = misp_enrichment.build_misp_enrichment_block(
      [row], {"ind-envelope": "N0"},
    )
    self.assertIsNotNone(block)
    node = block["nodes"][0]
    self.assertEqual(set(node), {
      "node_ref", "label", "misp_event_ids", "misp_attribute_ids", "misp_event_urls", "fields",
    })
    self.assertEqual(node["misp_event_ids"], [])
    self.assertEqual(node["misp_attribute_ids"], [])
    self.assertEqual(node["misp_event_urls"], [])
    self.assertEqual(node["fields"], {})
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(block))

  def test_no_raw_json_strings_and_nested_source_object_never_emitted(self):
    block = misp_enrichment.build_misp_enrichment_block(
      [_cve_row()], {"cve-1": "N0"},
    )
    fields = block["nodes"][0]["fields"]
    self.assertEqual(set(fields), {"cwe", "reference_urls", "source", "last_imported_from"})
    for value in fields.values():
      self.assertNotIsInstance(value, dict)
      if isinstance(value, list):
        for item in value:
          self.assertNotIsInstance(item, dict)
    self.assertNotIn("cvss_v31_data", fields)
    self.assertNotIn("affected_products", fields)  # empty list omitted

  def test_tf_tags_normalized_to_list_regardless_of_source_shape(self):
    threatfox_row = {
      "element_id": "ind-tf", "labels": ["Indicator"],
      "misp_event_ids": ["910"], "misp_attribute_ids": [],
      "source": "threatfox", "last_imported_from": None,
      "sourced": [{"source_id": "threatfox", "raw_data": json.dumps({
        "threat_type": "botnet_cc", "threat_type_desc": "Botnet C2",
        "tf_tags": ["mirai", "iot"], "reference": "https://threatfox.test/1",
        "malware_alias": "",
      })}],
    }
    urlhaus_row = {
      "element_id": "ind-uh", "labels": ["Indicator"],
      "misp_event_ids": ["911"], "misp_attribute_ids": [],
      "source": "urlhaus", "last_imported_from": None,
      "sourced": [{"source_id": "urlhaus", "raw_data": json.dumps({
        "threat_type": "malware_download", "tf_tags": "phishing",
        "reference": "", "malware_alias": "",
      })}],
    }
    block = misp_enrichment.build_misp_enrichment_block(
      [threatfox_row, urlhaus_row],
      {"ind-tf": "N0", "ind-uh": "N1"},
    )
    nodes_by_ref = {node["node_ref"]: node for node in block["nodes"]}
    self.assertEqual(nodes_by_ref["N0"]["fields"]["tf_tags"], ["mirai", "iot"])
    self.assertEqual(nodes_by_ref["N1"]["fields"]["tf_tags"], ["phishing"])

  def test_campaign_omitted_and_no_signal_node_omitted(self):
    campaign_row = {
      "element_id": "camp-1", "labels": ["Campaign"],
      "misp_event_ids": [], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None, "sourced": [],
    }
    no_signal_row = {
      "element_id": "entity-1", "labels": ["Malware"],
      "misp_event_ids": [], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None, "sourced": [],
    }
    block = misp_enrichment.build_misp_enrichment_block(
      [campaign_row, no_signal_row], {},
    )
    self.assertIsNone(block)  # block absent: nothing qualified

  def test_block_absent_when_no_rows(self):
    self.assertIsNone(misp_enrichment.build_misp_enrichment_block([], {}))

  def test_truncation_flags_are_consistent(self):
    rows = [_cve_row(element_id=f"cve-{i}", event_ids=(str(900 + i),)) for i in range(3)]
    block = misp_enrichment.build_misp_enrichment_block(
      rows, {f"cve-{i}": f"N{i}" for i in range(3)},
      truncated=True, omitted_nodes=7,
    )
    self.assertTrue(block["truncated"])
    self.assertEqual(block["omitted_nodes"], 7)
    not_truncated = misp_enrichment.build_misp_enrichment_block(
      rows, {f"cve-{i}": f"N{i}" for i in range(3)},
      truncated=False, omitted_nodes=5,
    )
    self.assertFalse(not_truncated["truncated"])
    self.assertEqual(not_truncated["omitted_nodes"], 0)

  def test_oversize_node_is_skipped_not_fatal(self):
    # One node's `fields` alone push it well past the other
    # node's size; the block still builds, with the big node folded into
    # `omitted_nodes`/`truncated` instead of failing the whole block. The
    # cap is patched between the two nodes' real encoded sizes so the test
    # does not depend on exact JSON-overhead byte counting.
    big_row = _cve_row(
      element_id="cve-big", event_ids=("920",),
      raw_data={
        "cwe": ["CWE-79"],
        "reference_urls": ["https://example.test/" + ("x" * 470) + str(i) for i in range(20)],
      },
    )
    small_row = _cve_row(element_id="cve-small", event_ids=("921",))

    def _node_size(row, node_ref):
      with patch.object(misp_enrichment, "MAX_NODE_BYTES", 10**7):
        one_node_block = misp_enrichment.build_misp_enrichment_block([row], {row["element_id"]: node_ref})
      return len(json.dumps(
        one_node_block["nodes"][0], ensure_ascii=False, separators=(",", ":"),
      ).encode("utf-8"))

    small_size = _node_size(small_row, "N1")
    big_size = _node_size(big_row, "N0")
    self.assertGreater(big_size, small_size)
    threshold = (small_size + big_size) // 2

    with patch.object(misp_enrichment, "MAX_NODE_BYTES", threshold):
      block = misp_enrichment.build_misp_enrichment_block(
        [big_row, small_row], {"cve-big": "N0", "cve-small": "N1"},
      )
    self.assertIsNotNone(block)
    self.assertEqual(len(block["nodes"]), 1)
    self.assertEqual(block["nodes"][0]["node_ref"], "N1")
    self.assertTrue(block["truncated"])
    self.assertEqual(block["omitted_nodes"], 1)

  def test_url_fields_keep_only_http_values(self):
    # `reference_urls`, `pulse_references`, `reference` keep only
    # `http(s)://` values; a non-http reference is dropped.
    row = {
      "element_id": "ind-url", "labels": ["Indicator"],
      "misp_event_ids": ["930"], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None,
      "sourced": [{"source_id": "threatfox", "raw_data": json.dumps({
        "threat_type": "botnet_cc", "threat_type_desc": "",
        "tf_tags": [], "reference": "javascript:alert(1)", "malware_alias": "",
      })}],
    }
    block = misp_enrichment.build_misp_enrichment_block([row], {"ind-url": "N0"})
    self.assertIsNotNone(block)
    self.assertNotIn("reference", block["nodes"][0]["fields"])
    self.assertNotIn("tf_tags", block["nodes"][0]["fields"])  # empty list omitted

    valid_row = {
      "element_id": "ind-url-2", "labels": ["Indicator"],
      "misp_event_ids": ["931"], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None,
      "sourced": [{"source_id": "threatfox", "raw_data": json.dumps({
        "threat_type": "", "threat_type_desc": "",
        "tf_tags": [], "reference": "https://threatfox.test/1", "malware_alias": "",
      })}],
    }
    block2 = misp_enrichment.build_misp_enrichment_block([valid_row], {"ind-url-2": "N0"})
    self.assertEqual(block2["nodes"][0]["fields"]["reference"], "https://threatfox.test/1")

  def test_raw_data_over_the_char_cap_is_skipped_before_json_loads(self):
    # `raw_data` longer than 65,536 characters is never parsed.
    oversized_raw = json.dumps({"cwe": ["CWE-79"]}) + " " * misp_enrichment.MAX_RAW_DATA_CHARS
    row = {
      "element_id": "cve-oversized-raw", "labels": ["CVE"],
      "misp_event_ids": ["940"], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None,
      "sourced": [{"source_id": "nvd", "raw_data": oversized_raw}],
    }
    block = misp_enrichment.build_misp_enrichment_block([row], {"cve-oversized-raw": "N0"})
    self.assertIsNotNone(block)  # the node still qualifies via misp_event_ids
    self.assertEqual(block["nodes"][0]["fields"], {})

  def test_malformed_raw_data_json_is_skipped_not_fatal(self):
    row = _cve_row()
    row["sourced"][0]["raw_data"] = "{not valid json"
    block = misp_enrichment.build_misp_enrichment_block([row], {"cve-1": "N0"})
    self.assertIsNotNone(block)  # the node still qualifies via misp_event_ids
    self.assertEqual(
      block["nodes"][0]["fields"], {"source": "nvd", "last_imported_from": "2026-09-01T00:00:00Z"},
    )

  def test_non_mapping_raw_data_is_skipped_not_fatal(self):
    row = _cve_row()
    row["sourced"][0]["raw_data"] = json.dumps(["not", "a", "mapping"])
    block = misp_enrichment.build_misp_enrichment_block([row], {"cve-1": "N0"})
    self.assertIsNotNone(block)
    self.assertEqual(set(block["nodes"][0]["fields"]), {"source", "last_imported_from"})

  def test_element_id_absent_from_node_ref_map_is_skipped_not_a_fallback_ref(self):
    block = misp_enrichment.build_misp_enrichment_block([_cve_row()], {"some-other-id": "N0"})
    self.assertIsNone(block)  # the only row has no digest ref -- nothing qualifies

  def test_attribute_ids_only_node_is_envelope_only_not_dropped(self):
    # Ruling R2: MISP ids alone (no event ids, no `SOURCED_FROM`) still
    # qualify for an envelope-only node.
    row = {
      "element_id": "ind-attr-only", "labels": ["Indicator"],
      "misp_event_ids": [], "misp_attribute_ids": ["attr-1"],
      "source": None, "last_imported_from": None, "sourced": [],
    }
    block = misp_enrichment.build_misp_enrichment_block([row], {"ind-attr-only": "N0"})
    self.assertIsNotNone(block)
    node = block["nodes"][0]
    self.assertEqual(node["misp_attribute_ids"], ["attr-1"])
    self.assertEqual(node["misp_event_ids"], [])
    self.assertEqual(node["fields"], {})
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(block))

  def test_raw_json_string_scalar_value_is_dropped_not_the_whole_node(self):
    row = _cve_row(raw_data={
      "cwe": '{"nested": "smuggled"}', "reference_urls": ["https://example.test/ref"],
      "affected_products": [],
    })
    block = misp_enrichment.build_misp_enrichment_block([row], {"cve-1": "N0"})
    self.assertIsNotNone(block)
    fields = block["nodes"][0]["fields"]
    self.assertNotIn("cwe", fields)  # dropped: value parses as a JSON object
    self.assertEqual(fields["reference_urls"], ["https://example.test/ref"])
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(block))

  def test_raw_json_string_array_item_is_dropped_not_the_whole_field(self):
    row = _cve_row(raw_data={
      "cwe": ["CWE-79", '{"nested": "smuggled"}'], "reference_urls": [], "affected_products": [],
    })
    block = misp_enrichment.build_misp_enrichment_block([row], {"cve-1": "N0"})
    self.assertIsNotNone(block)
    self.assertEqual(block["nodes"][0]["fields"]["cwe"], ["CWE-79"])
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(block))


class FetchRowsTests(unittest.TestCase):
  def test_fetch_runs_one_query_for_the_whole_batch(self):
    session = MagicMock()
    session.run.return_value = [{"element_id": "a"}, {"element_id": "b"}]
    rows = misp_enrichment.fetch_misp_enrichment_rows(session, ["a", "b"])
    self.assertEqual(session.run.call_count, 1)
    self.assertEqual(session.run.call_args.kwargs["element_ids"], ["a", "b"])
    self.assertEqual(rows, [{"element_id": "a"}, {"element_id": "b"}])

  def test_fetch_skips_the_query_entirely_for_no_ids(self):
    session = MagicMock()
    self.assertEqual(misp_enrichment.fetch_misp_enrichment_rows(session, []), [])
    session.run.assert_not_called()

  def test_fetch_wraps_the_query_with_the_given_timeout(self):
    # `Query(..., timeout=...)` when the neo4j driver is present.
    captured = {}

    class _FakeQuery:
      def __init__(self, text, timeout):
        captured["text"] = text
        captured["timeout"] = timeout

    session = MagicMock()
    session.run.return_value = []
    with patch.object(misp_enrichment, "Query", _FakeQuery):
      misp_enrichment.fetch_misp_enrichment_rows(session, ["a"], timeout_seconds=7)
    self.assertEqual(captured["timeout"], 7)
    self.assertIn("elementId", captured["text"])
    query_arg = session.run.call_args.args[0]
    self.assertIsInstance(query_arg, _FakeQuery)

  def test_query_caps_sourced_from_edges_per_node(self):
    # At most 10 `SOURCED_FROM` edges per node, ordered.
    self.assertIn("LIMIT 10", misp_enrichment.MISP_ENRICHMENT_QUERY)
    self.assertIn("ORDER BY s.source_id", misp_enrichment.MISP_ENRICHMENT_QUERY)


class FieldWhitelistTests(unittest.TestCase):
  def test_allowed_fields_union_over_sources_plus_envelope_keys(self):
    allowed = misp_enrichment.allowed_fields_for_label("Indicator")
    self.assertIn("pulse_name", allowed)  # alienvault_otx
    self.assertIn("tf_tags", allowed)  # threatfox/urlhaus
    self.assertIn("source", allowed)
    self.assertIn("last_imported_from", allowed)

  def test_unknown_label_gets_envelope_keys_only(self):
    allowed = misp_enrichment.allowed_fields_for_label("Malware")
    self.assertEqual(allowed, misp_enrichment.ENVELOPE_FIELD_KEYS)


class BlockValidatorTests(unittest.TestCase):
  def _valid_block(self):
    return misp_enrichment.build_misp_enrichment_block(
      [_cve_row()], {"cve-1": "N0"},
      now=__import__("datetime").datetime(2026, 9, 27, tzinfo=__import__("datetime").timezone.utc),
    )

  def test_valid_block_passes(self):
    self.assertTrue(misp_enrichment.validate_misp_enrichment_block(self._valid_block()))

  def test_nested_object_in_fields_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["fields"]["cwe"] = {"nested": "object"}
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_list_inside_list_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["fields"]["cwe"] = [["nested"]]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_raw_json_string_smuggled_as_scalar_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["fields"]["cwe"] = '{"nested": "object"}'
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_forbidden_key_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["fields"]["raw_payload"] = "smuggled"
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_non_whitelisted_key_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["fields"]["not_a_real_field"] = "value"
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_missing_key_fails_closed(self):
    block = self._valid_block()
    del block["nodes"][0]["misp_attribute_ids"]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_event_id_not_matching_pattern_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["misp_event_ids"] = ["not-numeric"]
    block["nodes"][0]["misp_event_urls"] = ["https://misp.edgeguard.org/events/view/not-numeric"]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_attribute_id_over_char_cap_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["misp_attribute_ids"] = ["x" * 65]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_id_list_over_cap_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["misp_attribute_ids"] = [f"attr-{i}" for i in range(101)]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_event_url_parity_mismatch_fails_closed(self):
    block = self._valid_block()
    block["nodes"][0]["misp_event_urls"] = ["https://misp.edgeguard.org/events/view/999"]
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_sha256_mismatch_fails_closed(self):
    block = self._valid_block()
    block["sha256"] = "0" * 64
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_oversized_node_fails_closed_as_backstop(self):
    block = self._valid_block()
    # Whitelisted CVE fields only, each value within the string and array
    # caps, but three-byte characters push the node past the 64 KiB byte
    # cap. The sha256 is recomputed so only the size rule can reject it.
    wide = "\u20ac" * 470
    block["nodes"][0]["fields"].update({
      "cwe": [wide + str(i) for i in range(20)],
      "affected_products": [wide + str(i) for i in range(20)],
      "reference_urls": ["https://example.test/" + wide + str(i) for i in range(20)],
    })
    block["sha256"] = _nodes_sha256(block["nodes"])
    self.assertGreater(
      len(json.dumps(block["nodes"][0], ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
      misp_enrichment.MAX_NODE_BYTES,
    )
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_extra_top_level_key_fails_closed(self):
    block = self._valid_block()
    block["redaction"] = {"contains_raw_misp_payload": False}
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))

  def test_omitted_nodes_inconsistent_with_truncated_fails_closed(self):
    block = self._valid_block()
    block["truncated"] = False
    block["omitted_nodes"] = 3
    self.assertFalse(misp_enrichment.validate_misp_enrichment_block(block))


class MispBlockContainsRawPayloadTests(unittest.TestCase):
  """`misp_block_contains_raw_payload` is the low-level signal the block
  validator fails closed on -- exercised directly."""

  def test_clean_block_is_false(self):
    block = misp_enrichment.build_misp_enrichment_block(
      [_cve_row()], {"cve-1": "N0"},
    )
    self.assertFalse(misp_enrichment.misp_block_contains_raw_payload(block))

  def test_nested_object_makes_it_true(self):
    block = misp_enrichment.build_misp_enrichment_block(
      [_cve_row()], {"cve-1": "N0"},
    )
    block["nodes"][0]["fields"]["injected"] = {"nested": "object"}
    self.assertTrue(misp_enrichment.misp_block_contains_raw_payload(block))


class GraphPacketRedactionRevertTests(unittest.TestCase):
  """v0.1 packet behaviour: `misp_enrichment` never accompanies the graph
  evidence packet in slice 3a, so `redaction.contains_raw_misp_payload` is
  the hard-coded `False`, and `_validate_graph_evidence_packet` trusts the
  declared field instead of recomputing it from `packet["graph"]`."""

  def _clean_packet(self):
    indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "203.0.113.7", "type": "ip"})
    source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
    packet, _meta = _build_graph_evidence_packet(
      request="Explain",
      accepted_cypher="MATCH (i)-[:SOURCED_FROM]->(s) RETURN i, s",
      executed_cypher="MATCH (i)-[:SOURCED_FROM]->(s) RETURN i, s",
      records=[{"i": indicator, "s": source}],
      generated_limit=10,
      executed_limit=10,
      limit_adjusted=False,
    )
    return packet

  def test_redaction_flag_is_hardcoded_false(self):
    packet = self._clean_packet()
    self.assertIs(packet["redaction"]["contains_raw_misp_payload"], False)
    errors, _context = _validate_graph_evidence_packet(packet)
    codes = {error["code"] for error in errors}
    self.assertNotIn("raw_misp_payload_not_allowed", codes)

  def test_validator_trusts_the_declared_field_not_a_recompute(self):
    # v0.1 behaviour: the validator only checks the declared flag -- a
    # clean packet with the flag declared `False` passes, and the same
    # packet with the flag declared `True` fails, regardless of what
    # `packet["graph"]` itself contains.
    clean_packet = self._clean_packet()
    errors, _context = _validate_graph_evidence_packet(clean_packet)
    codes = {error["code"] for error in errors}
    self.assertNotIn("raw_misp_payload_not_allowed", codes)

    declared_true_packet = self._clean_packet()
    declared_true_packet["redaction"]["contains_raw_misp_payload"] = True
    errors, _context = _validate_graph_evidence_packet(declared_true_packet)
    codes = {error["code"] for error in errors}
    self.assertIn("raw_misp_payload_not_allowed", codes)


class CandidateCollectionTests(unittest.TestCase):
  def test_nodes_without_misp_ids_are_not_candidates(self):
    indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "203.0.113.7"})
    candidates = _collect_misp_candidate_nodes([{"i": indicator}])
    self.assertEqual(candidates, {})

  def test_nodes_with_misp_ids_are_candidates(self):
    indicator = _GraphNode(
      "indicator-1", ["Indicator"],
      {"value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": []},
    )
    candidates = _collect_misp_candidate_nodes([{"i": indicator}])
    self.assertEqual(list(candidates), ["indicator-1"])
    self.assertEqual(candidates["indicator-1"]["labels"], ["Indicator"])

  def test_reuses_collect_graph_dedup_across_records(self):
    # The same node reached twice (e.g. via two rows) is one candidate,
    # exactly like it is one packet node.
    indicator = _GraphNode(
      "indicator-1", ["Indicator"],
      {"value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": []},
    )
    candidates = _collect_misp_candidate_nodes([{"i": indicator}, {"i": indicator}])
    self.assertEqual(len(candidates), 1)


class MispEnrichmentForResponseTests(unittest.TestCase):
  def _fake_driver(self, rows):
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.return_value = rows
    driver = MagicMock()
    driver.session.return_value = session
    return driver, session

  def _records(self):
    indicator = _GraphNode(
      "indicator-1", ["Indicator"],
      {"value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"]},
    )
    return [{"i": indicator}]

  def test_returns_block_and_queries_once(self):
    plugin = _make_api()
    rows = [{
      "element_id": "indicator-1", "labels": ["Indicator"],
      "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      "source": "alienvault_otx", "last_imported_from": None,
      "sourced": [{"source_id": "alienvault_otx", "raw_data": json.dumps({
        "pulse_name": "Synthetic Pulse",
      })}],
    }]
    driver, session = self._fake_driver(rows)
    records = self._records()
    block = plugin._misp_enrichment_for_response(
      driver=driver, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertIsNotNone(block)
    self.assertEqual(session.run.call_count, 1)
    self.assertEqual(block["nodes"][0]["node_ref"], "N0")
    self.assertEqual(block["nodes"][0]["fields"]["pulse_name"], "Synthetic Pulse")

  def test_absent_when_driver_is_none(self):
    plugin = _make_api()
    records = self._records()
    block = plugin._misp_enrichment_for_response(
      driver=None, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertIsNone(block)

  def test_absent_when_no_candidate_nodes(self):
    plugin = _make_api()
    driver, session = self._fake_driver([])
    plain_node = _GraphNode("n1", ["Entity"], {"value": "x"})
    block = plugin._misp_enrichment_for_response(driver=driver, records=[{"n": plain_node}])
    self.assertIsNone(block)
    session.run.assert_not_called()

  def test_absent_when_node_has_no_digest_alias(self):
    # A candidate node with MISP ids but no entry in the digest's alias map
    # is not enriched -- the query never even fires.
    plugin = _make_api()
    driver, session = self._fake_driver([])
    block = plugin._misp_enrichment_for_response(
      driver=driver, records=self._records(), node_source_aliases={},
    )
    self.assertIsNone(block)
    session.run.assert_not_called()

  def test_fail_open_on_neo4j_error(self):
    plugin = _make_api()
    driver = MagicMock()
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.side_effect = RuntimeError("neo4j down")
    driver.session.return_value = session
    records = self._records()
    block = plugin._misp_enrichment_for_response(
      driver=driver, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertIsNone(block)

  def test_swallowed_error_is_recorded_bounded_and_value_free(self):
    # A counter increments and only the exception class name is kept --
    # never the message or any raw data.
    plugin = _make_api()
    driver = MagicMock()
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.side_effect = RuntimeError("neo4j down, host=10.0.0.9 user=neo4j pass=hunter2")
    driver.session.return_value = session
    records = self._records()
    plugin._misp_enrichment_for_response(
      driver=driver, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertEqual(plugin._misp_enrichment_error_count, 1)
    self.assertEqual(plugin._misp_enrichment_last_error, "RuntimeError")

  def test_validator_rejection_is_recorded_with_a_fixed_reason(self):
    # The same counter as the exception path above, but with a fixed
    # reason name (never the block content) when the built block itself
    # fails the validator -- the fail-closed backstop still increments
    # observability instead of silently returning `None`.
    plugin = _make_api()
    driver, session = self._fake_driver([{
      "element_id": "indicator-1", "labels": ["Indicator"],
      "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      "source": None, "last_imported_from": None, "sourced": [],
    }])
    records = self._records()
    with patch.object(misp_enrichment, "validate_misp_enrichment_block", return_value=False):
      block = plugin._misp_enrichment_for_response(
        driver=driver, records=records, node_source_aliases=_alias_map_for(records),
      )
    self.assertIsNone(block)
    self.assertEqual(plugin._misp_enrichment_error_count, 1)
    self.assertEqual(plugin._misp_enrichment_last_error, "validation")

  def test_disabled_by_config_switch(self):
    plugin = _make_api()
    plugin.cfg_misp_enrichment_enabled = False
    driver, session = self._fake_driver([{"element_id": "indicator-1", "labels": ["Indicator"]}])
    records = self._records()
    block = plugin._misp_enrichment_for_response(
      driver=driver, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertIsNone(block)
    session.run.assert_not_called()

  def test_fifty_node_truncation_reported_with_omitted_nodes(self):
    plugin = _make_api()
    records = [{
      f"n{i}": _GraphNode(
        f"node-{i}", ["Indicator"],
        {"misp_event_ids": [str(900 + i)], "misp_attribute_ids": []},
      )
      for i in range(60)
    }]
    rows = [{
      "element_id": f"node-{i}", "labels": ["Indicator"],
      "misp_event_ids": [str(900 + i)], "misp_attribute_ids": [],
      "source": None, "last_imported_from": None, "sourced": [],
    } for i in range(50)]
    driver, session = self._fake_driver(rows)
    block = plugin._misp_enrichment_for_response(
      driver=driver, records=records, node_source_aliases=_alias_map_for(records),
    )
    self.assertIsNotNone(block)
    self.assertTrue(block["truncated"])
    self.assertEqual(block["omitted_nodes"], 10)
    self.assertEqual(len(block["nodes"]), 50)
    self.assertEqual(session.run.call_count, 1)
    queried_ids = session.run.call_args.kwargs["element_ids"]
    self.assertEqual(len(queried_ids), 50)


class BoundedGraphFirstSuccessTrimmingTests(unittest.TestCase):
  """Contract §7.3: `misp_enrichment` is dropped first, before
  `explanation_trace` is ever touched."""

  def test_misp_enrichment_dropped_before_explanation_trace(self):
    plugin = _make_api()
    # The oversized payload lives entirely in `misp_enrichment` here -- a
    # real, validator-valid block (many nodes, each padded through a
    # whitelisted CVE field, never an extra/unknown key) well past
    # `RESPONSE_MAX_BYTES` on its own -- `explanation_trace` stays small and
    # untouched. If the response fits once only `misp_enrichment` is
    # dropped, `explanation_trace` (and its `raw_output`/`parsed` fields)
    # must never have been trimmed.
    oversized_block = _valid_block(50, padded=True)
    self.assertGreater(
      len(json.dumps(oversized_block, ensure_ascii=False).encode("utf-8")), RESPONSE_MAX_BYTES,
    )
    trace = {
      "schema_version": "edgeguard.analyst_brief_trace.v1",
      "profile": {"id": "EAB/1"},
      "calls": [{"raw_output": "small completion", "parsed": {"summary": "ok"}, "finish_reason": "stop"}],
      "outcome": {"status": "supported", "attempted_calls": 1, "completed_calls": 1},
    }
    value = {
      "status": "ok",
      "result_digest": {"schema_version": "edgeguard.result_digest.v1"},
      "misp_enrichment": oversized_block,
      "explanation_trace": trace,
    }
    result = plugin._bounded_graph_first_success(value)
    self.assertNotIn("misp_enrichment", result)
    # `explanation_trace` (including `raw_output`/`parsed`) is byte-for-byte
    # untouched -- dropping `misp_enrichment` alone was enough.
    self.assertEqual(result["explanation_trace"], trace)
    self.assertIn("raw_output", result["explanation_trace"]["calls"][0])

  def test_still_oversized_after_dropping_misp_enrichment_falls_back_to_trace_trimming(self):
    plugin = _make_api()
    small_block = _valid_block()
    trace = {
      "schema_version": "edgeguard.analyst_brief_trace.v1",
      "profile": {"id": "EAB/1"},
      "calls": [{"raw_output": "x" * (RESPONSE_MAX_BYTES + 1000), "parsed": {}, "finish_reason": "stop"}],
      "outcome": {"status": "supported", "attempted_calls": 1, "completed_calls": 1},
    }
    value = {
      "status": "ok",
      "result_digest": {"schema_version": "edgeguard.result_digest.v1"},
      "misp_enrichment": small_block,
      "explanation_trace": trace,
    }
    with self.assertRaises(GraphFirstRuntimeError) as ctx:
      plugin._bounded_graph_first_success(value)
    safe_trace = ctx.exception.trace
    self.assertNotIn("raw_output", safe_trace["calls"][0])
    self.assertEqual(safe_trace["outcome"]["safe_code"], "explanation_response_size")

  def test_response_within_cap_keeps_misp_enrichment(self):
    plugin = _make_api()
    value = {
      "status": "ok",
      "result_digest": {"schema_version": "edgeguard.result_digest.v1"},
      "misp_enrichment": _valid_block(),
    }
    result = plugin._bounded_graph_first_success(value)
    self.assertIn("misp_enrichment", result)


class ExplainGraphEndToEndTests(unittest.TestCase):
  """Contract §7.5, criterion 2: an Indicator query response carries the
  block with correct event URLs, only whitelisted keys, no raw JSON
  strings, within caps -- through the real `explain_graph` endpoint, not
  just the internal builder. `node_ref` joins to the real `result_digest`
  node ref."""

  def _setup(self, *, strategy="eel_compatibility", indicator_props, misp_rows, misp_enrichment_enabled=None):
    """One shared driver/session/plugin setup for every `explain_graph`
    end-to-end test in this class -- callers that need extra patches (e.g.
    over `run_analyst_brief`) wrap the returned `(plugin, fake_driver)` in
    their own `with patch(...)` before invoking `explain_graph`."""
    plugin = _make_api(edgeguard_explanation_strategy=strategy)
    if misp_enrichment_enabled is not None:
      plugin.cfg_misp_enrichment_enabled = misp_enrichment_enabled
    indicator = _GraphNode("indicator-1", ["Indicator"], indicator_props)
    source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
    main_record = _DriverRecord(
      {"i": indicator, "s": source},
      {"i": {"value": "203.0.113.7"}, "s": {"name": "AlienVault OTX"}},
    )
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    side_effect = [_Result([main_record], keys=["i", "s"])]
    if misp_rows is not None:
      side_effect.append(misp_rows)
    fake_session.run.side_effect = side_effect
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session
    return plugin, fake_driver, fake_session

  def _run(self, *, indicator_props, misp_rows, misp_enrichment_enabled=None):
    plugin, fake_driver, fake_session = self._setup(
      indicator_props=indicator_props, misp_rows=misp_rows,
      misp_enrichment_enabled=misp_enrichment_enabled,
    )
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the indicator",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
        )
    return result, fake_session

  def test_indicator_response_carries_misp_enrichment_joined_to_the_digest_ref(self):
    misp_rows = [{
      "element_id": "indicator-1", "labels": ["Indicator"],
      "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      "source": "alienvault_otx", "last_imported_from": "2026-09-20T00:00:00Z",
      "sourced": [{"source_id": "alienvault_otx", "raw_data": json.dumps({
        "pulse_name": "Synthetic Pulse", "pulse_references": ["https://otx.test/pulse/1"],
      })}],
    }]
    result, fake_session = self._run(
      indicator_props={
        "value": "203.0.113.7", "type": "ip",
        "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      },
      misp_rows=misp_rows,
    )

    self.assertEqual(result["status"], "ok")
    self.assertIn("result_digest", result)
    self.assertIn("misp_enrichment", result)
    block = result["misp_enrichment"]
    self.assertEqual(fake_session.run.call_count, 2)
    node = block["nodes"][0]
    # The block's `node_ref` is the same digest ref the digest itself
    # assigned to this node -- not the packet id.
    digest_node_refs = {entry["ref"] for entry in result["result_digest"]["exact_inventory"]["nodes"]}
    self.assertIn(node["node_ref"], digest_node_refs)
    self.assertEqual(node["node_ref"], "N0")
    self.assertEqual(
      node["misp_event_urls"], ["https://misp.edgeguard.org/events/view/901"],
    )
    self.assertEqual(
      set(node["fields"]),
      {"pulse_name", "pulse_references", "source", "last_imported_from"},
    )
    encoded = json.dumps(result, ensure_ascii=False)
    self.assertNotIn("cvss_v31_data", encoded)

  def test_no_candidate_nodes_means_block_absent(self):
    result, fake_session = self._run(
      indicator_props={"value": "203.0.113.7"},
      misp_rows=None,
    )
    self.assertEqual(result["status"], "ok")
    self.assertNotIn("misp_enrichment", result)
    self.assertEqual(fake_session.run.call_count, 1)

  def test_production_config_default_is_disabled(self):
    # Ruling R4: read the class config directly, not a `_make_api` instance
    # (which may already carry a test-time override).
    self.assertIs(EdgeguardApiPlugin.CONFIG["MISP_ENRICHMENT_ENABLED"], False)

  def test_misp_enrichment_disabled_by_default_config(self):
    result, fake_session = self._run(
      indicator_props={
        "value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      },
      misp_rows=None,
      misp_enrichment_enabled=False,
    )
    self.assertNotIn("misp_enrichment", result)
    self.assertEqual(fake_session.run.call_count, 1)  # the internal query never fires

  def test_neither_run_analyst_brief_nor_insight_brief_ever_receive_the_block(self):
    # Contract §7.4: every dispatch path that can call a model is exercised
    # here -- `one_call` calls `run_analyst_brief`, `insight_brief` calls
    # `egx2.run_insight_brief` -- and neither ever receives
    # `misp_enrichment` as an argument.
    misp_rows = [{
      "element_id": "indicator-1", "labels": ["Indicator"],
      "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      "source": "alienvault_otx", "last_imported_from": None,
      "sourced": [{"source_id": "alienvault_otx", "raw_data": json.dumps({
        "pulse_name": "Synthetic Pulse",
      })}],
    }]
    for strategy, target in (
      ("one_call", "extensions.business.cybersec.edgeguard.edgeguard_api.run_analyst_brief"),
      ("insight_brief", "extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief"),
    ):
      with self.subTest(strategy=strategy):
        plugin, fake_driver, _fake_session = self._setup(
          strategy=strategy,
          indicator_props={
            "value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
          },
          misp_rows=misp_rows,
        )
        with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
          with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
            with patch(target) as fake_call:
              fake_call.side_effect = Exception("model call should not carry misp_enrichment as an argument")
              try:
                plugin.explain_graph(
                  uri="example.com:7687",
                  scheme="bolt+s",
                  username="neo4j",
                  password="secret",
                  request="Explain the indicator",
                  cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
                )
              except Exception:
                pass
              self.assertEqual(fake_call.call_count, 1)
              _assert_no_block_leak(self, fake_call)


class ResponsePathsCarryTheBlockTests(unittest.TestCase):
  """The truncated, insight-brief, one-call and digest-only response paths
  all carry `misp_enrichment` (as a sibling of `result_digest`) when a
  block is present."""

  _BLOCK = _valid_block()

  def test_one_call_digest_analyst_brief_path_carries_the_block(self):
    plugin = _make_api()
    result = plugin._run_digest_analyst_brief(
      digest={"counts": {"returned_rows": 0}},
      packet={"graph": {"nodes": [], "relationships": []}},
      packet_meta={},
      validation=None,
      live_retry={},
      request="Explain",
      deadline=time.monotonic() + 1000,
      misp_enrichment_block=self._BLOCK,
    )
    self.assertEqual(result["misp_enrichment"], self._BLOCK)

  def test_one_call_digest_analyst_brief_path_omits_the_block_when_absent(self):
    plugin = _make_api()
    result = plugin._run_digest_analyst_brief(
      digest={"counts": {"returned_rows": 0}},
      packet={"graph": {"nodes": [], "relationships": []}},
      packet_meta={},
      validation=None,
      live_retry={},
      request="Explain",
      deadline=time.monotonic() + 1000,
    )
    self.assertNotIn("misp_enrichment", result)

  def test_insight_brief_path_carries_the_block(self):
    plugin = _make_api()
    # Empty graph + returned_rows > 0 takes the deterministic
    # `tabular_result` branch -- no model call needed.
    result = plugin._run_insight_brief(
      digest={"counts": {"returned_rows": 1}},
      packet={"graph": {"nodes": [], "relationships": []}},
      packet_meta={},
      validation=None,
      live_retry={},
      request="Explain",
      deadline=time.monotonic() + 1000,
      misp_enrichment_block=self._BLOCK,
    )
    self.assertEqual(result["misp_enrichment"], self._BLOCK)

  def test_digest_only_path_carries_the_block(self):
    plugin = _make_api()
    result = plugin._digest_only_success(
      digest={"counts": {"returned_rows": 1}},
      failure={"result": {}},
      packet={"graph": {"nodes": [], "relationships": []}},
      packet_meta={},
      validation=None,
      live_retry={},
      misp_enrichment_block=self._BLOCK,
    )
    self.assertEqual(result["misp_enrichment"], self._BLOCK)

  def _truncated_explain_graph(self, *, strategy):
    plugin = _make_api(edgeguard_explanation_strategy=strategy)
    indicator = _GraphNode(
      "indicator-1", ["Indicator"],
      {"value": "203.0.113.7", "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"]},
    )
    other = _GraphNode("indicator-2", ["Indicator"], {"value": "203.0.113.8"})
    records = [
      _DriverRecord({"i": indicator}, {"i": {"value": "203.0.113.7"}}),
      _DriverRecord({"i": other}, {"i": {"value": "203.0.113.8"}}),
    ]
    misp_rows = [{
      "element_id": "indicator-1", "labels": ["Indicator"],
      "misp_event_ids": ["901"], "misp_attribute_ids": ["attr-1"],
      "source": None, "last_imported_from": None, "sourced": [],
    }]
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.side_effect = [_Result(records, keys=["i"]), misp_rows]
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the indicator",
          explanation_rows=1,  # "fast" mode, row_limit=1: two rows truncate.
          cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
        )
    return result

  def _truncated_explain_graph_spying(self, *, strategy, target):
    module_path, _, attribute = target.rpartition(".")
    owner = api_module.egx2 if module_path.endswith(".egx2") else api_module
    with patch(target, wraps=getattr(owner, attribute)) as spy:
      result = self._truncated_explain_graph(strategy=strategy)
    return result, spy

  def test_truncated_insight_brief_path_carries_the_block(self):
    result, spy = self._truncated_explain_graph_spying(
      strategy="insight_brief",
      target="extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief",
    )
    self.assertEqual(spy.call_count, 1)
    _assert_no_block_leak(self, spy)
    self.assertEqual(result["status"], "ok")
    self.assertIn("misp_enrichment", result)
    self.assertEqual(result["misp_enrichment"]["nodes"][0]["misp_event_ids"], ["901"])

  def test_truncated_digest_only_path_carries_the_block(self):
    result = self._truncated_explain_graph(strategy="eel_compatibility")
    self.assertEqual(result["status"], "ok")
    self.assertIn("misp_enrichment", result)
    self.assertEqual(result["misp_enrichment"]["nodes"][0]["misp_event_ids"], ["901"])


if __name__ == "__main__":
  unittest.main()
