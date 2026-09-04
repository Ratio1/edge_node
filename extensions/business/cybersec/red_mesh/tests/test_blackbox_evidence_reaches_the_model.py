"""RM-062 B3, blackbox half: the LLM was given no evidence at all.

`llm_input_builder` reads `evidence_items` and deliberately does not forward the
legacy `evidence` string ("raw probe output. Use evidence_items instead"). No
blackbox probe populates `evidence_items` — `Finding.evidence_items` has zero
constructions outside tests — so every blackbox finding arrived at the model
with `evidence_items: None` while its actual evidence sat one key over in a
field the builder drops on purpose.

RM-060 closed the graybox half by wiring `GrayboxEvidenceArtifact` through. This
is the other half, and the task's own wording allows the cheaper fix: "populate
`evidence_items` at the probe boundary ... **or forward a sanitised `evidence`
string**". Forwarding it at the normaliser covers every blackbox probe at once,
rather than editing dozens of call sites to construct an object each.
"""

import unittest

from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin


class _Host(_RiskScoringMixin):
  pass


def _flat(finding):
  _risk, flat = _Host()._compute_risk_and_findings({
    "target": "app.test",
    "port_protocols": {"443": "https"},
    "service_info": {"443": {"_service_info_ssl": {"findings": [finding]}}},
  })
  return flat[0]


_TLS = {
  "title": "Weak TLS", "severity": "MEDIUM", "confidence": "certain",
  "evidence": "TLSv1.0 offered on 443; cipher RC4-SHA",
}


class TestTheEvidenceReachesTheKeyTheModelReads(unittest.TestCase):

  def test_a_blackbox_finding_carries_an_evidence_item(self):
    items = _flat(_TLS)["evidence_items"]
    self.assertTrue(items, "the model is given no evidence for this finding")
    self.assertIn("TLSv1.0 offered on 443", items[0]["snippet"])

  def test_the_item_matches_the_shape_the_graybox_half_emits(self):
    item = _flat(_TLS)["evidence_items"][0]
    for key in ("kind", "caption", "snippet"):
      self.assertIn(key, item)
    self.assertTrue(item["caption"])

  def test_a_finding_with_no_evidence_gets_no_invented_item(self):
    flat = _flat({"title": "t", "severity": "LOW", "confidence": "firm"})
    self.assertEqual(flat.get("evidence_items", []), [])

  def test_an_existing_evidence_item_is_not_overwritten(self):
    """A probe that builds a real item must keep it — the fallback is for the
    probes that have only the legacy string."""
    flat = _flat({
      **_TLS,
      "evidence_items": [{"kind": "banner", "caption": "handshake", "snippet": "real"}],
    })
    self.assertEqual(len(flat["evidence_items"]), 1)
    self.assertEqual(flat["evidence_items"][0]["snippet"], "real")

  def test_the_legacy_string_is_left_in_place(self):
    # Existing consumers read `evidence`; this adds a key rather than moving one.
    self.assertEqual(_flat(_TLS)["evidence"], _TLS["evidence"])


class TestItSurvivesTheBuilder(unittest.TestCase):

  def test_the_model_actually_receives_it(self):
    from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input

    flat = _flat(_TLS)
    payload = build_llm_input(
      findings=[flat], aggregated_report={"target": "app.test"},
    )
    finding = payload.findings[0]
    self.assertTrue(
      finding.get("evidence_items"),
      "the evidence was dropped between the normaliser and the model",
    )


if __name__ == "__main__":
  unittest.main()
