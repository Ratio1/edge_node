"""Tests for GrayboxFinding model."""

import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxEvidenceArtifact, GrayboxFinding


class TestGrayboxFinding(unittest.TestCase):

  def _make_finding(self, **overrides):
    defaults = dict(
      scenario_id="PT-A01-01",
      title="IDOR on /api/records/",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cwe=["CWE-639", "CWE-862"],
      attack=["T1078"],
      evidence=["endpoint=/api/records/2/", "status=200"],
      replay_steps=["Login as user A", "GET /api/records/2/"],
      remediation="Enforce object-level authorization.",
    )
    defaults.update(overrides)
    return GrayboxFinding(**defaults)

  def test_to_dict_roundtrip(self):
    """to_dict() produces a JSON-safe dict."""
    f = self._make_finding()
    d = f.to_dict()
    self.assertIsInstance(d, dict)
    # JSON serializable
    serialized = json.dumps(d)
    self.assertIsInstance(json.loads(serialized), dict)
    # All fields present
    self.assertEqual(d["scenario_id"], "PT-A01-01")
    self.assertEqual(d["title"], "IDOR on /api/records/")
    self.assertEqual(d["status"], "vulnerable")
    self.assertEqual(d["severity"], "HIGH")
    self.assertEqual(d["owasp"], "A01:2021")
    self.assertEqual(d["cwe"], ["CWE-639", "CWE-862"])
    self.assertEqual(d["attack"], ["T1078"])

  def test_to_flat_finding_vulnerable(self):
    """Vulnerable status -> confidence=certain, severity preserved."""
    f = self._make_finding(status="vulnerable", severity="HIGH")
    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")
    self.assertEqual(flat["confidence"], "certain")
    self.assertEqual(flat["severity"], "HIGH")
    self.assertEqual(flat["probe_type"], "graybox")
    self.assertEqual(flat["port"], 443)
    self.assertEqual(flat["protocol"], "https")
    self.assertEqual(flat["probe"], "access_control")
    self.assertEqual(flat["category"], "graybox")
    self.assertIn("finding_id", flat)

  def test_to_flat_finding_not_vulnerable(self):
    """not_vulnerable status -> severity overridden to INFO."""
    f = self._make_finding(status="not_vulnerable", severity="HIGH")
    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")
    self.assertEqual(flat["severity"], "INFO")
    self.assertEqual(flat["confidence"], "firm")
    self.assertEqual(flat["status"], "not_vulnerable")

  def test_to_flat_finding_inconclusive(self):
    """inconclusive status -> confidence=tentative."""
    f = self._make_finding(status="inconclusive", severity="MEDIUM")
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="injection")
    self.assertEqual(flat["confidence"], "tentative")
    self.assertEqual(flat["severity"], "MEDIUM")

  def test_evidence_joined(self):
    """Evidence list is joined with '; ' in flat finding."""
    f = self._make_finding(evidence=["endpoint=/api/foo", "status=200"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["evidence"], "endpoint=/api/foo; status=200")

  def test_cwe_joined(self):
    """CWE list is joined with ', ' in flat finding."""
    f = self._make_finding(cwe=["CWE-639", "CWE-862"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["cwe_id"], "CWE-639, CWE-862")

  def test_finding_id_deterministic(self):
    """Same inputs produce the same finding_id."""
    f = self._make_finding()
    flat1 = f.to_flat_finding(port=443, protocol="https", probe_name="ac")
    flat2 = f.to_flat_finding(port=443, protocol="https", probe_name="ac")
    self.assertEqual(flat1["finding_id"], flat2["finding_id"])

  def test_finding_id_stable_for_equivalent_cwe_order(self):
    """Equivalent CWE sets produce the same finding_id regardless of list order."""
    f1 = self._make_finding(cwe=["CWE-639", "CWE-862"])
    f2 = self._make_finding(cwe=["CWE-862", "CWE-639"])
    flat1 = f1.to_flat_finding(port=443, protocol="https", probe_name="ac")
    flat2 = f2.to_flat_finding(port=443, protocol="https", probe_name="ac")
    self.assertEqual(flat1["finding_id"], flat2["finding_id"])

  def test_replay_steps_preserved(self):
    """Replay steps round-trip to flat finding."""
    steps = ["Login as user A", "GET /api/records/2/"]
    f = self._make_finding(replay_steps=steps)
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["replay_steps"], steps)

  def test_default_factory_lists(self):
    """All list fields default to [] (not None)."""
    f = GrayboxFinding(
      scenario_id="PT-X", title="T", status="vulnerable",
      severity="LOW", owasp="A01:2021",
    )
    self.assertEqual(f.cwe, [])
    self.assertEqual(f.attack, [])
    self.assertEqual(f.evidence, [])
    self.assertEqual(f.replay_steps, [])

  def test_attack_ids_in_flat(self):
    """attack_ids field in flat finding contains MITRE IDs."""
    f = self._make_finding(attack=["T1078", "T1110"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["attack_ids"], ["T1078", "T1110"])

  def test_description_format(self):
    """Description includes scenario_id and title."""
    f = self._make_finding(scenario_id="PT-A03-01", title="SQL Injection")
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="inj")
    self.assertEqual(flat["description"], "Scenario PT-A03-01: SQL Injection")

  def test_error_field(self):
    """error field is None by default, can be set."""
    f = self._make_finding()
    self.assertIsNone(f.error)
    f2 = self._make_finding(error="Connection refused")
    self.assertEqual(f2.error, "Connection refused")

  def test_evidence_artifacts_roundtrip(self):
    """Typed evidence artifacts serialize as JSON-safe dicts."""
    artifact = GrayboxEvidenceArtifact(
      summary="GET /api/records/2 -> 200",
      request_snapshot="GET /api/records/2",
      response_snapshot='{"owner":"bob"}',
      captured_at="2026-03-13T02:30:00Z",
      raw_evidence_cid="QmEvidenceCID",
    )
    f = self._make_finding(evidence_artifacts=[artifact])

    payload = f.to_dict()

    self.assertEqual(payload["evidence_artifacts"][0]["summary"], "GET /api/records/2 -> 200")
    self.assertEqual(payload["evidence_artifacts"][0]["raw_evidence_cid"], "QmEvidenceCID")

  def test_flat_finding_uses_artifact_summary_when_evidence_strings_absent(self):
    """Artifact summaries backfill the legacy flat evidence field."""
    artifact = GrayboxEvidenceArtifact(summary="GET /admin -> 403")
    f = self._make_finding(evidence=[], evidence_artifacts=[artifact])

    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")

    self.assertEqual(flat["evidence"], "GET /admin -> 403")
    self.assertEqual(flat["evidence_artifacts"][0]["summary"], "GET /admin -> 403")

  def test_flat_from_dict_preserves_typed_evidence_artifacts(self):
    """flat_from_dict is the canonical persisted-finding normalization path."""
    payload = self._make_finding(
      evidence=[],
      evidence_artifacts=[{"summary": "GET /admin -> 403", "raw_evidence_cid": "Qm1"}],
    ).to_dict()

    flat = GrayboxFinding.flat_from_dict(payload, port=443, protocol="https", probe_name="access_control")

    self.assertEqual(flat["evidence"], "GET /admin -> 403")
    self.assertEqual(flat["evidence_artifacts"][0]["raw_evidence_cid"], "Qm1")

  def test_cvss_metadata_survives_flattening(self):
    """Optional CVSS metadata survives typed graybox normalization."""
    f = self._make_finding(
      cvss_score=8.8,
      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    )

    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")

    self.assertEqual(flat["cvss_score"], 8.8)
    self.assertEqual(flat["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")

  def test_frozen(self):
    """Finding is immutable."""
    f = self._make_finding()
    with self.assertRaises(AttributeError):
      f.title = "Changed"


if __name__ == '__main__':
  unittest.main()


class TestGrayboxFindingLocation(unittest.TestCase):
  """
  A graybox finding carried no structured location. The endpoint existed only
  inside a free-text `evidence` string (`endpoint=http://...`) that nothing
  parsed, and `to_flat_finding` emitted no `affected_assets` at all — so a
  finding reached the report with no machine-readable answer to "where".

  RM-062's typed contract and dedup key are designed against
  `affected_assets[].url` / `.parameter`, which is why this has to exist before
  that contract is written rather than after.
  """

  def _finding(self, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    base = dict(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021",
    )
    base.update(kwargs)
    return GrayboxFinding(**base)

  def test_a_location_reaches_affected_assets(self):
    finding = self._finding(
      url="https://app.test/api/records/99", parameter="id", method="GET",
    )
    flat = finding.to_flat_finding(443, "https", "_graybox_idor")
    assets = flat.get("affected_assets")
    self.assertTrue(assets, "the flat finding carries no affected_assets")
    self.assertEqual(assets[0]["url"], "https://app.test/api/records/99")
    self.assertEqual(assets[0]["parameter"], "id")
    self.assertEqual(assets[0]["method"], "GET")
    self.assertEqual(assets[0]["port"], 443)

  def test_a_finding_without_a_location_still_normalises(self):
    flat = self._finding().to_flat_finding(443, "https", "_graybox_idor")
    self.assertEqual(flat.get("affected_assets"), [])

  def test_distinct_endpoints_stay_distinct(self):
    # The dedup key RM-062 builds must not collapse two endpoints that differ
    # only by URL. Before the location existed, identity came from the title
    # plus whichever evidence strings happened to be present.
    a = self._finding(url="https://app.test/api/records/1").to_flat_finding(
      443, "https", "_graybox_idor")
    b = self._finding(url="https://app.test/api/records/2").to_flat_finding(
      443, "https", "_graybox_idor")
    self.assertNotEqual(
      a["finding_id"], b["finding_id"],
      "two endpoints collapsed to one finding id, so N endpoints would dedup "
      "to a single finding",
    )

  def test_the_same_endpoint_still_dedups(self):
    a = self._finding(url="https://app.test/api/records/1").to_flat_finding(
      443, "https", "_graybox_idor")
    b = self._finding(url="https://app.test/api/records/1").to_flat_finding(
      443, "https", "_graybox_idor")
    self.assertEqual(a["finding_id"], b["finding_id"])

  def test_a_parameter_alone_distinguishes_two_findings(self):
    a = self._finding(url="https://app.test/s", parameter="q").to_flat_finding(
      443, "https", "_graybox_inj")
    b = self._finding(url="https://app.test/s", parameter="sort").to_flat_finding(
      443, "https", "_graybox_inj")
    self.assertNotEqual(a["finding_id"], b["finding_id"])

  def test_the_location_survives_a_dict_round_trip(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    original = self._finding(url="https://app.test/x", parameter="p", method="POST")
    restored = GrayboxFinding.from_dict(original.to_dict())
    self.assertEqual(restored.url, "https://app.test/x")
    self.assertEqual(restored.parameter, "p")
    self.assertEqual(restored.method, "POST")

  def test_the_probe_boundary_carries_the_location_through(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = ProbeBase.__new__(ProbeBase)
    probe.findings = []
    probe._scrub_for_emission = lambda value: value
    probe._resolve_attack = lambda scenario_id, attack: list(attack or [])
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/api/records/99"],
      url="https://app.test/api/records/99", parameter="id", method="GET",
    )
    self.assertEqual(probe.findings[0].url, "https://app.test/api/records/99")
    self.assertEqual(probe.findings[0].parameter, "id")


class TestLocationDerivedFromEvidence(unittest.TestCase):
  """
  `endpoint=<url>` is the established convention across the probes — 50 uses —
  and was the de-facto location before a typed field existed. Promoting it at
  the emission boundary populates every existing probe at once, rather than
  relying on 18 call sites each being edited correctly.

  An explicit `url=` always wins; a probe that emits no location key still gets
  no location, which is the same as before.
  """

  def _probe(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = ProbeBase.__new__(ProbeBase)
    probe.findings = []
    probe._scrub_for_emission = lambda value: value
    probe._resolve_attack = lambda scenario_id, attack: list(attack or [])
    return probe

  def _emit(self, evidence, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      evidence, **kwargs,
    )
    return probe.findings[0]

  def test_endpoint_evidence_becomes_the_location(self):
    finding = self._emit(["endpoint=https://app.test/api/records/99", "status=200"])
    self.assertEqual(finding.url, "https://app.test/api/records/99")

  def test_path_and_protected_path_are_also_recognised(self):
    for key in ("path", "protected_path", "token_path"):
      with self.subTest(key=key):
        self.assertEqual(
          self._emit([f"{key}=/admin/users"]).url, "/admin/users",
        )

  def test_an_explicit_url_wins_over_the_evidence(self):
    finding = self._emit(
      ["endpoint=https://app.test/from-evidence"],
      url="https://app.test/explicit",
    )
    self.assertEqual(finding.url, "https://app.test/explicit")

  def test_a_parameter_is_derived_when_present(self):
    finding = self._emit(["endpoint=https://app.test/s", "parameter=sort"])
    self.assertEqual(finding.parameter, "sort")

  def test_no_location_key_means_no_location(self):
    finding = self._emit(["status=200", "reason=whatever"])
    self.assertIsNone(finding.url)

  def test_the_derived_location_reaches_affected_assets(self):
    finding = self._emit(["endpoint=https://app.test/api/records/99"])
    flat = finding.to_flat_finding(443, "https", "_graybox_idor")
    self.assertEqual(flat["affected_assets"][0]["url"],
                     "https://app.test/api/records/99")

  def test_two_endpoints_from_evidence_alone_stay_distinct(self):
    a = self._emit(["endpoint=https://app.test/a"]).to_flat_finding(
      443, "https", "_p")
    b = self._emit(["endpoint=https://app.test/b"]).to_flat_finding(
      443, "https", "_p")
    self.assertNotEqual(a["finding_id"], b["finding_id"])


class TestEvidenceArtifactProduction(unittest.TestCase):
  """
  `GrayboxEvidenceArtifact` was dead schema: zero constructions anywhere outside
  tests. And even when populated it never reached the model — `to_flat_finding`
  emits `evidence_artifacts` while `llm_input_builder` reads `evidence_items`,
  which nothing produces for a graybox finding. The builder explicitly does not
  forward the legacy `evidence` string ("raw probe output. Use evidence_items
  instead"), so the LLM wrote its security narrative with **no evidence at all**.

  Two stacked defects: an absent producer, and a key-name mismatch of the same
  class as the `accepted` / `accepted_credentials` one.
  """

  def _probe(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = ProbeBase.__new__(ProbeBase)
    probe.findings = []
    probe._scrub_for_emission = lambda value: value
    probe._resolve_attack = lambda scenario_id, attack: list(attack or [])
    return probe

  def _response(self, body="secret-free body", status=200, elapsed=0.25):
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.headers = {"Content-Type": "application/json"}
    resp.url = "https://app.test/api/records/99"
    resp.request = MagicMock()
    resp.request.method = "GET"
    resp.request.url = "https://app.test/api/records/99"
    resp.request.headers = {"Accept": "application/json"}
    resp.request.body = None
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = elapsed
    return resp

  def _emit_with_response(self, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/api/records/99"],
      response=self._response(**kwargs),
    )
    return probe.findings[0]

  def test_the_triggering_response_becomes_an_evidence_artifact(self):
    finding = self._emit_with_response()
    self.assertTrue(finding.evidence_artifacts, "no artifact was produced")
    artifact = finding.evidence_artifacts[0]
    self.assertIn("GET", artifact.request_snapshot)
    self.assertIn("200", artifact.response_snapshot)

  def test_the_artifact_records_when_and_how_long(self):
    artifact = self._emit_with_response(elapsed=0.25).evidence_artifacts[0]
    self.assertTrue(artifact.captured_at, "no capture timestamp")
    self.assertEqual(artifact.latency_ms, 250)

  def test_the_artifact_carries_an_integrity_hash(self):
    artifact = self._emit_with_response().evidence_artifacts[0]
    self.assertEqual(len(artifact.content_sha256), 64)
    # The same response hashes the same way; a different one does not.
    other = self._emit_with_response(body="different body").evidence_artifacts[0]
    self.assertNotEqual(artifact.content_sha256, other.content_sha256)

  def test_the_snapshots_are_redacted(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    # Restore the real scrubber for this one: the artifact must not become a
    # new way to archive what the scrubber removes elsewhere.
    probe._scrub_for_emission = ProbeBase._scrub_for_emission.__get__(probe)
    probe.target_config = None
    resp = self._response()
    resp.request.headers = {"Authorization": "Bearer sk-live-abcdefghijklmnop"}
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"], response=resp,
    )
    artifact = probe.findings[0].evidence_artifacts[0]
    self.assertNotIn("sk-live-abcdefghijklmnop", artifact.request_snapshot)

  def test_the_artifact_reaches_the_llm_under_the_key_it_reads(self):
    flat = self._emit_with_response().to_flat_finding(443, "https", "_graybox_idor")
    self.assertTrue(
      flat.get("evidence_items"),
      "the LLM input builder reads evidence_items and nothing produces it, so "
      "the narrative is written with no evidence",
    )
    item = flat["evidence_items"][0]
    self.assertEqual(item["kind"], "request_response")
    self.assertTrue(item["caption"])

  def test_emitting_without_a_response_is_unchanged(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"],
    )
    self.assertEqual(probe.findings[0].evidence_artifacts, [])
