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


class TestDirectlyConstructedFindingsAlsoDeriveTheirLocation(unittest.TestCase):
  """
  The derivation above runs inside `emit_vulnerable`, so it only reaches probes
  that emit through it. `access_control`, `injection`, `misconfig` and
  `business_logic` append `GrayboxFinding(...)` straight onto `self.findings` —
  87 of the 93 constructions in the tree — and never populate `url`. Their
  findings therefore reached `dedup_key` with an empty `affected_assets`, and
  identity collapsed to probe + scenario_id + classification.

  That is a regression rather than a standing gap: the pre-RM-062
  `to_flat_finding` folded the `endpoint=` / `path=` evidence prefixes into its
  id input directly, so these endpoints used to be distinguishable.

  Deriving in `to_flat_finding` covers both producers at one site. It reads the
  same structured `key=value` prefixes the emission path does — not the evidence
  string as free text, which is what RM-062 removed from identity.
  """

  def _finding(self, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    base = dict(
      scenario_id="PT-A03-01", title="Reflected SQLI in authenticated form",
      status="vulnerable", severity="HIGH", owasp="A03:2021", cwe=["CWE-89"],
    )
    base.update(kwargs)
    return GrayboxFinding(**base)

  def _flat(self, **kwargs):
    return self._finding(**kwargs).to_flat_finding(443, "https", "_graybox_injection")

  def test_two_endpoints_in_evidence_stay_distinct(self):
    """The shape `injection.py` emits once per vulnerable form."""
    a = self._flat(evidence=["endpoint=https://app.test/admin/users/search",
                             "field=q", "payload_reflected=True"])
    b = self._flat(evidence=["endpoint=https://app.test/admin/settings/search",
                             "field=q", "payload_reflected=True"])
    self.assertNotEqual(
      a["finding_id"], b["finding_id"],
      "two endpoints share one finding_id, so triage applied to one closes the "
      "other — triage keys on finding_id alone",
    )

  def test_a_path_prefix_is_recognised_too(self):
    """`misconfig` records `path=`, not `endpoint=`."""
    a = self._flat(evidence=["path=/admin/users"])
    b = self._flat(evidence=["path=/admin/settings"])
    self.assertNotEqual(a["finding_id"], b["finding_id"])

  def test_the_derived_endpoint_reaches_affected_assets(self):
    flat = self._flat(evidence=["endpoint=https://app.test/a", "status=200"])
    self.assertEqual(flat["affected_assets"][0]["url"], "https://app.test/a")

  def test_an_explicit_url_still_wins(self):
    flat = self._flat(
      url="https://app.test/explicit",
      evidence=["endpoint=https://app.test/from-evidence"],
    )
    self.assertEqual(flat["affected_assets"][0]["url"], "https://app.test/explicit")

  def test_the_same_endpoint_still_dedups(self):
    a = self._flat(evidence=["endpoint=https://app.test/a", "status=200"])
    b = self._flat(evidence=["endpoint=https://app.test/a", "status=500"])
    self.assertEqual(a["finding_id"], b["finding_id"])
    self.assertNotEqual(
      a["finding_signature"], b["finding_signature"],
      "identity must survive a content change, and content must still move",
    )

  def test_a_finding_with_no_location_key_gets_no_asset(self):
    """A finding whose evidence names no location still records none.

    Not a statement about coverage records: six `not_vulnerable`/`inconclusive`
    sites *do* lead with `endpoint=` or `token_path=` (`misconfig.py:465`,
    `:942`, `:965`, `:1058`; `injection.py:375`; `access_control.py:204` when
    `has_content` is false) and now carry an asset. That is harmless — every
    coverage consumer keys on `status` via `models/finding_schema.is_coverage_result`,
    never on asset emptiness — but it changes their `finding_id` too, so it is
    part of the one-time rotation this branch causes.
    """
    flat = self._flat(evidence=["endpoints_tested=4"])
    self.assertEqual(flat["affected_assets"], [])

  def test_a_coverage_record_that_names_a_location_keeps_its_status(self):
    """The `misconfig.py:465` shape: `not_vulnerable`, but evidence names a URL."""
    flat = self._flat(status="not_vulnerable", severity="INFO",
                      evidence=["endpoint=https://app.test/login"])
    self.assertEqual(flat["status"], "not_vulnerable")
    self.assertEqual(flat["affected_assets"][0]["url"], "https://app.test/login")
    from extensions.business.cybersec.red_mesh.models.finding_schema import (
      is_coverage_result,
    )
    self.assertTrue(
      is_coverage_result(flat),
      "gaining an asset must not turn a coverage record into a finding",
    )

  def test_a_secret_in_the_derived_url_is_redacted_before_it_is_promoted(self):
    """A URL can carry a token in its query string.

    Promoting evidence to a typed field must not reintroduce what the scrubber
    removes elsewhere — `emit_vulnerable` derives from the scrubbed list for the
    same reason.
    """
    flat = self._flat(
      evidence=["endpoint=https://app.test/cb?api_key=ABCDEFG12345&x=1"],
    )
    self.assertNotIn("ABCDEFG12345", flat["affected_assets"][0]["url"])
    self.assertNotIn("ABCDEFG12345", str(flat))

  def test_the_persisted_form_carries_no_id_for_the_read_path_to_honour(self):
    """`flat_from_dict`'s stamped-id branch is dead for graybox — state it.

    An earlier version of this test handed `flat_from_dict` a payload with a
    `finding_id` and asserted the stamp won, and on that basis the PR claimed
    archived findings were unaffected by the identity change. The payload was
    fabricated. `GrayboxFinding` has no `finding_id` field, so `to_dict()` — the
    persistence path at `graybox/worker.py` — never emits one, and `mixins/risk.py`
    is the only production caller. Identity is therefore always recomputed, and
    this branch does rotate it once.

    A test whose fixture cannot occur in production proves nothing about
    production. The stamp is still honoured if a payload ever carries one, which
    the second half asserts; what changes is the claim built on it.
    """
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    persisted = self._finding(evidence=["endpoint=https://app.test/a"]).to_dict()
    self.assertNotIn("finding_id", persisted)
    self.assertNotIn("dedup_key", persisted)

    # Recomputed from the persisted form, and equal to the production value.
    from_archive = GrayboxFinding.flat_from_dict(
      persisted, 443, "https", "_graybox_injection")
    direct = self._flat(evidence=["endpoint=https://app.test/a"])
    self.assertEqual(from_archive["finding_id"], direct["finding_id"])

    # And a payload that does carry a stamp still wins — the branch is correct,
    # it is simply unreachable from this producer.
    stamped = GrayboxFinding.flat_from_dict(
      dict(persisted, finding_id="0123456789abcdef"),
      443, "https", "_graybox_injection")
    self.assertEqual(stamped["finding_id"], "0123456789abcdef")


class TestTheDerivedLocationIsALocationAndNotTheWholeClause(unittest.TestCase):
  """
  Half the location-bearing evidence in the four direct-construction probes is a
  `;`-joined composite — `endpoint={path}; param={p}; payload={payload}` and the
  like, 16 of 65 literals. Taking everything after the prefix to end of string
  put the payload, the target's `Location` header, a `repr()` of a record owner
  field and `probed_len={len(response.text)}` into `affected_assets[].url`, and
  from there into the identity hash.

  That made `finding_id` move whenever the target's response moved — the exact
  inverse of the property the derivation exists to provide, and worse than the
  collision it replaced: a colliding id is at least stable enough to triage.
  It also contradicted `llm_input_builder`'s stated contract that assets carry
  "host/port/url only — no full request bodies".

  Matching per `;`-separated clause fixes that, and two other things with it: a
  location key is found when it is not the first clause, and `param=` — which no
  probe emits in first position, so the parameter keys were dead — starts working.
  """

  def _finding(self, evidence, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    base = dict(
      scenario_id="PT-A01-10", title="Query role override", status="vulnerable",
      severity="HIGH", owasp="A01:2021", cwe=["CWE-639"], evidence=evidence,
    )
    base.update(kwargs)
    return GrayboxFinding(**base).to_flat_finding(443, "https", "_graybox_ac")

  def test_identity_does_not_move_with_the_targets_response(self):
    """`access_control.py:979` puts the probed response length in its evidence."""
    a = self._finding(["path=/dash/; param=role=admin; baseline_len=1200; probed_len=1873"])
    b = self._finding(["path=/dash/; param=role=admin; baseline_len=1200; probed_len=1874"])
    self.assertEqual(
      a["finding_id"], b["finding_id"],
      "one byte of target response changed the finding's identity, so triage "
      "never sticks and the timeline never accumulates",
    )

  def test_identity_does_not_move_with_a_reflected_location_header(self):
    """`injection.py:506` embeds the target's `Location` response header."""
    a = self._finding(["endpoint=/go; param=next; location=https://evil.example/?sid=abc"])
    b = self._finding(["endpoint=/go; param=next; location=https://evil.example/?sid=xyz"])
    self.assertEqual(a["finding_id"], b["finding_id"])

  def test_no_real_composite_leaves_a_clause_tail_in_the_asset(self):
    """The composite shapes the four probes actually emit, verbatim."""
    for evidence in (
      "endpoint=/admin/users; denied_method=GET; accepted_method=PUT; status=200",
      "endpoint=/profile/edit; persisted_fields=is_admin,role",
      "endpoint=/api/records/7; field=owner_user_id; before='alice'; after='bob'",
      "path=/admin; status=200",
      "path=/dash/; param=role=admin; new_markers=['admin panel']; probed_len=1873",
      "endpoint=/checkout; submitted_amount=-9999.99; status=500",
      "endpoint=/go; param=next; location=https://evil.example/x",
      "endpoint=/api/login; field=password; variant={'$ne': None}; status=200",
    ):
      with self.subTest(evidence=evidence):
        url = self._finding([evidence])["affected_assets"][0]["url"]
        self.assertNotIn(";", url, f"the asset carries the whole clause: {url!r}")
        self.assertFalse(url.endswith(" "), f"untrimmed: {url!r}")

  def test_a_location_key_in_a_later_clause_is_found(self):
    """`business_logic.py:331` and `access_control.py:1122` do not lead with it."""
    flat = self._finding(["negative_amount_accepted=True; endpoint=/checkout"])
    self.assertEqual(flat["affected_assets"][0]["url"], "/checkout")

  def test_a_parameter_in_a_later_clause_becomes_the_parameter(self):
    flat = self._finding(["endpoint=/go; param=next; location=https://evil.example/x"])
    asset = flat["affected_assets"][0]
    self.assertEqual(asset["url"], "/go")
    self.assertEqual(asset["parameter"], "next")

  def test_two_parameters_on_one_endpoint_stay_distinct(self):
    """The parameter keys were dead, so these used to collapse."""
    a = self._finding(["endpoint=/search; param=q"])
    b = self._finding(["endpoint=/search; param=sort"])
    self.assertNotEqual(a["finding_id"], b["finding_id"])

  def test_a_clean_single_value_is_untouched(self):
    for evidence, expected in (
      ("endpoint=https://app.test/api/records/99", "https://app.test/api/records/99"),
      ("path=/admin/users", "/admin/users"),
      ("token_path=/api/token/", "/api/token/"),
    ):
      with self.subTest(evidence=evidence):
        self.assertEqual(
          self._finding([evidence])["affected_assets"][0]["url"], expected,
        )

  def test_an_explicit_url_still_wins_over_every_clause(self):
    flat = self._finding(
      ["endpoint=/from-evidence; status=200"], url="https://app.test/explicit",
    )
    self.assertEqual(flat["affected_assets"][0]["url"], "https://app.test/explicit")


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

  def test_a_cookie_bearing_curl_replay_survives_every_scrub_pass(self):
    """End to end, on the path that actually assembles a curl line.

    `_curl_reproduction` scrubs each header before quoting it, then the step is
    scrubbed again at emission and a third time at the storage boundary. A
    cookie rule that reads to end of line and does not recognise an
    already-redacted *prefix* eats the remaining headers, the URL and the
    closing quote — leaving a replay step that is neither runnable nor honest
    about being truncated. The unit-level idempotency test used bare headers,
    which is exactly the shape that does not catch it.
    """
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    probe._scrub_for_emission = ProbeBase._scrub_for_emission.__get__(probe)
    probe.target_config = None
    resp = self._response()
    resp.request.headers = {
      "Cookie": "theme=dark; sessionid=s3cr3tSESSIONVALUE",
      "Accept": "*/*",
    }
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"], response=resp,
    )
    finding = probe.findings[0]
    curl = next(step for step in finding.replay_steps if step.startswith("curl"))
    self.assertNotIn("s3cr3tSESSIONVALUE", curl)
    self.assertNotIn("theme=dark", curl)
    # The rest of the command is still there, and the quoting still balances.
    self.assertIn("Accept", curl)
    self.assertIn(resp.request.url, curl)
    self.assertEqual(curl.count("'") % 2, 0, f"unbalanced quoting: {curl}")

    # And the storage-boundary pass does not chew it further.
    flat = finding.to_flat_finding(443, "https", "_graybox_idor")
    self.assertIn(curl, flat["replay_steps"])

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

  def test_a_secret_straddling_the_truncation_boundary_is_still_redacted(self):
    """Truncating before scrubbing left half a key in the artifact.

    The snapshot is capped at 2048 chars. Cutting first meant a secret that
    began just before the cap survived as a prefix the pattern no longer
    matched — and the retained half of an API key is still an API key, now
    archived under a hash that certifies it as the evidence of record.
    """
    from extensions.business.cybersec.red_mesh.graybox.probes.base import (
      ProbeBase, _SNAPSHOT_MAX_CHARS,
    )
    probe = self._probe()
    probe._scrub_for_emission = ProbeBase._scrub_for_emission.__get__(probe)
    probe.target_config = None
    secret = "sk-live-abcdefghijklmnopqrstuvwx"
    # Land the secret so it begins inside the retained region and ends outside.
    prefix = "HTTP 200\nContent-Type: application/json\n\n"
    lead = " token="
    padding = "a" * (_SNAPSHOT_MAX_CHARS - len(prefix) - len(lead) - 20)
    body = f"{padding}{lead}{secret} trailing"
    # Precondition, not decoration: the first version of this test put only two
    # characters of the secret inside the retained region, so it passed against
    # the very bug it was written for. Prove the naive snapshot really would
    # have kept a usable prefix before asserting the real one does not.
    naive = (prefix + body)[:_SNAPSHOT_MAX_CHARS]
    self.assertIn(secret[:16], naive, "the fixture no longer straddles the cut")
    self.assertNotIn(secret, naive, "the fixture no longer straddles the cut")
    resp = self._response(body=body)
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"], response=resp,
    )
    snapshot = probe.findings[0].evidence_artifacts[0].response_snapshot
    self.assertLessEqual(len(snapshot), _SNAPSHOT_MAX_CHARS)
    # Any run of the secret long enough to be usable must be gone, not just the
    # whole string: the leak is the surviving prefix.
    for length in range(12, len(secret) + 1):
      self.assertNotIn(
        secret[:length], snapshot,
        f"a {length}-char prefix of the secret survived truncation",
      )

  def test_emitting_without_a_response_is_unchanged(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"],
    )
    self.assertEqual(probe.findings[0].evidence_artifacts, [])


class TestLocationFieldsAreScrubbed(unittest.TestCase):
  """`url` / `parameter` are the one pair a probe may set from raw target input.

  Every other location value is derived from evidence the scrubber has already
  been over. These two, and the `affected_assets` copy `to_flat_finding` makes
  of them, were registered with neither scrubbing boundary — so a userinfo
  credential in a URL was masked in the sibling `evidence` field and shipped
  intact in `url`, to the LLM, the archive, the PDF and the exports.
  """

  def _flat(self, *, secret_field_names=(), **kwargs):
    finding = GrayboxFinding(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021", **kwargs,
    )
    return finding.to_flat_finding(
      port=443, protocol="https", probe_name="_p",
      secret_field_names=secret_field_names,
    )

  def test_a_configured_secret_name_is_masked_in_the_location(self):
    """The generic patterns already cover `to_dict`; the configured names did not.

    `secret_field_names` is how an operator declares their own auth parameter,
    and it is applied at the storage boundary — which `affected_assets` was
    never registered with.
    """
    flat = self._flat(
      url="https://app.test/x?corp_key=SEKRET-VALUE-1",
      secret_field_names=("corp_key",),
    )
    self.assertNotIn("SEKRET-VALUE-1", flat["affected_assets"][0]["url"])

  def test_a_configured_secret_name_is_masked_in_the_parameter(self):
    flat = self._flat(
      url="https://app.test/x", parameter="corp_key=SEKRET-VALUE-1",
      secret_field_names=("corp_key",),
    )
    self.assertNotIn("SEKRET-VALUE-1", flat["affected_assets"][0]["parameter"])

  def test_an_ordinary_location_is_untouched(self):
    flat = self._flat(url="https://app.test/api/records/99", parameter="id")
    asset = flat["affected_assets"][0]
    self.assertEqual(asset["url"], "https://app.test/api/records/99")
    self.assertEqual(asset["parameter"], "id")


class TestCurlReproduction(unittest.TestCase):
  """
  A vulnerable finding should carry a command that reproduces it. The evidence
  artifact captures the triggering request, so the reproduction is derivable
  rather than something a probe author has to hand-write and keep in sync.

  Redaction matters more here than elsewhere: a curl line is *designed* to be
  copied and run, so an Authorization header left in it is a credential handed
  to whoever reads the report.
  """

  def _probe(self, real_scrub=False):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = ProbeBase.__new__(ProbeBase)
    probe.findings = []
    probe._resolve_attack = lambda scenario_id, attack: list(attack or [])
    if real_scrub:
      probe._scrub_for_emission = ProbeBase._scrub_for_emission.__get__(probe)
      probe.target_config = None
    else:
      probe._scrub_for_emission = lambda value: value
    return probe

  def _response(self, method="GET", headers=None, body=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "{}"
    resp.headers = {"Content-Type": "application/json"}
    resp.url = "https://app.test/api/records/99"
    resp.request = MagicMock()
    resp.request.method = method
    resp.request.url = "https://app.test/api/records/99"
    resp.request.headers = headers if headers is not None else {"Accept": "*/*"}
    resp.request.body = body
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.1
    return resp

  def _emit(self, probe=None, **response_kwargs):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = probe or self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/api/records/99"],
      response=self._response(**response_kwargs),
    )
    return probe.findings[0]

  def _curl(self, finding):
    return next(
      (step for step in finding.replay_steps if step.startswith("curl ")), None,
    )

  def test_a_vulnerable_finding_carries_a_curl_reproduction(self):
    curl = self._curl(self._emit())
    self.assertIsNotNone(curl, "no curl reproduction was generated")
    self.assertIn("https://app.test/api/records/99", curl)

  def test_the_method_and_body_are_reproduced(self):
    curl = self._curl(self._emit(method="POST", body='{"id": 99}'))
    self.assertIn("-X POST", curl)
    self.assertIn('{"id": 99}', curl)

  def test_a_get_does_not_carry_a_redundant_method_flag(self):
    self.assertNotIn("-X GET", self._curl(self._emit()))

  def test_the_credential_is_not_handed_to_the_reader(self):
    probe = self._probe(real_scrub=True)
    finding = self._emit(
      probe=probe,
      headers={"Authorization": "Bearer sk-live-abcdefghijklmnop"},
    )
    curl = self._curl(finding)
    self.assertNotIn("sk-live-abcdefghijklmnop", curl)

  def test_the_command_is_shell_safe(self):
    # A target-controlled URL must not be able to break out of the quoting and
    # become a second shell command in something a reader is invited to run.
    resp = self._response()
    resp.request.url = "https://app.test/x'; rm -rf /tmp/pwned; echo '"
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=x"], response=resp,
    )
    curl = self._curl(probe.findings[0])
    # Assert the real property rather than the escaping style: a shell parsing
    # this line recovers the URL as a single argument, and the injected text
    # never becomes a command of its own.
    import shlex
    tokens = shlex.split(curl)
    self.assertEqual(tokens[-1], resp.request.url)
    self.assertNotIn("rm", tokens)

  def test_redaction_cannot_reach_inside_the_quoting(self):
    """Scrubbing the assembled line let a substitution unbalance the quotes.

    A URL carrying both a quote character and a scrubber trigger came out as a
    line `shlex` could not parse at all. That failed closed — the reader gets a
    syntax error, not an extra command — but the reproduction was useless, and
    it stayed harmless only while no scrubber pattern produced something that
    re-parses. Scrubbing each component before quoting removes the class.
    """
    import shlex
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    for payload in (
      "https://app.test/x?token=A'&z=1;touch /tmp/pwned;echo ",
      "https://app.test/x?api_key=B';rm -rf /tmp/pwned;#",
      "https://app.test/x?password=C' Authorization: Bearer zzzzzzzzzz '",
    ):
      with self.subTest(url=payload):
        resp = self._response()
        resp.request.url = payload
        probe = self._probe(real_scrub=True)
        ProbeBase.emit_vulnerable(
          probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
          ["endpoint=x"], response=resp,
        )
        curl = self._curl(probe.findings[0])
        tokens = shlex.split(curl)  # raises if the quoting was corrupted
        self.assertEqual(tokens[0], "curl")
        for dangerous in ("rm", "touch"):
          self.assertNotIn(dangerous, tokens)

  def test_a_probes_own_replay_steps_are_kept(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=x"], replay_steps=["Log in as a regular user."],
      response=self._response(),
    )
    steps = probe.findings[0].replay_steps
    self.assertIn("Log in as a regular user.", steps)
    self.assertTrue(any(s.startswith("curl ") for s in steps))

  def test_no_response_means_no_curl(self):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = self._probe()
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"], ["endpoint=x"],
    )
    self.assertIsNone(self._curl(probe.findings[0]))


class TestEvidenceEnrichmentNeverLosesTheFinding(unittest.TestCase):
  """
  Evidence is supplementary; the finding is the product. If artifact or curl
  construction raises, `run_safe` swallows it and the probe emits **no finding
  at all** — the vulnerability is silently dropped because decorating it failed.

  Caught when wiring the probes: both helpers raised on a response whose
  attributes were not the expected types, which took out 17 tests and would have
  taken out real findings against any response shape they did not anticipate.
  """

  def _emit(self, response):
    from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
    probe = ProbeBase.__new__(ProbeBase)
    probe.findings = []
    probe._scrub_for_emission = lambda value: value
    probe._resolve_attack = lambda scenario_id, attack: list(attack or [])
    ProbeBase.emit_vulnerable(
      probe, "PT-A01-01", "IDOR", "HIGH", "A01:2021", ["CWE-639"],
      ["endpoint=https://app.test/x"], response=response,
    )
    return probe.findings

  def test_an_unusable_response_still_yields_the_finding(self):
    for label, response in (
      ("bare mock", MagicMock()),
      ("no request attribute", object()),
      ("string masquerading as a response", "not-a-response"),
      ("integer", 7),
    ):
      with self.subTest(response=label):
        findings = self._emit(response)
        self.assertEqual(
          len(findings), 1,
          "the finding was lost because its evidence could not be built",
        )
        self.assertEqual(findings[0].status, "vulnerable")

  def test_the_finding_keeps_its_own_content_when_evidence_fails(self):
    finding = self._emit(MagicMock())[0]
    self.assertEqual(finding.title, "IDOR")
    self.assertEqual(finding.url, "https://app.test/x")


class TestFindingReferenceUrls(unittest.TestCase):
  """
  A graybox finding carried an OWASP category and CWE ids but no reference URLs,
  and `to_flat_finding` emitted no `references` key at all — which the LLM input
  builder reads, alongside the PDF and the exports. A reader got "A01:2021" with
  nowhere to go.

  URL construction was already duplicated in three places (misp_export,
  stix_export, tls.py) in three slightly different forms, so this derives from
  the shared category table instead of adding a fourth copy.
  """

  def _finding(self, **kwargs):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
    base = dict(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021", cwe=["CWE-639"],
    )
    base.update(kwargs)
    return GrayboxFinding(**base)

  def test_the_owasp_url_is_the_canonical_one(self):
    from extensions.business.cybersec.red_mesh.references import reference_urls
    urls = reference_urls("A01:2021", ())
    self.assertIn("https://owasp.org/Top10/A01_2021-Broken_Access_Control/", urls)

  def test_the_cwe_url_is_the_canonical_one(self):
    from extensions.business.cybersec.red_mesh.references import reference_urls
    urls = reference_urls("", ["CWE-639"])
    self.assertIn("https://cwe.mitre.org/data/definitions/639.html", urls)

  def test_a_finding_carries_its_references(self):
    flat = self._finding().to_flat_finding(443, "https", "_graybox_idor")
    refs = flat.get("references")
    self.assertTrue(refs, "the flat finding carries no references")
    self.assertTrue(any("owasp.org" in r for r in refs))
    self.assertTrue(any("cwe.mitre.org/data/definitions/639" in r for r in refs))

  def test_multiple_cwes_each_get_a_url(self):
    flat = self._finding(cwe=["CWE-639", "CWE-862"]).to_flat_finding(
      443, "https", "_graybox_idor")
    refs = flat["references"]
    self.assertTrue(any("639.html" in r for r in refs))
    self.assertTrue(any("862.html" in r for r in refs))

  def test_unknown_or_absent_ids_produce_no_url(self):
    from extensions.business.cybersec.red_mesh.references import reference_urls
    self.assertEqual(reference_urls("", ()), [])
    self.assertEqual(reference_urls("A99:2021", ()), [])
    self.assertEqual(reference_urls("", ["not-a-cwe"]), [])

  def test_references_are_deduplicated_and_ordered(self):
    from extensions.business.cybersec.red_mesh.references import reference_urls
    urls = reference_urls("A01:2021", ["CWE-639", "CWE-639"])
    self.assertEqual(len(urls), len(set(urls)))
