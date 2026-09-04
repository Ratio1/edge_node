"""RM-062 B2: one identity model, documented.

Three competing keys coexisted, none of them documented as the identity:

  * `Finding.compute_signature` (64-hex), over probe + asset + title +
    description + severity;
  * `compute_flat_signature` in `mixins/risk.py`, over the same five parts read
    from a dict — a second implementation of the same idea, free to drift;
  * `_compact_finding_signature` in `mixins/report.py`, a whole-dict hash with an
    exclusion list.

Two problems follow. Free-text `description` is in the identity input, so a
reworded finding is a *different* finding — triage does not survive a wording
change, and longitudinal tracking breaks silently. And `_infer_calling_probe_id`
stack-walks for the probe name, returning `""` whenever a probe function is
renamed or wrapped, which changes the identity of every finding that probe
produces without anything failing.

The contract this file pins: a **dedup key** over probe + scenario + normalised
asset (including url and parameter) + classification, and a separate **content
hash** for change detection. Rewording moves the content hash and leaves the
dedup key alone.

Those are the *computations* (`models.finding_identity.dedup_key` /
`content_hash`). The persisted fields are `finding_id` and `finding_signature`
— one field per concept, no duplicate names.
"""

import unittest

from extensions.business.cybersec.red_mesh.models.finding_identity import (
  content_hash,
  dedup_key,
)


def _finding(**overrides):
  payload = {
    "probe": "_service_info_http",
    "scenario_id": "PT-A01-01",
    "title": "IDOR on /api/records",
    "description": "The endpoint returns another user's record.",
    "severity": "HIGH",
    "owasp_id": "A01:2021",
    "cwe_id": "CWE-639",
    "affected_assets": [{
      "host": "app.test", "port": 443,
      "url": "https://app.test/api/records/99",
      "parameter": "id", "method": "GET",
    }],
  }
  payload.update(overrides)
  return payload


class TestTheDedupKeyIdentifiesTheFindingNotItsWording(unittest.TestCase):

  def test_the_same_finding_twice_has_the_same_key(self):
    self.assertEqual(dedup_key(_finding()), dedup_key(_finding()))

  def test_rewording_the_description_does_not_fork_identity(self):
    """The defect this replaces: `description` was in the signature input.

    Any edit to a probe's wording made every finding it had ever produced a new
    finding — triage lost, history broken, and nothing anywhere reported it.
    """
    self.assertEqual(
      dedup_key(_finding()),
      dedup_key(_finding(description="Another user's record is returned.")),
    )

  def test_rewording_the_title_does_not_fork_identity(self):
    self.assertEqual(
      dedup_key(_finding()),
      dedup_key(_finding(title="Insecure direct object reference")),
    )

  def test_a_different_endpoint_is_a_different_finding(self):
    other = _finding(affected_assets=[{
      "host": "app.test", "port": 443,
      "url": "https://app.test/api/invoices/7",
      "parameter": "id", "method": "GET",
    }])
    self.assertNotEqual(dedup_key(_finding()), dedup_key(other))

  def test_a_different_parameter_at_the_same_url_is_a_different_finding(self):
    other = _finding(affected_assets=[{
      "host": "app.test", "port": 443,
      "url": "https://app.test/api/records/99",
      "parameter": "owner", "method": "GET",
    }])
    self.assertNotEqual(dedup_key(_finding()), dedup_key(other))

  def test_a_different_scenario_at_the_same_endpoint_is_a_different_finding(self):
    self.assertNotEqual(
      dedup_key(_finding()), dedup_key(_finding(scenario_id="PT-A01-05")),
    )

  def test_asset_order_does_not_change_the_key(self):
    assets = _finding()["affected_assets"] + [{
      "host": "app.test", "port": 443, "url": "https://app.test/b",
      "parameter": "", "method": "GET",
    }]
    self.assertEqual(
      dedup_key(_finding(affected_assets=assets)),
      dedup_key(_finding(affected_assets=list(reversed(assets)))),
    )

  def test_a_finding_with_no_asset_still_gets_a_stable_key(self):
    bare = _finding(affected_assets=[])
    self.assertEqual(dedup_key(bare), dedup_key(_finding(affected_assets=[])))
    self.assertNotEqual(dedup_key(bare), dedup_key(_finding()))

  def test_cwe_order_does_not_change_the_key(self):
    # NVD lists multiple CWEs in either order; they classify the same weakness.
    self.assertEqual(
      dedup_key(_finding(cwe_id="CWE-639, CWE-862")),
      dedup_key(_finding(cwe_id="CWE-862, CWE-639")),
    )

  def test_a_different_cwe_set_is_a_different_finding(self):
    self.assertNotEqual(
      dedup_key(_finding(cwe_id="CWE-639")),
      dedup_key(_finding(cwe_id="CWE-79")),
    )

  def test_an_absent_probe_does_not_silently_collide_with_a_named_one(self):
    """`_infer_calling_probe_id` returns `""` on any probe-naming change.

    Every finding whose probe could not be inferred then shared the same empty
    probe component, so two unrelated findings could collide on identity — and
    a rename silently re-identified everything that probe had ever produced.
    """
    self.assertNotEqual(dedup_key(_finding()), dedup_key(_finding(probe="")))


class TestTheTitleFallbackForLocationlessFindings(unittest.TestCase):
  """Blackbox probes do not attach url/parameter yet — RM-061 owns that.

  Until they do, two genuinely different findings from one probe on one port
  differ in nothing but their titles: same CWE, same severity, same synthesised
  `{host, port}` asset. Dropping the title from identity unconditionally merges
  them, which loses a finding — a worse failure than the wording-fork it avoids.
  """

  def _locationless(self, title):
    return {
      "probe": "_web_test_xss",
      "title": title,
      "severity": "HIGH",
      "cwe_id": "CWE-79",
      "affected_assets": [{"host": "app.test", "port": 80}],
    }

  def test_two_locationless_findings_with_different_titles_stay_distinct(self):
    self.assertNotEqual(
      dedup_key(self._locationless("Reflected XSS in search")),
      dedup_key(self._locationless("Stored XSS in comment")),
    )

  def test_the_synthesised_host_asset_is_not_mistaken_for_a_location(self):
    """`affected_assets` being non-empty says nothing: the blackbox producer
    synthesises `{host, port}` for every finding it emits."""
    from extensions.business.cybersec.red_mesh.models.finding_identity import (
      _has_specific_location,
    )
    self.assertFalse(_has_specific_location([{"host": "app.test", "port": 80}]))
    self.assertTrue(_has_specific_location([{"host": "app.test", "url": "/x"}]))
    self.assertTrue(_has_specific_location([{"host": "app.test", "parameter": "q"}]))

  def test_a_located_finding_does_not_use_the_fallback(self):
    located = dict(self._locationless("Reflected XSS in search"))
    located["affected_assets"] = [{"host": "app.test", "port": 80, "url": "/search",
                                   "parameter": "q"}]
    reworded = dict(located)
    reworded["title"] = "XSS via the search parameter"
    self.assertEqual(dedup_key(located), dedup_key(reworded))

  def test_a_scenario_id_alone_is_enough_to_drop_the_fallback(self):
    with_scenario = dict(self._locationless("Reflected XSS in search"))
    with_scenario["scenario_id"] = "PT-A03-01"
    reworded = dict(with_scenario)
    reworded["title"] = "XSS via the search parameter"
    self.assertEqual(dedup_key(with_scenario), dedup_key(reworded))


class TestTheContentHashTracksChange(unittest.TestCase):

  def test_the_same_finding_twice_hashes_the_same(self):
    self.assertEqual(content_hash(_finding()), content_hash(_finding()))

  def test_rewording_moves_the_content_hash(self):
    """The other half of the split: wording changes are *detectable*, just not
    identity-forming. A reader wanting "did this finding change?" asks the
    content hash; a reader wanting "is this the same finding?" asks the key.
    """
    self.assertNotEqual(
      content_hash(_finding()),
      content_hash(_finding(description="Another user's record is returned.")),
    )

  def test_a_severity_change_moves_the_content_hash(self):
    self.assertNotEqual(
      content_hash(_finding()), content_hash(_finding(severity="CRITICAL")),
    )

  def test_worker_attribution_does_not_move_the_content_hash(self):
    """Per-worker custody fields vary across nodes for one underlying finding.

    `_stamp_worker_source` adds them after the fact; including them would make
    the same finding seen from two vantages look like two different findings.
    """
    self.assertEqual(
      content_hash(_finding()),
      content_hash(_finding(
        worker_source="0xabc", observed_at="2026-09-01T00:00:00Z",
        node_ip="203.0.113.9",
      )),
    )

  def test_the_key_and_the_hash_are_different_values(self):
    finding = _finding()
    self.assertNotEqual(dedup_key(finding), content_hash(finding))


class TestBothHalvesOfTheScannerAgree(unittest.TestCase):
  """One implementation, not one per producer.

  `Finding.compute_signature` and `compute_flat_signature` were two
  implementations of the same idea, free to drift — and they did: one read
  `self.severity.value`, the other a raw string.
  """

  def test_a_graybox_flat_finding_and_its_blackbox_shaped_twin_key_the_same(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding

    flat = GrayboxFinding(
      scenario_id="PT-A01-01", title="IDOR on /api/records",
      status="vulnerable", severity="HIGH", owasp="A01:2021", cwe=["CWE-639"],
      url="https://app.test/api/records/99", parameter="id", method="GET",
    ).to_flat_finding(port=443, protocol="https", probe_name="_service_info_http")

    self.assertEqual(dedup_key(flat), dedup_key(_finding()))


class TestCrossWorkerDedupInTheReportLayer(unittest.TestCase):
  """`_compact_finding_signature` is the third implementation, used as a
  fallback when a finding carries no stamped identity.

  Its exclusion list held two private keys and none of the worker-attribution
  fields `_stamp_worker_source` adds *before* it runs — so the same finding
  observed from two nodes hashed differently, and cross-worker dedup, the one
  thing this signature exists to do, did not happen for unstamped findings.
  """

  def _same_finding_from(self, node):
    return {
      "title": "Weak TLS",
      "severity": "MEDIUM",
      "cwe_id": "CWE-326",
      "worker_source": node,
      "node_ip": f"203.0.113.{len(node)}",
      "observed_at": f"2026-09-01T00:00:0{len(node)}Z",
      "_source_worker_id": node,
    }

  def test_one_finding_seen_from_two_nodes_deduplicates(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _compact_finding_signature,
    )
    self.assertEqual(
      _compact_finding_signature(self._same_finding_from("0xaa")),
      _compact_finding_signature(self._same_finding_from("0xbbbb")),
    )

  def test_two_different_findings_still_do_not_deduplicate(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _compact_finding_signature,
    )
    other = self._same_finding_from("0xaa")
    other["title"] = "Expired certificate"
    self.assertNotEqual(
      _compact_finding_signature(self._same_finding_from("0xaa")),
      _compact_finding_signature(other),
    )

  def test_a_stamped_finding_defers_to_its_content_signature(self):
    """`_compact_finding_signature` is a content signature, so it must never
    fall back to `finding_id`: the id is identity-derived and coarse, and two
    content-distinct findings sharing it would collapse into one "finding
    type" in the per-worker counts."""
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _compact_finding_signature,
    )
    finding = _finding()
    finding["finding_id"] = dedup_key(finding)
    finding["content_hash"] = content_hash(finding)
    self.assertEqual(_compact_finding_signature(finding), finding["content_hash"])
    self.assertNotEqual(_compact_finding_signature(finding), finding["finding_id"])


class TestIdentitySurvivesRedaction(unittest.TestCase):
  """Identity is computed pre-redaction and cannot be re-derived after it.

  The report layer rewrites `title`, `description`, `evidence`, `url` and
  `parameter` — every field either hash is over. A consumer that recomputed
  identity from the stored finding would get a different value for the same
  finding and read it as a new one, so the producer stamps once and everything
  downstream carries what it was given.
  """

  def _flatten(self, findings):
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    _risk, flat = MockHost()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": findings}}},
    })
    return flat

  def test_an_already_stamped_finding_keeps_its_identity(self):
    # The legacy field names, as a pre-collapse archive entry carries them:
    # honoured as the identity, resolved to the surviving names, and not
    # re-persisted under the old ones.
    stamped = {
      "title": "REDACTED after the fact",
      "severity": "HIGH",
      "confidence": "certain",
      "dedup_key": "0123456789abcdef",
      "content_hash": "f" * 64,
    }
    flat = self._flatten([stamped])[0]
    self.assertEqual(flat["finding_id"], "0123456789abcdef")
    self.assertEqual(flat["finding_signature"], "f" * 64)
    self.assertNotIn("dedup_key", flat)
    self.assertNotIn("content_hash", flat)

  def test_a_blackbox_finding_keeps_its_id_across_the_redaction_boundary(self):
    """The walk runs on both sides of `_redact_report` depending on the caller.

    `services/finalization.py` flattens before redaction; the manual-analysis
    path in `pentester_api_01.py` flattens after it. Anything derived from the
    item in hand therefore differs between them — and for a locationless
    blackbox finding the dedup key falls back to the title, which is exactly
    what redaction rewrites. The probe-time signature is carried instead.
    """
    import copy
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )

    stamped = probe_result(
      findings=[Finding(
        severity=Severity.HIGH,
        title="Default credentials accepted: admin:hunter2",
        description="d",
      )],
      probe_id="_service_info_http",
    )

    def flatten(probe_output):
      from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

      class MockHost(_RiskScoringMixin):
        pass

      _risk, flat = MockHost()._compute_risk_and_findings({
        "target": "app.test",
        "port_protocols": {"443": "https"},
        "service_info": {"443": {"_service_info_http": probe_output}},
      })
      return flat[0]

    before = flatten(copy.deepcopy(stamped))
    redacted = copy.deepcopy(stamped)
    # What `_redact_report` does: rewrite the text, leave the signature alone.
    redacted["findings"][0]["title"] = "Default credentials accepted: admin:***"
    after = flatten(redacted)

    self.assertEqual(
      before["finding_id"], after["finding_id"],
      "the same finding got two ids depending on which side of redaction it "
      "was flattened on",
    )
    self.assertEqual(before["finding_signature"], after["finding_signature"])

  def test_a_persisted_graybox_finding_keeps_the_identity_it_was_stamped_with(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding

    persisted = {
      "scenario_id": "PT-A01-01", "title": "IDOR", "status": "vulnerable",
      "severity": "HIGH", "owasp": "A01:2021",
      "url": "https://app.test/api/records/99",
      "dedup_key": "0123456789abcdef", "content_hash": "e" * 64,
    }
    flat = GrayboxFinding.flat_from_dict(
      persisted, port=443, protocol="https", probe_name="_graybox_access_control",
    )
    self.assertEqual(flat["finding_id"], "0123456789abcdef")
    self.assertEqual(flat["finding_signature"], "e" * 64)

  def test_re_flattening_a_redacted_finding_does_not_re_key_it(self):
    original = self._flatten([{
      "title": "Default credentials accepted: admin:hunter2",
      "severity": "HIGH", "confidence": "certain",
    }])[0]
    redacted = dict(original)
    redacted["title"] = "Default credentials accepted: admin:***"
    reflattened = self._flatten([redacted])[0]
    self.assertEqual(reflattened["finding_id"], original["finding_id"])
    self.assertEqual(reflattened["finding_signature"], original["finding_signature"])


class TestRewordingSurvivesTheRealBlackboxPath(unittest.TestCase):
  """The redaction-invariance fix reintroduced the defect B2 exists to remove.

  Carrying the probe-time `finding_signature` made identity stable across
  `_redact_report` — but `dedup_key` was then *derived* from it, as its first 16
  characters, and `finding_signature` is the **content** hash. Identity became
  content-addressed again by another route, and only on the path that ships:
  `probe_result` calls `enrich_finding_for_probe`, which stamps
  `finding_signature` and no `dedup_key`.

  The existing B2 tests miss it because they build finding dicts directly, and
  an unstamped dict takes the `_dedup_key(item)` branch — the correct one. Every
  blackbox finding a real probe produces takes the other branch.

  Measured: rewording one description moved `finding_id` from
  `e038552a47fe4deb` to `d07c5b6427f578b1`. Both keys must be stamped at probe
  time, independently of each other.
  """

  def _flat(self, description):
    from extensions.business.cybersec.red_mesh.findings import Finding, probe_result
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    result = probe_result(
      findings=[Finding(
        title="Default credentials accepted", severity="HIGH",
        confidence="certain", description=description,
      )],
      probe_id="_service_info_http",
    )
    _risk, flat = MockHost()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": result}},
    })
    return flat[0]

  def test_rewording_a_finding_does_not_change_its_identity(self):
    original = self._flat("admin login accepted")
    reworded = self._flat("admin login accepted (retested)")
    self.assertEqual(
      original["finding_id"], reworded["finding_id"],
      "a wording change gave the finding a new identity, so triage state and "
      "longitudinal tracking do not survive an edit to the description",
    )
    self.assertEqual(original["finding_id"], reworded["finding_id"])

  def test_rewording_a_finding_does_change_its_content_hash(self):
    """The other half of the contract: change detection still has to work."""
    self.assertNotEqual(
      self._flat("admin login accepted")["finding_signature"],
      self._flat("admin login accepted (retested)")["finding_signature"],
    )

  def test_the_probe_stamps_both_keys_rather_than_deriving_one(self):
    from extensions.business.cybersec.red_mesh.findings import Finding, probe_result

    stamped = probe_result(
      findings=[Finding(
        title="Weak TLS", description="", severity="MEDIUM", confidence="certain",
      )],
      probe_id="_service_info_ssl",
    )["findings"][0]
    self.assertTrue(stamped.get("finding_id"), "no identity key was stamped at probe time")
    self.assertTrue(stamped.get("finding_signature"))
    self.assertNotEqual(
      stamped["finding_id"], stamped["finding_signature"][:16],
      "the dedup key is still the content hash wearing a different name",
    )


class TestTheCveMatcherStampsOneIdentityNotTwo(unittest.TestCase):
  """`asset_canonical` exists for exactly one caller, and it was not wired.

  The CVE matcher identifies a finding by `product:version:cve_id` rather than
  by an `AffectedAsset` — that override is why `dedup_key` accepts
  `asset_canonical` at all. `cve_db` passed it to `compute_signature` and
  nothing stamped a `dedup_key`, so `enrich_finding_for_probe` computed one from
  the *probe* name with no override. The result was a finding whose
  `finding_signature` was built over one identity basis and whose `dedup_key`
  was built over another — the "two identities for one finding, disagreeing, in
  the same dict" that `graybox/findings.py` writes a comment to prevent.

  The first version of this test built the stamped finding itself, by calling
  `with_identity` inline. That made it a reimplementation of the production
  code rather than a test of it: deleting the `dedup_key=` argument from
  `cve_db` left all 2319 tests green. It now goes through `check_cves`, the
  function the probes actually call.
  """

  PRODUCT = "openssh"
  VERSION = "7.0"

  def _from_production(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves

    findings = check_cves(self.PRODUCT, self.VERSION)
    self.assertTrue(findings, "fixture no longer matches any CVE row")
    return findings

  def test_the_matcher_stamps_a_dedup_key_at_all(self):
    for finding in self._from_production():
      self.assertTrue(
        finding.finding_id,
        "check_cves emitted a finding with no dedup key, so identity would be "
        "recomputed downstream from the probe name",
      )

  def test_both_keys_are_built_over_the_same_identity_basis(self):
    for finding in self._from_production():
      cve_id = finding.cve[0]
      expected = finding.compute_dedup_key(
        probe_id=f"cve:{self.PRODUCT}",
        asset_canonical=f"{self.PRODUCT}:{self.VERSION}:{cve_id}",
      )
      self.assertEqual(finding.finding_id, expected)

  def test_the_probe_does_not_overwrite_the_stamped_identity(self):
    from extensions.business.cybersec.red_mesh.findings import (
      enrich_finding_for_probe,
    )
    for finding in self._from_production():
      enriched = enrich_finding_for_probe(finding, "_service_info_ssh")
      self.assertEqual(enriched.finding_id, finding.finding_id)
      self.assertEqual(enriched.finding_signature, finding.finding_signature)

  def test_each_cve_gets_its_own_identity(self):
    findings = self._from_production()
    self.assertEqual(len({f.finding_id for f in findings}), len(findings))


class TestTwoIdentityFieldsNotFour(unittest.TestCase):
  """Phase 5b: `finding_id` (identity) and `finding_signature` (content) are
  the only persisted identity fields.

  Every finding used to carry four — `dedup_key`/`content_hash` existed solely
  to derive the other two, and two names for one concept is how "two identities
  for one finding, disagreeing in the same dict" happened twice on this branch
  (the cve_db stamp, and carried-vs-recomputed). A single field cannot disagree
  with itself. The *functions* stay in `models/finding_identity.py`; the
  persisted duplicates go.
  """

  def _blackbox_flat(self):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    result = probe_result(
      findings=[Finding(
        severity=Severity.MEDIUM, title="Weak TLS", description="d",
        confidence="certain",
      )],
      probe_id="_service_info_ssl",
    )
    return MockHost()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_ssl": result}},
    })[1][0]

  def test_a_new_blackbox_finding_carries_exactly_the_two(self):
    flat = self._blackbox_flat()
    self.assertNotIn("dedup_key", flat)
    self.assertNotIn("content_hash", flat)
    self.assertTrue(flat["finding_id"])
    self.assertTrue(flat["finding_signature"])
    self.assertNotEqual(flat["finding_id"], flat["finding_signature"])

  def test_a_new_graybox_finding_carries_exactly_the_two(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding

    flat = GrayboxFinding(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021", url="https://app.test/x",
    ).to_flat_finding(port=443, protocol="https", probe_name="_graybox_access_control")
    self.assertNotIn("dedup_key", flat)
    self.assertNotIn("content_hash", flat)
    self.assertTrue(flat["finding_id"])
    self.assertTrue(flat["finding_signature"])

  def test_an_old_archive_entry_with_only_the_legacy_names_still_resolves(self):
    """Archives written before the collapse carry `dedup_key`/`content_hash`;
    identity must come from them, never be recomputed from redacted fields."""
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding

    persisted = {
      "scenario_id": "PT-A01-01", "title": "IDOR", "status": "vulnerable",
      "severity": "HIGH", "owasp": "A01:2021",
      "url": "https://app.test/api/records/99",
      "dedup_key": "0123456789abcdef", "content_hash": "e" * 64,
    }
    flat = GrayboxFinding.flat_from_dict(
      persisted, port=443, protocol="https", probe_name="_graybox_access_control",
    )
    self.assertEqual(flat["finding_id"], "0123456789abcdef")
    self.assertEqual(flat["finding_signature"], "e" * 64)

  def test_the_cve_matcher_stamps_finding_id_over_its_own_basis(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves

    findings = check_cves("openssh", "7.0")
    self.assertTrue(findings)
    for finding in findings:
      cve_id = finding.cve[0]
      self.assertEqual(
        finding.finding_id,
        finding.compute_dedup_key(
          probe_id="cve:openssh",
          asset_canonical=f"openssh:7.0:{cve_id}",
        ),
      )


class TestStampedAndRawRepresentationsShareIdentity(unittest.TestCase):
  """A synthesised `{host, port}` asset must not contribute to identity.

  Identity is stamped at probe time over `affected_assets = ()`; the flat walk
  then synthesises `[{host, port}]` for raw dicts before computing its
  fallback. The synthesised asset carried no location but still fed
  `canonical_asset_string`, so the same finding arriving stamped (empty assets)
  and raw (synthesised asset) got different keys — and the two representations
  of one finding never deduplicated against each other. A host/port-only asset
  is not a location; `_has_specific_location` already draws that line.
  """

  def _both(self):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    stamped = probe_result(
      findings=[Finding(
        severity=Severity.MEDIUM, title="Weak TLS", description="d",
        confidence="certain",
      )],
      probe_id="_service_info_http",
    )["findings"][0]
    # Classification matches what `enrich_finding_for_probe` stamps from the
    # registry: classification is legitimately part of identity, so an
    # UNclassified raw dict is a different identity than its enriched twin —
    # that residual asymmetry is documented in RM-062, not papered over here.
    # This pair isolates the asset half: same classification, and the only
    # remaining difference is the synthesised `{host, port}` asset.
    raw = {"title": "Weak TLS", "description": "d", "severity": "MEDIUM",
           "confidence": "certain", "owasp_id": "A05:2021", "cwe_id": "CWE-200"}
    return MockHost()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [stamped, raw]}}},
    })

  def test_the_two_representations_share_one_identity(self):
    _risk, flat = self._both()
    self.assertEqual(len({f["finding_id"] for f in flat}), 1)

  def test_the_shared_identity_is_reported_as_a_collision(self):
    """Content dedup still keeps both — enrichment adds real content (registry
    CVSS template, references) to the stamped twin, so their signatures differ
    and merging them would discard content. What the identity fix guarantees is
    that the pair now *shares an id*, so triage resolves both and the overlap
    is visible in `identity_collisions` instead of silently splitting."""
    risk, flat = self._both()
    self.assertEqual(len(flat), 2)
    self.assertEqual(risk["breakdown"]["identity_collisions"]["count"], 2)

  def test_a_real_location_still_separates_findings(self):
    """The control — dropping synthesised assets from the canonical string must
    not merge findings at genuinely different locations."""
    from extensions.business.cybersec.red_mesh.models.finding_identity import (
      dedup_key as compute,
    )
    at_a = {"probe": "_p", "title": "t", "cwe_id": "CWE-79",
            "affected_assets": [{"host": "h", "port": 443, "url": "/a"}]}
    at_b = {"probe": "_p", "title": "t", "cwe_id": "CWE-79",
            "affected_assets": [{"host": "h", "port": 443, "url": "/b"}]}
    self.assertNotEqual(compute(at_a), compute(at_b))


if __name__ == "__main__":
  unittest.main()


class TestTheThreeKeysAgreeAboutWhatMoves(unittest.TestCase):
  """There are three keys over a finding and they do not hash the same fields.
  That asymmetry has now caused two defects — reasoning about `content_hash`
  and forgetting `report._finding_dedup_key`:

  - `description` was believed not to affect identity, so per-scan counts were
    moved into it. The report key hashes it, so they still forked cross-worker.
  - `evidence_items` was believed to be a safe unhashed channel. Same reason.

  This pins the classification instead of leaving it to be rediscovered. A new
  `Finding` field lands in one of the buckets below and the test says which.
  """

  def _keys(self, finding):
    from extensions.business.cybersec.red_mesh.mixins.report import _finding_dedup_key
    return (dedup_key(finding), content_hash(finding), _finding_dedup_key(finding))

  def _moves(self, field, value):
    base = _finding(title="T", description="d", evidence="e")
    other = dict(base)
    other[field] = value
    a, b = self._keys(base), self._keys(other)
    return tuple(x != y for x, y in zip(a, b))

  def test_a_field_the_content_hash_ignores_because_it_moves_is_ignored_everywhere(self):
    """`cvss_data_freshness` is a fetch timestamp. `_CONTENT_FIELDS` excludes it
    so two workers whose NVD lookups straddle a second still collapse. The
    report layer's whole-dict key hashed it anyway until 2026-09-04, so the
    fork the exclusion exists to prevent happened one path over."""
    identity, content, report = self._moves("cvss_data_freshness", "2027-01-01T00:00:00Z")
    self.assertFalse(identity, "a fetch timestamp must not touch identity")
    self.assertFalse(content, "a fetch timestamp must not touch the content hash")
    self.assertFalse(report, "a fetch timestamp must not touch the report key")

  def test_fields_the_content_hash_ignores_because_they_are_untracked_still_key_the_report(self):
    """The other side of the distinction. Most fields absent from
    `_CONTENT_FIELDS` are simply not tracked for change detection; they are
    still content for "is this the same finding", so the report key should hash
    them. Only the *moving* ones get excluded everywhere."""
    for field, value in (("impact", "ZZZ"), ("tags", ["z"]), ("steps_to_reproduce", "ZZZ")):
      identity, content, report = self._moves(field, value)
      self.assertFalse(content, f"{field} unexpectedly entered the content hash")
      self.assertTrue(report, f"{field} should still distinguish two findings")

  def test_the_report_key_hashes_everything_the_content_hash_does(self):
    """The containment that makes the classification a hierarchy rather than
    two unrelated lists: anything that is content is also report-content."""
    checked = (("title", "ZZZ"), ("description", "ZZZ"), ("evidence", "ZZZ"),
               ("severity", "LOW"), ("confidence", "tentative"),
               ("remediation", "ZZZ"), ("kev", True))
    moved_content = 0
    for field, value in checked:
      _identity, content, report = self._moves(field, value)
      if content:
        moved_content += 1
        self.assertTrue(
          report, f"{field} moves the content hash but not the report key",
        )
    # Without this the assertion above is `if False`, and the whole test passes
    # the moment `_CONTENT_FIELDS` shrinks — which is exactly when the
    # containment claim would stop being true.
    self.assertEqual(
      moved_content, len(checked),
      "a field that used to be content no longer is; this test cannot make its "
      "containment claim about fields the content hash has stopped hashing",
    )
