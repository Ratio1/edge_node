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

  def test_a_stamped_finding_defers_to_the_shared_identity(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _compact_finding_signature,
    )
    finding = _finding()
    finding["finding_id"] = dedup_key(finding)
    self.assertEqual(_compact_finding_signature(finding), finding["finding_id"])


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
    stamped = {
      "title": "REDACTED after the fact",
      "severity": "HIGH",
      "confidence": "certain",
      "dedup_key": "0123456789abcdef",
      "content_hash": "f" * 64,
    }
    flat = self._flatten([stamped])[0]
    self.assertEqual(flat["dedup_key"], "0123456789abcdef")
    self.assertEqual(flat["content_hash"], "f" * 64)
    self.assertEqual(flat["finding_id"], "0123456789abcdef")

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
    self.assertEqual(flat["dedup_key"], "0123456789abcdef")
    self.assertEqual(flat["finding_id"], "0123456789abcdef")
    self.assertEqual(flat["content_hash"], "e" * 64)

  def test_re_flattening_a_redacted_finding_does_not_re_key_it(self):
    original = self._flatten([{
      "title": "Default credentials accepted: admin:hunter2",
      "severity": "HIGH", "confidence": "certain",
    }])[0]
    redacted = dict(original)
    redacted["title"] = "Default credentials accepted: admin:***"
    reflattened = self._flatten([redacted])[0]
    self.assertEqual(reflattened["dedup_key"], original["dedup_key"])
    self.assertEqual(reflattened["content_hash"], original["content_hash"])


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
      original["dedup_key"], reworded["dedup_key"],
      "a wording change gave the finding a new identity, so triage state and "
      "longitudinal tracking do not survive an edit to the description",
    )
    self.assertEqual(original["finding_id"], reworded["finding_id"])

  def test_rewording_a_finding_does_change_its_content_hash(self):
    """The other half of the contract: change detection still has to work."""
    self.assertNotEqual(
      self._flat("admin login accepted")["content_hash"],
      self._flat("admin login accepted (retested)")["content_hash"],
    )

  def test_the_probe_stamps_both_keys_rather_than_deriving_one(self):
    from extensions.business.cybersec.red_mesh.findings import Finding, probe_result

    stamped = probe_result(
      findings=[Finding(
        title="Weak TLS", description="", severity="MEDIUM", confidence="certain",
      )],
      probe_id="_service_info_ssl",
    )["findings"][0]
    self.assertTrue(stamped.get("dedup_key"), "no dedup key was stamped at probe time")
    self.assertTrue(stamped.get("finding_signature"))
    self.assertNotEqual(
      stamped["dedup_key"], stamped["finding_signature"][:16],
      "the dedup key is still the content hash wearing a different name",
    )


class TestTheCveMatcherStampsOneIdentityNotTwo(unittest.TestCase):
  """`asset_canonical` exists for exactly one caller, and it was not wired.

  The CVE matcher identifies a finding by `product:version:cve_id` rather than
  by an `AffectedAsset` — that override is why `dedup_key` accepts
  `asset_canonical` at all. `cve_db.py` passed it to `compute_signature` and
  nothing stamped a `dedup_key`, so `enrich_finding_for_probe` computed one from
  the *probe* name with no override.

  The result was a finding whose `finding_signature` was built over one identity
  basis and whose `dedup_key` was built over another — the "two identities for
  one finding, disagreeing, in the same dict" that `graybox/findings.py` writes
  a comment to prevent, and which falsifies `compute_signature`'s own docstring
  ("the finding's dedup key plus its presentation fields").
  """

  def _cve_finding(self):
    from extensions.business.cybersec.red_mesh.findings import Finding
    return Finding(
      title="CVE-2024-1234 in mysql 8.0.1",
      description="Remote code execution in mysql 8.0.1.",
      severity="HIGH", confidence="firm", cve=("CVE-2024-1234",),
    )

  def _stamped(self):
    """What `cve_db.build_cve_finding` produces, then enriched by the probe."""
    from extensions.business.cybersec.red_mesh.findings import (
      enrich_finding_for_probe,
    )
    finding = self._cve_finding()
    kwargs = {
      "probe_id": "cve:mysql",
      "asset_canonical": "mysql:8.0.1:CVE-2024-1234",
    }
    stamped = finding.with_identity(
      finding_signature=finding.compute_signature(**kwargs),
      dedup_key=finding.compute_dedup_key(**kwargs),
    )
    # The CVE finding is appended into a normal probe's findings list, so it
    # goes through the probe's enrichment on the way out.
    return enrich_finding_for_probe(stamped, "_service_info_mysql")

  def test_the_stamped_keys_share_one_identity_basis(self):
    enriched = self._stamped()
    expected = self._cve_finding().compute_dedup_key(
      probe_id="cve:mysql", asset_canonical="mysql:8.0.1:CVE-2024-1234",
    )
    self.assertEqual(
      enriched.dedup_key, expected,
      "the dedup key was recomputed from the probe name, so it no longer "
      "matches the basis the finding_signature was built over",
    )

  def test_the_probe_does_not_overwrite_a_stamped_cve_identity(self):
    self.assertEqual(self._stamped().finding_signature,
                     self._cve_finding().compute_signature(
                       probe_id="cve:mysql",
                       asset_canonical="mysql:8.0.1:CVE-2024-1234"))

  def test_the_same_cve_on_the_same_product_keeps_one_identity(self):
    self.assertEqual(self._stamped().dedup_key, self._stamped().dedup_key)

  def test_a_different_cve_on_the_same_product_is_a_different_finding(self):
    from extensions.business.cybersec.red_mesh.findings import Finding
    other = Finding(
      title="CVE-2024-9999 in mysql 8.0.1", description="d",
      severity="HIGH", confidence="firm",
    ).compute_dedup_key(
      probe_id="cve:mysql", asset_canonical="mysql:8.0.1:CVE-2024-9999",
    )
    self.assertNotEqual(self._stamped().dedup_key, other)


if __name__ == "__main__":
  unittest.main()
