"""
Risk scoring mixin for RedMesh pentester API.

Pure computation — takes aggregated scan reports and produces risk scores
(0-100) with breakdowns and flat findings lists. No CStore or R1FS access.
"""

import math

from ..models.finding_schema import (
  COVERAGE_STATUSES,
  REDMESH_FINDING_SCHEMA,
  REDMESH_FINDING_SCHEMA_VERSION,
  is_coverage_result as _is_coverage_result,
  normalize_confidence as _normalize_confidence,
  validate_flat_finding as _validate_flat_finding,
)
from ..models.finding_identity import (
  content_hash as _content_hash,
  dedup_key as _dedup_key,
  parse_cwe_list as _parse_cwe_list,
)
from ..constants import (
  RISK_SEVERITY_WEIGHTS,
  RISK_CONFIDENCE_MULTIPLIERS,
  RISK_RAW_TOTAL_CEILING,
  RISK_CRED_PENALTY_PER,
  RISK_CRED_PENALTY_CAP,
)


def normalize_risk_score(raw_total):
  """
  Map a raw risk total onto 0-100 without saturating.

  The previous logistic curve (`100 * (2/(1+e^-0.02x) - 1)`) reached 100 once
  `raw_total` passed roughly 300 — about eight CRITICAL findings — and
  `raw_total` grows linearly with finding count, so any substantial scan pinned
  at the ceiling. Measured on three real archived runs: a 46-finding blackbox
  run (raw 609), the client job (raw 1123) and a 600-finding run (raw 9007) all
  scored exactly 100. A remediation cycle could remove hundreds of findings
  without moving the number, which is the one thing a risk score has to do.

  Log compression keeps the curve monotonic across orders of magnitude and
  anchors the low end close to where it was — a single CRITICAL finding scores
  37 here against 38 before — while separating the cases that used to collide:
  those same three runs now score 65, 71 and 92.

  This is a customer-visible change in the mid range: four CRITICAL findings
  previously scored 92 and now score 51. That is the cost of a curve that can
  still rise afterwards, and it is deliberate.
  """
  try:
    raw_total = float(raw_total)
  except (TypeError, ValueError):
    return 0
  # NaN survives float() and compares False against every bound, so it would
  # reach int(round(...)) and raise. Infinity is clamped by the min() below,
  # but NaN has no meaningful score.
  if not math.isfinite(raw_total) or raw_total <= 0:
    return 0
  ratio = math.log10(1.0 + raw_total) / math.log10(1.0 + RISK_RAW_TOTAL_CEILING)
  return max(0, min(100, int(round(100.0 * ratio))))


class _RiskScoringMixin:
  """Risk scoring and findings extraction methods for PentesterApi01Plugin."""

  def _compute_risk_and_findings(self, aggregated_report):
    """
    Compute risk score AND extract flat findings in a single walk.

    The single scoring implementation. A second copy, `_compute_risk_score`,
    existed with no non-test caller and had already drifted: it received the
    confidence normalisation but not the coverage exclusion, so the two answered
    differently for the same report. That is exactly how the four signature
    implementations drifted, so it was deleted rather than kept in step.

    Parameters
    ----------
    aggregated_report : dict
      Aggregated report with service_info, web_tests_info, etc.

    Returns
    -------
    tuple[dict, list]
      (risk_result, flat_findings) where risk_result is {"score": int, "breakdown": dict}
      and flat_findings is a list of enriched finding dicts.
    """
    import math

    flat_findings = []
    schema_violations = []

    port_protocols = aggregated_report.get("port_protocols") or {}
    target = (
      aggregated_report.get("target")
      or aggregated_report.get("target_url")
      or aggregated_report.get("host")
      or ""
    )

    def process_findings(findings_list, port, probe_name, category):
      # Production only. This walk used to score as it produced, in parallel
      # with a post-dedup recount — three copies of one loop, and their drift
      # caused real defects twice (coverage rescored after dedup; a padded
      # confidence scoring 0.5 here and 1.0 there). Scoring now happens exactly
      # once, after dedup, over `flat_findings`.
      for finding in findings_list:
        if not isinstance(finding, dict):
          continue
        protocol = port_protocols.get(str(port), "unknown")
        flat_findings.append(
          normalize_flat_finding(finding, port, protocol, probe_name, category)
        )

    def normalize_flat_finding(finding, port, protocol, probe_name, category):
      item = {k: v for k, v in finding.items()}
      normalized_confidence, recognised = _normalize_confidence(
        item.get("confidence", "firm"),
      )
      if not recognised and item.get("confidence"):
        # Keep the raw value rather than overwriting it silently: a probe's typo
        # should be visible to whoever has to fix the probe.
        item["declared_confidence"] = item["confidence"]
      item["confidence"] = normalized_confidence
      item.setdefault("declared_severity", str(item.get("severity") or "INFO").upper())
      # The same stamp the graybox producer applies. A consumer reads
      # `PassReport.findings` without knowing which half of the scanner wrote
      # each entry, so the contract has to be declared by both or by neither.
      item.setdefault("schema", REDMESH_FINDING_SCHEMA)
      item.setdefault("schema_version", REDMESH_FINDING_SCHEMA_VERSION)
      cwe_values = tuple(
        _parse_cwe_list(item.get("cwe"))
        if isinstance(item.get("cwe"), (list, tuple)) else ()
      )
      if not cwe_values:
        # The joined form, not just its first entry. The parser this replaced
        # stripped one `CWE-` prefix and called `int()` on `"639, CWE-862"`,
        # which fails — so a multi-CWE finding normalised to nothing at all.
        cwe_values = tuple(_parse_cwe_list(item.get("cwe_id")))
      if cwe_values and not item.get("cwe"):
        item["cwe"] = list(cwe_values)
      if cwe_values and not item.get("cwe_id"):
        # Every value, matching the graybox producer's joined form. Printing
        # only `cwe_values[0]` meant a finding classified under three weaknesses
        # displayed one, with no sign the others existed.
        item["cwe_id"] = ", ".join(f"CWE-{value}" for value in cwe_values)

      owasp_values = normalize_string_list(item.get("owasp_top10"))
      if not owasp_values and item.get("owasp_id"):
        owasp_values = (str(item["owasp_id"]),)
      if owasp_values and not item.get("owasp_top10"):
        item["owasp_top10"] = list(owasp_values)
      if owasp_values and not item.get("owasp_id"):
        item["owasp_id"] = owasp_values[0]

      # The LLM input builder reads `evidence_items` and deliberately drops the
      # legacy `evidence` string as raw probe output. No blackbox probe fills
      # `evidence_items`, so every blackbox finding reached the model with no
      # evidence at all while its evidence sat one key over. Forwarding it here
      # covers every blackbox probe at once; a probe that builds a real item
      # keeps it.
      if not item.get("evidence_items"):
        evidence_text = item.get("evidence")
        if isinstance(evidence_text, str) and evidence_text.strip():
          item["evidence_items"] = [{
            "kind": "log",
            "caption": f"{probe_name} evidence",
            "snippet": evidence_text,
          }]
        else:
          item["evidence_items"] = []

      # A scenario that concluded nothing has nothing to remediate; the default
      # text made coverage records read like findings in the PDF.
      if not item.get("remediation_structured") and not _is_coverage_result(item):
        item["remediation_structured"] = {
          "primary": item.get("remediation")
                     or "Review the finding evidence and apply vendor or platform hardening guidance.",
          "mitigation": "",
          "compensating": "",
        }

      # Key absence, not falsiness: `affected_assets: []` is a deliberate
      # statement — "no location recorded" (the graybox producer documents the
      # distinction) — and the falsy check replaced it with an invented asset.
      if "affected_assets" not in item:
        asset = {"host": target, "port": port if port else None}
        url = item.get("url")
        if url:
          asset["url"] = url
        item["affected_assets"] = [asset]

      # `probe` has to be set before identity is computed: the dedup key
      # includes it, and it was previously threaded in as a separate argument to
      # a second signature implementation that could drift from the first — and
      # had, reading a raw severity string where `Finding.compute_signature`
      # read `Severity.value`.
      item["probe"] = probe_name
      # The probe-time signature wins over anything computed here.
      #
      # This walk runs on opposite sides of `_redact_report` depending on the
      # entry point — `services/finalization.py` before it, the manual-analysis
      # path in `pentester_api_01.py` after it — so anything derived from the
      # item in hand is not stable across them. That bites hardest for a
      # locationless blackbox finding, whose dedup key falls back to the title,
      # which is precisely what redaction rewrites: the same finding came out
      # with two different ids depending on which caller asked.
      #
      # `enrich_finding_for_probe` stamps both keys at probe time, on unredacted
      # values, and nothing downstream recomputes them. Carrying them is what
      # makes identity redaction-invariant.
      #
      # `dedup_key` used to be *derived* here as `finding_signature[:16]` when
      # only the signature was stamped — and the signature is the content hash,
      # so identity went straight back to being content-addressed on the one
      # path that ships. Rewording a description moved `finding_id`. The probe
      # stamps `dedup_key` itself now; the local computation is the fallback for
      # a finding that arrives unstamped, and never the truncated content hash.
      carried = item.get("finding_signature")
      item["dedup_key"] = item.get("dedup_key") or _dedup_key(item)
      item["content_hash"] = item.get("content_hash") or carried or _content_hash(item)
      item["finding_signature"] = carried or item["content_hash"]
      item["finding_id"] = item.get("finding_id") or item["dedup_key"]
      item["port"] = port
      item["protocol"] = protocol
      item["category"] = category
      # The contract's one production enforcement point. B1 defined
      # `validate_flat_finding`, tested it thoroughly, and never called it from
      # anywhere that runs — so a probe emitting an unknown severity or omitting
      # a required field produced exactly the silent pass-through the contract
      # exists to end.
      #
      # Reported, not raised, and never a reason to drop the finding: a probe
      # bug is evidence about the probe, and losing the finding to surface it
      # would be a worse trade than the one being fixed.
      for error in _validate_flat_finding(item):
        schema_violations.append(f"{probe_name}: {error}")
      # Validation runs on the normalised item, so a field this walk repairs can
      # never be reported by it. `confidence` is the case that matters: an
      # unrecognised value is mapped to `tentative` above, twenty lines before
      # the check, so a probe emitting `confidence: "probably"` produced zero
      # schema violations — the one defect `validate_flat_finding` names
      # explicitly in its own docstring. The repair is still right; it just has
      # to be reported rather than absorbed.
      if not recognised and finding.get("confidence"):
        schema_violations.append(
          f"{probe_name}: confidence is invalid: {finding['confidence']}"
        )
      return item

    def normalize_string_list(values):
      if isinstance(values, str):
        values = [values]
      if not isinstance(values, (list, tuple)):
        return ()
      out = []
      for value in values:
        text = str(value or "").strip()
        if text and text not in out:
          out.append(text)
      return tuple(out)

    def parse_port(port_key):
      """Extract integer port from keys like '80/tcp' or '80'."""
      try:
        return int(str(port_key).split("/")[0])
      except (ValueError, IndexError):
        return 0

    # Walk service_info
    service_info = aggregated_report.get("service_info", {})
    for port_key, probes in service_info.items():
      if not isinstance(probes, dict):
        continue
      port = parse_port(port_key)
      for probe_name, probe_data in probes.items():
        if not isinstance(probe_data, dict):
          continue
        process_findings(probe_data.get("findings", []), port, probe_name, "service")

    # Walk web_tests_info
    web_tests_info = aggregated_report.get("web_tests_info", {})
    for port_key, tests in web_tests_info.items():
      if not isinstance(tests, dict):
        continue
      port = parse_port(port_key)
      for test_name, test_data in tests.items():
        if not isinstance(test_data, dict):
          continue
        process_findings(test_data.get("findings", []), port, test_name, "web")

    # Walk correlation_findings
    correlation_findings = aggregated_report.get("correlation_findings", [])
    if isinstance(correlation_findings, list):
      process_findings(correlation_findings, 0, "_correlation", "correlation")

    # Walk graybox_results — delegates to GrayboxFinding.to_flat_finding()
    from ..graybox.findings import (
      FindingRedactionContext,
      GrayboxFinding as _GF,
    )
    from .report import _configured_graybox_secret_names_from_report
    graybox_secret_names = _configured_graybox_secret_names_from_report(
      aggregated_report,
    )
    graybox_results = aggregated_report.get("graybox_results", {})
    with FindingRedactionContext(secret_field_names=graybox_secret_names):
      for port_key, probes in graybox_results.items():
        if not isinstance(probes, dict):
          continue
        port = parse_port(port_key)
        protocol = port_protocols.get(str(port), "unknown")
        for probe_name, probe_data in probes.items():
          if not isinstance(probe_data, dict):
            continue
          for finding_dict in probe_data.get("findings", []):
            if not isinstance(finding_dict, dict):
              continue
            try:
              flat = _GF.flat_from_dict(finding_dict, port, protocol, probe_name)
            except (TypeError, KeyError, ValueError):
              continue

            # Coverage results included: they were appended raw here, which
            # meant graybox coverage was the one shape that skipped
            # normalisation — never schema-validated, unlike blackbox coverage.
            # One producer path for everything; the single scoring walk below
            # makes the coverage/finding distinction.
            flat_findings.append(
              normalize_flat_finding(flat, port, protocol, probe_name, "graybox")
            )

    # B. Open ports — diminishing returns
    open_ports = aggregated_report.get("open_ports", [])
    nr_ports = len(open_ports) if isinstance(open_ports, list) else 0
    open_ports_score = 15.0 * (1.0 - math.exp(-nr_ports / 8.0))

    # C. Attack surface breadth
    nr_protocols = len(set(port_protocols.values())) if isinstance(port_protocols, dict) else 0
    breadth_score = 10.0 * (1.0 - math.exp(-nr_protocols / 4.0))

    # D (default-credentials penalty) is computed after the scoring walk below —
    # it reads `cred_count`, which only exists once findings are counted.

    # Deduplicate finding signatures first. CVE title fallback remains for
    # older findings that represent the same CVE with different descriptions.
    import re as _re_dedup
    CONFIDENCE_RANK = {"certain": 3, "firm": 2, "tentative": 1}
    SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def finding_rank(f):
      severity = SEVERITY_RANK.get(str(f.get("severity", "INFO")).upper(), 0)
      confidence = CONFIDENCE_RANK.get(str(f.get("confidence", "tentative")).lower(), 0)
      return severity, confidence

    drop_indices = set()
    signature_best = {}
    for idx, f in enumerate(flat_findings):
      # Deduplicate on **content**, not on identity — deliberately, and not yet
      # the other way round.
      #
      # Keying this on `dedup_key` reads as the obvious improvement, and it
      # silently deleted findings. No blackbox probe sets `affected_assets`
      # (`grep -rn affected_assets worker/` returns nothing), so every blackbox
      # finding lands on `dedup_key`'s last-resort branch, whose only
      # discriminator is the lowercased title — and a probe that emits N
      # findings in a loop under one constant title collapses to a single
      # record. Measured on the real SRI loop in `worker/web/hardening.py`: five
      # unsafe CDN scripts, five distinct content hashes, one survivor.
      #
      # RM-061 owns giving blackbox findings a url and parameter. Once identity
      # can actually distinguish them, this should move to `dedup_key` — the CVE
      # title fallback below exists to approximate what that would do — but not
      # before, because losing a finding is worse than keeping a reworded
      # duplicate.
      signature = f.get("finding_signature")
      if not signature:
        continue
      key = (signature, f.get("port", 0))
      if key in signature_best:
        prev_idx = signature_best[key]
        if finding_rank(f) > finding_rank(flat_findings[prev_idx]):
          drop_indices.add(prev_idx)
          signature_best[key] = idx
        else:
          drop_indices.add(idx)
      else:
        signature_best[key] = idx

    cve_best = {}  # (cve_id, port) -> index of best finding
    for idx, f in enumerate(flat_findings):
      if idx in drop_indices:
        continue
      # Coverage results are not findings and must not be deduplicated against
      # them. This loop was the one place in the function that ignored that
      # distinction, and it ranks on confidence alone — unlike `finding_rank`
      # above, which ranks severity first. So a `not_vulnerable` INFO record
      # naming a CVE and a CRITICAL vulnerability naming the same CVE collapsed
      # into a single survivor, deleting one of them from the archive, the
      # counts and every export. Measured: one survivor and `coverage_counts` of
      # zero, contradicting this module's own "the entry is still archived".
      if _is_coverage_result(f):
        continue
      title = f.get("title", "")
      m = _re_dedup.search(r"CVE-\d{4}-\d+", title)
      if not m:
        continue
      cve_id = m.group(0)
      port = f.get("port", 0)
      key = (cve_id, port)
      # `finding_rank` — severity first, then confidence — the same ordering the
      # signature loop above uses. Ranking on confidence alone let a LOW banner
      # observation marked `certain` evict a CRITICAL RCE marked `tentative`,
      # both naming CVE-2024-1234, so the report carried one LOW where the scan
      # had found a critical remote code execution.
      if key in cve_best:
        prev_idx = cve_best[key]
        if finding_rank(f) > finding_rank(flat_findings[prev_idx]):
          drop_indices.add(prev_idx)
          cve_best[key] = idx
        else:
          drop_indices.add(idx)
      else:
        cve_best[key] = idx

    if drop_indices:
      flat_findings = [f for i, f in enumerate(flat_findings) if i not in drop_indices]

    # The one scoring walk, over what actually survives.
    #
    # Three copies of this loop used to coexist — two producing walks scoring as
    # they went, plus this recount gated on `if drop_indices:` — and their drift
    # caused real defects twice: coverage was rescored after dedup, and a
    # whitespace-padded confidence scored 0.5 in the producing walks (raw
    # string) and 1.0 here (normalised). Scoring once, after dedup, removes the
    # drift class rather than keeping the copies in step.
    findings_score = 0.0
    finding_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    coverage_counts = {status: 0 for status in COVERAGE_STATUSES}
    cred_count = 0
    for f in flat_findings:
      if _is_coverage_result(f):
        status = str(f.get("status") or "").lower()
        coverage_counts[status] = coverage_counts.get(status, 0) + 1
        continue
      # `str(... or ...)` rather than `.get(key, default)`: an explicit None
      # passes straight through a .get default, and `None.upper()` killed the
      # whole risk computation over one malformed finding.
      severity = str(f.get("severity") or "INFO").upper()
      confidence = str(f.get("confidence") or "firm").lower()
      weight = RISK_SEVERITY_WEIGHTS.get(severity, 0)
      multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
      findings_score += weight * multiplier
      if severity in finding_counts:
        finding_counts[severity] += 1
      title = f.get("title", "")
      if isinstance(title, str) and "default credential accepted" in title.lower():
        cred_count += 1
    # D. Default credentials penalty
    credentials_penalty = min(cred_count * RISK_CRED_PENALTY_PER, RISK_CRED_PENALTY_CAP)

    # `finding_id = dedup_key`, unconditionally — collisions are reported, not
    # hidden (plan decision 3; this deliberately re-opens E2, the two-port
    # collision, as an accepted and *visible* trade).
    #
    # The collision-detection pass this replaces suffixed every member of a
    # colliding group, which made the id depend on what else the scan found:
    # pass 2 finding one SRI script where pass 1 found three re-keyed the
    # survivor and `finding_timeline` reported a brand-new finding. It also
    # produced ~29-character ids against the documented 16-hex contract.
    # Identity stays coarse until RM-061 attaches locations; findings sharing a
    # `dedup_key` are a probe defect, and the count below is how it is seen.
    id_counts = {}
    for f in flat_findings:
      id_counts[f.get("finding_id")] = id_counts.get(f.get("finding_id"), 0) + 1
    colliding = [f for f in flat_findings if id_counts.get(f.get("finding_id"), 0) > 1]
    identity_collisions = {
      "count": len(colliding),
      "probes": sorted({str(f.get("probe") or "") for f in colliding} - {""}),
    }
    if colliding and callable(getattr(self, "P", None)):
      # The log line is the load-bearing surface — no Navigator consumer reads
      # the breakdown field yet. Probe names and a count only; never finding
      # text, which can carry target data.
      self.P(
        f"identity collision: {identity_collisions['count']} findings share "
        f"a finding_id (probes: {', '.join(identity_collisions['probes'])}) — "
        "the probe emits findings identity cannot distinguish until RM-061 "
        "attaches locations",
        color="y",
      )

    raw_total = findings_score + open_ports_score + breadth_score + credentials_penalty
    score = normalize_risk_score(raw_total)

    risk_result = {
      "score": score,
      "breakdown": {
        "findings_score": round(findings_score, 1),
        "open_ports_score": round(open_ports_score, 1),
        "breadth_score": round(breadth_score, 1),
        "credentials_penalty": credentials_penalty,
        "raw_total": round(raw_total, 1),
        "finding_counts": finding_counts,
        # Coverage stated alongside the findings rather than folded into them:
        # "we ran 40 scenarios and 1 was vulnerable" and "we found 40 findings"
        # are different claims, and only the first is true.
        "coverage_counts": coverage_counts,
        # Findings sharing an id — a probe emitting findings identity cannot
        # distinguish. Reported rather than hidden behind a synthetic suffix.
        "identity_collisions": identity_collisions,
        # A probe emitting a finding the contract does not accept is a defect in
        # the probe. Stated here so it is visible in the pass report rather
        # than absorbed silently by the layer that reads the finding.
        "schema_violations": {
          "count": len(schema_violations),
          "errors": schema_violations[:20],
        },
      },
    }
    return risk_result, flat_findings

  def _count_services(self, service_info):
    """Count ports that have at least one identified service.

    Parameters
    ----------
    service_info : dict
      Port-keyed service info dict from aggregated scan data.

    Returns
    -------
    int
      Number of ports with detected services.
    """
    if not isinstance(service_info, dict):
      return 0
    count = 0
    for port_key, probes in service_info.items():
      if isinstance(probes, dict) and len(probes) > 0:
        count += 1
    return count
