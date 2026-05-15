"""
Risk scoring mixin for RedMesh pentester API.

Pure computation — takes aggregated scan reports and produces risk scores
(0-100) with breakdowns and flat findings lists. No CStore or R1FS access.
"""

from ..constants import (
  RISK_SEVERITY_WEIGHTS,
  RISK_CONFIDENCE_MULTIPLIERS,
  RISK_SIGMOID_K,
  RISK_CRED_PENALTY_PER,
  RISK_CRED_PENALTY_CAP,
)


class _RiskScoringMixin:
  """Risk scoring and findings extraction methods for PentesterApi01Plugin."""

  def _compute_risk_score(self, aggregated_report):
    """
    Compute a 0-100 risk score from an aggregated scan report.

    The score combines four components:
    A. Finding severity (weighted by confidence)
    B. Open ports (diminishing returns)
    C. Attack surface breadth (distinct protocols)
    D. Default credentials penalty

    Parameters
    ----------
    aggregated_report : dict
      Aggregated report with service_info, web_tests_info, correlation_findings,
      open_ports, and port_protocols.

    Returns
    -------
    dict
      ``{"score": int, "breakdown": dict}``
    """
    import math

    findings_score = 0.0
    finding_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cred_count = 0

    def process_findings(findings_list):
      nonlocal findings_score, cred_count
      for finding in findings_list:
        if not isinstance(finding, dict):
          continue
        severity = finding.get("severity", "INFO").upper()
        confidence = finding.get("confidence", "firm").lower()
        weight = RISK_SEVERITY_WEIGHTS.get(severity, 0)
        multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
        findings_score += weight * multiplier
        if severity in finding_counts:
          finding_counts[severity] += 1
        title = finding.get("title", "")
        if isinstance(title, str) and "default credential accepted" in title.lower():
          cred_count += 1

    # A. Iterate service_info findings
    service_info = aggregated_report.get("service_info", {})
    for port_key, probes in service_info.items():
      if not isinstance(probes, dict):
        continue
      for probe_name, probe_data in probes.items():
        if not isinstance(probe_data, dict):
          continue
        process_findings(probe_data.get("findings", []))

    # A. Iterate web_tests_info findings
    web_tests_info = aggregated_report.get("web_tests_info", {})
    for port_key, tests in web_tests_info.items():
      if not isinstance(tests, dict):
        continue
      for test_name, test_data in tests.items():
        if not isinstance(test_data, dict):
          continue
        process_findings(test_data.get("findings", []))

    # A. Iterate correlation_findings
    correlation_findings = aggregated_report.get("correlation_findings", [])
    if isinstance(correlation_findings, list):
      process_findings(correlation_findings)

    # A. Iterate graybox_results — uses GrayboxFinding.to_flat_finding()
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
        for probe_name, probe_data in probes.items():
          if not isinstance(probe_data, dict):
            continue
          for finding_dict in probe_data.get("findings", []):
            if not isinstance(finding_dict, dict):
              continue
            try:
              flat = _GF.flat_from_dict(finding_dict, 0, "unknown", probe_name)
            except (TypeError, KeyError, ValueError):
              continue
            weight = RISK_SEVERITY_WEIGHTS.get(flat["severity"], 0)
            multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(flat["confidence"], 0.5)
            findings_score += weight * multiplier
            if flat["severity"] in finding_counts:
              finding_counts[flat["severity"]] += 1

    # B. Open ports — diminishing returns: 15 × (1 - e^(-ports/8))
    open_ports = aggregated_report.get("open_ports", [])
    nr_ports = len(open_ports) if isinstance(open_ports, list) else 0
    open_ports_score = 15.0 * (1.0 - math.exp(-nr_ports / 8.0))

    # C. Attack surface breadth — distinct protocols: 10 × (1 - e^(-protocols/4))
    port_protocols = aggregated_report.get("port_protocols", {})
    nr_protocols = len(set(port_protocols.values())) if isinstance(port_protocols, dict) else 0
    breadth_score = 10.0 * (1.0 - math.exp(-nr_protocols / 4.0))

    # D. Default credentials penalty
    credentials_penalty = min(cred_count * RISK_CRED_PENALTY_PER, RISK_CRED_PENALTY_CAP)

    # Raw total
    raw_total = findings_score + open_ports_score + breadth_score + credentials_penalty

    # Normalize to 0-100 via logistic curve
    score = int(round(100.0 * (2.0 / (1.0 + math.exp(-RISK_SIGMOID_K * raw_total)) - 1.0)))
    score = max(0, min(100, score))

    return {
      "score": score,
      "breakdown": {
        "findings_score": round(findings_score, 1),
        "open_ports_score": round(open_ports_score, 1),
        "breadth_score": round(breadth_score, 1),
        "credentials_penalty": credentials_penalty,
        "raw_total": round(raw_total, 1),
        "finding_counts": finding_counts,
      },
    }

  def _compute_risk_and_findings(self, aggregated_report):
    """
    Compute risk score AND extract flat findings in a single walk.

    Extends _compute_risk_score to also produce a flat list of enriched
    findings from the nested service_info/web_tests_info/correlation structure.

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
    import hashlib
    import math

    findings_score = 0.0
    finding_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cred_count = 0
    flat_findings = []

    port_protocols = aggregated_report.get("port_protocols") or {}
    target = (
      aggregated_report.get("target")
      or aggregated_report.get("target_url")
      or aggregated_report.get("host")
      or ""
    )

    def process_findings(findings_list, port, probe_name, category):
      nonlocal findings_score, cred_count
      for finding in findings_list:
        if not isinstance(finding, dict):
          continue
        severity = finding.get("severity", "INFO").upper()
        confidence = finding.get("confidence", "firm").lower()
        weight = RISK_SEVERITY_WEIGHTS.get(severity, 0)
        multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
        findings_score += weight * multiplier
        if severity in finding_counts:
          finding_counts[severity] += 1
        title = finding.get("title", "")
        if isinstance(title, str) and "default credential accepted" in title.lower():
          cred_count += 1

        protocol = port_protocols.get(str(port), "unknown")
        flat_findings.append(
          normalize_flat_finding(finding, port, protocol, probe_name, category)
        )

    def normalize_flat_finding(finding, port, protocol, probe_name, category):
      item = {k: v for k, v in finding.items()}
      cwe_values = normalize_cwe_values(item.get("cwe"))
      if not cwe_values:
        parsed_cwe = parse_cwe_id(item.get("cwe_id"))
        if parsed_cwe:
          cwe_values = (parsed_cwe,)
      if cwe_values and not item.get("cwe"):
        item["cwe"] = list(cwe_values)
      if cwe_values and not item.get("cwe_id"):
        item["cwe_id"] = f"CWE-{cwe_values[0]}"

      owasp_values = normalize_string_list(item.get("owasp_top10"))
      if not owasp_values and item.get("owasp_id"):
        owasp_values = (str(item["owasp_id"]),)
      if owasp_values and not item.get("owasp_top10"):
        item["owasp_top10"] = list(owasp_values)
      if owasp_values and not item.get("owasp_id"):
        item["owasp_id"] = owasp_values[0]

      if not item.get("remediation_structured"):
        item["remediation_structured"] = {
          "primary": item.get("remediation")
                     or "Review the finding evidence and apply vendor or platform hardening guidance.",
          "mitigation": "",
          "compensating": "",
        }

      if not item.get("affected_assets"):
        asset = {"host": target, "port": port if port else None}
        url = item.get("url")
        if url:
          asset["url"] = url
        item["affected_assets"] = [asset]

      signature = item.get("finding_signature")
      if not signature:
        signature = compute_flat_signature(item, probe_name)
        item["finding_signature"] = signature

      item["finding_id"] = item.get("finding_id") or signature[:16]
      item["port"] = port
      item["protocol"] = protocol
      item["probe"] = probe_name
      item["category"] = category
      return item

    def compute_flat_signature(finding, probe_name):
      asset_canonical = canonical_asset_string(finding.get("affected_assets"))
      parts = [
        probe_name or "",
        asset_canonical,
        finding.get("title") or "",
        finding.get("description") or "",
        finding.get("severity") or "",
      ]
      return hashlib.sha256("\x1e".join(str(p) for p in parts).encode()).hexdigest()

    def canonical_asset_string(assets):
      if not isinstance(assets, list) or not assets:
        return ""
      parts = []
      for asset in assets:
        if not isinstance(asset, dict):
          continue
        parts.append("|".join([
          str(asset.get("host") or ""),
          str(asset.get("port") or ""),
          str(asset.get("url") or ""),
          str(asset.get("parameter") or ""),
          str(asset.get("method") or "").upper(),
        ]))
      return "\x1f".join(sorted(parts))

    def normalize_cwe_values(values):
      out = []
      raw_values = values if isinstance(values, (list, tuple)) else []
      for value in raw_values:
        try:
          parsed = int(value)
        except (TypeError, ValueError):
          continue
        if parsed > 0 and parsed not in out:
          out.append(parsed)
      return tuple(out)

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

    def parse_cwe_id(value):
      if not isinstance(value, str):
        return 0
      cleaned = value.strip().upper()
      if cleaned.startswith("CWE-"):
        cleaned = cleaned[4:]
      try:
        parsed = int(cleaned)
      except (TypeError, ValueError):
        return 0
      return parsed if parsed > 0 else 0

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

            weight = RISK_SEVERITY_WEIGHTS.get(flat["severity"], 0)
            multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(flat["confidence"], 0.5)
            findings_score += weight * multiplier
            if flat["severity"] in finding_counts:
              finding_counts[flat["severity"]] += 1
            title = flat.get("title", "")
            if isinstance(title, str) and "default credential accepted" in title.lower():
              cred_count += 1

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

    # D. Default credentials penalty
    credentials_penalty = min(cred_count * RISK_CRED_PENALTY_PER, RISK_CRED_PENALTY_CAP)

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
      title = f.get("title", "")
      m = _re_dedup.search(r"CVE-\d{4}-\d+", title)
      if not m:
        continue
      cve_id = m.group(0)
      port = f.get("port", 0)
      key = (cve_id, port)
      conf = CONFIDENCE_RANK.get(f.get("confidence", "tentative"), 0)
      if key in cve_best:
        prev_idx = cve_best[key]
        prev_conf = CONFIDENCE_RANK.get(flat_findings[prev_idx].get("confidence", "tentative"), 0)
        if conf > prev_conf:
          drop_indices.add(prev_idx)
          cve_best[key] = idx
        else:
          drop_indices.add(idx)
      else:
        cve_best[key] = idx

    if drop_indices:
      flat_findings = [f for i, f in enumerate(flat_findings) if i not in drop_indices]
      # Recalculate scores after dedup
      findings_score = 0.0
      finding_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
      cred_count = 0
      for f in flat_findings:
        severity = f.get("severity", "INFO").upper()
        confidence = f.get("confidence", "firm").lower()
        weight = RISK_SEVERITY_WEIGHTS.get(severity, 0)
        multiplier = RISK_CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
        findings_score += weight * multiplier
        if severity in finding_counts:
          finding_counts[severity] += 1
        title = f.get("title", "")
        if isinstance(title, str) and "default credential accepted" in title.lower():
          cred_count += 1
      credentials_penalty = min(cred_count * RISK_CRED_PENALTY_PER, RISK_CRED_PENALTY_CAP)

    raw_total = findings_score + open_ports_score + breadth_score + credentials_penalty
    score = int(round(100.0 * (2.0 / (1.0 + math.exp(-RISK_SIGMOID_K * raw_total)) - 1.0)))
    score = max(0, min(100, score))

    risk_result = {
      "score": score,
      "breakdown": {
        "findings_score": round(findings_score, 1),
        "open_ports_score": round(open_ports_score, 1),
        "breadth_score": round(breadth_score, 1),
        "credentials_penalty": credentials_penalty,
        "raw_total": round(raw_total, 1),
        "finding_counts": finding_counts,
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
