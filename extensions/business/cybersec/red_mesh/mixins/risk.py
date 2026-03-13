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
    from ..graybox.findings import GrayboxFinding as _GF
    graybox_results = aggregated_report.get("graybox_results", {})
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

        # Build deterministic finding_id
        canon_title = (finding.get("title") or "").lower().strip()
        cwe = finding.get("cwe_id", "")
        id_input = f"{port}:{probe_name}:{cwe}:{canon_title}"
        finding_id = hashlib.sha256(id_input.encode()).hexdigest()[:16]

        protocol = port_protocols.get(str(port), "unknown")

        flat_findings.append({
          "finding_id": finding_id,
          **{k: v for k, v in finding.items()},
          "port": port,
          "protocol": protocol,
          "probe": probe_name,
          "category": category,
        })

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
    from ..graybox.findings import GrayboxFinding as _GF
    graybox_results = aggregated_report.get("graybox_results", {})
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

          flat_findings.append(flat)

    # B. Open ports — diminishing returns
    open_ports = aggregated_report.get("open_ports", [])
    nr_ports = len(open_ports) if isinstance(open_ports, list) else 0
    open_ports_score = 15.0 * (1.0 - math.exp(-nr_ports / 8.0))

    # C. Attack surface breadth
    nr_protocols = len(set(port_protocols.values())) if isinstance(port_protocols, dict) else 0
    breadth_score = 10.0 * (1.0 - math.exp(-nr_protocols / 4.0))

    # D. Default credentials penalty
    credentials_penalty = min(cred_count * RISK_CRED_PENALTY_PER, RISK_CRED_PENALTY_CAP)

    # Deduplicate CVE findings: when the same CVE appears on the same port
    # from different probes (behavioral + version-based), keep the higher
    # confidence detection and drop the duplicate.
    import re as _re_dedup
    CONFIDENCE_RANK = {"certain": 3, "firm": 2, "tentative": 1}
    cve_best = {}  # (cve_id, port) -> index of best finding
    drop_indices = set()
    for idx, f in enumerate(flat_findings):
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
