"""
Cross-service correlation engine for RedMesh Scanner.

Analyzes aggregated scan_metadata collected by individual probes to detect
patterns that no single probe can identify alone — honeypot indicators,
OS mismatches, infrastructure leaks, and timezone drift.
"""

import ipaddress

from ..findings import Finding, Severity, probe_result
from .probe_registry import register_probe, CATEGORY_CORRELATION


# Map keywords found in OS strings to normalized OS families
_OS_FAMILY_MAP = {
  "ubuntu": "Linux",
  "debian": "Linux",
  "centos": "Linux",
  "fedora": "Linux",
  "alpine": "Linux",
  "rhel": "Linux",
  "red hat": "Linux",
  "suse": "Linux",
  "arch": "Linux",
  "linux": "Linux",
  "windows": "Windows",
  "win32": "Windows",
  "win64": "Windows",
  "microsoft": "Windows",
  "darwin": "macOS",
  "macos": "macOS",
  "mac os": "macOS",
  "freebsd": "FreeBSD",
  "openbsd": "OpenBSD",
  "netbsd": "NetBSD",
}


def _normalize_os_family(os_string):
  """Map an OS claim string to a normalized family name."""
  lower = os_string.lower()
  for keyword, family in _OS_FAMILY_MAP.items():
    if keyword in lower:
      return family
  return os_string  # unknown — keep as-is for comparison


def _is_private_ip(ip_str):
  """Check if an IP address string is RFC1918 / private."""
  try:
    return ipaddress.ip_address(ip_str).is_private
  except (ValueError, TypeError):
    return False


def _subnet_16(ip_str):
  """Return the /16 subnet prefix for an IPv4 address string."""
  try:
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
      octets = str(addr).split(".")
      return f"{octets[0]}.{octets[1]}.0.0/16"
  except (ValueError, TypeError):
    pass
  return None


class _CorrelationMixin:
  """
  Post-scan cross-service correlation engine.

  Consumes ``self.state["scan_metadata"]`` populated by probe mixins and
  produces ``self.state["correlation_findings"]`` with honeypot indicators,
  OS consistency checks, infrastructure leak detection, and timezone drift.
  """

  @register_probe(
    display_name="Post-scan correlation",
    description=(
      "Cross-service analysis of aggregated scan output. Runs all "
      "_correlate_* sub-checks (port ratio, OS consistency, "
      "infrastructure leak, TLS consistency, timezone drift, "
      "redirect-to-SSRF chain). Emits findings that no single probe "
      "could identify alone."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _post_scan_correlate(self):
    """Entry point: run all correlation checks and store findings."""
    findings = []

    # Scan-metadata-dependent correlations
    meta = self.state.get("scan_metadata")
    if meta:
      findings += self._correlate_port_ratio()
      findings += self._correlate_os_consistency()
      findings += self._correlate_infrastructure_leak()
      findings += self._correlate_tls_consistency()
      findings += self._correlate_timezone_drift()

    # Cross-probe correlations (don't require scan_metadata)
    findings += self._correlate_redirect_ssrf()

    if findings:
      self.P(f"Correlation engine produced {len(findings)} findings.")
    self.state["correlation_findings"] = probe_result(
      findings=findings,
      probe_id="_post_scan_correlate",
    )["findings"]

  @register_probe(
    display_name="Honeypot indicator (port-open ratio)",
    description=(
      "Flag suspicious open-port ratios that suggest a honeypot "
      "(too many ports open across unrelated services)."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  )
  def _correlate_port_ratio(self):
    """Flag honeypot if >50% of scanned ports are open and >20 ports open."""
    findings = []
    open_ports = self.state.get("open_ports", [])
    ports_scanned = self.state.get("ports_scanned", [])
    if not ports_scanned:
      return findings
    ratio = len(open_ports) / len(ports_scanned)
    if ratio > 0.5 and len(open_ports) > 20:
      findings.append(Finding(
        severity=Severity.HIGH,
        title=f"Honeypot indicator: {len(open_ports)}/{len(ports_scanned)} ports open ({ratio:.0%})",
        description="An unusually high ratio of open ports suggests this host is a honeypot. "
                    "Real servers rarely expose more than 50% of scanned ports.",
        evidence=f"open={len(open_ports)}, scanned={len(ports_scanned)}, ratio={ratio:.2f}",
        remediation="Verify this is a legitimate host before relying on scan results.",
        cwe_id="CWE-345",
        confidence="firm",
      ))
    return findings

  @register_probe(
    display_name="OS-family consistency check",
    description=(
      "Compare OS hints across probes (SSH banner, Telnet system info, "
      "RDP fingerprint, SNMP sysDescr). Inconsistency suggests "
      "honeypot or NAT'd multi-host."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  )
  def _correlate_os_consistency(self):
    """Flag honeypot if services report conflicting OS families."""
    findings = []
    meta = self.state.get("scan_metadata", {})
    os_claims = meta.get("os_claims", {})
    if len(os_claims) < 2:
      return findings

    families = {}
    for source, os_string in os_claims.items():
      family = _normalize_os_family(os_string)
      families.setdefault(family, []).append(source)

    if len(families) > 1:
      evidence_parts = [f"{family}: {', '.join(sources)}" for family, sources in families.items()]
      findings.append(Finding(
        severity=Severity.HIGH,
        title=f"Honeypot indicator: OS mismatch across services ({', '.join(families.keys())})",
        description="Different services on this host report conflicting operating systems. "
                    "This is a strong honeypot indicator — real hosts run a single OS.",
        evidence="; ".join(evidence_parts),
        remediation="Investigate this host — it may be a honeypot or compromised system.",
        cwe_id="CWE-345",
        confidence="firm",
      ))
    return findings

  @register_probe(
    display_name="Internal infrastructure leak",
    description=(
      "Detect internal IPs / hostnames leaked through public-facing "
      "responses (SNMP interface IPs, error pages, Server headers)."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(200, 209),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _correlate_infrastructure_leak(self):
    """Detect Docker multi-network architecture from distinct /16 private subnets."""
    findings = []
    meta = self.state.get("scan_metadata", {})
    internal_ips = meta.get("internal_ips", [])
    if not internal_ips:
      return findings

    subnets = {}
    for entry in internal_ips:
      ip_str = entry.get("ip") if isinstance(entry, dict) else str(entry)
      if not _is_private_ip(ip_str):
        continue
      subnet = _subnet_16(ip_str)
      if subnet:
        subnets.setdefault(subnet, []).append(entry)

    if len(subnets) >= 2:
      subnet_list = ", ".join(sorted(subnets.keys()))
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title=f"Infrastructure leak: {len(subnets)} distinct private subnets detected",
        description="Internal IPs from multiple /16 subnets were leaked across services, "
                    "suggesting Docker multi-network architecture or multiple internal zones.",
        evidence=f"Subnets: {subnet_list}",
        remediation="Review network segmentation; ensure internal IPs are not exposed in service responses.",
        cwe_id="CWE-200",
        confidence="firm",
      ))
    return findings

  @register_probe(
    display_name="TLS certificate consistency",
    description=(
      "Compare TLS certificate SANs / CN across ports and probes. "
      "Inconsistency may indicate a load-balancer with mixed "
      "certificates or virtual host fronting."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(295,),
    default_owasp=("A02:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  )
  def _correlate_tls_consistency(self):
    """Compare cert issuers across TLS ports. Placeholder for future SAN emission."""
    # Will be populated once TLS SAN emission is fully wired
    return []

  @register_probe(
    display_name="Server timezone drift",
    description=(
      "Compare server timestamps in HTTP / SMTP / SSH headers vs. "
      "reference clock. Drift suggests NTP misconfig or honeypot."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  )
  def _correlate_timezone_drift(self):
    """Detect inconsistent timezone offsets across services."""
    findings = []
    meta = self.state.get("scan_metadata", {})
    tz_hints = meta.get("timezone_hints", [])
    if len(tz_hints) < 2:
      return findings

    offsets = set()
    for entry in tz_hints:
      offset = entry.get("offset") if isinstance(entry, dict) else str(entry)
      offsets.add(offset)

    if len(offsets) >= 2:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title=f"Timezone inconsistency: {len(offsets)} distinct offsets detected",
        description="Services on this host report different timezone offsets. "
                    "Real hosts share a single system clock — this may indicate a honeypot or misconfiguration.",
        evidence=f"Offsets: {', '.join(sorted(offsets))}",
        remediation="Investigate timezone configuration across services.",
        cwe_id="CWE-345",
        confidence="firm",
      ))
    return findings

  @register_probe(
    display_name="Open redirect + SSRF chain",
    description=(
      "Chain analysis: when an open redirect AND a metadata-endpoint "
      "indicator coexist on the same target, flag the SSRF "
      "exfiltration chain (PTES attack-chain narrative)."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(601, 918),
    default_owasp=("A10:2021", "A01:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
  )
  def _correlate_redirect_ssrf(self):
    """Flag SSRF chaining risk if open redirect + internal services detected."""
    findings = []
    web_info = self.state.get("web_tests_info", {})

    has_open_redirect = False
    has_metadata = False

    for port_data in web_info.values():
      for probe_name, result in port_data.items():
        if not isinstance(result, dict):
          continue
        for f in result.get("findings", []):
          title = f.get("title", "") if isinstance(f, dict) else ""
          if "open redirect" in title.lower():
            has_open_redirect = True
          if "metadata" in title.lower() and "exposed" in title.lower():
            has_metadata = True

    if has_open_redirect and has_metadata:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title="Open redirect may enable SSRF to cloud metadata",
        description="An open redirect was found alongside accessible cloud metadata "
                    "endpoints. If internal services follow redirects, an attacker "
                    "can chain the redirect to access metadata credentials.",
        evidence="Open redirect + cloud metadata endpoint both detected.",
        remediation="Fix the open redirect; ensure internal HTTP clients do not follow "
                    "redirects to metadata IPs.",
        owasp_id="A10:2021",
        cwe_id="CWE-918",
        confidence="tentative",
      ))
    return findings
