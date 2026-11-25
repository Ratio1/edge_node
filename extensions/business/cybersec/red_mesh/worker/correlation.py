"""
Cross-service correlation engine for RedMesh Scanner.

Analyzes aggregated scan_metadata collected by individual probes to detect
patterns that no single probe can identify alone — honeypot indicators,
OS mismatches, infrastructure leaks, and timezone drift.
"""

import ipaddress

from ..cve_view import FOLD_REASON, _subject, is_view_finding
from ..findings import epss_band, Finding, Severity, probe_result
from .. import cvss_vectors as V
from ..models.finding_identity import content_hash
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


def _port_ratio_fires(n_open, n_scanned):
  """The port-ratio honeypot rule: more than half of the scanned ports and more than 20 are open."""
  return bool(n_scanned) and n_open / n_scanned > 0.5 and n_open > 20


def _os_mismatch(os_claims):
  """True when the OS claims name more than one OS family."""
  return len({_normalize_os_family(os_string) for os_string in (os_claims or {}).values()}) > 1 and len(os_claims) >= 2


def host_honeypot_verdict(report):
  """`port_ratio`, `os_mismatch` or None for a merged report, over the whole host (D54).

  The same two rules the per-worker checks use, applied to the job's merged `open_ports`, `ports_scanned`
  (a count after the merge, a list on a worker) and `scan_metadata["os_claims"]`.
  """
  scanned = report.get("ports_scanned")
  scanned = len(scanned) if isinstance(scanned, (list, set, tuple)) else (scanned or 0)
  if _port_ratio_fires(len(report.get("open_ports") or ()), scanned):
    return "port_ratio"
  if _os_mismatch((report.get("scan_metadata") or {}).get("os_claims")):
    return "os_mismatch"
  return None


def _demotable(row):
  """A generated CVE row a host verdict may fold: not KEV, not `certain` (confirmed by behaviour), not folded yet."""
  return (is_view_finding(row) and not row.get("kev") and row.get("confidence") != "certain"
          and "honeypot_verdict=" not in str(row.get("evidence") or ""))


def apply_host_honeypot_verdict(report):
  """Fold the CVE rows of a merged job report when the host looks like a honeypot (RM-268 D42, D54). Returns the verdict.

  Every copy of a row in `service_info` and `web_tests_info` becomes tentative `banner_unverified`, so no firm
  copy survives the report's dedup and the RM-205 fold lists the row as folded, never dropped. The prior state
  is kept as `demoted_from=<confidence>:<reason>` and the `finding_signature` is recomputed (as `confirm_cve`
  does), so the engagement ledger sees the change; `finding_id` stays. Idempotent.
  """
  verdict = host_honeypot_verdict(report)
  if not verdict:
    return None
  for section in ("service_info", "web_tests_info"):
    for port, methods in (report.get(section) or {}).items():
      for info in (methods or {}).values():
        for row in info.get("findings", []) if isinstance(info, dict) else ():
          if not _demotable(row):
            continue
          was = f"{row.get('confidence')}:{row.get('confidence_reason') or ''}"
          row["confidence"], row["confidence_reason"] = "tentative", FOLD_REASON
          marks = f"honeypot_verdict={verdict}" if was.endswith(f":{FOLD_REASON}") else f"honeypot_verdict={verdict}; demoted_from={was}"
          row["evidence"] = f"{row['evidence']}; {marks}" if row.get("evidence") else marks
          product, version = _subject(row)
          try:
            port_nr = int(port)
          except (TypeError, ValueError):
            port_nr = None
          row["finding_signature"] = content_hash(
            # Same payload `confirm_cve` hashes: `Finding._identity_payload` bands the EPSS score (risk.py does the same).
            {**row, "probe": f"cve:{product}", "port": port_nr, "epss_score": epss_band(row.get("epss_score"))},
            asset_canonical=f"{product}:{version}:{row['cve'][0]}",
          )
  return verdict


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
      findings += self._correlate_banner_authenticity()
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
    if _port_ratio_fires(len(open_ports), len(ports_scanned)):
      findings.append(Finding(
        severity=Severity.HIGH,
        # The counts belong in the description, not the title: for a finding
        # with no scenario id and no specific location the title *is* the
        # `dedup_key` discriminator, so a per-scan number here re-keys the
        # finding every scan and detaches the triage recorded against it.
        title="Honeypot indicator: unusually high open-port ratio",
        description=f"{len(open_ports)} of {len(ports_scanned)} scanned ports are open "
                    f"({ratio:.0%}). An unusually high ratio suggests this host is a "
                    "honeypot; real servers rarely expose more than 50% of scanned ports.",
        evidence="More than half of the scanned ports accepted a TCP connection.",
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
    display_name="Honeypot indicator (banner authenticity)",
    description=(
      "Flag services whose announced implementation contradicts their protocol "
      "behaviour (SSH KEXINIT, SMTP EHLO): an emulator announcing a real version."
    ),
    category=CATEGORY_CORRELATION,
    default_cwe=(345,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
  )
  def _correlate_banner_authenticity(self):
    """Flag honeypot if one or more services were marked `banner_unverified` by their probe (RM-200)."""
    findings = []
    meta = self.state.get("scan_metadata", {})
    unverified = meta.get("banner_unverified", {})
    if not unverified:
      return findings
    findings.append(Finding(
      severity=Severity.HIGH,
      title="Honeypot indicator: service banner contradicted by protocol behaviour",
      description="One or more services announce an implementation and version that their own protocol "
                  "behaviour contradicts. Emulators and proxies do this; the announced versions cannot be "
                  "trusted, so CVEs matched on them are reported as unconfirmed.",
      evidence="; ".join(f"{source}: {why}" for source, why in sorted(unverified.items())),
      remediation="Verify this is a legitimate host before relying on scan results.",
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
        title="Infrastructure leak: internal IPs span multiple private subnets",
        description=f"Internal IPs from {len(subnets)} distinct /16 subnets were leaked across "
                    "services, suggesting Docker multi-network architecture or multiple "
                    "internal zones.",
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
        title="Timezone inconsistency: services report differing offsets",
        description=f"Services on this host report {len(offsets)} distinct timezone offsets. "
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
        cvss_vector=V.OPEN_REDIRECT,
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
