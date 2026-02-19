import re as _re
import requests

from .findings import Finding, Severity, probe_result


class _WebDiscoveryMixin:
  """
  Enumerate exposed files, admin panels, and homepage secrets (OWASP WSTG-INFO).
  """

  def _web_test_common(self, target, port):
    """
    Look for exposed common endpoints and weak access controls.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings from endpoint checks.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Check common sensitive endpoints
      for path in ["/robots.txt", "/.env", "/.git/", "/admin", "/login"]:
        url = base_url + path
        resp = requests.get(url, timeout=2, verify=False)
        if resp.status_code == 200:
          finding = f"VULNERABILITY: Accessible resource at {url} (200 OK)."
          self.P(finding)
          findings.append(finding)
        elif resp.status_code in (401, 403):
          self.P(f"Protected resource {url} (status {resp.status_code}).")
          findings.append(
            f"INFO: Access control enforced at {url} (status {resp.status_code})."
          )
    except Exception as e:
      message = f"ERROR: Common endpoint probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: No common endpoint exposures detected on {base_url}.")
    return "\n".join(findings)


  def _web_test_homepage(self, target, port):
    """
    Scan landing pages for clear-text secrets or database dumps.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    str
      Joined findings from homepage inspection.
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"
    try:
      # Check homepage for leaked info
      resp_main = requests.get(base_url, timeout=3, verify=False)
      text = resp_main.text[:10000]
      for marker in ["API_KEY", "PASSWORD", "SECRET", "BEGIN RSA PRIVATE KEY"]:
        if marker in text:
          finding = (
            f"VULNERABILITY: sensitive '{marker}' found on {base_url}."
          )
          findings.append(finding)
          self.P(finding)
      # Check for other potential leaks
      if "database" in text.lower():
        finding = f"VULNERABILITY: potential database leak at {base_url}."
        findings.append(finding)
        self.P(finding)
    except Exception as e:
      message = f"ERROR: Homepage probe failed on {base_url}: {e}"
      self.P(message, color='y')
      findings.append(message)
    if not findings:
      findings.append(f"OK: No sensitive markers detected on {base_url} homepage.")
    return "\n".join(findings)

  def _web_test_tech_fingerprint(self, target, port):
    """
    Technology fingerprinting: extract Server header, X-Powered-By,
    meta generator, and detect tech mismatches.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    dict
      Structured findings with technology details.
    """
    findings_list = []
    raw = {"server": None, "powered_by": None, "generator": None, "technologies": []}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    try:
      resp = requests.get(base_url, timeout=4, verify=False)

      # Server header
      server = resp.headers.get("Server")
      if server:
        raw["server"] = server
        raw["technologies"].append(server)
        findings_list.append(Finding(
          severity=Severity.LOW,
          title=f"Server header disclosed: {server}",
          description=f"Server header reveals software: {server}.",
          evidence=f"Server: {server}",
          remediation="Remove or obfuscate the Server header.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))

      # X-Powered-By header
      powered_by = resp.headers.get("X-Powered-By")
      if powered_by:
        raw["powered_by"] = powered_by
        raw["technologies"].append(powered_by)
        findings_list.append(Finding(
          severity=Severity.LOW,
          title=f"X-Powered-By disclosed: {powered_by}",
          description=f"X-Powered-By header reveals technology: {powered_by}.",
          evidence=f"X-Powered-By: {powered_by}",
          remediation="Remove X-Powered-By header.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))

      # Meta generator tag
      body = resp.text[:10000]
      gen_match = _re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        body, _re.IGNORECASE,
      )
      if gen_match:
        generator = gen_match.group(1).strip()
        raw["generator"] = generator
        raw["technologies"].append(generator)
        findings_list.append(Finding(
          severity=Severity.LOW,
          title=f"Generator meta tag: {generator}",
          description=f"HTML meta generator reveals CMS/framework: {generator}.",
          evidence=f'<meta name="generator" content="{generator}">',
          remediation="Remove the generator meta tag.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))

      # Tech mismatch detection
      if raw["generator"] and raw["server"]:
        gen_lower = raw["generator"].lower()
        srv_lower = raw["server"].lower()
        # Flag CMS + unexpected server combo (e.g. MediaWiki on Python/aiohttp)
        cms_indicators = {"wordpress": "php", "mediawiki": "php",
                          "drupal": "php", "joomla": "php"}
        for cms, expected_tech in cms_indicators.items():
          if cms in gen_lower and expected_tech not in srv_lower:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title=f"Technology mismatch: {raw['generator']} on {raw['server']}",
              description=f"{raw['generator']} typically runs on {expected_tech}, "
                          f"but server is {raw['server']}. Possible honeypot or proxy.",
              evidence=f"Generator={raw['generator']}, Server={raw['server']}",
              remediation="Verify this is intentional.",
              confidence="tentative",
            ))
            break

    except Exception as e:
      self.P(f"Tech fingerprint failed on {base_url}: {e}", color='y')

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="No technology disclosed",
        description=f"Server headers and HTML do not reveal technology stack.",
        confidence="firm",
      ))

    return probe_result(raw_data=raw, findings=findings_list)

  def _web_test_vpn_endpoints(self, target, port):
    """
    Detect VPN management endpoints from major vendors.

    Probes:
      - Cisco ASA:          /+CSCOE+/logon.html + webvpn cookie
      - FortiGate:          /remote/login
      - Pulse Secure:       /dana-na/auth/url_default/welcome.cgi
      - Palo Alto GP:       /global-protect/login.esp

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    dict
      Structured findings.
    """
    findings_list = []
    raw = {"vpn_endpoints": []}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    vpn_checks = [
      {
        "path": "/+CSCOE+/logon.html",
        "product": "Cisco ASA/AnyConnect",
        "check": lambda resp: resp.status_code == 200 and ("webvpn" in resp.headers.get("Set-Cookie", "").lower() or "webvpn" in resp.text.lower()),
      },
      {
        "path": "/remote/login",
        "product": "FortiGate SSL VPN",
        "check": lambda resp: resp.status_code == 200 and ("fortinet" in resp.text.lower() or "fortitoken" in resp.text.lower() or "fgt_lang" in resp.headers.get("Set-Cookie", "").lower()),
      },
      {
        "path": "/dana-na/auth/url_default/welcome.cgi",
        "product": "Pulse Secure / Ivanti VPN",
        "check": lambda resp: resp.status_code in (200, 302) and ("pulse" in resp.text.lower() or "dana" in resp.text.lower() or "dsid" in resp.headers.get("Set-Cookie", "").lower()),
      },
      {
        "path": "/global-protect/login.esp",
        "product": "Palo Alto GlobalProtect",
        "check": lambda resp: resp.status_code == 200 and ("global-protect" in resp.text.lower() or "panGPBannerContent" in resp.text),
      },
    ]

    for entry in vpn_checks:
      try:
        url = base_url.rstrip("/") + entry["path"]
        resp = requests.get(url, timeout=3, verify=False, allow_redirects=False)
        if entry["check"](resp):
          raw["vpn_endpoints"].append({"product": entry["product"], "path": entry["path"]})
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"VPN endpoint detected: {entry['product']}",
            description=f"{entry['product']} login page accessible at {url}.",
            evidence=f"URL: {url}, status={resp.status_code}",
            remediation="Restrict VPN management portal access; verify patching status.",
            owasp_id="A05:2021",
            cwe_id="CWE-200",
            confidence="firm",
          ))
      except Exception:
        pass

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="No VPN endpoints detected",
        description=f"Checked Cisco ASA, FortiGate, Pulse Secure, Palo Alto GP on {base_url}.",
        confidence="firm",
      ))

    return probe_result(raw_data=raw, findings=findings_list)
