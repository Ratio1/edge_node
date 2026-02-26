import re as _re
import uuid as _uuid
import requests

from .findings import Finding, Severity, probe_result, probe_error


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
    dict
      Structured findings from endpoint checks.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    # --- Honeypot detection: 200-for-all ---
    try:
      canary_path = f"/{_uuid.uuid4().hex}"
      canary_resp = requests.get(base_url + canary_path, timeout=2, verify=False)
      if canary_resp.status_code == 200:
        findings_list.append(Finding(
          severity=Severity.HIGH,
          title="Web server returns 200 for random paths (possible honeypot)",
          description="A request to a non-existent random UUID path returned HTTP 200, "
                      "suggesting a catch-all honeypot or severely misconfigured server.",
          evidence=f"GET {base_url}{canary_path} returned 200.",
          remediation="Investigate — this host may be a honeypot.",
          cwe_id="CWE-345",
          confidence="firm",
        ))
    except Exception:
      pass

    # Severity depends on what the path exposes
    _PATH_META = {
      "/.env": (Severity.HIGH, "CWE-538", "A05:2021",
        "Environment file may contain database passwords, API keys, and secrets."),
      "/.git/": (Severity.HIGH, "CWE-538", "A01:2021",
        "Git repository exposed — source code, credentials, and history downloadable."),
      "/admin": (Severity.MEDIUM, "CWE-200", "A01:2021",
        "Admin panel accessible — verify authentication is enforced."),
      "/robots.txt": (Severity.INFO, "", "",
        "Robots.txt present — may reveal hidden paths."),
      "/login": (Severity.INFO, "", "",
        "Login page accessible."),
    }

    try:
      for path, (severity, cwe, owasp, desc) in _PATH_META.items():
        url = base_url + path
        resp = requests.get(url, timeout=2, verify=False)
        if resp.status_code == 200:
          findings_list.append(Finding(
            severity=severity,
            title=f"Accessible resource: {path}",
            description=desc,
            evidence=f"GET {url} returned 200 OK.",
            remediation=f"Restrict access to {path} or remove it from production." if severity != Severity.INFO else "",
            owasp_id=owasp,
            cwe_id=cwe,
            confidence="certain",
          ))
    except Exception as e:
      self.P(f"Common endpoint probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "common", e)

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="No common endpoint exposures detected",
        description=f"Checked /.env, /.git/, /admin, /robots.txt, /login on {base_url}.",
        confidence="firm",
      ))
    return probe_result(findings=findings_list)


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
    dict
      Structured findings from homepage inspection.
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    _MARKER_META = {
      "API_KEY": (Severity.CRITICAL, "API key found in page source"),
      "PASSWORD": (Severity.CRITICAL, "Password string found in page source"),
      "SECRET": (Severity.HIGH, "Secret string found in page source"),
      "BEGIN RSA PRIVATE KEY": (Severity.CRITICAL, "RSA private key found in page source"),
    }

    try:
      resp_main = requests.get(base_url, timeout=3, verify=False)
      text = resp_main.text[:10000]
      for marker, (severity, title) in _MARKER_META.items():
        if marker in text:
          findings_list.append(Finding(
            severity=severity,
            title=title,
            description=f"The string '{marker}' was found in the HTML source of {base_url}.",
            evidence=f"Marker '{marker}' present in first 10KB of response.",
            remediation="Remove sensitive data from client-facing HTML; use server-side environment variables.",
            owasp_id="A01:2021",
            cwe_id="CWE-540",
            confidence="firm",
          ))
    except Exception as e:
      self.P(f"Homepage probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "homepage", e)

    if not findings_list:
      findings_list.append(Finding(
        severity=Severity.INFO,
        title="No sensitive markers detected on homepage",
        description=f"Checked for API_KEY, PASSWORD, SECRET, RSA keys on {base_url}.",
        confidence="firm",
      ))
    return probe_result(findings=findings_list)

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
