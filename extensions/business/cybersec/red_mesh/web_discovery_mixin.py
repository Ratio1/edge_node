import re as _re
import uuid as _uuid
import requests

from .findings import Finding, Severity, probe_result, probe_error
from .cve_db import check_cves


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

    # --- Catch-all detection: 200-for-all ---
    try:
      canary_path = f"/{_uuid.uuid4().hex}"
      canary_resp = requests.get(base_url + canary_path, timeout=2, verify=False)
      if canary_resp.status_code == 200:
        findings_list.append(Finding(
          severity=Severity.HIGH,
          title="Web server returns 200 for random paths",
          description="A request to a non-existent random UUID path returned HTTP 200, "
                      "suggesting a catch-all rule or severely misconfigured server.",
          evidence=f"GET {base_url}{canary_path} returned 200.",
          remediation="Investigate the catch-all behavior; ensure proper 404 responses for unknown paths.",
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
      "/xmlrpc.php": (Severity.MEDIUM, "CWE-288", "A01:2021",
        "WordPress XML-RPC endpoint — brute-force amplification and DDoS vector."),
      "/wp-login.php": (Severity.LOW, "CWE-200", "A01:2021",
        "WordPress login page accessible — confirms WordPress deployment."),
      "/.well-known/security.txt": (Severity.INFO, "", "",
        "Security policy (RFC 9116) published."),
      # Debug & monitoring endpoints (A09 — exposed monitoring)
      "/actuator": (Severity.HIGH, "CWE-215", "A09:2021",
        "Spring Boot Actuator exposed — may leak env vars, health, and beans."),
      "/actuator/env": (Severity.HIGH, "CWE-215", "A09:2021",
        "Spring Boot environment dump — leaks config, secrets, and database URLs."),
      "/server-status": (Severity.HIGH, "CWE-215", "A09:2021",
        "Apache mod_status exposed — reveals active connections and request details."),
      "/server-info": (Severity.HIGH, "CWE-215", "A09:2021",
        "Apache mod_info exposed — reveals server configuration."),
      "/elmah.axd": (Severity.HIGH, "CWE-215", "A09:2021",
        ".NET ELMAH error log viewer exposed — reveals stack traces and request data."),
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
      # (severity, title, owasp_id) — private key is A08 (integrity), rest is A01 (access control)
      "API_KEY": (Severity.CRITICAL, "API key found in page source", "A01:2021"),
      "PASSWORD": (Severity.CRITICAL, "Password string found in page source", "A01:2021"),
      "SECRET": (Severity.HIGH, "Secret string found in page source", "A01:2021"),
      "BEGIN RSA PRIVATE KEY": (Severity.CRITICAL, "RSA private key found in page source", "A08:2021"),
    }

    try:
      resp_main = requests.get(base_url, timeout=3, verify=False)
      text = resp_main.text[:10000]
      for marker, (severity, title, owasp) in _MARKER_META.items():
        if marker in text:
          findings_list.append(Finding(
            severity=severity,
            title=title,
            description=f"The string '{marker}' was found in the HTML source of {base_url}.",
            evidence=f"Marker '{marker}' present in first 10KB of response.",
            remediation="Remove sensitive data from client-facing HTML; use server-side environment variables.",
            owasp_id=owasp,
            cwe_id="CWE-540",
            confidence="firm",
          ))
    except Exception as e:
      self.P(f"Homepage probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "homepage", e)

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
                          f"but server is {raw['server']}. Possible reverse proxy or misconfiguration.",
              evidence=f"Generator={raw['generator']}, Server={raw['server']}",
              remediation="Verify this is intentional.",
              confidence="tentative",
            ))
            break

    except Exception as e:
      self.P(f"Tech fingerprint failed on {base_url}: {e}", color='y')

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

    return probe_result(raw_data=raw, findings=findings_list)


  # --- CMS fingerprinting ---

  _CMS_EOL = {
    "WordPress": {"3": "2015", "4": "2018"},
    "Drupal": {"7": "2025-01", "8": "2021-11"},
    "Joomla": {"3": "2023-08"},
  }

  _WP_SENSITIVE_PATHS = [
    ("/xmlrpc.php", "WordPress XML-RPC — brute-force amplification vector"),
    ("/wp-json/wp/v2/users", "WordPress REST API user enumeration"),
  ]

  def _web_test_cms_fingerprint(self, target, port):
    """
    Detect and version-check common CMS platforms (WordPress, Drupal, Joomla).

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Web port to probe.

    Returns
    -------
    dict
      Structured findings with CMS name, version, and EOL status.
    """
    findings_list = []
    raw = {"cms": None, "version": None}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
      base_url = f"{scheme}://{target}:{port}"

    # --- WordPress detection ---
    wp_version = None
    try:
      resp = requests.get(base_url, timeout=3, verify=False)
      if resp.ok:
        gen_match = _re.search(
          r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+([0-9.]+)',
          resp.text, _re.IGNORECASE,
        )
        if gen_match:
          wp_version = gen_match.group(1)
        elif '/wp-content/' in resp.text or '/wp-includes/' in resp.text:
          wp_version = "unknown"
    except Exception:
      pass

    if not wp_version:
      try:
        resp = requests.get(base_url + "/wp-login.php", timeout=3, verify=False, allow_redirects=False)
        if resp.status_code in (200, 302) and ('wp-login' in resp.text.lower() or 'wordpress' in resp.text.lower()):
          wp_version = "unknown"
      except Exception:
        pass

    # --- WordPress version fallback: /feed/, /wp-links-opml.php, /readme.html ---
    if wp_version == "unknown":
      for _wp_path, _wp_re in [
        ("/feed/", r'<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>'),
        ("/wp-links-opml.php", r'generator="WordPress/([0-9.]+)"'),
        ("/readme.html", r'Version\s+([0-9.]+)'),
      ]:
        try:
          resp = requests.get(base_url + _wp_path, timeout=3, verify=False)
          if resp.ok:
            _wp_m = _re.search(_wp_re, resp.text, _re.IGNORECASE)
            if _wp_m:
              wp_version = _wp_m.group(1)
              break
        except Exception:
          pass

    if wp_version:
      raw["cms"] = "WordPress"
      raw["version"] = wp_version
      findings_list.append(Finding(
        severity=Severity.LOW,
        title=f"WordPress {wp_version} detected",
        description=f"WordPress {wp_version} identified on {target}:{port}.",
        evidence="Detection via generator tag or wp-content paths.",
        remediation="Keep WordPress updated to the latest version.",
        confidence="certain",
      ))
      findings_list += self._cms_check_eol("WordPress", wp_version)
      if wp_version != "unknown":
        findings_list += check_cves("wordpress", wp_version)
      findings_list += self._wp_detect_plugins(base_url)
      for path, desc in self._WP_SENSITIVE_PATHS:
        try:
          resp = requests.get(base_url + path, timeout=3, verify=False)
          if resp.status_code == 200:
            findings_list.append(Finding(
              severity=Severity.MEDIUM,
              title=f"WordPress {path} exposed",
              description=desc,
              evidence=f"GET {base_url}{path} → HTTP 200",
              remediation=f"Block access to {path} via web server configuration.",
              owasp_id="A05:2021",
              cwe_id="CWE-200",
              confidence="certain",
            ))
        except Exception:
          continue
      return probe_result(raw_data=raw, findings=findings_list)

    # --- Drupal detection ---
    drupal_version = None
    try:
      resp = requests.get(base_url + "/core/CHANGELOG.txt", timeout=3, verify=False)
      if resp.ok and "Drupal" in resp.text:
        ver_match = _re.search(r'Drupal\s+([0-9.]+)', resp.text)
        drupal_version = ver_match.group(1) if ver_match else "unknown"
    except Exception:
      pass
    if not drupal_version:
      try:
        resp = requests.get(base_url, timeout=3, verify=False)
        if resp.ok:
          gen_match = _re.search(
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Drupal\s+([0-9.]+)',
            resp.text, _re.IGNORECASE,
          )
          if gen_match:
            drupal_version = gen_match.group(1)
      except Exception:
        pass

    # --- Drupal version fallback: install.php, JS query strings ---
    _DRUPAL_VERSION_SOURCES = [
      ("/core/modules/system/system.info.yml", r"version:\s*'?([0-9]+\.[0-9]+\.[0-9]+)"),
      ("/core/install.php", r'site-version[^>]*>([0-9]+\.[0-9]+\.[0-9]+)'),
      ("/core/install.php", r'drupal\.js\?v=([0-9]+\.[0-9]+\.[0-9]+)'),
    ]
    if drupal_version and (drupal_version == "unknown" or _re.match(r'^\d+$', drupal_version)):
      for _dp_path, _dp_re in _DRUPAL_VERSION_SOURCES:
        try:
          resp = requests.get(base_url + _dp_path, timeout=3, verify=False)
          if resp.ok:
            _dp_m = _re.search(_dp_re, resp.text)
            if _dp_m:
              drupal_version = _dp_m.group(1)
              break
        except Exception:
          pass

    if drupal_version:
      raw["cms"] = "Drupal"
      raw["version"] = drupal_version
      findings_list.append(Finding(
        severity=Severity.LOW,
        title=f"Drupal {drupal_version} detected",
        description=f"Drupal {drupal_version} identified on {target}:{port}.",
        evidence="Detection via CHANGELOG.txt or generator tag.",
        remediation="Keep Drupal updated to the latest version.",
        confidence="certain",
      ))
      findings_list += self._cms_check_eol("Drupal", drupal_version)
      if drupal_version != "unknown" and not _re.match(r'^\d+$', drupal_version):
        findings_list += check_cves("drupal", drupal_version)
      return probe_result(raw_data=raw, findings=findings_list)

    # --- Joomla detection ---
    joomla_version = None
    try:
      resp = requests.get(base_url + "/administrator/", timeout=3, verify=False, allow_redirects=False)
      if resp.status_code in (200, 302) and 'joomla' in resp.text.lower():
        joomla_version = "unknown"
        try:
          resp2 = requests.get(base_url + "/language/en-GB/en-GB.xml", timeout=3, verify=False)
          if resp2.ok:
            ver_match = _re.search(r'<version>([0-9.]+)</version>', resp2.text)
            if ver_match:
              joomla_version = ver_match.group(1)
        except Exception:
          pass
    except Exception:
      pass

    if joomla_version:
      raw["cms"] = "Joomla"
      raw["version"] = joomla_version
      findings_list.append(Finding(
        severity=Severity.LOW,
        title=f"Joomla {joomla_version} detected",
        description=f"Joomla {joomla_version} identified on {target}:{port}.",
        evidence="Detection via /administrator/ page.",
        remediation="Keep Joomla updated to the latest version.",
        confidence="certain",
      ))
      findings_list += self._cms_check_eol("Joomla", joomla_version)
      if joomla_version != "unknown":
        findings_list += check_cves("joomla", joomla_version)
      # CVE-2023-23752: Unauthenticated config disclosure via REST API
      try:
        resp = requests.get(
          base_url + "/api/index.php/v1/config/application?public=true",
          timeout=3, verify=False,
        )
        if resp.ok and ("password" in resp.text.lower() or '"db"' in resp.text.lower() or '"dbtype"' in resp.text.lower()):
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="CVE-2023-23752: Joomla unauthenticated config disclosure",
            description="Joomla REST API exposes application configuration "
                        "including database credentials without authentication.",
            evidence=f"GET {base_url}/api/index.php/v1/config/application?public=true → 200",
            remediation="Upgrade Joomla to >= 4.2.8.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
      except Exception:
        pass
      return probe_result(raw_data=raw, findings=findings_list)

    # --- Laravel / Ignition detection ---
    laravel_detected = False
    ignition_detected = False

    # Check /_ignition/health-check
    try:
      resp = requests.get(base_url + "/_ignition/health-check", timeout=3, verify=False)
      if resp.ok and ("can_execute_commands" in resp.text or "ok" in resp.text.lower()):
        ignition_detected = True
        laravel_detected = True
        findings_list.append(Finding(
          severity=Severity.HIGH,
          title="Laravel Ignition debug endpoint exposed",
          description="/_ignition/health-check is accessible, indicating Laravel's "
                      "debug error handler is enabled in production.",
          evidence=f"GET {base_url}/_ignition/health-check → {resp.status_code}",
          remediation="Set APP_DEBUG=false in production; remove Ignition package.",
          owasp_id="A05:2021",
          cwe_id="CWE-489",
          confidence="certain",
        ))
    except Exception:
      pass

    # Check for Laravel indicators in error pages
    if not laravel_detected:
      try:
        resp = requests.get(
          base_url + "/nonexistent_" + _uuid.uuid4().hex[:8],
          timeout=3, verify=False,
        )
        body = resp.text[:10000].lower()
        if "laravel" in body or "illuminate" in body:
          laravel_detected = True
      except Exception:
        pass

    if ignition_detected:
      # CVE-2021-3129: check execute-solution endpoint
      try:
        resp = requests.post(
          base_url + "/_ignition/execute-solution",
          json={"solution": "test", "parameters": {}},
          timeout=3, verify=False,
        )
        if resp.status_code != 404:
          findings_list.append(Finding(
            severity=Severity.CRITICAL,
            title="CVE-2021-3129: Laravel Ignition RCE endpoint accessible",
            description="/_ignition/execute-solution accepts POST requests. "
                        "With Ignition < 2.5.2, this enables unauthenticated RCE "
                        "via file_put_contents abuse.",
            evidence=f"POST {base_url}/_ignition/execute-solution → {resp.status_code}",
            remediation="Upgrade Ignition to >= 2.5.2; set APP_DEBUG=false.",
            owasp_id="A06:2021",
            cwe_id="CWE-94",
            confidence="firm",
          ))
      except Exception:
        pass

    if laravel_detected:
      raw["cms"] = "Laravel"
      raw["version"] = "unknown"
      findings_list.append(Finding(
        severity=Severity.LOW,
        title="Laravel framework detected",
        description=f"Laravel framework identified on {target}:{port}.",
        evidence="Detection via Ignition endpoint or error page markers.",
        remediation="Keep Laravel and dependencies updated.",
        confidence="certain",
      ))

    return probe_result(raw_data=raw, findings=findings_list)

  def _cms_check_eol(self, cms_name, version):
    """Check if a CMS version is end-of-life."""
    findings = []
    if version == "unknown":
      return findings
    eol_map = self._CMS_EOL.get(cms_name, {})
    major = version.split(".")[0]
    eol_date = eol_map.get(major)
    if eol_date:
      findings.append(Finding(
        severity=Severity.HIGH,
        title=f"{cms_name} {version} is end-of-life (EOL since {eol_date})",
        description=f"This {cms_name} version no longer receives security patches.",
        evidence=f"Version: {version}, EOL: {eol_date}",
        remediation=f"Upgrade to the latest supported {cms_name} version.",
        owasp_id="A06:2021",
        cwe_id="CWE-1104",
        confidence="certain",
      ))
    return findings

  # --- WordPress plugin detection (A06 improvement) ---

  _WP_PLUGIN_CHECKS = [
    ("elementor", "Elementor"),
    ("contact-form-7", "Contact Form 7"),
    ("woocommerce", "WooCommerce"),
    ("yoast-seo", "Yoast SEO"),
    ("wordfence", "Wordfence"),
    ("wpforms-lite", "WPForms"),
    ("all-in-one-seo-pack", "All in One SEO"),
    ("updraftplus", "UpdraftPlus"),
  ]

  def _wp_detect_plugins(self, base_url):
    """Detect WordPress plugins via readme.txt version disclosure."""
    findings = []
    for slug, name in self._WP_PLUGIN_CHECKS:
      try:
        url = f"{base_url}/wp-content/plugins/{slug}/readme.txt"
        resp = requests.get(url, timeout=3, verify=False)
        if resp.status_code != 200:
          continue
        ver_match = _re.search(r'Stable tag:\s*([0-9.]+)', resp.text, _re.IGNORECASE)
        version = ver_match.group(1) if ver_match else "unknown"
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"WordPress plugin version exposed: {name} {version}",
          description=f"Plugin {name} detected via readme.txt. "
                      "Version disclosure aids targeted exploit search.",
          evidence=f"GET {url} → Stable tag: {version}",
          remediation="Block access to plugin readme.txt files.",
          owasp_id="A06:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))
      except Exception:
        continue
    return findings


  # ── A09:2021 — Verbose errors & debug mode detection ────────────────

  _STACK_TRACE_MARKERS = [
    ("Traceback (most recent call last)", "Python"),
    ("SQLSTATE[", "PHP PDO"),
    ("Fatal error:", "PHP"),
    ("Parse error:", "PHP"),
    ("Exception in thread", "Java"),
    ("Stack trace:", "Generic"),
  ]
  _DEBUG_MODE_MARKERS = [
    ("djdt", "Django Debug Toolbar"),
    ("Django REST framework", "Django REST"),
  ]
  _PATH_LEAK_PATTERNS = [
    _re.compile(r'(/home/\w+|/var/www/|/opt/|/usr/local/|C:\\\\[Uu]sers)'),
  ]

  def _web_test_verbose_errors(self, target, port):
    """
    Detect verbose error pages and debug mode indicators (safe probes only).

    Requests a random non-existent path to trigger 404 handling, then checks
    for stack traces, framework debug output, and filesystem path leaks.
    Also probes for debug endpoints (__debug__/, actuator/env).

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    # --- 1. Trigger a 404 and inspect the error page ---
    try:
      canary = f"/nonexistent_{_uuid.uuid4().hex[:8]}"
      resp = requests.get(base_url + canary, timeout=3, verify=False)
      body = resp.text[:10000]

      for marker, framework in self._STACK_TRACE_MARKERS:
        if marker in body:
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Verbose error page: {framework} stack trace exposed",
            description=f"Error page at {canary} contains {framework} stack trace, "
                        "leaking internal code structure and potentially secrets.",
            evidence=f"Marker '{marker}' found in 404 response.",
            remediation="Configure production error handling to return generic error pages.",
            owasp_id="A09:2021",
            cwe_id="CWE-209",
            confidence="certain",
          ))
          break

      for pattern in self._PATH_LEAK_PATTERNS:
        match = pattern.search(body)
        if match and not findings_list:
          findings_list.append(Finding(
            severity=Severity.LOW,
            title=f"Internal path leaked in error page",
            description="Error page reveals filesystem paths.",
            evidence=f"Path pattern: {match.group(0)}",
            remediation="Suppress internal paths in error responses.",
            owasp_id="A09:2021",
            cwe_id="CWE-209",
            confidence="firm",
          ))
    except Exception:
      pass

    # --- 2. Debug mode detection on homepage ---
    try:
      resp = requests.get(base_url, timeout=3, verify=False)
      body = resp.text[:10000]
      for marker, framework in self._DEBUG_MODE_MARKERS:
        if marker in body:
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title=f"Debug mode enabled: {framework}",
            description=f"Debug interface detected on homepage, exposing internal "
                        "state, SQL queries, and configuration.",
            evidence=f"Marker '{marker}' found in homepage.",
            remediation=f"Disable {framework} debug mode in production.",
            owasp_id="A09:2021",
            cwe_id="CWE-489",
            confidence="certain",
          ))
          break
    except Exception:
      pass

    # --- 3. Django __debug__/ endpoint ---
    try:
      resp = requests.get(base_url + "/__debug__/", timeout=3, verify=False)
      if resp.status_code == 200 and "djdt" in resp.text.lower():
        findings_list.append(Finding(
          severity=Severity.HIGH,
          title="Debug mode enabled: Django Debug Toolbar endpoint",
          description="Django Debug Toolbar is accessible at /__debug__/.",
          evidence="GET /__debug__/ returned 200 with djdt content.",
          remediation="Remove django-debug-toolbar from production or restrict access.",
          owasp_id="A09:2021",
          cwe_id="CWE-489",
          confidence="certain",
        ))
    except Exception:
      pass

    return probe_result(findings=findings_list)


  # ── Java Application Server fingerprinting ──────────────────────────

  _JAVA_SERVER_EOL = {
    "JBoss AS": {"5": "2012", "6": "2016"},
  }

  def _web_test_java_servers(self, target, port):
    """
    Detect and version-check Java application servers and frameworks:
    WebLogic, Tomcat, JBoss/WildFly, Struts2, Spring.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    raw = {"java_server": None, "version": None, "framework": None}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    # --- 1. WebLogic detection ---
    weblogic_version = None
    # Console login page
    try:
      resp = requests.get(base_url + "/console/login/LoginForm.jsp", timeout=4, verify=False, allow_redirects=True)
      if resp.ok and "WebLogic" in resp.text:
        raw["java_server"] = "WebLogic"
        ver_m = _re.search(r'(?:WebLogic Server|footerVersion)[^0-9]*(\d+\.\d+\.\d+\.\d+)', resp.text)
        if ver_m:
          weblogic_version = ver_m.group(1)
        else:
          weblogic_version = "unknown"
    except Exception:
      pass
    # T3/IIOP banner on root (some WebLogic instances)
    if not weblogic_version:
      try:
        resp = requests.get(base_url, timeout=3, verify=False)
        if resp.ok:
          # Check for WebLogic error page patterns
          if "WebLogic" in resp.text or "BEA-" in resp.text:
            raw["java_server"] = "WebLogic"
            weblogic_version = "unknown"
          # Check X-Powered-By for Servlet/JSP versions typical of WebLogic
          xpb = resp.headers.get("X-Powered-By", "")
          if "Servlet" in xpb and "JSP" in xpb and not raw["java_server"]:
            # Could be WebLogic or other Java server — check console
            pass
      except Exception:
        pass

    if weblogic_version:
      raw["version"] = weblogic_version
      findings_list.append(Finding(
        severity=Severity.MEDIUM,
        title=f"WebLogic Server {weblogic_version} detected",
        description=f"Oracle WebLogic Server {weblogic_version} identified on {target}:{port}.",
        evidence="Detection via /console/login/LoginForm.jsp or error page.",
        remediation="Restrict access to the WebLogic console; keep WebLogic patched.",
        owasp_id="A05:2021",
        cwe_id="CWE-200",
        confidence="certain",
      ))
      if weblogic_version != "unknown":
        findings_list += check_cves("weblogic", weblogic_version)
      # Check for console exposure
      try:
        resp = requests.get(base_url + "/console/", timeout=3, verify=False, allow_redirects=True)
        if resp.ok and ("login" in resp.text.lower() or "WebLogic" in resp.text):
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title="WebLogic admin console exposed",
            description="The WebLogic administration console is accessible without IP restriction.",
            evidence=f"GET {base_url}/console/ → {resp.status_code}",
            remediation="Restrict console access to management network only.",
            owasp_id="A01:2021",
            cwe_id="CWE-306",
            confidence="certain",
          ))
      except Exception:
        pass
      return probe_result(raw_data=raw, findings=findings_list)

    # --- 2. Tomcat detection ---
    tomcat_version = None
    try:
      resp = requests.get(base_url, timeout=3, verify=False)
      if resp.ok:
        # Tomcat default page or error page
        tc_m = _re.search(r'Apache Tomcat[/\s]*(\d+\.\d+\.\d+)', resp.text)
        if tc_m:
          tomcat_version = tc_m.group(1)
        elif "Apache Tomcat" in resp.text:
          tomcat_version = "unknown"
        # Server header
        srv = resp.headers.get("Server", "")
        if not tomcat_version and "Tomcat" in srv:
          tc_m = _re.search(r'Tomcat[/\s]*(\d+\.\d+\.\d+)', srv)
          tomcat_version = tc_m.group(1) if tc_m else "unknown"
    except Exception:
      pass
    # Try 404 page which often reveals Tomcat version
    if not tomcat_version:
      try:
        resp = requests.get(base_url + "/nonexistent_" + _uuid.uuid4().hex[:6], timeout=3, verify=False)
        tc_m = _re.search(r'Apache Tomcat[/\s]*(\d+\.\d+\.\d+)', resp.text)
        if tc_m:
          tomcat_version = tc_m.group(1)
      except Exception:
        pass

    if tomcat_version:
      raw["java_server"] = "Tomcat"
      raw["version"] = tomcat_version
      findings_list.append(Finding(
        severity=Severity.LOW,
        title=f"Apache Tomcat {tomcat_version} detected",
        description=f"Apache Tomcat {tomcat_version} identified on {target}:{port}.",
        evidence="Detection via default page, error page, or Server header.",
        remediation="Keep Tomcat updated; remove default applications.",
        confidence="certain",
      ))
      if tomcat_version != "unknown":
        findings_list += check_cves("tomcat", tomcat_version)
      # Manager app exposure
      for mgr_path in ["/manager/html", "/manager/status"]:
        try:
          resp = requests.get(base_url + mgr_path, timeout=3, verify=False)
          if resp.status_code in (200, 401, 403):
            findings_list.append(Finding(
              severity=Severity.HIGH if resp.status_code == 200 else Severity.MEDIUM,
              title=f"Tomcat Manager accessible: {mgr_path}",
              description=f"Tomcat Manager at {mgr_path} returned {resp.status_code}.",
              evidence=f"GET {base_url}{mgr_path} → {resp.status_code}",
              remediation="Remove or restrict Tomcat Manager in production.",
              owasp_id="A01:2021",
              cwe_id="CWE-306",
              confidence="certain",
            ))
            break
        except Exception:
          pass
      # Do NOT return — frameworks (Spring, Struts2) often run on Tomcat

    # --- 3. JBoss / WildFly detection ---
    jboss_version = None
    try:
      resp = requests.get(base_url, timeout=3, verify=False)
      xpb = resp.headers.get("X-Powered-By", "")
      jb_m = _re.search(r'JBossAS[- ]*(\d+)', xpb)
      if jb_m:
        jboss_version = jb_m.group(1) + ".0"
        raw["java_server"] = "JBoss AS"
      elif "JBoss" in xpb or "WildFly" in xpb:
        jboss_version = "unknown"
        raw["java_server"] = "JBoss/WildFly"
      # Check for JBoss welcome page
      if not jboss_version and resp.ok:
        if "JBoss" in resp.text or "WildFly" in resp.text:
          jb_m = _re.search(r'(?:JBoss|WildFly)[/\s]*(\d+\.\d+\.\d+)', resp.text)
          jboss_version = jb_m.group(1) if jb_m else "unknown"
          raw["java_server"] = "JBoss" if "JBoss" in resp.text else "WildFly"
    except Exception:
      pass

    if jboss_version:
      raw["version"] = jboss_version
      findings_list.append(Finding(
        severity=Severity.LOW,
        title=f"{raw['java_server']} {jboss_version} detected",
        description=f"{raw['java_server']} {jboss_version} identified on {target}:{port}.",
        evidence=f"Detection via X-Powered-By header or welcome page.",
        remediation="Keep application server updated; restrict management interfaces.",
        confidence="certain",
      ))
      # EOL check
      if jboss_version != "unknown" and raw["java_server"] == "JBoss AS":
        major = jboss_version.split(".")[0]
        eol_date = self._JAVA_SERVER_EOL.get("JBoss AS", {}).get(major)
        if eol_date:
          findings_list.append(Finding(
            severity=Severity.HIGH,
            title=f"JBoss AS {jboss_version} is end-of-life (EOL since {eol_date})",
            description=f"JBoss AS {jboss_version} no longer receives security patches.",
            evidence=f"Version: {jboss_version}, EOL: {eol_date}",
            remediation="Migrate to WildFly or JBoss EAP.",
            owasp_id="A06:2021",
            cwe_id="CWE-1104",
            confidence="certain",
          ))
      if jboss_version != "unknown":
        findings_list += check_cves("jboss", jboss_version)
      # JMX console exposure
      try:
        resp = requests.get(base_url + "/jmx-console/", timeout=3, verify=False)
        if resp.status_code in (200, 401):
          findings_list.append(Finding(
            severity=Severity.HIGH if resp.status_code == 200 else Severity.MEDIUM,
            title="JBoss JMX console exposed",
            description=f"JMX console at /jmx-console/ returned {resp.status_code}.",
            evidence=f"GET {base_url}/jmx-console/ → {resp.status_code}",
            remediation="Remove or restrict JMX console access.",
            owasp_id="A01:2021",
            cwe_id="CWE-306",
            confidence="certain",
          ))
      except Exception:
        pass
      # Do NOT return — frameworks (Spring, Struts2) may run on JBoss

    # --- 4. Spring Framework detection ---
    spring_detected = False
    try:
      resp = requests.get(base_url, timeout=3, verify=False)
      body = resp.text[:10000]
      # Spring Whitelabel Error Page
      if "Whitelabel Error Page" in body or "Spring" in resp.headers.get("X-Application-Context", ""):
        spring_detected = True
      # JSESSIONID cookie (generic Java indicator)
      if not spring_detected and "JSESSIONID" in resp.headers.get("Set-Cookie", ""):
        raw["framework"] = "Java (JSESSIONID)"
    except Exception:
      pass
    if not spring_detected:
      try:
        resp = requests.get(base_url + "/nonexistent_" + _uuid.uuid4().hex[:6], timeout=3, verify=False)
        if "Whitelabel Error Page" in resp.text:
          spring_detected = True
        elif "org.springframework" in resp.text or "DispatcherServlet" in resp.text:
          spring_detected = True
      except Exception:
        pass
    # Spring MVC: POST to root returns 405 with Spring-specific message
    if not spring_detected:
      try:
        resp = requests.post(base_url, data="", timeout=3, verify=False)
        if resp.status_code == 405:
          body = resp.text
          if "Request method" in body and "not supported" in body:
            spring_detected = True
      except Exception:
        pass

    spring_evidence = []
    if spring_detected:
      raw["framework"] = "Spring"
      spring_evidence.append("Spring MVC indicators detected")
      findings_list.append(Finding(
        severity=Severity.LOW,
        title="Spring Framework detected",
        description=f"Spring Framework identified on {target}:{port}.",
        evidence="Whitelabel Error Page, X-Application-Context header, "
                 "DispatcherServlet in error page, or Spring MVC 405 response.",
        remediation="Disable the default error page in production; keep Spring updated.",
        confidence="certain",
      ))

    # --- 5. Struts2 detection ---
    struts_detected = False
    struts_evidence = ""
    # 5a. Check /struts/utils.js — present in all Struts2 apps using <s:head/> tag
    try:
      resp = requests.get(base_url + "/struts/utils.js", timeout=3, verify=False)
      if resp.ok and len(resp.text) > 50:
        struts_detected = True
        struts_evidence = "/struts/utils.js present"
    except Exception:
      pass
    # 5b. Check homepage for .action/.do URLs or Struts indicators
    if not struts_detected:
      try:
        resp = requests.get(base_url, timeout=3, verify=False)
        body = resp.text[:10000]
        struts_indicators = [".action", ".do", "struts", "Struts Problem Report"]
        if any(ind in body for ind in struts_indicators):
          struts_detected = True
          struts_evidence = ".action/.do URLs or Struts indicators in page"
      except Exception:
        pass
    if struts_detected:
      raw["framework"] = "Struts2"
      findings_list.append(Finding(
        severity=Severity.LOW,
        title="Apache Struts2 framework detected",
        description=f"Struts2 indicators found on {target}:{port}.",
        evidence=f"Detection via {struts_evidence}.",
        remediation="Keep Struts2 updated; review OGNL injection mitigations.",
        confidence="firm",
      ))

    return probe_result(raw_data=raw, findings=findings_list)

  # ── A08:2021 / A06:2021 — JS library version detection ─────────────

  _JS_LIB_PATTERNS = [
    # (filename regex, version-in-content regex, library name)
    (_re.compile(r'jquery[.-]?(\d+\.\d+\.\d+)', _re.IGNORECASE), None, "jQuery"),
    (None, _re.compile(r'/\*!?\s*jQuery\s+v(\d+\.\d+\.\d+)'), "jQuery"),
    (None, _re.compile(r'AngularJS\s+v(\d+\.\d+\.\d+)'), "AngularJS"),
    (_re.compile(r'angular[.-]?(\d+\.\d+\.\d+)', _re.IGNORECASE), None, "AngularJS"),
    (None, _re.compile(r'Bootstrap\s+v(\d+\.\d+\.\d+)'), "Bootstrap"),
    (None, _re.compile(r'Vue\.js\s+v(\d+\.\d+\.\d+)'), "Vue.js"),
    (None, _re.compile(r'React\s+v(\d+\.\d+\.\d+)'), "React"),
    (_re.compile(r'moment[.-]?(\d+\.\d+\.\d+)', _re.IGNORECASE), None, "Moment.js"),
  ]
  _JS_EOL_LIBRARIES = {
    "AngularJS": "EOL since 2021-12-31",
    "Moment.js": "Deprecated — use date-fns or Luxon",
  }

  def _web_test_js_library_versions(self, target, port):
    """
    Detect client-side JavaScript libraries and flag EOL/deprecated ones.

    Version detection only — emits INFO findings with version data for LLM
    analysis to cross-reference against CVE databases. Only definitively EOL
    libraries (AngularJS, Moment.js) get MEDIUM severity.

    Parameters
    ----------
    target : str
    port : int

    Returns
    -------
    dict
    """
    findings_list = []
    raw = {"js_libraries": []}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    try:
      resp = requests.get(base_url, timeout=4, verify=False)
      if resp.status_code != 200:
        return probe_result(findings=findings_list)
      html = resp.text
      detected = {}  # lib_name → version

      # Check script src URLs for version in filename
      script_re = _re.compile(r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', _re.IGNORECASE)
      for match in script_re.finditer(html):
        src = match.group(1)
        for filename_re, _, lib_name in self._JS_LIB_PATTERNS:
          if filename_re and lib_name not in detected:
            ver_match = filename_re.search(src)
            if ver_match:
              detected[lib_name] = ver_match.group(1)

      # Check inline script content for version comments
      inline_re = _re.compile(r'<script[^>]*>(.*?)</script>', _re.IGNORECASE | _re.DOTALL)
      for match in inline_re.finditer(html[:50000]):
        content = match.group(1)
        for _, content_re, lib_name in self._JS_LIB_PATTERNS:
          if content_re and lib_name not in detected:
            ver_match = content_re.search(content)
            if ver_match:
              detected[lib_name] = ver_match.group(1)

      for lib_name, version in detected.items():
        raw["js_libraries"].append({"name": lib_name, "version": version})
        eol_note = self._JS_EOL_LIBRARIES.get(lib_name)
        if eol_note:
          findings_list.append(Finding(
            severity=Severity.MEDIUM,
            title=f"End-of-life JS library: {lib_name} {version}",
            description=f"{lib_name} {version} is {eol_note}. "
                        "No security patches are available.",
            evidence=f"Detected {lib_name} {version} in page source.",
            remediation=f"Migrate away from {lib_name} to a supported alternative.",
            owasp_id="A08:2021",
            cwe_id="CWE-1104",
            confidence="certain",
          ))
        else:
          findings_list.append(Finding(
            severity=Severity.INFO,
            title=f"JS library detected: {lib_name} {version}",
            description=f"{lib_name} {version} detected in page source.",
            evidence=f"Version {version} found via script tag analysis.",
            remediation="Keep client-side libraries updated.",
            owasp_id="A06:2021",
            cwe_id="CWE-200",
            confidence="certain",
          ))

    except Exception as e:
      self.P(f"JS library probe failed on {base_url}: {e}", color='y')
      return probe_error(target, port, "js_libs", e)

    return probe_result(raw_data=raw, findings=findings_list)
