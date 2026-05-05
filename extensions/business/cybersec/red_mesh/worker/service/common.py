import random
import re as _re
import socket
import struct
import ftplib
import requests
import ssl
from datetime import datetime

import paramiko

from ...findings import Finding, Severity, probe_result, probe_error
from ...cve_db import check_cves
from ..probe_registry import register_probe, CATEGORY_SERVICE_INFO
from ._base import _ServiceProbeBase

# Default credentials commonly found on exposed SSH services.
# Kept intentionally small — this is a quick check, not a brute-force.
_SSH_DEFAULT_CREDS = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "user"),
    ("test", "test"),
]

# Default credentials for FTP services.
_FTP_DEFAULT_CREDS = [
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "password"),
    ("ftp", "ftp"),
    ("user", "user"),
    ("test", "test"),
]

# Default credentials for Telnet services.
_TELNET_DEFAULT_CREDS = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("user", "user"),
    ("test", "test"),
]

_HTTP_SERVER_RE = _re.compile(
    r'(Apache|nginx)[/ ]+(\d+(?:\.\d+)+)', _re.IGNORECASE,
)
_HTTP_PRODUCT_MAP = {'apache': 'apache', 'nginx': 'nginx'}


class _ServiceCommonMixin(_ServiceProbeBase):
  """HTTP, FTP, SSH, SMTP, Telnet and Rsync service probes."""

  @register_probe(
    display_name="HTTP service detection",
    description=(
      "Banner-grab + GET / probe on HTTP. Captures Server header, "
      "title, X-Powered-By, and runs CVE checks for known web servers."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_http(self, target, port):  # default port: 80
    """
    Assess HTTP service: server fingerprint, technology detection,
    dangerous HTTP methods, and page title extraction.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    import re as _re

    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    result = {
      "banner": None,
      "server": None,
      "title": None,
      "technologies": [],
      "dangerous_methods": [],
    }

    # --- 1. GET request — banner, server, title, tech fingerprint ---
    try:
      self.P(f"Fetching {url} for banner...")
      ua = getattr(self, 'scanner_user_agent', '')
      headers = {'User-Agent': ua} if ua else {}
      resp = requests.get(url, timeout=5, verify=False, allow_redirects=True, headers=headers)

      result["banner"] = f"HTTP {resp.status_code} {resp.reason}"
      result["server"] = resp.headers.get("Server")
      if result["server"]:
        self._emit_metadata("server_versions", port, result["server"])
      if result["server"]:
        _m = _HTTP_SERVER_RE.search(result["server"])
        if _m:
          _cve_product = _HTTP_PRODUCT_MAP.get(_m.group(1).lower())
          if _cve_product:
            findings += check_cves(_cve_product, _m.group(2))
      powered_by = resp.headers.get("X-Powered-By")

      # Page title
      title_match = _re.search(
        r"<title>(.*?)</title>", resp.text[:5000], _re.IGNORECASE | _re.DOTALL
      )
      if title_match:
        result["title"] = title_match.group(1).strip()[:100]

      # Technology fingerprinting
      body_lower = resp.text[:8000].lower()
      tech_signatures = {
        "WordPress": ["wp-content", "wp-includes"],
        "Joomla": ["com_content", "/media/jui/"],
        "Drupal": ["drupal.js", "sites/default/files"],
        "Django": ["csrfmiddlewaretoken"],
        "PHP": [".php", "phpsessid"],
        "ASP.NET": ["__viewstate", ".aspx"],
        "React": ["_next/", "__next_data__", "react"],
      }
      techs = []
      if result["server"]:
        techs.append(result["server"])
      if powered_by:
        techs.append(powered_by)
      for tech, markers in tech_signatures.items():
        if any(m in body_lower for m in markers):
          techs.append(tech)
      result["technologies"] = techs

    except Exception as e:
      # HTTP library failed (e.g. empty reply, connection reset).
      # Fall back to raw socket probe — try HTTP/1.0 without Host header
      # (some servers like nginx drop requests with unrecognized Host values).
      try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _s.settimeout(3)
        _s.connect((target, port))
        # Use HTTP/1.0 without Host — matches nmap's GetRequest probe
        _s.send(b"GET / HTTP/1.0\r\n\r\n")
        _raw = b""
        while True:
          chunk = _s.recv(4096)
          if not chunk:
            break
          _raw += chunk
          if len(_raw) > 16384:
            break
        _s.close()
        _raw_str = _raw.decode("utf-8", errors="ignore")
        if _raw_str:
          lines = _raw_str.split("\r\n")
          result["banner"] = lines[0].strip() if lines else "unknown"
          for line in lines[1:]:
            low = line.lower()
            if low.startswith("server:"):
              result["server"] = line.split(":", 1)[1].strip()
              break
          # Report that the server drops Host-header requests
          findings.append(Finding(
            severity=Severity.INFO,
            title="HTTP service drops requests with Host header",
            description=f"TCP port {port} returns empty replies for standard HTTP/1.1 "
                        "requests but responds to HTTP/1.0 without a Host header. "
                        "This indicates a server_name mismatch or intentional filtering.",
            evidence=f"HTTP/1.1 with Host:{target} → empty reply; "
                     f"HTTP/1.0 without Host → {result['banner']}",
            remediation="Configure a proper default server block or virtual host.",
            cwe_id="CWE-200",
            confidence="certain",
          ))
          # Check for directory listing in response body
          body_start = _raw_str.find("\r\n\r\n")
          if body_start > -1:
            body = _raw_str[body_start + 4:]
            if "directory listing" in body.lower() or "<li><a href=" in body.lower():
              findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Directory listing enabled",
                description=f"Web server on port {port} has directory listing enabled, "
                            "exposing file and folder names to any visitor.",
                evidence=f"GET / returned HTML with directory listing content.",
                remediation="Disable directory listing (autoindex off in nginx).",
                owasp_id="A01:2021",
                cwe_id="CWE-548",
                confidence="certain",
              ))
            # Extract page title
            title_m = _re.search(r"<title>(.*?)</title>", body[:5000], _re.IGNORECASE | _re.DOTALL)
            if title_m:
              result["title"] = title_m.group(1).strip()[:100]
        else:
          result["banner"] = "(empty reply)"
          findings.append(Finding(
            severity=Severity.INFO,
            title="HTTP service returns empty reply",
            description=f"TCP port {port} accepts connections but the server "
                        "closes without sending any HTTP response data.",
            evidence=f"Raw socket to {target}:{port} — connected OK, received 0 bytes.",
            remediation="Investigate why the server sends empty replies; "
                        "verify proxy/upstream configuration.",
            cwe_id="CWE-200",
            confidence="certain",
          ))
      except Exception:
        return probe_error(target, port, "HTTP", e)
      return probe_result(raw_data=result, findings=findings)

    # --- 2. Dangerous HTTP methods ---
    dangerous = []
    for method in ("TRACE", "PUT", "DELETE"):
      try:
        r = requests.request(method, url, timeout=3, verify=False)
        if r.status_code < 400:
          dangerous.append(method)
      except Exception:
        pass

    result["dangerous_methods"] = dangerous
    if "TRACE" in dangerous:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title="HTTP TRACE method enabled (cross-site tracing / XST attack vector).",
        description="TRACE echoes request bodies back, enabling cross-site tracing attacks.",
        evidence=f"TRACE {url} returned status < 400.",
        remediation="Disable the TRACE method in the web server configuration.",
        owasp_id="A05:2021",
        cwe_id="CWE-693",
        confidence="certain",
      ))
    if "PUT" in dangerous:
      findings.append(Finding(
        severity=Severity.HIGH,
        title="HTTP PUT method enabled (potential unauthorized file upload).",
        description="The PUT method allows uploading files to the server.",
        evidence=f"PUT {url} returned status < 400.",
        remediation="Disable the PUT method or restrict it to authenticated users.",
        owasp_id="A01:2021",
        cwe_id="CWE-749",
        confidence="certain",
      ))
    if "DELETE" in dangerous:
      findings.append(Finding(
        severity=Severity.HIGH,
        title="HTTP DELETE method enabled (potential unauthorized file deletion).",
        description="The DELETE method allows removing resources from the server.",
        evidence=f"DELETE {url} returned status < 400.",
        remediation="Disable the DELETE method or restrict it to authenticated users.",
        owasp_id="A01:2021",
        cwe_id="CWE-749",
        confidence="certain",
      ))

    return probe_result(raw_data=result, findings=findings)


  @register_probe(
    display_name="HTTP service detection (alt port)",
    description="HTTP probe targeting common alternate ports (8080, 8000, 8888, etc.).",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_http_alt(self, target, port):  # default port: 8080
    """
    Probe alternate HTTP port 8080 for verbose banners.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    # Skip standard HTTP ports — they are covered by _service_info_http.
    if port in (80, 443):
      return None

    findings = []
    raw = {"banner": None, "server": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      ua = getattr(self, 'scanner_user_agent', '')
      ua_header = f"\r\nUser-Agent: {ua}" if ua else ""
      msg = "HEAD / HTTP/1.1\r\nHost: {}{}\r\n\r\n".format(target, ua_header).encode('utf-8')
      sock.send(bytes(msg))
      data = sock.recv(1024).decode('utf-8', errors='ignore')
      sock.close()

      if data:
        # Extract status line and Server header instead of dumping raw bytes
        lines = data.split("\r\n")
        status_line = lines[0].strip() if lines else "unknown"
        raw["banner"] = status_line
        for line in lines[1:]:
          if line.lower().startswith("server:"):
            raw["server"] = line.split(":", 1)[1].strip()
            break

        # NOTE: CVE matching intentionally omitted here — _service_info_http
        # already handles CVE lookups for all HTTP ports.  Emitting them here
        # caused duplicate findings on non-standard ports (batch 3 dedup fix).
    except Exception as e:
      return probe_error(target, port, "HTTP-ALT", e)
    return probe_result(raw_data=raw, findings=findings)


  @register_probe(
    display_name="HTTPS service detection",
    description="HTTPS probe with TLS handshake, GET / over TLS, banner extraction.",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_https(self, target, port):  # default port: 443
    """
    Collect HTTPS response banner data for TLS services.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    findings = []
    raw = {"banner": None, "server": None}
    try:
      url = f"https://{target}"
      if port != 443:
        url = f"https://{target}:{port}"
      self.P(f"Fetching {url} for banner...")
      ua = getattr(self, 'scanner_user_agent', '')
      headers = {'User-Agent': ua} if ua else {}
      resp = requests.get(url, timeout=3, verify=False, headers=headers)
      raw["banner"] = f"HTTPS {resp.status_code} {resp.reason}"
      raw["server"] = resp.headers.get("Server")
      if raw["server"]:
        _m = _HTTP_SERVER_RE.search(raw["server"])
        if _m:
          _cve_product = _HTTP_PRODUCT_MAP.get(_m.group(1).lower())
          if _cve_product:
            findings += check_cves(_cve_product, _m.group(2))
      findings.append(Finding(
        severity=Severity.INFO,
        title=f"HTTPS service detected ({resp.status_code} {resp.reason})",
        description=f"HTTPS service on {target}:{port}.",
        evidence=f"Server: {raw['server'] or 'not disclosed'}",
        confidence="certain",
      ))
    except Exception as e:
      return probe_error(target, port, "HTTPS", e)
    return probe_result(raw_data=raw, findings=findings)


  # Default credentials for HTTP Basic Auth testing
  _HTTP_BASIC_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("root", "root"), ("root", "password"), ("root", "toor"),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("admin", ""), ("tomcat", "tomcat"), ("manager", "manager"),
  ]

  @register_probe(
    display_name="HTTP Basic Auth credential check",
    description=(
      "Tests known weak credentials against HTTP Basic Auth-protected "
      "URLs (admin panels, embedded device interfaces, etc.)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(521, 798),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
  def _service_info_http_basic_auth(self, target, port):
    """
    Test HTTP Basic Auth endpoints for default/weak credentials.

    Only runs when the target responds with 401 + WWW-Authenticate: Basic.
    Tests a small set of default credential pairs.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict or None
      Structured findings, or None if no Basic Auth detected.
    """
    findings = []
    raw = {"basic_auth_detected": False, "tested": 0, "accepted": []}
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    # Probe / and /admin for 401 + Basic auth
    auth_url = None
    realm = None
    for path in ("/", "/admin", "/manager"):
      try:
        resp = requests.get(base_url + path, timeout=3, verify=False)
        if resp.status_code == 401:
          www_auth = resp.headers.get("WWW-Authenticate", "")
          if "Basic" in www_auth:
            auth_url = base_url + path
            realm_match = _re.search(r'realm="?([^"]*)"?', www_auth, _re.IGNORECASE)
            realm = realm_match.group(1) if realm_match else "unknown"
            break
      except Exception:
        continue

    if not auth_url:
      return None  # No Basic auth detected — skip entirely

    raw["basic_auth_detected"] = True
    raw["realm"] = realm

    # Test credentials
    consecutive_401 = 0
    for username, password in self._HTTP_BASIC_CREDS:
      try:
        resp = requests.get(auth_url, timeout=3, verify=False, auth=(username, password))
        raw["tested"] += 1

        if resp.status_code == 429:
          break  # rate limited — stop

        if resp.status_code == 200 or resp.status_code == 301 or resp.status_code == 302:
          cred_str = f"{username}:{password}" if password else f"{username}:(empty)"
          raw["accepted"].append(cred_str)
          findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"HTTP Basic Auth default credential: {cred_str}",
            description=f"The web server at {auth_url} (realm: {realm}) accepted a default credential.",
            evidence=f"GET {auth_url} with {cred_str} → HTTP {resp.status_code}",
            remediation="Change default credentials immediately.",
            owasp_id="A07:2021",
            cwe_id="CWE-798",
            confidence="certain",
          ))
        elif resp.status_code == 401:
          consecutive_401 += 1
      except Exception:
        break

    # No rate limiting after all attempts
    if consecutive_401 >= len(self._HTTP_BASIC_CREDS) - 1:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title=f"HTTP Basic Auth has no rate limiting ({raw['tested']} attempts accepted)",
        description="The server does not rate-limit failed authentication attempts.",
        evidence=f"{consecutive_401} consecutive 401 responses without rate limiting.",
        remediation="Implement account lockout or rate limiting for failed auth attempts.",
        owasp_id="A07:2021",
        cwe_id="CWE-307",
        confidence="firm",
      ))

    return probe_result(raw_data=raw, findings=findings)


  @register_probe(
    display_name="FTP service detection",
    description=(
      "FTP banner / features / anonymous-login / write-access probes. "
      "Detects exposed FTP, anonymous read/write, missing FTPS."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 319),
    default_owasp=("A02:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_ftp(self, target, port):  # default port: 21
    """
    Assess FTP service security: banner, anonymous access, default creds,
    server fingerprint, TLS support, write access, and credential validation.

    Checks performed (in order):

    1. Banner grab and SYST/FEAT fingerprint.
    2. Anonymous login attempt.
    3. Write access test (STOR) after anonymous login.
    4. Directory listing and traversal.
    5. TLS support check (AUTH TLS).
    6. Default credential check.
    7. Arbitrary credential acceptance test.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings with banner, vulnerabilities, server_info, etc.
    """
    findings = []
    result = {
      "banner": None,
      "server_type": None,
      "features": [],
      "anonymous_access": False,
      "write_access": False,
      "tls_supported": False,
      "accepted_credentials": [],
      "directory_listing": None,
    }

    def _ftp_connect(user=None, passwd=None):
      """Open a fresh FTP connection and optionally login."""
      ftp = ftplib.FTP(timeout=5)
      ftp.connect(target, port, timeout=5)
      if user is not None:
        ftp.login(user, passwd or "")
      return ftp

    # --- 1. Banner grab ---
    try:
      ftp = _ftp_connect()
      result["banner"] = ftp.getwelcome()
    except Exception as e:
      return probe_error(target, port, "FTP", e)

    # FTP server version CVE check
    _ftp_m = _re.search(
      r'(ProFTPD|vsftpd)[/ ]+(\d+(?:\.\d+)+)',
      result["banner"], _re.IGNORECASE,
    )
    if _ftp_m:
      _cve_product = {'proftpd': 'proftpd', 'vsftpd': 'vsftpd'}.get(_ftp_m.group(1).lower())
      if _cve_product:
        findings += check_cves(_cve_product, _ftp_m.group(2))

    # --- 2. Anonymous login ---
    try:
      resp = ftp.login()
      result["anonymous_access"] = True
      findings.append(Finding(
        severity=Severity.HIGH,
        title="FTP allows anonymous login.",
        description="The FTP server permits unauthenticated access via anonymous login.",
        evidence="Anonymous login succeeded.",
        remediation="Disable anonymous FTP access unless explicitly required.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))
    except Exception:
      # Anonymous failed — close and move on to credential tests
      try:
        ftp.quit()
      except Exception:
        pass
      ftp = None

    # --- 2b. SYST / FEAT (after login — some servers require auth first) ---
    if ftp:
      try:
        syst = ftp.sendcmd("SYST")
        result["server_type"] = syst
      except Exception:
        pass

      try:
        feat_resp = ftp.sendcmd("FEAT")
        feats = [
          line.strip() for line in feat_resp.split("\n")
          if line.strip() and not line.startswith("211")
        ]
        result["features"] = feats
      except Exception:
        pass

    # --- 2c. PASV IP leak check ---
    if ftp and result["anonymous_access"]:
      try:
        pasv_resp = ftp.sendcmd("PASV")
        _pasv_match = _re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv_resp)
        if _pasv_match:
          pasv_ip = f"{_pasv_match.group(1)}.{_pasv_match.group(2)}.{_pasv_match.group(3)}.{_pasv_match.group(4)}"
          if pasv_ip != target:
            import ipaddress as _ipaddress
            try:
              if _ipaddress.ip_address(pasv_ip).is_private:
                result["pasv_ip"] = pasv_ip
                self._emit_metadata("internal_ips", {"ip": pasv_ip, "source": f"ftp_pasv:{port}"})
                findings.append(Finding(
                  severity=Severity.MEDIUM,
                  title=f"FTP PASV leaks internal IP: {pasv_ip}",
                  description=f"PASV response reveals RFC1918 address {pasv_ip}, different from target {target}.",
                  evidence=f"PASV response: {pasv_resp}",
                  remediation="Configure FTP passive address masquerading to use the public IP.",
                  owasp_id="A05:2021",
                  cwe_id="CWE-200",
                  confidence="certain",
                ))
            except (ValueError, TypeError):
              pass
      except Exception:
        pass

    # --- 3. Write access test (only if anonymous login succeeded) ---
    if ftp and result["anonymous_access"]:
      import io
      try:
        ftp.set_pasv(True)
        test_data = io.BytesIO(b"RedMesh write access probe")
        resp = ftp.storbinary("STOR __redmesh_probe.txt", test_data)
        if resp and resp.startswith("226"):
          result["write_access"] = True
          findings.append(Finding(
            severity=Severity.CRITICAL,
            title="FTP anonymous write access enabled (file upload possible).",
            description="Anonymous users can upload files to the FTP server.",
            evidence="STOR command succeeded with anonymous session.",
            remediation="Remove write permissions for anonymous FTP users.",
            owasp_id="A01:2021",
            cwe_id="CWE-434",
            confidence="certain",
          ))
          try:
            ftp.delete("__redmesh_probe.txt")
          except Exception:
            pass
      except Exception:
        pass

    # --- 4. Directory listing and traversal ---
    if ftp:
      try:
        pwd = ftp.pwd()
        files = []
        try:
          ftp.retrlines("LIST", files.append)
        except Exception:
          pass
        if files:
          result["directory_listing"] = files[:20]
      except Exception:
        pass

      # Check if CWD allows directory traversal
      for test_dir in ["/etc", "/var", ".."]:
        try:
          resp = ftp.cwd(test_dir)
          if resp and (resp.startswith("250") or resp.startswith("200")):
            findings.append(Finding(
              severity=Severity.HIGH,
              title=f"FTP directory traversal: CWD to '{test_dir}' succeeded.",
              description="The FTP server allows changing to directories outside the intended root.",
              evidence=f"CWD '{test_dir}' returned: {resp}",
              remediation="Restrict FTP users to their home directory (chroot).",
              owasp_id="A01:2021",
              cwe_id="CWE-22",
              confidence="certain",
            ))
            break
        except Exception:
          pass
      try:
        ftp.cwd("/")
      except Exception:
        pass

    if ftp:
      try:
        ftp.quit()
      except Exception:
        pass

    # --- 5. TLS support check ---
    try:
      ftp_tls = _ftp_connect()
      resp = ftp_tls.sendcmd("AUTH TLS")
      if resp.startswith("234"):
        result["tls_supported"] = True
      try:
        ftp_tls.quit()
      except Exception:
        pass
    except Exception:
      if not result["tls_supported"]:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="FTP does not support TLS encryption (cleartext credentials).",
          description="Credentials and data are transmitted in cleartext over the network.",
          evidence="AUTH TLS command rejected or not supported.",
          remediation="Enable FTPS (AUTH TLS) or migrate to SFTP.",
          owasp_id="A02:2021",
          cwe_id="CWE-319",
          confidence="certain",
        ))

    # --- 6. Default credential check ---
    for user, passwd in _FTP_DEFAULT_CREDS:
      try:
        ftp_cred = _ftp_connect(user, passwd)
        result["accepted_credentials"].append(f"{user}:{passwd}")
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title=f"FTP default credential accepted: {user}:{passwd}",
          description="The FTP server accepted a well-known default credential.",
          evidence=f"Accepted credential: {user}:{passwd}",
          remediation="Change default passwords and enforce strong credential policies.",
          owasp_id="A07:2021",
          cwe_id="CWE-798",
          confidence="certain",
        ))
        try:
          ftp_cred.quit()
        except Exception:
          pass
      except (ftplib.error_perm, ftplib.error_reply):
        pass
      except Exception:
        pass

    # --- 7. Arbitrary credential acceptance test ---
    import string as _string
    ruser = "".join(random.choices(_string.ascii_lowercase, k=8))
    rpass = "".join(random.choices(_string.ascii_letters + _string.digits, k=12))
    try:
      ftp_rand = _ftp_connect(ruser, rpass)
      findings.append(Finding(
        severity=Severity.CRITICAL,
        title="FTP accepts arbitrary credentials",
        description="Random credentials were accepted, indicating a dangerous misconfiguration or deceptive service.",
        evidence=f"Accepted random creds {ruser}:{rpass}",
        remediation="Investigate immediately — authentication is non-functional.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))
      try:
        ftp_rand.quit()
      except Exception:
        pass
    except (ftplib.error_perm, ftplib.error_reply):
      pass
    except Exception:
      pass

    return probe_result(raw_data=result, findings=findings)

  @register_probe(
    display_name="SSH service detection",
    description=(
      "Banner-grab + KEX inspection: SSH version, library "
      "(OpenSSH/libssh/Dropbear/Erlang/Paramiko), weak algorithms, "
      "auth methods. Runs CVE checks (incl. libssh CVE-2018-10933, "
      "Erlang SSH CVE-2025-32433)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(326, 327),
    default_owasp=("A02:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_ssh(self, target, port):  # default port: 22
    """
    Assess SSH service security: banner, auth methods, and default credentials.

    Checks performed (in order):

    1. Banner grab — fingerprint server version.
    2. Auth method enumeration — identify if password auth is enabled.
    3. Default credential check — try a small list of common creds.
    4. Arbitrary credential acceptance test.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings with banner, auth_methods, and vulnerabilities.
    """
    findings = []
    result = {
      "banner": None,
      "auth_methods": [],
    }

    # --- 1. Banner grab (raw socket) ---
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
      sock.close()
      result["banner"] = banner
      # Emit OS claim from SSH banner (e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
      _os_match = _re.search(r'(Ubuntu|Debian|Fedora|CentOS|Alpine|FreeBSD)', banner, _re.IGNORECASE)
      if _os_match:
        self._emit_metadata("os_claims", f"ssh:{port}", _os_match.group(1))
    except Exception as e:
      return probe_error(target, port, "SSH", e)

    # --- 2. Auth method enumeration via paramiko Transport ---
    try:
      transport = paramiko.Transport((target, port))
      transport.connect()
      try:
        transport.auth_none("")
      except paramiko.BadAuthenticationType as e:
        result["auth_methods"] = list(e.allowed_types)
      except paramiko.AuthenticationException:
        result["auth_methods"] = ["unknown"]
      finally:
        transport.close()
    except Exception as e:
      self.P(f"SSH auth enumeration failed on {target}:{port}: {e}", color='y')

    if "password" in result["auth_methods"]:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title="SSH password authentication is enabled (prefer key-based auth).",
        description="The SSH server allows password-based login, which is susceptible to brute-force attacks.",
        evidence=f"Auth methods: {', '.join(result['auth_methods'])}",
        remediation="Disable PasswordAuthentication in sshd_config and use key-based auth.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))

    # --- 3. Default credential check ---
    accepted_creds = []

    for username, password in _SSH_DEFAULT_CREDS:
      try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
          target, port=port,
          username=username, password=password,
          timeout=3, auth_timeout=3,
          look_for_keys=False, allow_agent=False,
        )
        accepted_creds.append(f"{username}:{password}")
        client.close()
      except paramiko.AuthenticationException:
        continue
      except Exception:
        break  # connection issue, stop trying

    # --- 4. Arbitrary credential acceptance test ---
    random_user = f"probe_{random.randint(10000, 99999)}"
    random_pass = f"rnd_{random.randint(10000, 99999)}"
    try:
      client = paramiko.SSHClient()
      client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      client.connect(
        target, port=port,
        username=random_user, password=random_pass,
        timeout=3, auth_timeout=3,
        look_for_keys=False, allow_agent=False,
      )
      findings.append(Finding(
        severity=Severity.CRITICAL,
        title="SSH accepts arbitrary credentials",
        description="Random credentials were accepted, indicating a dangerous misconfiguration or deceptive service.",
        evidence=f"Accepted random creds {random_user}:{random_pass}",
        remediation="Investigate immediately — authentication is non-functional.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))
      client.close()
    except paramiko.AuthenticationException:
      pass
    except Exception:
      pass

    if accepted_creds:
      result["accepted_credentials"] = accepted_creds
      for cred in accepted_creds:
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title=f"SSH default credential accepted: {cred}",
          description=f"The SSH server accepted a well-known default credential.",
          evidence=f"Accepted credential: {cred}",
          remediation="Change default passwords immediately and enforce strong credential policies.",
          owasp_id="A07:2021",
          cwe_id="CWE-798",
          confidence="certain",
        ))

    # --- 5. Cipher/KEX audit ---
    cipher_findings, weak_labels = self._ssh_check_ciphers(target, port)
    findings += cipher_findings
    result["weak_algorithms"] = weak_labels

    # --- 6. CVE check on banner version ---
    if result["banner"]:
      ssh_lib, ssh_version = self._ssh_identify_library(result["banner"])
      if ssh_lib and ssh_version:
        result["ssh_library"] = ssh_lib
        result["ssh_version"] = ssh_version
        findings += check_cves(ssh_lib, ssh_version)

        # --- 7. libssh auth bypass (CVE-2018-10933) ---
        if ssh_lib == "libssh":
          bypass = self._ssh_check_libssh_bypass(target, port)
          if bypass:
            findings.append(bypass)

    return probe_result(raw_data=result, findings=findings)

  # Patterns: (regex, product_name_for_cve_db)
  _SSH_LIBRARY_PATTERNS = [
    (_re.compile(r'OpenSSH[_\s](\d+\.\d+(?:\.\d+)?)', _re.IGNORECASE), "openssh"),
    (_re.compile(r'libssh[_\s-](\d+\.\d+(?:\.\d+)?)', _re.IGNORECASE), "libssh"),
    (_re.compile(r'dropbear[_\s](\d+(?:\.\d+)*)', _re.IGNORECASE), "dropbear"),
    (_re.compile(r'paramiko[_\s](\d+\.\d+(?:\.\d+)?)', _re.IGNORECASE), "paramiko"),
    (_re.compile(r'Erlang[/\s](?:OTP[_/\s]*)?(\d+\.\d+(?:\.\d+)*)', _re.IGNORECASE), "erlang_ssh"),
  ]

  def _ssh_identify_library(self, banner):
    """Identify SSH library and version from banner string.

    Returns
    -------
    tuple[str | None, str | None]
      (product_name, version) — product_name matches cve_db product keys.
    """
    for pattern, product in self._SSH_LIBRARY_PATTERNS:
      m = pattern.search(banner)
      if m:
        return product, m.group(1)
    return None, None

  def _ssh_check_ciphers(self, target, port):
    """Audit SSH ciphers, KEX, and MACs via paramiko Transport.

    Returns
    -------
    tuple[list[Finding], list[str]]
      (findings, weak_algorithm_labels) — findings for probe_result,
      labels for the raw-data ``weak_algorithms`` field.
    """
    findings = []
    weak_labels = []
    _WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "arcfour", "arcfour128", "arcfour256",
                     "aes128-cbc", "aes192-cbc", "aes256-cbc", "cast128-cbc"}
    _WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                 "diffie-hellman-group-exchange-sha1"}

    try:
      transport = paramiko.Transport((target, port))
      transport.connect()
      sec_opts = transport.get_security_options()

      ciphers = set(sec_opts.ciphers) if sec_opts.ciphers else set()
      kex = set(sec_opts.kex) if sec_opts.kex else set()
      key_types = set(sec_opts.key_types) if sec_opts.key_types else set()

      # RSA key size check — must be done before transport.close()
      try:
        remote_key = transport.get_remote_server_key()
        if remote_key is not None and remote_key.get_name() == "ssh-rsa":
          key_bits = remote_key.get_bits()
          if key_bits < 2048:
            findings.append(Finding(
              severity=Severity.HIGH,
              title=f"SSH RSA key is critically weak ({key_bits}-bit)",
              description=f"The server's RSA host key is only {key_bits}-bit, which is trivially factorable.",
              evidence=f"RSA key size: {key_bits} bits",
              remediation="Generate a new RSA key of at least 3072 bits, or switch to Ed25519.",
              owasp_id="A02:2021",
              cwe_id="CWE-326",
              confidence="certain",
            ))
            weak_labels.append(f"rsa_key: {key_bits}-bit")
          elif key_bits < 3072:
            findings.append(Finding(
              severity=Severity.LOW,
              title=f"SSH RSA key below NIST recommendation ({key_bits}-bit)",
              description=f"The server's RSA host key is {key_bits}-bit. NIST recommends >=3072-bit after 2023.",
              evidence=f"RSA key size: {key_bits} bits",
              remediation="Generate a new RSA key of at least 3072 bits, or switch to Ed25519.",
              owasp_id="A02:2021",
              cwe_id="CWE-326",
              confidence="certain",
            ))
            weak_labels.append(f"rsa_key: {key_bits}-bit")
      except Exception:
        pass

      transport.close()

      # DSA key detection
      if "ssh-dss" in key_types:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="SSH DSA host key offered (ssh-dss)",
          description="The SSH server offers DSA host keys, which are limited to 1024-bit and considered weak.",
          evidence=f"Key types: {', '.join(sorted(key_types))}",
          remediation="Remove DSA host keys and use Ed25519 or RSA (>=3072-bit) instead.",
          owasp_id="A02:2021",
          cwe_id="CWE-326",
          confidence="certain",
        ))
        weak_labels.append("key_types: ssh-dss")

      weak_ciphers = ciphers & _WEAK_CIPHERS
      weak_kex = kex & _WEAK_KEX

      if weak_ciphers:
        cipher_list = ", ".join(sorted(weak_ciphers))
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"SSH weak ciphers: {cipher_list}",
          description="The SSH server offers ciphers considered cryptographically weak.",
          evidence=f"Weak ciphers offered: {cipher_list}",
          remediation="Disable CBC-mode and RC4 ciphers in sshd_config.",
          owasp_id="A02:2021",
          cwe_id="CWE-326",
          confidence="certain",
        ))
        weak_labels.append(f"ciphers: {cipher_list}")

      if weak_kex:
        kex_list = ", ".join(sorted(weak_kex))
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"SSH weak key exchange: {kex_list}",
          description="The SSH server offers key-exchange algorithms with known weaknesses.",
          evidence=f"Weak KEX offered: {kex_list}",
          remediation="Disable SHA-1 based key exchange algorithms in sshd_config.",
          owasp_id="A02:2021",
          cwe_id="CWE-326",
          confidence="certain",
        ))
        weak_labels.append(f"kex: {kex_list}")

    except Exception as e:
      self.P(f"SSH cipher audit failed on {target}:{port}: {e}", color='y')

    return findings, weak_labels

  def _ssh_check_libssh_bypass(self, target, port):
    """Test CVE-2018-10933: libssh auth bypass via premature USERAUTH_SUCCESS.

    Affected versions: libssh 0.6.0–0.8.3 (fixed in 0.7.6 / 0.8.4).
    The vulnerability allows a client to send SSH2_MSG_USERAUTH_SUCCESS (52)
    instead of a proper auth request, and the server accepts it.

    Returns
    -------
    Finding or None
    """
    try:
      transport = paramiko.Transport((target, port))
      transport.connect()
      # SSH2_MSG_USERAUTH_SUCCESS = 52 (0x34)
      msg = paramiko.Message()
      msg.add_byte(b'\x34')
      transport._send_message(msg)
      try:
        chan = transport.open_session(timeout=3)
        if chan is not None:
          chan.close()
          transport.close()
          return Finding(
            severity=Severity.CRITICAL,
            title="libssh auth bypass (CVE-2018-10933)",
            description="Server accepted SSH2_MSG_USERAUTH_SUCCESS from client, "
                        "bypassing authentication entirely. Full shell access possible.",
            evidence="Session channel opened after sending USERAUTH_SUCCESS.",
            remediation="Upgrade libssh to >= 0.8.4 or >= 0.7.6.",
            owasp_id="A07:2021",
            cwe_id="CWE-287",
            confidence="certain",
          )
      except Exception:
        pass
      transport.close()
    except Exception as e:
      self.P(f"libssh bypass check failed on {target}:{port}: {e}", color='y')
    return None

  @register_probe(
    display_name="SMTP service detection",
    description=(
      "EHLO / HELP / VRFY / EXPN probes against SMTP. Detects "
      "open relay, user enumeration, missing STARTTLS."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 319),
    default_owasp=("A02:2021", "A05:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
  )
  def _service_info_smtp(self, target, port):  # default port: 25
    """
    Assess SMTP service security: banner, EHLO features, STARTTLS,
    authentication methods, open relay, and user enumeration.

    Checks performed (in order):

    1. Banner grab — fingerprint MTA software and version.
    2. EHLO — enumerate server capabilities (SIZE, AUTH, STARTTLS, etc.).
    3. STARTTLS support — check for encryption.
    4. AUTH methods — detect available authentication mechanisms.
    5. Open relay test — attempt MAIL FROM / RCPT TO without auth.
    6. VRFY / EXPN — test user enumeration commands.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    import smtplib

    findings = []
    result = {
      "banner": None,
      "server_hostname": None,
      "max_message_size": None,
      "auth_methods": [],
    }

    # --- 1. Connect and grab banner ---
    try:
      smtp = smtplib.SMTP(timeout=5)
      code, msg = smtp.connect(target, port)
      result["banner"] = f"{code} {msg.decode(errors='replace')}"
    except Exception as e:
      return probe_error(target, port, "SMTP", e)

    # --- 2. EHLO — server capabilities ---
    identity = getattr(self, 'scanner_identity', 'probe.redmesh.local')
    ehlo_features = []
    try:
      code, msg = smtp.ehlo(identity)
      if code == 250:
        for line in msg.decode(errors="replace").split("\n"):
          feat = line.strip()
          if feat:
            ehlo_features.append(feat)
    except Exception:
      # Fallback to HELO
      try:
        smtp.helo(identity)
      except Exception:
        pass

    # Parse meaningful fields from EHLO response
    for idx, feat in enumerate(ehlo_features):
      upper = feat.upper()
      if idx == 0 and " Hello " in feat:
        # First line is the server greeting: "hostname Hello client [ip]"
        result["server_hostname"] = feat.split()[0]
      if upper.startswith("SIZE "):
        try:
          size_bytes = int(feat.split()[1])
          result["max_message_size"] = f"{size_bytes // (1024*1024)}MB"
        except (ValueError, IndexError):
          pass
      if upper.startswith("AUTH "):
        result["auth_methods"] = feat.split()[1:]

    # --- 2b. Banner timezone extraction ---
    banner_text = result["banner"] or ""
    _tz_match = _re.search(r'([+-]\d{4})\s*$', banner_text)
    if _tz_match:
      self._emit_metadata("timezone_hints", {"offset": _tz_match.group(1), "source": f"smtp:{port}"})

    # --- 2c. Banner / hostname information disclosure ---
    # Extract MTA version from banner (e.g. "Exim 4.97", "Postfix", "Sendmail 8.x")
    version_match = _re.search(
      r"(Exim|Postfix|Sendmail|Microsoft ESMTP|hMailServer|Haraka|OpenSMTPD)"
      r"[\s/]*([0-9][0-9.]*)?",
      banner_text, _re.IGNORECASE,
    )
    if version_match:
      mta = version_match.group(0).strip()
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"SMTP banner discloses MTA software: {mta} (aids CVE lookup).",
        description="The SMTP banner reveals the mail transfer agent software and version.",
        evidence=f"Banner: {banner_text[:120]}",
        remediation="Remove or genericize the SMTP banner to hide MTA version details.",
        owasp_id="A05:2021",
        cwe_id="CWE-200",
        confidence="certain",
      ))

    # CVE check on extracted MTA version
    _smtp_product_map = {'exim': 'exim', 'postfix': 'postfix', 'opensmtpd': 'opensmtpd'}
    _mta_version = version_match.group(2) if version_match and version_match.group(2) else None
    _mta_name = version_match.group(1).lower() if version_match else None

    # If banner lacks version (common with OpenSMTPD), try HELP command
    if version_match and not _mta_version:
      try:
        code, msg = smtp.docmd("HELP")
        help_text = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
        _help_ver = _re.search(r'(\d+\.\d+(?:\.\d+)*(?:p\d+)?)', help_text)
        if _help_ver:
          _mta_version = _help_ver.group(1)
      except Exception:
        pass

    if _mta_name and _mta_version:
      _cve_product = _smtp_product_map.get(_mta_name)
      if _cve_product:
        findings += check_cves(_cve_product, _mta_version)

    if result["server_hostname"]:
      # Check if hostname reveals container/internal info
      hostname = result["server_hostname"]
      if _re.search(r"[0-9a-f]{12}", hostname):
        self._emit_metadata("container_ids", {"id": hostname, "source": f"smtp:{port}"})
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"SMTP hostname leaks container ID: {hostname} (infrastructure disclosure).",
          description="The EHLO response reveals a container ID or internal hostname.",
          evidence=f"Hostname: {hostname}",
          remediation="Configure the SMTP server to use a proper FQDN instead of the container ID.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="firm",
        ))
      if _re.match(r'^[a-z0-9-]+-[a-z0-9]{8,10}$', hostname):
        self._emit_metadata("container_ids", {"id": hostname, "source": f"smtp_k8s:{port}"})
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"SMTP hostname matches Kubernetes pod name pattern: {hostname}",
          description="The EHLO hostname resembles a Kubernetes pod name (deployment-replicaset-podid).",
          evidence=f"Hostname: {hostname}",
          remediation="Configure the SMTP server to use a proper FQDN instead of the pod name.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="firm",
        ))
      if hostname.endswith('.internal'):
        self._emit_metadata("container_ids", {"id": hostname, "source": f"smtp_internal:{port}"})
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"SMTP hostname uses cloud-internal DNS suffix: {hostname}",
          description="The EHLO hostname ends with '.internal', indicating AWS/GCP internal DNS.",
          evidence=f"Hostname: {hostname}",
          remediation="Configure the SMTP server to use a public FQDN instead of internal DNS.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="firm",
        ))

    # --- 3. STARTTLS ---
    starttls_supported = any("STARTTLS" in f.upper() for f in ehlo_features)
    if not starttls_supported:
      try:
        code, msg = smtp.docmd("STARTTLS")
        if code == 220:
          starttls_supported = True
      except Exception:
        pass

    if not starttls_supported:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title="SMTP does not support STARTTLS (credentials sent in cleartext).",
        description="The SMTP server does not offer STARTTLS, leaving credentials and mail unencrypted.",
        evidence="STARTTLS not listed in EHLO features and STARTTLS command rejected.",
        remediation="Enable STARTTLS support on the SMTP server.",
        owasp_id="A02:2021",
        cwe_id="CWE-319",
        confidence="certain",
      ))

    # --- 4. AUTH without credentials ---
    if result["auth_methods"]:
      try:
        code, msg = smtp.docmd("AUTH LOGIN")
        if code == 235:
          findings.append(Finding(
            severity=Severity.HIGH,
            title="SMTP AUTH LOGIN accepted without credentials.",
            description="The SMTP server accepted AUTH LOGIN without providing actual credentials.",
            evidence=f"AUTH LOGIN returned code {code}.",
            remediation="Fix AUTH configuration to require valid credentials.",
            owasp_id="A07:2021",
            cwe_id="CWE-287",
            confidence="certain",
          ))
      except Exception:
        pass

    # --- 5. Open relay test ---
    try:
      smtp.rset()
    except Exception:
      try:
        smtp.quit()
      except Exception:
        pass
      try:
        smtp = smtplib.SMTP(target, port, timeout=5)
        smtp.ehlo(identity)
      except Exception:
        smtp = None

    if smtp:
      try:
        code_from, _ = smtp.docmd(f"MAIL FROM:<probe@{identity}>")
        if code_from == 250:
          code_rcpt, _ = smtp.docmd("RCPT TO:<probe@external-domain.test>")
          if code_rcpt == 250:
            findings.append(Finding(
              severity=Severity.HIGH,
              title="SMTP open relay detected (accepts mail to external domains without auth).",
              description="The SMTP server relays mail to external domains without authentication.",
              evidence="RCPT TO:<probe@external-domain.test> accepted (code 250).",
              remediation="Configure SMTP relay restrictions to require authentication.",
              owasp_id="A01:2021",
              cwe_id="CWE-284",
              confidence="certain",
            ))
          smtp.docmd("RSET")
      except Exception:
        pass

    # --- 6. VRFY / EXPN ---
    if smtp:
      for cmd_name in ("VRFY", "EXPN"):
        try:
          code, msg = smtp.docmd(cmd_name, "root")
          if code in (250, 251, 252):
            findings.append(Finding(
              severity=Severity.MEDIUM,
              title=f"SMTP {cmd_name} command enabled (user enumeration possible).",
              description=f"The {cmd_name} command can be used to enumerate valid users on the system.",
              evidence=f"{cmd_name} root returned code {code}.",
              remediation=f"Disable the {cmd_name} command in the SMTP server configuration.",
              owasp_id="A01:2021",
              cwe_id="CWE-203",
              confidence="certain",
            ))
        except Exception:
          pass

    if smtp:
      try:
        smtp.quit()
      except Exception:
        pass

    return probe_result(raw_data=result, findings=findings)

  @register_probe(
    display_name="Telnet service detection",
    description=(
      "Telnet negotiation + login banner probe. Detects unencrypted "
      "remote-shell exposure (always a finding) and anonymous login."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(319, 287),
    default_owasp=("A02:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
  def _service_info_telnet(self, target, port):  # default port: 23
    """
    Assess Telnet service security: banner, negotiation options, default
    credentials, privilege level, system fingerprint, and credential validation.

    Checks performed (in order):

    1. Banner grab and IAC option parsing.
    2. Default credential check — try common user:pass combos.
    3. Privilege escalation check — report if root shell is obtained.
    4. System fingerprint — run ``id`` and ``uname -a`` on successful login.
    5. Arbitrary credential acceptance test.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    import time as _time

    findings = []
    result = {
      "banner": None,
      "negotiation_options": [],
      "accepted_credentials": [],
      "system_info": None,
    }

    findings.append(Finding(
      severity=Severity.MEDIUM,
      title="Telnet service is running (unencrypted remote access).",
      description="Telnet transmits all data including credentials in cleartext.",
      evidence=f"Telnet port {port} is open on {target}.",
      remediation="Replace Telnet with SSH for encrypted remote access.",
      owasp_id="A02:2021",
      cwe_id="CWE-319",
      confidence="certain",
    ))

    # --- 1. Banner grab + IAC negotiation parsing ---
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(5)
      sock.connect((target, port))
      raw = sock.recv(2048)
      sock.close()
    except Exception as e:
      return probe_error(target, port, "Telnet", e)

    # Parse IAC sequences
    iac_options = []
    cmd_names = {251: "WILL", 252: "WONT", 253: "DO", 254: "DONT"}
    opt_names = {
      0: "BINARY", 1: "ECHO", 3: "SGA", 5: "STATUS",
      24: "TERMINAL_TYPE", 31: "WINDOW_SIZE", 32: "TERMINAL_SPEED",
      33: "REMOTE_FLOW", 34: "LINEMODE", 36: "ENVIRON", 39: "NEW_ENVIRON",
    }
    i = 0
    text_parts = []
    while i < len(raw):
      if raw[i] == 0xFF and i + 2 < len(raw):
        cmd = cmd_names.get(raw[i + 1], f"CMD_{raw[i+1]}")
        opt = opt_names.get(raw[i + 2], f"OPT_{raw[i+2]}")
        iac_options.append(f"{cmd} {opt}")
        i += 3
      else:
        if 32 <= raw[i] < 127:
          text_parts.append(chr(raw[i]))
        i += 1

    banner_text = "".join(text_parts).strip()
    if banner_text:
      result["banner"] = banner_text
    elif iac_options:
      result["banner"] = "(IAC negotiation only, no text banner)"
    else:
      result["banner"] = "(no banner)"
    result["negotiation_options"] = iac_options

    # --- 2–4. Default credential check with system fingerprint ---
    def _try_telnet_login(user, passwd):
      """Attempt Telnet login, return (success, uid_line, uname_line)."""
      try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))

        # Read until login prompt
        buf = b""
        deadline = _time.time() + 5
        while _time.time() < deadline:
          try:
            chunk = s.recv(1024)
            if not chunk:
              break
            buf += chunk
            if b"login:" in buf.lower() or b"username:" in buf.lower():
              break
          except socket.timeout:
            break

        if b"login:" not in buf.lower() and b"username:" not in buf.lower():
          s.close()
          return False, None, None

        s.sendall(user.encode() + b"\n")

        # Read until password prompt
        buf = b""
        deadline = _time.time() + 5
        while _time.time() < deadline:
          try:
            chunk = s.recv(1024)
            if not chunk:
              break
            buf += chunk
            if b"assword:" in buf:
              break
          except socket.timeout:
            break

        if b"assword:" not in buf:
          s.close()
          return False, None, None

        s.sendall(passwd.encode() + b"\n")
        _time.sleep(1.5)

        # Read response
        resp = b""
        try:
          while True:
            chunk = s.recv(4096)
            if not chunk:
              break
            resp += chunk
        except socket.timeout:
          pass

        resp_text = resp.decode("utf-8", errors="replace")

        # Check for login failure indicators
        fail_indicators = ["incorrect", "failed", "denied", "invalid", "login:"]
        if any(ind in resp_text.lower() for ind in fail_indicators):
          s.close()
          return False, None, None

        # Login succeeded — try to get system info
        uid_line = None
        uname_line = None
        try:
          s.sendall(b"id\n")
          _time.sleep(0.5)
          id_resp = s.recv(2048).decode("utf-8", errors="replace")
          for line in id_resp.replace("\r\n", "\n").split("\n"):
            cleaned = line.strip()
            # Remove ANSI/control sequences
            import re
            cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", cleaned)
            if "uid=" in cleaned:
              uid_line = cleaned
              break
        except Exception:
          pass

        try:
          s.sendall(b"uname -a\n")
          _time.sleep(0.5)
          uname_resp = s.recv(2048).decode("utf-8", errors="replace")
          for line in uname_resp.replace("\r\n", "\n").split("\n"):
            cleaned = line.strip()
            import re
            cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", cleaned)
            if "linux" in cleaned.lower() or "unix" in cleaned.lower() or "darwin" in cleaned.lower():
              uname_line = cleaned
              break
        except Exception:
          pass

        s.close()
        return True, uid_line, uname_line

      except Exception:
        return False, None, None

    system_info_captured = False
    for user, passwd in _TELNET_DEFAULT_CREDS:
      success, uid_line, uname_line = _try_telnet_login(user, passwd)
      if success:
        result["accepted_credentials"].append(f"{user}:{passwd}")
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title=f"Telnet default credential accepted: {user}:{passwd}",
          description="The Telnet server accepted a well-known default credential.",
          evidence=f"Accepted credential: {user}:{passwd}",
          remediation="Change default passwords immediately and enforce strong credential policies.",
          owasp_id="A07:2021",
          cwe_id="CWE-798",
          confidence="certain",
        ))
        # Check for root access
        if uid_line and "uid=0" in uid_line:
          findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Root shell access via Telnet with {user}:{passwd}.",
            description="Root-level shell access was obtained over an unencrypted Telnet session.",
            evidence=f"uid=0 in id output: {uid_line}",
            remediation="Disable root login via Telnet; use SSH with key-based auth instead.",
            owasp_id="A07:2021",
            cwe_id="CWE-250",
            confidence="certain",
          ))

        # Capture system info once
        if not system_info_captured and (uid_line or uname_line):
          parts = []
          if uid_line:
            parts.append(uid_line)
          if uname_line:
            parts.append(uname_line)
          result["system_info"] = " | ".join(parts)
          system_info_captured = True

    # --- 5. Arbitrary credential acceptance test ---
    import string as _string
    ruser = "".join(random.choices(_string.ascii_lowercase, k=8))
    rpass = "".join(random.choices(_string.ascii_letters + _string.digits, k=12))
    success, _, _ = _try_telnet_login(ruser, rpass)
    if success:
      findings.append(Finding(
        severity=Severity.CRITICAL,
        title="Telnet accepts arbitrary credentials",
        description="Random credentials were accepted, indicating a dangerous misconfiguration or deceptive service.",
        evidence=f"Accepted random creds {ruser}:{rpass}",
        remediation="Investigate immediately — authentication is non-functional.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))

    return probe_result(raw_data=result, findings=findings)


  @register_probe(
    display_name="rsync service detection",
    description=(
      "rsync banner + module list (#list) probe. Detects exposed "
      "rsync daemon, anonymous module access, leaked filesystem paths."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A05:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_rsync(self, target, port):  # default port: 873
    """
    Rsync service probe: version handshake, module enumeration, auth check.

    Checks performed:

    1. Banner grab — extract rsync protocol version.
    2. Module enumeration — ``#list`` to discover available modules.
    3. Auth check — connect to each module to test unauthenticated access.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings.
    """
    findings = []
    raw = {"version": None, "modules": []}

    # --- 1. Connect and receive banner ---
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
    except Exception as e:
      return probe_error(target, port, "rsync", e)

    if not banner.startswith("@RSYNCD:"):
      try:
        sock.close()
      except Exception:
        pass
      findings.append(Finding(
        severity=Severity.INFO,
        title=f"Port {port} open but no rsync banner",
        description=f"Expected @RSYNCD banner, got: {banner[:80]}",
        confidence="tentative",
      ))
      return probe_result(raw_data=raw, findings=findings)

    # Extract protocol version
    proto_version = banner.split(":", 1)[1].strip().split()[0] if ":" in banner else None
    raw["version"] = proto_version

    findings.append(Finding(
      severity=Severity.LOW,
      title=f"Rsync service detected (protocol {proto_version})",
      description=f"Rsync daemon is running on {target}:{port}.",
      evidence=f"Banner: {banner}",
      remediation="Restrict rsync access to trusted networks; require authentication for all modules.",
      cwe_id="CWE-200",
      confidence="certain",
    ))

    # --- 2. Module enumeration ---
    try:
      # Send matching version handshake + list request
      sock.sendall(f"@RSYNCD: {proto_version}\n".encode())
      sock.sendall(b"#list\n")
      # Read module listing until @RSYNCD: EXIT
      module_data = b""
      while True:
        chunk = sock.recv(4096)
        if not chunk:
          break
        module_data += chunk
        if b"@RSYNCD: EXIT" in module_data:
          break
      sock.close()

      modules = []
      for line in module_data.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("@RSYNCD:") or not line:
          continue
        # Format: "module_name\tdescription" or just "module_name"
        parts = line.split("\t", 1)
        mod_name = parts[0].strip()
        mod_desc = parts[1].strip() if len(parts) > 1 else ""
        if mod_name:
          modules.append({"name": mod_name, "description": mod_desc})

      raw["modules"] = modules

      if modules:
        mod_names = ", ".join(m["name"] for m in modules)
        findings.append(Finding(
          severity=Severity.HIGH,
          title=f"Rsync module enumeration successful: {mod_names}",
          description=f"Rsync on {target}:{port} exposes {len(modules)} module(s). "
                      "Exposed modules may allow file read/write.",
          evidence=f"Modules: {mod_names}",
          remediation="Restrict module listing and require authentication for all rsync modules.",
          owasp_id="A01:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))
    except Exception as e:
      self.P(f"Rsync module enumeration failed on {target}:{port}: {e}", color='y')
      try:
        sock.close()
      except Exception:
        pass

    # --- 3. Test unauthenticated access per module ---
    for mod in raw["modules"]:
      try:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(3)
        sock2.connect((target, port))
        sock2.recv(256)  # banner
        sock2.sendall(f"@RSYNCD: {proto_version}\n".encode())
        sock2.sendall(f"{mod['name']}\n".encode())
        resp = sock2.recv(4096).decode("utf-8", errors="ignore")
        sock2.close()

        if "@RSYNCD: OK" in resp:
          findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Rsync module '{mod['name']}' accessible without authentication",
            description=f"Module '{mod['name']}' on {target}:{port} allows unauthenticated access. "
                        "An attacker can read or write arbitrary files within this module.",
            evidence=f"Connected to module '{mod['name']}', received @RSYNCD: OK",
            remediation=f"Add 'auth users' and 'secrets file' to the [{mod['name']}] section in rsyncd.conf.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
        elif "@ERROR" in resp and "auth" in resp.lower():
          raw["modules"] = [
            {**m, "auth_required": True} if m["name"] == mod["name"] else m
            for m in raw["modules"]
          ]
      except Exception:
        pass

    return probe_result(raw_data=raw, findings=findings)
