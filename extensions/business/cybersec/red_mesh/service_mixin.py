import random
import re as _re
import socket
import struct
import ftplib
import requests
import ssl
from datetime import datetime

import paramiko

from .findings import Finding, Severity, probe_result, probe_error
from .cve_db import check_cves

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


class _ServiceInfoMixin:
  """
  Network service banner probes feeding RedMesh reports.

  Each helper focuses on a specific protocol and maps findings to
  OWASP vulnerability families. The mixin is intentionally light-weight so
  that `PentestLocalWorker` threads can run without heavy dependencies while
  still surfacing high-signal clues.
  """

  def _emit_metadata(self, category, key_or_item, value=None):
    """Safely append to scan_metadata sub-dicts without crashing if state is uninitialized."""
    meta = self.state.get("scan_metadata")
    if meta is None:
      return
    bucket = meta.get(category)
    if bucket is None:
      return
    if isinstance(bucket, dict):
      bucket[key_or_item] = value
    elif isinstance(bucket, list):
      bucket.append(key_or_item)

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

        if raw["server"]:
          _m = _HTTP_SERVER_RE.search(raw["server"])
          if _m:
            _cve_product = _HTTP_PRODUCT_MAP.get(_m.group(1).lower())
            if _cve_product:
              findings += check_cves(_cve_product, _m.group(2))
    except Exception as e:
      return probe_error(target, port, "HTTP-ALT", e)
    return probe_result(raw_data=raw, findings=findings)  


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


  def _service_info_tls(self, target, port):
    """
    Inspect TLS handshake, certificate chain, and cipher strength.

    Uses a two-pass approach: unverified connect (always gets protocol/cipher),
    then verified connect (detects self-signed / chain issues).

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    dict
      Structured findings with protocol, cipher, cert details.
    """
    findings = []
    raw = {"protocol": None, "cipher": None, "cert_subject": None, "cert_issuer": None}

    # Pass 1: Unverified — always get protocol/cipher
    proto, cipher, cert_der = self._tls_unverified_connect(target, port)
    if proto is None:
      return probe_error(target, port, "TLS", Exception("unverified connect failed"))

    raw["protocol"], raw["cipher"] = proto, cipher
    findings += self._tls_check_protocol(proto, cipher)

    # Pass 1b: SAN parsing and signature check from DER cert
    if cert_der:
      san_dns, san_ips = self._tls_parse_san_from_der(cert_der)
      raw["san_dns"] = san_dns
      raw["san_ips"] = san_ips
      for ip_str in san_ips:
        try:
          import ipaddress as _ipaddress
          if _ipaddress.ip_address(ip_str).is_private:
            self._emit_metadata("internal_ips", {"ip": ip_str, "source": f"tls_san:{port}"})
        except (ValueError, TypeError):
          pass
      findings += self._tls_check_signature_algorithm(cert_der)
      findings += self._tls_check_validity_period(cert_der)

    # Pass 2: Verified — detect self-signed / chain issues
    findings += self._tls_check_certificate(target, port, raw)

    # Pass 3: Cert content checks (expiry, default CN)
    findings += self._tls_check_expiry(raw)
    findings += self._tls_check_default_cn(raw)

    # Pass 4: Heartbleed (CVE-2014-0160)
    heartbleed = self._tls_check_heartbleed(target, port)
    if heartbleed:
      findings.append(heartbleed)

    # Pass 5: Downgrade attacks (POODLE / BEAST)
    findings += self._tls_check_downgrade(target, port)

    if not findings:
      findings.append(Finding(Severity.INFO, f"TLS {proto} {cipher}", "TLS configuration adequate."))

    return probe_result(raw_data=raw, findings=findings)

  def _tls_unverified_connect(self, target, port):
    """Unverified TLS connect to get protocol, cipher, and DER cert."""
    try:
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      with socket.create_connection((target, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=target) as ssock:
          proto = ssock.version()
          cipher_info = ssock.cipher()
          cipher_name = cipher_info[0] if cipher_info else "unknown"
          cert_der = ssock.getpeercert(binary_form=True)
          return proto, cipher_name, cert_der
    except Exception as e:
      self.P(f"TLS unverified connect failed on {target}:{port}: {e}", color='y')
      return None, None, None

  def _tls_check_protocol(self, proto, cipher):
    """Flag obsolete TLS/SSL protocols and weak ciphers."""
    findings = []
    if proto and proto.upper() in ("SSLV2", "SSLV3", "TLSV1", "TLSV1.1"):
      findings.append(Finding(
        severity=Severity.HIGH,
        title=f"Obsolete TLS protocol: {proto}",
        description=f"Server negotiated {proto} with cipher {cipher}. "
                    f"SSLv2/v3 and TLS 1.0/1.1 are deprecated and vulnerable.",
        evidence=f"protocol={proto}, cipher={cipher}",
        remediation="Disable SSLv2/v3/TLS 1.0/1.1 and require TLS 1.2+.",
        owasp_id="A02:2021",
        cwe_id="CWE-326",
        confidence="certain",
      ))
    if cipher and any(w in cipher.lower() for w in ("rc4", "des", "null", "export")):
      findings.append(Finding(
        severity=Severity.HIGH,
        title=f"Weak TLS cipher: {cipher}",
        description=f"Cipher {cipher} is considered cryptographically weak.",
        evidence=f"cipher={cipher}",
        remediation="Disable weak ciphers (RC4, DES, NULL, EXPORT).",
        owasp_id="A02:2021",
        cwe_id="CWE-327",
        confidence="certain",
      ))
    return findings

  def _tls_check_certificate(self, target, port, raw):
    """Verified TLS pass — detect self-signed, untrusted issuer, hostname mismatch."""
    findings = []
    try:
      ctx = ssl.create_default_context()
      with socket.create_connection((target, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=target) as ssock:
          cert = ssock.getpeercert()
          subj = dict(x[0] for x in cert.get("subject", ()))
          issuer = dict(x[0] for x in cert.get("issuer", ()))
          raw["cert_subject"] = subj.get("commonName")
          raw["cert_issuer"] = issuer.get("organizationName") or issuer.get("commonName")
          raw["cert_not_after"] = cert.get("notAfter")
    except ssl.SSLCertVerificationError as e:
      err_msg = str(e).lower()
      if "self-signed" in err_msg or "self signed" in err_msg:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="Self-signed TLS certificate",
          description="The server presents a self-signed certificate that browsers will reject.",
          evidence=str(e),
          remediation="Replace with a certificate from a trusted CA.",
          owasp_id="A02:2021",
          cwe_id="CWE-295",
          confidence="certain",
        ))
      elif "hostname mismatch" in err_msg:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="TLS certificate hostname mismatch",
          description=f"Certificate CN/SAN does not match {target}.",
          evidence=str(e),
          remediation="Ensure the certificate covers the served hostname.",
          owasp_id="A02:2021",
          cwe_id="CWE-295",
          confidence="certain",
        ))
      else:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="TLS certificate validation failed",
          description="Certificate chain could not be verified.",
          evidence=str(e),
          remediation="Use a certificate from a trusted CA with a valid chain.",
          owasp_id="A02:2021",
          cwe_id="CWE-295",
          confidence="firm",
        ))
    except Exception:
      pass  # Non-cert errors (connection reset, etc.) — skip
    return findings

  def _tls_check_expiry(self, raw):
    """Check certificate expiry from raw dict."""
    findings = []
    expires = raw.get("cert_not_after")
    if not expires:
      return findings
    try:
      exp = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
      days = (exp - datetime.utcnow()).days
      raw["cert_days_remaining"] = days
      if days < 0:
        findings.append(Finding(
          severity=Severity.HIGH,
          title=f"TLS certificate expired ({-days} days ago)",
          description="The certificate has already expired.",
          evidence=f"notAfter={expires}",
          remediation="Renew the certificate immediately.",
          owasp_id="A02:2021",
          cwe_id="CWE-298",
          confidence="certain",
        ))
      elif days <= 30:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"TLS certificate expiring soon ({days} days)",
          description=f"Certificate expires in {days} days.",
          evidence=f"notAfter={expires}",
          remediation="Renew the certificate before expiry.",
          owasp_id="A02:2021",
          cwe_id="CWE-298",
          confidence="certain",
        ))
    except Exception:
      pass
    return findings

  def _tls_check_default_cn(self, raw):
    """Flag placeholder common names."""
    findings = []
    cn = raw.get("cert_subject")
    if not cn:
      return findings
    cn_lower = cn.lower()
    placeholders = ("example.com", "localhost", "internet widgits", "test", "changeme", "my company", "acme", "default")
    if any(p in cn_lower for p in placeholders) or len(cn.strip()) <= 1:
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"TLS certificate placeholder CN: {cn}",
        description="Certificate uses a default/placeholder common name.",
        evidence=f"CN={cn}",
        remediation="Replace with a certificate bearing the correct hostname.",
        owasp_id="A02:2021",
        cwe_id="CWE-295",
        confidence="firm",
      ))
    return findings

  def _tls_parse_san_from_der(self, cert_der):
    """Parse SAN DNS names and IP addresses from a DER-encoded certificate."""
    dns_names, ip_addresses = [], []
    if not cert_der:
      return dns_names, ip_addresses
    try:
      from cryptography import x509
      cert = x509.load_der_x509_certificate(cert_der)
      try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addresses = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
      except x509.ExtensionNotFound:
        pass
    except Exception:
      pass
    return dns_names, ip_addresses

  def _tls_check_signature_algorithm(self, cert_der):
    """Flag SHA-1 or MD5 signature algorithms."""
    findings = []
    if not cert_der:
      return findings
    try:
      from cryptography import x509
      from cryptography.hazmat.primitives import hashes
      cert = x509.load_der_x509_certificate(cert_der)
      algo = cert.signature_hash_algorithm
      if algo and isinstance(algo, (hashes.SHA1, hashes.MD5)):
        algo_name = algo.name.upper()
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"TLS certificate signed with weak algorithm: {algo_name}",
          description=f"The certificate uses {algo_name} for its signature, which is cryptographically weak.",
          evidence=f"signature_algorithm={algo_name}",
          remediation="Replace with a certificate using SHA-256 or stronger.",
          owasp_id="A02:2021",
          cwe_id="CWE-327",
          confidence="certain",
        ))
    except Exception:
      pass
    return findings

  def _tls_check_validity_period(self, cert_der):
    """Flag certificates with a total validity span >5 years (CA/Browser Forum violation)."""
    findings = []
    if not cert_der:
      return findings
    try:
      from cryptography import x509
      cert = x509.load_der_x509_certificate(cert_der)
      span = cert.not_valid_after_utc - cert.not_valid_before_utc
      if span.days > 5 * 365:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"TLS certificate validity span exceeds 5 years ({span.days} days)",
          description="Certificates valid for more than 5 years violate CA/Browser Forum baseline requirements.",
          evidence=f"not_before={cert.not_valid_before_utc}, not_after={cert.not_valid_after_utc}, span={span.days}d",
          remediation="Reissue with a validity period of 398 days or less.",
          owasp_id="A02:2021",
          cwe_id="CWE-298",
          confidence="certain",
        ))
    except Exception:
      pass
    return findings


  def _tls_check_heartbleed(self, target, port):
    """Test for Heartbleed (CVE-2014-0160) by sending a malformed TLS heartbeat.

    Builds a raw TLS connection, completes handshake, then sends a heartbeat
    request with payload_length > actual payload. If the server responds with
    more data than sent, it is leaking memory.

    Returns
    -------
    Finding or None
      CRITICAL finding if vulnerable, None otherwise.
    """
    try:
      # Connect and perform TLS handshake via ssl module
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      # Allow older protocols for compatibility with vulnerable servers
      ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

      raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      raw_sock.settimeout(3)
      raw_sock.connect((target, port))
      tls_sock = ctx.wrap_socket(raw_sock, server_hostname=target)

      # Get the negotiated TLS version for the heartbeat record
      tls_version = tls_sock.version()
      version_map = {
        "TLSv1": b"\x03\x01", "TLSv1.1": b"\x03\x02",
        "TLSv1.2": b"\x03\x03", "TLSv1.3": b"\x03\x03",
        "SSLv3": b"\x03\x00",
      }
      tls_ver_bytes = version_map.get(tls_version, b"\x03\x01")

      # Build heartbeat request (ContentType=24, HeartbeatMessageType=1=request)
      # payload_length is set to 16384 but actual payload is only 1 byte
      # This is the essence of the Heartbleed attack: asking for more data than sent
      hb_payload = b"\x01"  # 1 byte actual payload
      hb_msg = (
        b"\x01"               # HeartbeatMessageType: request
        + b"\x40\x00"         # payload_length: 16384 (0x4000)
        + hb_payload           # actual payload: 1 byte
        + b"\x00" * 16        # padding (16 bytes)
      )

      # TLS record: ContentType=24 (Heartbeat), version, length
      tls_record = (
        b"\x18"               # ContentType: Heartbeat
        + tls_ver_bytes        # TLS version
        + struct.pack(">H", len(hb_msg))
        + hb_msg
      )

      # Send via the underlying raw socket (bypassing ssl module)
      # We need to access the raw socket after handshake
      # The ssl wrapper doesn't let us send raw records, so use raw_sock.
      # After wrap_socket, raw_sock is consumed. Instead, use tls_sock.unwrap()
      # to get the raw socket back.
      try:
        raw_after = tls_sock.unwrap()
        raw_after.sendall(tls_record)
        raw_after.settimeout(3)
        response = raw_after.recv(65536)
        raw_after.close()
      except (ssl.SSLError, OSError):
        # If unwrap fails, try closing and testing with a new raw connection
        tls_sock.close()
        return self._tls_heartbleed_raw(target, port, tls_ver_bytes)

      if response and len(response) >= 7:
        # Check if response is a heartbeat response (ContentType=24)
        if response[0] == 24:
          resp_len = struct.unpack(">H", response[3:5])[0]
          # If server sent back more than we sent (3 bytes of heartbeat msg),
          # it leaked memory
          if resp_len > len(hb_msg):
            return Finding(
              severity=Severity.CRITICAL,
              title="TLS Heartbleed vulnerability (CVE-2014-0160)",
              description=f"Server at {target}:{port} is vulnerable to Heartbleed. "
                          "An attacker can read up to 64KB of server memory per request, "
                          "potentially exposing private keys, session tokens, and passwords.",
              evidence=f"Heartbeat response size ({resp_len} bytes) > request payload size ({len(hb_msg)} bytes). "
                       f"Leaked {resp_len - len(hb_msg)} bytes of server memory.",
              remediation="Upgrade OpenSSL to 1.0.1g or later and regenerate all private keys and certificates.",
              owasp_id="A06:2021",
              cwe_id="CWE-126",
              confidence="certain",
            )
        # TLS Alert (ContentType=21) = not vulnerable (server rejected heartbeat)
        elif response[0] == 21:
          return None

    except Exception:
      pass
    return None

  def _tls_heartbleed_raw(self, target, port, tls_ver_bytes):
    """Fallback Heartbleed test using a raw TLS ClientHello with heartbeat extension.

    This is needed when ssl.unwrap() fails. We build a minimal TLS 1.0
    ClientHello that advertises the heartbeat extension, complete the handshake,
    and then send the malformed heartbeat.

    Returns
    -------
    Finding or None
    """
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(5)
      sock.connect((target, port))

      # Minimal TLS 1.0 ClientHello with heartbeat extension
      # This is a simplified approach: we use struct to build the exact bytes
      hello = bytearray()
      # Handshake header: ClientHello (0x01)
      # Random: 32 bytes
      client_random = random.randbytes(32)
      # Session ID: 0 bytes
      # Cipher suites: a few common ones
      ciphers = (
        b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
        b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA
        b"\x00\x0a"  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
      )
      # Compression: null only
      compression = b"\x01\x00"
      # Extensions: heartbeat (type 0x000f, length 1, mode=1 peer allowed to send)
      heartbeat_ext = struct.pack(">HH", 0x000f, 1) + b"\x01"
      extensions = heartbeat_ext

      client_hello_body = (
        b"\x03\x01"  # TLS 1.0
        + client_random
        + b"\x00"  # Session ID length: 0
        + struct.pack(">H", len(ciphers)) + ciphers
        + compression
        + struct.pack(">H", len(extensions)) + extensions
      )

      # Handshake message: type=1 (ClientHello), length
      handshake = b"\x01" + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body

      # TLS record: ContentType=22 (Handshake), version=TLS 1.0
      tls_record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
      sock.sendall(tls_record)

      # Read ServerHello + Certificate + ServerHelloDone
      # We just need to consume enough to complete the handshake
      server_response = b""
      for _ in range(10):
        try:
          chunk = sock.recv(16384)
          if not chunk:
            break
          server_response += chunk
          # Check if we received ServerHelloDone (handshake type 0x0e)
          if b"\x0e\x00\x00\x00" in server_response:
            break
        except (socket.timeout, OSError):
          break

      if not server_response:
        sock.close()
        return None

      # Now send the malformed heartbeat
      hb_msg = b"\x01\x40\x00" + b"\x41" + b"\x00" * 16  # type=request, length=16384, 1 byte payload + padding
      hb_record = b"\x18\x03\x01" + struct.pack(">H", len(hb_msg)) + hb_msg
      sock.sendall(hb_record)

      # Read response
      sock.settimeout(3)
      try:
        response = sock.recv(65536)
      except (socket.timeout, OSError):
        response = b""
      sock.close()

      if response and len(response) >= 7 and response[0] == 24:
        resp_payload_len = struct.unpack(">H", response[3:5])[0]
        if resp_payload_len > len(hb_msg):
          return Finding(
            severity=Severity.CRITICAL,
            title="TLS Heartbleed vulnerability (CVE-2014-0160)",
            description=f"Server at {target}:{port} is vulnerable to Heartbleed. "
                        "An attacker can read up to 64KB of server memory per request, "
                        "potentially exposing private keys, session tokens, and passwords.",
            evidence=f"Heartbeat response ({resp_payload_len} bytes) exceeded request size.",
            remediation="Upgrade OpenSSL to 1.0.1g or later and regenerate all private keys and certificates.",
            owasp_id="A06:2021",
            cwe_id="CWE-126",
            confidence="certain",
          )
    except Exception:
      pass
    return None

  def _tls_check_downgrade(self, target, port):
    """Test for TLS downgrade vulnerabilities (POODLE, BEAST).

    Returns list of findings.
    """
    findings = []

    # --- POODLE: Test SSLv3 acceptance ---
    try:
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      ctx.maximum_version = ssl.TLSVersion.SSLv3
      ctx.minimum_version = ssl.TLSVersion.SSLv3
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      tls_sock = ctx.wrap_socket(sock, server_hostname=target)
      negotiated = tls_sock.version()
      tls_sock.close()
      if negotiated and "SSL" in negotiated:
        findings.append(Finding(
          severity=Severity.HIGH,
          title="Server accepts SSLv3 — vulnerable to POODLE (CVE-2014-3566)",
          description=f"TLS on {target}:{port} accepts SSLv3 connections. "
                      "The POODLE attack allows decrypting SSLv3 traffic using CBC cipher padding oracles.",
          evidence=f"Negotiated {negotiated} when SSLv3 was forced.",
          remediation="Disable SSLv3 entirely on the server.",
          owasp_id="A02:2021",
          cwe_id="CWE-757",
          confidence="certain",
        ))
    except (ssl.SSLError, OSError):
      pass  # SSLv3 rejected or not available in runtime — good

    # --- BEAST: Test TLS 1.0 with CBC cipher ---
    try:
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      ctx.maximum_version = ssl.TLSVersion.TLSv1
      ctx.minimum_version = ssl.TLSVersion.TLSv1
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      tls_sock = ctx.wrap_socket(sock, server_hostname=target)
      negotiated = tls_sock.version()
      cipher_info = tls_sock.cipher()
      tls_sock.close()
      if negotiated and cipher_info:
        cipher_name = cipher_info[0] if cipher_info else ""
        if "CBC" in cipher_name.upper():
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title="TLS 1.0 with CBC cipher — BEAST risk (CVE-2011-3389)",
            description=f"TLS on {target}:{port} accepts TLS 1.0 with CBC-mode cipher '{cipher_name}'. "
                        "The BEAST attack exploits predictable IVs in TLS 1.0 CBC mode.",
            evidence=f"Negotiated {negotiated} with cipher {cipher_name}.",
            remediation="Disable TLS 1.0 or ensure only non-CBC ciphers are used with TLS 1.0.",
            owasp_id="A02:2021",
            cwe_id="CWE-327",
            confidence="certain",
          ))
    except (ssl.SSLError, OSError):
      pass  # TLS 1.0 rejected — good

    return findings

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
    if version_match and version_match.group(2):
      _cve_product = _smtp_product_map.get(version_match.group(1).lower())
      if _cve_product:
        findings += check_cves(_cve_product, version_match.group(2))

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

  def _service_info_mysql(self, target, port):  # default port: 3306
    """
    MySQL handshake probe: extract version, auth plugin, and check CVEs.

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
    raw = {"version": None, "auth_plugin": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      data = sock.recv(256)
      sock.close()

      if data and len(data) > 4:
        # MySQL protocol: first byte of payload is protocol version (0x0a = v10)
        pkt_payload = data[4:]  # skip 3-byte length + 1-byte seq
        if pkt_payload and pkt_payload[0] == 0x0a:
          version = pkt_payload[1:].split(b'\x00')[0].decode('utf-8', errors='ignore')
          raw["version"] = version

          # Extract auth plugin name (at end of handshake after capabilities/salt)
          try:
            parts = pkt_payload.split(b'\x00')
            if len(parts) >= 2:
              last = parts[-2].decode('utf-8', errors='ignore') if parts[-1] == b'' else parts[-1].decode('utf-8', errors='ignore')
              if 'mysql_native' in last or 'caching_sha2' in last or 'sha256' in last:
                raw["auth_plugin"] = last
          except Exception:
            pass

          findings.append(Finding(
            severity=Severity.LOW,
            title=f"MySQL version disclosed: {version}",
            description=f"MySQL {version} handshake received on {target}:{port}.",
            evidence=f"version={version}, auth_plugin={raw['auth_plugin']}",
            remediation="Restrict MySQL to trusted networks; consider disabling version disclosure.",
            confidence="certain",
          ))

          # Salt entropy check — extract 20-byte auth scramble from handshake
          try:
            import math
            # After version null-terminated string: 4 bytes thread_id + 8 bytes salt1
            after_version = pkt_payload[1:].split(b'\x00', 1)[1]
            if len(after_version) >= 12:
              salt1 = after_version[4:12]  # 8 bytes after thread_id
              # Salt part 2: after capabilities(2)+charset(1)+status(2)+caps_upper(2)+auth_len(1)+reserved(10)
              salt2 = b''
              if len(after_version) >= 31:
                salt2 = after_version[31:43].rstrip(b'\x00')
              full_salt = salt1 + salt2
              if len(full_salt) >= 8:
                # Shannon entropy
                byte_counts = {}
                for b in full_salt:
                  byte_counts[b] = byte_counts.get(b, 0) + 1
                entropy = 0.0
                n = len(full_salt)
                for count in byte_counts.values():
                  p = count / n
                  if p > 0:
                    entropy -= p * math.log2(p)
                raw["salt_entropy"] = round(entropy, 2)
                if entropy < 2.0:
                  findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"MySQL salt entropy critically low ({entropy:.2f} bits)",
                    description="The authentication scramble has abnormally low entropy, "
                                "suggesting a non-standard or deceptive MySQL service.",
                    evidence=f"salt_entropy={entropy:.2f}, salt_hex={full_salt.hex()[:40]}",
                    remediation="Investigate this MySQL instance — authentication randomness is insufficient.",
                    cwe_id="CWE-330",
                    confidence="firm",
                  ))
          except Exception:
            pass

          # CVE check
          findings += check_cves("mysql", version)
        else:
          raw["protocol_byte"] = pkt_payload[0] if pkt_payload else None
          findings.append(Finding(
            severity=Severity.INFO,
            title="MySQL port open (non-standard handshake)",
            description=f"Port {port} responded but protocol byte is not 0x0a.",
            confidence="tentative",
          ))
      else:
        findings.append(Finding(
          severity=Severity.INFO,
          title="MySQL port open (no banner)",
          description=f"No handshake data received on {target}:{port}.",
          confidence="tentative",
        ))
    except Exception as e:
      return probe_error(target, port, "MySQL", e)

    return probe_result(raw_data=raw, findings=findings)

  def _service_info_mysql_creds(self, target, port):  # default port: 3306
    """
    MySQL default credential testing (opt-in via active_auth feature group).

    Attempts mysql_native_password auth with a small list of default credentials.

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
    import hashlib

    findings = []
    raw = {"tested_credentials": 0, "accepted_credentials": []}
    creds = [("root", ""), ("root", "root"), ("root", "password")]

    for username, password in creds:
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        data = sock.recv(256)

        if not data or len(data) < 4:
          sock.close()
          continue

        pkt_payload = data[4:]
        if not pkt_payload or pkt_payload[0] != 0x0a:
          sock.close()
          continue

        # Extract salt (scramble) from handshake
        parts = pkt_payload[1:].split(b'\x00', 1)
        rest = parts[1] if len(parts) > 1 else b''
        # Salt part 1: bytes 4..11 after capabilities (skip 4 bytes capabilities + 1 byte filler)
        if len(rest) >= 13:
          salt1 = rest[5:13]
        else:
          sock.close()
          continue
        # Salt part 2: after reserved bytes (skip 2+2+1+10 reserved = 15)
        salt2 = b''
        if len(rest) >= 28:
          salt2 = rest[28:40].rstrip(b'\x00')
        salt = salt1 + salt2

        # mysql_native_password auth response
        if password:
          sha1_pass = hashlib.sha1(password.encode()).digest()
          sha1_sha1 = hashlib.sha1(sha1_pass).digest()
          sha1_salt_sha1sha1 = hashlib.sha1(salt + sha1_sha1).digest()
          auth_data = bytes(a ^ b for a, b in zip(sha1_pass, sha1_salt_sha1sha1))
        else:
          auth_data = b''

        # Build auth response packet
        client_flags = struct.pack('<I', 0x0003a685)  # basic capabilities
        max_pkt = struct.pack('<I', 16777216)
        charset = b'\x21'  # utf8
        reserved = b'\x00' * 23
        user_bytes = username.encode() + b'\x00'
        auth_len = bytes([len(auth_data)])
        auth_plugin = b'mysql_native_password\x00'

        payload = client_flags + max_pkt + charset + reserved + user_bytes + auth_len + auth_data + auth_plugin
        pkt_len = struct.pack('<I', len(payload))[:3]
        seq = b'\x01'
        sock.sendall(pkt_len + seq + payload)

        resp = sock.recv(256)
        sock.close()
        raw["tested_credentials"] += 1

        if resp and len(resp) >= 5:
          resp_type = resp[4]
          if resp_type == 0x00:  # OK packet
            cred_str = f"{username}:{password}" if password else f"{username}:(empty)"
            raw["accepted_credentials"].append(cred_str)
            findings.append(Finding(
              severity=Severity.CRITICAL,
              title=f"MySQL default credential accepted: {cred_str}",
              description=f"MySQL on {target}:{port} accepts {cred_str}.",
              evidence=f"Auth response OK for {cred_str}",
              remediation="Change default passwords and restrict access.",
              owasp_id="A07:2021",
              cwe_id="CWE-798",
              confidence="certain",
            ))
      except Exception:
        continue

    if not findings:
      findings.append(Finding(
        severity=Severity.INFO,
        title="MySQL default credentials rejected",
        description=f"Tested {raw['tested_credentials']} credential pairs, all rejected.",
        confidence="certain",
      ))

    # --- CVE-2012-2122 auth bypass test ---
    # Affected: MySQL 5.1.x < 5.1.63, 5.5.x < 5.5.25, MariaDB < 5.5.23
    # Bug: memcmp return value truncation means ~1/256 chance of auth bypass
    cve_bypass = self._mysql_test_cve_2012_2122(target, port)
    if cve_bypass:
      findings.append(cve_bypass)
      raw["cve_2012_2122"] = True

    return probe_result(raw_data=raw, findings=findings)

  # Affected version ranges for CVE-2012-2122
  _MYSQL_CVE_2012_2122_RANGES = [
    ((5, 1, 0), (5, 1, 63)),   # MySQL 5.1.x < 5.1.63
    ((5, 5, 0), (5, 5, 25)),   # MySQL 5.5.x < 5.5.25
  ]

  def _mysql_test_cve_2012_2122(self, target, port):
    """Test for MySQL CVE-2012-2122 timing-based authentication bypass.

    On affected versions, memcmp() return value is cast to char, giving
    a ~1/256 chance that any password is accepted. 300 attempts gives
    ~69% probability of detection.

    Returns
    -------
    Finding or None
      CRITICAL finding if bypass confirmed, None otherwise.
    """
    import hashlib

    # First, connect to get version
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      data = sock.recv(256)
      sock.close()
    except Exception:
      return None

    if not data or len(data) < 5:
      return None
    pkt_payload = data[4:]
    if not pkt_payload or pkt_payload[0] != 0x0a:
      return None

    version_str = pkt_payload[1:].split(b'\x00')[0].decode('utf-8', errors='ignore')
    version_tuple = tuple(int(x) for x in _re.findall(r'\d+', version_str)[:3])
    if len(version_tuple) < 3:
      return None

    # Check if version is in affected range
    affected = False
    for low, high in self._MYSQL_CVE_2012_2122_RANGES:
      if low <= version_tuple < high:
        affected = True
        break
    if not affected:
      return None

    # Attempt rapid auth with random passwords
    self.P(f"MySQL {version_str} in CVE-2012-2122 range — testing auth bypass ({target}:{port})", color='y')
    attempts = 300

    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(5)
      sock.connect((target, port))

      for _ in range(attempts):
        # Read handshake
        data = sock.recv(512)
        if not data or len(data) < 5:
          break
        pkt_payload = data[4:]
        if not pkt_payload or pkt_payload[0] != 0x0a:
          break

        # Extract salt
        parts = pkt_payload[1:].split(b'\x00', 1)
        rest = parts[1] if len(parts) > 1 else b''
        if len(rest) < 13:
          break
        salt1 = rest[5:13]
        salt2 = rest[28:40].rstrip(b'\x00') if len(rest) >= 28 else b''
        salt = salt1 + salt2

        # Auth with random password
        rand_pass = random.randbytes(20)
        sha1_pass = hashlib.sha1(rand_pass).digest()
        sha1_sha1 = hashlib.sha1(sha1_pass).digest()
        sha1_salt = hashlib.sha1(salt + sha1_sha1).digest()
        auth_data = bytes(a ^ b for a, b in zip(sha1_pass, sha1_salt))

        client_flags = struct.pack('<I', 0x0003a685)
        max_pkt = struct.pack('<I', 16777216)
        charset = b'\x21'
        reserved = b'\x00' * 23
        user_bytes = b'root\x00'
        auth_len = bytes([len(auth_data)])
        auth_plugin = b'mysql_native_password\x00'

        payload = client_flags + max_pkt + charset + reserved + user_bytes + auth_len + auth_data + auth_plugin
        pkt_len = struct.pack('<I', len(payload))[:3]
        seq = b'\x01'
        sock.sendall(pkt_len + seq + payload)

        resp = sock.recv(256)
        if resp and len(resp) >= 5 and resp[4] == 0x00:
          sock.close()
          return Finding(
            severity=Severity.CRITICAL,
            title=f"MySQL authentication bypass confirmed (CVE-2012-2122)",
            description=f"MySQL {version_str} on {target}:{port} accepted login with a random password "
                        "due to CVE-2012-2122 memcmp truncation bug. Any attacker can gain root access.",
            evidence=f"Auth succeeded with random password on attempt (version {version_str})",
            remediation="Upgrade MySQL to at least 5.1.63 / 5.5.25 / MariaDB 5.5.23.",
            owasp_id="A07:2021",
            cwe_id="CWE-305",
            confidence="certain",
          )

        # If error packet, server closes connection — reconnect
        if resp and len(resp) >= 5 and resp[4] == 0xFF:
          sock.close()
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.settimeout(3)
          sock.connect((target, port))

      sock.close()
    except Exception:
      pass
    return None

  def _service_info_rdp(self, target, port):  # default port: 3389
    """
    Verify reachability of RDP services without full negotiation.

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
    raw = {"banner": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      raw["banner"] = "RDP service open"
      findings.append(Finding(
        severity=Severity.INFO,
        title="RDP service detected",
        description=f"RDP port {port} is open on {target}, no further enumeration performed.",
        evidence=f"TCP connect to {target}:{port} succeeded.",
        confidence="certain",
      ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "RDP", e)
    return probe_result(raw_data=raw, findings=findings)

  # SAFETY: Read-only commands only. NEVER add CONFIG SET, SLAVEOF, MODULE LOAD, EVAL, DEBUG.
  def _service_info_redis(self, target, port):  # default port: 6379
    """
    Deep Redis probe: auth check, version, config readability, data size, client list.

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
    findings, raw = [], {"version": None, "os": None, "config_writable": False}
    sock = self._redis_connect(target, port)
    if not sock:
      return probe_error(target, port, "Redis", Exception("connection failed"))

    auth_findings = self._redis_check_auth(sock, raw)
    if not auth_findings:
      # NOAUTH response — requires auth, stop here
      sock.close()
      return probe_result(
        raw_data=raw,
        findings=[Finding(Severity.INFO, "Redis requires authentication", "PING returned NOAUTH.")],
      )

    findings += auth_findings
    findings += self._redis_check_info(sock, raw)
    findings += self._redis_check_config(sock, raw)
    findings += self._redis_check_data(sock, raw)
    findings += self._redis_check_clients(sock, raw)
    findings += self._redis_check_persistence(sock, raw)

    # CVE check
    if raw["version"]:
      findings += check_cves("redis", raw["version"])

    sock.close()
    return probe_result(raw_data=raw, findings=findings)

  def _redis_connect(self, target, port):
    """Open a TCP socket to Redis."""
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      return sock
    except Exception as e:
      self.P(f"Redis connect failed on {target}:{port}: {e}", color='y')
      return None

  def _redis_cmd(self, sock, cmd):
    """Send an inline Redis command and return the response string."""
    try:
      sock.sendall(f"{cmd}\r\n".encode())
      data = sock.recv(4096).decode('utf-8', errors='ignore')
      return data
    except Exception:
      return ""

  def _redis_check_auth(self, sock, raw):
    """PING to check if auth is required. Returns findings if no auth, empty list if NOAUTH."""
    resp = self._redis_cmd(sock, "PING")
    if resp.startswith("+PONG"):
      return [Finding(
        severity=Severity.CRITICAL,
        title="Redis unauthenticated access",
        description="Redis responded to PING without authentication.",
        evidence=f"Response: {resp.strip()[:80]}",
        remediation="Set a strong password via requirepass in redis.conf.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      )]
    if "-NOAUTH" in resp.upper():
      return []  # signal: auth required
    return [Finding(
      severity=Severity.LOW,
      title="Redis unusual PING response",
      description=f"Unexpected response: {resp.strip()[:80]}",
      confidence="tentative",
    )]

  def _redis_check_info(self, sock, raw):
    """Extract version and OS from INFO server."""
    findings = []
    resp = self._redis_cmd(sock, "INFO server")
    if resp.startswith("-"):
      return findings
    uptime_seconds = None
    for line in resp.split("\r\n"):
      if line.startswith("redis_version:"):
        raw["version"] = line.split(":", 1)[1].strip()
      elif line.startswith("os:"):
        raw["os"] = line.split(":", 1)[1].strip()
      elif line.startswith("uptime_in_seconds:"):
        try:
          uptime_seconds = int(line.split(":", 1)[1].strip())
          raw["uptime_seconds"] = uptime_seconds
        except (ValueError, IndexError):
          pass
    if raw["os"]:
      self._emit_metadata("os_claims", "redis", raw["os"])
    if raw["version"]:
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"Redis version disclosed: {raw['version']}",
        description=f"Redis {raw['version']} on {raw['os'] or 'unknown OS'}.",
        evidence=f"version={raw['version']}, os={raw['os']}",
        remediation="Restrict INFO command access or rename it.",
        confidence="certain",
      ))
    if uptime_seconds is not None and uptime_seconds < 60:
      findings.append(Finding(
        severity=Severity.INFO,
        title=f"Redis uptime <60s ({uptime_seconds}s) — possible container restart",
        description="Very low uptime may indicate a recently restarted container or ephemeral instance.",
        evidence=f"uptime_in_seconds={uptime_seconds}",
        remediation="Investigate if the service is being automatically restarted.",
        confidence="tentative",
      ))
    return findings

  def _redis_check_config(self, sock, raw):
    """CONFIG GET dir — if accessible, it's an RCE vector."""
    findings = []
    resp = self._redis_cmd(sock, "CONFIG GET dir")
    if resp.startswith("-"):
      return findings  # blocked, good
    raw["config_writable"] = True
    findings.append(Finding(
      severity=Severity.CRITICAL,
      title="Redis CONFIG command accessible (RCE vector)",
      description="CONFIG GET is accessible, allowing attackers to write arbitrary files "
                  "via CONFIG SET dir / CONFIG SET dbfilename + SAVE.",
      evidence=f"CONFIG GET dir response: {resp.strip()[:120]}",
      remediation="Rename or disable CONFIG via rename-command in redis.conf.",
      owasp_id="A05:2021",
      cwe_id="CWE-94",
      confidence="certain",
    ))
    return findings

  def _redis_check_data(self, sock, raw):
    """DBSIZE — report if data is present."""
    findings = []
    resp = self._redis_cmd(sock, "DBSIZE")
    if resp.startswith(":"):
      try:
        count = int(resp.strip().lstrip(":"))
        raw["db_size"] = count
        if count > 0:
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Redis database contains {count} keys",
            description="Unauthenticated access to a Redis instance with live data.",
            evidence=f"DBSIZE={count}",
            remediation="Enable authentication and restrict network access.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
      except ValueError:
        pass
    return findings

  def _redis_check_clients(self, sock, raw):
    """CLIENT LIST — extract connected client IPs."""
    findings = []
    resp = self._redis_cmd(sock, "CLIENT LIST")
    if resp.startswith("-"):
      return findings
    ips = set()
    for line in resp.split("\n"):
      for part in line.split():
        if part.startswith("addr="):
          ip_port = part.split("=", 1)[1]
          ip = ip_port.rsplit(":", 1)[0]
          ips.add(ip)
    if ips:
      raw["connected_clients"] = list(ips)
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"Redis client IPs disclosed ({len(ips)} clients)",
        description=f"CLIENT LIST reveals connected IPs: {', '.join(sorted(ips)[:5])}",
        evidence=f"IPs: {', '.join(sorted(ips)[:10])}",
        remediation="Rename or disable CLIENT command.",
        confidence="certain",
      ))
    return findings

  def _redis_check_persistence(self, sock, raw):
    """Check INFO persistence for missing or stale RDB saves."""
    findings = []
    resp = self._redis_cmd(sock, "INFO persistence")
    if resp.startswith("-"):
      return findings
    import time as _time
    for line in resp.split("\r\n"):
      if line.startswith("rdb_last_bgsave_time:"):
        try:
          ts = int(line.split(":", 1)[1].strip())
          if ts == 0:
            findings.append(Finding(
              severity=Severity.LOW,
              title="Redis has never performed an RDB save",
              description="rdb_last_bgsave_time is 0, meaning no background save has ever been performed. "
                          "This may indicate a cache-only instance with persistence disabled, or an ephemeral deployment.",
              evidence="rdb_last_bgsave_time=0",
              remediation="Verify whether RDB persistence is intentionally disabled; if not, configure BGSAVE.",
              cwe_id="CWE-345",
              confidence="tentative",
            ))
          elif (_time.time() - ts) > 365 * 86400:
            age_days = int((_time.time() - ts) / 86400)
            findings.append(Finding(
              severity=Severity.LOW,
              title=f"Redis RDB save is stale ({age_days} days old)",
              description="The last RDB background save timestamp is over 1 year old. "
                          "This may indicate disabled persistence, a long-running cache-only instance, or stale data.",
              evidence=f"rdb_last_bgsave_time={ts}, age={age_days}d",
              remediation="Verify persistence configuration; stale saves may indicate data loss risk.",
              cwe_id="CWE-345",
              confidence="tentative",
            ))
        except (ValueError, IndexError):
          pass
        break
    return findings


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
            owasp_id="A04:2021",
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


  def _service_info_smb(self, target, port):  # default port: 445
    """
    Probe SMB services: dialect negotiation, version extraction, CVE matching,
    null session test, and security flag analysis.

    Checks performed:

    1. SMB negotiate — determine supported dialect (SMBv1/v2/v3).
    2. Version extraction — parse Samba/Windows version from NativeOS/NativeLanMan.
    3. Security flags — check signing requirements.
    4. Null session — attempt anonymous IPC$ access.
    5. CVE matching — run check_cves on extracted Samba version.

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
    raw = {
      "banner": None, "dialect": None, "server_os": None,
      "server_domain": None, "samba_version": None,
      "signing_required": None, "smbv1_supported": False,
    }

    # --- 1. SMBv1 Negotiate ---
    # Build a proper SMBv1 Negotiate Protocol Request with NT LM 0.12 dialect
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    smb_header = bytearray(32)
    smb_header[0:4] = b"\xffSMB"  # Protocol ID
    smb_header[4] = 0x72          # Command: Negotiate
    # Flags: 0x18 (case-sensitive, canonicalized paths)
    smb_header[13] = 0x18
    # Flags2: unicode + NT status + long names
    struct.pack_into("<H", smb_header, 14, 0xC803)
    # Word count = 0, byte count = len(dialects)
    smb_body = struct.pack("<BH", 0, len(dialects)) + dialects
    smb_payload = bytes(smb_header) + smb_body
    # NetBIOS session header: type=0x00, length=len(smb_payload)
    netbios_header = struct.pack(">I", len(smb_payload))
    netbios_header = b"\x00" + netbios_header[1:]  # force type=0

    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(4)
      sock.connect((target, port))
      sock.sendall(netbios_header + smb_payload)

      # Read NetBIOS header (4 bytes) + full response
      resp_hdr = self._smb_recv_exact(sock, 4)
      if not resp_hdr:
        sock.close()
        findings.append(Finding(
          severity=Severity.INFO,
          title="SMB port open but no negotiation response",
          description=f"Port {port} is open but SMB did not respond to negotiation.",
          confidence="tentative",
        ))
        return probe_result(raw_data=raw, findings=findings)

      resp_len = struct.unpack(">I", b"\x00" + resp_hdr[1:4])[0]
      resp_data = self._smb_recv_exact(sock, min(resp_len, 4096))
      sock.close()

      if not resp_data or len(resp_data) < 36:
        raw["banner"] = "SMB response too short"
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="SMB service responded to negotiation probe",
          description=f"SMB on {target}:{port} accepts negotiation requests.",
          evidence=f"Response: {(resp_data or b'').hex()[:48]}",
          remediation="Restrict SMB access to trusted networks; disable SMBv1.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
        return probe_result(raw_data=raw, findings=findings)

      # Check if SMBv1 or SMBv2 response
      protocol_id = resp_data[0:4]

      if protocol_id == b"\xffSMB":
        # --- SMBv1 response ---
        raw["smbv1_supported"] = True
        raw["banner"] = "SMBv1 negotiation response received"

        # Parse negotiate response body (after 32-byte header)
        if len(resp_data) >= 37:
          word_count = resp_data[32]
          if word_count >= 17 and len(resp_data) >= 32 + 1 + 34:
            words_start = 33
            dialect_idx = struct.unpack_from("<H", resp_data, words_start)[0]
            security_mode = resp_data[words_start + 2]
            raw["signing_required"] = bool(security_mode & 0x08)
            raw["dialect"] = "NT LM 0.12" if dialect_idx == 0 else f"dialect_{dialect_idx}"

            # Byte data after word parameters (17 words = 34 bytes)
            byte_offset = words_start + 2 + (word_count * 2)
            if byte_offset + 2 <= len(resp_data):
              byte_count = struct.unpack_from("<H", resp_data, byte_offset)[0]
              blob = resp_data[byte_offset + 2:]

              # After security blob: OemDomainName\x00\x00ServerName\x00\x00 (unicode)
              # The security blob length is in word 11 (22 bytes from words_start+2)
              if word_count >= 17 and len(resp_data) >= words_start + 2 + 22 + 2:
                sec_blob_len = struct.unpack_from("<H", resp_data, words_start + 2 + 22)[0]
                after_blob = blob[sec_blob_len:]
                # Try to extract unicode strings (OemDomainName, ServerName)
                try:
                  str_data = after_blob.decode("utf-16-le", errors="ignore")
                  parts = str_data.split("\x00")
                  parts = [p for p in parts if p]
                  if len(parts) >= 1:
                    raw["server_domain"] = parts[0]
                  if len(parts) >= 2:
                    raw["server_name"] = parts[1]
                except Exception:
                  pass

        # SMBv1 is a security concern
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="SMBv1 protocol supported (legacy, attack surface for MS17-010)",
          description=f"SMB on {target}:{port} supports SMBv1, which is vulnerable to "
                      "EternalBlue (MS17-010) and other SMBv1-specific attacks.",
          evidence=f"Negotiated dialect: {raw['dialect']}, SMBv1 response received.",
          remediation="Disable SMBv1 on the server (e.g., 'server min protocol = SMB2' in smb.conf).",
          owasp_id="A06:2021",
          cwe_id="CWE-757",
          confidence="certain",
        ))

      elif protocol_id == b"\xfeSMB":
        # --- SMBv2/3 response ---
        raw["banner"] = "SMBv2 negotiation response received"
        if len(resp_data) >= 72:
          smb2_dialect = struct.unpack_from("<H", resp_data, 68)[0]
          dialect_map = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1",
                        0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}
          raw["dialect"] = dialect_map.get(smb2_dialect, f"0x{smb2_dialect:04x}")
          # Security mode: offset 70
          security_mode = struct.unpack_from("<H", resp_data, 70)[0]
          raw["signing_required"] = bool(security_mode & 0x02)
      else:
        raw["banner"] = f"Unknown SMB response: {protocol_id.hex()}"

      # --- Signing check ---
      if raw["signing_required"] is False:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="SMB signing not required (relay attacks possible)",
          description=f"SMB on {target}:{port} does not require message signing, "
                      "allowing SMB relay / NTLM relay attacks.",
          evidence=f"Security mode flags indicate signing is not required.",
          remediation="Enable and require SMB signing on the server.",
          owasp_id="A07:2021",
          cwe_id="CWE-287",
          confidence="certain",
        ))

    except Exception as e:
      return probe_error(target, port, "SMB", e)

    # --- 2. Null session for Samba version extraction ---
    samba_version = self._smb_try_null_session(target, port)
    if samba_version:
      raw["samba_version"] = samba_version
      raw["server_os"] = f"Samba {samba_version}"

      findings.append(Finding(
        severity=Severity.LOW,
        title=f"Samba version disclosed: {samba_version}",
        description=f"Samba {samba_version} detected on {target}:{port}.",
        evidence=f"Samba version: {samba_version}",
        remediation="Hide Samba version string if possible.",
        cwe_id="CWE-200",
        confidence="certain",
      ))

      # CVE check
      findings += check_cves("samba", samba_version)

    # Share enumeration via null session
    shares = self._smb_enum_shares(target, port)
    if shares:
      raw["shares"] = shares
      share_names = [s["name"] for s in shares]
      admin_shares = [s["name"] for s in shares if s["name"].upper() in ("ADMIN$", "C$", "D$", "E$")]

      if admin_shares:
        findings.append(Finding(
          severity=Severity.HIGH,
          title=f"SMB admin shares accessible via null session: {', '.join(admin_shares)}",
          description="Administrative shares are accessible without authentication.",
          evidence=f"Shares: {share_names}",
          remediation="Disable null session access; restrict admin shares.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
      else:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"SMB null session share enumeration ({len(shares)} shares listed)",
          description="Anonymous user can enumerate available SMB shares.",
          evidence=f"Shares: {share_names}",
          remediation="Restrict anonymous share enumeration (RestrictNullSessAccess=1).",
          owasp_id="A01:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))

    if not findings:
      findings.append(Finding(
        severity=Severity.MEDIUM,
        title="SMB service responded to negotiation probe",
        description=f"SMB on {target}:{port} accepts negotiation requests.",
        evidence=f"Banner: {raw.get('banner', 'N/A')}",
        remediation="Restrict SMB access to trusted networks; disable SMBv1.",
        owasp_id="A01:2021",
        cwe_id="CWE-284",
        confidence="certain",
      ))

    return probe_result(raw_data=raw, findings=findings)

  @staticmethod
  def _smb_recv_exact(sock, nbytes):
    """Receive exactly nbytes from socket, or None on failure."""
    buf = b""
    while len(buf) < nbytes:
      chunk = sock.recv(nbytes - len(buf))
      if not chunk:
        return None
      buf += chunk
    return buf

  def _smb_enum_shares(self, target, port):
    """Enumerate SMB shares via null session + IPC$ + srvsvc NetShareEnumAll.

    Performs the full SMBv1 protocol sequence:
      Negotiate -> Session Setup (null) -> Tree Connect IPC$ ->
      Open \\srvsvc pipe -> DCE/RPC Bind -> NetShareEnumAll -> parse results.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      SMB port (typically 445).

    Returns
    -------
    list[dict]
      Each dict has keys ``name`` (str), ``type`` (int), ``comment`` (str).
      Returns empty list on any failure.
    """
    sock = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(4)
      sock.connect((target, port))

      def _send_smb(payload):
        nb_hdr = b"\x00" + struct.pack(">I", len(payload))[1:]
        sock.sendall(nb_hdr + payload)

      def _recv_smb():
        resp_hdr = self._smb_recv_exact(sock, 4)
        if not resp_hdr:
          return None
        resp_len = struct.unpack(">I", b"\x00" + resp_hdr[1:4])[0]
        return self._smb_recv_exact(sock, min(resp_len, 65536))

      # ---- 1. Negotiate (NT LM 0.12) ----
      dialects = b"\x02NT LM 0.12\x00"
      smb_hdr = bytearray(32)
      smb_hdr[0:4] = b"\xffSMB"
      smb_hdr[4] = 0x72  # Negotiate
      smb_hdr[13] = 0x18
      struct.pack_into("<H", smb_hdr, 14, 0xC803)
      smb_body = struct.pack("<BH", 0, len(dialects)) + dialects
      _send_smb(bytes(smb_hdr) + smb_body)

      neg_resp = _recv_smb()
      if not neg_resp or len(neg_resp) < 32:
        return []

      # ---- 2. Session Setup AndX (null creds) ----
      smb_hdr2 = bytearray(32)
      smb_hdr2[0:4] = b"\xffSMB"
      smb_hdr2[4] = 0x73  # Session Setup AndX
      smb_hdr2[13] = 0x18
      struct.pack_into("<H", smb_hdr2, 14, 0xC803)

      words = struct.pack("<BBHHIHIHII",
        13,        # word count
        0xFF,      # AndXCommand: no further
        0,         # reserved
        0,         # AndXOffset
        65535,     # max buffer size
        1,         # max mpx count
        0,         # VC number
        0,         # session key
        0,         # ANSI password length
        0,         # Unicode password length
      )
      words += struct.pack("<I", 0x000000D4)  # capabilities
      byte_data = b"\x00"
      byte_count = struct.pack("<H", len(byte_data))
      _send_smb(bytes(smb_hdr2) + words + byte_count + byte_data)

      sess_resp = _recv_smb()
      if not sess_resp or len(sess_resp) < 32:
        return []

      # Check NT Status (bytes 5-8): 0 = success
      nt_status = struct.unpack_from("<I", sess_resp, 5)[0]
      # Accept STATUS_SUCCESS (0) or STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
      if nt_status not in (0x00000000, 0xC0000016):
        return []

      uid = struct.unpack_from("<H", sess_resp, 28)[0]

      # ---- 3. Tree Connect AndX to \\target\IPC$ ----
      smb_hdr3 = bytearray(32)
      smb_hdr3[0:4] = b"\xffSMB"
      smb_hdr3[4] = 0x75  # Tree Connect AndX
      smb_hdr3[13] = 0x18
      struct.pack_into("<H", smb_hdr3, 14, 0xC803)
      struct.pack_into("<H", smb_hdr3, 28, uid)  # UID

      # Tree Connect AndX words: word_count=4
      path_str = f"\\\\{target}\\IPC$".encode("utf-16-le") + b"\x00\x00"
      service_str = b"?????\x00"
      tc_password = b"\x00"
      tc_byte_data = tc_password + path_str + service_str
      tc_words = struct.pack("<BBHHH",
        4,         # word count
        0xFF,      # AndXCommand: no further
        0,         # reserved
        0,         # AndXOffset
        len(tc_password),  # password length
      )
      tc_byte_count = struct.pack("<H", len(tc_byte_data))
      _send_smb(bytes(smb_hdr3) + tc_words + tc_byte_count + tc_byte_data)

      tc_resp = _recv_smb()
      if not tc_resp or len(tc_resp) < 32:
        return []

      nt_status = struct.unpack_from("<I", tc_resp, 5)[0]
      if nt_status != 0:
        return []

      tid = struct.unpack_from("<H", tc_resp, 24)[0]

      # ---- 4. NT Create AndX -- open \srvsvc named pipe ----
      smb_hdr4 = bytearray(32)
      smb_hdr4[0:4] = b"\xffSMB"
      smb_hdr4[4] = 0xA2  # NT Create AndX
      smb_hdr4[13] = 0x18
      struct.pack_into("<H", smb_hdr4, 14, 0xC803)
      struct.pack_into("<H", smb_hdr4, 24, tid)
      struct.pack_into("<H", smb_hdr4, 28, uid)

      pipe_name = "\\srvsvc".encode("utf-16-le") + b"\x00\x00"
      # NT Create AndX words: word_count=24
      nc_words = struct.pack("<BB", 24, 0xFF)  # word count, AndXCommand
      nc_words += struct.pack("<B", 0)          # reserved
      nc_words += struct.pack("<H", 0)          # AndXOffset
      nc_words += struct.pack("<B", 0)          # reserved2
      nc_words += struct.pack("<H", len(pipe_name))  # name length
      nc_words += struct.pack("<I", 0x00000016)  # create flags
      nc_words += struct.pack("<I", 0)           # root FID
      nc_words += struct.pack("<I", 0x0002019F)  # desired access (read/write/execute)
      nc_words += struct.pack("<Q", 0)           # allocation size
      nc_words += struct.pack("<I", 0)           # ext file attributes
      nc_words += struct.pack("<I", 0x00000007)  # share access (read|write|delete)
      nc_words += struct.pack("<I", 0x00000001)  # create disposition (open)
      nc_words += struct.pack("<I", 0x00000000)  # create options
      nc_words += struct.pack("<I", 0x00000002)  # impersonation level
      nc_words += struct.pack("<B", 0)           # security flags

      nc_byte_count = struct.pack("<H", len(pipe_name))
      _send_smb(bytes(smb_hdr4) + nc_words + nc_byte_count + pipe_name)

      nc_resp = _recv_smb()
      if not nc_resp or len(nc_resp) < 42:
        return []

      nt_status = struct.unpack_from("<I", nc_resp, 5)[0]
      if nt_status != 0:
        return []

      # FID is in NT Create AndX response words.
      # SMB header (32) + word_count(1) + AndXCommand(1) + reserved(1) +
      #   AndXOffset(2) + OpLockLevel(1) + FID(2)
      wc = nc_resp[32]
      if wc < 1:
        return []
      fid = struct.unpack_from("<H", nc_resp, 32 + 1 + 1 + 1 + 2 + 1)[0]  # offset 38

      # ---- 5. DCE/RPC Bind to srvsvc ----
      # srvsvc UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0
      # NDR transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
      srvsvc_uuid = (
        struct.pack("<IHH", 0x4B324FC8, 0x1670, 0x01D3)
        + b"\x12\x78\x5A\x47\xBF\x6E\xE1\x88"
      )
      ndr_uuid = (
        struct.pack("<IHH", 0x8A885D04, 0x1CEB, 0x11C9)
        + b"\x9F\xE8\x08\x00\x2B\x10\x48\x60"
      )

      # Context item: abstract syntax + transfer syntax
      ctx_item = struct.pack("<HBB", 0, 1, 0)  # context_id=0, num_transfer=1, reserved
      ctx_item += srvsvc_uuid + struct.pack("<HH", 3, 0)  # version 3.0
      ctx_item += ndr_uuid + struct.pack("<HH", 2, 0)     # version 2.0

      bind_body = struct.pack("<HHI", 4280, 4280, 0)  # max xmit, max recv, assoc group
      bind_body += struct.pack("<I", 1)  # num_ctx_items (with padding byte included)
      bind_body += ctx_item

      # DCE/RPC header: version=5, minor=0, type=11(bind), flags=3
      dce_hdr = struct.pack("<BBBBIHHI",
        5, 0,        # version major, minor
        11,          # packet type: bind
        3,           # flags: first_frag | last_frag
        0x00000010,  # data representation (little-endian, ASCII, IEEE)
        24 + len(bind_body),  # frag length
        0,           # auth length
        1,           # call id
      )
      bind_pkt = dce_hdr + bind_body

      # Write via SMB Write AndX
      smb_hdr5 = bytearray(32)
      smb_hdr5[0:4] = b"\xffSMB"
      smb_hdr5[4] = 0x2F  # Write AndX
      smb_hdr5[13] = 0x18
      struct.pack_into("<H", smb_hdr5, 14, 0xC803)
      struct.pack_into("<H", smb_hdr5, 24, tid)
      struct.pack_into("<H", smb_hdr5, 28, uid)

      # Write AndX words: word_count=14
      data_offset = 32 + 1 + (14 * 2) + 2  # smb_header + wc_byte + words + byte_count
      wr_words = struct.pack("<BB", 14, 0xFF)   # word count, AndXCommand
      wr_words += struct.pack("<BH", 0, 0)       # reserved, AndXOffset
      wr_words += struct.pack("<H", fid)          # FID
      wr_words += struct.pack("<I", 0)            # offset
      wr_words += struct.pack("<I", 0)            # reserved
      wr_words += struct.pack("<HH", 0x0008, 0)  # write mode (message start), remaining
      wr_words += struct.pack("<HH", 0, len(bind_pkt))  # data length high, data length
      wr_words += struct.pack("<H", data_offset)  # data offset
      wr_words += struct.pack("<I", 0)            # high offset

      wr_byte_count = struct.pack("<H", len(bind_pkt))
      _send_smb(bytes(smb_hdr5) + wr_words + wr_byte_count + bind_pkt)

      wr_resp = _recv_smb()
      if not wr_resp or len(wr_resp) < 32:
        return []

      # ---- Read Bind Ack ----
      smb_hdr6 = bytearray(32)
      smb_hdr6[0:4] = b"\xffSMB"
      smb_hdr6[4] = 0x2E  # Read AndX
      smb_hdr6[13] = 0x18
      struct.pack_into("<H", smb_hdr6, 14, 0xC803)
      struct.pack_into("<H", smb_hdr6, 24, tid)
      struct.pack_into("<H", smb_hdr6, 28, uid)

      # Read AndX words: word_count=12
      rd_words = struct.pack("<BB", 12, 0xFF)   # word count, AndXCommand
      rd_words += struct.pack("<BH", 0, 0)       # reserved, AndXOffset
      rd_words += struct.pack("<H", fid)          # FID
      rd_words += struct.pack("<I", 0)            # offset
      rd_words += struct.pack("<H", 4096)         # max count
      rd_words += struct.pack("<H", 4096)         # min count
      rd_words += struct.pack("<I", 0)            # max count high (timeout)
      rd_words += struct.pack("<H", 0)            # remaining
      rd_words += struct.pack("<I", 0)            # high offset

      rd_byte_count = struct.pack("<H", 0)
      _send_smb(bytes(smb_hdr6) + rd_words + rd_byte_count)

      bind_ack = _recv_smb()
      if not bind_ack or len(bind_ack) < 32:
        return []

      # ---- 6. NetShareEnumAll request (opnum 15) ----
      # Stub data: server name as referent pointer + info level + enum handle
      server_name_u16 = target.encode("utf-16-le") + b"\x00\x00"
      # Pad to 4-byte boundary
      name_padded = server_name_u16
      if len(name_padded) % 4:
        name_padded += b"\x00" * (4 - len(name_padded) % 4)

      char_count = len(server_name_u16) // 2  # number of UTF-16 chars including null

      stub = struct.pack("<I", 0x00020000)        # referent ID (pointer)
      stub += struct.pack("<I", char_count)        # max count
      stub += struct.pack("<I", 0)                 # offset
      stub += struct.pack("<I", char_count)        # actual count
      stub += name_padded                          # server name (UTF-16LE, padded)
      stub += struct.pack("<I", 1)                 # info level = 1
      stub += struct.pack("<I", 1)                 # switch value = 1
      stub += struct.pack("<I", 0x00020004)        # info struct pointer (referent)
      stub += struct.pack("<I", 0)                 # entries read = 0
      stub += struct.pack("<I", 0)                 # null buffer pointer
      stub += struct.pack("<I", 0xFFFFFFFF)        # preferred max length
      stub += struct.pack("<I", 0)                 # resume handle pointer (referent)
      stub += struct.pack("<I", 0)                 # resume handle value

      dce_req_hdr = struct.pack("<BBBBIHHI",
        5, 0,        # version
        0,           # packet type: request
        3,           # flags: first_frag | last_frag
        0x00000010,  # data representation
        24 + 8 + len(stub),  # frag length (hdr + req fields + stub)
        0,           # auth length
        2,           # call id
      )
      # Request PDU fields: alloc_hint, context_id, opnum
      dce_req_body = struct.pack("<IHH", len(stub), 0, 15)  # opnum 15 = NetShareEnumAll
      req_pkt = dce_req_hdr + dce_req_body + stub

      # Write the request
      smb_hdr7 = bytearray(32)
      smb_hdr7[0:4] = b"\xffSMB"
      smb_hdr7[4] = 0x2F  # Write AndX
      smb_hdr7[13] = 0x18
      struct.pack_into("<H", smb_hdr7, 14, 0xC803)
      struct.pack_into("<H", smb_hdr7, 24, tid)
      struct.pack_into("<H", smb_hdr7, 28, uid)

      data_offset2 = 32 + 1 + (14 * 2) + 2
      wr_words2 = struct.pack("<BB", 14, 0xFF)
      wr_words2 += struct.pack("<BH", 0, 0)
      wr_words2 += struct.pack("<H", fid)
      wr_words2 += struct.pack("<I", 0)
      wr_words2 += struct.pack("<I", 0)
      wr_words2 += struct.pack("<HH", 0x0008, 0)
      wr_words2 += struct.pack("<HH", 0, len(req_pkt))
      wr_words2 += struct.pack("<H", data_offset2)
      wr_words2 += struct.pack("<I", 0)

      wr2_byte_count = struct.pack("<H", len(req_pkt))
      _send_smb(bytes(smb_hdr7) + wr_words2 + wr2_byte_count + req_pkt)

      wr2_resp = _recv_smb()
      if not wr2_resp or len(wr2_resp) < 32:
        return []

      # ---- Read NetShareEnumAll response ----
      smb_hdr8 = bytearray(32)
      smb_hdr8[0:4] = b"\xffSMB"
      smb_hdr8[4] = 0x2E  # Read AndX
      smb_hdr8[13] = 0x18
      struct.pack_into("<H", smb_hdr8, 14, 0xC803)
      struct.pack_into("<H", smb_hdr8, 24, tid)
      struct.pack_into("<H", smb_hdr8, 28, uid)

      rd_words2 = struct.pack("<BB", 12, 0xFF)
      rd_words2 += struct.pack("<BH", 0, 0)
      rd_words2 += struct.pack("<H", fid)
      rd_words2 += struct.pack("<I", 0)
      rd_words2 += struct.pack("<H", 8192)
      rd_words2 += struct.pack("<H", 0)
      rd_words2 += struct.pack("<I", 0)
      rd_words2 += struct.pack("<H", 0)
      rd_words2 += struct.pack("<I", 0)

      rd2_byte_count = struct.pack("<H", 0)
      _send_smb(bytes(smb_hdr8) + rd_words2 + rd2_byte_count)

      enum_resp = _recv_smb()
      if not enum_resp or len(enum_resp) < 60:
        return []

      # ---- 7. Parse the response ----
      # Find DCE/RPC response data inside the SMB Read AndX response.
      # SMB Read AndX response: header(32) + word_count(1) + words(wc*2) +
      #   byte_count(2) + pad + data.
      wc8 = enum_resp[32]
      if wc8 < 12:
        return []
      # Data offset from start of SMB header is at word 6 (0-indexed)
      data_off = struct.unpack_from("<H", enum_resp, 32 + 1 + 11 * 2)[0]
      data_len = struct.unpack_from("<H", enum_resp, 32 + 1 + 5 * 2)[0]

      if data_off + data_len > len(enum_resp):
        data_len = len(enum_resp) - data_off
      if data_off >= len(enum_resp) or data_len < 24:
        return []

      dce_data = enum_resp[data_off:data_off + data_len]

      # DCE/RPC response header is 24 bytes, then stub data
      if len(dce_data) < 24:
        return []
      dce_stub = dce_data[24:]

      return self._parse_netshareenumall_response(dce_stub)

    except Exception:
      return []
    finally:
      if sock:
        try:
          sock.close()
        except Exception:
          pass

  @staticmethod
  def _parse_netshareenumall_response(stub):
    """Parse NetShareEnumAll DCE/RPC stub response into share list.

    Parameters
    ----------
    stub : bytes
      DCE/RPC stub data (after the 24-byte response header).

    Returns
    -------
    list[dict]
      Each dict: {"name": str, "type": int, "comment": str}.
    """
    shares = []
    try:
      if len(stub) < 20:
        return []

      # Response stub layout:
      # [4] info_level
      # [4] switch_value
      # [4] referent pointer for SHARE_INFO_1_CONTAINER
      # [4] entries_read
      # [4] referent pointer for array
      # Then for each entry: [4] name_ptr, [4] type, [4] comment_ptr
      # Then the actual strings (NDR conformant arrays)

      offset = 0
      offset += 4  # info_level
      offset += 4  # switch_value
      offset += 4  # referent pointer
      if offset + 4 > len(stub):
        return []
      entries_read = struct.unpack_from("<I", stub, offset)[0]
      offset += 4

      if entries_read == 0 or entries_read > 500:
        return []

      offset += 4  # array referent pointer
      offset += 4  # max count (NDR array header)

      # Read the fixed-size entries: name_ptr(4) + type(4) + comment_ptr(4) each
      entry_records = []
      for _ in range(entries_read):
        if offset + 12 > len(stub):
          break
        name_ptr = struct.unpack_from("<I", stub, offset)[0]
        share_type = struct.unpack_from("<I", stub, offset + 4)[0]
        comment_ptr = struct.unpack_from("<I", stub, offset + 8)[0]
        entry_records.append((name_ptr, share_type, comment_ptr))
        offset += 12

      # Now read the NDR conformant strings (name then comment for each entry)
      def read_ndr_string(data, off):
        """Read an NDR conformant+varying Unicode string."""
        if off + 12 > len(data):
          return "", off
        max_count = struct.unpack_from("<I", data, off)[0]
        off += 4
        str_offset = struct.unpack_from("<I", data, off)[0]
        off += 4
        actual_count = struct.unpack_from("<I", data, off)[0]
        off += 4
        byte_len = actual_count * 2  # UTF-16LE
        if off + byte_len > len(data):
          s = data[off:].decode("utf-16-le", errors="ignore").rstrip("\x00")
          return s, len(data)
        s = data[off:off + byte_len].decode("utf-16-le", errors="ignore").rstrip("\x00")
        off += byte_len
        # Align to 4-byte boundary
        if off % 4:
          off += 4 - (off % 4)
        return s, off

      for name_ptr, share_type, comment_ptr in entry_records:
        name, offset = read_ndr_string(stub, offset)
        comment, offset = read_ndr_string(stub, offset)
        if name:
          shares.append({
            "name": name,
            "type": share_type,
            "comment": comment,
          })

    except Exception:
      pass
    return shares

  def _smb_try_null_session(self, target, port):
    """Attempt SMBv1 null session to extract Samba version from SessionSetup response.

    Returns
    -------
    str or None
      Extracted Samba version string (e.g. '4.6.3'), or None.
    """
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))

      # --- Negotiate ---
      dialects = b"\x02NT LM 0.12\x00"
      smb_header = bytearray(32)
      smb_header[0:4] = b"\xffSMB"
      smb_header[4] = 0x72  # Negotiate
      smb_header[13] = 0x18
      struct.pack_into("<H", smb_header, 14, 0xC803)
      smb_body = struct.pack("<BH", 0, len(dialects)) + dialects
      payload = bytes(smb_header) + smb_body
      nb_hdr = b"\x00" + struct.pack(">I", len(payload))[1:]
      sock.sendall(nb_hdr + payload)

      # Read negotiate response
      resp_hdr = self._smb_recv_exact(sock, 4)
      if not resp_hdr:
        sock.close()
        return None
      resp_len = struct.unpack(">I", b"\x00" + resp_hdr[1:4])[0]
      self._smb_recv_exact(sock, min(resp_len, 4096))

      # --- Session Setup AndX (null session) ---
      smb_header2 = bytearray(32)
      smb_header2[0:4] = b"\xffSMB"
      smb_header2[4] = 0x73  # Session Setup AndX
      smb_header2[13] = 0x18
      struct.pack_into("<H", smb_header2, 14, 0xC803)

      # Word count = 13 (standard Session Setup AndX)
      words = struct.pack("<BBHHIHIHII",
        13,        # word count
        0xFF,      # AndXCommand: no further commands
        0,         # reserved
        0,         # AndXOffset
        65535,     # max buffer size
        1,         # max mpx count
        0,         # VC number
        0,         # session key (low)
        0,         # ANSI password length
        0,         # Unicode password length
      )
      # Capabilities
      words += struct.pack("<I", 0x000000D4)

      # Byte data: empty passwords + NativeOS + NativeLanManager
      byte_data = b"\x00"  # null padding for alignment
      byte_count = struct.pack("<H", len(byte_data))
      payload2 = bytes(smb_header2) + words + byte_count + byte_data

      nb_hdr2 = b"\x00" + struct.pack(">I", len(payload2))[1:]
      sock.sendall(nb_hdr2 + payload2)

      # Read session setup response
      resp_hdr2 = self._smb_recv_exact(sock, 4)
      if not resp_hdr2:
        sock.close()
        return None
      resp_len2 = struct.unpack(">I", b"\x00" + resp_hdr2[1:4])[0]
      resp_data2 = self._smb_recv_exact(sock, min(resp_len2, 4096))
      sock.close()

      if not resp_data2:
        return None

      # Extract NativeOS string — contains "Samba x.y.z" or "Windows ..."
      # Search the response bytes for "Samba" followed by a version
      resp_text = resp_data2.decode("utf-8", errors="ignore")
      samba_match = _re.search(r'Samba\s+(\d+\.\d+(?:\.\d+)?)', resp_text)
      if samba_match:
        return samba_match.group(1)

      # Also try UTF-16-LE decoding
      resp_text_u16 = resp_data2.decode("utf-16-le", errors="ignore")
      samba_match_u16 = _re.search(r'Samba\s+(\d+\.\d+(?:\.\d+)?)', resp_text_u16)
      if samba_match_u16:
        return samba_match_u16.group(1)

    except Exception:
      pass
    return None


  # NetBIOS name suffix → human-readable type
  _NBNS_SUFFIX_TYPES = {
    0x00: "Workstation",
    0x03: "Messenger (logged-in user)",
    0x20: "File Server (SMB sharing)",
    0x1C: "Domain Controller",
    0x1B: "Domain Master Browser",
    0x1E: "Browser Election Service",
  }

  def _service_info_wins(self, target, port):  # ports: 42 (WINS/TCP), 137 (NBNS/UDP)
    """
    Probe WINS / NetBIOS Name Service for name enumeration and service detection.

    Port 42 (TCP): WINS replication — sends MS-WINSRA Association Start Request
    to fingerprint the service and extract NBNS version.  Also fires a UDP
    side-probe to port 137 for NetBIOS name enumeration.
    Port 137 (UDP): NBNS — sends wildcard node-status query (RFC 1002) to
    enumerate registered NetBIOS names.

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
    raw = {"banner": None, "netbios_names": [], "wins_responded": False}

    # -- Build NetBIOS wildcard node-status query (RFC 1002) --
    tid = struct.pack('>H', random.randint(0, 0xFFFF))
    #   Flags: 0x0010 (recursion desired)
    #   Questions: 1, Answers/Auth/Additional: 0
    header = tid + struct.pack('>HHHHH', 0x0010, 1, 0, 0, 0)
    #   Encoded wildcard name "*" (first-level NetBIOS encoding)
    #   '*' (0x2A) → half-bytes 0x02, 0x0A → chars 'C','K', padded with 'A' (0x00 half-bytes)
    qname = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
    #   Type: NBSTAT (0x0021), Class: IN (0x0001)
    question = struct.pack('>HH', 0x0021, 0x0001)
    nbns_query = header + qname + question

    def _parse_nbns_response(data):
      """Parse a NetBIOS node-status response and return list of (name, suffix, flags)."""
      names = []
      if len(data) < 14:
        return names
      # Verify transaction ID matches
      if data[:2] != tid:
        return names
      ancount = struct.unpack('>H', data[6:8])[0]
      if ancount == 0:
        return names
      # Skip past header (12 bytes) then answer name (compressed pointer or full)
      idx = 12
      if idx < len(data) and data[idx] & 0xC0 == 0xC0:
        idx += 2
      else:
        while idx < len(data) and data[idx] != 0:
          idx += data[idx] + 1
        idx += 1
      # Type (2) + Class (2) + TTL (4) + RDLength (2) = 10 bytes
      if idx + 10 > len(data):
        return names
      idx += 10
      if idx >= len(data):
        return names
      num_names = data[idx]
      idx += 1
      # Each name entry: 15 bytes name + 1 byte suffix + 2 bytes flags = 18 bytes
      for _ in range(num_names):
        if idx + 18 > len(data):
          break
        name_bytes = data[idx:idx + 15]
        suffix = data[idx + 15]
        flags = struct.unpack('>H', data[idx + 16:idx + 18])[0]
        name = name_bytes.decode('ascii', errors='ignore').rstrip()
        names.append((name, suffix, flags))
        idx += 18
      return names

    def _udp_nbns_probe(udp_port):
      """Send UDP NBNS wildcard query, return parsed names or empty list."""
      sock = None
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(nbns_query, (target, udp_port))
        data, _ = sock.recvfrom(1024)
        return _parse_nbns_response(data)
      except Exception:
        return []
      finally:
        if sock is not None:
          sock.close()

    def _add_nbns_findings(names, probe_label):
      """Populate raw data and findings from enumerated NetBIOS names."""
      raw["netbios_names"] = [
        {"name": n, "suffix": f"0x{s:02X}", "type": self._NBNS_SUFFIX_TYPES.get(s, f"Unknown(0x{s:02X})")}
        for n, s, _f in names
      ]
      name_list = "; ".join(
        f"{n} <{s:02X}> ({self._NBNS_SUFFIX_TYPES.get(s, 'unknown')})"
        for n, s, _f in names
      )
      findings.append(Finding(
        severity=Severity.HIGH,
        title="NetBIOS name enumeration successful",
        description=(
          f"{probe_label} responded to a wildcard node-status query, "
          "leaking computer name, domain membership, and potentially logged-in users."
        ),
        evidence=f"Names: {name_list[:200]}",
        remediation="Block UDP port 137 at the firewall; disable NetBIOS over TCP/IP in network adapter settings.",
        owasp_id="A01:2021",
        cwe_id="CWE-200",
        confidence="certain",
      ))
      findings.append(Finding(
        severity=Severity.INFO,
        title=f"NetBIOS names discovered ({len(names)} entries)",
        description=f"Enumerated names: {name_list}",
        evidence=f"Names: {name_list[:300]}",
        confidence="certain",
      ))

    try:
      if port == 137:
        # -- Direct UDP NBNS probe --
        names = _udp_nbns_probe(137)
        if names:
          raw["banner"] = f"NBNS: {len(names)} name(s) enumerated"
          _add_nbns_findings(names, f"NBNS on {target}:{port}")
        else:
          raw["banner"] = "NBNS port open (no response to wildcard query)"
          findings.append(Finding(
            severity=Severity.INFO,
            title="NBNS port open but no names returned",
            description=f"UDP port {port} on {target} did not respond to NetBIOS wildcard query.",
            confidence="tentative",
          ))
      else:
        # -- TCP WINS replication probe (MS-WINSRA Association Start Request) --
        # Also attempt UDP NBNS side-probe to port 137 for name enumeration
        names = _udp_nbns_probe(137)
        if names:
          _add_nbns_findings(names, f"NBNS side-probe to {target}:137")

        # Build MS-WINSRA Association Start Request per [MS-WINSRA] §2.2.3:
        #   Common Header (16 bytes):
        #     Packet Length:               41 (0x00000029) — excludes this field
        #     Reserved:                    0x00007800 (opcode, ignored by spec)
        #     Destination Assoc Handle:    0x00000000 (first message, unknown)
        #     Message Type:                0x00000000 (Association Start Request)
        #   Body (25 bytes):
        #     Sender Assoc Handle:         random 4 bytes
        #     NBNS Major Version:          2 (required)
        #     NBNS Minor Version:          5 (Win2k+)
        #     Reserved:                    21 zero bytes (pad to 41)
        sender_ctx = random.randint(1, 0xFFFFFFFF)
        wrepl_header = struct.pack('>I', 41)           # Packet Length
        wrepl_header += struct.pack('>I', 0x00007800)  # Reserved / opcode
        wrepl_header += struct.pack('>I', 0)           # Destination Assoc Handle
        wrepl_header += struct.pack('>I', 0)           # Message Type: Start Request
        wrepl_body = struct.pack('>I', sender_ctx)     # Sender Assoc Handle
        wrepl_body += struct.pack('>HH', 2, 5)         # Major=2, Minor=5
        wrepl_body += b'\x00' * 21                     # Reserved padding
        wrepl_packet = wrepl_header + wrepl_body

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        sock.sendall(wrepl_packet)

        # Distinguish three recv outcomes:
        #   data received  → parse as WREPL (confirmed WINS)
        #   timeout        → connection held open, no reply (likely WINS, non-partner)
        #   empty / closed → server sent FIN immediately (unconfirmed service)
        data = None
        recv_timed_out = False
        try:
          data = sock.recv(1024)
        except socket.timeout:
          recv_timed_out = True
        finally:
          sock.close()

        if data and len(data) >= 20:
          raw["wins_responded"] = True
          # Parse response: first 4 bytes = Packet Length, next 16 = common header
          resp_msg_type = struct.unpack('>I', data[12:16])[0] if len(data) >= 16 else None
          version_info = ""
          if resp_msg_type == 1 and len(data) >= 24:
            # Association Start Response — extract version
            resp_major = struct.unpack('>H', data[20:22])[0] if len(data) >= 22 else None
            resp_minor = struct.unpack('>H', data[22:24])[0] if len(data) >= 24 else None
            if resp_major is not None:
              version_info = f" (NBNS version {resp_major}.{resp_minor})"
              raw["nbns_version"] = {"major": resp_major, "minor": resp_minor}
          raw["banner"] = f"WINS replication service{version_info}"
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title="WINS replication service exposed",
            description=(
              f"WINS on {target}:{port} responded to a WREPL Association Start Request{version_info}. "
              "WINS is a legacy name-resolution service vulnerable to spoofing, enumeration, and "
              "multiple remote code execution flaws (CVE-2004-1080, CVE-2009-1923, CVE-2009-1924). "
              "It should not be accessible from untrusted networks."
            ),
            evidence=f"WREPL response ({len(data)} bytes): {data[:24].hex()}",
            remediation=(
              "Decommission WINS or restrict TCP port 42 to trusted replication partners. "
              "If WINS is required, apply all patches (MS04-045, MS09-039) and set the registry key "
              "RplOnlyWCnfPnrs=1 to accept replication only from configured partners."
            ),
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
        elif data:
          # Got some data but not enough for a valid WREPL response
          raw["wins_responded"] = True
          raw["banner"] = f"Port {port} responded ({len(data)} bytes, non-WREPL)"
          findings.append(Finding(
            severity=Severity.LOW,
            title=f"Service on port {port} responded but is not standard WINS",
            description=(
              f"TCP port {port} on {target} returned data that does not match the "
              "WINS replication protocol (MS-WINSRA). Another service may be listening."
            ),
            evidence=f"Response ({len(data)} bytes): {data[:32].hex()}",
            confidence="tentative",
          ))
        elif recv_timed_out:
          # Connection accepted AND held open after our WREPL packet, but no
          # reply — consistent with WINS silently dropping a non-partner request
          # (RplOnlyWCnfPnrs=1).  A non-WINS service would typically RST or FIN.
          raw["banner"] = "WINS likely (connection held, no WREPL reply)"
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title="WINS replication port open (non-partner rejected)",
            description=(
              f"TCP port {port} on {target} accepted a WREPL Association Start Request "
              "and held the connection open without responding, consistent with a WINS "
              "server configured to reject non-partner replication (RplOnlyWCnfPnrs=1). "
              "An exposed WINS port is a legacy attack surface subject to remote code "
              "execution flaws (CVE-2004-1080, CVE-2009-1923, CVE-2009-1924)."
            ),
            evidence="TCP connection accepted and held open; WREPL handshake: no reply after 3 s",
            remediation=(
              "Block TCP port 42 at the firewall if WINS replication is not needed. "
              "If required, restrict to trusted replication partners only."
            ),
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="firm",
          ))
        else:
          # recv returned empty — server immediately closed the connection.
          # Cannot confirm WINS; don't produce a finding. The port scan
          # already reports the open port; a "service unconfirmed" finding
          # adds no actionable value to the report.
          pass
    except Exception as e:
      return probe_error(target, port, "WINS/NBNS", e)

    if not findings:
      # Could not confirm WINS — downgrade the protocol label so the UI
      # does not display an unverified "WINS" tag from WELL_KNOWN_PORTS.
      port_protocols = self.state.get("port_protocols")
      if port_protocols and port_protocols.get(port) in ("wins", "nbns"):
        port_protocols[port] = "unknown"
      return None

    return probe_result(raw_data=raw, findings=findings)

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


  def _service_info_vnc(self, target, port):  # default port: 5900
    """
    VNC handshake: read version banner, negotiate security types.

    Security types:
      1 (None)       → CRITICAL: unauthenticated desktop access
      2 (VNC Auth)   → MEDIUM: DES-based, max 8-char password
      19 (VeNCrypt)  → INFO: TLS-secured
      Other          → LOW: unknown auth type

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
    raw = {"banner": None, "security_types": []}

    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))

      # Read server banner (e.g. "RFB 003.008\n")
      banner = sock.recv(12).decode('ascii', errors='ignore').strip()
      raw["banner"] = banner

      if not banner.startswith("RFB"):
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"VNC service detected (non-standard banner: {banner[:30]})",
          description="VNC port open but banner is non-standard.",
          evidence=f"Banner: {banner}",
          remediation="Restrict VNC access to trusted networks or use SSH tunneling.",
          confidence="tentative",
        ))
        sock.close()
        return probe_result(raw_data=raw, findings=findings)

      # Echo version back to negotiate
      sock.sendall(banner.encode('ascii') + b"\n")

      # Read security type list
      sec_data = sock.recv(64)
      sec_types = []
      if len(sec_data) >= 1:
        num_types = sec_data[0]
        if num_types > 0 and len(sec_data) >= 1 + num_types:
          sec_types = list(sec_data[1:1 + num_types])
      raw["security_types"] = sec_types
      sock.close()

      _VNC_TYPE_NAMES = {1: "None", 2: "VNC Auth", 19: "VeNCrypt", 16: "Tight"}
      type_labels = [f"{t}({_VNC_TYPE_NAMES.get(t, 'unknown')})" for t in sec_types]
      raw["security_type_labels"] = type_labels

      if 1 in sec_types:
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title="VNC unauthenticated access (security type None)",
          description=f"VNC on {target}:{port} allows connections without authentication.",
          evidence=f"Banner: {banner}, security types: {type_labels}",
          remediation="Disable security type None and require VNC Auth or VeNCrypt.",
          owasp_id="A07:2021",
          cwe_id="CWE-287",
          confidence="certain",
        ))
      if 2 in sec_types:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="VNC password auth (DES-based, max 8 chars)",
          description=f"VNC Auth uses DES encryption with a maximum 8-character password.",
          evidence=f"Banner: {banner}, security types: {type_labels}",
          remediation="Use VeNCrypt (TLS) or SSH tunneling instead of plain VNC Auth.",
          owasp_id="A02:2021",
          cwe_id="CWE-326",
          confidence="certain",
        ))
      if 19 in sec_types:
        findings.append(Finding(
          severity=Severity.INFO,
          title="VNC VeNCrypt (TLS-secured)",
          description="VeNCrypt provides TLS-secured VNC connections.",
          evidence=f"Banner: {banner}, security types: {type_labels}",
          confidence="certain",
        ))
      if not sec_types:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title=f"VNC service exposed: {banner}",
          description="VNC protocol banner detected but security types could not be parsed.",
          evidence=f"Banner: {banner}",
          remediation="Restrict VNC access to trusted networks.",
          confidence="firm",
        ))

    except Exception as e:
      return probe_error(target, port, "VNC", e)

    return probe_result(raw_data=raw, findings=findings)


  def _service_info_snmp(self, target, port):  # default port: 161
    """
    Attempt SNMP community string disclosure using 'public'.

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
    raw = {"banner": None}
    sock = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2)
      packet = bytes.fromhex(
        "302e020103300702010304067075626c6963a019020405f5e10002010002010030100406082b060102010101000500"
      )
      sock.sendto(packet, (target, port))
      data, _ = sock.recvfrom(512)
      readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
      if 'public' in readable.lower():
        raw["banner"] = readable.strip()[:120]
        findings.append(Finding(
          severity=Severity.HIGH,
          title="SNMP default community string 'public' accepted",
          description="SNMP agent responds to the default 'public' community string, "
                      "allowing unauthenticated read access to device configuration and network data.",
          evidence=f"Response: {readable.strip()[:80]}",
          remediation="Change the community string from 'public' to a strong value; migrate to SNMPv3.",
          owasp_id="A07:2021",
          cwe_id="CWE-798",
          confidence="certain",
        ))
        # Walk system MIB for additional intel
        mib_result = self._snmp_walk_system_mib(target, port)
        if mib_result:
          sys_info = mib_result.get("system", {})
          raw.update(sys_info)
          findings.extend(mib_result.get("findings", []))
      else:
        raw["banner"] = readable.strip()[:120]
        findings.append(Finding(
          severity=Severity.INFO,
          title="SNMP service responded",
          description=f"SNMP agent on {target}:{port} responded but did not accept 'public' community.",
          evidence=f"Response: {readable.strip()[:80]}",
          confidence="firm",
        ))
    except socket.timeout:
      return probe_error(target, port, "SNMP", Exception("timed out"))
    except Exception as e:
      return probe_error(target, port, "SNMP", e)
    finally:
      if sock is not None:
        sock.close()
    return probe_result(raw_data=raw, findings=findings)

  # -- SNMP MIB walk helpers ------------------------------------------------

  _ICS_KEYWORDS = frozenset({
    "siemens", "simatic", "schneider", "allen-bradley", "honeywell",
    "abb", "modicon", "rockwell", "yokogawa", "emerson", "ge fanuc",
  })

  def _is_ics_indicator(self, text):
    lower = text.lower()
    return any(kw in lower for kw in self._ICS_KEYWORDS)

  @staticmethod
  def _snmp_encode_oid(oid_str):
    parts = [int(p) for p in oid_str.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for v in parts[2:]:
      if v < 128:
        body += bytes([v])
      else:
        chunks = []
        chunks.append(v & 0x7F)
        v >>= 7
        while v:
          chunks.append(0x80 | (v & 0x7F))
          v >>= 7
        body += bytes(reversed(chunks))
    return body

  def _snmp_build_getnext(self, community, oid_str, request_id=1):
    oid_body = self._snmp_encode_oid(oid_str)
    oid_tlv = bytes([0x06, len(oid_body)]) + oid_body
    varbind = bytes([0x30, len(oid_tlv) + 2]) + oid_tlv + b"\x05\x00"
    varbind_seq = bytes([0x30, len(varbind)]) + varbind
    req_id = bytes([0x02, 0x01, request_id & 0xFF])
    err_status = b"\x02\x01\x00"
    err_index = b"\x02\x01\x00"
    pdu_body = req_id + err_status + err_index + varbind_seq
    pdu = bytes([0xA1, len(pdu_body)]) + pdu_body
    version = b"\x02\x01\x00"
    comm = bytes([0x04, len(community)]) + community.encode()
    inner = version + comm + pdu
    return bytes([0x30, len(inner)]) + inner

  @staticmethod
  def _snmp_parse_response(data):
    try:
      pos = 0
      if data[pos] != 0x30:
        return None, None
      pos += 2  # skip SEQUENCE tag + length
      # skip version
      if data[pos] != 0x02:
        return None, None
      pos += 2 + data[pos + 1]
      # skip community
      if data[pos] != 0x04:
        return None, None
      pos += 2 + data[pos + 1]
      # response PDU (0xA2)
      if data[pos] != 0xA2:
        return None, None
      pos += 2
      # skip request-id, error-status, error-index (3 integers)
      for _ in range(3):
        pos += 2 + data[pos + 1]
      # varbind list SEQUENCE
      pos += 2  # skip SEQUENCE tag + length
      # first varbind SEQUENCE
      pos += 2  # skip SEQUENCE tag + length
      # OID
      if data[pos] != 0x06:
        return None, None
      oid_len = data[pos + 1]
      oid_bytes = data[pos + 2: pos + 2 + oid_len]
      # decode OID
      parts = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
      i = 1
      while i < len(oid_bytes):
        if oid_bytes[i] < 128:
          parts.append(str(oid_bytes[i]))
          i += 1
        else:
          val = 0
          while i < len(oid_bytes) and oid_bytes[i] & 0x80:
            val = (val << 7) | (oid_bytes[i] & 0x7F)
            i += 1
          if i < len(oid_bytes):
            val = (val << 7) | oid_bytes[i]
            i += 1
          parts.append(str(val))
      oid_str = ".".join(parts)
      pos += 2 + oid_len
      # value
      val_tag = data[pos]
      val_len = data[pos + 1]
      val_raw = data[pos + 2: pos + 2 + val_len]
      if val_tag == 0x04:  # OCTET STRING
        value = val_raw.decode("utf-8", errors="replace")
      elif val_tag == 0x02:  # INTEGER
        value = str(int.from_bytes(val_raw, "big", signed=True))
      elif val_tag == 0x43:  # TimeTicks
        value = str(int.from_bytes(val_raw, "big"))
      elif val_tag == 0x40:  # IpAddress (APPLICATION 0)
        if len(val_raw) == 4:
          value = ".".join(str(b) for b in val_raw)
        else:
          value = val_raw.hex()
      else:
        value = val_raw.hex()
      return oid_str, value
    except Exception:
      return None, None

  _SYSTEM_OID_NAMES = {
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation",
  }

  def _snmp_walk_system_mib(self, target, port):
    import ipaddress as _ipaddress
    system = {}
    walk_findings = []
    sock = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2)

      def _walk(prefix):
        oid = prefix
        results = []
        for _ in range(20):
          pkt = self._snmp_build_getnext("public", oid)
          sock.sendto(pkt, (target, port))
          try:
            resp, _ = sock.recvfrom(1024)
          except socket.timeout:
            break
          resp_oid, resp_val = self._snmp_parse_response(resp)
          if resp_oid is None or not resp_oid.startswith(prefix + "."):
            break
          results.append((resp_oid, resp_val))
          oid = resp_oid
        return results

      # Walk system MIB subtree
      for resp_oid, resp_val in _walk("1.3.6.1.2.1.1"):
        base = ".".join(resp_oid.split(".")[:8])
        name = self._SYSTEM_OID_NAMES.get(base)
        if name:
          system[name] = resp_val

      sys_descr = system.get("sysDescr", "")
      if sys_descr:
        self._emit_metadata("os_claims", f"snmp:{port}", sys_descr)
        if self._is_ics_indicator(sys_descr):
          walk_findings.append(Finding(
            severity=Severity.HIGH,
            title="SNMP exposes ICS/SCADA device identity",
            description=f"sysDescr contains ICS keywords: {sys_descr[:120]}",
            evidence=f"sysDescr={sys_descr[:120]}",
            remediation="Isolate ICS devices from general network; restrict SNMP access.",
            confidence="firm",
          ))

      # Walk ipAddrTable for interface IPs
      for resp_oid, resp_val in _walk("1.3.6.1.2.1.4.20.1.1"):
        try:
          addr = _ipaddress.ip_address(resp_val)
        except (ValueError, TypeError):
          continue
        if addr.is_private:
          self._emit_metadata("internal_ips", {"ip": str(addr), "source": f"snmp_interface:{port}"})
          walk_findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"SNMP leaks internal IP address {addr}",
            description="Interface IP from ipAddrTable is RFC1918, revealing internal topology.",
            evidence=f"ipAddrEntry={resp_val}",
            remediation="Restrict SNMP read access; filter sensitive MIBs.",
            confidence="certain",
          ))
    except Exception:
      pass
    finally:
      if sock is not None:
        sock.close()
    if not system and not walk_findings:
      return None
    return {"system": system, "findings": walk_findings}

  def _service_info_dns(self, target, port):  # default port: 53
    """
    Query CHAOS TXT version.bind to detect DNS version disclosure.

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
    raw = {"banner": None, "dns_version": None}
    sock = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2)
      tid = random.randint(0, 0xffff)
      header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
      qname = b'\x07version\x04bind\x00'
      question = struct.pack('>HH', 16, 3)
      packet = header + qname + question
      sock.sendto(packet, (target, port))
      data, _ = sock.recvfrom(512)

      # Parse CHAOS TXT response
      parsed = False
      if len(data) >= 12 and struct.unpack('>H', data[:2])[0] == tid:
        ancount = struct.unpack('>H', data[6:8])[0]
        if ancount:
          idx = 12 + len(qname) + 4
          if idx < len(data):
            if data[idx] & 0xc0 == 0xc0:
              idx += 2
            else:
              while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
              idx += 1
            idx += 8
            if idx + 2 <= len(data):
              rdlength = struct.unpack('>H', data[idx:idx+2])[0]
              idx += 2
              if idx < len(data):
                txt_length = data[idx]
                txt = data[idx+1:idx+1+txt_length].decode('utf-8', errors='ignore')
                if txt:
                  raw["dns_version"] = txt
                  raw["banner"] = f"DNS version: {txt}"
                  findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"DNS version disclosure: {txt}",
                    description=f"CHAOS TXT version.bind query reveals DNS software version.",
                    evidence=f"version.bind TXT: {txt}",
                    remediation="Disable version.bind responses in the DNS server configuration.",
                    owasp_id="A05:2021",
                    cwe_id="CWE-200",
                    confidence="certain",
                  ))
                  parsed = True

      # Fallback: check raw data for version keywords
      if not parsed:
        readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        if 'bind' in readable.lower() or 'version' in readable.lower():
          raw["banner"] = readable.strip()[:80]
          findings.append(Finding(
            severity=Severity.LOW,
            title="DNS version disclosure via CHAOS TXT",
            description=f"CHAOS TXT response on {target}:{port} contains version keywords.",
            evidence=f"Response contains: {readable.strip()[:80]}",
            remediation="Disable version.bind responses in the DNS server configuration.",
            owasp_id="A05:2021",
            cwe_id="CWE-200",
            confidence="firm",
          ))
        else:
          raw["banner"] = "DNS service responding"
          findings.append(Finding(
            severity=Severity.INFO,
            title="DNS CHAOS TXT query did not disclose version",
            description=f"DNS on {target}:{port} responded but did not reveal version.",
            confidence="firm",
          ))
    except socket.timeout:
      return probe_error(target, port, "DNS", Exception("CHAOS query timed out"))
    except Exception as e:
      return probe_error(target, port, "DNS", e)
    finally:
      if sock is not None:
        sock.close()

    # --- DNS zone transfer (AXFR) test ---
    axfr_findings = self._dns_test_axfr(target, port)
    findings += axfr_findings

    # --- Open recursive resolver test ---
    resolver_finding = self._dns_test_open_resolver(target, port)
    if resolver_finding:
      findings.append(resolver_finding)

    return probe_result(raw_data=raw, findings=findings)

  def _dns_test_axfr(self, target, port):
    """Attempt DNS zone transfer (AXFR) via TCP.

    Returns list of findings.
    """
    findings = []

    # Derive domain from reverse DNS of target, or use a common test domain
    test_domains = []
    try:
      import socket as _socket
      hostname, _, _ = _socket.gethostbyaddr(target)
      # Extract domain from hostname (e.g., "host.example.com" → "example.com")
      parts = hostname.split(".")
      if len(parts) >= 2:
        test_domains.append(".".join(parts[-2:]))
      if len(parts) >= 3:
        test_domains.append(".".join(parts[-3:]))
    except Exception:
      pass

    # Always test with the target itself as a domain if nothing else
    if not test_domains:
      test_domains = ["vulhub.org", "example.com"]

    for domain in test_domains[:2]:  # Test at most 2 domains
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))

        # Build AXFR query
        tid = random.randint(0, 0xffff)
        header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
        # Encode domain name
        qname = b""
        for label in domain.split("."):
          qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        # QTYPE=252 (AXFR), QCLASS=1 (IN)
        question = struct.pack('>HH', 252, 1)
        dns_query = header + qname + question
        # TCP DNS: 2-byte length prefix
        sock.sendall(struct.pack(">H", len(dns_query)) + dns_query)

        # Read response
        resp_len_bytes = sock.recv(2)
        if len(resp_len_bytes) < 2:
          sock.close()
          continue
        resp_len = struct.unpack(">H", resp_len_bytes)[0]
        resp_data = b""
        while len(resp_data) < resp_len:
          chunk = sock.recv(resp_len - len(resp_data))
          if not chunk:
            break
          resp_data += chunk
        sock.close()

        # Parse: check if we got answers (ancount > 0) and no error (rcode = 0)
        if len(resp_data) >= 12:
          resp_tid = struct.unpack(">H", resp_data[0:2])[0]
          flags = struct.unpack(">H", resp_data[2:4])[0]
          rcode = flags & 0x0F
          ancount = struct.unpack(">H", resp_data[6:8])[0]

          if resp_tid == tid and rcode == 0 and ancount > 0:
            findings.append(Finding(
              severity=Severity.HIGH,
              title=f"DNS zone transfer (AXFR) allowed for {domain}",
              description=f"DNS on {target}:{port} permits zone transfers for '{domain}'. "
                          "This leaks all DNS records — hostnames, IPs, mail servers, internal infrastructure.",
              evidence=f"AXFR query returned {ancount} answer records for {domain}.",
              remediation="Restrict zone transfers to authorized secondary nameservers only (allow-transfer).",
              owasp_id="A01:2021",
              cwe_id="CWE-200",
              confidence="certain",
            ))
            break  # One confirmed AXFR is enough
      except Exception:
        continue

    return findings

  def _dns_test_open_resolver(self, target, port):
    """Test if DNS server acts as an open recursive resolver.

    Returns Finding or None.
    """
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2)
      tid = random.randint(0, 0xffff)
      # Standard recursive query for example.com A record
      header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)  # RD=1
      qname = b'\x07example\x03com\x00'
      question = struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
      packet = header + qname + question
      sock.sendto(packet, (target, port))
      data, _ = sock.recvfrom(512)
      sock.close()

      if len(data) >= 12 and struct.unpack('>H', data[:2])[0] == tid:
        flags = struct.unpack('>H', data[2:4])[0]
        qr = (flags >> 15) & 1
        rcode = flags & 0x0F
        ancount = struct.unpack('>H', data[6:8])[0]
        ra = (flags >> 7) & 1  # Recursion Available

        if qr == 1 and rcode == 0 and ancount > 0 and ra == 1:
          return Finding(
            severity=Severity.MEDIUM,
            title="DNS open recursive resolver detected",
            description=f"DNS on {target}:{port} recursively resolves queries for external domains. "
                        "Open resolvers can be abused for DNS amplification DDoS attacks.",
            evidence=f"Recursive query for example.com returned {ancount} answers with RA flag set.",
            remediation="Restrict recursive queries to authorized clients only (allow-recursion).",
            owasp_id="A05:2021",
            cwe_id="CWE-406",
            confidence="certain",
          )
    except Exception:
      pass
    return None

  def _service_info_mssql(self, target, port):  # default port: 1433
    """
    Send a TDS prelogin probe to expose SQL Server version data.

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
    raw = {"banner": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      prelogin = bytes.fromhex(
        "1201001600000000000000000000000000000000000000000000000000000000"
      )
      sock.sendall(prelogin)
      data = sock.recv(256)
      if data:
        readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        raw["banner"] = f"MSSQL prelogin response: {readable.strip()[:80]}"
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="MSSQL prelogin handshake succeeded",
          description=f"SQL Server on {target}:{port} responds to TDS prelogin, "
                      "exposing version metadata and confirming the service is reachable.",
          evidence=f"Prelogin response: {readable.strip()[:80]}",
          remediation="Restrict SQL Server access to trusted networks; use firewall rules.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "MSSQL", e)
    return probe_result(raw_data=raw, findings=findings)


  def _service_info_postgresql(self, target, port):  # default port: 5432
    """
    Probe PostgreSQL authentication method and extract server version.

    Sends a v3 StartupMessage for user 'postgres'.  The server replies with
    an authentication request (type 'R') optionally followed by ParameterStatus
    messages (type 'S') that include ``server_version``.

    Auth codes:
      0  = AuthenticationOk (trust auth) → CRITICAL
      3  = CleartextPassword             → MEDIUM
      5  = MD5Password                   → INFO (adequate, prefer SCRAM)
      10 = SASL (SCRAM-SHA-256)          → INFO (strong)
    """
    findings = []
    raw = {"auth_type": None, "version": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      payload = b'user\x00postgres\x00database\x00postgres\x00\x00'
      startup = struct.pack('!I', len(payload) + 8) + struct.pack('!I', 196608) + payload
      sock.sendall(startup)
      # Read enough to get auth response + parameter status messages
      data = b""
      try:
        while len(data) < 4096:
          chunk = sock.recv(4096)
          if not chunk:
            break
          data += chunk
          # Stop after we see auth request — parameters come after for trust auth
          # but for password auth the server sends R then waits.
          if len(data) >= 9 and data[0:1] == b'R':
            auth_code = struct.unpack('!I', data[5:9])[0]
            if auth_code != 0:
              break  # Server wants a password — no more data coming
      except (socket.timeout, OSError):
        pass
      sock.close()

      # --- Extract version from ParameterStatus ('S') messages ---
      # Format: 'S' + int32 length + key\0 + value\0
      pg_version = None
      pos = 0
      while pos < len(data) - 5:
        msg_type = data[pos:pos+1]
        if msg_type not in (b'R', b'S', b'K', b'Z', b'E', b'N'):
          break
        msg_len = struct.unpack('!I', data[pos+1:pos+5])[0]
        msg_end = pos + 1 + msg_len
        if msg_type == b'S' and msg_end <= len(data):
          kv = data[pos+5:msg_end]
          parts = kv.split(b'\x00')
          if len(parts) >= 2:
            key = parts[0].decode('utf-8', errors='ignore')
            val = parts[1].decode('utf-8', errors='ignore')
            if key == 'server_version':
              pg_version = val
              raw["version"] = pg_version
        pos = msg_end
        if pos >= len(data):
          break

      # --- Parse auth response ---
      if len(data) >= 9 and data[0:1] == b'R':
        auth_code = struct.unpack('!I', data[5:9])[0]
        raw["auth_type"] = auth_code
        if auth_code == 0:
          findings.append(Finding(
            severity=Severity.CRITICAL,
            title="PostgreSQL trust authentication (no password)",
            description=f"PostgreSQL on {target}:{port} accepts connections without any password (auth code 0).",
            evidence=f"Auth response code: {auth_code}",
            remediation="Configure pg_hba.conf to require password or SCRAM authentication.",
            owasp_id="A07:2021",
            cwe_id="CWE-287",
            confidence="certain",
          ))
        elif auth_code == 3:
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title="PostgreSQL cleartext password authentication",
            description=f"PostgreSQL on {target}:{port} requests cleartext passwords.",
            evidence=f"Auth response code: {auth_code}",
            remediation="Switch to SCRAM-SHA-256 authentication in pg_hba.conf.",
            owasp_id="A02:2021",
            cwe_id="CWE-319",
            confidence="certain",
          ))
        elif auth_code == 5:
          findings.append(Finding(
            severity=Severity.INFO,
            title="PostgreSQL MD5 authentication",
            description="MD5 password auth is adequate but SCRAM-SHA-256 is preferred.",
            evidence=f"Auth response code: {auth_code}",
            remediation="Consider upgrading to SCRAM-SHA-256.",
            confidence="certain",
          ))
        elif auth_code == 10:
          findings.append(Finding(
            severity=Severity.INFO,
            title="PostgreSQL SASL/SCRAM authentication",
            description="Strong authentication (SCRAM-SHA-256) is in use.",
            evidence=f"Auth response code: {auth_code}",
            confidence="certain",
          ))
      elif b'AuthenticationCleartextPassword' in data:
        raw["auth_type"] = "cleartext_text"
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="PostgreSQL cleartext password authentication",
          description=f"PostgreSQL on {target}:{port} requests cleartext passwords.",
          evidence="Text response contained AuthenticationCleartextPassword",
          remediation="Switch to SCRAM-SHA-256 authentication.",
          owasp_id="A02:2021",
          cwe_id="CWE-319",
          confidence="firm",
        ))
      elif b'AuthenticationOk' in data:
        raw["auth_type"] = "ok_text"
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title="PostgreSQL trust authentication (no password)",
          description=f"PostgreSQL on {target}:{port} accepted connection without authentication.",
          evidence="Text response contained AuthenticationOk",
          remediation="Configure pg_hba.conf to require password authentication.",
          owasp_id="A07:2021",
          cwe_id="CWE-287",
          confidence="firm",
        ))

      # --- Version disclosure ---
      if pg_version:
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"PostgreSQL version disclosed: {pg_version}",
          description=f"PostgreSQL on {target}:{port} reports version {pg_version}.",
          evidence=f"server_version parameter: {pg_version}",
          remediation="Restrict network access to the PostgreSQL port.",
          cwe_id="CWE-200",
          confidence="certain",
        ))
        # Extract numeric version for CVE matching
        ver_match = _re.match(r'(\d+\.\d+(?:\.\d+)?)', pg_version)
        if ver_match:
          for f in check_cves("postgresql", ver_match.group(1)):
            findings.append(f)

      if not findings:
        findings.append(Finding(Severity.INFO, "PostgreSQL probe completed", "No auth weakness detected."))
    except Exception as e:
      return probe_error(target, port, "PostgreSQL", e)

    return probe_result(raw_data=raw, findings=findings)

  def _service_info_postgresql_creds(self, target, port):  # default port: 5432
    """
    PostgreSQL default credential testing (opt-in via active_auth feature group).

    Attempts cleartext password auth with common defaults.

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
    raw = {"tested_credentials": 0, "accepted_credentials": []}
    creds = [("postgres", ""), ("postgres", "postgres"), ("postgres", "password")]

    for username, password in creds:
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        payload = f'user\x00{username}\x00database\x00postgres\x00\x00'.encode()
        startup = struct.pack('!I', len(payload) + 8) + struct.pack('!I', 196608) + payload
        sock.sendall(startup)
        data = sock.recv(128)

        if len(data) >= 9 and data[0:1] == b'R':
          auth_code = struct.unpack('!I', data[5:9])[0]
          if auth_code == 0:
            cred_str = f"{username}:(empty)" if not password else f"{username}:{password}"
            raw["accepted_credentials"].append(cred_str)
            findings.append(Finding(
              severity=Severity.CRITICAL,
              title=f"PostgreSQL trust auth for {username}",
              description=f"No password required for user {username}.",
              evidence=f"Auth code 0 for {cred_str}",
              remediation="Configure pg_hba.conf to require authentication.",
              owasp_id="A07:2021",
              cwe_id="CWE-287",
              confidence="certain",
            ))
          elif auth_code == 3:
            # Send cleartext password
            pwd_bytes = password.encode() + b'\x00'
            pwd_msg = b'p' + struct.pack('!I', len(pwd_bytes) + 4) + pwd_bytes
            sock.sendall(pwd_msg)
            resp = sock.recv(128)
            if resp and resp[0:1] == b'R' and len(resp) >= 9:
              result_code = struct.unpack('!I', resp[5:9])[0]
              if result_code == 0:
                cred_str = f"{username}:{password}" if password else f"{username}:(empty)"
                raw["accepted_credentials"].append(cred_str)
                findings.append(Finding(
                  severity=Severity.CRITICAL,
                  title=f"PostgreSQL default credential accepted: {cred_str}",
                  description=f"Cleartext password auth accepted for {cred_str}.",
                  evidence=f"Auth OK for {cred_str}",
                  remediation="Change default passwords.",
                  owasp_id="A07:2021",
                  cwe_id="CWE-798",
                  confidence="certain",
                ))
        raw["tested_credentials"] += 1
        sock.close()
      except Exception:
        continue

    if not findings:
      findings.append(Finding(
        severity=Severity.INFO,
        title="PostgreSQL default credentials rejected",
        description=f"Tested {raw['tested_credentials']} credential pairs.",
        confidence="certain",
      ))

    return probe_result(raw_data=raw, findings=findings)

  def _service_info_memcached(self, target, port):  # default port: 11211
    """
    Issue Memcached stats command to detect unauthenticated access.

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
    raw = {"banner": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))

      # Extract version
      sock.sendall(b'version\r\n')
      ver_data = sock.recv(64).decode("utf-8", errors="replace").strip()
      ver_match = _re.match(r'VERSION\s+(\d+(?:\.\d+)+)', ver_data)
      if ver_match:
        raw["version"] = ver_match.group(1)
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"Memcached version disclosed: {raw['version']}",
          description=f"Memcached on {target}:{port} reveals version via VERSION command.",
          evidence=f"VERSION {raw['version']}",
          remediation="Restrict access to memcached to trusted networks.",
          cwe_id="CWE-200",
          confidence="certain",
        ))
        findings += check_cves("memcached", raw["version"])

      sock.sendall(b'stats\r\n')
      data = sock.recv(128)
      if data.startswith(b'STAT'):
        raw["banner"] = data.decode("utf-8", errors="replace").strip()[:120]
        findings.append(Finding(
          severity=Severity.HIGH,
          title="Memcached stats accessible without authentication",
          description=f"Memcached on {target}:{port} responds to stats without authentication, "
                      "exposing cache metadata and enabling cache poisoning or data exfiltration.",
          evidence=f"stats command returned: {raw['banner'][:80]}",
          remediation="Bind Memcached to localhost or use SASL authentication; restrict network access.",
          owasp_id="A07:2021",
          cwe_id="CWE-287",
          confidence="certain",
        ))
      else:
        raw["banner"] = "Memcached port open"
        findings.append(Finding(
          severity=Severity.INFO,
          title="Memcached port open",
          description=f"Memcached port {port} is open on {target} but stats command was not accepted.",
          evidence=f"Response: {data[:60].decode('utf-8', errors='replace')}",
          confidence="firm",
        ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "Memcached", e)
    return probe_result(raw_data=raw, findings=findings)


  def _service_info_elasticsearch(self, target, port):  # default port: 9200
    """
    Deep Elasticsearch probe: cluster info, index listing, node IPs, CVE matching.

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
    findings, raw = [], {"cluster_name": None, "version": None}
    base_url = f"http://{target}" if port == 80 else f"http://{target}:{port}"

    # First check if this is actually Elasticsearch (GET / must return JSON with cluster_name or tagline)
    findings += self._es_check_root(base_url, raw)
    if not raw["cluster_name"] and not raw.get("tagline"):
      # Not Elasticsearch — skip further probing to avoid noise on regular HTTP ports
      return None

    findings += self._es_check_indices(base_url, raw)
    findings += self._es_check_nodes(base_url, raw)

    if raw["version"]:
      findings += check_cves("elasticsearch", raw["version"])

    if not findings:
      findings.append(Finding(Severity.INFO, "Elasticsearch probe clean", "No issues detected."))

    return probe_result(raw_data=raw, findings=findings)

  def _es_check_root(self, base_url, raw):
    """GET / — extract version, cluster name."""
    findings = []
    try:
      resp = requests.get(base_url, timeout=3)
      if resp.ok:
        try:
          data = resp.json()
          raw["cluster_name"] = data.get("cluster_name")
          ver_info = data.get("version", {})
          raw["version"] = ver_info.get("number") if isinstance(ver_info, dict) else None
          raw["tagline"] = data.get("tagline")
          findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Elasticsearch cluster metadata exposed",
            description=f"Cluster '{raw['cluster_name']}' version {raw['version']} accessible without auth.",
            evidence=f"cluster={raw['cluster_name']}, version={raw['version']}",
            remediation="Enable X-Pack security or restrict network access.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
        except Exception:
          if 'cluster_name' in resp.text:
            findings.append(Finding(
              severity=Severity.HIGH,
              title="Elasticsearch cluster metadata exposed",
              description=f"Cluster metadata accessible at {base_url}.",
              evidence=resp.text[:200],
              remediation="Enable authentication.",
              owasp_id="A01:2021",
              cwe_id="CWE-284",
              confidence="firm",
            ))
    except Exception:
      pass
    return findings

  def _es_check_indices(self, base_url, raw):
    """GET /_cat/indices — list accessible indices."""
    findings = []
    try:
      resp = requests.get(f"{base_url}/_cat/indices?v", timeout=3)
      if resp.ok and resp.text.strip():
        lines = resp.text.strip().split("\n")
        index_count = max(0, len(lines) - 1)  # subtract header
        raw["index_count"] = index_count
        if index_count > 0:
          findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Elasticsearch {index_count} indices accessible",
            description=f"{index_count} indices listed without authentication.",
            evidence="\n".join(lines[:6]),
            remediation="Enable authentication and restrict index access.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
    except Exception:
      pass
    return findings

  def _es_check_nodes(self, base_url, raw):
    """GET /_nodes — extract transport/publish addresses, classify IPs, check JVM."""
    findings = []
    try:
      resp = requests.get(f"{base_url}/_nodes", timeout=3)
      if resp.ok:
        data = resp.json()
        nodes = data.get("nodes", {})
        ips = set()
        for node in nodes.values():
          for key in ("transport_address", "publish_address", "host"):
            val = node.get(key) or ""
            ip = val.rsplit(":", 1)[0] if ":" in val else val
            if ip and ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
              ips.add(ip)
          settings = node.get("settings", {})
          if isinstance(settings, dict):
            net = settings.get("network", {})
            if isinstance(net, dict):
              for k in ("host", "publish_host"):
                v = net.get(k)
                if v and v not in ("127.0.0.1", "localhost", "0.0.0.0"):
                  ips.add(v)

        if ips:
          import ipaddress as _ipaddress
          raw["node_ips"] = list(ips)
          public_ips, private_ips = [], []
          for ip_str in ips:
            try:
              is_priv = _ipaddress.ip_address(ip_str).is_private
            except (ValueError, TypeError):
              is_priv = True  # assume private on parse failure
            if is_priv:
              private_ips.append(ip_str)
            else:
              public_ips.append(ip_str)
            self._emit_metadata("internal_ips", {"ip": ip_str, "source": "es_nodes"})

          if public_ips:
            findings.append(Finding(
              severity=Severity.CRITICAL,
              title=f"Elasticsearch leaks real public IP: {', '.join(sorted(public_ips)[:3])}",
              description="The _nodes endpoint exposes public IP addresses, potentially revealing "
                          "the real infrastructure behind NAT/VPN/honeypot.",
              evidence=f"Public IPs: {', '.join(sorted(public_ips))}",
              remediation="Restrict /_nodes endpoint; configure network.publish_host to a safe value.",
              owasp_id="A01:2021",
              cwe_id="CWE-200",
              confidence="certain",
            ))
          if private_ips:
            findings.append(Finding(
              severity=Severity.MEDIUM,
              title=f"Elasticsearch node internal IPs disclosed ({len(private_ips)})",
              description=f"Node API exposes internal IPs: {', '.join(sorted(private_ips)[:5])}",
              evidence=f"IPs: {', '.join(sorted(private_ips)[:10])}",
              remediation="Restrict /_nodes endpoint access.",
              owasp_id="A01:2021",
              cwe_id="CWE-200",
              confidence="certain",
            ))

        # --- JVM version extraction ---
        for node in nodes.values():
          jvm = node.get("jvm", {})
          if isinstance(jvm, dict):
            jvm_version = jvm.get("version")
            if jvm_version:
              raw["jvm_version"] = jvm_version
              try:
                if jvm_version.startswith("1."):
                  # Java 1.x format: 1.7.0_55 → major=7, 1.8.0_345 → major=8
                  major = int(jvm_version.split(".")[1])
                else:
                  # Modern format: 17.0.5 → major=17
                  major = int(str(jvm_version).split(".")[0])
                if major <= 8:
                  findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Elasticsearch running on EOL JVM: Java {jvm_version}",
                    description=f"Java {jvm_version} is end-of-life and no longer receives security patches.",
                    evidence=f"jvm.version={jvm_version}",
                    remediation="Upgrade to a supported Java LTS release (17+).",
                    owasp_id="A06:2021",
                    cwe_id="CWE-1104",
                    confidence="certain",
                  ))
              except (ValueError, IndexError):
                pass
              break  # one node is enough
    except Exception:
      pass
    return findings


  def _service_info_modbus(self, target, port):  # default port: 502
    """
    Send Modbus device identification request to detect exposed PLCs.

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
    raw = {"banner": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      request = b'\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00'
      sock.sendall(request)
      data = sock.recv(256)
      if data:
        readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        raw["banner"] = readable.strip()[:120]
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title="Modbus device responded to identification request",
          description=f"Industrial control system on {target}:{port} is accessible without authentication. "
                      "Modbus has no built-in security — any network access means full device control.",
          evidence=f"Device ID response: {readable.strip()[:80]}",
          remediation="Isolate Modbus devices on a dedicated OT network; deploy a Modbus-aware firewall.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "Modbus", e)
    return probe_result(raw_data=raw, findings=findings)


  def _service_info_mongodb(self, target, port):  # default port: 27017
    """
    Attempt MongoDB isMaster + buildInfo to detect unauthenticated access
    and extract the server version for CVE matching.
    """
    findings = []
    raw = {"banner": None, "version": None}
    try:
      # --- Pass 1: isMaster ---
      is_master = False
      data = self._mongodb_query(target, port, b'isMaster')
      if data and (b'ismaster' in data or b'isMaster' in data):
        is_master = True

      if is_master:
        raw["banner"] = "MongoDB isMaster response"
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title="MongoDB unauthenticated access (isMaster responded)",
          description=f"MongoDB on {target}:{port} accepts commands without authentication, "
                      "allowing full database read/write access.",
          evidence="isMaster command succeeded without credentials.",
          remediation="Enable MongoDB authentication (--auth) and bind to localhost or trusted networks.",
          owasp_id="A07:2021",
          cwe_id="CWE-287",
          confidence="certain",
        ))

        # --- Pass 2: buildInfo (for version) ---
        build_data = self._mongodb_query(target, port, b'buildInfo')
        mongo_version = self._mongodb_extract_bson_string(build_data, b'version')
        if mongo_version:
          raw["version"] = mongo_version
          findings.append(Finding(
            severity=Severity.LOW,
            title=f"MongoDB version disclosed: {mongo_version}",
            description=f"MongoDB on {target}:{port} reports version {mongo_version}.",
            evidence=f"buildInfo version: {mongo_version}",
            remediation="Restrict network access to the MongoDB port.",
            cwe_id="CWE-200",
            confidence="certain",
          ))
          ver_match = _re.match(r'(\d+\.\d+(?:\.\d+)?)', mongo_version)
          if ver_match:
            for f in check_cves("mongodb", ver_match.group(1)):
              findings.append(f)

    except Exception as e:
      return probe_error(target, port, "MongoDB", e)
    return probe_result(raw_data=raw, findings=findings)

  @staticmethod
  def _mongodb_query(target, port, command_name):
    """Send a MongoDB OP_QUERY command and return the raw response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((target, port))
    # Build BSON: {<command_name>: 1}
    field = b'\x10' + command_name + b'\x00' + struct.pack('<i', 1)
    doc_body = field + b'\x00'
    doc = struct.pack('<i', 4 + len(doc_body)) + doc_body
    collection = b'admin.$cmd\x00'
    msg = (struct.pack('<i', 0) + collection
           + struct.pack('<i', 0) + struct.pack('<i', -1) + doc)
    header = struct.pack('<iiii', 16 + len(msg), 1, 0, 2004)
    sock.sendall(header + msg)
    try:
      data = sock.recv(4096)
    except (socket.timeout, OSError):
      data = b""
    sock.close()
    return data

  @staticmethod
  def _mongodb_extract_bson_string(data, field_name):
    """Extract a UTF-8 string field from a MongoDB BSON response.

    Looks for BSON type 0x02 (UTF-8 string) with the given field name.
    Returns the string value or None.
    """
    if not data:
      return None
    marker = b'\x02' + field_name + b'\x00'
    idx = data.find(marker)
    if idx < 0:
      return None
    str_start = idx + len(marker)
    if str_start + 4 > len(data):
      return None
    str_len = struct.unpack('<i', data[str_start:str_start+4])[0]
    if str_len <= 0 or str_start + 4 + str_len > len(data):
      return None
    return data[str_start+4:str_start+4+str_len-1].decode('utf-8', errors='ignore')



  # Product patterns for generic banner version extraction.
  # Maps regex → CVE DB product name.  Each regex must have a named group 'ver'.
  _GENERIC_BANNER_PATTERNS = [
    (_re.compile(r'OpenSSH[_\s](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "openssh"),
    (_re.compile(r'Apache[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "apache"),
    (_re.compile(r'nginx[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "nginx"),
    (_re.compile(r'Exim\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "exim"),
    (_re.compile(r'Postfix[/ ]?(?:.*?smtpd)?\s*(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "postfix"),
    (_re.compile(r'ProFTPD\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "proftpd"),
    (_re.compile(r'vsftpd\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "vsftpd"),
    (_re.compile(r'Redis[/ ](?:server\s+)?v?(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "redis"),
    (_re.compile(r'Samba\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "samba"),
    (_re.compile(r'Asterisk\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "asterisk"),
    (_re.compile(r'MySQL[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "mysql"),
    (_re.compile(r'PostgreSQL\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "postgresql"),
    (_re.compile(r'MongoDB\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "mongodb"),
    (_re.compile(r'Elasticsearch[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "elasticsearch"),
    (_re.compile(r'memcached\s+(?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "memcached"),
    (_re.compile(r'TightVNC[/ ](?P<ver>\d+\.\d+(?:\.\d+)?)', _re.I), "tightvnc"),
  ]

  def _service_info_generic(self, target, port):
    """
    Attempt a generic TCP banner grab for uncovered ports.

    Performs three checks on the banner:
    1. Version disclosure — flags any product/version string as info leak.
    2. CVE matching — runs extracted versions against the CVE database.
    3. Unauthenticated data exposure — flags services that send data
       without any client request (potential auth bypass).

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
    raw = {"banner": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      raw_bytes = sock.recv(512)
      sock.close()
      if not raw_bytes:
        return None
    except Exception as e:
      return probe_error(target, port, "generic", e)

    # --- Protocol fingerprinting: detect known services on non-standard ports ---
    reclassified = self._generic_fingerprint_protocol(raw_bytes, target, port)
    if reclassified is not None:
      return reclassified

    # --- Standard banner analysis for truly unknown services ---
    data = raw_bytes.decode('utf-8', errors='ignore')
    banner = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in data)
    readable = banner.strip().replace('.', '')
    if not readable:
      return None
    raw["banner"] = banner.strip()
    banner_text = raw["banner"]

    # --- 1. Version extraction + CVE check ---
    for pattern, product in self._GENERIC_BANNER_PATTERNS:
      m = pattern.search(banner_text)
      if m:
        version = m.group("ver")
        raw["product"] = product
        raw["version"] = version
        findings.append(Finding(
          severity=Severity.LOW,
          title=f"Service version disclosed: {product} {version}",
          description=f"Banner on {target}:{port} reveals {product} {version}. "
                      "Version disclosure aids attackers in targeting known vulnerabilities.",
          evidence=f"Banner: {banner_text[:80]}",
          remediation="Suppress or genericize the service banner.",
          cwe_id="CWE-200",
          confidence="certain",
        ))
        findings += check_cves(product, version)
        break  # First match wins

    return probe_result(raw_data=raw, findings=findings)

  # Protocol signatures for reclassifying services on non-standard ports.
  # Each entry: (check_function, protocol_name, probe_method_name)
  # Check functions receive raw bytes and return True if matched.
  @staticmethod
  def _is_redis_banner(data):
    """Redis RESP: starts with +, -, :, $, or * (protocol type bytes)."""
    return len(data) > 0 and data[0:1] in (b'+', b'-', b'$', b'*', b':')

  @staticmethod
  def _is_ftp_banner(data):
    """FTP: 220 greeting."""
    return data[:4] in (b'220 ', b'220-')

  @staticmethod
  def _is_smtp_banner(data):
    """SMTP: 220 greeting with SMTP/ESMTP keyword."""
    text = data[:200].decode('utf-8', errors='ignore').upper()
    return text.startswith('220') and ('SMTP' in text or 'ESMTP' in text)

  @staticmethod
  def _is_mysql_handshake(data):
    """MySQL: 3-byte length + seq + protocol version 0x0a."""
    if len(data) > 4:
      payload = data[4:]
      return payload[0:1] == b'\x0a'
    return False

  @staticmethod
  def _is_rsync_banner(data):
    """Rsync: @RSYNCD: version."""
    return data.startswith(b'@RSYNCD:')

  @staticmethod
  def _is_telnet_banner(data):
    """Telnet: IAC (0xFF) followed by WILL/WONT/DO/DONT."""
    return len(data) >= 2 and data[0] == 0xFF and data[1] in (0xFB, 0xFC, 0xFD, 0xFE)

  _PROTOCOL_SIGNATURES = None  # lazy init to avoid forward reference issues

  def _generic_fingerprint_protocol(self, raw_bytes, target, port):
    """Try to identify the protocol from raw banner bytes.

    If a known protocol is detected, reclassifies the port and runs the
    appropriate specialized probe directly.

    Returns
    -------
    dict or None
        Probe result from the specialized probe, or None if no match.
    """
    signatures = [
      (self._is_redis_banner, "redis", "_service_info_redis"),
      (self._is_ftp_banner, "ftp", "_service_info_ftp"),
      (self._is_smtp_banner, "smtp", "_service_info_smtp"),
      (self._is_mysql_handshake, "mysql", "_service_info_mysql"),
      (self._is_rsync_banner, "rsync", "_service_info_rsync"),
      (self._is_telnet_banner, "telnet", "_service_info_telnet"),
    ]

    for check_fn, proto, method_name in signatures:
      try:
        if check_fn(raw_bytes):
          # Reclassify port protocol for future reference
          port_protocols = self.state.get("port_protocols", {})
          old_proto = port_protocols.get(port, "unknown")
          port_protocols[port] = proto
          self.P(f"Protocol reclassified: port {port} {old_proto} → {proto} (banner fingerprint)")

          # Run the specialized probe directly
          probe_fn = getattr(self, method_name, None)
          if probe_fn:
            return probe_fn(target, port)
      except Exception:
        continue
    return None
