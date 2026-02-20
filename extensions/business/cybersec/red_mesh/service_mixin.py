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

class _ServiceInfoMixin:
  """
  Network service banner probes feeding RedMesh reports.

  Each helper focuses on a specific protocol and maps findings to
  OWASP vulnerability families. The mixin is intentionally light-weight so
  that `PentestLocalWorker` threads can run without heavy dependencies while
  still surfacing high-signal clues.
  """
  
  def _service_info_80(self, target, port):
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
      return probe_error(target, port, "HTTP", e)

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
  

  def _service_info_8080(self, target, port):
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

        findings.append(Finding(
          severity=Severity.INFO,
          title=f"HTTP service on alternate port {port}",
          description=f"HTTP service responding on {target}:{port}.",
          evidence=f"Status: {status_line}, Server: {raw['server'] or 'not disclosed'}",
          confidence="certain",
        ))
      else:
        raw["banner"] = "(no response)"
        findings.append(Finding(
          severity=Severity.INFO,
          title=f"Port {port} open (no HTTP banner)",
          description="Connection succeeded but no HTTP response received.",
          confidence="tentative",
        ))
    except Exception as e:
      return probe_error(target, port, "HTTP-ALT", e)
    return probe_result(raw_data=raw, findings=findings)  


  def _service_info_443(self, target, port):
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

    # Pass 2: Verified — detect self-signed / chain issues
    findings += self._tls_check_certificate(target, port, raw)

    # Pass 3: Cert content checks (expiry, default CN)
    findings += self._tls_check_expiry(raw)
    findings += self._tls_check_default_cn(raw)

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
    placeholders = ("example.com", "localhost", "internet widgits", "test", "changeme")
    if any(p in cn_lower for p in placeholders):
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


  def _service_info_21(self, target, port):
    """
    Assess FTP service security: banner, anonymous access, default creds,
    server fingerprint, TLS support, write access, and honeypot detection.

    Checks performed (in order):

    1. Banner grab and SYST/FEAT fingerprint.
    2. Anonymous login attempt.
    3. Write access test (STOR) after anonymous login.
    4. Directory listing and traversal.
    5. TLS support check (AUTH TLS).
    6. Default credential check.
    7. Honeypot detection — random credentials accepted.

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

    # --- 7. Honeypot detection — try random credentials ---
    import string as _string
    ruser = "".join(random.choices(_string.ascii_lowercase, k=8))
    rpass = "".join(random.choices(_string.ascii_letters + _string.digits, k=12))
    try:
      ftp_rand = _ftp_connect(ruser, rpass)
      findings.append(Finding(
        severity=Severity.CRITICAL,
        title="FTP accepts arbitrary credentials (possible honeypot).",
        description="Random credentials were accepted, indicating a honeypot or dangerous misconfiguration.",
        evidence=f"Accepted random creds {ruser}:{rpass}",
        remediation="Investigate immediately — this host may be a honeypot or compromised.",
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

  def _service_info_22(self, target, port):
    """
    Assess SSH service security: banner, auth methods, and default credentials.

    Checks performed (in order):

    1. Banner grab — fingerprint server version.
    2. Auth method enumeration — identify if password auth is enabled.
    3. Default credential check — try a small list of common creds.
    4. Weak credential acceptance — flag if *any* password is accepted
       (strong honeypot indicator).

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

    # --- 4. Honeypot / any-password detection ---
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
        title="SSH accepts ANY credentials — possible honeypot or severely misconfigured service.",
        description="Random credentials were accepted, indicating a honeypot or dangerous misconfiguration.",
        evidence=f"Accepted random creds {random_user}:{random_pass}",
        remediation="Investigate immediately — this host may be a honeypot or compromised.",
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
      ssh_version = self._ssh_extract_version(result["banner"])
      if ssh_version:
        result["ssh_version"] = ssh_version
        findings += check_cves("openssh", ssh_version)

    return probe_result(raw_data=result, findings=findings)

  def _ssh_extract_version(self, banner):
    """Extract OpenSSH version from banner like 'SSH-2.0-OpenSSH_8.9p1'."""
    m = _re.search(r'OpenSSH[_\s](\d+\.\d+(?:\.\d+)?)', banner, _re.IGNORECASE)
    return m.group(1) if m else None

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

      transport.close()

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

  def _service_info_25(self, target, port):
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

    # --- 2b. Banner / hostname information disclosure ---
    import re as _re
    banner_text = result["banner"] or ""
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

    if result["server_hostname"]:
      # Check if hostname reveals container/internal info
      hostname = result["server_hostname"]
      if _re.search(r"[0-9a-f]{12}", hostname):
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

  def _service_info_3306(self, target, port):
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

  def _service_info_3306_creds(self, target, port):
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

    return probe_result(raw_data=raw, findings=findings)

  def _service_info_3389(self, target, port):
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
  def _service_info_6379(self, target, port):
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
    for line in resp.split("\r\n"):
      if line.startswith("redis_version:"):
        raw["version"] = line.split(":", 1)[1].strip()
      elif line.startswith("os:"):
        raw["os"] = line.split(":", 1)[1].strip()
    if raw["version"]:
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"Redis version disclosed: {raw['version']}",
        description=f"Redis {raw['version']} on {raw['os'] or 'unknown OS'}.",
        evidence=f"version={raw['version']}, os={raw['os']}",
        remediation="Restrict INFO command access or rename it.",
        confidence="certain",
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


  def _service_info_23(self, target, port):
    """
    Assess Telnet service security: banner, negotiation options, default
    credentials, privilege level, system fingerprint, and honeypot detection.

    Checks performed (in order):

    1. Banner grab and IAC option parsing.
    2. Default credential check — try common user:pass combos.
    3. Privilege escalation check — report if root shell is obtained.
    4. System fingerprint — run ``id`` and ``uname -a`` on successful login.
    5. Honeypot detection — random credentials should be rejected.

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

    # --- 5. Honeypot detection — random credentials ---
    import string as _string
    ruser = "".join(random.choices(_string.ascii_lowercase, k=8))
    rpass = "".join(random.choices(_string.ascii_letters + _string.digits, k=12))
    success, _, _ = _try_telnet_login(ruser, rpass)
    if success:
      findings.append(Finding(
        severity=Severity.CRITICAL,
        title="Telnet accepts arbitrary credentials (possible honeypot).",
        description="Random credentials were accepted, indicating a honeypot or dangerous misconfiguration.",
        evidence=f"Accepted random creds {ruser}:{rpass}",
        remediation="Investigate immediately — this host may be a honeypot or compromised.",
        owasp_id="A07:2021",
        cwe_id="CWE-287",
        confidence="certain",
      ))

    return probe_result(raw_data=result, findings=findings)


  def _service_info_445(self, target, port):
    """
    Probe SMB services for negotiation responses.

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
      probe = b"\x00\x00\x00\x2f\xffSMB" + b"\x00" * 39
      sock.sendall(probe)
      data = sock.recv(4)
      if data:
        raw["banner"] = "SMB negotiation response received"
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="SMB service responded to negotiation probe",
          description=f"SMB on {target}:{port} accepts negotiation requests, "
                      "exposing the host to SMB relay and enumeration attacks.",
          evidence=f"SMB negotiate response: {data.hex()[:24]}",
          remediation="Restrict SMB access to trusted networks; disable SMBv1.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
      else:
        raw["banner"] = "SMB port open (no response)"
        findings.append(Finding(
          severity=Severity.INFO,
          title="SMB port open but no negotiation response",
          description=f"Port {port} is open but SMB did not respond to negotiation.",
          confidence="tentative",
        ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "SMB", e)
    return probe_result(raw_data=raw, findings=findings)


  def _service_info_5900(self, target, port):
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


  def _service_info_161(self, target, port):
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


  def _service_info_53(self, target, port):
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
    return probe_result(raw_data=raw, findings=findings)


  def _service_info_1433(self, target, port):
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


  def _service_info_5432(self, target, port):
    """
    Probe PostgreSQL authentication method by parsing the auth response byte.

    Auth codes:
      0  = AuthenticationOk (trust auth) → CRITICAL
      3  = CleartextPassword             → MEDIUM
      5  = MD5Password                   → INFO (adequate, prefer SCRAM)
      10 = SASL (SCRAM-SHA-256)          → INFO (strong)

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
    raw = {"auth_type": None}
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      payload = b'user\x00postgres\x00database\x00postgres\x00\x00'
      startup = struct.pack('!I', len(payload) + 8) + struct.pack('!I', 196608) + payload
      sock.sendall(startup)
      data = sock.recv(128)
      sock.close()

      # Parse auth response: type byte 'R' (0x52), then int32 length, then int32 auth code
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
        # Fallback: text-based detection for older/non-standard servers
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

      if not findings:
        findings.append(Finding(Severity.INFO, "PostgreSQL probe completed", "No auth weakness detected."))
    except Exception as e:
      return probe_error(target, port, "PostgreSQL", e)

    return probe_result(raw_data=raw, findings=findings)

  def _service_info_5432_creds(self, target, port):
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

  def _service_info_11211(self, target, port):
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


  def _service_info_9200(self, target, port):
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
    """GET /_nodes — extract transport/publish addresses (IP leak)."""
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
            # Extract IP from "1.2.3.4:9300" style
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
          raw["node_ips"] = list(ips)
          findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Elasticsearch node IPs disclosed ({len(ips)})",
            description=f"Node API exposes internal IPs: {', '.join(sorted(ips)[:5])}",
            evidence=f"IPs: {', '.join(sorted(ips)[:10])}",
            remediation="Restrict /_nodes endpoint access.",
            owasp_id="A01:2021",
            cwe_id="CWE-200",
            confidence="certain",
          ))
    except Exception:
      pass
    return findings


  def _service_info_502(self, target, port):
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


  def _service_info_27017(self, target, port):
    """
    Attempt MongoDB isMaster handshake to detect unauthenticated access.

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
      doc = bytearray(b"\x00\x00\x00\x00\x10isMaster\x00")
      doc.extend(struct.pack('<i', 1))
      doc.append(0x00)
      struct.pack_into('<i', doc, 0, len(doc) + 4)
      header_len = 16
      collection = b'admin.$cmd\x00'
      flags = struct.pack('<i', 0)
      number_to_skip = struct.pack('<i', 0)
      number_to_return = struct.pack('<i', -1)
      message = (
        flags + collection + number_to_skip + number_to_return + doc
      )
      total_length = header_len + len(message)
      header = struct.pack('<iiii', total_length, 1, 0, 2004)
      sock.sendall(header + message)
      data = sock.recv(256)
      if b'isMaster' in data or b'ismaster' in data:
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
      sock.close()
    except Exception as e:
      return probe_error(target, port, "MongoDB", e)
    return probe_result(raw_data=raw, findings=findings)



  def _service_info_generic(self, target, port):
    """
    Attempt a generic TCP banner grab for uncovered ports.

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
      data = sock.recv(100).decode('utf-8', errors='ignore')
      if data:
        banner = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in data)
        raw["banner"] = banner.strip()
        findings.append(Finding(
          severity=Severity.INFO,
          title=f"Service banner on port {port}",
          description=f"TCP banner received on {target}:{port}.",
          evidence=f"Banner: {banner.strip()[:80]}",
          confidence="certain",
        ))
      else:
        raw["banner"] = "(no banner)"
        findings.append(Finding(
          severity=Severity.INFO,
          title=f"Port {port} open (no banner)",
          description="Connection succeeded but no banner received; service may require protocol handshake.",
          confidence="tentative",
        ))
      sock.close()
    except Exception as e:
      return probe_error(target, port, "generic", e)
    return probe_result(raw_data=raw, findings=findings)
