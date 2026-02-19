import random
import socket
import struct
import ftplib
import requests
import ssl
from datetime import datetime

import paramiko

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

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

    result = {
      "banner": None,
      "server": None,
      "title": None,
      "technologies": [],
      "dangerous_methods": [],
      "vulnerabilities": [],
    }

    # --- 1. GET request — banner, server, title, tech fingerprint ---
    try:
      self.P(f"Fetching {url} for banner...")
      resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)

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
      return {"error": f"HTTP probe failed on {target}:{port}: {e}"}

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
      result["vulnerabilities"].append(
        "HTTP TRACE method enabled (cross-site tracing / XST attack vector)."
      )
    if "PUT" in dangerous:
      result["vulnerabilities"].append(
        "HTTP PUT method enabled (potential unauthorized file upload)."
      )
    if "DELETE" in dangerous:
      result["vulnerabilities"].append(
        "HTTP DELETE method enabled (potential unauthorized file deletion)."
      )

    return result
  

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
    str | None
      Banner text or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      msg = "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target).encode('utf-8')
      sock.send(bytes(msg))
      data = sock.recv(1024).decode('utf-8', errors='ignore')
      if data:
        banner = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in data)
        info = f"Banner on port {port}: \"{banner.strip()}\""
      else:
        info = "No banner (possibly protocol handshake needed)."
      sock.close()
    except Exception as e:
      info = f"HTTP-ALT probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info  


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
    str | None
      Banner summary or error message.
    """
    info = None
    try:
      url = f"https://{target}"
      if port != 443:
        url = f"https://{target}:{port}"
      self.P(f"Fetching {url} for banner...")
      resp = requests.get(url, timeout=3, verify=False)
      info = (f"HTTPS {resp.status_code} {resp.reason}; Server: {resp.headers.get('Server')}")
    except Exception as e:
      info = f"HTTPS probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


  def _service_info_tls(self, target, port):
    """
    Inspect TLS handshake details and certificate lifetime.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      TLS version/cipher summary or error message.
    """
    info = None
    try:
      context = ssl.create_default_context()
      with socket.create_connection((target, port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
          cert = ssock.getpeercert()
          proto = ssock.version()
          cipher = ssock.cipher()
          expires = cert.get("notAfter")
          info = f"TLS {proto} {cipher[0]}"
          if proto and proto.upper() in ("SSLV3", "SSLV2", "TLSV1", "TLSV1.1"):
            info = f"VULNERABILITY: Obsolete TLS protocol negotiated ({proto}) using {cipher[0]}"
          if expires:
            try:
              exp = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
              days = (exp - datetime.utcnow()).days
              if days <= 30:
                info = f"VULNERABILITY: TLS {proto} {cipher[0]}; certificate expires in {days} days"
              else:
                info = f"TLS {proto} {cipher[0]}; cert exp in {days} days"
            except Exception:
              info = f"TLS {proto} {cipher[0]}; cert expires {expires}"
    except Exception as e:
      info = f"TLS probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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
    result = {
      "banner": None,
      "server_type": None,
      "features": [],
      "anonymous_access": False,
      "write_access": False,
      "tls_supported": False,
      "vulnerabilities": [],
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
      return {"error": f"FTP probe failed on {target}:{port}: {e}"}

    # --- 2. Anonymous login ---
    try:
      resp = ftp.login()
      result["anonymous_access"] = True
      result["vulnerabilities"].append(
        "FTP allows anonymous login."
      )
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
          result["vulnerabilities"].append(
            "FTP anonymous write access enabled (file upload possible)."
          )
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
            result["vulnerabilities"].append(
              f"FTP directory traversal: CWD to '{test_dir}' succeeded."
            )
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
        result["vulnerabilities"].append(
          "FTP does not support TLS encryption (cleartext credentials)."
        )

    # --- 6. Default credential check ---
    for user, passwd in _FTP_DEFAULT_CREDS:
      try:
        ftp_cred = _ftp_connect(user, passwd)
        result["accepted_credentials"].append(f"{user}:{passwd}")
        result["vulnerabilities"].append(
          f"FTP default credential accepted: {user}:{passwd}"
        )
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
      result["vulnerabilities"].append(
        "FTP accepts arbitrary credentials (possible honeypot)."
      )
      try:
        ftp_rand.quit()
      except Exception:
        pass
    except (ftplib.error_perm, ftplib.error_reply):
      pass
    except Exception:
      pass

    return result

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
    result = {
      "banner": None,
      "auth_methods": [],
      "vulnerabilities": [],
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
      return {"error": f"SSH probe failed on {target}:{port}: {e}"}

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
      result["vulnerabilities"].append(
        "SSH password authentication is enabled (prefer key-based auth)."
      )

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
      result["vulnerabilities"].append(
        "SSH accepts ANY credentials — possible honeypot or "
        "severely misconfigured service."
      )
      client.close()
    except paramiko.AuthenticationException:
      pass
    except Exception:
      pass

    if accepted_creds:
      result["accepted_credentials"] = accepted_creds
      for cred in accepted_creds:
        result["vulnerabilities"].append(
          f"SSH default credential accepted: {cred}"
        )

    return result

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

    result = {
      "banner": None,
      "server_hostname": None,
      "max_message_size": None,
      "auth_methods": [],
      "vulnerabilities": [],
    }

    # --- 1. Connect and grab banner ---
    try:
      smtp = smtplib.SMTP(timeout=5)
      code, msg = smtp.connect(target, port)
      result["banner"] = f"{code} {msg.decode(errors='replace')}"
    except Exception as e:
      return {"error": f"SMTP probe failed on {target}:{port}: {e}"}

    # --- 2. EHLO — server capabilities ---
    ehlo_features = []
    try:
      code, msg = smtp.ehlo("probe.redmesh.local")
      if code == 250:
        for line in msg.decode(errors="replace").split("\n"):
          feat = line.strip()
          if feat:
            ehlo_features.append(feat)
    except Exception:
      # Fallback to HELO
      try:
        smtp.helo("probe.redmesh.local")
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
      result["vulnerabilities"].append(
        f"SMTP banner discloses MTA software: {mta} (aids CVE lookup)."
      )

    if result["server_hostname"]:
      # Check if hostname reveals container/internal info
      hostname = result["server_hostname"]
      if _re.search(r"[0-9a-f]{12}", hostname):
        result["vulnerabilities"].append(
          f"SMTP hostname leaks container ID: {hostname} (infrastructure disclosure)."
        )

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
      result["vulnerabilities"].append(
        "SMTP does not support STARTTLS (credentials sent in cleartext)."
      )

    # --- 4. AUTH without credentials ---
    if result["auth_methods"]:
      try:
        code, msg = smtp.docmd("AUTH LOGIN")
        if code == 235:
          result["vulnerabilities"].append(
            "SMTP AUTH LOGIN accepted without credentials."
          )
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
        smtp.ehlo("probe.redmesh.local")
      except Exception:
        smtp = None

    if smtp:
      try:
        code_from, _ = smtp.docmd("MAIL FROM:<probe@redmesh.local>")
        if code_from == 250:
          code_rcpt, _ = smtp.docmd("RCPT TO:<probe@external-domain.test>")
          if code_rcpt == 250:
            result["vulnerabilities"].append(
              "SMTP open relay detected (accepts mail to external domains without auth)."
            )
          smtp.docmd("RSET")
      except Exception:
        pass

    # --- 6. VRFY / EXPN ---
    if smtp:
      for cmd_name in ("VRFY", "EXPN"):
        try:
          code, msg = smtp.docmd(cmd_name, "root")
          if code in (250, 251, 252):
            result["vulnerabilities"].append(
              f"SMTP {cmd_name} command enabled (user enumeration possible)."
            )
        except Exception:
          pass

    if smtp:
      try:
        smtp.quit()
      except Exception:
        pass

    return result

  def _service_info_3306(self, target, port):
    """
    Perform a lightweight MySQL handshake to expose server version.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      MySQL version info or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      data = sock.recv(128)
      if data and data[0] == 0x0a:
        version = data[1:].split(b'\x00')[0].decode('utf-8', errors='ignore')
        info = f"MySQL handshake version: {version}"
      else:
        info = "MySQL port open (no banner)"
      sock.close()
    except Exception as e:
      info = f"MySQL probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info

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
    str | None
      RDP reachability summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      info = "RDP service open (no easy banner)."
      sock.close()
    except Exception as e:
      info = f"RDP probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info

  def _service_info_6379(self, target, port):
    """
    Test Redis exposure by issuing a PING command.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      Redis response summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      sock.send(b"PING\r\n")
      data = sock.recv(64).decode('utf-8', errors='ignore')
      if data.startswith("+PONG"):
        info = "VULNERABILITY: Redis responded to PING (no authentication)."
      elif data.upper().startswith("-NOAUTH"):
        info = "Redis requires authentication (NOAUTH)."
      else:
        info = f"Redis response: {data.strip()}"
      sock.close()
    except Exception as e:
      info = f"Redis probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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

    result = {
      "banner": None,
      "negotiation_options": [],
      "vulnerabilities": [
        "Telnet service is running (unencrypted remote access)."
      ],
      "accepted_credentials": [],
      "system_info": None,
    }

    # --- 1. Banner grab + IAC negotiation parsing ---
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(5)
      sock.connect((target, port))
      raw = sock.recv(2048)
      sock.close()
    except Exception as e:
      return {"error": f"Telnet probe failed on {target}:{port}: {e}"}

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
        result["vulnerabilities"].append(
          f"Telnet default credential accepted: {user}:{passwd}"
        )
        # Check for root access
        if uid_line and "uid=0" in uid_line:
          result["vulnerabilities"].append(
            f"Root shell access via Telnet with {user}:{passwd}."
          )

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
      result["vulnerabilities"].append(
        "Telnet accepts arbitrary credentials (possible honeypot)."
      )

    return result


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
    str | None
      SMB response summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      probe = b"\x00\x00\x00\x2f\xffSMB" + b"\x00" * 39
      sock.sendall(probe)
      data = sock.recv(4)
      if data:
        info = "VULNERABILITY: SMB service responded to negotiation probe."
      else:
        info = "SMB port open but no negotiation response."
      sock.close()
    except Exception as e:
      info = f"SMB probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


  def _service_info_5900(self, target, port):
    """
    Read VNC handshake string to assess remote desktop exposure.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      VNC banner summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      banner = sock.recv(12).decode('ascii', errors='ignore')
      if banner:
        info = f"VULNERABILITY: VNC protocol banner: {banner.strip()}"
      else:
        info = "VULNERABILITY: VNC open with no banner"
      sock.close()
    except Exception as e:
      info = f"VNC probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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
    str | None
      SNMP response summary or error message.
    """
    info = None
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
        info = (
          f"VULNERABILITY: SNMP responds to community 'public' on {target}:{port}"
          f" (response: {readable.strip()[:120]})"
        )
      else:
        info = f"SNMP response: {readable.strip()[:120]}"
    except socket.timeout:
      info = f"SNMP probe timed out on {target}:{port}"
      self.P(info, color='y')
    except Exception as e:
      info = f"SNMP probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    finally:
      if sock is not None:
        sock.close()
    return info


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
    str | None
      DNS disclosure summary or error message.
    """
    info = None
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
      if len(data) < 12:
        return f"DNS CHAOS response too short on {target}:{port}"
      if struct.unpack('>H', data[:2])[0] != tid:
        return f"DNS CHAOS response transaction mismatch on {target}:{port}"
      ancount = struct.unpack('>H', data[6:8])[0]
      if not ancount:
        return f"DNS CHAOS response missing answers on {target}:{port}"
      idx = 12 + len(qname) + 4
      if idx >= len(data):
        return f"DNS CHAOS response truncated after question on {target}:{port}"
      if data[idx] & 0xc0 == 0xc0:
        idx += 2
      else:
        while idx < len(data) and data[idx] != 0:
          idx += data[idx] + 1
        idx += 1
      idx += 8
      if idx + 2 > len(data):
        return f"DNS CHAOS response missing TXT length on {target}:{port}"
      rdlength = struct.unpack('>H', data[idx:idx+2])[0]
      idx += 2
      if idx >= len(data):
        return f"DNS CHAOS response missing TXT payload on {target}:{port}"
      txt_length = data[idx]
      txt = data[idx+1:idx+1+txt_length].decode('utf-8', errors='ignore')
      if txt:
        info = (
          f"VULNERABILITY: DNS version disclosure '{txt}' via CHAOS TXT on {target}:{port}"
        )
      if info is None:
        readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        if 'bind' in readable.lower() or 'version' in readable.lower():
          info = (
            f"VULNERABILITY: DNS version disclosure via CHAOS TXT on {target}:{port}"
          )
      if info is None:
        info = f"DNS CHAOS TXT query did not disclose version on {target}:{port}"
    except socket.timeout:
      info = f"DNS CHAOS query timed out on {target}:{port}"
      self.P(info, color='y')
    except Exception as e:
      info = f"DNS CHAOS query failed on {target}:{port}: {e}"
      self.P(info, color='y')
    finally:
      if sock is not None:
        sock.close()
    return info


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
    str | None
      MSSQL response summary or error message.
    """
    info = None
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
        info = (
          f"VULNERABILITY: MSSQL prelogin succeeded on {target}:{port}"
          f" (response: {readable.strip()[:120]})"
        )
      sock.close()
    except Exception as e:
      info = f"MSSQL probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


  def _service_info_5432(self, target, port):
    """
    Probe PostgreSQL for weak authentication methods.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      PostgreSQL response summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      payload = b'user\x00postgres\x00database\x00postgres\x00\x00'
      startup = struct.pack('!I', len(payload) + 8) + struct.pack('!I', 196608) + payload
      sock.sendall(startup)
      data = sock.recv(128)
      if b'AuthenticationCleartextPassword' in data:
        info = (
          f"VULNERABILITY: PostgreSQL requests cleartext passwords on {target}:{port}"
        )
      elif b'AuthenticationOk' in data:
        info = f"PostgreSQL responded with AuthenticationOk on {target}:{port}"
      sock.close()
    except Exception as e:
      info = f"PostgreSQL probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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
    str | None
      Memcached response summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      sock.sendall(b'stats\r\n')
      data = sock.recv(128)
      if data.startswith(b'STAT'):
        info = (
          f"VULNERABILITY: Memcached stats accessible without auth on {target}:{port}"
        )
      sock.close()
    except Exception as e:
      info = f"Memcached probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


  def _service_info_9200(self, target, port):
    """
    Detect Elasticsearch/OpenSearch nodes leaking cluster metadata.

    Parameters
    ----------
    target : str
      Hostname or IP address.
    port : int
      Port being probed.

    Returns
    -------
    str | None
      Elasticsearch exposure summary or error message.
    """
    info = None
    try:
      scheme = "http"
      base_url = f"{scheme}://{target}"
      if port != 80:
        base_url = f"{scheme}://{target}:{port}"
      resp = requests.get(base_url, timeout=3)
      if resp.ok and 'cluster_name' in resp.text:
        info = (
          f"VULNERABILITY: Elasticsearch cluster metadata exposed at {base_url}"
        )
    except Exception as e:
      info = f"Elasticsearch probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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
    str | None
      Modbus exposure summary or error message.
    """
    info = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(3)
      sock.connect((target, port))
      request = b'\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00'
      sock.sendall(request)
      data = sock.recv(256)
      if data:
        readable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        info = (
          f"VULNERABILITY: Modbus device responded to identification request on {target}:{port}"
          f" (response: {readable.strip()[:120]})"
        )
      sock.close()
    except Exception as e:
      info = f"Modbus probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info


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
    str | None
      MongoDB exposure summary or error message.
    """
    info = None
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
        info = (
          f"VULNERABILITY: MongoDB isMaster responded without auth on {target}:{port}"
        )
      sock.close()
    except Exception as e:
      info = f"MongoDB probe failed on {target}:{port}: {e}"
      self.P(info, color='y')
    return info



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
    str | None
      Generic banner text or error message.
    """
    info = None
    try:
      # Generic service: attempt to connect and read a short banner if any
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(2)
      sock.connect((target, port))
      data = sock.recv(100).decode('utf-8', errors='ignore')
      if data:
        # Filter non-printable chars for readability
        banner = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in data)
        info = f"Service banner on port {port}: \"{banner.strip()}\""
      else:
        info = "No banner received (service may require protocol handshake)."
      sock.close()
    except Exception as e:
      info = f"Generic banner grab failed on port {port}: {e}"
    return info
