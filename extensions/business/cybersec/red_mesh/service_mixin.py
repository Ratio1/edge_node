import socket
import ftplib
import requests
import ssl
from datetime import datetime

class _ServiceInfoMixin:
  """
  Network service banner probes feeding RedMesh reports.

  Each helper focuses on a specific protocol and maps findings to
  OWASP vulnerability families such as A06:2021 (Security
  Misconfiguration) or A09:2021 (Security Logging and Monitoring).
  The mixin is intentionally light-weight so that PentestLocalWorker
  threads can run without external dependencies while still surfacing
  high-signal security clues.
  """
  
  def _service_info_80(self, target, port):
    """Collect HTTP banner and server metadata for common web ports."""
    info = None
    try:
      if port in (80, 8080, 8000, 8443):
        scheme = "https" if port in (8443,) else "http"
        url = f"{scheme}://{target}"
        if port not in (80, 443):
          url = f"{scheme}://{target}:{port}"
        self.P("Fetching {url} for banner...")
        resp = requests.get(url, timeout=3, verify=False)
        info = (f"HTTP {resp.status_code} {resp.reason}; Server: {resp.headers.get('Server')}")
    except Exception as e:
      info = f"Banner grab failed on port {port}: {e}"      
    return info
  

  def _service_info_8080(self, target, port):
    """Probe alternate HTTP port 8080 for verbose banners."""
    info = None
    try:
      if port == 8080:
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
      info = f"HTTP banner grab failed on port {port}: {e}"
    return info  


  def _service_info_443(self, target, port):
    """Collect HTTPS response banner data for TLS services."""
    info = None
    try:
      if port in (443,):
        url = f"https://{target}"
        self.P(f"Fetching {url} for banner...")
        resp = requests.get(url, timeout=3, verify=False)
        info = (f"HTTPS {resp.status_code} {resp.reason}; Server: {resp.headers.get('Server')}")
    except Exception as e:
      info = f"Banner grab failed on port {port}: {e}"
    return info


  def _service_info_tls(self, target, port):
    """Inspect TLS handshake details and certificate lifetime."""
    info = None
    try:
      if port in (443, 8443):
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=3) as sock:
          with context.wrap_socket(sock, server_hostname=target) as ssock:
            cert = ssock.getpeercert()
            proto = ssock.version()
            cipher = ssock.cipher()
            expires = cert.get("notAfter")
            if expires:
              try:
                exp = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                info = f"TLS {proto} {cipher[0]}; cert exp in {days} days"
              except Exception:
                info = f"TLS {proto} {cipher[0]}; cert expires {expires}"
            else:
              info = f"TLS {proto} {cipher[0]}"
    except Exception as e:
      info = f"TLS info fetch failed on port {port}: {e}"
    return info


  def _service_info_21(self, target, port):
    """Identify FTP banners and anonymous login exposure."""
    info = None
    try:
      if port == 21:
        ftp = ftplib.FTP(timeout=3)
        ftp.connect(target, port, timeout=3)
        banner = ftp.getwelcome()
        info = f"FTP banner: {banner}"
        try:
          ftp.login()  # attempt anonymous login
          info += " | Anonymous login allowed"
        except Exception:
          info += " | Anonymous login not allowed"
        ftp.quit()
    except Exception as e:
      info = f"FTP banner grab failed on port {port}: {e}"
    return info

  def _service_info_22(self, target, port):
    """Retrieve the SSH banner to fingerprint implementations."""
    info = None
    try:
      if port == 22:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        info = f"SSH banner: {banner.strip()}"
        sock.close()
    except Exception as e:
      info = f"SSH banner grab failed on port {port}: {e}"
    return info

  def _service_info_25(self, target, port):
    """Capture SMTP banner data for mail infrastructure mapping."""
    info = None
    try:
      if port in (25, 587):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        info = f"SMTP banner: {banner.strip()}"
        sock.close()
    except Exception as e:
      info = f"SMTP banner grab failed on port {port}: {e}"
    return info

  def _service_info_3306(self, target, port):
    """Perform a lightweight MySQL handshake to expose server version."""
    info = None
    try:
      if port == 3306:
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
      info = f"MySQL banner grab failed on port {port}: {e}"
    return info

  def _service_info_3389(self, target, port):
    """Verify reachability of RDP services without full negotiation."""
    info = None
    try:
      if port == 3389:
        info = "RDP service open (no easy banner)."
    except Exception as e:
      info = f"RDP banner grab failed on port {port}: {e}"
    return info

  def _service_info_6379(self, target, port):
    """Test Redis exposure by issuing a PING command."""
    info = None
    try:
      if port == 6379:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"PING\r\n")
        data = sock.recv(64).decode('utf-8', errors='ignore')
        if data.startswith("+PONG"):
          info = "Redis responded to PING (no auth)."
        elif data.upper().startswith("-NOAUTH"):
          info = "Redis requires authentication (NOAUTH)."
        else:
          info = f"Redis response: {data.strip()}"
        sock.close()
    except Exception as e:
      info = f"Redis banner grab failed on port {port}: {e}"
    return info


  def _service_info_23(self, target, port):
    """Fetch Telnet negotiation banner (OWASP A05: insecure protocols)."""
    info = None
    try:
      if port == 23:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        info = f"Telnet banner: {banner.strip()}" if banner else "Telnet open with no banner"
        sock.close()
    except Exception as e:
      info = f"Telnet banner grab failed on port {port}: {e}"
    return info


  def _service_info_445(self, target, port):
    """Probe SMB services for negotiation responses (OWASP A06)."""
    info = None
    try:
      if port == 445:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        probe = b"\x00\x00\x00\x2f\xffSMB" + b"\x00" * 39
        sock.sendall(probe)
        data = sock.recv(4)
        if data:
          info = "SMB service responded to negotiation probe."
        else:
          info = "SMB port open but no negotiation response."
        sock.close()
    except Exception as e:
      info = f"SMB probe failed on port {port}: {e}"
    return info


  def _service_info_5900(self, target, port):
    """Read VNC handshake string to assess remote desktop exposure."""
    info = None
    try:
      if port == 5900:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        banner = sock.recv(12).decode('ascii', errors='ignore')
        info = f"VNC protocol banner: {banner.strip()}" if banner else "VNC open with no banner"
        sock.close()
    except Exception as e:
      info = f"VNC banner grab failed on port {port}: {e}"
    return info


  def _service_info_generic(self, target, port):
    """Attempt a generic TCP banner grab for uncovered ports."""
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
