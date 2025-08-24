import socket
import ftplib
import requests
import ssl
from datetime import datetime

class _ServiceInfoMixin:
  """
  Mixin class providing service information gathering capabilities.
  """
  
  def _service_info_80(self, target, port):
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
    info = None
    try:
      if port == 8080:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target).encode('utf-8'))
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
    info = None
    try:
      if port in (443,):
        url = f"https://{target}"
        self.P("Fetching {url} for banner...")
        resp = requests.get(url, timeout=3, verify=False)
        info = (f"HTTPS {resp.status_code} {resp.reason}; Server: {resp.headers.get('Server')}")
    except Exception as e:
      info = f"Banner grab failed on port {port}: {e}"
    return info


  def _service_info_tls(self, target, port):
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
    info = None
    try:
      if port == 3389:
        info = "RDP service open (no easy banner)."
    except Exception as e:
      info = f"RDP banner grab failed on port {port}: {e}"
    return info

  def _service_info_6379(self, target, port):
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


  def _service_info_generic(self, target, port):
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
