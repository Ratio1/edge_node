import random
import socket
import struct
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
          info = f"VULNERABILITY: FTP allows anonymous login (banner: {banner})"
        except Exception:
          info = f"FTP banner: {banner} | Anonymous login not allowed"
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
          info = "VULNERABILITY: Redis responded to PING (no authentication)."
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
        if banner:
          info = f"VULNERABILITY: Telnet banner: {banner.strip()}"
        else:
          info = "VULNERABILITY: Telnet open with no banner"
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
          info = "VULNERABILITY: SMB service responded to negotiation probe."
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
        if banner:
          info = f"VULNERABILITY: VNC protocol banner: {banner.strip()}"
        else:
          info = "VULNERABILITY: VNC open with no banner"
        sock.close()
    except Exception as e:
      info = f"VNC banner grab failed on port {port}: {e}"
    return info


  def _service_info_161(self, target, port):
    """Attempt SNMP community string disclosure using 'public'."""
    info = None
    sock = None
    try:
      if port == 161:
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
      info = None
    except Exception as e:
      info = f"SNMP probe failed on port {port}: {e}"
    finally:
      if sock is not None:
        sock.close()
    return info


  def _service_info_53(self, target, port):
    """Query CHAOS TXT version.bind to detect DNS version disclosure."""
    info = None
    sock = None
    try:
      if port == 53:
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
          return None
        if struct.unpack('>H', data[:2])[0] != tid:
          return None
        ancount = struct.unpack('>H', data[6:8])[0]
        if not ancount:
          return None
        idx = 12 + len(qname) + 4
        if idx >= len(data):
          return None
        if data[idx] & 0xc0 == 0xc0:
          idx += 2
        else:
          while idx < len(data) and data[idx] != 0:
            idx += data[idx] + 1
          idx += 1
        idx += 8
        if idx + 2 > len(data):
          return None
        rdlength = struct.unpack('>H', data[idx:idx+2])[0]
        idx += 2
        if idx >= len(data):
          return None
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
    except socket.timeout:
      info = None
    except Exception as e:
      info = f"DNS CHAOS query failed on port {port}: {e}"
    finally:
      if sock is not None:
        sock.close()
    return info


  def _service_info_1433(self, target, port):
    """Send a TDS prelogin probe to expose SQL Server version data."""
    info = None
    try:
      if port == 1433:
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
      info = f"MSSQL prelogin failed on port {port}: {e}"
    return info


  def _service_info_5432(self, target, port):
    """Probe PostgreSQL for weak authentication methods."""
    info = None
    try:
      if port == 5432:
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
      info = f"PostgreSQL probe failed on port {port}: {e}"
    return info


  def _service_info_11211(self, target, port):
    """Issue Memcached stats command to detect unauthenticated access."""
    info = None
    try:
      if port == 11211:
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
      info = f"Memcached probe failed on port {port}: {e}"
    return info


  def _service_info_9200(self, target, port):
    """Detect Elasticsearch/OpenSearch nodes leaking cluster metadata."""
    info = None
    try:
      if port == 9200:
        url = f"http://{target}:9200"
        resp = requests.get(url, timeout=3)
        if resp.ok and 'cluster_name' in resp.text:
          info = (
            f"VULNERABILITY: Elasticsearch cluster metadata exposed at {url}"
          )
    except Exception as e:
      info = f"Elasticsearch probe failed on port {port}: {e}"
    return info


  def _service_info_502(self, target, port):
    """Send Modbus device identification request to detect exposed PLCs."""
    info = None
    try:
      if port == 502:
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
      info = f"Modbus probe failed on port {port}: {e}"
    return info


  def _service_info_27017(self, target, port):
    """Attempt MongoDB isMaster handshake to detect unauthenticated access."""
    info = None
    try:
      if port == 27017:
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
      info = f"MongoDB probe failed on port {port}: {e}"
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
