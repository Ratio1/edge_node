import re as _re
import socket
import struct

import requests

from ...findings import Finding, Severity, probe_result, probe_error
from ...cve_db import check_cves
from ..probe_registry import register_probe, CATEGORY_SERVICE_INFO
from ._base import _ServiceProbeBase


# Common per-probe metadata reused below (kept as module-level for
# clarity; each probe still passes its own values to @register_probe).

class _ServiceDatabaseMixin(_ServiceProbeBase):
  """MySQL, Redis, MSSQL, PostgreSQL, Memcached, MongoDB, CouchDB and InfluxDB probes."""

  @register_probe(
    display_name="MySQL service detection",
    description="Handshake probe: extract MySQL version, auth plugin, run CVE checks.",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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

  @register_probe(
    display_name="MySQL credential check",
    description=(
      "Tests known weak / default credential pairs against MySQL's "
      "native auth (mysql_native_password). Skipped when the server "
      "advertises caching_sha2_password without a known weak account."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(521, 798),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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
    import random

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

  # SAFETY: Read-only commands only. NEVER add CONFIG SET, SLAVEOF, MODULE LOAD, EVAL, DEBUG.
  @register_probe(
    display_name="Redis service detection",
    description=(
      "INFO and CONFIG probes for Redis: detects unauthenticated "
      "access, version, persistence config, and dangerous "
      "CONFIG SET write-paths."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 306),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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


  @register_probe(
    display_name="MSSQL service detection",
    description="TDS prelogin to detect SQL Server version + encryption posture.",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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


  @register_probe(
    display_name="PostgreSQL service detection",
    description="StartupMessage probe to extract PG version + auth requirement; runs CVE checks.",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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

  @register_probe(
    display_name="PostgreSQL credential check",
    description="Tests known weak / default credentials against PostgreSQL md5/scram auth.",
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(521, 798),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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
            resp = sock.recv(4096)
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
                findings += self._pg_extract_version_findings(resp)
          elif auth_code == 5 and len(data) >= 13:
            # MD5 auth: server sends 4-byte salt at bytes 9:13
            import hashlib
            salt = data[9:13]
            inner = hashlib.md5(password.encode() + username.encode()).hexdigest()
            outer = 'md5' + hashlib.md5(inner.encode() + salt).hexdigest()
            pwd_bytes = outer.encode() + b'\x00'
            pwd_msg = b'p' + struct.pack('!I', len(pwd_bytes) + 4) + pwd_bytes
            sock.sendall(pwd_msg)
            resp = sock.recv(4096)
            if resp and resp[0:1] == b'R' and len(resp) >= 9:
              result_code = struct.unpack('!I', resp[5:9])[0]
              if result_code == 0:
                cred_str = f"{username}:{password}" if password else f"{username}:(empty)"
                raw["accepted_credentials"].append(cred_str)
                findings.append(Finding(
                  severity=Severity.CRITICAL,
                  title=f"PostgreSQL default credential accepted: {cred_str}",
                  description=f"MD5 password auth accepted for {cred_str}.",
                  evidence=f"Auth OK for {cred_str}",
                  remediation="Change default passwords.",
                  owasp_id="A07:2021",
                  cwe_id="CWE-798",
                  confidence="certain",
                ))
                findings += self._pg_extract_version_findings(resp)
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

  def _pg_extract_version_findings(self, data):
    """Parse ParameterStatus messages after PG auth success for version + CVEs."""
    findings = []
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
            findings.append(Finding(
              severity=Severity.LOW,
              title=f"PostgreSQL version disclosed: {val}",
              description=f"PostgreSQL reports version {val} (via authenticated session).",
              evidence=f"server_version parameter: {val}",
              remediation="Restrict network access to the PostgreSQL port.",
              cwe_id="CWE-200",
              confidence="certain",
            ))
            ver_match = _re.match(r'(\d+\.\d+(?:\.\d+)?)', val)
            if ver_match:
              findings += check_cves("postgresql", ver_match.group(1))
            break
      pos = msg_end
      if pos >= len(data):
        break
    return findings

  @register_probe(
    display_name="Memcached service detection",
    description=(
      "stats / version probes against Memcached: detects "
      "unauthenticated public exposure (DDoS amplification source)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 306),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
  )
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


  @register_probe(
    display_name="MongoDB service detection",
    description=(
      "isMaster + buildInfo probes against MongoDB: detects "
      "unauthenticated public exposure, version, collection enum risk."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 306),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  )
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



  # ── CouchDB ──────────────────────────────────────────────────────

  @register_probe(
    display_name="CouchDB service detection",
    description=(
      "Welcome page, _all_dbs, Fauxton UI, and config endpoint "
      "probes for CouchDB. Detects unauthenticated admin and CVEs."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 306),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
  def _service_info_couchdb(self, target, port):  # default port: 5984
    """
    Probe Apache CouchDB HTTP API for unauthenticated access, admin panel,
    database listing, and version-based CVE matching.
    """
    findings, raw = [], {"version": None}
    base_url = f"http://{target}:{port}"

    # 1. Root endpoint — identifies CouchDB and extracts version
    try:
      resp = requests.get(base_url, timeout=3)
      if not resp.ok:
        return None
      data = resp.json()
      if "couchdb" not in str(data).lower():
        return None  # Not CouchDB
      raw["version"] = data.get("version")
      raw["vendor"] = data.get("vendor", {}).get("name") if isinstance(data.get("vendor"), dict) else None
    except Exception:
      return None

    if raw["version"]:
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"CouchDB version disclosed: {raw['version']}",
        description=f"CouchDB on {target}:{port} reports version {raw['version']}.",
        evidence=f"GET / → version={raw['version']}",
        remediation="Restrict network access to the CouchDB port.",
        cwe_id="CWE-200",
        confidence="certain",
      ))
      ver_match = _re.match(r'(\d+\.\d+(?:\.\d+)?)', raw["version"])
      if ver_match:
        findings += check_cves("couchdb", ver_match.group(1))

    # 2. Database listing — unauthenticated access to /_all_dbs
    try:
      resp = requests.get(f"{base_url}/_all_dbs", timeout=3)
      if resp.ok:
        dbs = resp.json()
        if isinstance(dbs, list):
          raw["databases"] = dbs
          user_dbs = [d for d in dbs if not d.startswith("_")]
          findings.append(Finding(
            severity=Severity.CRITICAL if user_dbs else Severity.HIGH,
            title=f"CouchDB unauthenticated database listing ({len(dbs)} databases)",
            description=f"/_all_dbs accessible without credentials. "
                        f"{'User databases exposed: ' + ', '.join(user_dbs[:5]) if user_dbs else 'Only system databases found.'}",
            evidence=f"Databases: {', '.join(dbs[:10])}" + (f"... (+{len(dbs)-10} more)" if len(dbs) > 10 else ""),
            remediation="Enable CouchDB authentication via [admins] section in local.ini.",
            owasp_id="A01:2021",
            cwe_id="CWE-284",
            confidence="certain",
          ))
    except Exception:
      pass

    # 3. Admin panel (Fauxton) accessibility
    try:
      resp = requests.get(f"{base_url}/_utils/", timeout=3, allow_redirects=True)
      if resp.ok and ("fauxton" in resp.text.lower() or "couchdb" in resp.text.lower()):
        findings.append(Finding(
          severity=Severity.HIGH,
          title="CouchDB admin panel (Fauxton) accessible",
          description=f"/_utils/ on {target}:{port} serves the admin web interface.",
          evidence=f"GET /_utils/ returned {resp.status_code}, content-length={len(resp.text)}",
          remediation="Restrict access to /_utils via reverse proxy or bind to localhost.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
    except Exception:
      pass

    # 4. Config endpoint — critical if accessible
    try:
      resp = requests.get(f"{base_url}/_node/_local/_config", timeout=3)
      if resp.ok and resp.text.startswith("{"):
        findings.append(Finding(
          severity=Severity.CRITICAL,
          title="CouchDB configuration exposed without authentication",
          description="/_node/_local/_config returns full server configuration including credentials.",
          evidence=f"GET /_node/_local/_config returned {resp.status_code}",
          remediation="Enable admin authentication immediately.",
          owasp_id="A01:2021",
          cwe_id="CWE-284",
          confidence="certain",
        ))
    except Exception:
      pass

    if not findings:
      findings.append(Finding(Severity.INFO, "CouchDB probe clean", "No issues detected."))
    return probe_result(raw_data=raw, findings=findings)

  # ── InfluxDB ────────────────────────────────────────────────────

  @register_probe(
    display_name="InfluxDB service detection",
    description=(
      "/ping (version header), SHOW DATABASES, /debug/vars probes "
      "for InfluxDB. Detects version, unauthenticated DB list, "
      "and exposed debug surface."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
  def _service_info_influxdb(self, target, port):  # default port: 8086
    """
    Probe InfluxDB HTTP API for version disclosure, unauthenticated access,
    and database listing.
    """
    findings, raw = [], {"version": None}
    base_url = f"http://{target}:{port}"

    # 1. Ping — extract version from X-Influxdb-Version header
    try:
      resp = requests.get(f"{base_url}/ping", timeout=3)
      version = resp.headers.get("X-Influxdb-Version")
      if not version:
        return None  # Not InfluxDB
      raw["version"] = version
      findings.append(Finding(
        severity=Severity.LOW,
        title=f"InfluxDB version disclosed: {version}",
        description=f"InfluxDB on {target}:{port} reports version {version}.",
        evidence=f"X-Influxdb-Version: {version}",
        remediation="Restrict network access to the InfluxDB port.",
        cwe_id="CWE-200",
        confidence="certain",
      ))
      ver_match = _re.match(r'(\d+\.\d+(?:\.\d+)?)', version)
      if ver_match:
        findings += check_cves("influxdb", ver_match.group(1))
    except Exception:
      return None

    # 2. Unauthenticated database listing
    try:
      resp = requests.get(f"{base_url}/query", params={"q": "SHOW DATABASES"}, timeout=3)
      if resp.ok:
        data = resp.json()
        results = data.get("results", [])
        if results and not results[0].get("error"):
          series = results[0].get("series", [])
          db_names = []
          for s in series:
            for row in s.get("values", []):
              if row:
                db_names.append(row[0])
          raw["databases"] = db_names
          user_dbs = [d for d in db_names if d not in ("_internal",)]
          findings.append(Finding(
            severity=Severity.CRITICAL if user_dbs else Severity.HIGH,
            title=f"InfluxDB unauthenticated access ({len(db_names)} databases)",
            description=f"SHOW DATABASES succeeded without credentials. "
                        f"{'User databases: ' + ', '.join(user_dbs[:5]) if user_dbs else 'Only internal databases found.'}",
            evidence=f"Databases: {', '.join(db_names[:10])}",
            remediation="Enable InfluxDB authentication in the configuration ([http] auth-enabled = true).",
            owasp_id="A07:2021",
            cwe_id="CWE-287",
            confidence="certain",
          ))
        elif results and results[0].get("error"):
          # Auth required — good
          findings.append(Finding(
            severity=Severity.INFO,
            title="InfluxDB authentication enforced",
            description="SHOW DATABASES rejected without credentials.",
            evidence=f"Error: {results[0]['error'][:80]}",
            confidence="certain",
          ))
    except Exception:
      pass

    # 3. Debug endpoint exposure
    try:
      resp = requests.get(f"{base_url}/debug/vars", timeout=3)
      if resp.ok and "memstats" in resp.text:
        findings.append(Finding(
          severity=Severity.MEDIUM,
          title="InfluxDB debug endpoint exposed (/debug/vars)",
          description="Go runtime debug variables accessible, leaking memory stats and internal state.",
          evidence=f"GET /debug/vars returned {resp.status_code}",
          remediation="Disable or restrict access to debug endpoints.",
          owasp_id="A05:2021",
          cwe_id="CWE-200",
          confidence="certain",
        ))
    except Exception:
      pass

    if not findings:
      findings.append(Finding(Severity.INFO, "InfluxDB probe clean", "No issues detected."))
    return probe_result(raw_data=raw, findings=findings)
