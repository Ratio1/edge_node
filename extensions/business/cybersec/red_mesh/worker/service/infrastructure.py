import random
import re as _re
import socket
import struct

import requests

from ...findings import Finding, Severity, probe_result, probe_error
from ...cve_db import check_cves
from ..probe_registry import register_probe, CATEGORY_SERVICE_INFO
from ._base import _ServiceProbeBase


class _ServiceInfraMixin(_ServiceProbeBase):
  """RDP, VNC, SNMP, DNS, SMB, WINS, Modbus and Elasticsearch probes."""

  @register_probe(
    display_name="RDP service detection",
    description=(
      "X.224 connection request to detect Remote Desktop Protocol. "
      "Flags exposed RDP (BlueKeep / DejaBlue surface)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A05:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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

  @register_probe(
    display_name="VNC service detection",
    description=(
      "RFB protocol handshake to detect VNC. Identifies security "
      "type (None, VNC password, TLS, ARD, etc.) — None auth is "
      "always reported critical."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 326),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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


  @register_probe(
    display_name="SNMP service detection",
    description=(
      "SNMP v1/v2c/v3 detection with default-community probes "
      "(public/private). Walks system MIB to detect ICS/SCADA "
      "indicators and leaked interface IPs."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A05:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  )
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

  @register_probe(
    display_name="DNS service detection",
    description=(
      "DNS server fingerprint, version.bind / hostname.bind / "
      "id.server CHAOS-class queries, AXFR zone-transfer attempt "
      "with SOA-based zone discovery. Runs CVE checks for BIND."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200, 538),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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
                  # CVE check — version.bind is BIND-specific
                  _bind_m = _re.search(r'(\d+\.\d+(?:\.\d+)*)', txt)
                  if _bind_m:
                    findings += check_cves("bind", _bind_m.group(1))

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

  def _dns_discover_zones(self, target, port):
    """Discover zone names the DNS server is authoritative for.

    Strategy: send SOA queries for a set of candidate domains and check
    for authoritative (AA-flag) responses.  This is far more reliable than
    reverse-DNS guessing when the target serves non-obvious zones.

    Returns list of domain strings (may be empty).
    """
    candidates = set()

    # 1. Reverse DNS of target → extract domain
    try:
      import socket as _socket
      hostname, _, _ = _socket.gethostbyaddr(target)
      parts = hostname.split(".")
      if len(parts) >= 2:
        candidates.add(".".join(parts[-2:]))
      if len(parts) >= 3:
        candidates.add(".".join(parts[-3:]))
    except Exception:
      pass

    # 2. Common pentest / CTF domains
    candidates.update(["vulhub.org", "example.com", "test.local"])

    # 3. Probe each candidate with a SOA query — keep only authoritative hits
    authoritative = []
    for domain in list(candidates):
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        tid = random.randint(0, 0xffff)
        header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in domain.split("."):
          qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        question = struct.pack('>HH', 6, 1)  # QTYPE=SOA, QCLASS=IN
        sock.sendto(header + qname + question, (target, port))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) >= 12 and struct.unpack('>H', data[:2])[0] == tid:
          flags = struct.unpack('>H', data[2:4])[0]
          aa = (flags >> 10) & 1   # Authoritative Answer
          rcode = flags & 0x0F
          ancount = struct.unpack('>H', data[6:8])[0]
          if aa and rcode == 0 and ancount > 0:
            authoritative.append(domain)
      except Exception:
        pass

    # Return authoritative zones first, then remaining candidates as fallback
    seen = set(authoritative)
    result = list(authoritative)
    for d in candidates:
      if d not in seen:
        result.append(d)
    return result

  def _dns_test_axfr(self, target, port):
    """Attempt DNS zone transfer (AXFR) via TCP.

    Uses SOA-based zone discovery to find authoritative zones before
    attempting AXFR, falling back to reverse DNS and common domains.

    Returns list of findings.
    """
    findings = []

    test_domains = self._dns_discover_zones(target, port)

    for domain in test_domains[:4]:  # Test at most 4 domains
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

  @register_probe(
    display_name="SMB service detection",
    description=(
      "SMB protocol negotiation, version detection, share "
      "enumeration via null session. Detects SMBv1, MS17-010 "
      "surface, anonymous shares, and CVE-2017-7494 (Samba)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200, 326),
    default_owasp=("A02:2021", "A05:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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

  @register_probe(
    display_name="WINS / NetBIOS service detection",
    description=(
      "WINS (TCP/42) and NetBIOS Name Service (UDP/137) probes. "
      "Detects legacy Windows name resolution exposure."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(200,),
    default_owasp=("A05:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  )
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

  @register_probe(
    display_name="Modbus service detection",
    description=(
      "Modbus/TCP read-only function-code 17 (Report Server ID) "
      "probe. Detects ICS/SCADA exposure on the public internet."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A07:2021",),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  )
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


  @register_probe(
    display_name="Elasticsearch service detection",
    description=(
      "GET / + cluster info probe. Detects unauthenticated ES, "
      "version, JVM info, and public-IP classification (data leak)."
    ),
    category=CATEGORY_SERVICE_INFO,
    default_cwe=(287, 200),
    default_owasp=("A05:2021", "A07:2021"),
    cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  )
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
