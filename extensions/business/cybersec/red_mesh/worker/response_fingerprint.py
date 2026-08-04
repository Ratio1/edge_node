"""
Per-vantage response fingerprint capture (comparison-mode jobs only).

Geographic comparison answers one question: does the target respond
differently depending on where the request originates? Answering it
requires each vantage to record what the target actually *said* — its DNS
resolution, TLS identity, and HTTP response — rather than how our own scan
behaved.

This mixin probes only the mirrored comparison port tier, so every vantage
issues the same requests against the same ports and the results are directly
comparable. It runs on a single local worker per node (the one that received
`comparison_ports`), because the tier is node-wide evidence rather than
per-thread work.

Body excerpts are truncated and scrubbed here, inside the worker, before the
value can leave the node.
"""

import hashlib
import ipaddress
import re
import socket

import requests

# Excerpts exist so an operator can see *that* two vantages were served
# different content. A few hundred bytes of the head of the document is
# enough for that; storing more would commit third-party content to an
# immutable archive without adding comparative value.
EXCERPT_MAX_BYTES = 512
EXCERPT_SCAN_CHARS = 4096
EXCERPT_CONTENT_TYPES = ("text/html", "text/plain", "application/json")

# Headers that identify *which* infrastructure answered. These are what
# actually differ between a CDN edge in Brazil and one in China.
CAPTURED_HEADERS = ("server", "via", "x-cache", "cf-ray", "x-powered-by", "location")

TITLE_MAX_CHARS = 200

_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Order matters:
#   - bearer precedes the generic key/value rule, which would otherwise match
#     "Authorization: Bearer" and consume the scheme as the value, leaving the
#     token itself in the clear;
#   - email precedes the hex/base64 rules, which would otherwise swallow a long
#     local part;
#   - hex precedes base64, because hex is a strict subset of that alphabet.
_REDACTIONS = (
  (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*"), "bearer [REDACTED]"),
  (
    re.compile(
      r"(?i)\b(authorization|api[-_]?key|apikey|access[-_]?token|token|"
      r"session[-_]?id|sessionid|session|secret|password|passwd|pwd)\b"
      # An optional closing quote covers JSON keys such as {"api_key": "..."}.
      r"[\"']?(\s*[:=]\s*)[\"']?[^\s\"',;&<>]+"
    ),
    r"\1\2[REDACTED]",
  ),
  (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
  (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[REDACTED_HEX]"),
  (re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}"), "[REDACTED_B64]"),
)


def sanitize_excerpt(text):
  """
  Scrub and bound a response body excerpt.

  Redaction runs before truncation so a credential straddling the byte cap
  cannot survive as a leaked prefix. Truncation is byte-based but respects
  UTF-8 character boundaries.

  Parameters
  ----------
  text : str
    Raw response body text.

  Returns
  -------
  str or None
    Scrubbed excerpt of at most ``EXCERPT_MAX_BYTES`` bytes, or None when
    the input is empty.
  """
  if not text:
    return None
  scrubbed = text[:EXCERPT_SCAN_CHARS]
  for pattern, replacement in _REDACTIONS:
    scrubbed = pattern.sub(replacement, scrubbed)
  encoded = scrubbed.encode("utf-8")[:EXCERPT_MAX_BYTES]
  # errors="ignore" drops a partial multi-byte character left by the slice.
  excerpt = encoded.decode("utf-8", errors="ignore")
  return excerpt or None


def excerpt_allowed(content_type):
  """True when the content type is textual enough to excerpt safely."""
  if not content_type:
    return False
  base = content_type.split(";")[0].strip().lower()
  return base in EXCERPT_CONTENT_TYPES


def normalize_content_type(content_type):
  """Reduce a Content-Type header to its bare media type."""
  if not content_type:
    return None
  return content_type.split(";")[0].strip().lower() or None


def resolve_host(host):
  """
  Resolve a target host to its sorted, deduplicated A/AAAA set.

  Each vantage resolves independently — this is what makes geo-DNS
  divergence observable at all.

  Returns
  -------
  tuple[list[str], str or None]
    Resolved addresses and an error string when resolution failed. A
    literal IP target resolves to an empty list with no error, because
    there is no DNS answer to compare.
  """
  if not host:
    return [], "empty host"
  try:
    ipaddress.ip_address(host)
    return [], None
  except ValueError:
    pass
  try:
    infos = socket.getaddrinfo(host, None)
  except Exception as exc:
    return [], str(exc)
  addresses = {info[4][0] for info in infos if info[4]}
  return sorted(addresses), None


def certificate_identity(cert_der):
  """
  Extract comparable identity fields from a DER-encoded certificate.

  Returns None when the certificate is absent or unparseable — an
  unparseable certificate must not masquerade as a matching one.
  """
  if not cert_der:
    return None
  identity = {"cert_sha256": hashlib.sha256(cert_der).hexdigest()}
  try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(cert_der)

    def _common_name(name):
      attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
      return attributes[0].value if attributes else None

    identity["subject_cn"] = _common_name(cert.subject)
    identity["issuer_cn"] = _common_name(cert.issuer)
    identity["not_before"] = cert.not_valid_before_utc.isoformat()
    identity["not_after"] = cert.not_valid_after_utc.isoformat()
  except Exception:
    # The fingerprint alone still distinguishes one certificate from
    # another, which is all clustering needs.
    pass
  return identity


class _ResponseFingerprintMixin:
  """Captures per-vantage target response evidence for comparison jobs."""

  def _capture_response_fingerprint(self):
    """
    Probe the comparison port tier and record what the target answered.

    No-ops when this worker holds no comparison tier, which is how
    non-comparison jobs and the non-designated local workers skip the phase.
    """
    ports = sorted({int(port) for port in (self.comparison_ports or [])})
    if not ports:
      return

    resolved_ips, resolver_error = resolve_host(self.target)
    evidence = {
      "target_host": self.target,
      "resolved_ips": resolved_ips,
      "ports": {},
    }
    if resolver_error:
      evidence["resolver_error"] = resolver_error

    for port in ports:
      if self._check_stopped():
        break
      evidence["ports"][str(port)] = self._fingerprint_port(port)

    self.state["response_evidence"] = evidence

  def _fingerprint_port(self, port):
    """Capture reachability, TLS identity, and HTTP response for one port."""
    entry = {"reachable": False, "tls": None, "http": None, "excerpt": None}

    try:
      with socket.create_connection((self.target, port), timeout=self._target_timeout(3)):
        entry["reachable"] = True
    except Exception:
      # An unreachable port is itself a comparable result: a target that
      # refuses one vantage and serves another is the divergence we are
      # looking for, so this is recorded rather than treated as an error.
      return entry

    _proto, _cipher, cert_der = self._tls_unverified_connect(self.target, port)
    if cert_der:
      identity = certificate_identity(cert_der)
      if identity:
        _dns_names, _ips = self._tls_parse_san_from_der(cert_der)
        identity["san_count"] = len(_dns_names) + len(_ips)
        entry["tls"] = identity

    scheme = "https" if entry["tls"] else "http"
    http, excerpt = self._fingerprint_http(scheme, port)
    entry["http"] = http
    entry["excerpt"] = excerpt
    return entry

  def _fingerprint_http(self, scheme, port):
    """Issue one GET and reduce the response to comparable attributes."""
    url = f"{scheme}://{self.target}:{port}/"
    try:
      user_agent = getattr(self, "scanner_user_agent", "")
      headers = {"User-Agent": user_agent} if user_agent else {}
      resp = requests.get(
        url,
        timeout=self._target_timeout(5),
        verify=False,
        allow_redirects=True,
        headers=headers,
      )
    except Exception as exc:
      self.P(f"Response fingerprint GET failed on {url}: {exc}", color='y')
      return None, None

    content_type = normalize_content_type(resp.headers.get("Content-Type"))
    title_match = _TITLE_RE.search(resp.text[:5000])
    http = {
      "status": resp.status_code,
      "final_url": resp.url,
      "redirect_count": len(resp.history),
      "title": title_match.group(1).strip()[:TITLE_MAX_CHARS] if title_match else None,
      "content_type": content_type,
      "body_length": len(resp.content),
      "body_sha256": hashlib.sha256(resp.content).hexdigest(),
      "headers": {
        name: resp.headers.get(name)
        for name in CAPTURED_HEADERS
        if resp.headers.get(name)
      },
    }

    excerpt = sanitize_excerpt(resp.text) if excerpt_allowed(content_type) else None
    return http, excerpt
