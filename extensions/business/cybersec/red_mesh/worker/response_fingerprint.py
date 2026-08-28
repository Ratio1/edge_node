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
import queue
import re
import socket
import threading
import time

import requests
from requests.compat import urljoin, urlparse
from requests.models import DEFAULT_REDIRECT_LIMIT
from urllib3.util import parse_url

from ..constants import FINGERPRINT_HTTP_TIMEOUT, FINGERPRINT_TIMEOUT

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
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

TITLE_MAX_CHARS = 200
RESPONSE_BODY_MAX_BYTES = 1024 * 1024

_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Order matters:
#   - bearer precedes the generic key/value rule, which would otherwise match
#     "Authorization: Bearer" and consume the scheme as the value, leaving the
#     token itself in the clear;
#   - email precedes the hex/base64 rules, which would otherwise swallow a long
#     local part;
#   - hex precedes base64, because hex is a strict subset of that alphabet.
_REDACTIONS = (
  # URL userinfo, first: `https://user:secret@host` carries a credential that
  # none of the key/value patterns below would recognise.
  (re.compile(r"(?<=://)[^/@\s]+:[^/@\s]+@"), "[REDACTED]@"),
  (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*"), "bearer [REDACTED]"),
  (
    re.compile(
      # `(?<![A-Za-z0-9])` rather than `\b`: an underscore is a word character,
      # so `\b` could never match after one and every `db_password=` /
      # `jwt_secret=` style key escaped this rule entirely.
      r"(?i)(?<![A-Za-z0-9])(authorization|"
      r"(?:api|access|refresh|session|client|auth|id|private|secret)[-_]?"
      r"(?:key|token|secret|id)|"
      r"apikey|token|session|secret|password|passwd|pwd)\b"
      # An optional closing quote covers JSON keys such as {"api_key": "..."}.
      r"(?P<quote>[\"'])?(?P<separator>\s*[:=]\s*)"
      r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n,;&<>}]+)"
    ),
    r"\1\g<quote>\g<separator>[REDACTED]",
  ),
  (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
  (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[REDACTED_HEX]"),
  # A token is distinguished from prose by an unbroken alphanumeric run, not by
  # its alphabet. Admitting `-` and `_` without that requirement swallowed
  # ordinary hyphenated titles, CSS class names and paths — which are exactly
  # the content this evidence exists to compare between vantages.
  (
    re.compile(
      r"(?<![A-Za-z0-9_+/\-])"
      r"(?=[A-Za-z0-9_+/\-]*[A-Za-z0-9+/]{20,})"
      r"[A-Za-z0-9_+/\-]{32,}={0,2}"
      r"(?![A-Za-z0-9_+/\-=])"
    ),
    "[REDACTED_B64]",
  ),
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


def resolve_host(host, timeout=None):
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
  if timeout is None:
    try:
      infos = socket.getaddrinfo(host, None)
    except Exception as exc:
      return [], str(exc)
  else:
    result = queue.Queue(maxsize=1)

    def _lookup():
      try:
        result.put((socket.getaddrinfo(host, None), None))
      except Exception as exc:
        result.put((None, exc))

    threading.Thread(target=_lookup, daemon=True).start()
    try:
      infos, error = result.get(timeout=timeout)
    except queue.Empty:
      return [], "DNS resolution timed out"
    if error is not None:
      return [], str(error)
  addresses = {info[4][0] for info in infos if info[4]}
  return sorted(addresses), None


def redirect_stays_on_target(next_url, host, port):
  """
  A scan is authorized for one host and port, so a redirect is followed only
  when it stays there. A target that answers `302 -> http://169.254.169.254/`
  would otherwise make this node fetch an internal endpoint and archive the
  response as scan evidence.

  Pinning to the authorized host is the whole control: anything else — public
  or private — is out of scope by definition. Classifying the hop's IP would
  add nothing here and would break scanning private targets, which is a normal
  authorized case.

  Both parsers must agree, because validating with either alone is bypassable.
  This module reads a URL with `urlparse` while `requests` dials with urllib3's
  `parse_url`, and the two split authority differently:
  `http://169.254.169.254\\@authorized-host/` is host `authorized-host` to the
  first and `169.254.169.254` to the second, so a guard trusting `urlparse`
  would wave through a hop that fetches cloud metadata. Refusing on
  disagreement fails closed against that whole class of parser differential
  rather than against one spelling of it.
  """
  try:
    stdlib = urlparse(next_url)
    dialed = parse_url(next_url)
    # `.port` raises on a malformed port; refuse rather than guess.
    hop_ports = (stdlib.port, dialed.port)
  except Exception:
    return False
  scheme = (stdlib.scheme or "").lower()
  if scheme not in ("http", "https"):
    return False
  expected_host = (host or "").lower()
  hop_hosts = ((stdlib.hostname or "").lower(), (dialed.host or "").lower())
  default_port = 443 if scheme == "https" else 80
  return (
    all(hop == expected_host for hop in hop_hosts)
    and all((hop or default_port) == port for hop in hop_ports)
  )


def release_response_connection(response):
  """
  Break a streamed connection without waiting for the reader to finish.

  `response.close()` acquires the same buffer lock the reader thread holds
  inside `iter_content`, so against a peer that keeps dribbling bytes it blocks
  well past any deadline — the read timeout never fires, because data keeps
  arriving. Shutting the socket down instead makes the reader's blocked read
  fail at once, after which it unwinds on its own and the connection can be
  released normally by the caller's `finally`.
  """
  sock = getattr(getattr(response, "raw", None), "_connection", None)
  sock = getattr(sock, "sock", None)
  if sock is not None:
    try:
      sock.shutdown(socket.SHUT_RDWR)
      return
    except OSError:
      pass
  try:
    response.close()
  except Exception:
    pass


def read_bounded_response_body(response, max_bytes, max_seconds):
  """Read a streamed response without allowing a hostile peer to grow memory forever."""
  chunks = []
  total = 0
  deadline = time.monotonic() + max_seconds
  events = queue.Queue(maxsize=1)
  stopped = threading.Event()

  def _read():
    try:
      for chunk in response.iter_content(chunk_size=64 * 1024):
        if stopped.is_set():
          return
        events.put(("chunk", chunk))
      if not stopped.is_set():
        events.put(("done", None))
    except Exception:
      if not stopped.is_set():
        events.put(("error", None))

  def _stop():
    """
    Stop the reader and free it if it is blocked.

    Checking `stopped` before a put is not enough on its own: a put that was
    already blocked completes the moment this consumer takes an item, refilling
    the one-slot queue, and the reader can then block on a further put before it
    observes `stopped`. With no timeout on `Queue.put` that thread would wait
    forever, pinning a chunk and the response. Draining one slot here releases
    it, so every exit path must call this rather than only setting the flag.
    """
    stopped.set()
    # Drain first: a reader blocked on the full queue must be released, and the
    # connection teardown below is not guaranteed to reach it.
    try:
      events.get_nowait()
    except queue.Empty:
      pass
    release_response_connection(response)

  threading.Thread(target=_read, daemon=True).start()

  while True:
    remaining_seconds = deadline - time.monotonic()
    if remaining_seconds <= 0:
      _stop()
      return b"".join(chunks), False
    try:
      kind, payload = events.get(timeout=remaining_seconds)
    except queue.Empty:
      _stop()
      return b"".join(chunks), False
    if kind == "done":
      return b"".join(chunks), True
    if kind == "error":
      return b"".join(chunks), False
    if not payload:
      continue
    chunks.append(payload)
    total += len(payload)
    if total > max_bytes:
      stopped.set()
      response.close()
      return b"".join(chunks)[:max_bytes], False


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

    resolved_ips, resolver_error = resolve_host(
      self.target,
      timeout=self._target_timeout(FINGERPRINT_HTTP_TIMEOUT),
    )
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
      with socket.create_connection(
        (self.target, port),
        timeout=self._target_timeout(FINGERPRINT_TIMEOUT),
      ):
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
    session = requests.Session()
    resp = None
    try:
      user_agent = getattr(self, "scanner_user_agent", "")
      headers = {"User-Agent": user_agent} if user_agent else {}
      timeout = self._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
      deadline = time.monotonic() + timeout
      current_url = url
      redirect_count = 0
      while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
          raise requests.Timeout("response fingerprint deadline exceeded")
        resp = session.get(
          current_url,
          timeout=remaining,
          verify=False,
          allow_redirects=False,
          headers=headers,
          stream=True,
        )
        location = resp.headers.get("Location")
        if resp.status_code not in REDIRECT_STATUSES or not location:
          break
        if redirect_count >= DEFAULT_REDIRECT_LIMIT:
          raise requests.TooManyRedirects("response fingerprint redirect limit exceeded")
        next_url = urljoin(resp.url or current_url, location)
        if not redirect_stays_on_target(next_url, self.target, port):
          # Out of scope: keep this last in-scope response as the evidence and
          # never issue the off-target request.
          break
        current_url = next_url
        redirect_count += 1
        resp.close()
        resp = None
    except Exception as exc:
      self.P(f"Response fingerprint GET failed on {url}: {exc}", color='y')
      if resp is not None:
        resp.close()
      session.close()
      return None, None

    try:
      body, body_complete = read_bounded_response_body(
        resp,
        max_bytes=RESPONSE_BODY_MAX_BYTES,
        max_seconds=max(deadline - time.monotonic(), 0),
      )
      encoding = resp.encoding or "utf-8"
      try:
        body_text = body.decode(encoding, errors="replace")
      except LookupError:
        body_text = body.decode("utf-8", errors="replace")
      content_type = normalize_content_type(resp.headers.get("Content-Type"))
      title_match = _TITLE_RE.search(body_text[:5000])
      declared_length = resp.headers.get("Content-Length")
      try:
        declared_length = int(declared_length) if declared_length is not None else None
      except (TypeError, ValueError):
        declared_length = None
      if declared_length is not None and declared_length < 0:
        declared_length = None
      body_length = len(body) if body_complete else declared_length
      # Redact before truncating, so a credential straddling the cap cannot
      # survive as a prefix — the same order sanitize_excerpt uses internally.
      title = sanitize_excerpt(title_match.group(1).strip()) if title_match else None
      http = {
        "status": resp.status_code,
        "final_url": sanitize_excerpt(resp.url),
        "redirect_count": redirect_count,
        "title": title[:TITLE_MAX_CHARS] if title else None,
        "content_type": content_type,
        "body_length": body_length,
        # False means body_length is the peer's declared Content-Length and
        # title is derived from a partial body: both are attacker-influenced
        # and must not be treated as stable identity when comparing vantages.
        "body_complete": body_complete,
        "body_sha256": hashlib.sha256(body).hexdigest() if body_complete else None,
        # Captured headers are archived too, and `location` routinely carries a
        # token in its query string — especially on a hop refused as off-target,
        # whose raw Location would otherwise be stored verbatim.
        "headers": {
          name: sanitize_excerpt(resp.headers.get(name))
          for name in CAPTURED_HEADERS
          if resp.headers.get(name)
        },
      }

      excerpt = sanitize_excerpt(body_text) if excerpt_allowed(content_type) else None
      return http, excerpt
    except Exception as exc:
      # Reading and reducing the body must not end the scan. This block is no
      # longer safe-by-construction now that the body is streamed rather than
      # buffered by requests, and an uncaught error here reaches execute_job's
      # catch-all and skips every remaining phase.
      self.P(f"Response fingerprint capture failed on {url}: {exc}", color='y')
      return None, None
    finally:
      resp.close()
      session.close()
