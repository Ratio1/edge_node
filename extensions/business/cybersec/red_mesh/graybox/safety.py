"""
Safety controls for graybox scanning.

Rate limiting, attempt budgeting, and target validation.
"""

import contextlib
import ipaddress
import random
import socket
import time
from urllib.parse import urlparse

from ..constants import (
  GRAYBOX_BREAKER_THRESHOLD,
  GRAYBOX_DEFAULT_DELAY,
  GRAYBOX_WEAK_AUTH_DELAY,
  GRAYBOX_MAX_WEAK_ATTEMPTS,
)

from .budget import TargetThrottled

# Backoff and pacing sleeps poll the kill switch at least this often (seconds).
_STOP_POLL = 0.25


class GrayboxAbort(Exception):
  """Signal that the graybox pipeline must stop immediately.

  Raised from phase methods when a fatal safety or policy gate fails (unauthorized
  target, preflight rejection, unrecoverable auth failure), and from the HTTP
  admission gate when a stop is requested (reason_class "stopped"). The final
  handler is GrayboxLocalWorker.execute_job. Code that holds partial results may
  catch it only to keep them (ProbeBase._run_guarded, the worker's probe and
  stateful-flow runners, the weak-auth lockout check), and must re-raise it. A gate
  abort records its fatal finding via _record_fatal before raising; a stop records none.
  Defined here so safety can raise it; re-exported by graybox.worker.
  """

  def __init__(self, reason: str, reason_class: str = "unknown"):
    self.reason = reason
    self.reason_class = reason_class
    super().__init__(reason)


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# IPv6 forms whose low 32 bits carry an IPv4 address: NAT64, IPv4-compatible, -mapped, -translated.
_EMBEDS_IPV4 = tuple(ipaddress.ip_network(n) for n in
                     ("64:ff9b::/96", "::/96", "::ffff:0:0/96", "::ffff:0:0:0/96"))


class SafetyControls:
  """Rate limiting, attempt budgeting, and target validation."""

  def __init__(self, request_delay=None, request_delay_max=None, weak_auth_delay=None,
               target_is_local=False, stop_check=None):
    self._request_delay = request_delay or GRAYBOX_DEFAULT_DELAY
    self._request_delay_max = request_delay_max or self._request_delay
    self._weak_auth_delay = weak_auth_delay or GRAYBOX_WEAK_AUTH_DELAY
    self._last_request_at = 0.0
    self._prepaid = 0
    # Kill switch and circuit breaker (RM-273 Phase F). Refusals are counted so a probe
    # run that swallowed one can be downgraded by ProbeBase._run_guarded.
    self._stop_check = stop_check
    self._consecutive_throttles = 0
    self._breaker_open = False
    self.refusals = 0
    self.last_refusal = ""
    # Enforce minimum delay for non-local targets to avoid
    # triggering WAF blocking or causing DoS on resource-constrained targets.
    if not target_is_local and self._request_delay < GRAYBOX_DEFAULT_DELAY:
      self._request_delay = GRAYBOX_DEFAULT_DELAY
    if self._request_delay_max < self._request_delay:
      self._request_delay_max = self._request_delay

  def _next_request_delay(self):
    """Return a fixed or randomized Dune delay for ordinary requests."""
    if self._request_delay_max <= self._request_delay:
      return self._request_delay
    return random.uniform(self._request_delay, self._request_delay_max)

  @contextlib.contextmanager
  def prepaid(self):
    """Requests inside were paced by the caller just before: the client adds no delay.

    For timing probes, which must pace before starting the clock so the client's
    sleep never lands inside the measured window.
    """
    self._prepaid += 1
    try:
      yield
    finally:
      self._prepaid -= 1

  @property
  def breaker_open(self):
    return self._breaker_open

  @property
  def prepaid_active(self):
    return self._prepaid > 0

  def _refuse(self, reason, exc):
    self.refusals += 1
    self.last_refusal = reason
    raise exc

  def note_degraded(self, reason):
    """Count a non-raising degradation so `_run_guarded` downgrades the run's clean verdicts."""
    self.refusals += 1
    self.last_refusal = reason

  def _check_stop(self):
    if self._stop_check is not None and self._stop_check():
      self._refuse("stopped", GrayboxAbort("stop requested", reason_class="stopped"))

  def check_admission(self, exempt=False):
    """Refuse a non-exempt hop while a stop is requested or the breaker is open.

    Exempt hops (rollbacks) are never refused: an undo must complete.
    """
    if exempt:
      return
    self._check_stop()
    if self._breaker_open:
      self._refuse("target_throttled", TargetThrottled())

  def record_response(self, status_code):
    """Count consecutive 429/503 responses; any other status resets the count."""
    if status_code in (429, 503):
      self._consecutive_throttles += 1
      if self._consecutive_throttles >= GRAYBOX_BREAKER_THRESHOLD:
        self._breaker_open = True
    else:
      self._consecutive_throttles = 0

  def reset_breaker(self):
    self._consecutive_throttles = 0
    self._breaker_open = False

  def sleep(self, seconds, interruptible=True):
    """Sleep, waking on a stop request (at most `_STOP_POLL` late) unless not interruptible."""
    if not (interruptible and self._stop_check is not None):
      time.sleep(seconds)
      return
    end = time.time() + seconds
    while True:
      self._check_stop()
      left = end - time.time()
      if left <= 0:
        return
      time.sleep(min(left, _STOP_POLL))

  def throttle(self, min_delay=None, interruptible=True):
    """Enforce minimum delay between requests."""
    if self._prepaid and min_delay is None:
      return
    delay = min_delay if min_delay is not None else self._next_request_delay()
    elapsed = time.time() - self._last_request_at
    if elapsed < delay:
      self.sleep(delay - elapsed, interruptible)
    self._last_request_at = time.time()

  def throttle_auth(self):
    """Throttle for auth attempts (higher delay)."""
    self.throttle(min_delay=self._weak_auth_delay)

  @staticmethod
  def clamp_attempts(requested: int) -> int:
    """Enforce hard cap on weak-auth attempts."""
    return min(max(requested, 0), GRAYBOX_MAX_WEAK_ATTEMPTS)

  @staticmethod
  def is_local_target(target_url: str) -> bool:
    """Check if target is localhost/loopback."""
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    return hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1",
                        "host.docker.internal")

  @staticmethod
  def private_target_reason(hostname: str, resolver=None, fail_closed=False) -> str | None:
    """RM-273 (D30): why `hostname` resolves to a non-public address, else None.

    Covers private, loopback, link-local, CGNAT (100.64/10), unique-local, site-local and
    IPv6 forms embedding a private IPv4 (mapped, compatible, translated, NAT64). Called at
    admission and re-checked on every request, so a name that later resolves private is
    refused at its next request. The gap between this check and the connect is closed by
    connect-time pinning in RM-273 Phase G. An unresolvable name is refused only when
    `fail_closed` (per request); at admission the connection fails on its own.
    """
    host = (hostname or "").strip("[]")
    try:
      addresses = [ipaddress.ip_address(host)]
    except ValueError:
      try:
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0])
                       for info in (resolver or socket.getaddrinfo)(host, None)]
      except (OSError, ValueError):
        return (f"Target {hostname} did not resolve; refused without allow_private_targets."
                if fail_closed else None)
    for address in addresses:
      embedded = (ipaddress.IPv4Address(int(address) & 0xFFFFFFFF) if address.version == 6
                  and any(address in net for net in _EMBEDS_IPV4) else None)
      for candidate in filter(None, (address, embedded)):
        if (candidate.is_private or candidate.is_loopback or candidate.is_link_local
            or candidate.is_unspecified or candidate in _CGNAT
            or getattr(candidate, "is_site_local", False)):
          return (f"Target {hostname} resolves to private address {address}. "
                  "Set allow_private_targets on the engagement to scan it.")
    return None

  @staticmethod
  def validate_target(target_url: str, authorized: bool) -> str | None:
    """
    Validate target URL before scanning.

    Returns error message if invalid, None if OK.
    """
    if not authorized:
      return "Scan not authorized. Set authorized=True to confirm."

    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.hostname:
      return f"Invalid target URL: {target_url}"
    if parsed.scheme not in ("http", "https"):
      return f"Unsupported scheme: {parsed.scheme}"

    # Block obviously wrong targets
    blocked = {"google.com", "facebook.com", "amazon.com", "github.com"}
    hostname = parsed.hostname.lower()
    for domain in blocked:
      if hostname == domain or hostname.endswith("." + domain):
        return f"Target {hostname} is a public service. Refusing scan."

    return None

  @staticmethod
  def sanitize_error(msg: str, *, secret_field_names=()) -> str:
    """
    Remove potential credential leaks from error messages.

    Scrubs password= patterns, common secret markers, and configured
    API auth header/query names when provided by the caller.
    """
    import re
    msg = re.sub(r'password["\']?\s*[:=]\s*["\']?[^\s"\'&]+', 'password=***', msg, flags=re.I)
    msg = re.sub(r'secret["\']?\s*[:=]\s*["\']?[^\s"\'&]+', 'secret=***', msg, flags=re.I)
    msg = re.sub(r'token["\']?\s*[:=]\s*["\']?[^\s"\'&]+', 'token=***', msg, flags=re.I)
    try:
      from .findings import scrub_graybox_secrets
    except Exception:
      return msg
    return scrub_graybox_secrets(
      msg, secret_field_names=tuple(secret_field_names or ()),
    )
