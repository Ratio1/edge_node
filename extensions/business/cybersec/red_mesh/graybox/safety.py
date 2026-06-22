"""
Safety controls for graybox scanning.

Rate limiting, attempt budgeting, and target validation.
"""

import time
from urllib.parse import urlparse

from ..constants import (
  GRAYBOX_DEFAULT_DELAY,
  GRAYBOX_WEAK_AUTH_DELAY,
  GRAYBOX_MAX_WEAK_ATTEMPTS,
)


class SafetyControls:
  """Rate limiting, attempt budgeting, and target validation."""

  def __init__(self, request_delay=None, weak_auth_delay=None,
               target_is_local=False):
    self._request_delay = request_delay or GRAYBOX_DEFAULT_DELAY
    self._weak_auth_delay = weak_auth_delay or GRAYBOX_WEAK_AUTH_DELAY
    self._last_request_at = 0.0
    # Enforce minimum delay for non-local targets to avoid
    # triggering WAF blocking or causing DoS on resource-constrained targets.
    if not target_is_local and self._request_delay < GRAYBOX_DEFAULT_DELAY:
      self._request_delay = GRAYBOX_DEFAULT_DELAY

  def throttle(self, min_delay=None):
    """Enforce minimum delay between requests."""
    delay = min_delay or self._request_delay
    elapsed = time.time() - self._last_request_at
    if elapsed < delay:
      time.sleep(delay - elapsed)
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
