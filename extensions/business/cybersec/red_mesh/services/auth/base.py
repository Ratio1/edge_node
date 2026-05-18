from __future__ import annotations


class AuthError(Exception):
  """Raised when an auth provider can't produce credentials.

  Distinct from transport errors: AuthError means the configured username,
  password env var, or login endpoint is wrong — retrying without operator
  intervention won't help.
  """


class AuthConfigError(AuthError):
  """Raised when an auth provider can't be built from the given config."""


class AuthExpiredError(AuthError):
  """Raised when a cached credential is known-stale and needs re-auth."""


class AuthProvider:
  """Base class. Subclasses produce request headers for outbound integrations.

  Contract:
    headers() may raise AuthError on permanent credential failures (missing
    username, missing password env var, login endpoint rejecting creds).
    It must not raise for transient network failures during, say, JWT
    refresh — those should bubble up as the underlying transport exception
    so the delivery retry loop handles them uniformly.

    invalidate() is idempotent and cheap. Delivery code calls it after a 401
    to force the next headers() call to mint fresh credentials.
  """

  kind: str = "base"

  def headers(self) -> dict:
    raise NotImplementedError

  def invalidate(self) -> None:
    return None

  def __repr__(self) -> str:
    return f"{type(self).__name__}(kind={self.kind!r})"
