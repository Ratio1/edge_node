"""The channel-token check every RedMesh endpoint runs before its body (RM-075 Phase 2).

The framework's ``require_token=True`` only guarantees that *a* bearer header was present and
binds its value to the endpoint's first ``token`` parameter; it never compares the value
(``basic_server.j2`` ``get_bearer_token`` checks presence and scheme). The comparison lives here,
once, instead of being copied into 52 endpoint bodies.

Usage - innermost, directly on the endpoint, ``token`` first::

    @BasePlugin.endpoint(method="post", require_token=True)
    @channel_token_required
    def launch_network_scan(self, token: str, ...):

``functools.wraps`` is load-bearing three times: the framework discovers endpoints by
``hasattr(method, '__endpoint__')`` and ``wraps`` copies that attribute through ``__dict__``;
it validates ``inspect.signature(method)`` at plugin init (``token`` must be first) and
``signature`` follows ``__wrapped__``; and at dispatch it recomputes ``has_kwargs`` from the
signature to decide how to splat extra request fields.
"""
import functools

from ..model_testing.security import validate_backend_token

MARKER = "__channel_token_required__"


def channel_token_required(fn):
  """Deny with the typed backend-auth error unless ``token`` equals the deployment credential."""

  @functools.wraps(fn)
  def _guarded(self, token, *args, **kwargs):
    auth_error = validate_backend_token(token)
    if auth_error:
      return auth_error
    return fn(self, token, *args, **kwargs)

  setattr(_guarded, MARKER, True)
  return _guarded


def is_channel_guarded(fn):
  """True when ``fn`` (or what it wraps) carries the decorator marker."""
  return bool(getattr(fn, MARKER, False))
