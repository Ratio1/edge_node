"""Mutable credential value object for graybox auth strategies.

`Credentials` holds the secret material a single `AuthStrategy` needs to
authenticate against a target. The orchestrator (`AuthManager`) hands it
to the strategy at ``authenticate()`` time; strategies retain a reference
only for the active session lifetime and call ``clear()`` on cleanup.

Critically:
- This class never appears in persisted JobConfig payloads. Secrets travel
  from the launch API into the R1FS secret payload via
  ``services/secrets.py::persist_job_config_with_secrets`` (Subphase 1.5
  commit #8). At worker startup the secrets are resolved out of the secret
  payload and packed into a `Credentials` instance.
- ``clear()`` overwrites each field with empty strings so accidental
  references (logs, repr, post-hoc serialisation) cannot leak token values.
- ``__repr__`` is overridden to never include secret values.

Mutable on purpose — `dataclass(frozen=True)` was considered but `clear()`
needs to overwrite fields. The class is treated as conceptually
write-once-then-clear; do not mutate it outside the auth layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Credentials:
  """Per-strategy credential bundle.

  Fields are union-typed by strategy:
    FormAuth        — uses ``username`` + ``password``.
    BearerAuth      — uses ``bearer_token`` (+ optional ``bearer_refresh_token``).
    ApiKeyAuth      — uses ``api_key``.

  Strategies must not write back into this object; only the orchestrator
  populates it. Strategies may, however, call ``clear()`` on cleanup.
  """
  username: str = ""
  password: str = ""
  bearer_token: str = ""
  bearer_refresh_token: str = ""
  api_key: str = ""

  # Optional principal label for diagnostics ("official", "regular", ...).
  principal: str = "official"

  # Static empty-string marker used by clear(). Defined as a class attribute
  # to avoid importing typing.Final each time.
  _CLEARED = ""

  def has_form_credentials(self) -> bool:
    return bool(self.username) and bool(self.password)

  def has_bearer_token(self) -> bool:
    return bool(self.bearer_token)

  def has_api_key(self) -> bool:
    return bool(self.api_key)

  def clear(self) -> None:
    """Overwrite every credential field. Idempotent.

    Note: Python strings are immutable, so ``clear()`` does not truly
    zeroise memory the way a buffer .fill(0) would. We rely instead on
    GC + the limited scope of the Credentials object. The point of this
    method is to ensure code that re-reads the object (after cleanup)
    sees empty values, not historical secrets.
    """
    self.username = self._CLEARED
    self.password = self._CLEARED
    self.bearer_token = self._CLEARED
    self.bearer_refresh_token = self._CLEARED
    self.api_key = self._CLEARED

  def __repr__(self) -> str:
    """Never include secret values in repr() (Subphase 1.5 secret-handling)."""
    return (
      "Credentials("
      f"principal={self.principal!r}, "
      f"has_form_credentials={self.has_form_credentials()}, "
      f"has_bearer_token={self.has_bearer_token()}, "
      f"has_api_key={self.has_api_key()}"
      ")"
    )
