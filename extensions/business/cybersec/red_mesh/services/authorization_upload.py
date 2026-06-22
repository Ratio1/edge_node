"""Authorization document upload service (PR-3.2).

PTES Pre-engagement requires written permission-to-test, signed by an
authorized party. This module handles the upload pipeline:

  1. Decode the base64 payload, enforce a 50 MB cap.
  2. Sniff magic bytes — accept only PDF / PNG / JPEG. Reject
     executables, archives, and MIME-spoofed uploads (Content-Type
     header is ignored; we trust only the file bytes themselves).
  3. Compute sha256 over the raw bytes for integrity.
  4. Wrap the file in a JSON envelope and persist via the existing
     R1FS ArtifactRepository.put_json path.
  5. Return the resulting CID.

Why JSON-wrapped bytes (and not a raw binary upload)
----------------------------------------------------

The existing R1FS access pattern only exposes put_json / get_json /
delete. A binary primitive doesn't exist yet. Wrapping the file in
``{filename, mime, sha256, size, content_b64}`` lets us reuse the
existing primitive without inventing a new one. Decoded size adds
~33 % overhead vs. raw-binary storage — acceptable for documents
capped at 50 MB and stored once per engagement.

Scope of this PR
----------------

PR-3.2 ships the validator + storage service. The HTTP route exposing
``POST /upload_authorization`` (which would call this service) is
intentionally NOT defined here — that's a thin wrapper that lands
when the frontend form (PR-3.5) is wired end-to-end. Until then this
module is exercised via unit tests.

Future hardening (out of scope for PR-3.2)
------------------------------------------

  - Virus-scan integration. A `VIRUS_SCAN_HOOK` env var pattern is
    sketched below; the actual ClamAV / VirusTotal integration is a
    separate ops PR.
  - Page-1 PDF thumbnail via poppler-utils. Skipped for now — poppler
    isn't installed in the dev container. The PDF appendix in Phase 7
    will display a placeholder when no thumbnail is available.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------
# Limits + accepted formats
# ---------------------------------------------------------------------

MAX_AUTH_DOCUMENT_BYTES = 50 * 1024 * 1024  # 50 MB

# Magic bytes for accepted formats. Each tuple is (label, byte prefix).
# Sniffed against the raw decoded bytes; the Content-Type header from
# the client is intentionally ignored to defeat MIME spoofing.
ACCEPTED_FORMATS: list[tuple[str, bytes]] = [
  ("application/pdf",          b"%PDF-"),
  ("image/png",                b"\x89PNG\r\n\x1a\n"),
  ("image/jpeg",               b"\xff\xd8\xff"),
  ("image/jpeg",               b"\xff\xd8\xff\xe0"),  # JFIF
  ("image/jpeg",               b"\xff\xd8\xff\xe1"),  # EXIF
]

# Filename sanitization — reject path-traversal attempts and shell
# metacharacters. The server-side filename never leaves the JSON
# envelope but we still want a clean record.
_FILENAME_RE = re.compile(r"[^\w\.\-]+")
_FILENAME_MAX_LEN = 255


# ---------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationUploadResult:
  cid: str                # R1FS CID of the stored envelope
  filename: str           # sanitized filename used in the envelope
  mime: str               # detected MIME type
  size_bytes: int
  sha256_hex: str
  uploaded_at: str        # ISO 8601 UTC


@dataclass(frozen=True)
class AuthorizationUploadError(Exception):
  code: str               # invalid_base64 | empty | too_large | bad_mime | storage_failed
  message: str

  def __str__(self) -> str:
    return f"{self.code}: {self.message}"


# ---------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------


def store_authorization_document(
  *,
  filename: str,
  content_b64: str,
  artifact_repo,
  virus_scan_hook=None,
  now_fn=None,
) -> AuthorizationUploadResult:
  """Validate + store an authorization document via R1FS.

  Parameters
  ----------
  filename : str
      Original filename for record-keeping. Sanitized server-side;
      path-traversal attempts (../) are stripped.
  content_b64 : str
      Standard base64 (RFC 4648) encoding of the file bytes.
  artifact_repo : ArtifactRepository
      Existing R1FS artifact-repo instance. We call put_json on it.
  virus_scan_hook : callable | None
      Optional hook ``hook(raw_bytes) -> bool`` returning True if the
      bytes are clean. Called after MIME validation. When None,
      virus-scan is skipped (logged, not blocked).
  now_fn : callable | None
      Injectable clock for deterministic tests; defaults to UTC now.

  Raises
  ------
  AuthorizationUploadError
      With ``code`` indicating which check failed:
        invalid_base64 | empty | too_large | bad_mime |
        virus_detected | storage_failed
  """
  if now_fn is None:
    now_fn = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  # 1. Decode
  try:
    raw = base64.b64decode(content_b64 or "", validate=True)
  except (binascii.Error, ValueError) as exc:
    raise AuthorizationUploadError(
      code="invalid_base64",
      message=f"content_b64 is not valid base64: {exc}",
    )

  if not raw:
    raise AuthorizationUploadError(
      code="empty", message="uploaded file is empty",
    )

  if len(raw) > MAX_AUTH_DOCUMENT_BYTES:
    raise AuthorizationUploadError(
      code="too_large",
      message=(
        f"file size {len(raw)} bytes exceeds the {MAX_AUTH_DOCUMENT_BYTES} "
        f"byte ({MAX_AUTH_DOCUMENT_BYTES // (1024*1024)} MB) cap"
      ),
    )

  # 2. MIME sniff
  detected_mime = _sniff_mime(raw)
  if detected_mime is None:
    raise AuthorizationUploadError(
      code="bad_mime",
      message=(
        "file is not a recognized PDF, PNG, or JPEG. Content-Type "
        "headers are ignored — we sniff the file bytes directly."
      ),
    )

  # 3. Optional virus scan
  if virus_scan_hook is not None:
    try:
      clean = bool(virus_scan_hook(raw))
    except Exception as exc:
      raise AuthorizationUploadError(
        code="storage_failed",
        message=f"virus-scan hook raised: {exc}",
      )
    if not clean:
      raise AuthorizationUploadError(
        code="virus_detected",
        message="virus-scan hook flagged the upload",
      )

  # 4. Build envelope
  sanitized = _sanitize_filename(filename)
  sha256_hex = hashlib.sha256(raw).hexdigest()
  envelope: dict[str, Any] = {
    "kind": "redmesh_authorization_document",
    "schema_version": "1.0",
    "filename": sanitized,
    "mime": detected_mime,
    "size_bytes": len(raw),
    "sha256": sha256_hex,
    "uploaded_at": now_fn(),
    "content_b64": base64.b64encode(raw).decode("ascii"),
  }

  # 5. Store via R1FS
  try:
    cid = artifact_repo.put_json(envelope, show_logs=False)
  except Exception as exc:
    raise AuthorizationUploadError(
      code="storage_failed",
      message=f"R1FS put_json raised: {exc}",
    )
  if not cid:
    raise AuthorizationUploadError(
      code="storage_failed",
      message="R1FS put_json returned empty CID",
    )

  return AuthorizationUploadResult(
    cid=cid,
    filename=sanitized,
    mime=detected_mime,
    size_bytes=len(raw),
    sha256_hex=sha256_hex,
    uploaded_at=envelope["uploaded_at"],
  )


# ---------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------


def _sniff_mime(raw: bytes) -> str | None:
  """Detect MIME by magic bytes. Returns None for unrecognized.

  Trusts only the file bytes — ignores any Content-Type header the
  client may have sent. Defeats MIME-spoofing where an attacker
  renames an .exe to .pdf.
  """
  for mime, prefix in ACCEPTED_FORMATS:
    if raw.startswith(prefix):
      return mime
  return None


def _sanitize_filename(name: str | None) -> str:
  """Strip path components, replace dangerous chars, cap length."""
  if not isinstance(name, str) or not name:
    return "unnamed"
  # Keep only the basename — defeat ../../../etc/passwd
  base = os.path.basename(name).strip()
  if not base:
    return "unnamed"
  # Replace anything other than [A-Za-z0-9_.-] with underscore
  cleaned = _FILENAME_RE.sub("_", base)
  # Cap length
  if len(cleaned) > _FILENAME_MAX_LEN:
    # Preserve extension if present
    head, dot, ext = cleaned.rpartition(".")
    if dot and 1 <= len(ext) <= 8:
      keep = _FILENAME_MAX_LEN - len(ext) - 1
      cleaned = head[:keep] + "." + ext
    else:
      cleaned = cleaned[:_FILENAME_MAX_LEN]
  return cleaned or "unnamed"
