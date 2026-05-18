"""Phase 3 PR-3.2 — authorization upload validator + storage tests.

Coverage:
  - PDF / PNG / JPEG accepted by magic-byte sniff.
  - Executable / archive / random bytes / MIME-spoofed inputs rejected.
  - 50 MB size cap enforced.
  - Empty / malformed base64 rejected.
  - Path-traversal filenames sanitized.
  - sha256 + size + filename + MIME present in stored envelope.
  - Optional virus-scan hook called and respected.
  - Storage failure surfaces as storage_failed error.
"""
from __future__ import annotations

import base64
import unittest

from extensions.business.cybersec.red_mesh.services.authorization_upload import (
  AuthorizationUploadError,
  AuthorizationUploadResult,
  MAX_AUTH_DOCUMENT_BYTES,
  store_authorization_document,
)


# ---------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------


class _MockArtifactRepo:
  """Captures put_json calls for inspection."""
  def __init__(self, return_cid="QmFakeAuthCID"):
    self.calls: list[dict] = []
    self._return_cid = return_cid

  def put_json(self, envelope, *, show_logs=False, **kwargs):
    self.calls.append(envelope)
    return self._return_cid


class _RaisingArtifactRepo:
  def put_json(self, envelope, **kwargs):
    raise RuntimeError("R1FS unavailable")


class _EmptyCidArtifactRepo:
  def put_json(self, envelope, **kwargs):
    return ""


# Realistic-shaped magic-byte fixtures
PDF_BYTES = b"%PDF-1.4\n%fake pdf body for tests\n%%EOF\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\nfake png body for tests"
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIFfake jpg body"
EXE_BYTES = b"MZ\x90\x00fake-windows-pe-header"
ZIP_BYTES = b"PK\x03\x04fake-zip-archive"
GIF_BYTES = b"GIF89a\x01\x00fake-gif"
RANDOM_BYTES = b"this is just plain text\nnot a recognized format"


def _b64(raw: bytes) -> str:
  return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------
# Acceptance tests — known-good formats
# ---------------------------------------------------------------------


class TestAcceptedFormats(unittest.TestCase):

  def test_pdf_accepted(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="auth.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.mime, "application/pdf")
    self.assertEqual(result.cid, "QmFakeAuthCID")
    self.assertEqual(result.filename, "auth.pdf")

  def test_png_accepted(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="auth-scan.png", content_b64=_b64(PNG_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.mime, "image/png")

  def test_jpeg_accepted(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="signed.jpg", content_b64=_b64(JPEG_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.mime, "image/jpeg")


# ---------------------------------------------------------------------
# Rejection tests — bad MIME / size / encoding
# ---------------------------------------------------------------------


class TestRejectsBadMime(unittest.TestCase):

  def test_executable_rejected(self):
    """Windows PE renamed to .pdf must be rejected — content not header."""
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="malware.pdf", content_b64=_b64(EXE_BYTES),
        artifact_repo=repo,
      )
    self.assertEqual(ctx.exception.code, "bad_mime")
    self.assertEqual(repo.calls, [], "must not store after MIME failure")

  def test_zip_rejected(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="archive.pdf", content_b64=_b64(ZIP_BYTES),
        artifact_repo=repo,
      )
    self.assertEqual(ctx.exception.code, "bad_mime")

  def test_gif_rejected(self):
    """GIF is not in the accepted set — only PDF/PNG/JPEG."""
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError):
      store_authorization_document(
        filename="signed.gif", content_b64=_b64(GIF_BYTES),
        artifact_repo=repo,
      )

  def test_random_bytes_rejected(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError):
      store_authorization_document(
        filename="auth.pdf", content_b64=_b64(RANDOM_BYTES),
        artifact_repo=repo,
      )


class TestRejectsSizeAndEncoding(unittest.TestCase):

  def test_oversize_rejected(self):
    """Cap is 50 MB; 51 MB blob with PDF magic bytes must be rejected."""
    repo = _MockArtifactRepo()
    big = PDF_BYTES + b"x" * MAX_AUTH_DOCUMENT_BYTES
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="big.pdf", content_b64=_b64(big),
        artifact_repo=repo,
      )
    self.assertEqual(ctx.exception.code, "too_large")

  def test_at_size_cap_accepted(self):
    """Exactly at the cap should be accepted (off-by-one safety check)."""
    repo = _MockArtifactRepo()
    pad_len = MAX_AUTH_DOCUMENT_BYTES - len(PDF_BYTES)
    at_cap = PDF_BYTES + b"\x00" * pad_len
    self.assertEqual(len(at_cap), MAX_AUTH_DOCUMENT_BYTES)
    result = store_authorization_document(
      filename="cap.pdf", content_b64=_b64(at_cap),
      artifact_repo=repo,
    )
    self.assertEqual(result.size_bytes, MAX_AUTH_DOCUMENT_BYTES)

  def test_empty_rejected(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="empty.pdf", content_b64="", artifact_repo=repo,
      )
    self.assertEqual(ctx.exception.code, "empty")

  def test_invalid_base64_rejected(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="bad.pdf", content_b64="not-base64!!!",
        artifact_repo=repo,
      )
    self.assertEqual(ctx.exception.code, "invalid_base64")


# ---------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------


class TestFilenameSanitization(unittest.TestCase):

  def test_path_traversal_stripped(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="../../../etc/passwd.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.filename, "passwd.pdf")
    self.assertNotIn("/", result.filename)

  def test_shell_metacharacters_replaced(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="file with spaces & $vars.pdf",
      content_b64=_b64(PDF_BYTES), artifact_repo=repo,
    )
    self.assertNotIn(" ", result.filename)
    self.assertNotIn("&", result.filename)
    self.assertNotIn("$", result.filename)
    self.assertTrue(result.filename.endswith(".pdf"))

  def test_empty_or_dotted_filename_falls_back(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="", content_b64=_b64(PDF_BYTES), artifact_repo=repo,
    )
    self.assertEqual(result.filename, "unnamed")

  def test_long_filename_truncated_preserving_extension(self):
    repo = _MockArtifactRepo()
    long_name = "a" * 300 + ".pdf"
    result = store_authorization_document(
      filename=long_name, content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertLessEqual(len(result.filename), 255)
    self.assertTrue(result.filename.endswith(".pdf"))


# ---------------------------------------------------------------------
# Envelope contents + integrity
# ---------------------------------------------------------------------


class TestEnvelopeStored(unittest.TestCase):

  def test_envelope_carries_required_fields(self):
    repo = _MockArtifactRepo()
    store_authorization_document(
      filename="auth.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(len(repo.calls), 1)
    env = repo.calls[0]
    self.assertEqual(env["kind"], "redmesh_authorization_document")
    self.assertEqual(env["schema_version"], "1.0")
    self.assertEqual(env["filename"], "auth.pdf")
    self.assertEqual(env["mime"], "application/pdf")
    self.assertEqual(env["size_bytes"], len(PDF_BYTES))
    self.assertTrue(env["uploaded_at"])
    self.assertTrue(env["content_b64"])
    # sha256 sanity
    self.assertEqual(len(env["sha256"]), 64)

  def test_sha256_matches_decoded_bytes(self):
    import hashlib
    expected = hashlib.sha256(PDF_BYTES).hexdigest()
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="auth.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.sha256_hex, expected)


# ---------------------------------------------------------------------
# Virus-scan hook
# ---------------------------------------------------------------------


class TestVirusScanHook(unittest.TestCase):

  def test_hook_returning_false_blocks_upload(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="auth.pdf", content_b64=_b64(PDF_BYTES),
        artifact_repo=repo,
        virus_scan_hook=lambda raw: False,
      )
    self.assertEqual(ctx.exception.code, "virus_detected")
    self.assertEqual(repo.calls, [], "must not store after virus detected")

  def test_hook_returning_true_allows_upload(self):
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="auth.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
      virus_scan_hook=lambda raw: True,
    )
    self.assertEqual(result.cid, "QmFakeAuthCID")

  def test_hook_raising_surfaces_storage_failed(self):
    repo = _MockArtifactRepo()
    def boom(raw):
      raise RuntimeError("scanner crashed")
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="auth.pdf", content_b64=_b64(PDF_BYTES),
        artifact_repo=repo, virus_scan_hook=boom,
      )
    self.assertEqual(ctx.exception.code, "storage_failed")

  def test_no_hook_means_no_scan(self):
    """Default behavior: skip virus scan, log only — do not block."""
    repo = _MockArtifactRepo()
    result = store_authorization_document(
      filename="auth.pdf", content_b64=_b64(PDF_BYTES),
      artifact_repo=repo,
    )
    self.assertEqual(result.cid, "QmFakeAuthCID")


# ---------------------------------------------------------------------
# Storage failure paths
# ---------------------------------------------------------------------


class TestStorageFailures(unittest.TestCase):

  def test_repo_raising_surfaces_storage_failed(self):
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="auth.pdf", content_b64=_b64(PDF_BYTES),
        artifact_repo=_RaisingArtifactRepo(),
      )
    self.assertEqual(ctx.exception.code, "storage_failed")

  def test_repo_returning_empty_cid_surfaces_storage_failed(self):
    with self.assertRaises(AuthorizationUploadError) as ctx:
      store_authorization_document(
        filename="auth.pdf", content_b64=_b64(PDF_BYTES),
        artifact_repo=_EmptyCidArtifactRepo(),
      )
    self.assertEqual(ctx.exception.code, "storage_failed")


if __name__ == "__main__":
  unittest.main()
