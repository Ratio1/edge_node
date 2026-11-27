"""Read and write the Deeploy documents used only by oracles."""

# The SDK holder is populated from the protected seed environment or verified dAuth.
from ratio1.bc.base import BaseBlockEngine

# Enable only in a defaults release after every protocol oracle reports the matching startup check.
ORACLE_R1FS_WRITES = False
# The signed pointer identifies how its exact CID was written.
R1FS_ENCRYPTION = "r1fs_encryption"
# Both marker values identify custody-protected copies. The rewrite value supports the owner notice.
ORACLE_ENCRYPTED = "oracle"
ORACLE_REWROTE_LEGACY = "oracle_rewrote_legacy"
PROTECTED_R1FS_MODES = (ORACLE_ENCRYPTED, ORACLE_REWROTE_LEGACY)


def read_r1fs_document(r1fs, cid, *, protected_only=False, **kwargs):
  """Read a Deeploy document using local keys on a single download.

  Ordinary reads accept existing documents and documents encrypted with
  the shared oracle key. A protected-only read verifies the latter mode.

  Parameters
  ----------
  r1fs : R1FSEngine
    Instance used by the calling oracle.
  cid : str
    Document's immutable content identifier.
  protected_only : bool, optional
    Require the shared key when verifying a new pointer that claims protection.
  **kwargs : dict
    Read options such as timeout and pin.

  Returns
  -------
  dict or None
    The JSON document if an applicable passphrase authenticated it.

  Raises
  ------
  RuntimeError
    A protected read was requested without the shared key.

  Notes
  -----
  The write activation flag does not change the read policy. With a key,
  ordinary reads try that key and then the SDK default passphrase for
  legacy documents. Without a key, ordinary reads leave the supplied key
  options in place, including the SDK default when no options are given.
  Protected-only reads require the oracle key and disable fallback.

  Examples
  --------
  >>> read_r1fs_document(plugin.r1fs, cid, timeout=10, pin=False)  # doctest: +SKIP
  """
  # Reads remain compatible while protected writes are disabled.
  secret = BaseBlockEngine.oracle_secret()
  if protected_only and not secret:
    # Without the oracle key this read cannot verify the protection asserted by a pointer.
    raise RuntimeError("The oracle R1FS secret is unavailable.")
  if secret:
    # Try the public passphrase only for compatibility with pre-existing documents.
    kwargs.update(secret=secret, fallback_secrets=() if protected_only else (None,))
  # Keep secret values and raw document contents out of the SDK diagnostic logs by default.
  kwargs.setdefault("show_logs", False)
  # The SDK handles fallback without a second network read.
  return r1fs.get_json(cid, **kwargs)


def write_r1fs_document(r1fs, document, filename):
  """Write an oracle document with a random nonce and the active passphrase.

  Use the SDK to upload the JSON document under an immutable content
  identifier for subsequent reads.

  Parameters
  ----------
  r1fs : R1FSEngine
    Instance used by the calling oracle.
  document : dict
    Oracle-only job copy or deployment plan.
  filename : str
    Name recorded inside the encrypted document.

  Returns
  -------
  str or None
    The uploaded document's CID, or None if the upload failed.

  Raises
  ------
  RuntimeError
    Protected writes are enabled and the shared key is unavailable.

  Notes
  -----
  The write activation flag selects the passphrase for new writes. While
  it is disabled, writes use the SDK default passphrase. When it is
  enabled, every write requires the shared oracle key.

  Examples
  --------
  >>> write_r1fs_document(plugin.r1fs, plan, "deployment-plan.json")  # doctest: +SKIP
  """
  # Ship the reader first. Until the activation gate passes, keep writing with the public default.
  secret = BaseBlockEngine.oracle_secret() if ORACLE_R1FS_WRITES else None
  if ORACLE_R1FS_WRITES and not secret:
    # A protected write must fail before uploading a copy under the SDK default passphrase.
    raise RuntimeError("The oracle R1FS secret is unavailable.")
  # Omit nonce to use the SDK's random 96-bit AES-GCM nonce for every write.
  return r1fs.add_json(document, secret=secret, fn=filename, show_logs=False)
