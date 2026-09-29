"""RM-095. Tenant documents on R1FS through the artifact repository.

The envelope is stored as JSON and addressed by CID. It is not encrypted: anyone who learns the
CID can fetch it. RM-097 adds a database backend behind the same port.
"""
from ..ports import DocumentStoreError


class R1fsDocumentStore:
  name = "r1fs"

  def __init__(self, artifact_repo):
    self._artifacts = artifact_repo

  def put(self, envelope):
    try:
      ref = self._artifacts.put_json(envelope, show_logs=False)
    except Exception as exc:
      raise DocumentStoreError("Document storage write failed") from exc
    if not isinstance(ref, str) or not ref:
      raise DocumentStoreError("Document storage returned no reference")
    return ref

  def get(self, ref):
    if not isinstance(ref, str) or not ref:
      return None
    try:
      envelope = self._artifacts.get_json(ref)
    except Exception as exc:
      raise DocumentStoreError("Document storage cannot be read") from exc
    return envelope if isinstance(envelope, dict) else None

  def delete(self, ref):
    # Unpinned locally and remotely, then garbage-collected: the same call `purge_job` makes.
    try:
      deleted = self._artifacts.delete(ref, show_logs=False, raise_on_error=False, purge=True)
    except Exception as exc:
      raise DocumentStoreError("Document storage delete failed") from exc
    if deleted is not True:
      raise DocumentStoreError("Document storage did not confirm the delete")
