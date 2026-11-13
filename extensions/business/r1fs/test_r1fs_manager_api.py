"""
Tests for the base64 upload endpoint of the R1FS manager API (``add_file_base64``).

The real plugin class runs without its node-bound ``__init__``, over a private temporary local cache, with the
real diskapi helpers of the plugin base. Only the R1FS engine is a mock, specified by the real engine class.
"""
import base64
import functools
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from naeural_core.ipfs import R1FSEngine
from extensions.business.r1fs.r1fs_manager_api import R1fsManagerApiPlugin


PAYLOAD = b"plaintext bytes of an uploaded file"
PAYLOAD_B64 = base64.b64encode(PAYLOAD).decode("utf-8")


class _Probe(R1fsManagerApiPlugin):
  """
  The real plugin class without its node-bound ``__init__``, over a private local cache.

  The logger answers only the folders the diskapi helpers ask for, and the engine mock records the path and
  the bytes it was given, read while the staged file still exists.

  Parameters
  ----------
  root : str
      Folder that stands for the node's local cache; its ``_output`` subfolder is created here.

  Returns
  -------
  None

  Examples
  --------
  >>> probe = _Probe(tempfile.mkdtemp())
  >>> probe.add_file_base64(PAYLOAD_B64, filename="a.bin")
  {'cid': 'QmStaged'}
  """
  cfg_r1fs_verbose = 0
  # A read-only property on the plugin base; a plain class attribute lets __init__ set the engine mock.
  r1fs = None

  def __init__(self, root):  # pylint: disable=super-init-not-called
    output = os.path.join(root, "_output")
    os.makedirs(output)
    # Any other folder than the output one fails loudly with a KeyError.
    self.log = SimpleNamespace(
      get_base_folder=lambda: root,
      get_output_folder=lambda: output,
      get_target_folder=lambda target: {"output": output}[target],
    )
    self.P = mock.Mock()
    self.r1fs = mock.Mock(spec=R1FSEngine)
    # The real generator, so a missing name gets exactly the format the engine produces.
    self.r1fs._get_unique_name.side_effect = functools.partial(R1FSEngine._get_unique_name, self.r1fs)
    self.r1fs.add_file.side_effect = self._add_file
    self.staged = []

  def _add_file(self, file_path, secret=None, nonce=None):
    """
    Stand-in for the engine's ``add_file`` that records what it received.

    Parameters
    ----------
    file_path : str
        Staged plaintext file handed over by the endpoint.
    secret : str, optional
        Encryption key, unused here.
    nonce : int, optional
        Encryption nonce seed, unused here.

    Returns
    -------
    str
        A fixed CID.
    """
    with open(file_path, "rb") as handle:
      self.staged.append((file_path, handle.read()))
    return "QmStaged"


class AddFileBase64Tests(unittest.TestCase):

  def setUp(self):
    self.root = tempfile.mkdtemp(prefix="r1fs_api_test_")
    self.addCleanup(shutil.rmtree, self.root)
    self.output = os.path.join(self.root, "_output")
    self.plugin = _Probe(self.root)

  def _entries(self):
    """
    List every file and folder under the private local cache.

    Returns
    -------
    list of str
        Sorted paths relative to the local cache root.
    """
    found = []
    for folder, dirs, files in os.walk(self.root):
      found += [os.path.relpath(os.path.join(folder, name), self.root) for name in dirs + files]
    return sorted(found)

  def test_name_that_can_leave_the_staging_folder_is_refused_before_any_write(self):
    """Without the check the first name writes over a plugin cache inside the local cache and returns a CID."""
    names = [
      "../_data/cache_plugins/probe/object.pickle",
      # A '..' part after a harmless directory still climbs out of the per-request folder.
      "sub/../../x",
      # Absolute, but inside the local cache, so the cache's own path check would let it through.
      os.path.join(self.root, "_data", "abs.bin"),
      ".",
      "..",
    ]
    for name in names:
      with self.subTest(filename=name):
        # An undecodable payload: a refusal after decoding would raise binascii.Error instead of answering 400.
        result = self.plugin.add_file_base64("abc", filename=name)
        self.assertEqual(result["status_code"], 400)
        self.assertIn(repr(name), result["error"])
        self.assertEqual(self._entries(), ["_output"])
        self.plugin.r1fs.add_file.assert_not_called()
        red = [c.args[0] for c in self.plugin.P.call_args_list if c.kwargs.get("color") == "r"]
        self.assertTrue(any(repr(name) in line for line in red), red)

  def test_bare_name_is_added_with_its_name_and_bytes_and_no_copy_is_left(self):
    """The engine gets the same name, bytes, secret and nonce as before; nothing stays on disk."""
    result = self.plugin.add_file_base64(PAYLOAD_B64, filename="photo.png", secret="key", nonce=7)
    self.assertEqual(result, {"cid": "QmStaged"})
    [(file_path, data)] = self.plugin.staged
    self.assertEqual(os.path.basename(file_path), "photo.png")
    self.assertEqual(data, PAYLOAD)
    self.plugin.r1fs.add_file.assert_called_once_with(file_path=file_path, secret="key", nonce=7)
    # Staged in a folder of its own directly under the output folder.
    self.assertEqual(os.path.dirname(os.path.dirname(file_path)), self.output)
    self.assertEqual(self._entries(), ["_output"])

  def test_relative_directory_part_is_kept_inside_the_staging_folder(self):
    """A relative path, as the published Go client sends its FilePath, is added as before; nothing stays."""
    result = self.plugin.add_file_base64(PAYLOAD_B64, filename="app/run1/a.bin")
    self.assertEqual(result, {"cid": "QmStaged"})
    [(file_path, data)] = self.plugin.staged
    self.assertEqual(os.path.basename(file_path), "a.bin")
    self.assertEqual(data, PAYLOAD)
    # The name's folders were created under the per-request folder, which sits directly under the output folder.
    self.assertEqual(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(file_path)))), self.output)
    self.assertEqual(self._entries(), ["_output"])

  def test_existing_file_with_the_same_name_is_not_overwritten(self):
    """Without the per-request folder the upload replaces a file already in the output folder."""
    kept = os.path.join(self.output, "photo.png")
    with open(kept, "wb") as handle:
      handle.write(b"keep")
    self.plugin.add_file_base64(PAYLOAD_B64, filename="photo.png")
    with open(kept, "rb") as handle:
      self.assertEqual(handle.read(), b"keep")
    self.assertEqual(self.plugin.staged[0][1], PAYLOAD)
    self.assertEqual(self._entries(), ["_output", "_output/photo.png"])

  def test_staged_folder_is_removed_when_the_add_raises(self):
    """The engine's error reaches the caller and the staged plaintext is gone all the same."""
    seen = []

    def _fail(file_path, secret=None, nonce=None):
      seen.append(os.path.isfile(file_path))
      raise RuntimeError("ipfs add failed")
    self.plugin.r1fs.add_file.side_effect = _fail
    with self.assertRaisesRegex(RuntimeError, "ipfs add failed"):
      self.plugin.add_file_base64(PAYLOAD_B64, filename="photo.png")
    self.assertEqual(seen, [True])
    self.assertEqual(self._entries(), ["_output"])

  def test_missing_name_uses_a_generated_bare_name_and_leaves_no_copy(self):
    """An omitted or empty name is generated in the engine's format and staged like a given one."""
    for missing in (None, ""):
      with self.subTest(filename=missing):
        self.plugin.staged.clear()
        result = self.plugin.add_file_base64(PAYLOAD_B64, filename=missing)
        self.assertEqual(result, {"cid": "QmStaged"})
        [(file_path, data)] = self.plugin.staged
        self.assertRegex(os.path.basename(file_path), r"^r1fs_[0-9a-f]{8}$")
        self.assertEqual(data, PAYLOAD)
        self.assertEqual(self._entries(), ["_output"])


if __name__ == "__main__":
  unittest.main()
