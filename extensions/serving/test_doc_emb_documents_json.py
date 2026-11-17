"""The documents file of the doc-embedding flow is JSON at both ends: the Jeeves API writes it, the serving reads it.

The serving module and the Jeeves API module are imported as they are, so these tests run in the production image.
"""
# Paths and copies of the stored and restored files.
import os
# The format of the documents file before this change, written to show it is no longer loaded.
import pickle
# Copies and removal of the files of a test.
import shutil
# A folder of files per test.
import tempfile
# The test framework.
import unittest
# Stand-ins for the plugin members a test does not need.
from types import SimpleNamespace
# Recorded calls of the request helpers and of R1FS.
from unittest.mock import Mock

# The SDK's R1FS engine, whose real add_json stores the documents.
from ratio1.ipfs.r1fs import R1FSEngine

# The Jeeves API, the end that stores the documents.
from extensions.business.jeeves.jeeves_api import JeevesApiPlugin
# The doc-embedding serving, the end that reads them.
from extensions.serving.base.base_doc_emb_serving import BaseDocEmbServing, DocEmbCt


def _serving(lines, restored_path):
  """
  Build a doc-embedding serving without its model, whose R1FS restores one given file for any CID.

  The real class is used, without its constructor, so `retrieve_documents_from_path` and the ADD_DOC check run as
  they do on a node, while no model, tokenizer or vector store is loaded.

  Parameters
  ----------
  lines : list
    Receives each log line as (message, color).
  restored_path : str
    The path `r1fs.get_file` returns, as if R1FS had restored the file named by the request there.

  Returns
  -------
  BaseDocEmbServing
    The serving, with `P` and `r1fs` replaced.

  Examples
  --------
  >>> serving = _serving([], '/tmp/x/data.json')
  >>> serving.r1fs.get_file(cid='Qm', secret='ctx')
  '/tmp/x/data.json'
  """
  # The real class without its constructor: the tests need no model.
  serving = BaseDocEmbServing.__new__(BaseDocEmbServing)
  # Keep each log line with its color.
  serving.P = lambda message, color=None, **kw: lines.append((message, color))
  # R1FS restores the file under its stored name; the given path stands for that restored file.
  serving.r1fs = SimpleNamespace(get_file=Mock(return_value=restored_path))
  # The serving, ready for the ADD_DOC check.
  return serving


def _jeeves(r1fs):
  """
  Build a stand-in for the Jeeves API plugin with the members `add_documents` uses.

  Parameters
  ----------
  r1fs : object
    The R1FS engine the plugin stores the documents with.

  Returns
  -------
  SimpleNamespace
    `r1fs`, a `P` that keeps (message, color) in `lines`, and mocks of the request registration and solving.

  Examples
  --------
  >>> plugin = _jeeves(SimpleNamespace(add_json=lambda **kw: 'Qm'))
  >>> plugin.lines
  []
  """
  # The log lines, with their colors.
  lines = []
  # Only what add_documents reads: R1FS, the log, and the two request helpers it calls after storing.
  return SimpleNamespace(
    r1fs=r1fs, lines=lines, P=lambda message, color=None, **kw: lines.append((message, color)),
    register_add_documents_request=Mock(return_value="request-1"),
    solve_postponed_request=Mock(return_value={"status": "queued"}),
  )


class DocumentsJsonFormatTests(unittest.TestCase):
  """
  The documents of an ADD_DOC request travel as a JSON file: the Jeeves API stores them so, the serving reads them.

  Each test works in a folder of its own that stands for the folder R1FS restores files into. The Jeeves API is
  driven through its real `add_documents` on a stand-in plugin, and the serving through its real ADD_DOC check on
  an instance without a model.

  Examples
  --------
  >>> unittest.main(module="extensions.serving.test_doc_emb_documents_json", exit=False)
  """

  def setUp(self):
    """
    Make a folder for the files of one test.

    It stands for the folder R1FS restores files into, and is removed after the test, also when the test fails.

    Returns
    -------
    None
      The folder's path is kept in `self.folder`.
    """
    # Each test's files in a folder of their own.
    self.folder = tempfile.mkdtemp()
    # Removed even when the test fails.
    self.addCleanup(shutil.rmtree, self.folder)

  def _add_doc(self, serving):
    """
    Run the ADD_DOC check of a request that names one CID.

    Parameters
    ----------
    serving : BaseDocEmbServing
      The serving built by `_serving`.

    Returns
    -------
    tuple
      (is_bad_request, processed_request_params, err_msg), as the serving answers.

    Examples
    --------
    >>> self._add_doc(_serving([], '/tmp/x/data.json'))[0]   # a restored {"DOCUMENTS": ["text"]}
    False
    """
    # The request the Jeeves API registers: the CID and the context whose secret encrypts the file.
    return serving.doc_embedding_validate_request_params(
      DocEmbCt.ADD_DOC, {"documents_cid": "QmDocuments", "context_id": "ctx"},
    )

  def test_documents_stored_by_the_api_are_a_json_file_the_serving_reads(self):
    """The Jeeves API stores a list of documents through the SDK's add_json as "data.json", and the serving's
    ADD_DOC check reads that file back as the same documents."""
    # The real SDK add_json, without IPFS: an engine object without its constructor, whose add_file keeps a copy
    # of the file under its stored name, as get_file restores it later.
    engine = object.__new__(R1FSEngine)
    # The stored names, in the order add_file saw them.
    stored = []

    def add_file(file_path, secret, nonce, show_logs, raise_on_error):
      """
      Store a file as R1FS would, without IPFS: keep its name and a copy that `get_file` would restore.

      Parameters
      ----------
      file_path : str
        The temporary file that `add_json` wrote; its name is the stored name.
      secret : str
        The secret the file is encrypted with; the context id.
      nonce : int or None
        The encryption nonce `add_json` passes on; not used here.
      show_logs : bool
        Whether R1FS would log the store.
      raise_on_error : bool
        Whether R1FS would raise on a failed store; not used here.

      Returns
      -------
      str
        The CID of the stored file, always "QmDocuments".

      Examples
      --------
      >>> add_file("/tmp/x/data.json", "ctx", None, False, False)
      'QmDocuments'
      """
      # Keep the stored name, then a copy of the file under it.
      stored.append((os.path.basename(file_path), secret, show_logs))
      # The copy stands for the file that get_file restores; add_json removes its own afterwards.
      shutil.copy(file_path, os.path.join(self.folder, os.path.basename(file_path)))
      # The CID of the stored file.
      return "QmDocuments"

    # add_json calls add_file on the engine.
    engine.add_file = add_file
    # The documents must never be pickled again.
    engine.add_pickle = Mock(side_effect=AssertionError("documents stored as a pickle"))
    # The plugin stand-in stores through the real add_json.
    plugin = _jeeves(engine)
    # A list of documents given to the API.
    result = JeevesApiPlugin.add_documents(plugin, context_id="ctx", documents=["First document.", "Second one."])
    # The file is stored once, as "data.json", encrypted with the context, without logging the text.
    self.assertEqual(stored, [("data.json", "ctx", False)])
    # The ADD_DOC request carries the CID of that file.
    plugin.register_add_documents_request.assert_called_once_with(documents_cid="QmDocuments", context_id="ctx")
    # The request's answer is returned.
    self.assertEqual(result, {"status": "queued"})
    # The log lines of the serving.
    lines = []
    # Its R1FS restores the stored file.
    serving = _serving(lines, os.path.join(self.folder, "data.json"))
    # The request is accepted with the same documents, merged into one short segment as before.
    self.assertEqual(self._add_doc(serving),
                     (False, {"docs": ["First document.\nSecond one."], "CONTEXT_ID": "ctx"}, ""))
    # The file was fetched by the request's CID with the context as its secret.
    serving.r1fs.get_file.assert_called_once_with(cid="QmDocuments", secret="ctx")

  def test_api_reports_a_failed_store_in_red(self):
    """When add_json fails, the API answers an error, logs it in red and registers no request."""
    # An R1FS whose JSON store fails; add_pickle must not be called at all.
    r1fs = SimpleNamespace(add_json=Mock(return_value=None), add_pickle=Mock(side_effect=AssertionError("pickle")))
    # The plugin stand-in.
    plugin = _jeeves(r1fs)
    # The error answer names the context.
    expected = {"error": "Failed to add documents to context 'ctx'"}
    # A list of documents that cannot be stored.
    self.assertEqual(JeevesApiPlugin.add_documents(plugin, context_id="ctx", documents=["text"]), expected)
    # The same message, in red.
    self.assertEqual(plugin.lines, [(expected["error"], "r")])
    # No request is queued for the agents.
    plugin.register_add_documents_request.assert_not_called()

  def test_pickled_documents_file_is_not_loaded_and_is_a_bad_request(self):
    """A pickled ".pkl" file named by a request is not loaded: the request ends as a bad request, as any other
    unknown file type does."""
    # The file the API stored before this change, with valid documents, so only its format can refuse it.
    path = os.path.join(self.folder, "r1fs_documents.pkl")
    # Write it as add_pickle did.
    with open(path, "wb") as handle:
      # The same dict the API stores, pickled.
      pickle.dump({"DOCUMENTS": ["text"], "CONTEXT_ID": "ctx"}, handle)
    # The log lines of the serving.
    lines = []
    # The request names that file.
    is_bad, params, error = self._add_doc(_serving(lines, path))
    # A bad request, with the message for a value that is not a list of strings.
    self.assertEqual((is_bad, params), (True, {}))
    # The documents were never read: the check saw None.
    self.assertIn("NoneType", error)
    # The failed sample line on None is logged in red.
    self.assertEqual([color for _, color in lines], ["r"])

  def test_other_file_types_and_malformed_json_stay_bad_requests(self):
    """An unknown file type, a JSON file that is not an object and a JSON list that is not text end as bad
    requests; a JSON object without "DOCUMENTS" gives no documents, as the pickled file did."""
    # File name, content, and the expected (is_bad_request, docs) of the ADD_DOC check.
    cases = [
      ("documents.bin", '{"DOCUMENTS": ["text"]}', (True, None)),
      ("data.json", '["text"]', (True, None)),
      ("data.json", '{"DOCUMENTS": "text"}', (True, None)),
      ("data.json", '{"CONTEXT_ID": "ctx"}', (False, [])),
    ]
    # Each case on a fresh serving.
    for name, content, expected in cases:
      # One subtest per file.
      with self.subTest(name=name, content=content):
        # The file as R1FS would restore it.
        path = os.path.join(self.folder, name)
        # Write its content.
        with open(path, "w", encoding="utf-8") as handle:
          # The text of the case.
          handle.write(content)
        # The request names that file.
        is_bad, params, _ = self._add_doc(_serving([], path))
        # Bad or not, and the documents it would add.
        self.assertEqual((is_bad, params.get("docs")), expected)


if __name__ == "__main__":
  # Run the tests of this file.
  unittest.main()
