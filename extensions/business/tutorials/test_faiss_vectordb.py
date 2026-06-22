"""
Test plugin for FAISS vectordb replacement.

Exposes FastAPI endpoints to test the FaissVectorDB adapter:
  GET  /status         — check plugin is alive and show db stats
  POST /add_docs       — add documents to a context
  POST /search         — search a context with a query string
  GET  /list_contexts  — list all contexts and their doc counts
  POST /reset_context  — delete and recreate a context
"""

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin

from extensions.utils.faiss_vectordb import FaissVectorDB

__VER__ = '0.1.0.0'

EMBEDDING_SIZE = 128  # small for testing, real uses 1024

_CONFIG = {
  **FastApiWebAppPlugin.CONFIG,

  'PORT': None,

  'VALIDATION_RULES': {
    **FastApiWebAppPlugin.CONFIG['VALIDATION_RULES'],
  },
}


class TestFaissVectordbPlugin(FastApiWebAppPlugin):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    self._dbs = {}
    super(TestFaissVectordbPlugin, self).__init__(**kwargs)
    return


  def on_init(self, **kwargs):
    super(TestFaissVectordbPlugin, self).on_init(**kwargs)
    self.P("TestFaissVectordb plugin initialized")
    return

  def _get_db(self, context: str) -> FaissVectorDB:
    if context not in self._dbs:
      workspace = self.os_path.join(
        self.get_data_folder(), 'faiss_test', context
      )
      self._dbs[context] = FaissVectorDB(
        workspace=workspace,
        embedding_size=EMBEDDING_SIZE,
      )
      self.P(f"Created new context: {context}")
    return self._dbs[context]

  def _embed_texts(self, texts: list):
    """Simple deterministic embedding for testing — hash-based."""
    embeddings = []
    for text in texts:
      self.np.random.seed(hash(text) % (2**31))
      emb = self.np.random.randn(EMBEDDING_SIZE).astype(self.np.float32)
      emb /= self.np.linalg.norm(emb)
      embeddings.append(emb)
    return self.np.array(embeddings, dtype=self.np.float32)

  @FastApiWebAppPlugin.endpoint
  def status(self) -> dict:
    """Health check and db stats."""
    contexts = {}
    for name, db in self._dbs.items():
      contexts[name] = db.num_docs()
    return {
      "status": "ok",
      "version": __VER__,
      "embedding_size": EMBEDDING_SIZE,
      "contexts": contexts,
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def add_docs(self, context: str = "default", documents: list = []) -> dict:
    """Add documents (list of strings) to a context."""
    if not documents:
      return {"error": "No documents provided"}
    db = self._get_db(context)
    embeddings = self._embed_texts(documents)
    curr_size = db.num_docs()
    docs = [
      {"text": doc, "embedding": emb, "idx": curr_size + i}
      for i, (doc, emb) in enumerate(zip(documents, embeddings))
    ]
    db.index(docs)
    self.P(f"Indexed {len(docs)} docs in context '{context}', total={db.num_docs()}")
    return {
      "context": context,
      "added": len(docs),
      "total": db.num_docs(),
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def search(self, query: str, context: str = "default", k: int = 5) -> dict:
    """Search a context with a query string."""
    if context not in self._dbs:
      return {"error": f"Context '{context}' not found"}
    db = self._get_db(context)
    query_embedding = self._embed_texts([query])[0]
    results = db.search(query_embedding, limit=k)
    return {
      "context": context,
      "query": query,
      "results": [
        {"text": r.text, "idx": r.idx, "score": round(r.score, 4)}
        for r in results
      ],
    }

  @FastApiWebAppPlugin.endpoint
  def list_contexts(self) -> dict:
    """List all contexts and doc counts."""
    return {
      "contexts": {
        name: db.num_docs() for name, db in self._dbs.items()
      }
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def reset_context(self, context: str = "default") -> dict:
    """Delete and recreate a context."""
    if context in self._dbs:
      self._dbs[context].close()
      import shutil
      workspace = self.os_path.join(
        self.get_data_folder(), 'faiss_test', context
      )
      shutil.rmtree(workspace, ignore_errors=True)
      del self._dbs[context]
      self.P(f"Reset context: {context}")
    return {"status": "ok", "context": context}
