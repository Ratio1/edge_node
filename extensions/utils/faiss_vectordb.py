"""
FAISS vector database adapter for Edge Node.

Replaces jina-ai/vectordb (archived, broken on modern Python).
Uses IndexFlatIP for cosine similarity on L2-normalized vectors.
Auto-detects GPU and moves index there when available.

Storage layout per context directory:
  index.faiss  — binary FAISS index
  meta.json    — sidecar with document text and idx
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import faiss
import numpy as np


@dataclass
class SearchResult:
  text: str
  idx: int
  score: float


class FaissVectorDB:
  """Thin FAISS wrapper matching the edge_node vectordb usage pattern."""

  INDEX_FILE = "index.faiss"
  META_FILE = "meta.json"

  def __init__(self, workspace: str | Path, embedding_size: int = 1024):
    self.workspace = Path(workspace)
    self.embedding_size = embedding_size
    self._index = None
    self._meta: list[dict] = []
    self._gpu_res = None
    self._open()

  # -- lifecycle ---------------------------------------------------------------

  def _open(self) -> None:
    self.workspace.mkdir(parents=True, exist_ok=True)
    index_path = self.workspace / self.INDEX_FILE
    meta_path = self.workspace / self.META_FILE

    if index_path.exists() and meta_path.exists():
      self._index = faiss.read_index(str(index_path))
      with open(meta_path) as f:
        self._meta = json.load(f)
    else:
      self._index = faiss.IndexFlatIP(self.embedding_size)
      self._meta = []

    self._maybe_move_to_gpu()

  def _gpu_available(self) -> bool:
    return hasattr(faiss, "get_num_gpus") and faiss.get_num_gpus() > 0

  def _maybe_move_to_gpu(self) -> None:
    if not self._gpu_available():
      return
    self._gpu_res = faiss.StandardGpuResources()
    self._index = faiss.index_cpu_to_gpu(self._gpu_res, 0, self._index)

  def _save(self) -> None:
    if self._index is None:
      return

    index_to_write = self._index
    if self._gpu_res is not None:
      index_to_write = faiss.index_gpu_to_cpu(self._index)

    faiss.write_index(index_to_write, str(self.workspace / self.INDEX_FILE))
    with open(self.workspace / self.META_FILE, "w") as f:
      json.dump(self._meta, f)

  def close(self) -> None:
    self._save()
    self._index = None
    self._meta = []
    self._gpu_res = None

  # -- operations --------------------------------------------------------------

  def index(self, documents: list[dict]) -> None:
    """Index a batch of documents. Each doc is a dict with text, embedding, idx."""
    embeddings = []
    for d in documents:
      emb = d["embedding"]
      if hasattr(emb, "numpy"):
        emb = emb.numpy()
      embeddings.append(emb)

    vectors = np.array(embeddings, dtype=np.float32)
    if vectors.ndim == 1:
      vectors = vectors.reshape(1, -1)

    faiss.normalize_L2(vectors)
    self._index.add(vectors)
    self._meta.extend({"text": d["text"], "idx": d["idx"]} for d in documents)
    self._save()

  def search(self, query_embedding, limit: int = 10) -> list[SearchResult]:
    """Search for nearest documents. Returns list of SearchResult."""
    if self._index is None or self._index.ntotal == 0:
      return []

    if hasattr(query_embedding, "numpy"):
      query_embedding = query_embedding.numpy()

    query = np.array(query_embedding, dtype=np.float32)
    if query.ndim == 1:
      query = query.reshape(1, -1)

    faiss.normalize_L2(query)
    scores, indices = self._index.search(query, min(limit, self._index.ntotal))

    results = []
    for score, i in zip(scores[0], indices[0]):
      if i < 0:
        continue
      meta = self._meta[i]
      results.append(SearchResult(text=meta["text"], idx=meta["idx"], score=float(score)))
    return results

  def num_docs(self) -> int:
    return self._index.ntotal if self._index else 0
