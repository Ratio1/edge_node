"""Dedicated Model Test worker placeholder.

This worker is intentionally separate from scan workers. The first RM-012
execution slice proves lifecycle isolation and selected-node-only launch; the
provider runner/evaluator fills in the real case execution later.
"""

from __future__ import annotations

import threading
import uuid


class ModelTestWorker:
  """Lifecycle-compatible worker tracked under ``owner.model_test_jobs``."""

  def __init__(self, owner, *, job_id, initiator, job_config, local_id="1"):
    self.owner = owner
    self.job_id = job_id
    self.initiator = initiator
    self.job_config = dict(job_config or {})
    self.local_worker_id = "MT-{}-{}".format(local_id, str(uuid.uuid4())[:4])
    self.thread = None
    self.stop_event = None
    self.state = {
      "job_id": job_id,
      "initiator": initiator,
      "job_type": "model_test",
      "scan_type": "model_test",
      "phase": "queued",
      "progress": 0.0,
      "done": False,
      "canceled": False,
      "completed_tests": [],
      "model_test_results": {},
      "model_test_summary": {"overall_status": "queued"},
      "error": None,
    }

  def start(self):
    self.stop_event = threading.Event()
    self.thread = threading.Thread(target=self.execute_job, daemon=True)
    self.thread.start()

  def stop(self):
    if self.stop_event:
      self.stop_event.set()
    self.state["canceled"] = True

  def execute_job(self):
    self.state["phase"] = "model_test_running"
    self.state["progress"] = 10.0
    if self.stop_event is not None and self.stop_event.is_set():
      self.state["canceled"] = True
      self.state["model_test_summary"] = {"overall_status": "canceled"}
    else:
      self.state["phase"] = "done"
      self.state["progress"] = 100.0
      self.state["completed_tests"] = ["model_test_worker_placeholder"]
      self.state["model_test_summary"] = {
        "overall_status": "not_implemented",
        "cases_total": int((self.job_config.get("limits") or {}).get("max_cases", 0) or 0),
        "cases_completed": 0,
      }
      self.state["model_test_results"] = {
        "overall_status": "not_implemented",
        "cases": [],
      }
    self.state["done"] = True

  def get_status(self, for_aggregations=False):
    result = {
      "job_id": self.job_id,
      "initiator": self.initiator,
      "job_type": "model_test",
      "scan_type": "model_test",
      "phase": self.state.get("phase", ""),
      "progress": self.state.get("progress", 0),
      "done": self.state.get("done", False),
      "canceled": self.state.get("canceled", False),
      "completed_tests": list(self.state.get("completed_tests") or []),
      "model_test_results": dict(self.state.get("model_test_results") or {}),
      "model_test_summary": dict(self.state.get("model_test_summary") or {}),
      "error": self.state.get("error"),
    }
    if not for_aggregations:
      result["local_worker_id"] = self.local_worker_id
    return result
