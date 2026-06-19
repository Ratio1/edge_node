"""Dedicated Model Test worker."""

from __future__ import annotations

import threading
import uuid

from .artifacts import sanitize_model_test_results, sanitize_model_test_summary
from .constants import (
  MODEL_TEST_ERROR_CANCELED_BY_USER,
  MODEL_TEST_ERROR_PROVIDER_RESPONSE_INVALID,
  MODEL_TEST_PHASE_CANCELED,
  MODEL_TEST_PHASE_FAILED,
)
from .runner import ModelTestRunner
from .secrets import resolve_model_test_runtime_config


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
    self.state["phase"] = MODEL_TEST_PHASE_CANCELED
    self.state["progress"] = 100.0
    self.state["error_class"] = MODEL_TEST_ERROR_CANCELED_BY_USER
    self.state["error_message"] = "Model test cancellation requested"
    self.state["model_test_summary"] = {
      **dict(self.state.get("model_test_summary") or {}),
      "overall_status": "canceled",
      "error_class": MODEL_TEST_ERROR_CANCELED_BY_USER,
    }

  def execute_job(self):
    if self.stop_event is not None and self.stop_event.is_set():
      self.state["canceled"] = True
      self.state["model_test_summary"] = {"overall_status": "canceled"}
      self.state["done"] = True
      return
    self.state["phase"] = "model_test_running"
    self.state["progress"] = 10.0
    try:
      runtime_config = resolve_model_test_runtime_config(self.owner, self.job_config)
      factory = getattr(self.owner, "model_test_provider_client_factory", None)
      runner = ModelTestRunner(
        self.owner,
        runtime_config,
        provider_client_factory=factory if callable(factory) else None,
        progress_callback=self._apply_progress_snapshot,
        stop_event=self.stop_event,
      )
      result = runner.run()
      self.state.update(result)
    except Exception:
      limits = dict((self.job_config or {}).get("limits") or {})
      cases_total = int(limits.get("max_cases") or 0) if str(limits.get("max_cases") or "").isdigit() else 0
      self.state["phase"] = MODEL_TEST_PHASE_FAILED
      self.state["progress"] = 100.0
      self.state["error_class"] = MODEL_TEST_ERROR_PROVIDER_RESPONSE_INVALID
      self.state["model_test_summary"] = {
        "overall_status": "failed",
        "cases_total": cases_total,
        "cases_completed": 0,
        "error_class": MODEL_TEST_ERROR_PROVIDER_RESPONSE_INVALID,
      }
      self.state["model_test_results"] = {
        "overall_status": "failed",
        "cases": [],
      }
    self.state["done"] = True

  def _apply_progress_snapshot(self, snapshot):
    if not isinstance(snapshot, dict):
      return
    for key in (
        "phase",
        "progress",
        "completed_tests",
        "model_test_results",
        "model_test_summary",
        "live_metrics",
    ):
      if key in snapshot:
        self.state[key] = snapshot[key]

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
      "model_test_results": sanitize_model_test_results(self.state.get("model_test_results") or {}),
      "model_test_summary": sanitize_model_test_summary(self.state.get("model_test_summary") or {}),
      "live_metrics": dict(self.state.get("live_metrics") or {}),
      "error": self.state.get("error"),
      "error_class": self.state.get("error_class"),
      "error_message": self.state.get("error_message"),
    }
    if not for_aggregations:
      result["local_worker_id"] = self.local_worker_id
    return result
