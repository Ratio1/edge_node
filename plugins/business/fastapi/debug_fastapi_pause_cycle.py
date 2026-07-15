import os


if os.environ.get("EE_ENABLE_DEBUG_FASTAPI_PAUSE_CYCLE", "").strip().lower() not in {"1", "true", "yes"}:
  raise RuntimeError("DEBUG_FASTAPI_PAUSE_CYCLE is disabled outside its explicit debug testbed.")


from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin


__VER__ = "0.1.0"


_CONFIG = {
  **BasePlugin.CONFIG,

  "PORT": 3001,
  "ASSETS": None,
  "TEMPLATE": "basic_server",
  "TUNNEL_ENGINE": "cloudflare",
  "TUNNEL_ENGINE_ENABLED": True,
  "REQUESTS_PER_PAUSE": 10,
  "PAUSE_SECONDS": 10 * 60,
  "MAX_INCOMING_PER_LOOP": 1,
  "PROCESS_DELAY": 0,
  "LOG_REQUESTS": True,
  "DEBUG_TIMINGS": False,
  "PROFILE_LOG_PER_REQUEST": False,

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG["VALIDATION_RULES"],
  },
}


class DebugFastapiPauseCyclePlugin(BasePlugin):
  """Debug FastAPI app that pauses after each configured request batch."""
  CONFIG = _CONFIG

  def on_init(self):
    self.__requests_since_pause = 0
    self.__pause_until = None
    self.__pause_teardown_succeeded = True
    super(DebugFastapiPauseCyclePlugin, self).on_init()
    return

  def on_response(self, method, response):
    super(DebugFastapiPauseCyclePlugin, self).on_response(method, response)
    self.__requests_since_pause += 1
    if (
      self.__pause_until is None and
      self.__requests_since_pause >= self.cfg_requests_per_pause
    ):
      self.__pause_until = self.time() + self.cfg_pause_seconds
    return

  def should_pause(self):
    return self.__pause_until is not None

  def should_resume(self):
    return self.__pause_until is None or self.time() >= self.__pause_until

  def on_pause(self):
    if not self._init_process_finalized:
      return
    self.__pause_teardown_succeeded = False
    self._stop_request_monitor.set()
    if self._request_monitor_thread is not None:
      self._request_monitor_thread.join(timeout=1.0)
    self._maybe_close_start_commands()
    running_commands = [
      idx for idx, process in enumerate(self.start_commands_processes)
      if process is not None and process.poll() is None
    ]
    if running_commands:
      raise RuntimeError(f"Failed to stop start commands {running_commands} while pausing")
    if self._request_monitor_thread is not None and self._request_monitor_thread.is_alive():
      raise RuntimeError("Failed to stop the FastAPI request monitor while pausing")

    with self._incoming_lock:
      self._incoming_requests.clear()
    self.postponed_requests.clear()
    while True:
      try:
        self._server_queue.get(False)
      except Exception:
        break
    self._maybe_read_and_stop_all_log_readers()
    self.reset_tunnel_engine()

    nr_commands = len(self.get_start_commands())
    self.start_commands_started = [False] * nr_commands
    self.start_commands_finished = [False] * nr_commands
    self.start_commands_processes = [None] * nr_commands
    self.start_commands_start_time = [None] * nr_commands
    self.__pause_teardown_succeeded = True
    return

  def on_resume(self):
    if not self.__pause_teardown_succeeded:
      raise RuntimeError("Cannot resume after an incomplete web app teardown")
    self.__requests_since_pause = 0
    self.__pause_until = None
    self.failed = False
    self._stop_request_monitor.clear()
    self._start_request_monitor_thread()
    return

  @BasePlugin.endpoint(method="get", require_token=False)
  def ping(self):
    return {"message": "pong"}
