"""Mixin: exponential backoff for container restart attempts."""


class _RestartBackoffMixin:
  """
  Exponential backoff for container restart attempts.

  Required on the composing plugin (BasePlugin already provides time/P/Pd):
    - self.time(), self.P(msg, color=...), self.Pd(...)
    - self.cfg_restart_backoff_initial / _multiplier / _max
    - self.cfg_restart_reset_interval
    - self.cfg_restart_max_retries
    - self._consecutive_failures (int)
    - self._last_failure_time (float)
    - self._next_restart_time (float)
    - self._restart_backoff_seconds (float)
    - self._last_successful_start (float | None)
  """

  def _calculate_restart_backoff(self):
    """
    Calculate exponential backoff delay for restart attempts.

    Returns
    -------
    float
        Seconds to wait before next restart attempt
    """
    if self._consecutive_failures == 0:
      return 0

    # Exponential backoff: initial * (multiplier ^ (failures - 1))
    backoff = self.cfg_restart_backoff_initial * (
      self.cfg_restart_backoff_multiplier ** (self._consecutive_failures - 1)
    )

    # Cap at maximum backoff
    backoff = min(backoff, self.cfg_restart_backoff_max)

    return backoff


  def _should_reset_retry_counter(self):
    """
    Check if container has been running long enough to reset retry counter.

    Returns
    -------
    bool
        True if retry counter should be reset
    """
    if not self._last_successful_start:
      return False

    uptime = self.time() - self._last_successful_start
    return uptime >= self.cfg_restart_reset_interval


  def _record_restart_failure(self):
    """
    Record a restart failure and update backoff state.

    Returns
    -------
    None
    """
    self._consecutive_failures += 1
    self._last_failure_time = self.time()
    self._restart_backoff_seconds = self._calculate_restart_backoff()
    self._next_restart_time = self.time() + self._restart_backoff_seconds

    self.P(
      f"Container restart failure #{self._consecutive_failures}. "
      f"Next retry in {self._restart_backoff_seconds:.1f}s",
      color='r'
    )
    return


  def _record_restart_success(self):
    """
    Record a successful restart and reset failure counters if appropriate.

    Returns
    -------
    None
    """
    self._last_successful_start = self.time()

    # Reset failure counter after first successful start
    if self._consecutive_failures > 0:
      self.P(
        f"Container started successfully after {self._consecutive_failures} failure(s). "
        f"Retry counter will reset after {self.cfg_restart_reset_interval}s of uptime.",
      )
      # Don't reset immediately - wait for reset interval
      # self._consecutive_failures = 0  # This happens in _maybe_reset_retry_counter
    # end if
    return


  def _maybe_reset_retry_counter(self):
    """
    Reset retry counter if container has been running successfully.

    Returns
    -------
    None
    """
    if self._consecutive_failures > 0 and self._should_reset_retry_counter():
      old_failures = self._consecutive_failures
      self._consecutive_failures = 0
      self._restart_backoff_seconds = 0
      self.P(
        f"Container running successfully for {self.cfg_restart_reset_interval}s. "
        f"Reset failure counter (was {old_failures})"
      )
    # end if
    return


  def _is_restart_backoff_active(self):
    """
    Check if we're currently in backoff period.

    Returns
    -------
    bool
        True if we should wait before restarting
    """
    if self._next_restart_time == 0:
      return False

    current_time = self.time()
    if current_time < self._next_restart_time:
      remaining = self._next_restart_time - current_time
      self.Pd(f"Restart backoff active: {remaining:.1f}s remaining")
      return True

    return False


  def _has_exceeded_max_retries(self):
    """
    Check if max retry attempts exceeded.

    Returns
    -------
    bool
        True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_restart_max_retries <= 0:
      return False  # Unlimited retries

    return self._consecutive_failures >= self.cfg_restart_max_retries
