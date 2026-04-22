"""Mixin: exponential backoff for per-tunnel-port restart attempts."""


class _TunnelBackoffMixin:
  """
  Per-tunnel-port exponential backoff for tunnel restart attempts.

  Each container_port has its own independent backoff state, so a
  failing tunnel for one port does not penalize others.

  Required on the composing plugin (BasePlugin already provides time/P/Pd):
    - self.time(), self.P(msg, color=...), self.Pd(...)
    - self.cfg_tunnel_restart_backoff_initial / _multiplier / _max
    - self.cfg_tunnel_restart_max_retries
    - self.cfg_tunnel_restart_reset_interval
    - self._tunnel_consecutive_failures   (dict[int, int])
    - self._tunnel_last_failure_time      (dict[int, float])
    - self._tunnel_next_restart_time      (dict[int, float])
    - self._tunnel_last_successful_start  (dict[int, float | None])
  """

  def _calculate_tunnel_backoff(self, container_port):
    """
    Calculate exponential backoff delay for tunnel restart attempts.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    float
        Seconds to wait before next tunnel restart attempt
    """
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures == 0:
      return 0

    # Exponential backoff: initial * (multiplier ^ (failures - 1))
    backoff = self.cfg_tunnel_restart_backoff_initial * (
      self.cfg_tunnel_restart_backoff_multiplier ** (failures - 1)
    )

    # Cap at maximum backoff
    backoff = min(backoff, self.cfg_tunnel_restart_backoff_max)

    return backoff


  def _record_tunnel_restart_failure(self, container_port):
    """
    Record a tunnel restart failure and update backoff state.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    self._tunnel_consecutive_failures[container_port] = \
      self._tunnel_consecutive_failures.get(container_port, 0) + 1
    self._tunnel_last_failure_time[container_port] = self.time()

    backoff = self._calculate_tunnel_backoff(container_port)
    self._tunnel_next_restart_time[container_port] = self.time() + backoff

    failures = self._tunnel_consecutive_failures[container_port]
    self.P(
      f"Tunnel restart failure for port {container_port} (#{failures}). "
      f"Next retry in {backoff:.1f}s",
      color='r'
    )
    return


  def _record_tunnel_restart_success(self, container_port):
    """
    Record a successful tunnel restart.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    self._tunnel_last_successful_start[container_port] = self.time()

    # Note success if there were previous failures
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures > 0:
      self.P(
        f"Tunnel for port {container_port} started successfully after {failures} failure(s)."
      )
    return


  def _is_tunnel_backoff_active(self, container_port):
    """
    Check if tunnel is currently in backoff period.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    bool
        True if we should wait before restarting tunnel
    """
    next_restart = self._tunnel_next_restart_time.get(container_port, 0)
    if next_restart == 0:
      return False

    current_time = self.time()
    if current_time < next_restart:
      remaining = next_restart - current_time
      self.Pd(f"Tunnel {container_port} backoff active: {remaining:.1f}s remaining")
      return True

    return False


  def _has_tunnel_exceeded_max_retries(self, container_port):
    """
    Check if tunnel has exceeded max retry attempts.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    bool
        True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_tunnel_restart_max_retries <= 0:
      return False  # Unlimited retries

    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    return failures >= self.cfg_tunnel_restart_max_retries


  def _maybe_reset_tunnel_retry_counter(self, container_port):
    """
    Reset tunnel retry counter if it has been running successfully.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures == 0:
      return

    last_start = self._tunnel_last_successful_start.get(container_port, 0)
    if not last_start:
      return

    uptime = self.time() - last_start
    if uptime >= self.cfg_tunnel_restart_reset_interval:
      self.P(
        f"Tunnel {container_port} running successfully for {self.cfg_tunnel_restart_reset_interval}s. "
        f"Reset failure counter (was {failures})",
      )
      self._tunnel_consecutive_failures[container_port] = 0

    return
