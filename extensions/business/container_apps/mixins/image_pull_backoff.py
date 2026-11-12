"""Mixin: exponential backoff with jitter for image pull retries."""


class _ImagePullBackoffMixin:
  """
  Exponential backoff with jitter for image pull retries.

  The jitter component avoids the thundering-herd effect when multiple
  plugins on the same node hit a shared failure (e.g. DockerHub rate limit).

  Required on the composing plugin (BasePlugin already provides time/np/P):
    - self.time(), self.np, self.P(msg, color=...)
    - self.cfg_image_pull_backoff_base
    - self.cfg_image_pull_max_retries
    - self._image_pull_failures (int)
    - self._next_image_pull_time (float)
  """

  def _calculate_image_pull_backoff(self):
    """
    Calculate exponential backoff delay with random jitter for image pull retries.

    Formula: base * 2^(failures-1) + uniform(0, base * 2^(failures-1))
    No max cap here -- exponential growth naturally spaces out retries; a caller that never gives
    up passes its own ceiling to `_record_image_pull_failure`. The doubling itself stops at 2^20.
    The jitter component ensures multiple plugins on the same node
    don't retry simultaneously after a shared failure (e.g. DockerHub rate limit).

    With default base=20s:
      Failure 1:  20-40s
      Failure 2:  40-80s
      Failure 3:  80-160s   (~1-3 min)
      Failure 5:  320-640s  (~5-11 min)
      Failure 8:  2560-5120s (~43-85 min)
      Failure 10: ~3-6 hours
      Failure 13: ~1-2 days
      Failure 15: ~4-8 days

    Returns
    -------
    float
        Seconds to wait before next pull attempt

    Examples
    --------
    >>> self._image_pull_failures = 3
    >>> 80 <= self._calculate_image_pull_backoff() <= 160
    True
    """
    if self._image_pull_failures == 0:
      return 0
    # The doubling stops at 2^20 (about 240 days with the default base). A caller that never gives up
    # lets the failure count rise without end, and from failure 1021 the number no longer fitted a
    # float: the pause could not be computed and the pacing of the registry attempts was lost.
    base_backoff = self.cfg_image_pull_backoff_base * (2 ** min(self._image_pull_failures - 1, 20))
    jitter = self.np.random.uniform(0, base_backoff)
    return base_backoff + jitter


  def _record_image_pull_failure(self, max_backoff=None):
    """
    Record an image pull failure and schedule next attempt with backoff + jitter.

    Parameters
    ----------
    max_backoff : float, optional
        Longest pause in seconds before the next attempt. None (the default) leaves the pause
        uncapped, for callers that stop after `IMAGE_PULL_MAX_RETRIES`. A caller that retries
        forever sets it, so that the next attempt is never days away.

    Returns
    -------
    None

    Examples
    --------
    >>> self._record_image_pull_failure()                  # 20-40 s, 40-80 s, 80-160 s, ...
    >>> self._record_image_pull_failure(max_backoff=3600)  # the same, but at most one hour
    """
    self._image_pull_failures += 1
    backoff = self._calculate_image_pull_backoff()
    if max_backoff is not None:
      # The caller's ceiling, applied before the pause is scheduled and logged below.
      backoff = min(backoff, max_backoff)
    self._next_image_pull_time = self.time() + backoff
    self.P(
      f"Image pull failure #{self._image_pull_failures}. "
      f"Next attempt in {backoff:.1f}s (backoff + jitter)",
      color='r'
    )


  def _record_image_pull_success(self):
    """
    Record a successful image pull and reset backoff state.

    Returns
    -------
    None
    """
    if self._image_pull_failures > 0:
      self.P(
        f"Image pull succeeded after {self._image_pull_failures} failure(s). "
        f"Pull backoff reset.",
      )
    self._image_pull_failures = 0
    self._next_image_pull_time = 0


  def _is_image_pull_backoff_active(self):
    """
    Check if we're currently in image pull backoff period.

    Returns
    -------
    bool
        True if we should wait before attempting another pull
    """
    if self._next_image_pull_time == 0:
      return False
    return self.time() < self._next_image_pull_time


  def _has_exceeded_image_pull_retries(self):
    """
    Check if max image pull retry attempts exceeded.

    Returns
    -------
    bool
        True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_image_pull_max_retries <= 0:
      return False  # Unlimited retries
    return self._image_pull_failures >= self.cfg_image_pull_max_retries
