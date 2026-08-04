"""Connection-window aggregation and signal semantics shared across scan levels."""

RESPONSIVE_CONNECTION_OUTCOMES = frozenset(("connected", "refused", "reset"))
MIN_QUALIFIED_WINDOW_ATTEMPTS = 5
BLOCKING_BASELINE_RATE = 0.8
BLOCKING_RESPONSE_RATE = 0.2
THROTTLING_DROP_RATIO = 0.7


def detect_connection_signals(windows: list | None) -> dict:
  """Derive blocking/throttling signals from sufficiently sampled windows."""
  qualified = []
  for window in windows or []:
    attempts = window.get("attempts")
    if not isinstance(attempts, (int, float)) or attempts < MIN_QUALIFIED_WINDOW_ATTEMPTS:
      continue
    responsive_count = window.get("responsive_count")
    response_rate = window.get("response_rate")
    if response_rate is None and responsive_count is not None:
      response_rate = responsive_count / attempts
    if responsive_count is None and response_rate is not None:
      responsive_count = response_rate * attempts
    if response_rate is None or responsive_count is None:
      continue
    qualified.append({
      "attempts": attempts,
      "responsive_count": responsive_count,
      "response_rate": response_rate,
    })

  blocking = any(
    previous["response_rate"] >= BLOCKING_BASELINE_RATE
    and current["response_rate"] <= BLOCKING_RESPONSE_RATE
    for previous, current in zip(qualified, qualified[1:])
  )

  throttling = False
  if len(qualified) >= 4:
    first_attempts = sum(window["attempts"] for window in qualified[:2])
    last_attempts = sum(window["attempts"] for window in qualified[-2:])
    first_responsive = sum(window["responsive_count"] for window in qualified[:2])
    last_responsive = sum(window["responsive_count"] for window in qualified[-2:])
    baseline_rate = first_responsive / first_attempts
    later_rate = last_responsive / last_attempts
    throttling = (
      later_rate > BLOCKING_RESPONSE_RATE
      and later_rate < baseline_rate * THROTTLING_DROP_RATIO
    )

  return {
    "rate_limiting_detected": throttling,
    "blocking_detected": blocking,
  }


def merge_connection_windows(metrics_list: list) -> list | None:
  """Merge aligned count-bearing windows, excluding unverifiable legacy samples."""
  grouped = {}
  legacy_fallback = None
  for metrics in metrics_list:
    windows = metrics.get("success_rate_over_time") or []
    if legacy_fallback is None or len(windows) > len(legacy_fallback):
      legacy_fallback = windows
    for window in windows:
      attempts = window.get("attempts")
      responsive_count = window.get("responsive_count")
      if attempts is None or attempts <= 0:
        continue
      if responsive_count is None:
        response_rate = window.get("response_rate")
        if response_rate is None:
          continue
        responsive_count = round(response_rate * attempts)
      key = (window.get("window_start", 0), window.get("window_end", 0))
      bucket = grouped.setdefault(key, {
        "attempts": 0,
        "responsive_count": 0,
        "connected_weight": 0.0,
      })
      bucket["attempts"] += attempts
      bucket["responsive_count"] += responsive_count
      bucket["connected_weight"] += window.get("success_rate", 0) * attempts

  if not grouped:
    return legacy_fallback or None

  merged = []
  for (window_start, window_end), counts in sorted(grouped.items()):
    attempts = counts["attempts"]
    merged.append({
      "window_start": window_start,
      "window_end": window_end,
      "success_rate": round(counts["connected_weight"] / attempts, 3),
      "attempts": attempts,
      "responsive_count": counts["responsive_count"],
      "response_rate": round(counts["responsive_count"] / attempts, 3),
    })
  return merged
