def _safe_log(owner, message: str, color: str = None):
  logger = getattr(owner, "P", None)
  if callable(logger):
    if color is None:
      logger(message)
    else:
      logger(message, color=color)


def _safe_audit(owner, event: str, payload: dict):
  audit = getattr(owner, "_log_audit_event", None)
  if callable(audit):
    audit(event, payload)


def run_bounded_retry(owner, action: str, attempts: int, operation, is_success=None):
  """Run a side-effecting operation with bounded retries and observable logs."""
  attempts = max(int(attempts or 1), 1)
  last_result = None
  last_error = None
  success_check = is_success or (lambda value: bool(value))

  for attempt in range(1, attempts + 1):
    try:
      last_result = operation()
      if success_check(last_result):
        if attempt > 1:
          _safe_log(owner, f"[RETRY] {action} succeeded on attempt {attempt}/{attempts}")
          _safe_audit(owner, "retry_recovered", {
            "action": action,
            "attempt": attempt,
            "attempts": attempts,
          })
        return last_result
      _safe_log(owner, f"[RETRY] {action} attempt {attempt}/{attempts} did not meet success criteria", color='y')
    except Exception as exc:
      last_error = exc
      last_result = None
      _safe_log(owner, f"[RETRY] {action} attempt {attempt}/{attempts} failed: {exc}", color='y')

    if attempt < attempts:
      _safe_audit(owner, "retry_attempt", {
        "action": action,
        "attempt": attempt,
        "attempts": attempts,
      })

  payload = {"action": action, "attempts": attempts}
  if last_error is not None:
    payload["error"] = str(last_error)
  _safe_audit(owner, "retry_exhausted", payload)
  return last_result
