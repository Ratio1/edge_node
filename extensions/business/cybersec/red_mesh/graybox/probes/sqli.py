"""
SQL injection decision logic (RM-060 Phase D).

Transport-free: the caller passes ``send(value) -> response`` for one
parameter. The engine measures a baseline, then tries error, boolean and
time techniques and returns the first confirmed result, or None.

Safety: read-style payloads only. No stacked queries, no ``;``, and no
DROP/UPDATE/DELETE/INSERT.

Request budget per parameter (worst case):
  baseline 2 + error 2 + boolean 8 (2 pairs x TRUE/FALSE x 2 passes)
  + time: at most 4 sleep requests plus one control per confirmation try.
The time technique runs on GET only. A login form is capped (boolean and
error only, 8 POSTs per field, 16 per worker) so a lockout is not triggered.
"""

import hashlib
import html
import re
import time

from ..budget import RequestBudgetExhausted

TIME_DELAY = 3                 # seconds asked of the database
TIME_MARGIN = 0.8              # elapsed must exceed baseline + delay * margin
MAX_TIME_REQUESTS = 4          # hard cap of time-based requests per parameter
SCAN_TIME_ALLOWANCE = 60       # seconds of time-based waiting per worker
TIME_CONTROL_MARGIN = 1.0      # control request must stay under baseline + this
LOGIN_MAX_PER_FIELD = 8        # login form: POSTs per field
LOGIN_MAX_PER_SCAN = 16        # login form: POSTs per worker

DBMS_ERRORS = {
  "mysql": re.compile(
    r"you have an error in your sql syntax|mysqli?_\w+\(\)|"
    r"warning: mysql|mariadb server version", re.I),
  "postgresql": re.compile(
    r"pg_query\(|psycopg2?\.|unterminated quoted string at or near|"
    r"syntax error at or near|postgresql.{0,60}error|pg::syntaxerror", re.I),
  "sqlite": re.compile(
    r"sqlite3?\.operationalerror|sqlite error|unrecognized token:|"
    r"near \".{0,60}\": syntax error|sqlite_error", re.I),
  "mssql": re.compile(
    r"unclosed quotation mark after the character string|"
    r"microsoft sql server.{0,40}error|incorrect syntax near|odbc sql server driver|"
    r"ole db provider for sql server|sql server native client|"
    r"sqlserverexception|system\.data\.sqlclient", re.I),
  "oracle": re.compile(
    r"ora-\d{5}|oracle error|quoted string not properly terminated|"
    r"oracle.{0,40}driver", re.I),
}

BOOLEAN_PAIRS = (
  ("1' AND '1'='1", "1' AND '1'='2"),
  ("1 AND 1=1", "1 AND 1=2"),
)
ERROR_PAYLOADS = ("1'", '1"')
TIME_PAYLOADS = (
  ("mysql", f"1' AND (SELECT 1 FROM (SELECT SLEEP({TIME_DELAY}))x)-- -"),
  ("mysql", f"1 AND (SELECT 1 FROM (SELECT SLEEP({TIME_DELAY}))x)"),
  ("postgresql", f"1' AND 1=(SELECT 1 FROM pg_sleep({TIME_DELAY}))-- -"),
)

# Dynamic content that differs per request: long opaque tokens, long numbers.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{16,}|\d{6,}")


def dbms_from_text(text):
  """Name of the first DBMS whose error signature appears in ``text``."""
  for name, rx in DBMS_ERRORS.items():
    if rx.search(text or ""):
      return name
  return None


def _variants(text):
  """A string as it may be echoed: raw and HTML-escaped."""
  esc = (text.replace("&", "&amp;").replace("'", "&#39;")
         .replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;"))
  return {text, esc, html.escape(text), html.escape(text, quote=False)}


def _signature(resp, strip, base_value):
  """(status, hash of the stable content): echoed payloads, the echoed
  baseline value and dynamic tokens removed."""
  text = getattr(resp, "text", "") or ""
  variants = set()
  for s in strip:
    variants |= _variants(s)
  for v in sorted(variants, key=len, reverse=True):
    text = text.replace(v, "")
  text = text.replace(base_value, "")
  text = _TOKEN_RE.sub("", text)
  return (resp.status_code, hashlib.sha1(text.encode("utf-8", "replace")).hexdigest())


def status_reached(resp):
  """Login-form reachability by status: 2xx/3xx reached; the rest denied."""
  status = getattr(resp, "status_code", None)
  return isinstance(status, int) and 200 <= status < 400


# The client's refusal, raised by a ``prepare`` step or by ``send``.
BudgetRefused = RequestBudgetExhausted


class CsrfUnavailable(Exception):
  """Raised by a ``prepare`` step when the CSRF page cannot be fetched: no POST
  is sent and only this form's check ends (outcome ``csrf_unavailable``)."""


class _Stop(Exception):
  """End the run: message is the outcome (budget or capped)."""


def detect_sqli(send, throttle=None, reached=None, budget=None,
                time_left=None, base_value="1", prepare=None,
                allow_time=True, max_requests=None, cap=None):
  """Run the techniques for one parameter; return a result dict.

  ``send(value)`` (or ``send(value, ctx)`` when ``prepare`` is given) does one
  request and returns a response; it may raise. ``prepare()`` runs untimed
  before each request (a CSRF fetch) and may raise ``BudgetRefused``.
  ``reached(resp)`` says whether the response came from the endpoint handler.
  ``budget()`` peeks before every request (the client charges it); False stops
  the run, as does a ``BudgetRefused`` raised by ``send`` or ``prepare``.
  ``time_left`` is a one-key dict ``{"s": seconds}``: the allowance of
  time-based waiting, one dict per worker. ``allow_time=False`` skips the time
  technique. ``max_requests`` caps this parameter; ``cap`` is a shared
  ``{"left": n}`` cap across parameters.
  Result ``outcome``: hit | clean | denied | unstable | timeout | budget |
  capped. A hit also carries technique, payload_true, payload_false, dbms,
  confidence, requests, response (the response that proved it).
  """
  strip = [p for pair in BOOLEAN_PAIRS for p in pair] + list(ERROR_PAYLOADS)
  strip += [p for _, p in TIME_PAYLOADS]
  count = {"n": 0}

  def req(value):
    if max_requests is not None and count["n"] >= max_requests:
      raise _Stop("field_capped")
    if cap is not None and cap["left"] <= 0:
      raise _Stop("capped")
    if budget is not None and not budget():
      raise _Stop("budget")
    count["n"] += 1
    if cap is not None:
      cap["left"] -= 1
    try:
      ctx = prepare() if prepare else None
    except BudgetRefused:
      raise _Stop("budget")
    except CsrfUnavailable:
      raise _Stop("csrf_unavailable")
    except Exception:
      return None, 0.0
    # Pace last, after any prepare() request, so the gap before the timed send is
    # already served and the client adds none inside the clock.
    if throttle:
      throttle()
    started = time.monotonic()
    try:
      resp = send(value, ctx) if prepare else send(value)
    except BudgetRefused:
      raise _Stop("budget")
    except Exception:
      return None, time.monotonic() - started
    if getattr(resp, "status_code", None) == 429:
      raise _Stop("rate_limited")
    return resp, time.monotonic() - started

  def hit(technique, true_p, false_p, dbms, confidence, response=None):
    return {"outcome": "hit", "technique": technique, "payload_true": true_p,
            "payload_false": false_p, "dbms": dbms or "unknown",
            "confidence": confidence, "requests": count["n"],
            "response": response}

  try:
    return _run(req, hit, strip, reached, time_left, base_value, allow_time)
  except _Stop as stop:
    return {"outcome": str(stop)}


def _run(req, hit, strip, reached, time_left, base_value, allow_time):
  b1, t1 = req(base_value)
  b2, t2 = req(base_value)
  if b1 is None or b2 is None:
    return {"outcome": "denied"}
  if reached is not None and not (reached(b1) and reached(b2)):
    return {"outcome": "denied"}
  base_sig = _signature(b1, strip, base_value)
  stable = base_sig == _signature(b2, strip, base_value)
  base_dbms = {dbms_from_text(b1.text), dbms_from_text(b2.text)} - {None}
  base_elapsed = max(t1, t2)

  # Error: a signature after a quote that the baseline does not show.
  for payload in ERROR_PAYLOADS:
    resp, _ = req(payload)
    if resp is None:
      continue
    found = dbms_from_text(resp.text)
    if found and found not in base_dbms:
      return hit("error", payload, "", found, "firm", resp)

  # Boolean: TRUE matches the baseline, FALSE differs; repeated once.
  # No verdict when the baseline itself is not stable.
  if stable:
    for true_p, false_p in BOOLEAN_PAIRS:
      for _ in range(2):
        rt, _ = req(true_p)
        rf, _ = req(false_p)
        if rt is None or rf is None:
          break
        if not (_signature(rt, strip, base_value) == base_sig
                and _signature(rf, strip, base_value) != base_sig):
          break
      else:
        return hit("boolean", true_p, false_p, None, "firm", rf)

  if allow_time:
    result = _time_check(req, hit, time_left, base_value, base_elapsed)
    if result:
      return result
  return {"outcome": "clean" if stable else "unstable"}


def _time_check(req, hit, time_left, base_value, base_elapsed):
  """Sleep payload twice, with a benign control request between the hits that
  must stay near baseline. Capped per parameter and by the worker allowance;
  a request that raises is charged its real elapsed time."""
  threshold = base_elapsed + TIME_DELAY * TIME_MARGIN
  used = 0
  for dbms, payload in TIME_PAYLOADS:
    hits = 0
    for attempt in range(2):
      if used >= MAX_TIME_REQUESTS:
        break
      if time_left is not None and time_left["s"] < TIME_DELAY:
        break
      used += 1
      resp, elapsed = req(payload)
      if time_left is not None:
        time_left["s"] -= max(elapsed, 0)
      if resp is None:
        return {"outcome": "timeout"}
      if elapsed <= threshold:
        break
      hits += 1
      if attempt == 0:
        ctrl, ctrl_elapsed = req(base_value)
        if ctrl is None or ctrl_elapsed > base_elapsed + TIME_CONTROL_MARGIN:
          break  # the server is slow in general: not a sleep payload
    if hits == 2:
      return hit("time", payload, "", dbms, "tentative", resp)
  return None
