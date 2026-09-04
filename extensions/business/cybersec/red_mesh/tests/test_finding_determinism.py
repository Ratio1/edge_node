"""One target, two observations, one finding.

`test_evidence_hygiene.py` decides whether a value moves by matching its
*identifier* against a denylist. That is a blocklist over an open vocabulary:
five review rounds each closed the sites it knew about and the next round found
more — a subscripted `raw['banner']`, per-scan counts in titles, `uptime_seconds`,
salt `entropy`, wall-clock `elapsed`. Every one was found by a person reading
code, never by the guard.

This file checks the property the denylist is a proxy for, and checks it by
running the code rather than reading it: **two observations of one unchanged
target must produce the same finding keys.** No vocabulary, no identifier
knowledge, no per-probe judgement.

Both dedup paths are compared, because they differ and reasoning about one while
forgetting the other has now caused two defects:

- `finding_identity.dedup_key` — identity. Falls back to the title for findings
  with no scenario id and no specific location, which under `worker/` is all of
  them. Triage is persisted at `job_id:finding_id`, so a fork here detaches an
  analyst's decision from the finding it was made on.
- `mixins/report._finding_dedup_key` — the whole-dict key that collapses one
  finding seen by several workers. It hashes *every* field except worker
  attribution, so `evidence`, `title` and `description` are all load-bearing.

Deliberate limits, so the next reader does not over-trust this:

- It drives probes through one generic stub, so it reaches the probes that stub
  happens to satisfy — a real net, not a complete one. Widening the stub widens
  the net; that is the intended way to grow this file.
- Two runs *in one process against one stub* cannot surface a value that differs
  between nodes but not between runs (a `join()` over a per-worker set), nor one
  that only a real rotating server would produce.
- Time-derived values that are stable within a run survive it. Moving the clock
  is a separate, optional property, and `_tls_check_expiry` would need a shim:
  it does `from datetime import datetime` inside the function, and
  `patch("datetime.datetime.utcnow")` raises TypeError on the immutable type.
"""

import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, PentestLocalWorker

from extensions.business.cybersec.red_mesh.mixins.report import _finding_dedup_key
from extensions.business.cybersec.red_mesh.models.finding_identity import dedup_key


_WORKER_MODULES = (
  "service.common", "service.database", "service.infrastructure", "service.tls",
  "web.discovery", "web.hardening", "web.injection", "web.api_exposure",
)


def _worker():
  worker = PentestLocalWorker(
    owner=DummyOwner(),
    target="example.com",
    job_id="job-123",
    initiator="init@example",
    local_id_prefix="1",
    worker_target_ports=[443],
    exceptions=None,
  )
  worker.stop_event = MagicMock()
  worker.stop_event.is_set.return_value = False
  return worker


def _response():
  """One deterministic HTTP response, reused for every request."""
  resp = MagicMock()
  resp.status_code = 200
  resp.ok = True
  resp.reason = "OK"
  resp.text = "<html><title>Example</title>index of /</html>"
  resp.content = resp.text.encode()
  resp.headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
  resp.json.return_value = {"version": {"number": "7.0.0"}}
  resp.elapsed.total_seconds.return_value = 0.1
  resp.history = []
  resp.url = "http://example.com/"
  return resp


class _Socket:
  """One deterministic socket. Every read returns the same bytes."""

  def __init__(self, *a, **kw):
    self._read = False

  def settimeout(self, *_a):
    return None

  def connect(self, *_a):
    return None

  def connect_ex(self, *_a):
    return 0

  def sendall(self, *_a):
    return None

  def send(self, *_a):
    return 0

  def recv(self, *_a):
    # One banner, then EOF — what a real socket does. An endless stream of the
    # same bytes is not realistic and is actively harmful here: probes that read
    # until a prompt appears spin against their own wall-clock deadline instead,
    # which cost 40s in the telnet login loop alone.
    if self._read:
      return b""
    self._read = True
    return b"SSH-2.0-OpenSSH_8.2p1\r\n"

  def close(self):
    return None

  def shutdown(self, *_a):
    return None

  def makefile(self, *_a, **_kw):
    import io
    return io.BytesIO(b"220 example.com ESMTP\r\n")


def _stubbed_network():
  """Every network seam in every worker submodule, patched once.

  Built once per test rather than per probe call: rebuilding ~70 patchers for
  each of 122 calls dominated the runtime, and a slow test is one people skip.
  """
  from contextlib import ExitStack

  stack = ExitStack()
  # Probes that pace themselves between credential attempts do it with
  # `import time as _time` inside the function body, so the seam is the real
  # `time.sleep`. Telnet alone spends 40s per run sleeping; the property is
  # about which values reach a finding, not about timing.
  stack.enter_context(patch("time.sleep", return_value=None))
  for module in _WORKER_MODULES:
    base = f"extensions.business.cybersec.red_mesh.worker.{module}"
    for attr in ("get", "post", "put", "head", "options", "delete", "request"):
      try:
        stack.enter_context(
          patch(f"{base}.requests.{attr}", side_effect=lambda *a, **k: _response()))
      except (AttributeError, ModuleNotFoundError):
        continue
    for attr in ("socket.socket", "socket.create_connection"):
      try:
        stack.enter_context(
          patch(f"{base}.{attr}", side_effect=lambda *a, **k: _Socket()))
      except (AttributeError, ModuleNotFoundError):
        continue
  return stack


def _run_probe(name):
  """Drive one probe under the already-stubbed network and return its findings."""
  method = getattr(_worker(), name, None)
  if method is None:
    return None
  try:
    result = method("example.com", 443)
  except Exception as exc:
    # Returned, not swallowed. A probe that *starts* raising used to be
    # indistinguishable from one the generic stub never satisfied, so it left
    # the net silently.
    return exc
  return result.get("findings") or [] if isinstance(result, dict) else None


def _probe_names():
  names = set()
  for attr in dir(PentestLocalWorker):
    if attr.startswith("_service_info_") or attr.startswith("_web_test_"):
      names.add(attr)
  return sorted(names)


class TestTwoObservationsOfOneTargetProduceOneFinding(unittest.TestCase):

  def test_no_probe_forks_its_own_findings_across_two_identical_runs(self):
    """The whole property. A probe run twice against byte-identical input must
    produce byte-identical keys; anything else means a value that varies run to
    run reached a hashed field, and that finding will not collapse across
    workers — or, if the value is in the title, will not keep its identity or
    its triage across passes."""
    offenders = []
    covered = 0

    raised = []
    with _stubbed_network():
      pairs = [(name, _run_probe(name), _run_probe(name)) for name in _probe_names()]

    for name, first, second in pairs:
      if isinstance(first, Exception) or isinstance(second, Exception):
        raised.append(f"{name}: {type(first if isinstance(first, Exception) else second).__name__}")
        continue
      if not first and not second:
        continue
      if len(first or []) != len(second or []):
        # Worse than a volatile field, and it used to exit through the skip.
        offenders.append(
          f"{name}: produced {len(first or [])} findings then "
          f"{len(second or [])} from identical input"
        )
        continue
      covered += 1
      if sorted(map(_finding_dedup_key, first)) != sorted(map(_finding_dedup_key, second)):
        pass  # fall through to the pairwise report below
      first = sorted(first, key=_finding_dedup_key)
      second = sorted(second, key=_finding_dedup_key)
      for a, b in zip(first, second):
        for label, key in (
          ("identity (dedup_key)", dedup_key),
          ("cross-worker (report)", _finding_dedup_key),
        ):
          if key(a) != key(b):
            differing = sorted(
              field for field in set(a) | set(b) if a.get(field) != b.get(field)
            )
            offenders.append(
              f"{name}: {label} differs across two identical runs; "
              f"fields={differing}; first={ {f: a.get(f) for f in differing} }"
            )
            break

    self.assertEqual(
      offenders, [],
      "a value that changes between two observations of one unchanged target "
      "reached a hashed finding field. In `evidence`/`description` it breaks the "
      "cross-worker collapse, so one finding is reported once per worker; in "
      "`title` it also breaks identity, so the finding re-keys every scan and "
      "the triage recorded against it is orphaned. Put the observation in "
      "`raw_data` and state the stable fact in the field.",
    )
    # Coverage is a real number, not an implied one. If this drops, the stub
    # stopped satisfying probes it used to reach and the net shrank silently.
    self.assertEqual(
      raised, [],
      "a probe raised under the generic stub. That is either a real break or a "
      "stub that no longer matches the probe's call signature; either way the "
      "net silently loses it, so it fails here instead.",
    )
    # The measured number, not a token floor. It was 8 against an actual 26,
    # which let 18 probes drop out of the net without failing anything.
    self.assertGreaterEqual(
      covered, 26,
      f"only {covered} of 26 probes produced comparable findings under the "
      "generic stub — the net shrank; widen the stub rather than lower this",
    )
