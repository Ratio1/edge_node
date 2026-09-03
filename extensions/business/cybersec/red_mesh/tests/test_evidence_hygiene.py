"""Evidence must be stable across runs and nodes, and carry no secrets.

`evidence` is part of both dedup keys — the report layer's whole-dict key and
(via `content_hash`) the risk layer's signature — so per-request data in it
defeats the one thing dedup exists for in a distributed scanner: the same
vulnerability seen from five nodes must appear once. Demonstrated before the
fix: two workers reporting one missing-Secure-flag cookie did **not** dedup,
because each captured a different session token in `Set-Cookie`.

Two of the offenders are also data exposure in their own right: the raw
`Set-Cookie` value (a live session token) and a real username were archived and
rendered — the same class as the `_CRED_RE` leak fixed earlier on this branch.

The rule: `evidence` states what was observed that makes this a finding, in
terms stable across runs and across nodes. Secrets, per-request identifiers,
response sizes, timing and attempt counts belong in `raw_data` /
`evidence_items`, which are not part of identity.
"""

import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, PentestLocalWorker


def _worker():
  owner = DummyOwner()
  worker = PentestLocalWorker(
    owner=owner,
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


def _dedup_keys(result):
  from extensions.business.cybersec.red_mesh.mixins.report import (
    _finding_dedup_key,
  )
  return [
    _finding_dedup_key(finding)
    for finding in sorted(result["findings"], key=lambda f: f["title"])
  ]


class TestCookieFindingsAreWorkerStable(unittest.TestCase):

  def _scan(self, token):
    resp = MagicMock()
    resp.headers = {"Set-Cookie": f"sessionid={token}; Path=/"}
    resp.status_code = 200
    resp.text = ""
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      return _worker()._web_test_flags("example.com", 443)

  def test_the_session_token_does_not_reach_the_finding(self):
    result = self._scan("SECRET-TOKEN-AAA111")
    for finding in result["findings"]:
      for field in ("evidence", "title", "description"):
        self.assertNotIn(
          "SECRET-TOKEN-AAA111", str(finding.get(field, "")),
          f"a live session token was archived in `{field}`",
        )

  def test_two_workers_seeing_different_tokens_deduplicate(self):
    """The cross-worker case dedup exists for: same cookie, same missing flag,
    different per-request token. One vulnerability, one row."""
    self.assertEqual(
      _dedup_keys(self._scan("token-from-worker-a")),
      _dedup_keys(self._scan("token-from-worker-b")),
    )


class TestVolatileObservationsStayOutOfEvidence(unittest.TestCase):

  def _redirect(self, suffix):
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {
      "Location": f"https://attacker.example/landing?state={suffix}",
    }
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      return _worker()._web_test_open_redirect("example.com", 443)

  def test_open_redirect_evidence_is_stable_across_rotating_tokens(self):
    self.assertEqual(
      _dedup_keys(self._redirect("nonce-111")),
      _dedup_keys(self._redirect("nonce-222")),
    )

  def test_a_hostile_location_header_does_not_kill_the_finding(self):
    """`urlsplit` raises ValueError on malformed IPv6 authorities. A target
    controlling the header must not convert a confirmed open redirect into a
    probe error — that would be a detection loss on exactly the hostile
    targets that matter."""
    resp = MagicMock()
    resp.status_code = 302
    # Malformed enough to make urlsplit raise, and it carries the probe's
    # payload, so the open redirect is genuinely confirmed.
    resp.headers = {"Location": "http://[bad/https://attacker.example"}
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      out = _worker()._web_test_open_redirect("example.com", 443)
    titles = [f.get("title", "") for f in out.get("findings", [])]
    self.assertIn("Open redirect via next parameter", titles)

  def _enumeration(self, fake_len, real_len):
    def fake_post(url, **_kwargs):
      resp = MagicMock()
      resp.status_code = 200
      resp.text = "x" * (fake_len if "nonexistent" in str(_kwargs.get("data", "")) else real_len)
      resp.headers = {}
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.post",
      side_effect=fake_post,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      side_effect=Exception("no GET expected"),
    ):
      return _worker()._web_test_account_enumeration("example.com", 443)

  def test_account_enumeration_evidence_has_no_username_or_sizes(self):
    result = self._enumeration(100, 900)
    findings = [
      f for f in result["findings"]
      if "response size differs" in f.get("title", "")
    ]
    self.assertTrue(findings, "enumeration finding was not produced")
    for finding in findings:
      evidence = str(finding.get("evidence", ""))
      self.assertNotIn("admin", evidence, "a probed username was archived")
      self.assertNotRegex(evidence, r"\d{2,} bytes", "response sizes are per-request data")

  def test_account_enumeration_evidence_is_stable_across_response_sizes(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _finding_dedup_key,
    )

    def keys(result):
      return [
        _finding_dedup_key(f) for f in result["findings"]
        if "response size differs" in f.get("title", "")
      ]

    self.assertEqual(keys(self._enumeration(100, 900)),
                     keys(self._enumeration(150, 1400)))


class TestBannerFindingsAreRunStable(unittest.TestCase):

  def test_vnc_banner_stays_out_of_title_and_evidence(self):
    """The banner is in `raw_data` already; in the *title* it makes `dedup_key`
    itself volatile (title is the locationless fallback discriminator), so the
    finding re-keyed on every scan."""
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _finding_dedup_key,
    )

    def scan(banner):
      sock = MagicMock()
      sock.recv.return_value = banner
      with patch(
        "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
        return_value=sock,
      ):
        return _worker()._service_info_vnc("example.com", 5900)

    result_a = scan(b"GARBAGE-abc123")
    result_b = scan(b"OTHERJUNK-xyz9")
    for result, marker in ((result_a, "abc123"), (result_b, "xyz9")):
      self.assertTrue(result["findings"], "non-RFB finding was not produced")
      for finding in result["findings"]:
        self.assertNotIn(marker, finding.get("title", ""))
        self.assertNotIn(marker, finding.get("evidence", ""))
    self.assertEqual(
      [_finding_dedup_key(f) for f in result_a["findings"]],
      [_finding_dedup_key(f) for f in result_b["findings"]],
    )
    # The observation itself is preserved where it belongs: raw_data.
    self.assertEqual(result_a.get("banner"), "GARBAGE-abc123")


class TestNoNewVolatileEvidenceInterpolations(unittest.TestCase):
  """Ratchet: a new `evidence=f"..."` interpolating per-request data fails here.

  Line-based and deliberately approximate — it catches the single-line form
  every current producer uses; a volatile value smuggled onto a continuation
  line slips past it. The allowlist is documented debt, not endorsement: each
  entry is a site where per-request bytes still reach the dedup key, kept small
  and burned down rather than grown. Fixing one removes its entry.
  """

  # Locals whose interpolation into `evidence` makes it per-request data.
  _VOLATILE = (
    "banner", "location", "cookie", "readable", "token", "resp.text", "data",
  )
  _VOLATILE_PREFIXES = ("len_", "len(")
  _VOLATILE_SUFFIXES = ("_count", "count}")

  # path:line-content fingerprints of the known remaining offenders — debt to
  # burn down, not endorsement. Each still puts per-request or per-run data
  # into the dedup key. Fixing a site removes its entry (the shrink test
  # enforces that the entry goes with it).
  _ALLOWLIST = {
    ("correlation.py", 'evidence=f"open={len(open_ports)}, scanned={len(ports_scanned)}, ratio={ratio:.2f}",'),
    ("service/common.py", 'evidence=f"Banner: {banner_text[:120]}",'),
    ("service/common.py", 'evidence=f"Banner: {banner}",'),
    ("service/database.py", 'evidence=f"DBSIZE={count}",'),
    ("service/database.py", 'evidence=f"Prelogin response: {readable.strip()[:80]}",'),
    ("service/database.py", """evidence=f"Response: {data[:60].decode('utf-8', errors='replace')}","""),
    ("service/database.py", 'evidence=f"Databases: {\', \'.join(dbs[:10])}" + (f"... (+{len(dbs)-10} more)" if len(dbs) > 10 else ""),'),
    ("service/database.py", 'evidence=f"GET /_utils/ returned {resp.status_code}, content-length={len(resp.text)}",'),
    ("service/infrastructure.py", 'evidence=f"Banner: {banner}, security types: {type_labels}",'),
    ("service/infrastructure.py", 'evidence=f"Banner: {banner}",'),
    ("service/infrastructure.py", 'evidence=f"Response: {readable.strip()[:80]}",'),
    ("service/infrastructure.py", 'evidence=f"Response contains: {readable.strip()[:80]}",'),
    ("service/infrastructure.py", 'evidence=f"AXFR query returned {ancount} answer records for {domain}.",'),
    ("service/infrastructure.py", 'evidence=f"Recursive query for example.com returned {ancount} answers with RA flag set.",'),
    ("service/infrastructure.py", 'evidence=f"WREPL response ({len(data)} bytes): {data[:24].hex()}",'),
    ("service/infrastructure.py", 'evidence=f"Response ({len(data)} bytes): {data[:32].hex()}",'),
    ("service/infrastructure.py", 'evidence=f"Device ID response: {readable.strip()[:80]}",'),
    ("service/tls.py", 'evidence=f"Heartbeat response size ({resp_len} bytes) > request payload size ({len(hb_msg)} bytes). "'),
    ("service/tls.py", 'evidence=f"Banner: {banner_text[:80]}",'),
    ("web/injection.py", 'evidence=f"Base size={len(resp_base.text)}, true={len(resp_true.text)}, "'),
  }

  def _is_volatile(self, line):
    import re

    for chunk in line.split("{")[1:]:
      name = chunk.split("}")[0]
      # Identifier-boundary match: `cookie` must flag `{cookie.strip()}` and
      # `{cookie}` but not `{cookie_name}` — the cookie's *name* is stable
      # data, its value is the secret.
      for volatile in self._VOLATILE:
        if re.match(rf"{re.escape(volatile)}(?![A-Za-z0-9_])", name):
          return True
      if any(name.startswith(v) for v in self._VOLATILE_PREFIXES):
        return True
      if re.match(r"[a-z_]*count(?![A-Za-z0-9_])", name):
        return True
    return False

  def test_worker_evidence_does_not_interpolate_per_request_data(self):
    import pathlib

    worker_dir = pathlib.Path(__file__).resolve().parent.parent / "worker"
    offenders = []
    for path in sorted(worker_dir.rglob("*.py")):
      rel = str(path.relative_to(worker_dir))
      for nr, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if 'evidence=f"' not in stripped:
          continue
        if not self._is_volatile(stripped):
          continue
        if (rel, stripped) in self._ALLOWLIST:
          continue
        offenders.append(f"{rel}:{nr}: {stripped}")
    self.assertEqual(
      offenders, [],
      "per-request data reached `evidence`, which breaks cross-worker dedup "
      "and can archive secrets; put stable facts in evidence and the volatile "
      "observation in raw_data/evidence_items",
    )

  def test_the_allowlist_only_shrinks(self):
    """Every allowlist entry must still exist — a fixed site must also drop its
    entry, or the list quietly becomes a graveyard nobody trusts."""
    import pathlib

    worker_dir = pathlib.Path(__file__).resolve().parent.parent / "worker"
    live = set()
    for path in sorted(worker_dir.rglob("*.py")):
      rel = str(path.relative_to(worker_dir))
      for line in path.read_text().splitlines():
        live.add((rel, line.strip()))
    stale = [entry for entry in self._ALLOWLIST if entry not in live]
    self.assertEqual(stale, [], "allowlist entries for lines that no longer exist")


if __name__ == "__main__":
  unittest.main()
