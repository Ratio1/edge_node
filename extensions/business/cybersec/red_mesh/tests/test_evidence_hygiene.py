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

  def test_a_changing_memcached_stats_reply_still_deduplicates(self):
    """The `stats` reply opens with `uptime` and `time`, which move every
    second. While it was interpolated into `evidence` — part of the content
    hash — two workers scanning one server a second apart produced two
    different signatures, so the finding landed in the report twice."""
    def scan(uptime, when):
      reply = (f"STAT pid 1\r\nSTAT uptime {uptime}\r\nSTAT time {when}\r\n"
               f"STAT version 1.6.21\r\nSTAT curr_connections 7\r\n").encode()
      sock = MagicMock()
      sock.recv.return_value = reply
      with patch(
        "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
        return_value=sock,
      ):
        return _worker()._service_info_memcached("example.com", 11211)

    a = scan(86412, 1764725101)
    b = scan(86413, 1764725102)
    for result in (a, b):
      stats = [f for f in result["findings"] if "stats accessible" in f.get("title", "")]
      self.assertTrue(stats, "the stats finding was not produced")
      for finding in stats:
        self.assertNotIn("uptime", finding.get("evidence", ""))
        self.assertNotIn("1764725", finding.get("evidence", ""))
    self.assertEqual(
      [f.get("evidence") for f in a["findings"]],
      [f.get("evidence") for f in b["findings"]],
      "evidence still moves between two scans a second apart",
    )
    # The reply itself is preserved where it belongs: raw_data.
    self.assertIn("uptime 86412", a.get("banner", ""))


class TestVolatileCountsStayOutOfTitles(unittest.TestCase):
  """`dedup_key` falls back to the title when a finding carries no scenario id
  and no specific location — which is every finding under `worker/`, since
  `scenario_id` is set only in `graybox/`. A per-scan count in a title
  therefore re-keys the finding on every scan, and triage is persisted at
  `job_id:finding_id`, so the analyst's decision detaches from it.
  """

  def test_a_redis_keyspace_that_grew_keeps_its_identity(self):
    def scan(count):
      probe = _worker()
      probe._redis_cmd = lambda sock, cmd: f":{count}\r\n" if cmd == "DBSIZE" else ""
      raw = {}
      return probe._redis_check_data(MagicMock(), raw), raw

    grown, raw_grown = scan(1201)
    before, raw_before = scan(1200)
    self.assertTrue(before and grown, "the DBSIZE finding was not produced")
    keys = lambda fs: [f.compute_dedup_key(probe_id="_service_info_redis") for f in fs]
    self.assertEqual(
      keys(before), keys(grown),
      "one written key re-keyed the finding and detached its triage",
    )
    # The count is not lost — it moves to raw_data and the description.
    self.assertEqual(raw_before["db_size"], 1200)
    self.assertIn("1200", before[0].description)


class TestNoNewVolatileEvidenceInterpolations(unittest.TestCase):
  """Ratchet: a new `evidence=f"..."` interpolating per-request data fails here.

  Line-based and deliberately approximate — it catches the single-line form
  every current producer uses; a volatile value smuggled onto a continuation
  line slips past it. The allowlist was burned down to empty on 2026-09-03;
  a new entry is debt being taken on and needs a justification comment and an
  owner, not a silent add.
  """

  # Locals whose interpolation into `evidence` makes it per-request data.
  _VOLATILE = (
    "banner", "location", "cookie", "readable", "token", "resp.text", "data",
  )
  _VOLATILE_PREFIXES = ("len_", "len(")
  _VOLATILE_SUFFIXES = ("_count", "count}")

  # Empty by design: every previously-exempt site was fixed 2026-09-03
  # (closeout plan, Phase 3). A new entry here is debt being taken on — it
  # needs a justification comment and a burn-down owner, not a silent add.
  _ALLOWLIST = set()

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


class TestAValuelessCookieHeaderStaysOutOfTheFinding(unittest.TestCase):
  """A Set-Cookie with no `=` has no name — only content.

  `cookie_name` fell back to the first 30 characters of the raw header, which
  for a malformed or hostile header is arbitrary content: it landed in the
  *title* (pre-existing) and, after the evidence fix, in `evidence` too. And
  because the title feeds the locationless identity fallback, a rotating
  valueless header re-keyed the finding on every scan.
  """

  def _scan(self, header):
    resp = MagicMock()
    resp.headers = {"Set-Cookie": header}
    resp.status_code = 200
    resp.text = ""
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      return _worker()._web_test_flags("example.com", 443)

  def test_the_header_content_reaches_neither_title_nor_evidence(self):
    result = self._scan("eyJSECRETJWTPAYLOADxyz")
    self.assertTrue(result["findings"])
    for finding in result["findings"]:
      for field in ("title", "evidence", "description"):
        self.assertNotIn("eyJSECRET", str(finding.get(field, "")), field)

  def test_the_finding_id_is_stable_across_rotating_valueless_headers(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _finding_dedup_key,
    )

    def keys(result):
      return sorted(
        _finding_dedup_key(f) for f in result["findings"]
      )

    self.assertEqual(keys(self._scan("nonce-run-one")), keys(self._scan("nonce-run-two")))

  def test_a_named_cookie_still_shows_its_name(self):
    result = self._scan("sessionid=whatever; Path=/")
    self.assertIn("sessionid", result["findings"][0]["title"])


class TestRedirectAuthorityIsHostOnly(unittest.TestCase):
  """F6 (external review, validated): `parts.netloc` carries userinfo, so
  `https://user:secret@evil.example/cb` archived the credential — in the fix
  made for the previous credential leak. And the path carries per-request
  nonces, churning the dedup key. The redirect *host* is the load-bearing
  fact; everything else goes.
  """

  def _authority(self, location):
    from extensions.business.cybersec.red_mesh.worker.web.hardening import (
      _WebHardeningMixin,
    )
    return _WebHardeningMixin._redirect_authority(location)

  def test_userinfo_never_reaches_the_authority(self):
    self.assertNotIn("secret", self._authority("https://user:secret@evil.example/cb?t=1"))

  def test_the_host_and_port_survive(self):
    self.assertEqual(
      self._authority("https://user:secret@evil.example:8443/cb"),
      "https://evil.example:8443",
    )

  def test_a_rotating_path_nonce_does_not_change_the_authority(self):
    self.assertEqual(
      self._authority("https://evil.example/cb/nonce-111"),
      self._authority("https://evil.example/cb/nonce-222"),
    )

  def test_hostless_shapes_do_not_fabricate_an_authority(self):
    # No invented "//" for javascript:, no dangling "://" for scheme-relative.
    self.assertEqual(self._authority("javascript:alert(1)"), "javascript:")
    self.assertEqual(self._authority("//evil.example/x"), "//evil.example")
    self.assertEqual(self._authority("http://[bad"), "an unparseable URL")


class TestSetCookieParsingSurvivesExpiresDates(unittest.TestCase):
  """`requests` folds multiple Set-Cookie headers into one comma-joined string,
  and a bare `split(",")` cuts a lone `Expires=Wed, 21 Oct...` in half — the
  date fragment then produced a phantom "(unnamed cookie)" finding set.
  """

  def _scan(self, header):
    resp = MagicMock()
    resp.headers = {"Set-Cookie": header}
    resp.status_code = 200
    resp.text = ""
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      return _worker()._web_test_flags("example.com", 443)

  def test_an_expires_date_does_not_split_the_cookie(self):
    result = self._scan("sid=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/")
    names = {f["title"].rsplit(": ", 1)[-1] for f in result["findings"]}
    self.assertEqual(names, {"sid"}, "the Expires comma produced phantom cookies")

  def test_two_real_cookies_still_yield_two(self):
    result = self._scan("sid=abc; Path=/, theme=dark; Path=/")
    names = {f["title"].rsplit(": ", 1)[-1] for f in result["findings"]}
    self.assertEqual(names, {"sid", "theme"})


if __name__ == "__main__":
  unittest.main()
