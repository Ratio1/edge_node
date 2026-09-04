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

    grown, _ = scan(1201)
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
  """Ratchet: a volatile value reaching a hashed finding field fails here.

  Three fields, two tiers. A *raw observed value* (banner, cookie, response
  bytes) is barred from `evidence`, `title` and `description` alike. A
  *per-scan magnitude* (a count, a length, an age) is barred from `evidence`
  and `title` but allowed in `description`, which feeds `content_hash` without
  feeding `dedup_key`.

  Line-based and deliberately approximate. Known gaps, none currently live:
  continuation lines, single-quoted f-strings, `.format()`, `%`, concatenation,
  and an f-string bound to a local then passed by name. The name vocabulary is
  a denylist, so `{tokens}` and `{csrf_token}` slip the identifier boundaries.
  It catches the single-line form every current producer uses; it is a ratchet,
  not a proof.

  An allowlist entry is a verified false positive or documented debt. It needs
  a justification and an owner, not a silent add, and the shrink test below
  requires the line it names to still exist.
  """

  # Raw observed values. These belong in `raw_data` and in no hashed field at
  # all — not evidence, not title, not description.
  _VOLATILE = (
    "banner", "location", "cookie", "readable", "token", "resp.text", "data",
  )
  # Per-scan magnitudes. Barred from `evidence` and `title`, but permitted in
  # `description`: that is the destination this batch chose for them, and
  # `description` feeds `content_hash` (change detection) without feeding
  # `dedup_key` (identity). A count that moves is a change worth detecting.
  _VOLATILE_PREFIXES = ("len_", "len(")
  _VOLATILE_SUFFIXES = ("_count", "count}")
  # Magnitudes the `len(`/`count` shapes miss, each having reached a title in
  # the tree: `uptime_seconds` advances once per second, `tested` varies when a
  # probe loop breaks early, `age_days` moves at midnight. Same tier as the
  # counts — out of evidence and title, fine in description. The vocabulary is
  # a denylist and is known incomplete: `{tokens}` and `{csrf_token}` still
  # slip the identifier boundaries below.

  # Empty by design: every previously-exempt site was fixed 2026-09-03
  # (closeout plan, Phase 3). A new entry here is debt being taken on — it
  # needs a justification comment and a burn-down owner, not a silent add.
  _ALLOWLIST = {
    # Verified false positive, 2026-09-04: flagged on the *name* `banner`, but
    # `raw["banner"]` in `_service_info_smb` is one of four deterministic
    # strings (infrastructure.py :846/:865/:915/:925), the last being the
    # 4-byte protocol id — constant per server. Keeping it is what
    # distinguishes SMBv1 from SMBv2 from unknown in the finding itself.
    # Owner: RM-062. Removable only by making the predicate value-aware.
    ("service/infrastructure.py",
     'evidence=f"Banner: {raw.get(\'banner\', \'N/A\')}",'),
  }

  @staticmethod
  def _named(name, token):
    import re
    # Identifier boundaries: `cookie` must flag `{cookie.strip()}` and
    # `{cookie}` but not `{cookie_name}` — the cookie's *name* is stable data,
    # its value is the secret. `search`, not `match`: anchoring at the start of
    # the expression made every subscript form invisible, so
    # `{raw['banner'][:80]}` slipped past while `{banner}` was caught.
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", name)

  def _has_raw_value(self, line):
    """Raw observed values — barred from every hashed field."""
    for chunk in line.split("{")[1:]:
      name = chunk.split("}")[0]
      if any(self._named(name, v) for v in self._VOLATILE):
        return True
    return False

  def _has_magnitude(self, line):
    """Per-scan counts and sizes — barred from `evidence` and `title` only."""
    import re

    for chunk in line.split("{")[1:]:
      name = chunk.split("}")[0]
      if any(name.startswith(v) for v in self._VOLATILE_PREFIXES):
        return True
      if re.search(r"(?<![A-Za-z0-9_])[a-z_]*count(?![A-Za-z0-9_])", name):
        return True
      if any(self._named(name, v) for v in ("uptime_seconds", "tested", "age_days")):
        return True
    return False

  def _is_volatile(self, line):
    return self._has_raw_value(line) or self._has_magnitude(line)

  # `evidence` and `description` are both in `_CONTENT_FIELDS`, so both feed
  # `content_hash`. `title` is worse than either: it is `dedup_key`'s
  # discriminator for any finding with no scenario id and no specific location,
  # which under worker/ is all of them, so a volatile value there re-keys the
  # finding and detaches its persisted triage.
  _GUARDED_FIELDS = ("evidence", "title")
  # Checked for raw values only — counts are deliberately allowed here.
  _RAW_VALUE_ONLY_FIELDS = ("description",)

  def _line_is_offending(self, stripped):
    """The per-line decision, separated so the field wiring is testable without
    a live offender in the tree to demonstrate it."""
    if any(f'{field}=f"' in stripped for field in self._GUARDED_FIELDS):
      return self._is_volatile(stripped)
    if any(f'{field}=f"' in stripped for field in self._RAW_VALUE_ONLY_FIELDS):
      return self._has_raw_value(stripped)
    return False

  def _offenders(self):
    import pathlib

    worker_dir = pathlib.Path(__file__).resolve().parent.parent / "worker"
    offenders = []
    for path in sorted(worker_dir.rglob("*.py")):
      rel = str(path.relative_to(worker_dir))
      for nr, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if not self._line_is_offending(stripped):
          continue
        if (rel, stripped) in self._ALLOWLIST:
          continue
        offenders.append(f"{rel}:{nr}: {stripped}")
    return offenders

  def test_worker_evidence_does_not_interpolate_per_request_data(self):
    offenders = self._offenders()
    self.assertEqual(
      offenders, [],
      "per-request data reached `evidence` or `title`. In `evidence` it breaks "
      "cross-worker dedup and can archive secrets; in `title` it re-keys the "
      "finding every scan and detaches its triage. Put the stable fact in the "
      "field and the volatile observation in raw_data/evidence_items, or state "
      "the count in the description.",
    )

  def test_the_ratchet_sees_subscripts_and_titles(self):
    """The two shapes this guard was blind to until 2026-09-04, each of which
    had a live offender in the tree at the time."""
    self.assertTrue(
      self._is_volatile("""evidence=f"stats returned: {raw['banner'][:80]}","""),
      "a subscripted volatile is invisible — `re.match` anchors at the start",
    )
    self.assertTrue(
      self._is_volatile('title=f"Redis database contains {count} keys",'),
      "a per-scan count in a title is invisible",
    )
    # The deliberate exemption must survive: a cookie's *name* is stable data.
    self.assertFalse(
      self._is_volatile('evidence=f"Cookie {cookie_name} lacks the Secure flag",'),
    )

  def test_counts_are_barred_from_evidence_and_title_but_allowed_in_description(self):
    """`description` is hashed into `content_hash` but is not part of
    `dedup_key`, so it is where a per-scan magnitude belongs — that is the
    destination this batch moved 14 counts to. A raw observed value is barred
    from all three."""
    count_line = 'description=f"Holding {count} keys.",'
    self.assertTrue(self._has_magnitude(count_line))
    self.assertFalse(self._has_raw_value(count_line))

    raw_line = 'description=f"Expected a banner, got: {banner[:80]}",'
    self.assertTrue(self._has_raw_value(raw_line))
    # The wiring, not just the predicates: a raw value in a description is
    # reported, a count in one is not, and both rules bite in evidence/title.
    self.assertTrue(self._line_is_offending(raw_line))
    self.assertFalse(self._line_is_offending(count_line))
    self.assertTrue(self._line_is_offending('evidence=f"Holding {count} keys.",'))
    self.assertTrue(self._line_is_offending('title=f"Holding {count} keys",'))

    # The three magnitudes the len()/count shapes do not match.
    for name in ("uptime_seconds", "tested", "age_days"):
      self.assertTrue(
        self._has_magnitude(f'title=f"x {{{name}}} y",'), name,
      )
      self.assertFalse(self._has_raw_value(f'title=f"x {{{name}}} y",'), name)

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
