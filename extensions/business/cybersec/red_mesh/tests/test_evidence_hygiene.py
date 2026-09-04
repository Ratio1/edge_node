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
  """Ratchet: a value that moves between observations must not reach a hashed
  finding field.

  There are **two** dedup paths and both matter. `finding_identity.dedup_key`
  is the identity key and reads title (as the locationless discriminator), not
  description. `mixins/report._finding_dedup_key` is a whole-dict JSON key that
  strips only worker-attribution fields, so `evidence`, `title` **and
  `description` are all load-bearing** for the cross-worker collapse. An
  earlier version of this guard claimed description "feeds content_hash without
  feeding dedup_key" and concluded magnitudes were safe there. That was wrong:
  two workers a second apart still produced two report rows.

  So the tiers are about *what the value does*, not what field it lands in:

  - `_VOLATILE` / `_OBSERVATION_VARYING`: differs between two observations of
    one target — raw bytes, timestamps, uptimes, ages, per-connection entropy.
    Barred from evidence, title and description alike.
  - magnitudes (`len(...)`, `*count`): barred from evidence and title. Allowed
    in `description` only when the value is *target-stable* — the same from
    every worker, like "9 databases exist". That is a judgement this lint
    cannot make; a count that can move between observations belongs in the
    tier above and in `raw_data`.

  Line-based and deliberately approximate. Known gaps: continuation lines,
  single-quoted f-strings, `.format()`, `%`, concatenation, and an f-string
  bound to a local then passed by name. The name vocabulary is a denylist, so
  volatile locals it has never seen slip through. It is a ratchet, not a proof.

  An allowlist entry is a verified false positive or documented debt. It needs
  a justification and an owner, and the shrink test below requires the line it
  names to still be reported by the predicate.
  """

  # Values that differ between two observations of one target. Barred from
  # every hashed field: evidence, title and description.
  _VOLATILE = (
    "banner", "location", "cookie", "readable", "token", "resp.text", "data",
  )
  # Same tier, found the hard way — each of these reached a hashed field and
  # forked a finding: `uptime_seconds` moves every second, `age_days` and
  # `days` at midnight, `tested` and `consecutive_401` when a probe loop breaks
  # early, `entropy`/`full_salt` are per-connection.
  _OBSERVATION_VARYING = (
    "uptime_seconds", "age_days", "tested", "consecutive_401",
    "entropy", "full_salt", "elapsed",
    # Deliberately NOT a bare "days": `span.days` at tls.py is
    # notAfter - notBefore, a property of the certificate and stable across
    # observations, so flagging it would be a false positive.
  )
  # Verified false positives and documented debt. Keyed on (path, line number,
  # exact line): the line number stops an entry leaking to an identical line
  # elsewhere in the same file — `infrastructure.py` has 18 `raw["banner"]`
  # sites and several do carry per-connection bytes. The shrink test below
  # requires each entry to still be reported by the predicate, so an entry
  # whose site was fixed fails rather than lingering.
  _ALLOWLIST = {
    # 2026-09-04, owner RM-062: flagged on the *name* `banner`, but
    # `raw["banner"]` in `_service_info_smb` is one of two reachable
    # deterministic strings at this site (infrastructure.py :915/:925 — :846
    # returns early and :865 makes `findings` non-empty). The last is the
    # 4-byte protocol prefix, constant per server. Keeping it is what
    # distinguishes SMBv1 from SMBv2 from unknown in the finding itself.
    # Removable only by making the predicate value-aware.
    ("service/infrastructure.py", 1002,
     'evidence=f"Banner: {raw.get(\'banner\', \'N/A\')}",'),
  }

  # Magnitudes. Barred from evidence and title; allowed in description when the
  # value is target-stable (see the class docstring).
  _MAGNITUDE_PREFIXES = ("len_", "len(")

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
      if any(self._named(name, v) for v in self._OBSERVATION_VARYING):
        return True
    return False

  def _has_magnitude(self, line):
    """Per-scan counts and sizes — barred from `evidence` and `title` only."""
    import re

    for chunk in line.split("{")[1:]:
      name = chunk.split("}")[0]
      if any(name.startswith(v) for v in self._MAGNITUDE_PREFIXES):
        return True
      if re.search(r"(?<![A-Za-z0-9_])(?:[a-z]+_)*count(?![A-Za-z0-9_])", name):
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
        if (rel, nr, stripped) in self._ALLOWLIST:
          continue
        offenders.append(f"{rel}:{nr}: {stripped}")
    return offenders

  def test_worker_evidence_does_not_interpolate_per_request_data(self):
    offenders = self._offenders()
    self.assertEqual(
      offenders, [],
      "a moving value reached a hashed finding field. `evidence`, `title` and "
      "`description` all feed the report layer's cross-worker dedup key, and "
      "`title` additionally feeds identity, so a value there re-keys the "
      "finding and detaches its triage. State the stable fact in the field and "
      "put the observation in raw_data/evidence_items. A count belongs in the "
      "description only if every worker sees the same number.",
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

  def test_a_moving_value_is_barred_from_every_hashed_field(self):
    """`description` is in the report layer's whole-dict dedup key just as
    `evidence` is, so a value that moves between observations forks the finding
    there too. An earlier version of this guard allowed magnitudes in
    `description` on the belief that it only fed change detection."""
    for field in ("evidence", "title", "description"):
      for name in ("banner[:80]", "uptime_seconds", "age_days", "tested",
                   "consecutive_401", "entropy:.2f", "elapsed:.1f"):
        line = f'{field}=f"x {{{name}}} y",'
        self.assertTrue(self._has_raw_value(line), line)
        self.assertTrue(self._line_is_offending(line), line)

  def test_a_target_stable_count_is_allowed_only_in_the_description(self):
    """A count every worker sees identically does not fork the dedup key, and
    the description is where this batch put them. It stays barred from
    `evidence` and `title`, which also feed identity."""
    self.assertFalse(self._line_is_offending('description=f"Holding {len(dbs)} databases.",'))
    self.assertTrue(self._line_is_offending('evidence=f"Holding {len(dbs)} databases.",'))
    self.assertTrue(self._line_is_offending('title=f"Holding {len(dbs)} databases",'))

  def test_the_count_rule_does_not_fire_on_ordinary_english(self):
    """`[a-z_]*count` matched `account` and `discount` by backtracking, so an
    account-related finding could not be written without an allowlist entry."""
    for benign in ("account", "discount"):
      self.assertFalse(
        self._line_is_offending(f'title=f"Weak password for {{{benign}}}",'), benign,
      )

  def test_a_certificate_property_is_not_treated_as_moving(self):
    """`span.days` is notAfter - notBefore. It is stable across observations,
    and a change to it means a different certificate — which should be a
    different finding. Flagging it would be a false positive."""
    self.assertFalse(
      self._line_is_offending('title=f"validity span exceeds 5 years ({span.days} days)",'),
    )

  def test_the_allowlist_only_shrinks(self):
    """Every entry must still name a live line *that the predicate still
    reports*. Existence alone is not enough: an entry naming some ordinary line
    would sit there forever exempting nothing, and an entry whose site was
    fixed would linger. Either way the list becomes a graveyard nobody trusts."""
    import pathlib

    worker_dir = pathlib.Path(__file__).resolve().parent.parent / "worker"
    live = {}
    for path in sorted(worker_dir.rglob("*.py")):
      rel = str(path.relative_to(worker_dir))
      for nr, line in enumerate(path.read_text().splitlines(), 1):
        live[(rel, nr)] = line.strip()

    stale = []
    for entry in self._ALLOWLIST:
      rel, nr, text = entry
      if live.get((rel, nr)) != text:
        stale.append(f"{rel}:{nr} no longer holds that line")
      elif not self._line_is_offending(text):
        stale.append(f"{rel}:{nr} is no longer flagged — drop the entry")
    self.assertEqual(stale, [], "allowlist entries that no longer earn their place")


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
