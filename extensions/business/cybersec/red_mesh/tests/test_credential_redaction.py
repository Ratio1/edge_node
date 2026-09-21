"""
Direct unit tests for `credential_redaction` — the shared rule applied to
finding text, the LLM input and the SIEM egress boundary.

The module had no test of its own before RM-064's closeout; its behaviour was
pinned only indirectly through `_redact_report`.
"""

import unittest

from extensions.business.cybersec.red_mesh.credential_redaction import (
  CREDENTIAL_TEXT_FIELDS,
  redact_credential_text,
)


class TestProbePhrasings(unittest.TestCase):
  """Every string a default-credential probe emits, verbatim from the emitter."""

  # (text, secret) — the secret must not survive, the user half must.
  CASES = (
    # worker/service/common.py:480-482 (HTTP Basic)
    ("HTTP Basic Auth default credential: admin:hunter2", "hunter2"),
    ("GET http://t/adm with admin:hunter2 → HTTP 200", "hunter2"),
    # `("admin", "1234")` is in the default list (common.py:402); a
    # port-shaped secret after a lead is still a secret.
    ("GET http://t/adm with admin:1234 → HTTP 200", "1234"),
    ("HTTP Basic Auth default credential: admin:1234", "1234"),
    # common.py:755-757 (FTP), :945-947 (SSH), :1633-1635 (Telnet)
    ("FTP default credential accepted: ftpuser:s3cr3t", "s3cr3t"),
    ("Accepted credential: root:toor", "toor"),
    ("SSH default credential accepted: root:toor", "toor"),
    ("Telnet default credential accepted: admin:admin1", "admin1"),
    ("Root shell access via Telnet with root:toor.", "toor"),
    # worker/service/database.py:242-244 (MySQL)
    ("MySQL default credential accepted: root:mysqlpw", "mysqlpw"),
    ("MySQL on 10.0.0.5:3306 accepts root:mysqlpw.", "mysqlpw"),
    ("Auth response OK for root:mysqlpw", "mysqlpw"),
    # database.py:918 (PostgreSQL trust), :937-939 / :963-965 (cleartext, md5)
    ("Auth code 0 for postgres:postgres", "postgres:postgres"),
    ("PostgreSQL default credential accepted: postgres:pgpw", "pgpw"),
    ("Auth OK for postgres:pgpw", "pgpw"),
    # Secrets containing the terminators.
    ("Accepted credential: admin:P@ssw0rd.1", "P@ssw0rd.1"),
    ("Accepted credential: admin:p@$$:w0rd!", "p@$$:w0rd!"),
  )

  def test_secret_is_masked_and_user_kept(self):
    for text, secret in self.CASES:
      with self.subTest(text=text):
        out = redact_credential_text(text)
        self.assertNotIn(secret, out)
        self.assertIn(":***", out)

  def test_host_and_port_in_the_same_sentence_survive(self):
    out = redact_credential_text("MySQL on 10.0.0.5:3306 accepts root:mysqlpw.")
    self.assertIn("10.0.0.5:3306", out)
    self.assertEqual(out, "MySQL on 10.0.0.5:3306 accepts root:***.")


class TestGuards(unittest.TestCase):

  def test_urls_after_an_ambiguous_lead_are_left_intact(self):
    # Before the post-colon guard, `\bwith\s+` turned the URL into `https:***`.
    for text in (
      "Reachable with https://10.0.0.5:8443/admin exposed",
      "Reachable with http://10.0.0.5:8080/admin exposed",
      "Compared with https://app.test/x and https://app.test/y",
    ):
      with self.subTest(text=text):
        self.assertEqual(redact_credential_text(text), text)

  def test_every_pair_in_a_list_is_masked(self):
    # Each match needs its own lead, so the second and later pairs of a
    # comma-separated list used to survive.
    cases = (
      ("Weak credentials admin:admin, admin:password", ("password",)),
      ("Accepted credential: a:one, b:two; c:three and d:four",
       ("one", "two", "three", "four")),
    )
    for text, secrets in cases:
      with self.subTest(text=text):
        out = redact_credential_text(text)
        for secret in secrets:
          self.assertNotIn(secret, out)
    self.assertEqual(
      redact_credential_text("Weak credentials admin:admin, admin:password"),
      "Weak credentials admin:***, admin:***",
    )

  def test_a_list_separator_does_not_reach_into_unrelated_text(self):
    # The continuation lead is the mask plus a separator; a following clause
    # with a host:port is not a credential.
    out = redact_credential_text("Accepted credential: root:toor, then on host.test:22 the banner")
    self.assertNotIn("toor", out)
    self.assertIn("host.test:22", out)

  def test_non_strings_pass_through(self):
    for value in (None, 7, ["a:b"], {"k": "v"}):
      with self.subTest(value=value):
        self.assertIs(redact_credential_text(value), value)

  def test_text_fields_list_covers_the_probe_prose_fields(self):
    self.assertEqual(
      set(CREDENTIAL_TEXT_FIELDS),
      {"title", "description", "remediation", "evidence", "error"},
    )


if __name__ == "__main__":
  unittest.main()
