"""RM-103 item 0: a finding's identity never reads an accepted secret.

A client verification job (2026-09-24) published the `finding_id` of
"SSH default credential accepted: admin:<password>". Both identity keys were
stamped at probe time over the unredacted title, and every other input to the
key is printed in the export, so hashing the default-credential list against
the published id recovered the password. The same defect gave the finding a
new id whenever the honeypot accepted a different password.

Contract pinned here: for every producer that interpolates a credential pair,
`finding_id` and `finding_signature` depend on the username and not on the
secret, including a blank secret printed as `(empty)`.
"""

import unittest

from extensions.business.cybersec.red_mesh.credential_redaction import (
  redact_credential_text,
)
from extensions.business.cybersec.red_mesh.findings import (
  Finding, Severity, probe_result,
)
from extensions.business.cybersec.red_mesh.models.finding_identity import (
  content_hash,
  dedup_key,
)
from extensions.business.cybersec.red_mesh.worker.service.common import (
  _FTP_DEFAULT_CREDS,
  _SSH_DEFAULT_CREDS,
  _TELNET_DEFAULT_CREDS,
)


def _cred(user, password):
  """The pair as every producer prints it: a blank secret reads `(empty)`."""
  return f"{user}:{password}" if password else f"{user}:(empty)"


# (probe, port, title, description, evidence) per producer, exactly as the
# probes format them. `{c}` is the pair, `{u}` the username.
PRODUCERS = {
  "ssh": ("_service_info_ssh", 22,
          "SSH default credential accepted: {c}",
          "The SSH server accepted a well-known default credential.",
          "Accepted credential: {c}; authenticated action: uid=0(root)"),
  "ftp": ("_service_info_ftp", 21,
          "FTP default credential accepted: {c}",
          "The FTP server accepted a well-known default credential.",
          "Accepted credential: {c}"),
  "telnet_root": ("_service_info_telnet", 23,
                  "Root shell access via Telnet with {c}.",
                  "Root shell.",
                  "uid=0 in id output: uid=0(root)"),
  "http_basic": ("_service_info_http_basic_auth", 80,
                 "HTTP Basic Auth default credential: {c}",
                 "The web server at http://h/admin (realm: r) accepted a default credential.",
                 "GET http://h/admin with {c} → HTTP 200"),
  "mysql": ("_service_info_mysql_creds", 3306,
            "MySQL default credential accepted: {c}",
            "MySQL on 10.0.0.5:3306 accepts {c}.",
            "Auth response OK for {c}"),
  "postgres_trust": ("_service_info_postgresql_creds", 5432,
                     "PostgreSQL trust auth for {u}",
                     "No password required for user {u}.",
                     "Auth code 0 for {c}"),
  "postgres_password": ("_service_info_postgresql_creds", 5432,
                        "PostgreSQL default credential accepted: {c}",
                        "Cleartext password auth accepted for {c}.",
                        "Auth OK for {c}"),
}

SECRETS = ("admin", "S3cret!", "P@ssw0rd.1", "1234", "")


def _finding(producer, user, password):
  probe, port, title, description, evidence = PRODUCERS[producer]
  c = _cred(user, password)
  return {
    "probe": probe, "port": port,
    "title": title.format(c=c, u=user),
    "description": description.format(c=c, u=user),
    "evidence": evidence.format(c=c, u=user),
    "remediation": "Change default passwords.",
    "severity": "CRITICAL", "confidence": "firm",
    "owasp_id": "A07:2021", "cwe_id": "CWE-798",
    "affected_assets": [],
  }


class TestIdentityDoesNotReadTheSecret(unittest.TestCase):

  def test_only_the_secret_changed_means_the_same_finding(self):
    for producer in PRODUCERS:
      ids = {dedup_key(_finding(producer, "admin", s)) for s in SECRETS}
      sigs = {content_hash(_finding(producer, "admin", s)) for s in SECRETS}
      with self.subTest(producer=producer):
        self.assertEqual(len(ids), 1, "finding_id moved with the secret")
        self.assertEqual(len(sigs), 1, "finding_signature moved with the secret")

  def test_a_different_username_is_a_different_finding(self):
    for producer in PRODUCERS:
      with self.subTest(producer=producer):
        self.assertNotEqual(
          dedup_key(_finding(producer, "admin", "admin")),
          dedup_key(_finding(producer, "root", "admin")),
        )

  def test_the_default_lists_cannot_be_distinguished_through_the_id(self):
    # The offline recovery that worked on that job: hash each candidate and
    # compare with the published id. Every candidate for one user must now
    # produce the same id, so the comparison carries no information.
    candidates = {
      p for _u, p in _SSH_DEFAULT_CREDS + _FTP_DEFAULT_CREDS + _TELNET_DEFAULT_CREDS
    } | {"", "1234", "tomcat", "manager", "guest"}
    for producer in PRODUCERS:
      with self.subTest(producer=producer):
        self.assertEqual(
          len({dedup_key(_finding(producer, "admin", p)) for p in candidates}), 1,
        )
        self.assertEqual(
          len({content_hash(_finding(producer, "admin", p)) for p in candidates}), 1,
        )

  def test_the_probe_stamped_keys_do_not_read_the_secret(self):
    # The real stamping path, not just the pure functions.
    def stamp(password):
      out = probe_result(
        findings=[Finding(
          severity=Severity.CRITICAL,
          title=f"SSH default credential accepted: {_cred('admin', password)}",
          description="The SSH server accepted a well-known default credential.",
          evidence=f"Accepted credential: {_cred('admin', password)}",
          owasp_id="A07:2021", cwe_id="CWE-798",
        )],
        probe_id="_service_info_ssh",
      )
      f = out["findings"][0]
      return f["finding_id"], f["finding_signature"]

    self.assertEqual(stamp("admin"), stamp("password"))
    self.assertEqual(stamp("admin"), stamp(""))


class TestTheBlankSecretIsASecret(unittest.TestCase):

  def test_empty_is_masked_like_any_other_secret(self):
    for text, expected in (
      ("HTTP Basic Auth default credential: admin:(empty)",
       "HTTP Basic Auth default credential: admin:***"),
      ("MySQL default credential accepted: root:(empty)",
       "MySQL default credential accepted: root:***"),
      ("Auth code 0 for postgres:(empty)", "Auth code 0 for postgres:***"),
      ("Cleartext password auth accepted for postgres:(empty).",
       "Cleartext password auth accepted for postgres:***."),
      ("GET http://h/admin with admin:(empty) → HTTP 200",
       "GET http://h/admin with admin:*** → HTTP 200"),
    ):
      with self.subTest(text=text):
        self.assertEqual(redact_credential_text(text), expected)

  def test_redaction_is_idempotent_on_every_producer_wording(self):
    for producer in PRODUCERS:
      for secret in SECRETS:
        f = _finding(producer, "admin", secret)
        for field in ("title", "description", "evidence"):
          once = redact_credential_text(f[field])
          with self.subTest(producer=producer, secret=secret, field=field):
            self.assertEqual(redact_credential_text(once), once)
            # The pair, not the bare secret: `admin` is also the username,
            # which is meant to survive.
            self.assertNotIn(_cred("admin", secret), once)


class TestNonCredentialIdentityIsUnchanged(unittest.TestCase):
  """Values computed on develop fb060643, before this change.

  The client diffs ids between runs; the id change in this release must be
  confined to findings that carry a credential.
  """

  PINNED = {
    "hsts": ({"probe": "_web_test_security_headers", "port": 443,
              "title": "Missing Strict-Transport-Security header",
              "description": "HSTS not set.",
              "evidence": "GET / -> no Strict-Transport-Security",
              "severity": "MEDIUM", "owasp_id": "A05:2021", "cwe_id": "CWE-319",
              "affected_assets": []},
             "b2e0793cbb18bc67",
             "df5c8ce310be7c22521c303913a8baded6abe5a25e01a0fde96f6aa92092a34f"),
    "idor": ({"probe": "_graybox_access_control", "scenario_id": "PT-A01-01",
              "port": 443, "title": "IDOR", "severity": "HIGH",
              "owasp_id": "A01:2021", "cwe_id": "CWE-639",
              "affected_assets": [{"host": "app.test", "port": 443,
                                   "url": "https://app.test/api/records/99",
                                   "parameter": "id", "method": "GET"}]},
             "58e08b70d792bf59",
             "d21cf3e4439f232b2a486154e8cae49b2722b3771bc371654a7e12ce771fe6e2"),
    "ssh_weak_kex": ({"probe": "_service_info_ssh", "port": 22,
                      "title": "SSH weak key exchange: diffie-hellman-group1-sha1",
                      "description": "Legacy KEX offered.",
                      "evidence": "kex_algorithms: diffie-hellman-group1-sha1",
                      "severity": "LOW", "owasp_id": "A02:2021", "cwe_id": "CWE-327",
                      "affected_assets": []},
                     "8b8d7fec6a9ecdcb",
                     "acffbbc987a8bbca3a418ce1ea248aa2d8687a2d719194cd529741f40a52b57b"),
  }

  def test_pinned_ids_and_signatures_do_not_move(self):
    for name, (finding, fid, sig) in self.PINNED.items():
      with self.subTest(finding=name):
        self.assertEqual(dedup_key(finding), fid)
        self.assertEqual(content_hash(finding), sig)

  def test_the_one_non_credential_signature_that_moves_keeps_its_id(self):
    # `worker/service/common.py` HTTP Host-drop evidence reads `with Host:<target>`,
    # which the rule masks. Measured on fb060643: id da836ede9c8b1092, signature
    # 4f2bce20…0615. The id must not move; the signature moves once (disclosed).
    finding = {
      "probe": "_service_info_http", "port": 8080,
      "title": "HTTP service drops requests with Host header",
      "description": "TCP port 8080 returns empty replies for standard HTTP/1.1 requests "
                     "but responds to HTTP/1.0 without a Host header. This indicates a "
                     "server_name mismatch or intentional filtering.",
      "evidence": "HTTP/1.1 with Host:10.0.0.5 → empty reply; HTTP/1.0 without Host → nginx",
      "remediation": "Configure a proper default server block or virtual host.",
      "severity": "INFO", "confidence": "certain", "cwe_id": "CWE-200", "affected_assets": [],
    }
    self.assertEqual(dedup_key(finding), "da836ede9c8b1092")
    self.assertEqual(
      content_hash(finding),
      "b28bfc4e92e12258381bbe633cd9b3228783a8ed78f4b0959a392f92c6ccbc39",
    )

  def test_two_passwords_for_one_user_are_one_finding(self):
    # Owner decision 2026-09-26: identity is protocol + port + username. Two
    # accepted passwords for `root` on one port collapse into one finding with
    # one id and one signature; the pairs stay in `accepted_credentials`.
    a = _finding("ssh", "root", "toor")
    b = _finding("ssh", "root", "password")
    self.assertEqual(dedup_key(a), dedup_key(b))
    self.assertEqual(content_hash(a), content_hash(b))


if __name__ == "__main__":
  unittest.main()
