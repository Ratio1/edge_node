"""RM-134 phase 1: the super-tenant branding through the real plugin endpoints, service and adapters."""
import base64
import copy
import hashlib
import struct
import unittest
from unittest.mock import patch
from uuid import uuid4

from .contract_fixture import CONTRACT_PDF, FakeDocumentStore, contract_b64
from .test_tenant_administration import FakeAdministrationStore
from .test_tenant_drafts import TENANCY_HKEY, ok, refused

BRANDING_KEY = (TENANCY_HKEY, '["super_tenant_branding","deployment","deployment"]')
EMPTY = {"theme": "dark", "logo": None}


def png(width=300, height=80, size=2048):
  """A PNG header with an IHDR of the given size, padded to `size` bytes (the sniffer and the
  dimension parse read the first 24)."""
  head = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
  return head + b"\x00" * (size - len(head))


def jpeg(width=400, height=100):
  return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
          + b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", height, width) + b"\x03" + b"\x00" * 9 + b"\xff\xd9")


def upload(raw, filename="logo.png"):
  return {"filename": filename, "content_b64": base64.b64encode(raw).decode("ascii")}


class _BrandingCase(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.store.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.store.account("scoped-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": "tn_" + str(uuid4())}])
    self.documents = FakeDocumentStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.P = lambda *args, **kwargs: None
    self.plugin._document_store = lambda: self.documents
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}
    # A tenant member: an active account without a platform role.
    self.member = {"account_id": "initial"}

  def get(self, actor=None):
    return self.plugin.get_super_tenant_branding(actor or self.actor)

  def update(self, changes, actor=None):
    return self.plugin.update_super_tenant_branding(actor or self.actor, changes)

  def download(self, actor=None):
    return self.plugin.download_super_tenant_branding_logo(actor or self.actor)


class TestBrandingRecord(_BrandingCase):
  def test_the_default_branding_is_answered_to_any_active_account_without_a_write(self):
    for actor in (self.actor, self.member, {"account_id": "pentester"}):
      with self.subTest(actor=actor["account_id"]):
        self.assertEqual(ok(self, self.get(actor)), EMPTY)
    self.assertEqual((self.store.writes, self.events), ([], []))
    refused(self, self.download(self.member), 404, "not_found")

  def test_unknown_and_no_actor_are_refused(self):
    for actor in ({"account_id": "nobody"}, None):
      with self.subTest(actor=actor):
        self.assertEqual(self.plugin.get_super_tenant_branding(actor)["status_code"], 404)

  def test_a_theme_is_written_attributed_audited_by_key_and_read_by_a_tenant_member(self):
    self.assertEqual(ok(self, self.update({"theme": "navy"})), {"theme": "navy", "logo": None})
    row = self.store.data[BRANDING_KEY]
    self.assertEqual((row["kind"], row["ids"], row["updated_by"]), ("super_tenant_branding", ["deployment"], "creator"))
    self.assertEqual(self.events, [("super_tenant_branding_updated", {"actor": "creator", "changed": ["theme"]})])
    self.assertEqual(ok(self, self.get(self.member))["theme"], "navy")
    # The same theme again writes and audits nothing.
    writes = len(self.store.writes)
    ok(self, self.update({"theme": "navy"}))
    self.assertEqual((len(self.store.writes), len(self.events)), (writes, 1))
    for theme in ("midnight", "dark", "umber", "light"):
      self.assertEqual(ok(self, self.update({"theme": theme}))["theme"], theme)

  def test_malformed_changes_are_refused_without_a_write_or_a_file(self):
    cases = {"not a dict": None, "empty": {}, "unknown key": {"color": "red"}, "unknown theme": {"theme": "pink"},
             "theme type": {"theme": 3}, "logo as a ref": {"logo": {"ref": "doc-1"}},
             "logo string": {"logo": "x"}, "logo extra key": {"logo": {**upload(png()), "mime": "image/png"}}}
    for label, changes in cases.items():
      with self.subTest(label):
        refused(self, self.update(changes), 400, "invalid_request")
    self.assertEqual((self.store.writes, self.documents.puts, self.events), ([], [], []))


class TestBrandingLogo(_BrandingCase):
  def test_a_png_is_stored_bound_by_hash_and_downloaded_by_a_tenant_member(self):
    raw = png(size=300 * 1024)
    data = ok(self, self.update({"logo": upload(raw), "theme": "navy"}))
    sha = hashlib.sha256(raw).hexdigest()
    self.assertEqual(data, {"theme": "navy", "logo": {"sha256": sha, "mime": "image/png", "size_bytes": len(raw)}})
    envelope = self.documents.puts[0]
    self.assertEqual((envelope["kind"], envelope["document_kind"]), ("redmesh_tenant_contract", "branding_logo"))
    self.assertNotIn("draft_id", envelope)
    self.assertEqual(self.events, [("super_tenant_branding_updated", {"actor": "creator", "changed": ["logo", "theme"]})])
    # The member's read names the logo by hash only, never its reference or filename.
    self.assertEqual(ok(self, self.get(self.member)), data)
    got = ok(self, self.download(self.member))
    self.assertEqual(set(got), {"mime", "sha256", "content_b64"})
    self.assertEqual(hashlib.sha256(base64.b64decode(got["content_b64"])).hexdigest(), sha)

  def test_a_jpeg_is_accepted(self):
    self.assertEqual(ok(self, self.update({"logo": upload(jpeg(), "logo.jpg")}))["logo"]["mime"], "image/jpeg")

  def test_a_jpeg_with_its_tables_before_the_frame_header_is_accepted(self):
    # DQT and DHT before SOF0 is a legal layout some encoders write; DHT (0xC4) is not a frame coding.
    raw = jpeg()
    tables = b"\xff\xdb\x00\x43\x00" + b"\x01" * 64 + b"\xff\xc4\x00\x14\x00" + b"\x00" * 17
    at = raw.index(b"\xff\xc0")
    data = ok(self, self.update({"logo": upload(raw[:at] + tables + raw[at:], "logo.jpg")}))
    self.assertEqual(data["logo"]["mime"], "image/jpeg")

  def test_bad_logos_are_refused_logo_invalid_and_leave_no_file(self):
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    cases = {"2.5 MB": png(size=2560 * 1024), "4000x600": png(4000, 600), "2048x513": png(2048, 513),
             "zero width": png(0, 10), "svg": svg, "pdf": CONTRACT_PDF, "truncated png": png()[:20],
             "lossless jpeg (SOF3)": jpeg().replace(b"\xff\xc0", b"\xff\xc3")}
    for label, raw in cases.items():
      with self.subTest(label):
        refused(self, self.update({"logo": upload(raw)}), 400, "logo_invalid")
    refused(self, self.update({"logo": {"filename": "x.png", "content_b64": "%%%"}}), 400, "logo_invalid")
    self.assertEqual((self.documents.puts, self.store.writes, self.events), ([], [], []))

  def test_the_largest_accepted_logo(self):
    ok(self, self.update({"logo": upload(png(2048, 512, size=2 * 1024 * 1024))}))

  def test_replace_and_remove_delete_the_old_file_after_the_write(self):
    ok(self, self.update({"logo": upload(png(size=1000))}))
    ok(self, self.update({"logo": upload(png(size=2000))}))
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(ok(self, self.get())["logo"]["size_bytes"], 2000)
    self.assertEqual(ok(self, self.update({"logo": None})), EMPTY)
    self.assertEqual(self.documents.deleted, ["doc-1", "doc-2"])
    refused(self, self.download(), 404, "not_found")
    # Removing when nothing is set changes nothing.
    events = len(self.events)
    ok(self, self.update({"logo": None}))
    self.assertEqual((self.documents.deleted, len(self.events)), (["doc-1", "doc-2"], events))

  def test_a_bind_refused_after_the_store_deletes_the_new_file(self):
    ok(self, self.update({"logo": upload(png())}))
    before = copy.deepcopy(self.store.data)
    # The theme is checked under the lock, after the file was stored.
    refused(self, self.update({"logo": upload(png(size=4096)), "theme": "pink"}), 400, "invalid_request")
    self.assertEqual(self.documents.deleted, ["doc-2"])
    self.assertEqual(self.store.data, before)

  def test_a_failed_delete_is_logged_and_the_write_stands(self):
    ok(self, self.update({"logo": upload(png())}))
    self.documents.fail_delete.add("doc-1")
    self.assertEqual(ok(self, self.update({"logo": upload(png(size=4096))}))["logo"]["size_bytes"], 4096)
    self.assertIn("doc-1", self.documents.envelopes)

  def test_a_tampered_file_answers_integrity_and_a_lost_one_not_found(self):
    ok(self, self.update({"logo": upload(png())}))
    self.documents.envelopes["doc-1"]["content_b64"] = base64.b64encode(png(size=4096)).decode("ascii")
    refused(self, self.download(), 409, "contract_integrity")
    self.documents.envelopes["doc-1"]["document_kind"] = "contract"
    refused(self, self.download(), 409, "contract_integrity")
    del self.documents.envelopes["doc-1"]
    refused(self, self.download(), 404, "not_found")
    self.documents.fail = True
    refused(self, self.download(), 503, "unavailable")

  def test_a_logo_envelope_never_resolves_as_a_contract_and_a_contract_still_refuses_a_png(self):
    from extensions.business.cybersec.red_mesh.services.tenant_contract import (
      ContractRefused, resolve_contract, store_contract)
    ok(self, self.update({"logo": upload(png())}))
    with self.assertRaises(ContractRefused) as caught:
      resolve_contract(self.documents, "doc-1")
    self.assertEqual(caught.exception.error, "contract_invalid")
    with self.assertRaises(ContractRefused) as caught:
      store_contract(self.documents, filename="c.png", content_b64=upload(png())["content_b64"], uploaded_by="creator")
    self.assertEqual(caught.exception.error, "bad_mime")
    self.assertEqual(store_contract(self.documents, filename="c.pdf", content_b64=contract_b64(),
                                    uploaded_by="creator")["mime"], "application/pdf")


class TestBrandingGates(_BrandingCase):
  def test_only_a_full_portfolio_super_tenant_admin_writes_and_no_file_is_stored_first(self):
    actors = {"tenant member": self.member, "super pentester": {"account_id": "pentester"},
              "tenant-scoped STA": {"account_id": "scoped-sta"}, "unknown": {"account_id": "nobody"}, "no actor": None}
    for label, actor in actors.items():
      with self.subTest(label):
        result = self.plugin.update_super_tenant_branding(actor, {"logo": upload(png()), "theme": "navy"})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 403 if label in ("tenant member", "super pentester") else 404)
    self.assertEqual((self.documents.puts, self.store.writes, self.events), ([], [], []))

  def test_a_locked_deployment_refuses_branding_locked_before_any_file_and_still_reads(self):
    ok(self, self.update({"theme": "umber"}))
    before = copy.deepcopy(self.store.data)
    self.plugin.cfg_super_tenant_permissions = {"edit_branding": False}
    for changes in ({"theme": "navy"}, {"logo": upload(png())}, {"logo": None}):
      with self.subTest(changes=list(changes)):
        refused(self, self.update(changes), 403, "branding_locked")
    self.assertEqual((self.documents.puts, self.store.data), ([], before))
    self.assertEqual(ok(self, self.get(self.member))["theme"], "umber")
    profile = ok(self, self.plugin.get_super_tenant_profile(self.actor))
    self.assertEqual(profile["permissions"], {"edit_company_details": True, "edit_branding": False})
    # The company-details lock leaves branding open.
    self.plugin.cfg_super_tenant_permissions = {"edit_company_details": False}
    self.assertEqual(ok(self, self.update({"theme": "navy"}))["theme"], "navy")

  def test_no_namespace_means_unavailable_before_any_storage_access(self):
    self.plugin.cfg_tenancy_namespace = None
    for name in ("get_super_tenant_branding", "update_super_tenant_branding", "download_super_tenant_branding_logo"):
      with self.subTest(name):
        self.assertEqual(getattr(self.Plugin, name).__http_method__, "post")
        kwargs = {"changes": {"theme": "navy"}} if name.startswith("update") else {}
        self.assertEqual(getattr(self.plugin, name)(actor=self.actor, **kwargs)["status_code"], 503)
    self.assertEqual((self.store.writes, self.documents.puts), ([], []))


class TestBrandingStoredRow(unittest.TestCase):
  def test_the_validator_refuses_rows_the_operations_could_not_write(self):
    from extensions.business.cybersec.red_mesh.tenancy.super_tenant_branding import validate_super_tenant_branding
    logo = {"store": "fake", "ref": "doc-1", "sha256": "a" * 64, "filename": "logo.png", "mime": "image/png",
            "size_bytes": 10, "uploaded_at": "2026-10-13T00:00:00Z", "uploaded_by": "creator"}
    good = {"theme": "navy", "logo": logo, "updated_by": "creator", "updated_at": "2026-10-13T00:00:00Z"}
    self.assertIs(validate_super_tenant_branding(good, ["deployment"]), good)
    bad = {"id": ({}, ["other"]), "theme": ({"theme": "pink"}, None), "mime": ({"logo": {**logo, "mime": "image/svg+xml"}}, None),
           "size": ({"logo": {**logo, "size_bytes": 2 * 1024 * 1024 + 1}}, None), "logo keys": ({"logo": {"ref": "doc-1"}}, None),
           "attribution": ({"updated_by": ""}, None)}
    for label, (change, ids) in bad.items():
      with self.subTest(label), self.assertRaises(ValueError):
        validate_super_tenant_branding({**good, **change}, ids or ["deployment"])
  # Data maintenance: `test_data_maintenance.test_the_super_tenant_branding_is_current_with_its_logo_and_cleanup_keeps_it`.


if __name__ == "__main__":
  unittest.main()
