"""Phase 1 PR-1.2 — probe registration CI gate.

Per principle P14 of the PTES rebuild plan ("Probe metadata declared
at probe definition") this test walks every module that defines probes
and asserts each probe-prefixed function carries @register_probe.

Drift becomes impossible: a new probe that ships without registration
fails this test, and the test runs as part of the standard pytest
suite.

Migration completion (PR-1.5)
-----------------------------

The transitional allowlist is now empty: PR-1.3 migrated 29 service
probes, PR-1.4 migrated 32 web probes, PR-1.5 migrated the 7
correlation probes. The CI gate now hard-fails on any undecorated
probe; there is no allowlist escape hatch. The PROBE_MIGRATION_ALLOWLIST
constant is preserved as an empty set for backwards-compat with any
external test imports, but the test asserts it stays empty.

Test harness
------------

  - test_decorator_registers_metadata: smoke test that the decorator
    works (independent of any specific probe).
  - test_decorator_validates_inputs: rejects bad metadata at import.
  - test_decorator_rejects_duplicate_probe_ids: catches accidental
    double-decoration.
  - test_metadata_attached_to_function: probe functions can access
    their own metadata via fn.__probe_metadata__.
  - test_all_probes_decorated_or_in_allowlist: walks the codebase and
    asserts every probe-prefixed method is either decorated OR in the
    transitional allowlist.
"""
from __future__ import annotations

import inspect
import unittest

from extensions.business.cybersec.red_mesh.worker.probe_registry import (
  ALLOWED_CATEGORIES,
  CATEGORY_CORRELATION,
  CATEGORY_GRAYBOX,
  CATEGORY_SERVICE_INFO,
  CATEGORY_WEB_TEST,
  ProbeMetadata,
  clear_registry_for_tests,
  get_probe_metadata,
  list_registered_probes,
  register_probe,
)


# Allowlist of probe_ids exempted from the registration requirement.
# Phase 1 migration is complete — this is empty. The variable is kept
# (rather than removed) so future emergency exemptions can be added
# inline with a tracking comment, rather than requiring re-introducing
# the test scaffolding from scratch.
PROBE_MIGRATION_ALLOWLIST: set[str] = set()


PROBE_PREFIXES = (
  "_service_info_",
  "_web_test_",
  "_post_scan_",
  "_correlate_",
  "_graybox_",
)


# --------------------------------------------------------------------
# Decorator-level tests (independent of any concrete probe)
# --------------------------------------------------------------------


class TestRegisterProbeDecorator(unittest.TestCase):

  def setUp(self):
    self._saved = list_registered_probes()
    clear_registry_for_tests()

  def tearDown(self):
    # Restore the registry directly without going through the
    # decorator (which would reject duplicate __name__='<lambda>').
    from extensions.business.cybersec.red_mesh.worker import probe_registry
    clear_registry_for_tests()
    probe_registry._REGISTRY.update(self._saved)

  def test_decorator_registers_metadata(self):
    @register_probe(
      display_name="Test SSH version",
      description="Banner-grab SSH and check version",
      category=CATEGORY_SERVICE_INFO,
      default_cwe=(287,),
      default_owasp=("A07:2021",),
      cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    )
    def _service_info_test_ssh(self, ip, port):
      pass

    md = get_probe_metadata("_service_info_test_ssh")
    self.assertIsNotNone(md)
    self.assertEqual(md.display_name, "Test SSH version")
    self.assertEqual(md.default_cwe, (287,))
    self.assertEqual(md.default_owasp, ("A07:2021",))
    self.assertEqual(md.category, CATEGORY_SERVICE_INFO)

  def test_metadata_attached_to_function(self):
    @register_probe(
      display_name="Test", description="t", category=CATEGORY_WEB_TEST,
    )
    def _web_test_attached(self):
      pass

    self.assertTrue(hasattr(_web_test_attached, "__probe_metadata__"))
    self.assertIsInstance(_web_test_attached.__probe_metadata__, ProbeMetadata)
    self.assertEqual(_web_test_attached.__probe_metadata__.probe_id, "_web_test_attached")

  def test_decorator_rejects_unknown_category(self):
    with self.assertRaises(ValueError) as ctx:
      @register_probe(
        display_name="x", description="y", category="not_a_category",
      )
      def _service_info_bad(self):
        pass
    self.assertIn("category", str(ctx.exception))

  def test_decorator_rejects_invalid_cwe(self):
    with self.assertRaises(ValueError):
      @register_probe(
        display_name="x", description="y", category=CATEGORY_SERVICE_INFO,
        default_cwe=(0,),
      )
      def _service_info_zero_cwe(self):
        pass
    with self.assertRaises(ValueError):
      @register_probe(
        display_name="x", description="y", category=CATEGORY_SERVICE_INFO,
        default_cwe=(-5,),
      )
      def _service_info_negative_cwe(self):
        pass

  def test_decorator_rejects_malformed_owasp(self):
    bad_values = ["a01:2021", "A1:2021", "A01-2021", "A01:21", "X01:2021", ""]
    for bad in bad_values:
      with self.assertRaises(ValueError, msg=f"should reject: {bad!r}"):
        @register_probe(
          display_name="x", description="y", category=CATEGORY_SERVICE_INFO,
          default_owasp=(bad,),
        )
        def _service_info_bad_owasp(self):
          pass

  def test_decorator_rejects_malformed_cvss_template(self):
    with self.assertRaises(ValueError):
      @register_probe(
        display_name="x", description="y", category=CATEGORY_SERVICE_INFO,
        cvss_template="not-a-cvss-vector",
      )
      def _service_info_bad_cvss(self):
        pass
    # v2 vectors rejected (we only support v3.1 + v4.0)
    with self.assertRaises(ValueError):
      @register_probe(
        display_name="x", description="y", category=CATEGORY_SERVICE_INFO,
        cvss_template="CVSS:2.0/AV:N",
      )
      def _service_info_v2_cvss(self):
        pass

  def test_decorator_accepts_v3_1_and_v4_0_cvss(self):
    @register_probe(
      display_name="v31", description="d", category=CATEGORY_WEB_TEST,
      cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    def _web_test_v31_cvss(self):
      pass

    @register_probe(
      display_name="v40", description="d", category=CATEGORY_WEB_TEST,
      cvss_template="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    def _web_test_v40_cvss(self):
      pass

    self.assertIsNotNone(get_probe_metadata("_web_test_v31_cvss"))
    self.assertIsNotNone(get_probe_metadata("_web_test_v40_cvss"))

  def test_decorator_rejects_duplicate_probe_ids(self):
    @register_probe(
      display_name="first", description="d", category=CATEGORY_SERVICE_INFO,
    )
    def _service_info_dup(self):
      pass

    with self.assertRaises(RuntimeError) as ctx:
      @register_probe(
        display_name="second", description="d", category=CATEGORY_SERVICE_INFO,
      )
      def _service_info_dup(self):  # noqa: F811 — intentional duplicate
        pass
    self.assertIn("duplicate", str(ctx.exception))

  def test_categories_match_pentest_worker_prefixes(self):
    """Categories declared in probe_registry must match the prefix
    routing in PentestLocalWorker.FEATURE_CATEGORY_PREFIXES so that a
    probe's category matches what the runner expects.
    """
    from extensions.business.cybersec.red_mesh.worker.pentest_worker import (
      PentestLocalWorker,
    )
    expected_prefixes = {
      CATEGORY_SERVICE_INFO: "_service_info_",
      CATEGORY_WEB_TEST: "_web_test_",
      CATEGORY_CORRELATION: "_post_scan_",
    }
    for cat, expected_prefix in expected_prefixes.items():
      self.assertIn(cat, ALLOWED_CATEGORIES)
      # The runner uses these strings — make sure our categories line
      # up with what the worker actually invokes.
      worker_prefixes = PentestLocalWorker.FEATURE_CATEGORY_PREFIXES
      worker_label = {
        CATEGORY_SERVICE_INFO: "service",
        CATEGORY_WEB_TEST: "web",
        CATEGORY_CORRELATION: "correlation",
      }[cat]
      self.assertEqual(worker_prefixes[worker_label], expected_prefix)


# --------------------------------------------------------------------
# CI gate — walks codebase, every probe-prefixed function must be
# either decorated OR in the transitional allowlist.
# --------------------------------------------------------------------


def _discover_probe_functions() -> dict[str, str]:
  """Return {probe_id: source_module} for every probe-prefixed
  function across the canonical probe modules.
  """
  modules = []
  # Service / web probes live as mixin methods on PentestLocalWorker
  # via worker/service/*.py and worker/web/*.py (imported from worker.__init__).
  from extensions.business.cybersec.red_mesh.worker import service as svc_pkg
  from extensions.business.cybersec.red_mesh.worker import web as web_pkg
  from extensions.business.cybersec.red_mesh.worker import correlation as corr_mod

  modules.append(corr_mod)
  for name in dir(svc_pkg):
    obj = getattr(svc_pkg, name)
    if inspect.ismodule(obj) and obj.__name__.startswith("extensions.business.cybersec.red_mesh.worker.service"):
      modules.append(obj)
  for name in dir(web_pkg):
    obj = getattr(web_pkg, name)
    if inspect.ismodule(obj) and obj.__name__.startswith("extensions.business.cybersec.red_mesh.worker.web"):
      modules.append(obj)

  found: dict[str, str] = {}
  for mod in modules:
    for member_name, member in inspect.getmembers(mod):
      if not callable(member):
        continue
      if not any(member_name.startswith(p) for p in PROBE_PREFIXES):
        continue
      # Only include functions/methods *defined* in this module
      try:
        if inspect.getmodule(member) != mod:
          # mixin classes also expose probe methods; their owning module
          # is the mixin file, not the consumer. Walk class members too.
          pass
      except Exception:
        pass
      found.setdefault(member_name, mod.__name__)

  # Also walk methods on mixin classes in worker/service/*.py and
  # worker/web/*.py (probes are class methods, not module-level).
  from extensions.business.cybersec.red_mesh.worker.service.common import _ServiceCommonMixin
  from extensions.business.cybersec.red_mesh.worker.service.database import _ServiceDatabaseMixin
  from extensions.business.cybersec.red_mesh.worker.service.infrastructure import _ServiceInfraMixin
  from extensions.business.cybersec.red_mesh.worker.service.tls import _ServiceTlsMixin
  from extensions.business.cybersec.red_mesh.worker.web.discovery import _WebDiscoveryMixin
  from extensions.business.cybersec.red_mesh.worker.web.injection import _WebInjectionMixin
  from extensions.business.cybersec.red_mesh.worker.web.hardening import _WebHardeningMixin
  from extensions.business.cybersec.red_mesh.worker.web.api_exposure import _WebApiExposureMixin
  from extensions.business.cybersec.red_mesh.worker.correlation import _CorrelationMixin

  for cls in (
    _ServiceCommonMixin, _ServiceDatabaseMixin,
    _ServiceInfraMixin, _ServiceTlsMixin,
    _WebDiscoveryMixin, _WebInjectionMixin,
    _WebHardeningMixin, _WebApiExposureMixin, _CorrelationMixin,
  ):
    for name, member in inspect.getmembers(cls, inspect.isfunction):
      if any(name.startswith(p) for p in PROBE_PREFIXES):
        found.setdefault(name, cls.__module__)

  return found


class TestProbeRegistrationCoverage(unittest.TestCase):
  """CI gate. Every probe must be @register_probe-decorated.

  Phase 1 migration is complete — there is no transitional allowlist.
  A new probe that lands without registration fails this test and
  blocks the merge.
  """

  def test_all_probes_decorated(self):
    found = _discover_probe_functions()
    self.assertGreater(
      len(found), 0,
      "discovery returned no probes — something is wrong with the walker",
    )
    undecorated = []
    for probe_id, source in found.items():
      md = get_probe_metadata(probe_id)
      if md is None and probe_id not in PROBE_MIGRATION_ALLOWLIST:
        undecorated.append((probe_id, source))
    if undecorated:
      msg = "\n  ".join(f"{pid} ({src})" for pid, src in undecorated)
      self.fail(
        f"Probes missing @register_probe decoration:\n  {msg}\n"
        "Decorate each with @register_probe(...) — see "
        "worker/probe_registry.py for the metadata schema."
      )

  def test_allowlist_is_empty(self):
    """The migration allowlist must remain empty. New temporary
    exemptions require a tracking issue and explicit reviewer
    approval — adding to this set should be rare and brief."""
    self.assertEqual(
      len(PROBE_MIGRATION_ALLOWLIST), 0,
      f"PROBE_MIGRATION_ALLOWLIST must be empty (Phase 1 migration "
      f"complete). Got: {sorted(PROBE_MIGRATION_ALLOWLIST)}",
    )

  def test_registration_summary(self):
    """Informational — print decorated/total counts for PR review."""
    found = _discover_probe_functions()
    decorated = sum(1 for pid in found if get_probe_metadata(pid) is not None)
    by_category = {}
    for pid in found:
      md = get_probe_metadata(pid)
      if md:
        by_category[md.category] = by_category.get(md.category, 0) + 1
    print(
      f"\n  [probe-registry] {decorated}/{len(found)} decorated, "
      f"by category: {by_category}"
    )


if __name__ == "__main__":
  unittest.main()
