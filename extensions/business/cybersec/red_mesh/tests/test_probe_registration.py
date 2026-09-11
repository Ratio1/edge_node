"""Every probe method must be registered — a misplaced decorator is silent.

Ratchet from a near-miss: inserting a helper between `@register_probe(...)` and
its probe made the decorator register the *helper*, leaving the probe
unregistered — so it would never be scheduled in production and would get no
registry metadata (default CWE/OWASP, CVSS template). Every existing test kept
passing, because they call probe methods directly.
"""

import inspect
import unittest


class TestEveryProbeIsRegistered(unittest.TestCase):

  _PROBE_PREFIXES = ("_web_test_", "_service_info_")

  def _probe_methods(self):
    from extensions.business.cybersec.red_mesh.worker.web import (
      discovery, hardening, injection,
    )
    from extensions.business.cybersec.red_mesh.worker.service import (
      common, database, infrastructure, tls,
    )

    for module in (discovery, hardening, injection, common, database,
                   infrastructure, tls):
      for _, cls in inspect.getmembers(module, inspect.isclass):
        if cls.__module__ != module.__name__:
          continue
        for name, _fn in inspect.getmembers(cls, callable):
          if name.startswith(self._PROBE_PREFIXES):
            yield f"{module.__name__.rsplit('.', 1)[-1]}.{name}", name

  def test_every_probe_method_has_registry_metadata(self):
    from extensions.business.cybersec.red_mesh.worker.probe_registry import (
      get_probe_metadata,
    )

    seen = 0
    unregistered = []
    for qualified, name in self._probe_methods():
      seen += 1
      if get_probe_metadata(name) is None:
        unregistered.append(qualified)
    self.assertGreaterEqual(seen, 40, "the probe sweep stopped finding probes")
    self.assertEqual(
      unregistered, [],
      "a probe method has no registry metadata — most likely a decorator was "
      "displaced onto a neighbouring function, so the probe will never be "
      "scheduled and gets no default CWE/OWASP enrichment",
    )


if __name__ == "__main__":
  unittest.main()
