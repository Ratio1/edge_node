"""Probe metadata registry — enforced at probe definition time.

Phase 1 PR-1.2 (P14 — "Probe metadata declared at probe definition").

Why this exists
---------------

Without a registry, probe metadata (display name, default CWE, default
OWASP Top 10 mapping, CVSS template) lives implicitly across the
codebase: probe function name patterns, hard-coded strings inside
probes, the CVE DB module, the LLM prompt builders, etc. Adding a new
probe means remembering to update each of those — drift is silent and
inevitable.

This module makes the metadata declaration a *property of the probe
function* via a decorator. The CI gate test
(``tests/test_probe_registry.py``) walks the codebase, finds every
probe-prefixed method in worker mixins, and asserts each one is
decorated. New probes that ship without registration fail CI before
they reach a release.

Usage
-----

    from extensions.business.cybersec.red_mesh.worker.probe_registry import register_probe

    @register_probe(
      display_name="PostgreSQL credential check",
      description="Tests known weak credentials against PostgreSQL md5 auth.",
      default_cwe=(521, 798),
      default_owasp=("A07:2021",),
      cvss_template="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      category="service_info",
    )
    def _service_info_postgresql_creds(self, ip, port, ...):
        ...

The decorator is applied at module import. Duplicate registration
(same probe_id) raises a RuntimeError immediately so accidental
double-decoration is caught.

Categories
----------

The ``category`` argument matches the prefix routing used by
``PentestLocalWorker.PHASE_EXECUTION_PLAN`` and the feature catalog in
``constants.py``. Allowed values:

  - ``service_info``  — service detection / fingerprinting on a port
  - ``web_test``      — HTTP-layer probes (XSS, CSRF, headers, etc.)
  - ``correlation``   — post-scan correlation / chaining checks
  - ``graybox``       — authenticated webapp probes (graybox/* package)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

CATEGORY_SERVICE_INFO = "service_info"
CATEGORY_WEB_TEST = "web_test"
CATEGORY_CORRELATION = "correlation"
CATEGORY_GRAYBOX = "graybox"

ALLOWED_CATEGORIES = frozenset({
  CATEGORY_SERVICE_INFO,
  CATEGORY_WEB_TEST,
  CATEGORY_CORRELATION,
  CATEGORY_GRAYBOX,
})


@dataclass(frozen=True)
class ProbeMetadata:
  """Static metadata declared on a probe function via @register_probe.

  Populated once at module import time and looked up during finding
  emit so each Finding can carry the registered defaults
  (display_name, default_cwe, default_owasp, cvss_template). Probes
  may still override per-finding.
  """
  probe_id: str
  display_name: str
  description: str
  default_cwe: tuple[int, ...] = ()
  default_owasp: tuple[str, ...] = ()
  cvss_template: str = ""
  category: str = ""
  # Forward-compat: probes can flag stateful / destructive behavior
  # so the safety policy module can refuse to run them in --safe mode.
  stateful: bool = False
  destructive: bool = False
  references: tuple[str, ...] = ()


# Module-level registry. Keys are probe_ids (the function name).
_REGISTRY: dict[str, ProbeMetadata] = {}


def register_probe(
  *,
  display_name: str,
  description: str,
  category: str,
  default_cwe: tuple[int, ...] | list[int] | None = None,
  default_owasp: tuple[str, ...] | list[str] | None = None,
  cvss_template: str = "",
  stateful: bool = False,
  destructive: bool = False,
  references: tuple[str, ...] | list[str] | None = None,
) -> Callable:
  """Decorator that registers probe metadata at definition time.

  Validates inputs at import time:
    - category must be one of ALLOWED_CATEGORIES
    - probe_id (derived from fn.__name__) must be unique
    - default_cwe entries must be int CWE IDs (no strings)
    - default_owasp entries must look like ``A##:YYYY``
    - cvss_template, when present, must start with ``CVSS:3.1/`` or
      ``CVSS:4.0/`` (the only versions we support; v4 is forward-compat).

  Bad metadata fails at import — there is no graceful fallback.
  This is intentional per P14 (drift is impossible).
  """
  if category not in ALLOWED_CATEGORIES:
    raise ValueError(
      f"register_probe: category={category!r} not in {sorted(ALLOWED_CATEGORIES)}"
    )

  cwe_tuple = tuple(int(x) for x in (default_cwe or ()))
  for cwe in cwe_tuple:
    if cwe <= 0:
      raise ValueError(f"register_probe: invalid CWE id {cwe}")

  owasp_tuple = tuple(default_owasp or ())
  for owasp in owasp_tuple:
    if not _looks_like_owasp(owasp):
      raise ValueError(
        f"register_probe: default_owasp entry {owasp!r} should look like 'A##:YYYY'"
      )

  if cvss_template and not (
    cvss_template.startswith("CVSS:3.1/") or cvss_template.startswith("CVSS:4.0/")
  ):
    raise ValueError(
      f"register_probe: cvss_template must start with 'CVSS:3.1/' or 'CVSS:4.0/'"
      f" (got: {cvss_template!r})"
    )

  refs_tuple = tuple(references or ())

  def decorator(fn: Callable) -> Callable:
    probe_id = fn.__name__
    if probe_id in _REGISTRY:
      raise RuntimeError(
        f"register_probe: duplicate registration for probe_id={probe_id!r} "
        f"(already in {_REGISTRY[probe_id].category})"
      )
    _REGISTRY[probe_id] = ProbeMetadata(
      probe_id=probe_id,
      display_name=display_name,
      description=description,
      default_cwe=cwe_tuple,
      default_owasp=owasp_tuple,
      cvss_template=cvss_template,
      category=category,
      stateful=stateful,
      destructive=destructive,
      references=refs_tuple,
    )
    # Stamp the metadata onto the function so callers can fetch it
    # without going through the registry dict.
    fn.__probe_metadata__ = _REGISTRY[probe_id]  # type: ignore[attr-defined]
    return fn

  return decorator


def _looks_like_owasp(s: str) -> bool:
  """Return True if s looks like an OWASP Top 10 category id, e.g. 'A01:2021'."""
  if not isinstance(s, str) or len(s) < 7:
    return False
  return s[0] == "A" and s[1:3].isdigit() and s[3] == ":" and s[4:].isdigit()


def get_probe_metadata(probe_id: str) -> ProbeMetadata | None:
  """Return the registered metadata for a probe, or None if not registered."""
  return _REGISTRY.get(probe_id)


def list_registered_probes() -> dict[str, ProbeMetadata]:
  """Return a read-only snapshot of the registry — for tests, diagnostics."""
  return dict(_REGISTRY)


def clear_registry_for_tests() -> None:
  """Test-only escape hatch — clears the registry. Production code must
  not call this."""
  _REGISTRY.clear()
