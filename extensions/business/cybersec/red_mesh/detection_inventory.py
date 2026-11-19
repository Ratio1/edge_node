"""Detection signature inventory for RedMesh coverage accounting."""

from __future__ import annotations

from dataclasses import dataclass

from .cve_db import CVE_DATABASE
from .graybox.scenario_catalog import GRAYBOX_SCENARIO_CATALOG
from .worker.blackbox_detection_catalog import BLACKBOX_DETECTION_CATALOG


# Catalog product keys that no probe passes to `check_cves`, so their rows can
# never fire. They stay in the catalog and in the counts; `not_probe_reachable`
# reports how many CVEs that makes (RM-168).
PRODUCTS_WITHOUT_PROBE = frozenset({
  "struts2", "spring_framework", "spring_cloud_function", "django",
  "laravel_ignition", "libvncserver",
})


@dataclass(frozen=True)
class DetectionInventory:
  """Countable detection signature sets.

  ``blackbox`` includes unique static CVEs and native black-box non-CVE
  detector families. ``graybox`` includes authenticated scenario IDs.
  """

  cves: frozenset[str]
  blackbox_detectors: frozenset[str]
  graybox_scenarios: frozenset[str]
  # Subset of `cves` whose every catalog row has a product key no probe passes.
  not_probe_reachable: frozenset[str] = frozenset()

  @property
  def blackbox(self) -> frozenset[str]:
    return frozenset(self.cves | self.blackbox_detectors)

  @property
  def total(self) -> frozenset[str]:
    return frozenset(self.blackbox | self.graybox_scenarios)

  def counts(self) -> dict[str, int]:
    return {
      "cves": len(self.cves),
      "cves_not_probe_reachable": len(self.not_probe_reachable),
      "blackbox_detectors": len(self.blackbox_detectors),
      "blackbox": len(self.blackbox),
      "graybox": len(self.graybox_scenarios),
      "total": len(self.total),
    }


def build_detection_inventory() -> DetectionInventory:
  """Build the current stable detection signature inventory."""
  cves = frozenset(f"CVE:{entry.cve_id}" for entry in CVE_DATABASE)
  reachable = {entry.cve_id for entry in CVE_DATABASE if entry.product not in PRODUCTS_WITHOUT_PROBE}
  not_probe_reachable = frozenset(
    f"CVE:{entry.cve_id}" for entry in CVE_DATABASE if entry.cve_id not in reachable
  )
  blackbox_detectors = frozenset(
    f"BB:{entry['id']}" for entry in BLACKBOX_DETECTION_CATALOG
  )
  graybox_scenarios = frozenset(
    f"GB:{entry['id']}" for entry in GRAYBOX_SCENARIO_CATALOG
  )
  return DetectionInventory(
    cves=cves,
    blackbox_detectors=blackbox_detectors,
    graybox_scenarios=graybox_scenarios,
    not_probe_reachable=not_probe_reachable,
  )
