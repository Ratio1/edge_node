from dataclasses import dataclass

from ..constants import ScanType
from ..graybox.worker import GrayboxLocalWorker
from ..worker import PentestLocalWorker


@dataclass(frozen=True)
class ScanStrategy:
  scan_type: ScanType
  worker_cls: type
  catalog_categories: tuple[str, ...]


SCAN_STRATEGIES = {
  ScanType.NETWORK: ScanStrategy(
    scan_type=ScanType.NETWORK,
    worker_cls=PentestLocalWorker,
    catalog_categories=("service", "web", "correlation"),
  ),
  ScanType.WEBAPP: ScanStrategy(
    scan_type=ScanType.WEBAPP,
    worker_cls=GrayboxLocalWorker,
    catalog_categories=("graybox",),
  ),
}


def coerce_scan_type(scan_type=None):
  """Normalize optional scan-type input to ScanType or None."""
  if scan_type in (None, "", "all"):
    return None
  if isinstance(scan_type, ScanType):
    return scan_type
  return ScanType(str(scan_type))


def get_scan_strategy(scan_type=None, default=ScanType.NETWORK) -> ScanStrategy:
  normalized = coerce_scan_type(scan_type)
  if normalized is None:
    normalized = default
  return SCAN_STRATEGIES[normalized]


def iter_scan_strategies(scan_type=None):
  normalized = coerce_scan_type(scan_type)
  if normalized is not None:
    return [(normalized, SCAN_STRATEGIES[normalized])]
  return list(SCAN_STRATEGIES.items())
