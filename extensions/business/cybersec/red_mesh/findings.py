"""
Structured vulnerability findings for RedMesh probes.

Every probe returns a plain dict via ``probe_result()`` so that the
aggregator pipeline (merge_objects_deep, R1FS serialization) keeps working
unchanged.  The ``Finding`` dataclass and ``Severity`` enum provide
type-safe construction and JSON-safe serialization.
"""

from dataclasses import dataclass, asdict
from enum import Enum


class Severity(str, Enum):
  CRITICAL = "CRITICAL"
  HIGH = "HIGH"
  MEDIUM = "MEDIUM"
  LOW = "LOW"
  INFO = "INFO"


_VULN_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM})


@dataclass(frozen=True)
class Finding:
  severity: Severity
  title: str
  description: str
  evidence: str = ""
  remediation: str = ""
  owasp_id: str = ""       # e.g. "A07:2021"
  cwe_id: str = ""         # e.g. "CWE-287"
  confidence: str = "firm"  # certain | firm | tentative


def probe_result(*, raw_data: dict = None, findings: list = None) -> dict:
  """Build a probe return dict: JSON-safe, merge_objects_deep-safe, backward-compat."""
  result = dict(raw_data or {})
  f_list = findings or []
  result["findings"] = [{**asdict(f), "severity": f.severity.value} for f in f_list]
  result["vulnerabilities"] = [f.title for f in f_list if f.severity in _VULN_SEVERITIES]
  return result


def probe_error(target: str, port: int, probe_name: str, exc: Exception) -> dict:
  """Standardized error return for all probes."""
  return probe_result(raw_data={"error": f"{probe_name} failed on {target}:{port}: {exc}"})
