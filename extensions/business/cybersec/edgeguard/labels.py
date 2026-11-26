"""One schema-label picker shared by the digest, notation, selection and brief code.

Sector nodes carry a sector label beside the schema label (`["Energy", "ThreatActor"]`),
so `labels[0]` names the sector, not the node type.
"""

from __future__ import annotations

from typing import Any, Optional

KNOWN_LABEL_PRIORITY = (
  "CVE", "Indicator", "Malware", "ThreatActor", "Technique", "Tactic", "Tool", "Campaign",
)


def primary_label(labels: Any) -> Optional[str]:
  label_set = set(labels or [])
  for candidate in KNOWN_LABEL_PRIORITY:
    if candidate in label_set:
      return candidate
  for label in labels or []:
    if isinstance(label, str) and label:
      return label
  return None
