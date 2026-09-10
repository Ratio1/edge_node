"""Node address and assignment-record validation shared by administration boundaries."""
from datetime import datetime, timezone

from .identity import canonical_account_id
from .ports import TenantStoreError


def valid_node_address(value):
  """Preserve case/codepoints; reject whitespace, controls and the Unicode BOM."""
  return (isinstance(value, str) and 1 <= len(value) <= 256
          and not any(ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch == "\ufeff"
              for ch in value))


def validate_node_assignment(row, ids):
  """Validate the domain payload at every persisted assignment boundary, even inactive rows."""
  if (len(ids) != 2 or not valid_node_address(ids[1])
      or row.get("tenant_id") != ids[0] or row.get("node_address") != ids[1]
      or type(row.get("active")) is not bool or not row.get("changed_by")
      or canonical_account_id(row["changed_by"]) != row["changed_by"]):
    raise TenantStoreError("Invalid tenant node assignment")
  try:
    changed_at = datetime.fromisoformat(row.get("changed_at"))
  except (TypeError, ValueError) as exc:
    raise TenantStoreError("Invalid tenant node assignment") from exc
  if changed_at.tzinfo != timezone.utc:
    raise TenantStoreError("Invalid tenant node assignment")
