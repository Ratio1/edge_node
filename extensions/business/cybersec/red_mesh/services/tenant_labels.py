"""RM-139 phase 3: the tenant a deployment export carries, so the SOC can filter one deployment's
output by tenant.

Every export goes to the deployment's destination, so a tenant is told apart by a label, never by
a destination. The id label is the stable filter key (`redmesh:tenant_id=<id>`, the same string on
MISP events and STIX objects); the MISP-only name label follows renames and is informative only.
A job without a tenant binding (only an unbound JSON download can reach here) is the super-tenant's.
"""
import re

SUPER_TENANT = "super-tenant"
TENANT_ID_PREFIX = "redmesh:tenant_id="
TENANT_NAME_PREFIX = "redmesh:tenant_name="
TENANT_NAME_MAX = 64
# Quotes and `=` would break `name=value` tag parsing and MISP tag searches; control characters
# would reach a SOC console verbatim.
_NAME_DROPPED = re.compile(r"[\"'=\x00-\x1f\x7f]")


def tenant_label_value(tenant_id):
  return tenant_id if isinstance(tenant_id, str) and tenant_id.strip() else SUPER_TENANT


def tenant_id_label(tenant_id):
  return TENANT_ID_PREFIX + tenant_label_value(tenant_id)


def sanitized_tenant_name(value):
  """The display name fit for a tag value, or None when nothing usable remains."""
  if not isinstance(value, str):
    return None
  name = _NAME_DROPPED.sub("", value).strip()[:TENANT_NAME_MAX].strip()
  return name or None


def tenant_display_name(owner, tenant_id):
  """The tenant's current display name, sanitised, or None. Read at export time so a rename shows
  on the next export. Never raises: the name is informative, so an unreadable tenant record omits
  the name label instead of failing the export (the id label is still there)."""
  getter = getattr(type(owner), "_get_tenant_display_name", None)
  if not tenant_id or not callable(getter):
    return None
  try:
    return sanitized_tenant_name(getter(owner, tenant_id))
  except Exception:
    return None


def misp_tenant_tags(owner, tenant_id):
  tags = [tenant_id_label(tenant_id)]
  name = tenant_display_name(owner, tenant_id)
  if name:
    tags.append(TENANT_NAME_PREFIX + name)
  return tags
