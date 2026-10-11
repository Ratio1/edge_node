"""RM-125 phase 2b: an engagement or an engagement draft picks a registered tenant asset.

`register_asset` works on the administration service and on the plugin (the plugin unwraps `asset`).
"""
from uuid import uuid4


def register_asset(endpoint, actor, parent, target, display_name="Asset"):
  """Register `target` under `parent` (`tenant_id` or `draft_id`) and answer its `asset_id`."""
  result = endpoint.create_tenant_asset(actor, parent, str(uuid4()), display_name, target)
  assert result.get("success"), result
  data = result["data"]
  return data.get("asset", data)["asset_id"]


def pick(asset_id):
  """The public request entry for a registered asset."""
  return {"asset_id": asset_id}
