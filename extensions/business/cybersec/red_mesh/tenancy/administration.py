"""Tenant control plane; memberships remain owned by the account identity provider.

Publication is the final tenant write, not a second receipt update. A verified active tenant is
also the completion marker, so uncertain successful publication cannot cause a retry to re-grant
an initial administrator. The lock/read-backs only mitigate local races; CStore's documented
distributed consistency limitations still apply.
"""
from datetime import datetime, timezone
from functools import wraps
import re
from threading import RLock
from uuid import UUID, uuid4

from .identity import IdentityStoreError, TenantMembership, canonical_account_id, holds_platform_role, resolve_actor
from .policy import (TENANT_LOCAL_ROLES, TenantPolicyContext, authorize_tenant_operation, resolve_tenant_roles,
                     resolve_operation_roles, valid_account_scope)
from .execution import CurrentExecutionFacts, ExecutionBinding, ResolvedExecutionContext
from .ports import TenantStoreError
from .nodes import valid_node_address
from .assets import (canonical_digest, normalize_name, normalize_port_scope, normalize_target,
                     valid_digest)
from .integrations import (NODE_LEVEL_INTEGRATION_IDS, integration_ids,
                           normalize_integration_config, public_integration_config,
                           valid_integration_id)


_ADMINISTRATION_LOCK = RLock()
# An asset update that omits `authorized_ports` keeps the stored scope; an explicit None clears it.
# A string rather than `object()` so it can be an HTTP endpoint default; it is never a valid scope.
KEEP_PORT_SCOPE = "__keep__"


def _port_scope_for(target, value):
  scope = normalize_port_scope(value)
  if scope is not None and target["kind"] != "network":
    raise ValueError("Port scope applies to network assets only")
  return scope
_MEMBER_ROLES = TENANT_LOCAL_ROLES
# RM-083 (owner, 2026-09-17): only a Super-Tenant Admin grants, removes or replaces these.
_PLATFORM_RESERVED_MEMBER_ROLES = frozenset({"tenant_pentester"})
_ACTIVE_STATE = "active"
_DEACTIVATED_STATE = "deactivated"
# RM-084 P7. The two states an administrator acts on; `deleting` is terminal and hidden everywhere.
_ACCOUNT_STATES = (_ACTIVE_STATE, _DEACTIVATED_STATE)
_VISIBLE_MEMBER_STATES = frozenset(_ACCOUNT_STATES)


class AdministrationDenied(Exception):
  def __init__(self, status_code, error):
    self.status_code = status_code
    self.error = error


def administration_unavailable():
  return {"success": False, "status": "error", "status_code": 503, "error": "unavailable"}


def _endpoint(method):
  @wraps(method)
  def call(*args, **kwargs):
    try:
      # Shared across service instances in this process, including authorization after queueing.
      with _ADMINISTRATION_LOCK:
        data = method(*args, **kwargs)
      return {"success": True, "status_code": 200, "data": data}
    except AdministrationDenied as exc:
      return {"success": False, "status": "error", "status_code": exc.status_code, "error": exc.error}
    except (IdentityStoreError, TenantStoreError):
      return administration_unavailable()
  return call


def _request_id(value):
  if not isinstance(value, str):
    raise AdministrationDenied(400, "invalid_request")
  try:
    normalized = str(UUID(value))
  except ValueError:
    raise AdministrationDenied(400, "invalid_request") from None
  if normalized != value:
    raise AdministrationDenied(400, "invalid_request")
  return normalized


def _domain(value):
  if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value):
    raise AdministrationDenied(400, "invalid_domain")
  return value


class TenantAdministrationService:
  def __init__(self, accounts, store, configured_peers_reader=None):
    self.accounts = accounts
    self.store = store
    self.configured_peers_reader = configured_peers_reader

  def _actor(self, actor, *, creator=False):
    account, denial = resolve_actor(actor, self.accounts)
    if denial:
      raise AdministrationDenied(denial["status_code"], denial["error"])
    if creator and not holds_platform_role(account):
      raise AdministrationDenied(403, "forbidden")
    return account

  def _initial_admin(self, account_id, generation=None):
    account = self.accounts.get_account(account_id)
    if account is None or not account.active:
      raise AdministrationDenied(404, "not_found")
    if not account.account_generation or (generation is not None and account.account_generation != generation):
      raise AdministrationDenied(409, "account_changed")
    return account

  def _receipt(self, actor_id, request_id):
    receipt = self.store.get("receipt", actor_id, request_id)
    if receipt is None:
      return None
    if (receipt.get("actor_id") != actor_id or receipt.get("request_id") != request_id
        or not isinstance(receipt.get("tenant_id"), str) or not receipt["tenant_id"].startswith("tn_")
        or not isinstance(receipt.get("display_name"), str) or not receipt["display_name"].strip()
        or canonical_account_id(receipt.get("initial_admin_id")) != receipt.get("initial_admin_id")
        or not receipt.get("initial_admin_id")
        or not isinstance(receipt.get("initial_admin_generation"), str) or not receipt["initial_admin_generation"]
        or not isinstance(receipt.get("created_at"), str) or not receipt["created_at"]):
      raise TenantStoreError("Invalid creation receipt")
    try:
      _domain(receipt.get("domain_id"))
      _request_id(receipt["tenant_id"][3:])
    except AdministrationDenied:
      raise TenantStoreError("Invalid creation receipt") from None
    return receipt

  @staticmethod
  def _binding(receipt):
    return {key: receipt[key] for key in ("actor_id", "request_id", "tenant_id")}

  @staticmethod
  def _tenant_payload(receipt):
    return {
      "tenant_id": receipt["tenant_id"], "actor_id": receipt["actor_id"],
      "request_id": receipt["request_id"], "display_name": receipt["display_name"],
      "domain_id": receipt["domain_id"], "created_by": receipt["actor_id"],
      "created_at": receipt["created_at"], "active": False, "allow_pentester": False,
      "node_failure_policy": "stop",
      # The tenant's root administrator: the account the tenant was created around. Recorded so a
      # tenant admin cannot reset the founder's credential and take the tenant over. Tenants created
      # before this field existed simply do not carry it; absence means "unknown", never "anyone".
      "root_admin_id": receipt["initial_admin_id"],
    }

  def _reserved_tenant(self, receipt):
    domain = self.store.get("domain", receipt["domain_id"])
    binding = self._binding(receipt)
    if domain is not None and any(domain.get(key) != value for key, value in binding.items()):
      raise AdministrationDenied(409, "domain_conflict")
    tenant = self.store.get("tenant", receipt["tenant_id"])
    if tenant is not None:
      self._assert_tenant_binding(tenant, receipt)
      if tenant["active"] and domain is None:
        raise TenantStoreError("Active tenant has no domain reservation")
    return domain, tenant

  def _assert_tenant_binding(self, tenant, receipt):
    expected = self._tenant_payload(receipt)
    # `root_admin_id` is compared only when the stored record carries it: tenants created before the
    # field existed must stay bound to their receipt rather than reading as corrupt. A record that
    # does carry it is held to the receipt exactly, which is what makes a tampered or malformed
    # founder fail closed -- no separate validation is needed, and an earlier revision's extra check
    # here was redundant.
    mutable = ("active", "allow_pentester", "node_failure_policy")
    optional = () if "root_admin_id" in tenant else ("root_admin_id",)
    if (any(tenant.get(key) != value for key, value in expected.items()
            if key not in mutable and key not in optional)
        or type(tenant.get("active")) is not bool or type(tenant.get("allow_pentester")) is not bool):
      raise TenantStoreError("Tenant receipt binding mismatch")
    if "allow_pentester_changed_by" in tenant or "allow_pentester_changed_at" in tenant:
      changed_by = tenant.get("allow_pentester_changed_by")
      if not changed_by or canonical_account_id(changed_by) != changed_by:
        raise TenantStoreError("Invalid tenant policy attribution")
      try:
        changed_at = datetime.fromisoformat(tenant.get("allow_pentester_changed_at"))
      except (TypeError, ValueError):
        raise TenantStoreError("Invalid tenant policy timestamp") from None
      if changed_at.tzinfo != timezone.utc:
        raise TenantStoreError("Invalid tenant policy timestamp")
    self._node_failure_policy(tenant)

  @staticmethod
  def _node_failure_policy(tenant):
    policy = tenant.get("node_failure_policy", "stop")
    if not isinstance(policy, str) or policy not in ("stop", "continue"):
      raise TenantStoreError("Invalid node failure policy")
    if "node_failure_policy_changed_by" in tenant or "node_failure_policy_changed_at" in tenant:
      changed_by = tenant.get("node_failure_policy_changed_by")
      if not isinstance(changed_by, str) or not changed_by or canonical_account_id(changed_by) != changed_by:
        raise TenantStoreError("Invalid node failure policy attribution")
      try:
        changed_at = datetime.fromisoformat(tenant.get("node_failure_policy_changed_at"))
      except (TypeError, ValueError):
        raise TenantStoreError("Invalid node failure policy timestamp") from None
      if changed_at.tzinfo != timezone.utc:
        raise TenantStoreError("Invalid node failure policy timestamp")
    return policy

  @_endpoint
  def prepare_tenant(self, actor, request_id, display_name, domain_id, initial_admin_id):
    creator = self._actor(actor, creator=True)
    request_id = _request_id(request_id)
    domain_id = _domain(domain_id)
    initial_admin_id = canonical_account_id(initial_admin_id)
    if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 120 or not initial_admin_id:
      raise AdministrationDenied(400, "invalid_request")
    intent = {"display_name": display_name.strip(), "domain_id": domain_id, "initial_admin_id": initial_admin_id}
    receipt = self._receipt(creator.account_id, request_id)
    if receipt is not None:
      if any(receipt[key] != value for key, value in intent.items()):
        raise AdministrationDenied(409, "request_conflict")
      domain, tenant = self._reserved_tenant(receipt)
    else:
      if self.store.get("domain", domain_id) is not None:
        raise AdministrationDenied(409, "domain_conflict")
      admin = self._initial_admin(initial_admin_id)
      # RM-083. The initial administrator becomes this tenant's account; one that already holds any
      # scope (platform or another tenant) cannot take a second. Only on first preparation: a retry
      # finds its own tenant_admin membership already written.
      if admin.tenant_memberships:
        raise AdministrationDenied(409, "scope_conflict")
      receipt = {**intent, "actor_id": creator.account_id, "request_id": request_id,
                 "initial_admin_generation": admin.account_generation, "tenant_id": "tn_" + str(uuid4()),
                 "created_at": datetime.now(timezone.utc).isoformat()}
      self.store.put("receipt", creator.account_id, request_id, record=receipt)
      domain, tenant = None, None
    if tenant is None or not tenant["active"]:
      admin = self._initial_admin(initial_admin_id, receipt["initial_admin_generation"])
      if admin.tenant_memberships not in ((), (TenantMembership("tenant_admin", receipt["tenant_id"]),)):
        raise AdministrationDenied(409, "scope_conflict")
      if domain is None:
        self.store.put("domain", domain_id, record=self._binding(receipt))
      if tenant is None:
        self.store.put("tenant", receipt["tenant_id"], record=self._tenant_payload(receipt))
    return {"requestId": request_id, "tenantId": receipt["tenant_id"], "initialAdminId": initial_admin_id,
            "initialAdminGeneration": receipt["initial_admin_generation"],
            "state": "active" if tenant is not None and tenant["active"] else "pending"}

  @_endpoint
  def activate_tenant(self, actor, request_id):
    creator = self._actor(actor, creator=True)
    receipt = self._receipt(creator.account_id, _request_id(request_id))
    if receipt is None:
      raise AdministrationDenied(404, "not_found")
    domain, tenant = self._reserved_tenant(receipt)
    if domain is None or tenant is None:
      raise AdministrationDenied(409, "creation_pending")
    if not tenant["active"]:
      admin = self._initial_admin(receipt["initial_admin_id"], receipt["initial_admin_generation"])
      if TenantMembership("tenant_admin", receipt["tenant_id"]) not in admin.tenant_memberships:
        raise AdministrationDenied(409, "initial_admin_required")
      tenant = {**tenant, "active": True}
      self.store.put("tenant", receipt["tenant_id"], record=tenant)
    return self._detail(tenant, creator)

  def _authorized_tenant(self, actor, tenant_id, operation="reports:view"):
    account = self._actor(actor)
    return self.authorize_tenant_for_account(account, tenant_id, operation)

  def authorize_tenant_for_account(self, account, tenant_id, operation="reports:view"):
    """Internal seam for an account resolved once at this operation's trusted entry point."""
    _, denial = resolve_tenant_roles(account, tenant_id)
    if denial:
      raise AdministrationDenied(denial.status_code, denial.error)
    tenant = self.store.get("tenant", tenant_id)
    if tenant is None or tenant.get("active") is not True:
      raise AdministrationDenied(404, "not_found")
    self._validate_tenant(tenant)
    decision = authorize_tenant_operation(account, operation, TenantPolicyContext(
      tenant_id, tenant["active"], tenant["allow_pentester"]))
    if not decision.allowed:
      raise AdministrationDenied(decision.status_code, decision.error)
    return tenant, account

  def _validate_tenant(self, tenant):
    if (not all(isinstance(tenant.get(key), str) and tenant[key].strip()
                for key in ("tenant_id", "display_name", "domain_id", "created_by", "created_at", "actor_id"))
        or canonical_account_id(tenant["actor_id"]) != tenant["actor_id"]
        or type(tenant.get("allow_pentester")) is not bool):
      raise TenantStoreError("Invalid administration tenant")
    try:
      request_id = _request_id(tenant.get("request_id"))
    except AdministrationDenied:
      raise TenantStoreError("Invalid tenant publication binding") from None
    receipt = self._receipt(tenant["actor_id"], request_id)
    if receipt is None:
      raise TenantStoreError("Missing tenant publication receipt")
    self._assert_tenant_binding(tenant, receipt)
    domain = self.store.get("domain", tenant["domain_id"])
    if domain is None or any(domain.get(key) != value for key, value in self._binding(receipt).items()):
      raise TenantStoreError("Invalid tenant domain reservation")

  def _members(self, tenant_id, accounts=None):
    """RM-084 P7. Deactivated members stay listed with their state; a tenant admin has to see who is
    archived to restore them. `deleting` (and any state this reader does not know) stays hidden."""
    members = []
    for account in self.accounts.list_accounts() if accounts is None else accounts:
      if account.state not in _VISIBLE_MEMBER_STATES:
        continue
      roles = {m.role for m in account.tenant_memberships if m.tenant_id == tenant_id and m.role in _MEMBER_ROLES}
      for role in sorted(roles):
        members.append({"accountId": account.account_id, "displayName": account.account_id,
                        "role": role, "state": account.state})
    return sorted(members, key=lambda member: (member["accountId"], member["role"]))

  def _active_tenant_admins(self, tenant_id, accounts=None):
    """Accounts holding an active tenant_admin membership in the tenant: what "the last admin" counts."""
    return {member["accountId"] for member in self._members(tenant_id, accounts)
            if member["role"] == "tenant_admin" and member["state"] == _ACTIVE_STATE}

  def _row(self, tenant, accounts=None):
    # Called only with an authorized published row or the verified activation result.
    members = self._members(tenant["tenant_id"], accounts)
    # RM-084 P7: an archived member is not a member for counting; the counts state present access.
    active = [m for m in members if m["state"] == _ACTIVE_STATE]
    return {"tenantId": tenant["tenant_id"], "displayName": tenant["display_name"], "domainId": tenant["domain_id"],
            "lifecycle": "active", "memberCount": len({m["accountId"] for m in active}),
            "adminCount": len({m["accountId"] for m in active if m["role"] == "tenant_admin"}),
            "allowPentester": tenant["allow_pentester"], "createdBy": tenant["created_by"],
            "rootAdminId": tenant.get("root_admin_id"),
            "createdAt": tenant["created_at"], "lastActivityAt": None}

  def _detail(self, tenant, account):
    detail = {**self._row(tenant), "assetCount": self.store.count_assets(tenant["tenant_id"]),
              "nodeFailurePolicy": self._node_failure_policy(tenant),
              "canUpdateNodeFailurePolicy": authorize_tenant_operation(
                account, "node_failure_policy:update", TenantPolicyContext(
                  tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed,
              "canUpdateAllowPentester": authorize_tenant_operation(
                account, "allow_pentester:update", TenantPolicyContext(
                  tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed,
              "canManageMembers": authorize_tenant_operation(
                account, "tenant_users:manage", TenantPolicyContext(
                  tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed,
              "assignableMemberRoles": self._assignable_member_roles(account, tenant)}
    for stored, public in (("allow_pentester_changed_by", "allowPentesterChangedBy"),
                           ("allow_pentester_changed_at", "allowPentesterChangedAt"),
                           ("node_failure_policy_changed_by", "nodeFailurePolicyChangedBy"),
                           ("node_failure_policy_changed_at", "nodeFailurePolicyChangedAt")):
      if stored in tenant:
        detail[public] = tenant[stored]
    return detail

  @_endpoint
  def list_tenants(self, actor):
    account = self._actor(actor)
    visible = []
    for tenant in self.store.list_tenants():
      roles, denial = resolve_tenant_roles(account, tenant["tenant_id"])
      if denial is None and roles:
        self._validate_tenant(tenant)
        visible.append(tenant)
    if not visible:
      return []
    accounts = self.accounts.list_accounts()
    return [self._row(tenant, accounts) for tenant in sorted(visible, key=lambda row: row["tenant_id"])]

  @_endpoint
  def get_tenant(self, actor, tenant_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    return self._detail(tenant, account)

  @_endpoint
  def update_tenant_allow_pentester(self, actor, tenant_id, allow_pentester):
    tenant, account = self._authorized_tenant(actor, tenant_id, "allow_pentester:update")
    if type(allow_pentester) is not bool:
      raise AdministrationDenied(400, "invalid_request")
    if tenant["allow_pentester"] is allow_pentester:
      return self._detail(tenant, account)
    tenant = {**tenant, "allow_pentester": allow_pentester,
              "allow_pentester_changed_by": account.account_id,
              "allow_pentester_changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant", tenant_id, record=tenant)
    return self._detail(tenant, account)

  @_endpoint
  def update_tenant_node_failure_policy(self, actor, tenant_id, node_failure_policy):
    tenant, account = self._authorized_tenant(actor, tenant_id, "node_failure_policy:update")
    if not isinstance(node_failure_policy, str) or node_failure_policy not in ("stop", "continue"):
      raise AdministrationDenied(400, "invalid_request")
    if self._node_failure_policy(tenant) == node_failure_policy:
      return self._detail(tenant, account)
    tenant = {**tenant, "node_failure_policy": node_failure_policy,
              "node_failure_policy_changed_by": account.account_id,
              "node_failure_policy_changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant", tenant_id, record=tenant)
    return self._detail(tenant, account)

  @_endpoint
  def get_tenant_members(self, actor, tenant_id):
    self._authorized_tenant(actor, tenant_id, "tenant_users:manage")
    return self._members(tenant_id)

  def resolve_execution_admission(self, actor, tenant_id, asset_id, selected_peers=None, *,
                                  expected_target_digest=None):
    """Resolve current stored facts only; no endpoint, publication, DNS or execution."""
    return self._resolve_execution_admission_for_account(self._actor(actor), tenant_id, asset_id,
      selected_peers, expected_target_digest=expected_target_digest)

  def _execution_asset_for_account(self, account, tenant_id, asset_id, expected_target_digest):
    tenant, account = self.authorize_tenant_for_account(account, tenant_id)
    policy = TenantPolicyContext(tenant_id, tenant["active"], tenant["allow_pentester"])
    _, denial = resolve_operation_roles(account, "tasks:launch", policy)
    if denial:
      raise AdministrationDenied(denial.status_code, denial.error)
    if not account.account_generation:
      raise AdministrationDenied(409, "account_changed")
    asset = self.store.get("asset", tenant_id, self._asset_id(asset_id))
    if asset is None or asset["active"] is not True:
      raise AdministrationDenied(404, "not_found")
    decision = authorize_tenant_operation(account, "tasks:launch", policy,
      asset_tenant_ids=(asset["tenant_id"],))
    if not decision.allowed:
      raise AdministrationDenied(decision.status_code, decision.error)
    if expected_target_digest is not None:
      if not valid_digest(expected_target_digest):
        raise AdministrationDenied(400, "invalid_request")
      if expected_target_digest != asset["target_digest"]:
        raise AdministrationDenied(409, "target_changed")
    return tenant, asset

  def _execution_eligible_nodes(self, tenant_id):
    assignments = self.store.list_node_assignments(tenant_id)
    try:
      configured = self.configured_peers_reader()
    except Exception as exc:
      raise TenantStoreError("Node eligibility is unavailable") from exc
    if not isinstance(configured, list) or any(not valid_node_address(peer) for peer in configured):
      raise TenantStoreError("Node eligibility is unavailable")
    eligible = {row["node_address"] for row in assignments if row["active"]} & set(configured)
    return sorted(eligible)

  def _resolve_execution_admission_for_account(self, account, tenant_id, asset_id, selected_peers=None, *,
                                               expected_target_digest=None):
    tenant, asset = self._execution_asset_for_account(account, tenant_id, asset_id, expected_target_digest)
    eligible = self._execution_eligible_nodes(tenant_id)
    if selected_peers is not None and (not isinstance(selected_peers, list)
        or any(not valid_node_address(peer) for peer in selected_peers)
        or len(set(selected_peers)) != len(selected_peers)):
      raise AdministrationDenied(400, "invalid_request")
    selected = list(selected_peers) if selected_peers else sorted(eligible)
    if not selected or not set(selected).issubset(eligible):
      raise AdministrationDenied(400, "ineligible_node")
    try:
      return ResolvedExecutionContext({"namespace": self.store.namespace, "tenant_id": tenant_id,
        "asset_id": asset["asset_id"], "asset_target": asset["target"],
        "asset_target_digest": asset["target_digest"], "actor_id": account.account_id,
        "actor_generation": account.account_generation,
        "node_failure_policy": self._node_failure_policy(tenant), "selected_candidates": selected,
        **({"asset_authorized_ports": asset["authorized_ports"]} if "authorized_ports" in asset else {})})
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Invalid stored execution facts") from exc

  def reauthorize_execution(self, binding, *, worker_node=None):
    """Re-read original execution authority; preserve every field in the saved binding."""
    try:
      saved = (binding if isinstance(binding, ExecutionBinding) else ExecutionBinding(binding)).to_dict()
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(409, "invalid_execution_binding") from None
    if saved["namespace"] != self.store.namespace:
      raise AdministrationDenied(404, "not_found")
    account = self._actor({"account_id": saved["actor_id"]})
    if account.account_generation != saved["actor_generation"]:
      raise AdministrationDenied(409, "account_changed")
    _, asset = self._execution_asset_for_account(account, saved["tenant_id"], saved["asset_id"],
      saved["asset_target_digest"])
    eligible = self._execution_eligible_nodes(saved["tenant_id"])
    if worker_node is not None and (not valid_node_address(worker_node)
        or worker_node not in saved["participant_order"] or worker_node not in eligible):
      raise AdministrationDenied(403, "ineligible_node")
    try:
      return CurrentExecutionFacts({"namespace": self.store.namespace, "tenant_id": saved["tenant_id"],
        "asset_id": asset["asset_id"], "asset_target": asset["target"],
        "asset_target_digest": asset["target_digest"], "actor_id": account.account_id,
        "actor_generation": account.account_generation, "eligible_nodes": eligible})
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Invalid current execution facts") from exc

  @_endpoint
  def get_tenant_nodes(self, actor, tenant_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    assignments = self.store.list_node_assignments(tenant_id)
    return {"tenantId": tenant_id,
            "nodes": [{"nodeAddress": row["node_address"]} for row in
                      sorted(assignments, key=lambda row: row["node_address"]) if row["active"]],
            "canManageAssignments": authorize_tenant_operation(
              account, "node_assignments:manage", TenantPolicyContext(
                tenant_id, tenant["active"], tenant["allow_pentester"])).allowed}

  @staticmethod
  def _asset_row(row):
    if row is None:
      raise TenantStoreError("Asset readback is unavailable")
    return {"tenantId": row["tenant_id"], "assetId": row["asset_id"],
            "displayName": row["display_name"], "target": row["target"], "active": row["active"],
            "createdBy": row["created_by"], "createdAt": row["created_at"],
            "changedBy": row["changed_by"], "changedAt": row["changed_at"],
            "targetDigest": row["target_digest"], "version": canonical_digest(row),
            **({"authorizedPorts": row["authorized_ports"]} if "authorized_ports" in row else {})}

  @staticmethod
  def _asset_id(value):
    if not isinstance(value, str) or not value.startswith("as_"):
      raise AdministrationDenied(400, "invalid_request")
    return "as_" + _request_id(value[3:])

  @staticmethod
  def _asset_permission(account, tenant, operation):
    return authorize_tenant_operation(account, operation, TenantPolicyContext(
      tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed

  @_endpoint
  def list_tenant_assets(self, actor, tenant_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    return {"tenantId": tenant_id,
            "assets": [self._asset_row(row) for row in sorted(self.store.list_assets(tenant_id),
                                                              key=lambda row: row["asset_id"])],
            "canCreateAssets": self._asset_permission(account, tenant, "assets:create"),
            "canUpdateAssets": self._asset_permission(account, tenant, "assets:update")}

  @_endpoint
  def get_tenant_asset(self, actor, tenant_id, asset_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    asset_id = self._asset_id(asset_id)
    row = self.store.get("asset", tenant_id, asset_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return {"asset": self._asset_row(row),
            "canUpdateAssets": self._asset_permission(account, tenant, "assets:update"),
            "canLaunchJobs": row["active"] is True and authorize_tenant_operation(
              account, "tasks:launch", TenantPolicyContext(
                tenant["tenant_id"], tenant["active"], tenant["allow_pentester"]),
              asset_tenant_ids=(row["tenant_id"],)).allowed}

  @_endpoint
  def create_tenant_asset(self, actor, tenant_id, request_id, display_name, target, authorized_ports=None):
    _, account = self._authorized_tenant(actor, tenant_id, "assets:create")
    request_id = _request_id(request_id)
    try:
      display_name, target = normalize_name(display_name), normalize_target(target)
      scope = _port_scope_for(target, authorized_ports)
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(400, "invalid_request") from None
    asset_id = "as_" + request_id
    # The scope joins the intent only when set, so an unscoped create replays to the same digest.
    intent = {"namespace": self.store.namespace, "tenant_id": tenant_id, "asset_id": asset_id,
              "request_id": request_id, "created_by": account.account_id,
              "display_name": display_name, "target": target,
              **({"authorized_ports": scope} if scope is not None else {})}
    existing = self.store.get("asset", tenant_id, asset_id)
    if existing is not None:
      if existing["create_intent_digest"] != canonical_digest(intent) or existing["created_by"] != account.account_id:
        raise AdministrationDenied(409, "conflict")
      return self._asset_row(existing)
    now = datetime.now(timezone.utc).isoformat()
    self.store.put("asset", tenant_id, asset_id, record={
      **intent, "active": True, "create_intent_digest": canonical_digest(intent),
      "created_at": now, "changed_by": account.account_id, "changed_at": now,
      "target_digest": canonical_digest(target)})
    return self._asset_row(self.store.get("asset", tenant_id, asset_id))

  @_endpoint
  def update_tenant_asset(self, actor, tenant_id, asset_id, expected_version, display_name, target, active,
                          authorized_ports=KEEP_PORT_SCOPE):
    _, account = self._authorized_tenant(actor, tenant_id, "assets:update")
    asset_id = self._asset_id(asset_id)
    try:
      display_name, target = normalize_name(display_name), normalize_target(target)
      if type(active) is not bool or not valid_digest(expected_version):
        raise ValueError("Invalid desired state")
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(400, "invalid_request") from None
    row = self.store.get("asset", tenant_id, asset_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    if row["target"]["kind"] != target["kind"]:
      raise AdministrationDenied(400, "invalid_request")
    try:
      scope = (row.get("authorized_ports") if authorized_ports == KEEP_PORT_SCOPE
               else _port_scope_for(target, authorized_ports))
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(400, "invalid_request") from None
    if ((row["display_name"], row["target"], row["active"], row.get("authorized_ports"))
        == (display_name, target, active, scope)):
      return self._asset_row(row)
    if canonical_digest(row) != expected_version:
      raise AdministrationDenied(409, "conflict")
    record = {
      **row, "display_name": display_name, "target": target, "active": active,
      "target_digest": canonical_digest(target), "changed_by": account.account_id,
      "changed_at": datetime.now(timezone.utc).isoformat()}
    record.pop("authorized_ports", None)
    if scope is not None:
      record["authorized_ports"] = scope
    self.store.put("asset", tenant_id, asset_id, record=record)
    return self._asset_row(self.store.get("asset", tenant_id, asset_id))

  @staticmethod
  def _integration_row(row):
    if row is None:
      raise TenantStoreError("Integration readback is unavailable")
    return {"tenantId": row["tenant_id"], "integrationId": row["integration_id"],
            "enabled": row["enabled"],
            "config": public_integration_config(row["integration_id"], row["config"]),
            "updatedBy": row["updated_by"], "updatedAt": row["updated_at"],
            "version": canonical_digest(row)}

  @staticmethod
  def _integration_id(value):
    # A node-level id is refused with its own reason rather than a bare not_found, so an operator
    # who asks for suricata learns it is node-level instead of assuming the tenant is broken.
    if isinstance(value, str) and value in NODE_LEVEL_INTEGRATION_IDS:
      raise AdministrationDenied(400, "integration_not_tenant_scoped")
    if not valid_integration_id(value):
      raise AdministrationDenied(404, "not_found")
    return value

  @_endpoint
  def list_tenant_integrations(self, actor, tenant_id):
    """Every tenant-scopable id, configured or not, so the surface never hides an unset one."""
    _, _account = self._authorized_tenant(actor, tenant_id, "integrations:manage")
    stored = {row["integration_id"]: row for row in self.store.list_integrations(tenant_id)}
    return {"tenantId": tenant_id,
            "integrations": [self._integration_row(stored[integration_id])
                             if integration_id in stored
                             else {"tenantId": tenant_id, "integrationId": integration_id,
                                   "enabled": False, "config": None, "updatedBy": None,
                                   "updatedAt": None, "version": None}
                             for integration_id in integration_ids()]}

  @_endpoint
  def get_tenant_integration(self, actor, tenant_id, integration_id):
    self._authorized_tenant(actor, tenant_id, "integrations:manage")
    integration_id = self._integration_id(integration_id)
    row = self.store.get("integration", tenant_id, integration_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return {"integration": self._integration_row(row)}

  @_endpoint
  def put_tenant_integration(self, actor, tenant_id, integration_id, enabled, config,
                             expected_version=None):
    """Replace one tenant's config for one integration. Absent expected_version means first write."""
    _, account = self._authorized_tenant(actor, tenant_id, "integrations:manage")
    integration_id = self._integration_id(integration_id)
    try:
      if type(enabled) is not bool:
        raise ValueError("Invalid desired state")
      config = normalize_integration_config(integration_id, config)
      if expected_version is not None and not valid_digest(expected_version):
        raise ValueError("Invalid expected version")
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(400, "invalid_request") from None
    row = self.store.get("integration", tenant_id, integration_id)
    if (row is None) != (expected_version is None):
      raise AdministrationDenied(409, "conflict")
    if row is not None:
      if canonical_digest(row) != expected_version:
        raise AdministrationDenied(409, "conflict")
      if (row["enabled"], row["config"]) == (enabled, config):
        return self._integration_row(row)
    self.store.put("integration", tenant_id, integration_id, record={
      "tenant_id": tenant_id, "integration_id": integration_id, "enabled": enabled,
      "config": config, "updated_by": account.account_id,
      "updated_at": datetime.now(timezone.utc).isoformat()})
    return self._integration_row(self.store.get("integration", tenant_id, integration_id))

  @_endpoint
  def set_tenant_node_assignment(self, actor, tenant_id, node_address, active):
    _, account = self._authorized_tenant(actor, tenant_id, "node_assignments:manage")
    if not valid_node_address(node_address) or type(active) is not bool:
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("tenant_node", tenant_id, node_address)
    if active:
      try:
        peers = self.configured_peers_reader()
      except Exception as exc:
        raise TenantStoreError("Node eligibility is unavailable") from exc
      if not isinstance(peers, list) or any(not valid_node_address(peer) for peer in peers):
        raise TenantStoreError("Node eligibility is unavailable")
      if node_address not in peers:
        raise AdministrationDenied(400, "ineligible_node")
    elif row is None:
      raise AdministrationDenied(404, "not_found")
    if row is None or row["active"] is not active:
      row = {**(row or {}), "tenant_id": tenant_id, "node_address": node_address,
             "active": active, "changed_by": account.account_id,
             "changed_at": datetime.now(timezone.utc).isoformat()}
      self.store.put("tenant_node", tenant_id, node_address, record=row)
    return {"tenantId": tenant_id, "nodeAddress": node_address, "active": active}

  @_endpoint
  def check_tenant_domain(self, actor, domain_id):
    self._actor(actor, creator=True)
    return {"available": self.store.get("domain", _domain(domain_id)) is None}

  def _assignable_member_roles(self, account, tenant):
    """RM-083. Roles this caller may write in the tenant; tenant_pentester is the platform's to give."""
    if not authorize_tenant_operation(account, "tenant_users:manage", TenantPolicyContext(
        tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed:
      return []
    if holds_platform_role(account):
      return sorted(_MEMBER_ROLES)
    return sorted(_MEMBER_ROLES - _PLATFORM_RESERVED_MEMBER_ROLES)

  @_endpoint
  def authorize_tenant_account_creation(self, actor, tenant_id, account_id, role):
    """RM-083. Every account is born scoped: approve a new account together with its one membership.

    Nothing is written here; the Navigator creates the account with this membership in the same
    record write, so no unscoped account exists between two steps.
    """
    tenant, caller = self._authorized_tenant(actor, tenant_id, "tenant_users:manage")
    account_id = canonical_account_id(account_id)
    if not account_id or not isinstance(role, str) or role not in _MEMBER_ROLES:
      raise AdministrationDenied(400, "invalid_membership")
    if role not in self._assignable_member_roles(caller, tenant):
      raise AdministrationDenied(403, "pentester_role_reserved")
    if self.accounts.get_account(account_id) is not None:
      raise AdministrationDenied(409, "account_exists")
    return {"accountId": account_id, "tenantId": tenant_id, "role": role}

  @_endpoint
  def authorize_tenant_membership(self, actor, tenant_id, account_id, role, remove=False):
    tenant, caller = self._authorized_tenant(actor, tenant_id, "tenant_users:manage")
    account_id = canonical_account_id(account_id)
    if not account_id or not isinstance(role, str) or role not in _MEMBER_ROLES or type(remove) is not bool:
      raise AdministrationDenied(400, "invalid_membership")
    target = self._initial_admin(account_id)
    platform_admin = holds_platform_role(caller)
    if not platform_admin:
      # RM-083. Below the platform, membership administration is confined to the tenant's own members:
      # attaching an outside account would make it resettable by this tenant's admins (a takeover).
      if not any(m.tenant_id == tenant_id and m.role in _MEMBER_ROLES for m in target.tenant_memberships):
        raise AdministrationDenied(403, "not_a_member")
      # A write replaces every local role the target holds in the tenant, so touching a pentester at
      # all -- granting, removing or overwriting the role -- is the platform's decision.
      if (role in _PLATFORM_RESERVED_MEMBER_ROLES
          or any(m.tenant_id == tenant_id and m.role in _PLATFORM_RESERVED_MEMBER_ROLES
                 for m in target.tenant_memberships)):
        raise AdministrationDenied(403, "pentester_role_reserved")
    removes_admin = (role == "tenant_admin" if remove else role != "tenant_admin")
    if removes_admin and TenantMembership("tenant_admin", tenant_id) in target.tenant_memberships:
      others = self._active_tenant_admins(tenant_id) - {account_id}
      if not others:
        raise AdministrationDenied(409, "last_tenant_admin")
      # RM-082. The root tenant administrator's admin membership is the founder's to give up, or a
      # Super-Tenant Admin's to take; a peer tenant admin removing it is the same takeover the
      # password-reset rule refuses (§Root tenant administrator).
      if (tenant.get("root_admin_id") == account_id and caller.account_id != account_id
          and not platform_admin):
        raise AdministrationDenied(403, "root_tenant_admin")
    # RM-083 (owner, 2026-09-17). The write must leave the account with exactly one scope: a platform
    # account or another tenant's member cannot join this tenant, and a member's last role is not
    # removable (an account never exists with no scope).
    current = tuple(target.tenant_memberships)
    if remove:
      if current == (TenantMembership(role, tenant_id),):
        raise AdministrationDenied(409, "last_membership")
    else:
      kept = tuple(m for m in current if not (m.tenant_id == tenant_id and m.role in _MEMBER_ROLES))
      if not valid_account_scope((m.role, m.tenant_id) for m in kept + (TenantMembership(role, tenant_id),)):
        raise AdministrationDenied(409, "scope_conflict")
    return {"accountId": account_id, "accountGeneration": target.account_generation,
            "tenantId": tenant_id, "role": role, "remove": remove}

  @_endpoint
  def authorize_account_state_change(self, actor, account_id, state, tenant_id=None):
    """RM-084 P7. Approve archiving (deactivating) or restoring an account; nothing is written here.

    The rules are `redmesh-auth.md` §9, checked in its order so the first denial is the one the
    operator sees. The Navigator writes the state with the generation returned here, which is what
    makes the decision and the write one operation: a record that moved meanwhile is refused there.
    """
    caller = self._actor(actor)
    account_id = canonical_account_id(account_id)
    if not account_id or state not in _ACCOUNT_STATES:
      raise AdministrationDenied(400, "invalid_request")
    target = self.accounts.get_account(account_id)
    # Not `_initial_admin`: restoring an account means reading one that is deactivated.
    if target is None or target.state not in _ACCOUNT_STATES:
      raise AdministrationDenied(404, "not_found")
    if not target.account_generation:
      raise AdministrationDenied(409, "account_changed")
    if target.account_id == caller.account_id:
      raise AdministrationDenied(403, "self")
    rows = tuple(target.tenant_memberships)
    if tenant_id is not None and any(m.tenant_id != tenant_id for m in rows):
      # The tenant route names the workspace it acts in; a target outside it is not its business.
      raise AdministrationDenied(404, "not_found")
    deactivating = state == _DEACTIVATED_STATE and target.state == _ACTIVE_STATE

    if holds_platform_role(caller):
      if deactivating and holds_platform_role(target) and not self._other_active_platform_admins(account_id):
        raise AdministrationDenied(409, "last_super_tenant_admin")
      target_tenants = {m.tenant_id for m in rows if m.tenant_id is not None}
      for tenant in target_tenants:
        self._refuse_last_tenant_admin(tenant, account_id, rows, deactivating)
      return {"accountId": account_id, "accountGeneration": target.account_generation, "state": state}

    # A none-scope account is the platform's alone: a tenant admin cannot even see one.
    if not rows:
      raise AdministrationDenied(404, "not_found")
    scope = {m.tenant_id for m in caller.tenant_memberships if m.tenant_id is not None}
    if len(scope) != 1:
      raise AdministrationDenied(404, "not_found")
    tenant_of_caller = next(iter(scope))
    try:
      tenant, _ = self.authorize_tenant_for_account(caller, tenant_of_caller, "tenant_users:manage")
    except AdministrationDenied:
      # §9: a caller who may not manage this tenant's users is told nothing about the account.
      raise AdministrationDenied(404, "not_found")
    if any(m.tenant_id != tenant_of_caller or m.role not in _MEMBER_ROLES for m in rows):
      raise AdministrationDenied(403, "not_a_member")
    if any(m.role in _PLATFORM_RESERVED_MEMBER_ROLES for m in rows):
      raise AdministrationDenied(403, "pentester_role_reserved")
    is_admin = TenantMembership("tenant_admin", tenant_of_caller) in rows
    # RM-082: the founder is not a peer's to archive, and with no recorded founder no tenant admin is.
    if tenant.get("root_admin_id") == account_id or (tenant.get("root_admin_id") is None and is_admin):
      raise AdministrationDenied(403, "root_tenant_admin")
    self._refuse_last_tenant_admin(tenant_of_caller, account_id, rows, deactivating)
    return {"accountId": account_id, "accountGeneration": target.account_generation, "state": state}

  def _other_active_platform_admins(self, account_id):
    return {account.account_id for account in self.accounts.list_accounts()
            if account.state == _ACTIVE_STATE and account.account_id != account_id
            and holds_platform_role(account)}

  def _refuse_last_tenant_admin(self, tenant_id, account_id, rows, deactivating):
    """Owner, 2026-09-20: no caller, the platform included, leaves a tenant with no active admin."""
    if not deactivating or TenantMembership("tenant_admin", tenant_id) not in rows:
      return
    if not self._active_tenant_admins(tenant_id) - {account_id}:
      raise AdministrationDenied(409, "last_tenant_admin")
