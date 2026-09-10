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

from .identity import IdentityStoreError, TenantMembership, canonical_account_id, resolve_actor
from .policy import TenantPolicyContext, authorize_tenant_operation, resolve_tenant_roles
from .ports import TenantStoreError


_ADMINISTRATION_LOCK = RLock()
_MEMBER_ROLES = frozenset({"tenant_admin", "tenant_pentester", "tenant_user"})


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
  def __init__(self, accounts, store):
    self.accounts = accounts
    self.store = store

  def _actor(self, actor, *, creator=False):
    account, denial = resolve_actor(actor, self.accounts)
    if denial:
      raise AdministrationDenied(denial["status_code"], denial["error"])
    if creator and TenantMembership("super_tenant_admin", None) not in account.tenant_memberships:
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
    if (any(tenant.get(key) != value for key, value in expected.items() if key not in ("active", "allow_pentester"))
        or type(tenant.get("active")) is not bool or type(tenant.get("allow_pentester")) is not bool):
      raise TenantStoreError("Tenant receipt binding mismatch")

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
      receipt = {**intent, "actor_id": creator.account_id, "request_id": request_id,
                 "initial_admin_generation": admin.account_generation, "tenant_id": "tn_" + str(uuid4()),
                 "created_at": datetime.now(timezone.utc).isoformat()}
      self.store.put("receipt", creator.account_id, request_id, record=receipt)
      domain, tenant = None, None
    if tenant is None or not tenant["active"]:
      self._initial_admin(initial_admin_id, receipt["initial_admin_generation"])
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
    return self._detail(tenant)

  def _authorized_tenant(self, actor, tenant_id, operation="reports:view"):
    account = self._actor(actor)
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
    return tenant

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
    members = []
    for account in self.accounts.list_accounts() if accounts is None else accounts:
      if not account.active:
        continue
      roles = {m.role for m in account.tenant_memberships if m.tenant_id == tenant_id and m.role in _MEMBER_ROLES}
      for role in sorted(roles):
        members.append({"accountId": account.account_id, "displayName": account.account_id, "role": role})
    return sorted(members, key=lambda member: (member["accountId"], member["role"]))

  def _row(self, tenant, accounts=None):
    # Called only with an authorized published row or the verified activation result.
    members = self._members(tenant["tenant_id"], accounts)
    return {"tenantId": tenant["tenant_id"], "displayName": tenant["display_name"], "domainId": tenant["domain_id"],
            "lifecycle": "active", "memberCount": len({m["accountId"] for m in members}),
            "adminCount": len({m["accountId"] for m in members if m["role"] == "tenant_admin"}),
            "allowPentester": tenant["allow_pentester"], "createdBy": tenant["created_by"],
            "createdAt": tenant["created_at"], "lastActivityAt": None}

  def _detail(self, tenant):
    return {**self._row(tenant), "assetCount": self.store.count_assets(tenant["tenant_id"])}

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
    return self._detail(self._authorized_tenant(actor, tenant_id))

  @_endpoint
  def get_tenant_members(self, actor, tenant_id):
    self._authorized_tenant(actor, tenant_id, "tenant_users:manage")
    return self._members(tenant_id)

  @_endpoint
  def check_tenant_domain(self, actor, domain_id):
    self._actor(actor, creator=True)
    return {"available": self.store.get("domain", _domain(domain_id)) is None}

  @_endpoint
  def authorize_tenant_membership(self, actor, tenant_id, account_id, role, remove=False):
    self._authorized_tenant(actor, tenant_id, "tenant_users:manage")
    account_id = canonical_account_id(account_id)
    if not account_id or not isinstance(role, str) or role not in _MEMBER_ROLES or type(remove) is not bool:
      raise AdministrationDenied(400, "invalid_membership")
    target = self._initial_admin(account_id)
    removes_admin = (role == "tenant_admin" if remove else role != "tenant_admin")
    if removes_admin and TenantMembership("tenant_admin", tenant_id) in target.tenant_memberships:
      others = {member["accountId"] for member in self._members(tenant_id)
                if member["role"] == "tenant_admin" and member["accountId"] != account_id}
      if not others:
        raise AdministrationDenied(409, "last_tenant_admin")
    return {"accountId": account_id, "accountGeneration": target.account_generation,
            "tenantId": tenant_id, "role": role, "remove": remove}
