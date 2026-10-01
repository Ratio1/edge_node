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
from .nodes import NODE_ASSIGNMENT_MODES, node_assignment_mode, valid_node_address
from .assets import canonical_digest, normalize_name, valid_digest
from .integrations import (NODE_LEVEL_INTEGRATION_IDS, integration_ids,
                           normalize_integration_config, public_integration_config,
                           valid_integration_id)
from .engagements import (MAX_ENGAGEMENT_DOCUMENTS, EngagementInvalid, document_id_for, engagement_hash,
                          engagement_id_for, normalize_context, normalize_engagement_assets, normalize_roe,
                          normalize_run_modes, normalize_window, valid_doc_ref, valid_engagement_id)


_ADMINISTRATION_LOCK = RLock()
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


# RM-095 phase 1: a tenant is created around a signed contract and its legal details.
_LEGAL_FIELDS = ("name", "registration_id", "signer_name", "signer_role")
_CONTRACT_TEXT_FIELDS = ("store", "ref", "filename", "mime", "uploaded_at", "uploaded_by")


def _legal(value):
  if not isinstance(value, dict) or set(value) != set(_LEGAL_FIELDS):
    raise AdministrationDenied(400, "legal_details_required")
  legal = {}
  for key in _LEGAL_FIELDS:
    text = value[key].strip() if isinstance(value[key], str) else ""
    if not 1 <= len(text) <= 200:
      raise AdministrationDenied(400, "legal_details_required")
    legal[key] = text
  return legal


def _valid_contract(value):
  return (isinstance(value, dict)
          and set(value) == {*_CONTRACT_TEXT_FIELDS, "sha256", "size_bytes"}
          and all(isinstance(value[key], str) and value[key] for key in _CONTRACT_TEXT_FIELDS)
          and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
          and type(value["size_bytes"]) is int and value["size_bytes"] > 0)


def _same_contract(stored, requested):
  # Same bytes, same contract: a re-upload of the file gets a new reference (the envelope carries its
  # upload time), and a retry after a page reload must still be the same creation. The receipt keeps
  # the reference it was first created with.
  return (isinstance(stored, dict) and isinstance(requested, dict)
          and stored.get("sha256") == requested.get("sha256"))


class TenantAdministrationService:
  def __init__(self, accounts, store, configured_peers_reader=None, tenant_node_jobs_reader=None):
    self.accounts = accounts
    self.store = store
    self.configured_peers_reader = configured_peers_reader
    # RM-102: `(tenant_id, node_address) -> bool`, whether the tenant still has a running job on
    # the node. Injected like `configured_peers_reader`; a draining row is read at every point that
    # matters, never written by a background sweep.
    self.tenant_node_jobs_reader = tenant_node_jobs_reader
    # The engagement window is checked against this clock at launch (a test seam).
    self.clock = lambda: datetime.now(timezone.utc)

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
      if "legal" in receipt and _legal(receipt["legal"]) != receipt["legal"]:
        raise AdministrationDenied(400, "legal_details_required")
    except AdministrationDenied:
      raise TenantStoreError("Invalid creation receipt") from None
    if "contract" in receipt and not _valid_contract(receipt["contract"]):
      raise TenantStoreError("Invalid creation receipt")
    return receipt

  @staticmethod
  def _binding(receipt):
    return {key: receipt[key] for key in ("actor_id", "request_id", "tenant_id")}

  @staticmethod
  def _tenant_payload(receipt):
    # RM-095: `legal` and `contract` exist only on tenants created since contracts were required;
    # the tenant copies them from its receipt, so both sides match exactly or not at all.
    contract_terms = {key: receipt[key] for key in ("legal", "contract") if key in receipt}
    return {**contract_terms,
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
      # RM-107: a retried creation or activation must not bring back a tenant being deleted.
      if "deleting" in tenant:
        raise AdministrationDenied(409, "tenant_deleting")
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
  def prepare_tenant(self, actor, request_id, display_name, domain_id, initial_admin_id, legal=None,
                     contract=None):
    """`contract` is the document reference `services.tenant_contract.resolve_contract` verified
    outside this lock; this method never reads the document store."""
    creator = self._actor(actor, creator=True)
    request_id = _request_id(request_id)
    domain_id = _domain(domain_id)
    initial_admin_id = canonical_account_id(initial_admin_id)
    if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 120 or not initial_admin_id:
      raise AdministrationDenied(400, "invalid_request")
    legal = _legal(legal)
    if contract is None:
      raise AdministrationDenied(400, "contract_required")
    if not _valid_contract(contract) or contract["uploaded_by"] != creator.account_id:
      raise AdministrationDenied(400, "contract_invalid")
    intent = {"display_name": display_name.strip(), "domain_id": domain_id, "initial_admin_id": initial_admin_id}
    receipt = self._receipt(creator.account_id, request_id)
    if receipt is not None:
      if (any(receipt.get(key) != value for key, value in intent.items())
          or receipt.get("legal") != legal or not _same_contract(receipt.get("contract"), contract)):
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
      receipt = {**intent, "legal": legal, "contract": dict(contract),
                 "actor_id": creator.account_id, "request_id": request_id,
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
    detail = {**self._row(tenant), "nodeFailurePolicy": self._node_failure_policy(tenant),
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

  def resolve_execution_admission(self, actor, tenant_id, engagement_id, engagement_asset_id,
                                  selected_peers=None):
    """Resolve current stored facts only; no endpoint, publication, DNS or execution."""
    return self._resolve_execution_admission_for_account(self._actor(actor), tenant_id, engagement_id,
      engagement_asset_id, selected_peers)

  def _execution_entry_for_account(self, account, tenant_id, engagement_id, engagement_asset_id):
    """RM-107: the engagement row and the asset entry a job runs on; the entry is the target."""
    tenant, account = self.authorize_tenant_for_account(account, tenant_id)
    policy = TenantPolicyContext(tenant_id, tenant["active"], tenant["allow_pentester"])
    _, denial = resolve_operation_roles(account, "tasks:launch", policy)
    if denial:
      raise AdministrationDenied(denial.status_code, denial.error)
    if not account.account_generation:
      raise AdministrationDenied(409, "account_changed")
    engagement_id = self._engagement_id(engagement_id)
    if not isinstance(engagement_asset_id, str) or not re.fullmatch(r"ea_[1-9][0-9]*", engagement_asset_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("engagement", tenant_id, engagement_id)
    if row is None:
      raise AdministrationDenied(404, "engagement_not_found")
    decision = authorize_tenant_operation(account, "tasks:launch", policy, asset_tenant_ids=(row["tenant_id"],))
    if not decision.allowed:
      raise AdministrationDenied(decision.status_code, decision.error)
    entry = next((item for item in row["assets"] if item["engagement_asset_id"] == engagement_asset_id), None)
    if entry is None:
      raise AdministrationDenied(400, "engagement_asset_not_locked")
    return tenant, account, row, entry

  def _tenant_node_has_jobs(self, tenant_id, node_address):
    """RM-102: whether tenant jobs still run on the node, read fresh through the injected reader.
    A missing reader or a failed read is unavailable, never "no jobs" -- a release or an
    eligibility read must not cut off a job it cannot actually see."""
    if self.tenant_node_jobs_reader is None:
      raise TenantStoreError("Node job state is unavailable")
    try:
      running = self.tenant_node_jobs_reader(tenant_id, node_address)
    except Exception as exc:
      raise TenantStoreError("Node job state is unavailable") from exc
    if type(running) is not bool:
      raise TenantStoreError("Node job state is unavailable")
    return running

  def _assignment_live(self, tenant_id, row):
    """RM-102: a draining row counts as released once its tenant's jobs are gone -- re-evaluated
    here, never written by a background sweep. The reader is called only for a draining row."""
    if row["active"] is not True:
      return False
    if not row.get("draining"):
      return True
    return self._tenant_node_has_jobs(tenant_id, row["node_address"])

  def _configured_peers(self):
    try:
      configured = self.configured_peers_reader()
    except Exception as exc:
      raise TenantStoreError("Node eligibility is unavailable") from exc
    if not isinstance(configured, list) or any(not valid_node_address(peer) for peer in configured):
      raise TenantStoreError("Node eligibility is unavailable")
    return set(configured)

  def _launch_eligible_nodes(self, tenant_id):
    """RM-102: a launch never starts on a draining row, whatever a (possibly stale) job check
    would say -- it is the reauthorization path that must never cut off a running job, not this one."""
    assignments = self.store.list_node_assignments(tenant_id)
    eligible = {row["node_address"] for row in assignments if row["active"] and not row.get("draining")}
    return sorted(eligible & self._configured_peers())

  def _reauth_eligible_nodes(self, tenant_id):
    """RM-102: reauthorization keeps a draining row eligible, with no job check -- a stale local
    job view must never be the reason a still-running job is cut off."""
    assignments = self.store.list_node_assignments(tenant_id)
    eligible = {row["node_address"] for row in assignments if row["active"]}
    return sorted(eligible & self._configured_peers())

  def _execution_engagement(self, tenant, row, entry):
    """The launch gate's engagement facts, from the stored row (never the DTO, which has no refs).

    Refusals follow the engagements contract. RM-107: the authorization is the tenant contract the
    engagement was created under, so it is read from the tenant and must still be it.
    """
    if row["active"] is not True:
      raise AdministrationDenied(400, "engagement_revoked")
    now = self.clock()
    if not (datetime.fromisoformat(row["valid_from"]) <= now < datetime.fromisoformat(row["valid_until"])):
      raise AdministrationDenied(400, "engagement_expired")
    contract, legal = tenant.get("contract"), tenant.get("legal")
    if (not _valid_contract(contract) or not isinstance(legal, dict)
        or contract["sha256"] != row["contract_sha256"]):
      # The contract cannot change after creation (there is no attach operation): a mismatch is a
      # damaged record, never a reason to launch under a different signed basis.
      raise TenantStoreError("Engagement contract does not match its tenant")
    facts = {
      "engagement_id": row["engagement_id"], "engagement_hash": row["engagement_hash"],
      "contract_sha256": row["contract_sha256"],
      "authorized_tests": list(entry["authorized_tests"]), "roe": dict(row["roe"]),
      "context": row["context"], "allowed_run_modes": list(row["allowed_run_modes"]),
      # `AuthorizationRef` shape, so reports, exports and SIEM hooks read the job snapshot as
      # before. The signed basis is the tenant contract, signed by the tenant's legal signer. No
      # document reference: the job is readable under `reports:view`, while the contract itself is
      # Super-Tenant Admin only (`download_tenant_contract`).
      "authorization": {
        "document_cid": "",
        "document_thumbnail_cid": "",
        "authorized_signer_name": legal["signer_name"],
        "authorized_signer_role": legal["signer_role"],
        "third_party_auth_cids": [document["title"] for document in row["documents"]
                                  if document["kind"] == "third_party_consent"],
        "document_filename": contract["filename"], "document_mime": contract["mime"],
        "document_size_bytes": contract["size_bytes"], "document_sha256": contract["sha256"],
        "document_uploaded_at": contract["uploaded_at"],
      },
    }
    if entry["kind"] != "network":
      return facts, None
    return {**facts, "authorized_scan_modes": list(entry["authorized_scan_modes"])}, entry["authorized_ports"]

  @staticmethod
  def _entry_facts(row, entry):
    return {"engagement_id": row["engagement_id"], "engagement_asset_id": entry["engagement_asset_id"],
            "engagement_hash": row["engagement_hash"], "asset_target": entry["target"],
            "asset_target_digest": entry["target_digest"]}

  def _resolve_execution_admission_for_account(self, account, tenant_id, engagement_id, engagement_asset_id,
                                               selected_peers=None):
    tenant, account, row, entry = self._execution_entry_for_account(
      account, tenant_id, engagement_id, engagement_asset_id)
    engagement, ports = self._execution_engagement(tenant, row, entry)
    eligible = self._launch_eligible_nodes(tenant_id)
    if selected_peers is not None and (not isinstance(selected_peers, list)
        or any(not valid_node_address(peer) for peer in selected_peers)
        or len(set(selected_peers)) != len(selected_peers)):
      raise AdministrationDenied(400, "invalid_request")
    selected = list(selected_peers) if selected_peers else sorted(eligible)
    if not selected or not set(selected).issubset(eligible):
      raise AdministrationDenied(400, "ineligible_node")
    try:
      return ResolvedExecutionContext({"namespace": self.store.namespace, "tenant_id": tenant_id,
        **self._entry_facts(row, entry), "actor_id": account.account_id,
        "actor_generation": account.account_generation,
        "node_failure_policy": self._node_failure_policy(tenant), "selected_candidates": selected,
        "engagement": engagement, **({"asset_authorized_ports": ports} if ports is not None else {})})
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Invalid stored execution facts") from exc

  def reauthorize_execution(self, binding, *, worker_node=None):
    """Re-read original execution authority; preserve every field in the saved binding.

    RM-107: authority is the engagement entry the job was bound to, unchanged (same hash, same
    target), plus `tasks:launch` and Allow Pentester. The engagement's window and revoke are not
    checked here: the engagement-end hard stop (`engagement_end_reason`) owns them, so a stop's own
    finalization is never refused. A schema-1 binding (a tenant asset row) is never reauthorized.
    """
    try:
      saved = (binding if isinstance(binding, ExecutionBinding) else ExecutionBinding(binding)).to_dict()
    except (ValueError, TypeError, RecursionError):
      raise AdministrationDenied(409, "invalid_execution_binding") from None
    if saved["schema_version"] != 2:
      raise AdministrationDenied(409, "invalid_execution_binding")
    if saved["namespace"] != self.store.namespace:
      raise AdministrationDenied(404, "not_found")
    account = self._actor({"account_id": saved["actor_id"]})
    if account.account_generation != saved["actor_generation"]:
      raise AdministrationDenied(409, "account_changed")
    _, account, row, entry = self._execution_entry_for_account(
      account, saved["tenant_id"], saved["engagement_id"], saved["engagement_asset_id"])
    current = self._entry_facts(row, entry)
    if any(current[key] != saved[key] for key in current):
      raise AdministrationDenied(409, "invalid_execution_binding")
    # RM-102: eligibility here includes a draining row (no job check); a stale job view on this
    # backend node must never cut off a job that is actually still running.
    eligible = self._reauth_eligible_nodes(saved["tenant_id"])
    if worker_node is not None and (not valid_node_address(worker_node)
        or worker_node not in saved["participant_order"] or worker_node not in eligible):
      raise AdministrationDenied(403, "ineligible_node")
    try:
      return CurrentExecutionFacts({"namespace": self.store.namespace, "tenant_id": saved["tenant_id"],
        **current, "actor_id": account.account_id, "actor_generation": account.account_generation,
        "eligible_nodes": eligible})
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Invalid current execution facts") from exc

  def engagement_end_reason(self, tenant_id, engagement_id):
    """Why an admitted job's engagement no longer covers it, or None while it does.

    RM-095 (owner, 2026-09-28): a continuous job hard-stops when its engagement ends, at
    `valid_until` or on a revoke. System-internal like `reauthorize_execution`: the launcher asks
    it for jobs it already admitted. A store it cannot read raises `TenantStoreError`, so a
    transient outage never reads as an ended engagement.
    """
    if not valid_engagement_id(engagement_id):
      return "engagement_not_found"
    row = self.store.get("engagement", tenant_id, engagement_id)
    if row is None:
      return "engagement_not_found"
    if row["active"] is not True:
      return "engagement_revoked"
    if self.clock() >= datetime.fromisoformat(row["valid_until"]):
      return "engagement_expired"
    return None

  def _tenant_node_row(self, tenant_id, row):
    """RM-102: the read DTO for one live row, or None for a released or a dead-draining one. The
    jobs reader is called only for a draining row."""
    if row["active"] is not True:
      return None
    if row.get("draining"):
      if not self._tenant_node_has_jobs(tenant_id, row["node_address"]):
        return None
      state = "draining"
    else:
      state = "assigned"
    return {"nodeAddress": row["node_address"], "mode": node_assignment_mode(row), "state": state}

  @_endpoint
  def get_tenant_nodes(self, actor, tenant_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    assignments = self.store.list_node_assignments(tenant_id)
    nodes = [self._tenant_node_row(tenant_id, row) for row in
             sorted(assignments, key=lambda row: row["node_address"])]
    return {"tenantId": tenant_id, "nodes": [node for node in nodes if node is not None],
            "canManageAssignments": authorize_tenant_operation(
              account, "node_assignments:manage", TenantPolicyContext(
                tenant_id, tenant["active"], tenant["allow_pentester"])).allowed}

  @staticmethod
  def _permission(account, tenant, operation):
    return authorize_tenant_operation(account, operation, TenantPolicyContext(
      tenant["tenant_id"], tenant["active"], tenant["allow_pentester"])).allowed

  # RM-095 phase 2: engagements. Created by the platform roles, read by every tenant role, changed
  # only by a revoke. The DTO never carries a document or contract reference: tenant roles read it,
  # and a reference would bypass the download rules (engagement documents: STA and SP only; the
  # tenant contract: STA only).

  @staticmethod
  def _engagement_document(ref):
    return {"sha256": ref["sha256"], "filename": ref["filename"], "mime": ref["mime"],
            "sizeBytes": ref["size_bytes"], "uploadedAt": ref["uploaded_at"]}

  def _engagement_row(self, row):
    if row is None:
      raise TenantStoreError("Engagement readback is unavailable")
    assets = []
    for entry in row["assets"]:
      asset = {"engagementAssetId": entry["engagement_asset_id"], "displayName": entry["display_name"],
               "kind": entry["kind"], "target": entry["target"], "targetDigest": entry["target_digest"],
               "authorizedTests": entry["authorized_tests"]}
      if entry["kind"] == "network":
        asset.update(authorizedPorts=entry["authorized_ports"],
                     authorizedScanModes=entry["authorized_scan_modes"])
      assets.append(asset)
    return {
      "tenantId": row["tenant_id"], "engagementId": row["engagement_id"],
      "displayName": row["display_name"], "allowedRunModes": row["allowed_run_modes"],
      "validFrom": row["valid_from"], "validUntil": row["valid_until"],
      "contractSha256": row["contract_sha256"],
      "documents": [{"documentId": document["document_id"], "kind": document["kind"],
                     "title": document["title"], "comment": document["comment"],
                     **self._engagement_document(document)} for document in row["documents"]],
      "supersedes": row.get("supersedes"), "roe": row["roe"], "context": row["context"],
      "assets": assets, "engagementHash": row["engagement_hash"],
      # No registry function anchors an arbitrary hash yet (owner, 2026-09-28): always pending.
      "anchor": {"status": "pending"},
      "active": row["active"], "createdBy": row["created_by"], "createdAt": row["created_at"],
      **({"revokedBy": row["revoked_by"], "revokedAt": row["revoked_at"],
          "revokeReason": row["revoke_reason"]} if not row["active"] else {}),
    }

  @staticmethod
  def _engagement_id(value):
    if not valid_engagement_id(value):
      raise AdministrationDenied(400, "invalid_request")
    return value

  @staticmethod
  def _tenant_contract_sha256(tenant):
    """RM-107: the tenant contract is the permission an engagement extends, so it must exist.
    Tenants created before contracts were required keep `contract: null` and create no engagement."""
    contract = tenant.get("contract")
    if contract is None:
      raise AdministrationDenied(400, "contract_required")
    if not _valid_contract(contract):
      raise TenantStoreError("Invalid tenant contract record")
    return contract["sha256"]

  @_endpoint
  def authorize_engagement_create(self, actor, tenant_id):
    """The plugin reads the documents outside this lock, and only after this check. Refusing a
    tenant without a contract here spares the uploads and the document reads."""
    tenant, account = self._authorized_tenant(actor, tenant_id, "engagements:create")
    self._tenant_contract_sha256(tenant)
    return {"accountId": account.account_id}

  @staticmethod
  def _engagement_request(display_name, allowed_run_modes, valid_from, valid_until, roe, context, assets,
                          documents, supersedes, creator):
    """The request as sent, normalized without any store read: the replay intent."""
    try:
      display_name = normalize_name(display_name)
    except (ValueError, TypeError):
      raise AdministrationDenied(400, "invalid_request") from None
    try:
      allowed_run_modes = normalize_run_modes(allowed_run_modes)
      if "single_pass" not in allowed_run_modes:
        # RM-107 (owner, 2026-09-28): single pass is always allowed; continuous is the opt-in.
        raise EngagementInvalid("run_modes_invalid")
      valid_from, valid_until = normalize_window(valid_from, valid_until)
      roe, context = normalize_roe(roe), normalize_context(context)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    # The plugin verified every document; the uploader rule is re-checked here (phase-1 precedent).
    # The same file twice is refused: its hash says nothing the first entry did not.
    if (not isinstance(documents, list) or len(documents) > MAX_ENGAGEMENT_DOCUMENTS
        or any(not valid_doc_ref(document, labels=True) or document["uploaded_by"] != creator
               for document in documents)
        or len({document["sha256"] for document in documents}) != len(documents)):
      raise AdministrationDenied(400, "document_invalid")
    if supersedes is not None and not valid_engagement_id(supersedes):
      raise AdministrationDenied(400, "supersedes_invalid")
    # RM-107: the engagement defines its targets; nothing is read from a tenant asset row.
    try:
      assets = normalize_engagement_assets(assets)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    return {"display_name": display_name, "allowed_run_modes": allowed_run_modes, "valid_from": valid_from,
            "valid_until": valid_until, "roe": roe, "context": context,
            "documents": [[document[key] for key in ("kind", "sha256", "title", "comment")]
                          for document in documents],
            "supersedes": supersedes, "assets": assets}

  @_endpoint
  def create_engagement(self, actor, tenant_id, request_id, display_name, allowed_run_modes, valid_from,
                        valid_until, roe, context, assets, documents=None, supersedes=None):
    """`documents` are the references `services.engagement_documents.resolve_engagement_document`
    verified outside this lock, in the order they are numbered (`ed_1`, `ed_2`, ...)."""
    tenant, account = self._authorized_tenant(actor, tenant_id, "engagements:create")
    contract_sha256 = self._tenant_contract_sha256(tenant)
    request_id = _request_id(request_id)
    engagement_id = engagement_id_for(request_id)
    documents = [] if documents is None else documents
    request = self._engagement_request(
      display_name, allowed_run_modes, valid_from, valid_until, roe, context, assets, documents,
      supersedes, account.account_id)
    intent = {"namespace": self.store.namespace, "tenant_id": tenant_id, "engagement_id": engagement_id,
              "request_id": request_id, "created_by": account.account_id, "request": request}
    # Replay is decided on the request alone.
    existing = self.store.get("engagement", tenant_id, engagement_id)
    if existing is not None:
      if existing["create_intent_digest"] != canonical_digest(intent) or existing["created_by"] != account.account_id:
        raise AdministrationDenied(409, "conflict")
      return {**self._engagement_row(existing), "replayed": True}
    if supersedes is not None and (supersedes == engagement_id
                                   or self.store.get("engagement", tenant_id, supersedes) is None):
      raise AdministrationDenied(400, "supersedes_invalid")
    record = {
      "tenant_id": tenant_id, "engagement_id": engagement_id, "request_id": request_id,
      "display_name": request["display_name"], "allowed_run_modes": request["allowed_run_modes"],
      "valid_from": request["valid_from"], "valid_until": request["valid_until"],
      "contract_sha256": contract_sha256,
      "documents": [{"document_id": document_id_for(index), **document}
                    for index, document in enumerate(documents)],
      **({"supersedes": supersedes} if supersedes is not None else {}),
      "roe": request["roe"], "context": request["context"],
      "assets": request["assets"],
      "active": True, "created_by": account.account_id,
      "created_at": datetime.now(timezone.utc).isoformat(),
      "create_intent_digest": canonical_digest(intent),
    }
    record["engagement_hash"] = engagement_hash(record)
    self.store.put("engagement", tenant_id, engagement_id, record=record)
    # `replayed` says whether this call wrote, decided under the lock (the plugin audits on it).
    return {**self._engagement_row(self.store.get("engagement", tenant_id, engagement_id)), "replayed": False}

  @_endpoint
  def list_engagements(self, actor, tenant_id, active=None):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    if active is not None and type(active) is not bool:
      raise AdministrationDenied(400, "invalid_request")
    rows = [row for row in self.store.list_engagements(tenant_id) if active is None or row["active"] is active]
    rows.sort(key=lambda row: row["engagement_id"])
    rows.sort(key=lambda row: row["created_at"], reverse=True)
    return {"tenantId": tenant_id, "engagements": [self._engagement_row(row) for row in rows],
            "canCreateEngagements": self._permission(account, tenant, "engagements:create"),
            "canRevokeEngagements": self._permission(account, tenant, "engagements:revoke")}

  @_endpoint
  def get_engagement(self, actor, tenant_id, engagement_id):
    tenant, account = self._authorized_tenant(actor, tenant_id)
    row = self.store.get("engagement", tenant_id, self._engagement_id(engagement_id))
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return {"engagement": self._engagement_row(row),
            "canRevokeEngagements": self._permission(account, tenant, "engagements:revoke"),
            "canDownloadDocuments": self._permission(account, tenant, "engagements:documents")}

  @_endpoint
  def revoke_engagement(self, actor, tenant_id, engagement_id, reason):
    _, account = self._authorized_tenant(actor, tenant_id, "engagements:revoke")
    engagement_id = self._engagement_id(engagement_id)
    try:
      reason = normalize_name(reason, 500)
    except (ValueError, TypeError):
      raise AdministrationDenied(400, "invalid_request") from None
    row = self.store.get("engagement", tenant_id, engagement_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    if not row["active"]:
      return {**self._engagement_row(row), "replayed": True}
    self.store.put("engagement", tenant_id, engagement_id, record={
      **row, "active": False, "revoked_by": account.account_id,
      "revoked_at": datetime.now(timezone.utc).isoformat(), "revoke_reason": reason})
    return {**self._engagement_row(self.store.get("engagement", tenant_id, engagement_id)), "replayed": False}

  @_endpoint
  def engagement_document_ref(self, actor, tenant_id, engagement_id, document_id):
    """The stored reference for a download; authorized before the engagement is looked up."""
    self._authorized_tenant(actor, tenant_id, "engagements:documents")
    engagement_id = self._engagement_id(engagement_id)
    if not isinstance(document_id, str) or not re.fullmatch(r"ed_[1-9][0-9]*", document_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("engagement", tenant_id, engagement_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    ref = next((document for document in row["documents"] if document["document_id"] == document_id), None)
    if ref is None:
      raise AdministrationDenied(404, "not_found")
    return {"store": ref["store"], "ref": ref["ref"], "sha256": ref["sha256"], "filename": ref["filename"],
            "size_bytes": ref["size_bytes"], "engagement_hash": row["engagement_hash"]}

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

  def _assign_node(self, account, tenant_id, node_address, mode, row):
    """RM-102 conflict precedence for (tenant, node, mode), over every tenant's live row for the
    node: own row draining; own live row, same mode (idempotent); own live row, the other mode;
    another tenant's live private row; private requested while any other live row exists; else
    write. Rows are "live" per `_assignment_live` -- a dead-draining row is released everywhere."""
    others = [other for other in self.store.list_node_assignments_for_node(node_address)
              if self._assignment_live(other["tenant_id"], other)]
    own = next((other for other in others if other["tenant_id"] == tenant_id), None)
    foreign = [other for other in others if other["tenant_id"] != tenant_id]
    if own is not None:
      if own.get("draining"):
        raise AdministrationDenied(409, "node_draining")
      own_mode = node_assignment_mode(own)
      if own_mode == mode:
        return {"tenantId": tenant_id, "nodeAddress": node_address, "active": True,
                "mode": own_mode, "state": "assigned"}
      raise AdministrationDenied(409, "node_private_assigned" if own_mode == "private" else "node_shared_assigned")
    if any(node_assignment_mode(other) == "private" for other in foreign):
      raise AdministrationDenied(409, "node_private_assigned")
    if mode == "private" and foreign:
      raise AdministrationDenied(409, "node_shared_assigned")
    new_row = {**(row or {}), "tenant_id": tenant_id, "node_address": node_address, "active": True,
               "mode": mode, "draining": False, "changed_by": account.account_id,
               "changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_node", tenant_id, node_address, record=new_row)
    return {"tenantId": tenant_id, "nodeAddress": node_address, "active": True, "mode": mode, "state": "assigned"}

  def _release_node(self, account, tenant_id, node_address, row):
    """RM-102 release: inactive is idempotent; an active row with running jobs enters (or stays)
    `draining`; one with none releases, including a draining row whose jobs just ended."""
    if row is None:
      raise AdministrationDenied(404, "not_found")
    if row["active"] is not True:
      return {"tenantId": tenant_id, "nodeAddress": node_address, "active": False,
              "mode": node_assignment_mode(row), "state": "released"}
    if self._tenant_node_has_jobs(tenant_id, node_address):
      if row.get("draining"):
        return {"tenantId": tenant_id, "nodeAddress": node_address, "active": False,
                "mode": node_assignment_mode(row), "state": "draining"}
      new_row = {**row, "active": True, "draining": True, "changed_by": account.account_id,
                 "changed_at": datetime.now(timezone.utc).isoformat()}
    else:
      new_row = {**row, "active": False, "draining": False, "changed_by": account.account_id,
                 "changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_node", tenant_id, node_address, record=new_row)
    return {"tenantId": tenant_id, "nodeAddress": node_address, "active": False,
            "mode": node_assignment_mode(new_row), "state": "draining" if new_row["draining"] else "released"}

  @_endpoint
  def set_tenant_node_assignment(self, actor, tenant_id, node_address, active, mode=None):
    _, account = self._authorized_tenant(actor, tenant_id, "node_assignments:manage")
    if (not valid_node_address(node_address) or type(active) is not bool
        or (mode is not None and mode not in NODE_ASSIGNMENT_MODES)):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("tenant_node", tenant_id, node_address)
    if not active:
      return self._release_node(account, tenant_id, node_address, row)
    try:
      peers = self.configured_peers_reader()
    except Exception as exc:
      raise TenantStoreError("Node eligibility is unavailable") from exc
    if not isinstance(peers, list) or any(not valid_node_address(peer) for peer in peers):
      raise TenantStoreError("Node eligibility is unavailable")
    if node_address not in peers:
      raise AdministrationDenied(400, "ineligible_node")
    return self._assign_node(account, tenant_id, node_address, mode if mode is not None else "shared", row)

  @_endpoint
  def get_tenant_contract(self, actor, tenant_id):
    """RM-095. The tenant's legal details and contract record (never the file), for a full-portfolio
    Super-Tenant Admin only. Tenants created before contracts were required read as not recorded."""
    tenant, account = self._authorized_tenant(actor, tenant_id)
    if not holds_platform_role(account):
      raise AdministrationDenied(403, "forbidden")
    legal, contract = tenant.get("legal"), tenant.get("contract")
    # The receipt binding covers tenants whose receipt carries the terms; this covers the reverse
    # (a record that gained terms its receipt never bound). Both or neither, and well formed.
    if (legal is None) != (contract is None) or (contract is not None and not _valid_contract(contract)):
      raise TenantStoreError("Invalid tenant contract record")
    if legal is not None:
      try:
        valid_legal = _legal(legal) == legal
      except AdministrationDenied:
        valid_legal = False
      if not valid_legal:
        raise TenantStoreError("Invalid tenant contract record")
    return {"legal": legal, "contract": contract}

  # RM-107: delete a tenant. Owner, 2026-09-28: it exists so tenants created before contracts can be
  # removed; it deletes the tenant's records and its stored documents, refuses while the tenant has
  # jobs or members (accounts are the Navigator's records, never deleted here), and keeps the domain
  # reserved. The plugin runs it in steps so every document read and delete is outside this lock and
  # a failed attempt can be retried: `begin_tenant_delete` (check, then mark), the job checks,
  # the document deletes (`record_tenant_documents_deleted`), `finish_tenant_delete`.
  _DELETABLE_KINDS = ("engagement", "integration", "tenant_node")

  def _tenant_for_delete(self, actor, tenant_id):
    account = self._actor(actor)
    _, denial = resolve_tenant_roles(account, tenant_id)
    if denial:
      raise AdministrationDenied(denial.status_code, denial.error)
    tenant = self.store.get("tenant", tenant_id)
    deleting = isinstance(tenant, dict) and isinstance(tenant.get("deleting"), dict)
    if tenant is None or (tenant.get("active") is not True and not deleting):
      raise AdministrationDenied(404, "not_found")
    # A failed `finish_tenant_delete` can leave the marked row after its receipt is gone (the receipt
    # goes first); the marker is then the only binding left, and the retry must still finish.
    if not deleting or self.store.get("receipt", tenant.get("actor_id"), tenant.get("request_id")) is not None:
      self._validate_tenant(tenant)
    elif type(tenant.get("allow_pentester")) is not bool:
      raise TenantStoreError("Invalid administration tenant")
    # A tenant being deleted is inactive to every other operation; the delete itself is authorized
    # as on the live tenant, so a retry after a failed attempt can finish it.
    decision = authorize_tenant_operation(account, "tenants:delete", TenantPolicyContext(
      tenant_id, True, tenant["allow_pentester"]))
    if not decision.allowed:
      raise AdministrationDenied(decision.status_code, decision.error)
    if self._members(tenant_id):
      raise AdministrationDenied(409, "tenant_has_members")
    return tenant, account

  def _tenant_document_refs(self, tenant):
    """Every stored document the tenant's records point at, read from the raw rows."""
    refs = [tenant["contract"]] if isinstance(tenant.get("contract"), dict) else []
    for ids in self.store.tenant_record_ids("engagement", tenant["tenant_id"]):
      row = self.store.raw_record("engagement", *ids) or {}
      documents = row.get("documents") if isinstance(row.get("documents"), list) else []
      refs.extend(documents)
    done = set(tenant.get("deleting", {}).get("deleted_refs", []))
    unique = {}
    for ref in refs:
      if isinstance(ref, dict) and isinstance(ref.get("ref"), str) and ref["ref"] and ref["ref"] not in done:
        unique.setdefault(ref["ref"], {"store": ref.get("store"), "ref": ref["ref"]})
    return [unique[key] for key in sorted(unique)]

  @_endpoint
  def begin_tenant_delete(self, actor, tenant_id, mark=False):
    """Check the delete; with `mark`, make the tenant inactive to everything but this delete."""
    tenant, account = self._tenant_for_delete(actor, tenant_id)
    if mark and not isinstance(tenant.get("deleting"), dict):
      tenant = {**tenant, "active": False, "deleting": {
        "by": account.account_id, "at": datetime.now(timezone.utc).isoformat(), "deleted_refs": []}}
      self.store.put("tenant", tenant_id, record=tenant)
    return {"tenantId": tenant_id, "accountId": account.account_id,
            "marked": isinstance(tenant.get("deleting"), dict),
            "documentRefs": self._tenant_document_refs(tenant)}

  @_endpoint
  def abort_tenant_delete(self, actor, tenant_id):
    """Undo the mark when jobs appeared after it, so they can be purged; never once a document went."""
    tenant, _ = self._tenant_for_delete(actor, tenant_id)
    marker = tenant.get("deleting")
    if isinstance(marker, dict) and not marker.get("deleted_refs"):
      restored = {key: value for key, value in tenant.items() if key != "deleting"}
      self.store.put("tenant", tenant_id, record={**restored, "active": True})
    return {"tenantId": tenant_id}

  @_endpoint
  def record_tenant_documents_deleted(self, actor, tenant_id, refs):
    tenant, _ = self._tenant_for_delete(actor, tenant_id)
    marker = tenant.get("deleting")
    if not isinstance(marker, dict):
      raise AdministrationDenied(409, "conflict")
    deleted = sorted(set(marker.get("deleted_refs", [])) | set(refs))
    self.store.put("tenant", tenant_id, record={**tenant, "deleting": {**marker, "deleted_refs": deleted}})
    return {"tenantId": tenant_id, "deletedRefs": deleted}

  @_endpoint
  def finish_tenant_delete(self, actor, tenant_id):
    """Delete the records. The receipt goes before the tenant row, so a retried `prepare_tenant`
    can never re-create the tenant; the domain reservation stays (owner, 2026-09-28)."""
    tenant, _ = self._tenant_for_delete(actor, tenant_id)
    if not isinstance(tenant.get("deleting"), dict) or self._tenant_document_refs(tenant):
      raise AdministrationDenied(409, "conflict")
    counts = {}
    for kind in self._DELETABLE_KINDS:
      ids = self.store.tenant_record_ids(kind, tenant_id)
      for record_ids in ids:
        self.store.delete(kind, *record_ids)
      counts[kind] = len(ids)
    self.store.delete("receipt", tenant["actor_id"], tenant["request_id"])
    self.store.delete("tenant", tenant_id)
    return {"tenantId": tenant_id, "deleted": True, "engagements": counts["engagement"],
            "integrations": counts["integration"],
            "nodeAssignments": counts["tenant_node"],
            "documents": len(tenant["deleting"]["deleted_refs"])}

  @_endpoint
  def authorize_platform(self, actor):
    """RM-095. The caller is a full-portfolio Super-Tenant Admin; the contract calls do their
    storage I/O outside this lock after it."""
    return {"accountId": self._actor(actor, creator=True).account_id}

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
