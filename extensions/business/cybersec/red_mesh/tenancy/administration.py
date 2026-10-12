"""Tenant control plane; memberships remain owned by the account identity provider.

Publication is the final tenant write, not a second receipt update. A verified active tenant is
also the completion marker, so uncertain successful publication cannot cause a retry to re-grant
an initial administrator. The lock/read-backs only mitigate local races; CStore's documented
distributed consistency limitations still apply.
"""
from datetime import datetime, timezone
from functools import wraps
import copy
import json
import re
from threading import RLock
from uuid import UUID, uuid4

from .identity import IdentityStoreError, TenantMembership, canonical_account_id, holds_platform_role, resolve_actor
from .policy import (TENANT_LOCAL_ROLES, TenantPolicyContext, authorize_tenant_operation, resolve_tenant_roles,
                     resolve_operation_roles, valid_account_scope)
from .execution import CurrentExecutionFacts, ExecutionBinding, ResolvedExecutionContext
from .ports import TenantStoreError
from .nodes import NODE_ASSIGNMENT_MODES, node_assignment_mode, valid_node_address
from .deployment_nodes import named_entry
from .assets import canonical_digest, normalize_name, valid_digest
from .integrations import (NODE_LEVEL_INTEGRATION_IDS, integration_ids,
                           normalize_integration_config, public_integration_config,
                           valid_integration_id)
from .engagements import (MAX_ENGAGEMENT_DOCUMENTS, EngagementInvalid, document_id_for, engagement_hash,
                          engagement_id_for, normalize_asset_requests, normalize_context,
                          build_engagement_assets, normalize_engagement_assets, normalize_window, valid_doc_ref, valid_engagement_id)
from . import drafts, engagement_drafts, super_tenant_profile, tenant_assets, tenant_contracts


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
  def __init__(self, status_code, error, **details):
    self.status_code = status_code
    self.error = error
    # RM-109: a refusal may carry what the caller needs to act on it (`missing`, `holder`).
    self.details = details


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
      # Details first: they never override the fixed keys of the refusal.
      return {**exc.details, "success": False, "status": "error", "status_code": exc.status_code,
              "error": exc.error}
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


# RM-095 phase 1: a tenant is created around a signed contract and its legal details. RM-110: the
# party block may carry the optional customer fields too (`drafts.LEGAL_OPTIONAL_FIELDS`, empty
# allowed); a block written before them has the four keys only and is accepted as it is.
_LEGAL_FIELDS = drafts.LEGAL_FIELDS
_LEGAL_OPTIONAL_FIELDS = drafts.LEGAL_OPTIONAL_FIELDS
_CONTRACT_TEXT_FIELDS = ("store", "ref", "filename", "mime", "uploaded_at", "uploaded_by")


def _legal(value):
  """The normalized party block: exactly the keys given (the four required ones 1-200, an optional
  one 0-200), so a stored four-key block reads back unchanged and no default is written."""
  if (not isinstance(value, dict) or not set(_LEGAL_FIELDS) <= set(value)
      or not set(value) <= set(drafts.LEGAL_ALL_FIELDS)):
    raise AdministrationDenied(400, "legal_details_required")
  legal = {}
  for key in drafts.LEGAL_ALL_FIELDS:
    if key not in value:
      continue
    text = value[key].strip() if isinstance(value[key], str) else ""
    if not (0 if key in _LEGAL_OPTIONAL_FIELDS else 1) <= len(text) <= 200:
      raise AdministrationDenied(400, "legal_details_required")
    legal[key] = text
  return legal


def _legal_input(value):
  """RM-132: the one-step `prepare_tenant` party block as the caller sent it: `_legal`, then the
  contact formats. Only here: `_legal` alone is also the stored-row check, and a block written
  before the formats existed must keep reading, activating and replaying."""
  legal = _legal(value)
  try:
    return {**legal, **{key: drafts.LEGAL_FORMATS[key](legal[key]) for key in drafts.LEGAL_FORMATS if key in legal}}
  except drafts.DraftInvalid as exc:
    raise AdministrationDenied(400, exc.code) from None


def _legal_dto(legal):
  """RM-110: a stored block answers every party field, the optional ones empty when absent."""
  return None if legal is None else {**{key: "" for key in _LEGAL_OPTIONAL_FIELDS}, **legal}


def _valid_generated_block(value):
  """RM-110 `contract_generated` on a receipt or tenant: when the key is there, a full block. RM-127:
  with the nodes the pack printed, when it was generated since."""
  return value is not None and drafts.valid_generated(value, with_nodes=True)


def _contract_blocks(tenant):
  """RM-133: the tenant's further contracts (`contracts[c_<n>]`), validated, in id order; `{}` for a
  row written before the map existed. A malformed block fails the read closed."""
  blocks = tenant.get("contracts")
  if blocks is None:
    return {}
  if (not isinstance(blocks, dict)
      or any(not tenant_contracts.valid_block(contract_id, block, _valid_contract) for contract_id, block in blocks.items())):
    raise TenantStoreError("Invalid tenant contracts record")
  return {contract_id: blocks[contract_id] for contract_id in tenant_contracts.sorted_ids(blocks)}


def _contract_nodes(tenant):
  """RM-127: the nodes the tenant's generated contract printed; empty for a one-step tenant and for
  one activated from a pack generated before RM-127. RM-133: the union over `c_1` and every further
  contract, active or superseded (nothing is released); one entry per node."""
  nodes = list((tenant.get("contract_generated") or {}).get("nodes") or ())
  seen = {entry["node_address"] for entry in nodes}
  for block in _contract_blocks(tenant).values():
    for entry in block["nodes"]:
      if entry["node_address"] not in seen:
        seen.add(entry["node_address"])
        nodes.append(dict(entry))
  return nodes


def _contract_sha256s(tenant):
  """RM-133: the sha256 of every contract of the tenant, `c_1` first."""
  contract = tenant.get("contract")
  return ([contract["sha256"]] if _valid_contract(contract) else []) + [
    block["contract"]["sha256"] for block in _contract_blocks(tenant).values()]


def _valid_contract(value):
  return (isinstance(value, dict)
          and set(value) == {*_CONTRACT_TEXT_FIELDS, "sha256", "size_bytes"}
          and all(isinstance(value[key], str) and value[key] for key in _CONTRACT_TEXT_FIELDS)
          and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
          and type(value["size_bytes"]) is int and value["size_bytes"] > 0)


# RM-109: what a draft activation adds to the receipt; the tenant copies all but the draft id.
_DRAFT_TENANT_FIELDS = ("compliance_types", "framework_agreement", "data_handling", "governance")
_DRAFT_RECEIPT_FIELDS = ("draft_id", *_DRAFT_TENANT_FIELDS)
_TENANT_DOCUMENT_KINDS = ("contract", "framework_agreement", "data_handling")


def _same_contract(stored, requested):
  # Same bytes, same contract: a re-upload of the file gets a new reference (the envelope carries its
  # upload time), and a retry after a page reload must still be the same creation. The receipt keeps
  # the reference it was first created with.
  return (isinstance(stored, dict) and isinstance(requested, dict)
          and stored.get("sha256") == requested.get("sha256"))


class TenantAdministrationService:
  def __init__(self, accounts, store, configured_peers_reader=None, tenant_node_jobs_reader=None,
               node_directory_reader=None, super_tenant_permissions_reader=None):
    self.accounts = accounts
    self.store = store
    self.configured_peers_reader = configured_peers_reader
    # RM-132: `() -> {key: bool}`, the deployment's `SUPER_TENANT_PERMISSIONS` (read-only here, set
    # by Ratio1). Injected like `configured_peers_reader`; without one, every key is `True`.
    self.super_tenant_permissions_reader = super_tenant_permissions_reader
    # RM-126: `[address] -> {address: {"alias", "tags"}}`, the network monitor's names for the
    # configured peers. Injected like `configured_peers_reader`; it only decorates reads, so a
    # missing or failing reader names nothing and never fails a read.
    self.node_directory_reader = node_directory_reader
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
        # RM-112: a tenant activated from a draft may have no initial admin; both fields are then None.
        or "initial_admin_id" not in receipt or "initial_admin_generation" not in receipt
        or (receipt["initial_admin_id"] is None) != (receipt["initial_admin_generation"] is None)
        or (receipt["initial_admin_id"] is not None
            and (canonical_account_id(receipt["initial_admin_id"]) != receipt["initial_admin_id"]
                 or not receipt["initial_admin_id"]
                 or not isinstance(receipt["initial_admin_generation"], str)
                 or not receipt["initial_admin_generation"]))
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
    # RM-110: the contract's generated baseline, optional and outside the all-or-none set below, so
    # receipts written before it stay valid.
    if "contract_generated" in receipt and not _valid_generated_block(receipt["contract_generated"]):
      raise TenantStoreError("Invalid creation receipt")
    # RM-109: a receipt of a draft activation carries the draft's terms, all of them or none.
    if any(key in receipt for key in _DRAFT_RECEIPT_FIELDS):
      if (any(key not in receipt for key in _DRAFT_RECEIPT_FIELDS)
          or not drafts.valid_draft_id(receipt["draft_id"])
          or not isinstance(receipt["compliance_types"], list) or not receipt["compliance_types"]
          or drafts.normalize_compliance_types(receipt["compliance_types"]) != receipt["compliance_types"]
          or any(receipt[key] is not None and not _valid_contract(receipt[key])
                 for key in ("framework_agreement", "data_handling"))
          or not drafts.valid_governance(receipt["governance"])):
        raise TenantStoreError("Invalid creation receipt")
    return receipt

  @staticmethod
  def _binding(receipt):
    return {key: receipt[key] for key in ("actor_id", "request_id", "tenant_id")}

  @staticmethod
  def _tenant_payload(receipt):
    # RM-095: `legal` and `contract` exist only on tenants created since contracts were required;
    # the tenant copies them from its receipt, so both sides match exactly or not at all. RM-109:
    # the same for the terms a draft activation adds (the draft id stays on the receipt); RM-110:
    # and for the contract's generated baseline.
    contract_terms = {key: receipt[key] for key in ("legal", "contract", *_DRAFT_TENANT_FIELDS, "contract_generated")
                      if key in receipt}
    return {**contract_terms,
      "tenant_id": receipt["tenant_id"], "actor_id": receipt["actor_id"],
      "request_id": receipt["request_id"], "display_name": receipt["display_name"],
      "domain_id": receipt["domain_id"], "created_by": receipt["actor_id"],
      "created_at": receipt["created_at"], "active": False, "allow_pentester": False,
      "node_failure_policy": "stop",
      # The tenant's root administrator: the account the tenant was created around. Recorded so a
      # tenant admin cannot reset the founder's credential and take the tenant over. Tenants created
      # before this field existed simply do not carry it; absence means "unknown", never "anyone".
      # RM-112: None for a tenant activated without an admin, for good.
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
        or any(key in tenant and key not in expected for key in (*_DRAFT_TENANT_FIELDS, "contract_generated"))
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
  def prepare_tenant(self, actor, request_id, display_name=None, domain_id=None, initial_admin_id=None, legal=None,
                     contract=None, draft_id=None, draft_documents=None):
    """`contract` is the document reference `services.tenant_contract.resolve_contract` verified
    outside this lock; this method never reads the document store.

    RM-109: with `draft_id` every creation field comes from the draft and the caller's are
    ignored; `draft_documents` are the draft's refs as `resolve_draft_document` verified them.
    """
    creator = self._actor(actor, creator=True)
    request_id = _request_id(request_id)
    if draft_id is not None:
      draft, intent, legal, contract, terms = self._draft_terms(creator, request_id, draft_id, draft_documents)
    else:
      draft, terms = None, {}
      domain_id = _domain(domain_id)
      initial_admin_id = canonical_account_id(initial_admin_id)
      if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 120 or not initial_admin_id:
        raise AdministrationDenied(400, "invalid_request")
      legal = _legal_input(legal)
      if contract is None:
        raise AdministrationDenied(400, "contract_required")
      if not _valid_contract(contract):
        raise AdministrationDenied(400, "contract_invalid")
      intent = {"display_name": display_name.strip(), "domain_id": domain_id, "initial_admin_id": initial_admin_id}
    domain_id, initial_admin_id = intent["domain_id"], intent["initial_admin_id"]
    receipt = self._receipt(creator.account_id, request_id)
    if receipt is not None:
      if (any(receipt.get(key) != value for key, value in intent.items())
          or receipt.get("legal") != legal or not _same_contract(receipt.get("contract"), contract)
          or not self._same_draft_terms(receipt, terms)):
        raise AdministrationDenied(409, "request_conflict")
      domain, tenant = self._reserved_tenant(receipt)
    else:
      if self.store.get("domain", domain_id) is not None:
        raise AdministrationDenied(409, "domain_conflict")
      # RM-112: a draft activation may name no admin; then no account is read or touched.
      admin = self._initial_admin(initial_admin_id) if initial_admin_id is not None else None
      # RM-083. The initial administrator becomes this tenant's account; one that already holds any
      # scope (platform or another tenant) cannot take a second. Only on first preparation: a retry
      # finds its own tenant_admin membership already written.
      if admin is not None and admin.tenant_memberships:
        raise AdministrationDenied(409, "scope_conflict")
      documents = {"contract": contract, **{kind: terms[kind] for kind in _TENANT_DOCUMENT_KINDS[1:] if kind in terms}}
      self._first_preparation_documents(documents)
      if draft is not None and draft["activation"] is None:
        # The marker goes before the receipt, so every receipt of a draft has one.
        self.store.put("tenant_draft", draft["draft_id"], record={
          **draft, "activation": {"actor_id": creator.account_id, "request_id": request_id,
                                  "started_at": datetime.now(timezone.utc).isoformat()},
          "last_release": None})
      receipt = {**intent, "legal": legal, "contract": dict(contract), **terms,
                 "actor_id": creator.account_id, "request_id": request_id,
                 "initial_admin_generation": admin.account_generation if admin is not None else None,
                 "tenant_id": "tn_" + str(uuid4()),
                 "created_at": datetime.now(timezone.utc).isoformat()}
      self.store.put("receipt", creator.account_id, request_id, record=receipt)
      domain, tenant = None, None
    if tenant is None or not tenant["active"]:
      if initial_admin_id is not None:
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

  def _draft_terms(self, creator, request_id, draft_id, draft_documents):
    """RM-109 locked step of `prepare_tenant` with a draft, in the contract's order: the refs the
    plugin resolved are still the draft's, the marker, completeness; then the creation fields."""
    draft = self._tenant_draft(draft_id)
    stored = {kind: draft["items"][kind]["document"] for kind in drafts.DOCUMENT_KINDS}
    # RM-110: the generated baseline is re-verified by the plugin too, as `activate_engagement_draft`
    # does for its pack; its stored ref is the block's document part.
    stored["contract_generated"] = self._generated_ref(draft["items"]["contract"]["generated"])
    resolved = draft_documents if isinstance(draft_documents, dict) else {}
    if set(resolved) - set(stored) or {key: resolved.get(key) for key in stored} != stored:
      raise AdministrationDenied(409, "draft_changed")
    marker = draft["activation"]
    if marker is not None and (marker["actor_id"], marker["request_id"]) != (creator.account_id, request_id):
      raise AdministrationDenied(409, "activation_in_progress",
                                 holder={"actor_id": marker["actor_id"], "started_at": marker["started_at"]})
    completeness = drafts.completeness(draft)
    if not completeness["complete"]:
      raise AdministrationDenied(409, "draft_incomplete", missing=completeness["missing"])
    # RM-112: the draft's "" (no admin) is None on the intent, the receipt and the tenant.
    intent = {"display_name": draft["display_name"], "domain_id": _domain(draft["domain_id"]),
              "initial_admin_id": draft["initial_admin_id"] or None}
    terms = {"draft_id": draft_id, "compliance_types": list(draft["compliance_types"]),
             "framework_agreement": stored["framework_agreement"], "data_handling": stored["data_handling"],
             "governance": drafts.governance(draft)}
    # RM-110: the unsigned baseline outlives the draft as the tenant's `contract_generated`; a draft
    # whose pack was never generated adds nothing.
    if draft["items"]["contract"]["generated"] is not None:
      terms["contract_generated"] = copy.deepcopy(draft["items"]["contract"]["generated"])
    return draft, intent, _legal(draft["legal"]), stored["contract"], terms

  @staticmethod
  def _same_draft_terms(receipt, terms):
    """A replay carries the same draft terms as its receipt; documents compare by bytes."""
    if not terms:
      return not any(key in receipt for key in _DRAFT_RECEIPT_FIELDS)
    return (receipt.get("draft_id") == terms["draft_id"]
            and receipt.get("compliance_types") == terms["compliance_types"]
            and receipt.get("governance") == terms["governance"]
            and all((receipt.get(key) is None) == (terms.get(key) is None)
                    and (terms.get(key) is None or _same_contract(receipt[key], terms[key]))
                    for key in (*_TENANT_DOCUMENT_KINDS[1:], "contract_generated")))

  def _first_preparation_documents(self, documents):
    """RM-109, both paths, first preparation only (a replay is bound by its receipt's sha256):
    every uploader holds the full-portfolio Super-Tenant Admin role now, and no file is already the
    document of a tenant or a creation receipt (`contract_in_use`)."""
    for kind, document in documents.items():
      if document is None:
        continue
      refusal = "contract_invalid" if kind == "contract" else "document_invalid"
      if not _valid_contract(document):
        raise AdministrationDenied(400, refusal)
      uploader = self.accounts.get_account(document["uploaded_by"])
      if uploader is None or not uploader.active or not holds_platform_role(uploader):
        raise AdministrationDenied(400, refusal)
    self._refuse_documents_in_use({document["ref"] for document in documents.values() if document is not None})

  def _refuse_documents_in_use(self, wanted, exclude=None):
    """RM-109 `contract_in_use` over every tenant document slot of the tenant and receipt rows;
    RM-133: and over the further contracts' blocks and every contract draft's files (`exclude`: the
    draft being activated, whose own files are wanted). Raw rows: a row the validator refuses may
    still hold the reference."""
    for kind in ("tenant", "receipt"):
      for row in self.store.raw_rows(kind):
        for slot in _TENANT_DOCUMENT_KINDS:
          bound = row.get(slot)
          if isinstance(bound, dict) and bound.get("ref") in wanted:
            raise AdministrationDenied(409, "contract_in_use")
        blocks = row.get("contracts") if isinstance(row.get("contracts"), dict) else {}
        for block in blocks.values():
          for key in ("contract", "contract_generated"):
            bound = block.get(key) if isinstance(block, dict) else None
            if isinstance(bound, dict) and bound.get("ref") in wanted:
              raise AdministrationDenied(409, "contract_in_use")
    for row in self.store.raw_rows("tenant_contract_draft"):
      if (row.get("tenant_id"), row.get("contract_id")) == exclude:
        continue
      for key in ("document", "generated"):
        bound = row.get(key)
        if isinstance(bound, dict) and bound.get("ref") in wanted:
          raise AdministrationDenied(409, "contract_in_use")

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
      if receipt["initial_admin_id"] is not None:
        admin = self._initial_admin(receipt["initial_admin_id"], receipt["initial_admin_generation"])
        if TenantMembership("tenant_admin", receipt["tenant_id"]) not in admin.tenant_memberships:
          raise AdministrationDenied(409, "initial_admin_required")
      self._assign_contract_nodes(creator, tenant, _contract_nodes(tenant))
      tenant = {**tenant, "active": True}
      self.store.put("tenant", receipt["tenant_id"], record=tenant)
    return self._detail(tenant, creator)

  def _assign_contract_nodes(self, account, tenant, nodes):
    """RM-127: assign every node the contract printed, before the tenant turns active. All are checked
    first (eligibility as `set_tenant_node_assignment`, conflicts as `_assign_node`; the draft's own
    private plan holds for this tenant), and any refusal writes nothing. A replay after a crash
    part-way finds its own rows assigned and fills the gaps; a release removes them. RM-133: `nodes`
    is the list to assign (the tenant's union, or one further contract's plan), so a node the tenant
    already holds in the same mode is the existing assignment and another mode is refused."""
    if not nodes:
      return
    peers = self._configured_peers()
    failures = []
    for entry in nodes:
      address = entry["node_address"]
      error = "ineligible_node" if address not in peers else \
        self._assignment_conflict(tenant["tenant_id"], address, entry["mode"])[0]
      if error not in (None, "assigned"):
        failures.append({"nodeAddress": address, "error": error})
    if failures:
      raise AdministrationDenied(409, "contract_nodes_unavailable", nodes=failures)
    for entry in nodes:
      address = entry["node_address"]
      self._assign_node(account, tenant["tenant_id"], address, entry["mode"],
                        self.store.get("tenant_node", tenant["tenant_id"], address))

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
    # RM-112: live assignments, as `get_tenant_nodes` lists them (a dead-draining row is released).
    node_count = sum(1 for row in self.store.list_node_assignments(tenant["tenant_id"])
                     if self._assignment_live(tenant["tenant_id"], row))
    return {"tenantId": tenant["tenant_id"], "displayName": tenant["display_name"], "domainId": tenant["domain_id"],
            "lifecycle": "active", "memberCount": len({m["accountId"] for m in active}),
            "nodeCount": node_count,
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
              "assignableMemberRoles": self._assignable_member_roles(account, tenant),
              # RM-133: every contract of the tenant, hashes and dates only (no file name, no ref).
              "contracts": self._contracts_dto(tenant)}
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

  def _configured_peer_list(self):
    """The configured peers, validated, in configured order (RM-126 lists them in that order)."""
    try:
      configured = self.configured_peers_reader()
    except Exception as exc:
      raise TenantStoreError("Node eligibility is unavailable") from exc
    if not isinstance(configured, list) or any(not valid_node_address(peer) for peer in configured):
      raise TenantStoreError("Node eligibility is unavailable")
    return list(configured)

  def _configured_peers(self):
    return set(self._configured_peer_list())

  def _node_directory(self, addresses):
    """RM-126: names for `addresses` from the injected reader; nothing on a missing or failing one."""
    addresses = list(addresses)
    if self.node_directory_reader is None or not addresses:
      return {}
    try:
      directory = self.node_directory_reader(addresses)
    except Exception:
      return {}
    return directory if isinstance(directory, dict) else {}

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
    # RM-133: the engagement was created under one of the tenant's contracts (`c_1` or a further
    # one, superseded included); the contract cannot change after creation (there is no attach
    # operation), so a sha256 outside the set is a damaged record, never a reason to launch under a
    # different signed basis.
    if (not _valid_contract(contract) or not isinstance(legal, dict)
        or row["contract_sha256"] not in _contract_sha256s(tenant)):
      raise TenantStoreError("Engagement contract does not match its tenant")
    facts = {
      "engagement_id": row["engagement_id"], "engagement_hash": row["engagement_hash"],
      "contract_sha256": row["contract_sha256"],
      "context": row["context"],
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
    return facts

  @staticmethod
  def _entry_facts(row, entry):
    return {"engagement_id": row["engagement_id"], "engagement_asset_id": entry["engagement_asset_id"],
            "engagement_hash": row["engagement_hash"], "asset_target": entry["target"],
            "asset_target_digest": entry["target_digest"]}

  def _entry_environment(self, entry):
    """RM-131: the registered asset's environment for the launch policy. The asset is locked once
    the engagement names it, so the live row is the agreed one; a missing row or an unset value is
    `None`, which the launch policy holds to `prod`."""
    asset_id = entry.get("asset_id")
    row = self.store.get("tenant_asset", asset_id) if tenant_assets.valid_asset_id(asset_id) else None
    environment = row.get("environment") if row is not None else None
    return environment if environment in tenant_assets.ENVIRONMENTS else None

  def _resolve_execution_admission_for_account(self, account, tenant_id, engagement_id, engagement_asset_id,
                                               selected_peers=None):
    tenant, account, row, entry = self._execution_entry_for_account(
      account, tenant_id, engagement_id, engagement_asset_id)
    engagement = self._execution_engagement(tenant, row, entry)
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
        "engagement": engagement, "asset_environment": self._entry_environment(entry)})
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
    nodes = [node for node in nodes if node is not None]
    # RM-126: the tenant's own nodes carry their name and tags, under the read the caller already has.
    directory = self._node_directory(node["nodeAddress"] for node in nodes)
    # RM-127: a tenant whose contract lists its nodes keeps them; amendments will change them.
    fixed = bool(_contract_nodes(tenant))
    return {"tenantId": tenant_id,
            "nodes": [{**node, **named_entry(directory, node["nodeAddress"])} for node in nodes],
            "canManageAssignments": not fixed and authorize_tenant_operation(
              account, "node_assignments:manage", TenantPolicyContext(
                tenant_id, tenant["active"], tenant["allow_pentester"])).allowed,
            "nodesFixed": fixed}

  @_endpoint
  def list_deployment_nodes(self, actor):
    """RM-126: the configured peers, in configured order, each with the network monitor's alias and
    tags (`alias` null when the node has not seen the peer). A full-portfolio Super-Tenant Admin
    read: this is the deployment's whole node list, which no tenant-scoped read or error carries.
    A malformed configuration is unavailable, as for eligibility."""
    self._actor(actor, creator=True)
    peers = self._configured_peer_list()
    directory = self._node_directory(peers)
    return {"nodes": [{"nodeAddress": peer, **named_entry(directory, peer)} for peer in peers]}

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
    assets = [{"engagementAssetId": entry["engagement_asset_id"], "assetId": entry["asset_id"],
               "displayName": entry["display_name"], "kind": entry["kind"], "target": entry["target"],
               "targetDigest": entry["target_digest"]} for entry in row["assets"]]
    return {
      "tenantId": row["tenant_id"], "engagementId": row["engagement_id"],
      "displayName": row["display_name"],
      "validFrom": row["valid_from"], "validUntil": row["valid_until"],
      "contractSha256": row["contract_sha256"],
      "documents": [{"documentId": document["document_id"], "kind": document["kind"],
                     "title": document["title"], "comment": document["comment"],
                     **self._engagement_document(document)} for document in row["documents"]],
      "supersedes": row.get("supersedes"), "context": row["context"],
      "assets": assets, "engagementHash": row["engagement_hash"],
      # No registry function anchors an arbitrary hash yet (owner, 2026-09-28): always pending.
      "anchor": {"status": "pending"},
      "active": row["active"], "createdBy": row["created_by"], "createdAt": row["created_at"],
      **({"revokedBy": row["revoked_by"], "revokedAt": row["revoked_at"],
          "revokeReason": row["revoke_reason"]} if not row["active"] else {}),
    }

  @staticmethod
  def _engagement_id(value):
    if engagement_drafts.valid_engagement_draft_id(value):
      # RM-109 phase 4: an engagement draft id is never an engagement id.
      raise AdministrationDenied(404, "not_found")
    if not valid_engagement_id(value):
      raise AdministrationDenied(400, "invalid_request")
    return value

  @staticmethod
  def _tenant_contract_sha256(tenant, contract_id=None):
    """RM-107: the tenant contract is the permission an engagement extends, so it must exist.
    Tenants created before contracts were required keep `contract: null` and create no engagement.
    RM-133: with `contract_id`, that contract of the tenant (`c_1` or a `contracts[*]` block); an id
    the tenant does not hold, or a malformed one, is `contract_unknown`."""
    contract = tenant.get("contract")
    if contract is None:
      raise AdministrationDenied(400, "contract_required")
    if not _valid_contract(contract):
      raise TenantStoreError("Invalid tenant contract record")
    if contract_id is None or contract_id == tenant_contracts.FIRST_CONTRACT_ID:
      # RM-133 step 3: a replaced contract takes no new engagement (its own keep running).
      if tenant.get("contract_superseded_by") is not None:
        raise AdministrationDenied(409, "contract_superseded")
      return contract["sha256"]
    if not tenant_contracts.valid_contract_id(contract_id):
      raise AdministrationDenied(400, "contract_unknown")
    block = _contract_blocks(tenant).get(contract_id)
    if block is None:
      raise AdministrationDenied(400, "contract_unknown")
    if block["superseded_by"] is not None:
      raise AdministrationDenied(409, "contract_superseded")
    return block["contract"]["sha256"]

  @staticmethod
  def _contract_lineage(tenant, contract_id):
    """RM-133 step 3: `(exists, superseded_by, nodes)` of one contract of the set, `c_1` included."""
    if contract_id == tenant_contracts.FIRST_CONTRACT_ID:
      if tenant.get("contract") is None:
        return False, None, []
      return True, tenant.get("contract_superseded_by"), list((tenant.get("contract_generated") or {}).get("nodes") or ())
    block = _contract_blocks(tenant).get(contract_id)
    if block is None:
      return False, None, []
    return True, block["superseded_by"], list(block["nodes"])

  def _contracts_dto(self, tenant):
    """RM-133: the member-visible contract list, `c_1` synthesized from the tenant's own fields,
    then the further contracts in id order; `[]` for a tenant without a contract."""
    contract = tenant.get("contract")
    if contract is None:
      return []
    effective = ((tenant.get("governance") or {}).get("effective") or {}).get("contract") or {}
    entries = [tenant_contracts.contract_entry(
      tenant_contracts.FIRST_CONTRACT_ID, contract, tenant.get("contract_generated"), effective,
      (tenant.get("contract_generated") or {}).get("nodes") or [], None, tenant.get("contract_superseded_by"))]
    for contract_id, block in _contract_blocks(tenant).items():
      entries.append(tenant_contracts.contract_entry(
        contract_id, block["contract"], block["contract_generated"],
        {key: block[key] for key in ("effective_from", "effective_until")}, block["nodes"],
        block["supersedes"], block["superseded_by"]))
    return entries

  @_endpoint
  def authorize_engagement_create(self, actor, tenant_id, contract_id=None, pick=False):
    """The plugin reads the documents outside this lock, and only after this check. Refusing a
    tenant without a contract here spares the uploads and the document reads. RM-133: with `pick`,
    the contract the creation names (`contract_id`, `c_1` when absent) must be one the tenant holds
    and nobody replaced; an upload, made before the pick is known, needs only a contract."""
    tenant, account = self._authorized_tenant(actor, tenant_id, "engagements:create")
    if pick:
      self._tenant_contract_sha256(tenant, None if contract_id in (None, "") else contract_id)
    elif tenant.get("contract") is None:
      raise AdministrationDenied(400, "contract_required")
    return {"accountId": account.account_id}

  @staticmethod
  def _engagement_request(display_name, valid_from, valid_until, context, assets,
                          documents, supersedes, creator, contract_id=None):
    """The request as sent, normalized without any store read: the replay intent. RM-109 phase 4:
    `creator` None skips the uploader rule (an engagement draft's packs are checked for the platform
    role instead, by `activate_engagement_draft`). RM-133: `contract_id` enters the intent only when
    it was sent, so a request made before the pick existed replays unchanged."""
    try:
      display_name = normalize_name(display_name)
    except (ValueError, TypeError):
      raise AdministrationDenied(400, "invalid_request") from None
    try:
      valid_from, valid_until = normalize_window(valid_from, valid_until)
      context = normalize_context(context)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    # The plugin verified every document; the uploader rule is re-checked here (phase-1 precedent).
    # The same file twice under one kind is refused: its hash says nothing the first entry did not.
    # RM-128: across kinds it is allowed, so the generated pack (`other`) may be the signed copy.
    if (not isinstance(documents, list) or len(documents) > MAX_ENGAGEMENT_DOCUMENTS
        or any(not valid_doc_ref(document, labels=True)
               or (creator is not None and document["uploaded_by"] != creator)
               for document in documents)
        or len({(document["kind"], document["sha256"]) for document in documents}) != len(documents)):
      raise AdministrationDenied(400, "document_invalid")
    if supersedes is not None and not valid_engagement_id(supersedes):
      raise AdministrationDenied(400, "supersedes_invalid")
    # RM-125 phase 2b: only the request form `{asset_id}`, so the replay intent
    # needs no store read; `_engagement_assets` copies the asset rows at write time, after the replay.
    try:
      assets = normalize_asset_requests(assets)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    return {"display_name": display_name, "valid_from": valid_from, "valid_until": valid_until,
            "context": context,
            "documents": [[document[key] for key in ("kind", "sha256", "title", "comment")]
                          for document in documents],
            "supersedes": supersedes, "assets": assets,
            **({"contract_id": contract_id} if contract_id is not None else {})}

  @_endpoint
  def create_engagement(self, actor, tenant_id, request_id, display_name, valid_from,
                        valid_until, context, assets, documents=None, supersedes=None, contract_id=None):
    """`documents` are the references `services.engagement_documents.resolve_engagement_document`
    verified outside this lock, in the order they are numbered (`ed_1`, `ed_2`, ...). RM-133:
    `contract_id` picks one of the tenant's contracts; absent, `c_1` as before."""
    tenant, account = self._authorized_tenant(actor, tenant_id, "engagements:create")
    contract_id = None if contract_id in (None, "") else contract_id
    contract_sha256 = self._tenant_contract_sha256(tenant, contract_id)
    request_id = _request_id(request_id)
    engagement_id = engagement_id_for(request_id)
    documents = [] if documents is None else documents
    request = self._engagement_request(
      display_name, valid_from, valid_until, context, assets, documents,
      supersedes, account.account_id, contract_id)
    record = self._engagement_record(account, tenant_id, request_id, request, contract_sha256, documents, supersedes)
    # Replay is decided on the request alone.
    existing = self.store.get("engagement", tenant_id, engagement_id)
    if existing is not None:
      if (existing["create_intent_digest"] != record["create_intent_digest"]
          or existing["created_by"] != account.account_id):
        raise AdministrationDenied(409, "conflict")
      return {**self._engagement_row(existing), "replayed": True}
    if supersedes is not None and (supersedes == engagement_id
                                   or self.store.get("engagement", tenant_id, supersedes) is None):
      raise AdministrationDenied(400, "supersedes_invalid")
    record = self._with_assets(record, self._engagement_assets(request["assets"], {"tenant_id": tenant_id}))
    self.store.put("engagement", tenant_id, engagement_id, record=record)
    # `replayed` says whether this call wrote, decided under the lock (the plugin audits on it).
    return {**self._engagement_row(self.store.get("engagement", tenant_id, engagement_id)), "replayed": False}

  def _engagement_assets(self, requests, parent, kept=()):
    """RM-125 phase 2b: the stored entries for normalized request entries, each copied from the
    registered asset of `parent`. Another parent's asset is `asset_not_found`, never revealed.
    `kept`: stored entries whose copy stands (a draft keeps its copy until the asset is re-picked)."""
    copies = {entry["asset_id"]: entry for entry in kept}
    def lookup(asset_id):
      if asset_id in copies:
        return copies[asset_id]
      row = self.store.get("tenant_asset", asset_id)
      if row is None or row["parent"] != parent:
        raise AdministrationDenied(404, "asset_not_found")
      if row["archived_at"] is not None:
        raise AdministrationDenied(409, "asset_archived")
      return row
    try:
      return build_engagement_assets(requests, lookup)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None

  @staticmethod
  def _with_assets(record, assets):
    return {**record, "assets": assets, "engagement_hash": engagement_hash({**record, "assets": assets})}

  def _engagement_record(self, account, tenant_id, request_id, request, contract_sha256, documents, supersedes):
    """The stored row of a new engagement, hashed; `request` is `_engagement_request`'s answer and
    `documents` the verified references in the order they are numbered."""
    engagement_id = engagement_id_for(request_id)
    intent = {"namespace": self.store.namespace, "tenant_id": tenant_id, "engagement_id": engagement_id,
              "request_id": request_id, "created_by": account.account_id, "request": request}
    record = {
      "tenant_id": tenant_id, "engagement_id": engagement_id, "request_id": request_id,
      "display_name": request["display_name"],
      "valid_from": request["valid_from"], "valid_until": request["valid_until"],
      "contract_sha256": contract_sha256,
      "documents": [{"document_id": document_id_for(index), **document}
                    for index, document in enumerate(documents)],
      **({"supersedes": supersedes} if supersedes is not None else {}),
      "context": request["context"],
      "assets": request["assets"],
      "active": True, "created_by": account.account_id,
      "created_at": datetime.now(timezone.utc).isoformat(),
      "create_intent_digest": canonical_digest(intent),
    }
    record["engagement_hash"] = engagement_hash(record)
    return record

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

  def _assignment_conflict(self, tenant_id, node_address, mode):
    """RM-102 conflict precedence for (tenant, node, mode), over every tenant's live row for the
    node: own row draining; own live row, same mode (`assigned`, idempotent); own live row, the other
    mode; another tenant's live private row; private requested while any other live row exists;
    RM-112: a draft's private plan of the node, unless this tenant was activated from that draft.
    Answers `(error, holder)`: `(None, None)` when the node is free, `holder` only for
    `node_planned_private`. Rows are "live" per `_assignment_live` -- a dead-draining row is
    released everywhere. RM-127: shared by `_assign_node` and the contract nodes' activation check."""
    others = [other for other in self.store.list_node_assignments_for_node(node_address)
              if self._assignment_live(other["tenant_id"], other)]
    own = next((other for other in others if other["tenant_id"] == tenant_id), None)
    foreign = [other for other in others if other["tenant_id"] != tenant_id]
    if own is not None:
      if own.get("draining"):
        return "node_draining", None
      own_mode = node_assignment_mode(own)
      if own_mode == mode:
        return "assigned", None
      return "node_private_assigned" if own_mode == "private" else "node_shared_assigned", None
    if any(node_assignment_mode(other) == "private" for other in foreign):
      return "node_private_assigned", None
    if mode == "private" and foreign:
      return "node_shared_assigned", None
    holder = self._private_plan_holder(node_address)
    if holder is not None and not self._holder_is_own(holder, tenant_id):
      return "node_planned_private", holder
    return None, None

  def _holder_is_own(self, holder, tenant_id):
    """RM-112: a tenant activated from the holding draft is its own holder. RM-133: so is the tenant
    whose contract draft plans the node."""
    if "tenant_id" in holder:
      return holder["tenant_id"] == tenant_id
    return holder["draft_id"] == self._tenant_source_draft(tenant_id)

  def _assign_node(self, account, tenant_id, node_address, mode, row):
    """Assign (tenant, node, mode) unless `_assignment_conflict` refuses; idempotent."""
    error, holder = self._assignment_conflict(tenant_id, node_address, mode)
    if error == "assigned":
      return {"tenantId": tenant_id, "nodeAddress": node_address, "active": True, "mode": mode, "state": "assigned"}
    if error == "node_planned_private":
      raise self._planned_private(account, holder)
    if error is not None:
      raise AdministrationDenied(409, error)
    new_row = {**(row or {}), "tenant_id": tenant_id, "node_address": node_address, "active": True,
               "mode": mode, "draining": False, "changed_by": account.account_id,
               "changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_node", tenant_id, node_address, record=new_row)
    return {"tenantId": tenant_id, "nodeAddress": node_address, "active": True, "mode": mode, "state": "assigned"}

  def _private_plan_holder(self, node_address, exclude=None):
    """RM-112: the draft whose plan holds the node privately, or None. Reads every draft. RM-133:
    a contract draft's plan holds it the same way, from the plan write; its holder names the
    tenant and the contract id. `exclude` is the holder key of the row being written
    (`("tenant_draft", draft_id)` or `("tenant_contract_draft", tenant_id, contract_id)`)."""
    entry = {"node_address": node_address, "mode": "private"}
    for draft in sorted(self.store.list_tenant_drafts(), key=lambda row: row["draft_id"]):
      if ("tenant_draft", draft["draft_id"]) != exclude and entry in draft["nodes"]:
        return {"draft_id": draft["draft_id"], "display_name": draft["display_name"]}
    for row in sorted(self.store.list_tenant_contract_drafts(), key=lambda row: (row["tenant_id"], row["contract_id"])):
      if ("tenant_contract_draft", row["tenant_id"], row["contract_id"]) != exclude and entry in row["nodes"]:
        return {"tenant_id": row["tenant_id"], "contract_id": row["contract_id"]}
    return None

  def _tenant_source_draft(self, tenant_id):
    """RM-112: the draft a tenant was activated from, through its receipt (the tenant row has no
    draft id); None for a tenant created in one step."""
    tenant = self.store.get("tenant", tenant_id)
    receipt = self._receipt(tenant["actor_id"], tenant["request_id"]) if tenant is not None else None
    return receipt.get("draft_id") if receipt is not None else None

  @staticmethod
  def _planned_private(account, holder):
    """`node_planned_private`, naming the draft (RM-133: or the tenant and contract draft) only to a
    full-portfolio Super-Tenant Admin (who may read drafts); anyone else learns only that the node
    is reserved."""
    details = {"holder": dict(holder)} if holds_platform_role(account) else {}
    return AdministrationDenied(409, "node_planned_private", **details)

  @staticmethod
  def _holder_key(row):
    """The holder key of a plan-carrying row: a tenant draft's or a contract draft's."""
    if "draft_id" in row:
      return ("tenant_draft", row["draft_id"])
    return ("tenant_contract_draft", row["tenant_id"], row["contract_id"])

  def _check_node_plan(self, account, previous, row):
    """RM-112: the plan entries this update adds or changes. No node held privately by another
    draft is planned; a private entry also needs the node free of every live assignment. RM-133:
    the same for a contract draft's plan."""
    for entry in row["nodes"]:
      if entry in previous["nodes"]:
        continue
      holder = self._private_plan_holder(entry["node_address"], exclude=self._holder_key(row))
      if holder is not None:
        raise self._planned_private(account, holder)
      if entry["mode"] == "private":
        live = [other for other in self.store.list_node_assignments_for_node(entry["node_address"])
                if self._assignment_live(other["tenant_id"], other)]
        if any(node_assignment_mode(other) == "private" for other in live):
          raise AdministrationDenied(409, "node_private_assigned")
        if live:
          raise AdministrationDenied(409, "node_shared_assigned")

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
      new_row = {**row, "active": True, "draining": True, "mode": node_assignment_mode(row),
                 "changed_by": account.account_id,
                 "changed_at": datetime.now(timezone.utc).isoformat()}
    else:
      new_row = {**row, "active": False, "draining": False, "mode": node_assignment_mode(row),
                 "changed_by": account.account_id,
                 "changed_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_node", tenant_id, node_address, record=new_row)
    return {"tenantId": tenant_id, "nodeAddress": node_address, "active": False,
            "mode": node_assignment_mode(new_row), "state": "draining" if new_row["draining"] else "released"}

  @_endpoint
  def set_tenant_node_assignment(self, actor, tenant_id, node_address, active, mode=None):
    tenant, account = self._authorized_tenant(actor, tenant_id, "node_assignments:manage")
    if (not valid_node_address(node_address) or type(active) is not bool
        or (mode is not None and mode not in NODE_ASSIGNMENT_MODES)):
      raise AdministrationDenied(400, "invalid_request")
    # RM-127: the contract lists the tenant's nodes; a change waits for contract amendments. Asking
    # for an assignment the tenant already holds is still answered, as `_assign_node` does.
    if _contract_nodes(tenant):
      if active and self._assignment_conflict(tenant_id, node_address, mode or "shared")[0] == "assigned":
        return {"tenantId": tenant_id, "nodeAddress": node_address, "active": True, "mode": mode or "shared",
                "state": "assigned"}
      raise AdministrationDenied(409, "nodes_fixed_by_contract")
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
  def get_tenant_contract(self, actor, tenant_id, contract_id=None):
    """RM-095. The tenant's legal details and contract record (never the file), for a full-portfolio
    Super-Tenant Admin only. Tenants created before contracts were required read as not recorded.
    RM-133: with `contract_id`, one of the further contracts (its block's record, baseline, dates
    and nodes; the pack records belong to `c_1`); absent or `c_1`, the first contract as before."""
    tenant, account = self._platform_tenant(actor, tenant_id)
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
    # RM-109: the terms a draft activation added; a one-step tenant has none of them. RM-110: nor
    # the contract's generated baseline (hashes and ids, never the bytes).
    if any(tenant.get(kind) is not None and not _valid_contract(tenant[kind])
           for kind in _TENANT_DOCUMENT_KINDS[1:]):
      raise TenantStoreError("Invalid tenant contract record")
    if "contract_generated" in tenant and not _valid_generated_block(tenant["contract_generated"]):
      raise TenantStoreError("Invalid tenant contract record")
    if contract_id not in (None, "", tenant_contracts.FIRST_CONTRACT_ID):
      if not tenant_contracts.valid_contract_id(contract_id):
        raise AdministrationDenied(400, "invalid_request")
      block = _contract_blocks(tenant).get(contract_id)
      if block is None:
        raise AdministrationDenied(404, "not_found")
      return {"legal": _legal_dto(legal), "contract": block["contract"],
              "compliance_types": tenant.get("compliance_types"),
              "framework_agreement": None, "data_handling": None, "governance": None,
              "contract_generated": block["contract_generated"], "contract_id": contract_id,
              **{key: block[key] for key in ("effective_from", "effective_until", "nodes", "supersedes", "superseded_by")}}
    return {"legal": _legal_dto(legal), "contract": contract,
            **{key: tenant.get(key) for key in _DRAFT_TENANT_FIELDS},
            "contract_generated": tenant.get("contract_generated"),
            # RM-133: a tenant without a contract names none.
            "contract_id": tenant_contracts.FIRST_CONTRACT_ID if contract is not None else None, "supersedes": None,
            "superseded_by": tenant.get("contract_superseded_by")}

  def _platform_tenant(self, actor, tenant_id):
    """An active tenant read by a full-portfolio Super-Tenant Admin: the tenant check first, then
    the platform role (as `get_tenant_contract` has always done)."""
    tenant, account = self._authorized_tenant(actor, tenant_id)
    if not holds_platform_role(account):
      raise AdministrationDenied(403, "forbidden")
    return tenant, account

  # RM-107: delete a tenant. Owner, 2026-09-28: it exists so tenants created before contracts can be
  # removed; it deletes the tenant's records and its stored documents, refuses while the tenant has
  # jobs or members (accounts are the Navigator's records, never deleted here), and keeps the domain
  # reserved. The plugin runs it in steps so every document read and delete is outside this lock and
  # a failed attempt can be retried: `begin_tenant_delete` (check, then mark), the job checks,
  # the document deletes (`record_tenant_documents_deleted`), `finish_tenant_delete`.
  # RM-133: the tenant's contract drafts go with it (their files are in `_tenant_document_refs`).
  _DELETABLE_KINDS = ("engagement", "integration", "tenant_node", "tenant_contract_draft")

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
    """Every stored document the tenant's records point at, read from the raw rows. RM-110: the
    contract's generated baseline (`contract_generated.ref`) is one of them."""
    refs = [tenant[key] for key in (*_TENANT_DOCUMENT_KINDS, "contract_generated") if isinstance(tenant.get(key), dict)]
    # RM-133: the further contracts' signed copies and baselines, and every contract draft's files.
    blocks = tenant.get("contracts") if isinstance(tenant.get("contracts"), dict) else {}
    for block in blocks.values():
      if isinstance(block, dict):
        refs.extend(block.get(key) for key in ("contract", "contract_generated"))
    for ids in self.store.tenant_record_ids("tenant_contract_draft", tenant["tenant_id"]):
      row = self.store.raw_record("tenant_contract_draft", *ids) or {}
      refs.extend(row.get(key) for key in ("document", "generated"))
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
    # RM-125: the assets name their tenant in the row, not the key; found unvalidated, as above.
    asset_ids = self.store.child_record_ids("tenant_asset", {"tenant_id": tenant_id})
    for record_ids in asset_ids:
      self.store.delete("tenant_asset", *record_ids)
    self.store.delete("receipt", tenant["actor_id"], tenant["request_id"])
    self.store.delete("tenant", tenant_id)
    return {"tenantId": tenant_id, "deleted": True, "engagements": counts["engagement"],
            "integrations": counts["integration"], "assets": len(asset_ids),
            "nodeAssignments": counts["tenant_node"], "contractDrafts": counts["tenant_contract_draft"],
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

  # RM-110 phase 1: the super-tenant profile, one row per deployment, a full-portfolio Super-Tenant
  # Admin only (contract `onboarding-drafts.md` §Super-tenant profile). A deployment without the row
  # reads as the empty profile; a read never writes it.

  def _super_tenant_permissions(self):
    """RM-132: the deployment's flags, the known keys only; every key `True` without a reader."""
    reader = self.super_tenant_permissions_reader
    flags = reader() if callable(reader) else None
    flags = flags if isinstance(flags, dict) else {}
    return {key: bool(flags.get(key, default)) for key, default in super_tenant_profile.PERMISSIONS.items()}

  @_endpoint
  def get_super_tenant_profile(self, actor):
    """RM-132: the envelope `{"profile", "permissions"}`; `permissions` never enters the DTO."""
    self._actor(actor, creator=True)
    row = self.store.get("super_tenant_profile", super_tenant_profile.RECORD_ID)
    profile = super_tenant_profile.profile_dto(row if row is not None else super_tenant_profile.empty_profile())
    return {"profile": profile, "permissions": self._super_tenant_permissions()}

  @_endpoint
  def update_super_tenant_profile(self, actor, changes):
    """Partial `changes`, formats checked, emptiness allowed. Answers the profile and the keys whose
    value changed (the plugin audits those, never the values); nothing changed, nothing written.
    RM-132: refused while the deployment locks the company details, before any read of the row."""
    account = self._actor(actor, creator=True)
    if not self._super_tenant_permissions()["edit_company_details"]:
      raise AdministrationDenied(403, "company_details_locked")
    previous = self.store.get("super_tenant_profile", super_tenant_profile.RECORD_ID)
    if previous is None:
      previous = super_tenant_profile.empty_profile()
    try:
      row, changed = super_tenant_profile.apply_changes(previous, changes)
    except drafts.DraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    if changed:
      row = {**row, "updated_by": account.account_id, "updated_at": datetime.now(timezone.utc).isoformat()}
      self.store.put("super_tenant_profile", super_tenant_profile.RECORD_ID, record=row)
      row = self.store.get("super_tenant_profile", super_tenant_profile.RECORD_ID)
    return {"profile": super_tenant_profile.profile_dto(row), "changed": changed, "accountId": account.account_id}

  # RM-109 phase 2: tenant drafts. A full-portfolio Super-Tenant Admin only, as tenant creation; a
  # draft has no tenant, so these are not rows of the tenant policy matrix. Every document read,
  # write and delete is the plugin's, outside this lock: these methods return stored rows and the
  # refs whose files the plugin deletes after the write. Phase 3 sets `activation`; while it is set
  # the draft is locked. No method here reads the document store, and a stored row never changes
  # because a file could not be read (contract §Missing files).

  def _tenant_draft(self, draft_id):
    if not drafts.valid_draft_id(draft_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("tenant_draft", draft_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return row

  def _unlocked_tenant_draft(self, draft_id):
    row = self._tenant_draft(draft_id)
    if row["activation"] is not None:
      raise AdministrationDenied(409, "draft_locked")
    return row

  @staticmethod
  def _draft_document_kind(value):
    if not isinstance(value, str) or value not in drafts.DOCUMENT_KINDS:
      raise AdministrationDenied(400, "invalid_request")
    return value

  def _write_tenant_draft(self, row, account, previous=None):
    """Write a changed row with its attribution; an unchanged one is not written."""
    if previous is not None and row == previous:
      return previous
    row = {**row, "updated_by": account.account_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_draft", row["draft_id"], record=row)
    return self.store.get("tenant_draft", row["draft_id"])

  def _marker_tenant(self, marker):
    """The receipt the marker names and its tenant row; either may be None."""
    receipt = self._receipt(marker["actor_id"], marker["request_id"])
    tenant = self.store.get("tenant", receipt["tenant_id"]) if receipt is not None else None
    return receipt, tenant

  def _draft_answer(self, row):
    """RM-109 phase 3: while the marker is set, its tenant's state: `none` (no receipt), `pending`
    or `active`. Answer only; never written. A corrupt receipt is a store failure here as on every
    tenant read, so one such receipt fails `list_tenant_drafts` closed (503) on purpose: the list
    never shows a state it could not read."""
    if row["activation"] is None:
      return row
    receipt, tenant = self._marker_tenant(row["activation"])
    state = "none" if receipt is None else "active" if tenant is not None and tenant.get("active") is True else "pending"
    return {**row, "activation": {**row["activation"], "tenant_state": state}}

  @_endpoint
  def create_tenant_draft(self, actor, request_id, display_name, compliance_types):
    account = self._actor(actor, creator=True)
    draft_id = drafts.draft_id_for(_request_id(request_id))
    existing = self.store.get("tenant_draft", draft_id)
    if existing is not None:
      return self._draft_answer(existing)
    try:
      row = drafts.new_draft(draft_id, display_name, compliance_types, account.account_id,
                             datetime.now(timezone.utc).isoformat())
    except drafts.DraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    self.store.put("tenant_draft", draft_id, record=row)
    return self.store.get("tenant_draft", draft_id)

  @_endpoint
  def get_tenant_draft(self, actor, draft_id):
    self._actor(actor, creator=True)
    return self._draft_answer(self._tenant_draft(draft_id))

  @_endpoint
  def list_tenant_drafts(self, actor):
    self._actor(actor, creator=True)
    rows = sorted(self.store.list_tenant_drafts(), key=lambda row: row["draft_id"])
    rows.sort(key=lambda row: row["created_at"], reverse=True)
    return [drafts.draft_list_row(self._draft_answer(row)) for row in rows]

  @_endpoint
  def update_tenant_draft(self, actor, draft_id, changes):
    """Answers the row and the `(slot, ref)` pairs whose files the plugin deletes after this write."""
    account = self._actor(actor, creator=True)
    previous = self._unlocked_tenant_draft(draft_id)
    try:
      row, dropped = drafts.apply_changes(previous, changes)
    except drafts.DraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    # RM-127: the signed contract lists the nodes; the copy is dropped first, in its own update.
    if previous["items"]["contract"]["state"] == "signed" and row["nodes"] != previous["nodes"]:
      raise AdministrationDenied(409, "nodes_locked")
    self._check_node_plan(account, previous, row)
    return {"draft": self._write_tenant_draft(row, account, previous), "dropped": dropped}

  @_endpoint
  def authorize_tenant_draft_upload(self, actor, draft_id, document_kind):
    account = self._actor(actor, creator=True)
    row = self._unlocked_tenant_draft(draft_id)
    self._draft_document_kind(document_kind)
    return {"accountId": account.account_id, "draft": row}

  @_endpoint
  def attach_tenant_draft_document(self, actor, draft_id, document_kind, document):
    """Bind an uploaded file (`store_draft_document`) to its slot and sign the item. Answers the row
    and the ref the slot held before, whose file the plugin deletes after this write."""
    account = self._actor(actor, creator=True)
    previous = self._unlocked_tenant_draft(draft_id)
    kind = self._draft_document_kind(document_kind)
    if not valid_doc_ref(document) or document["uploaded_by"] != account.account_id:
      raise AdministrationDenied(400, "contract_invalid" if kind == "contract" else "document_invalid")
    row = previous
    replaced = row["items"][kind]["document"]
    row = {**row, "items": {**row["items"], kind: {**row["items"][kind], "state": "signed",
                                                   "document": dict(document)}}}
    return {"draft": self._write_tenant_draft(row, account),
            "replaced": replaced["ref"] if replaced is not None else None}

  @_endpoint
  def tenant_draft_document_ref(self, actor, draft_id, document_kind):
    self._actor(actor, creator=True)
    row = self._tenant_draft(draft_id)
    document = row["items"][self._draft_document_kind(document_kind)]["document"]
    if document is None:
      raise AdministrationDenied(404, "not_found")
    return document

  @_endpoint
  def begin_tenant_draft_delete(self, actor, draft_id):
    """RM-109 phase 4: the delete cascades, so the children and their files are listed too; the
    plugin deletes the children (files, then rows) before the draft's own files and row. RM-112: a
    draft holding a signed document (its agreement pack or a child's engagement pack) is kept; the
    delete drops the node plan with the row."""
    account = self._actor(actor, creator=True)
    row = self._unlocked_tenant_draft(draft_id)
    children = self._engagement_draft_children({"draft_id": draft_id})
    if (any(item["state"] == "signed" for item in row["items"].values())
        or any(child["document"]["state"] == "signed" for child in children)):
      raise AdministrationDenied(409, "draft_has_signed_documents")
    return {"accountId": account.account_id, "documentRefs": drafts.document_refs(row),
            "children": [{"engagement_draft_id": child["engagement_draft_id"],
                          "documentRefs": engagement_drafts.document_refs(child)}
                         for child in children]}

  @_endpoint
  def finish_tenant_draft_delete(self, actor, draft_id, deleted_refs):
    """Delete the record once every file it names is gone and no child is left. A file attached or
    a child created since the plugin started deleting is a conflict; the next attempt removes it too."""
    self._actor(actor, creator=True)
    row = self._unlocked_tenant_draft(draft_id)
    if (not set(drafts.document_refs(row)) <= set(deleted_refs)
        or self._engagement_draft_children({"draft_id": draft_id})):
      raise AdministrationDenied(409, "conflict")
    # RM-125: the draft's assets hold no file; they go with the draft.
    asset_ids = self.store.child_record_ids("tenant_asset", {"draft_id": draft_id})
    for record_ids in asset_ids:
      self.store.delete("tenant_asset", *record_ids)
    self.store.delete("tenant_draft", draft_id)
    return {"draft_id": draft_id, "assets_deleted": len(asset_ids)}

  @_endpoint
  def release_tenant_draft_activation(self, actor, draft_id):
    """Undo a stuck activation, any full-portfolio Super-Tenant Admin. The receipt is the marker's,
    never the caller's. Deletes the inactive tenant row, the domain reservation bound to the receipt
    and the receipt, in that order, and no document file: the files stay the draft's.

    `last_release` is written while the marker is still set, so a retry after a crash part-way
    finds the ids it must answer. A receipt that is gone means one of three things: this release
    already removed it (`last_release` names the marker's request), the tenant was activated and
    deleted (its domain reservation, kept by the delete, is still bound to the marker; the delete
    removed the draft's files, so every item with a document reads `missing`), or the preparation
    stopped between the marker and the receipt (nothing to remove, the files are intact).
    """
    account = self._actor(actor, creator=True)
    draft = self._tenant_draft(draft_id)
    marker = draft["activation"]
    if marker is None:
      if draft["last_release"] is None:
        raise AdministrationDenied(409, "not_activating")
      return {"draft_id": draft_id, "released": draft["last_release"], "cleared": False, "rows_deleted": 0}
    receipt, tenant = self._marker_tenant(marker)
    deleted = 0
    if receipt is not None:
      if tenant is not None and "deleting" in tenant:
        # Being deleted: `delete_tenant` finishes it, and its rows are not this release's.
        raise AdministrationDenied(409, "tenant_deleting")
      if tenant is not None and tenant.get("active") is True:
        raise AdministrationDenied(409, "tenant_active")
      release = {"actor_id": account.account_id, "released_at": datetime.now(timezone.utc).isoformat(),
                 "request_id": marker["request_id"], "tenant_id": receipt["tenant_id"],
                 "initial_admin_id": receipt["initial_admin_id"]}
      draft = {**draft, "last_release": release}
      self.store.put("tenant_draft", draft_id, record=draft)
      # RM-127: the contract nodes an activation stopped part-way assigned go before their tenant.
      for row in self.store.list_node_assignments(receipt["tenant_id"]):
        self.store.delete("tenant_node", receipt["tenant_id"], row["node_address"])
        deleted += 1
      if tenant is not None:
        self.store.delete("tenant", receipt["tenant_id"])
        deleted += 1
      domain = self.store.get("domain", receipt["domain_id"])
      if domain is not None and all(domain.get(key) == value for key, value in self._binding(receipt).items()):
        self.store.delete("domain", receipt["domain_id"])
        deleted += 1
      self.store.delete("receipt", marker["actor_id"], marker["request_id"])
      deleted += 1
    # Otherwise, when `last_release` names the marker's request, a release stopped after its receipt
    # delete and only the marker is left to clear.
    elif (draft["last_release"] or {}).get("request_id") != marker["request_id"]:
      domain = self.store.get("domain", draft["domain_id"]) if draft["domain_id"] else None
      tenant_deleted = domain is not None and (domain.get("actor_id"), domain.get("request_id")) == (
        marker["actor_id"], marker["request_id"])
      items = draft["items"]
      if tenant_deleted:
        # The tenant delete removed the signed files and (RM-110) the generated baseline, the
        # same CIDs the draft names: an item with a file reads `missing`, a block is dropped.
        items = {kind: {**item,
                        "state": "missing" if item["document"] is not None or item["state"] == "generated" else item["state"],
                        "document": None, "generated": None}
                 for kind, item in items.items()}
      draft = {**draft, "items": items, "last_release": {
        "actor_id": account.account_id, "released_at": datetime.now(timezone.utc).isoformat(),
        "request_id": marker["request_id"], "tenant_id": None, "initial_admin_id": None}}
    draft = {**draft, "activation": None}
    self.store.put("tenant_draft", draft_id, record=draft)
    # `cleared`: this call cleared the marker, which every release does exactly once; the plugin
    # audits on it. `rows_deleted` counts this call's deletes only.
    return {"draft_id": draft_id, "released": draft["last_release"], "cleared": True, "rows_deleted": deleted}

  @_endpoint
  def close_tenant_draft(self, actor, draft_id):
    """Delete the draft record once its activation produced an active tenant; the files are the
    tenant's now, so none is deleted. RM-109 phase 4: every child is re-homed to the tenant first,
    so a crash between the two is finished by the next close call."""
    account = self._actor(actor, creator=True)
    draft = self._tenant_draft(draft_id)
    tenant = self._marker_tenant(draft["activation"])[1] if draft["activation"] is not None else None
    if tenant is None or tenant.get("active") is not True:
      raise AdministrationDenied(409, "activation_not_complete")
    for child in self._engagement_draft_children({"draft_id": draft_id}):
      self._write_engagement_draft({**child, "parent": {"tenant_id": tenant["tenant_id"]}}, account)
    # RM-125: the draft's assets become the tenant's the same way.
    for asset in self._tenant_asset_children({"draft_id": draft_id}):
      self._write_tenant_asset({**asset, "parent": {"tenant_id": tenant["tenant_id"]}}, account)
    self.store.delete("tenant_draft", draft_id)
    return {"draft_id": draft_id, "tenant_id": tenant["tenant_id"]}

  # RM-109 phase 4: engagement drafts, the children of a tenant draft (or of an active tenant). The
  # same conventions as the tenant draft: a full-portfolio Super-Tenant Admin only, every document
  # read, write and delete the plugin's, outside this lock, and every write refused `draft_locked`
  # while the parent tenant draft's marker is set. Activation is one locked call with no marker.

  def _engagement_draft(self, engagement_draft_id):
    if not engagement_drafts.valid_engagement_draft_id(engagement_draft_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("engagement_draft", engagement_draft_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return row

  def _parent_unlocked(self, parent):
    """The parent tenant draft's marker locks every child; a tenant parent has no marker."""
    if "draft_id" in parent:
      tenant_draft = self.store.get("tenant_draft", parent["draft_id"])
      if tenant_draft is not None and tenant_draft["activation"] is not None:
        raise AdministrationDenied(409, "draft_locked")

  def _unlocked_engagement_draft(self, engagement_draft_id):
    row = self._engagement_draft(engagement_draft_id)
    self._parent_unlocked(row["parent"])
    return row

  def _engagement_draft_parent(self, value, present=True):
    """`{draft_id}` or `{tenant_id}`; with `present`, an existing tenant draft or a live tenant."""
    if drafts.valid_draft_id(value):
      if present and self.store.get("tenant_draft", value) is None:
        raise AdministrationDenied(404, "not_found")
      return {"draft_id": value}
    if engagement_drafts.valid_tenant_id(value):
      if present:
        tenant = self.store.get("tenant", value)
        if tenant is None or tenant.get("active") is not True:
          raise AdministrationDenied(404, "not_found")
      return {"tenant_id": value}
    raise AdministrationDenied(400, "invalid_request")

  def _engagement_draft_children(self, parent):
    return [row for row in self.store.list_engagement_drafts() if row["parent"] == parent]

  def _write_engagement_draft(self, row, account, previous=None):
    """Write a changed row with its attribution; an unchanged one is not written."""
    if previous is not None and row == previous:
      return previous
    row = {**row, "updated_by": account.account_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("engagement_draft", row["engagement_draft_id"], record=row)
    return self.store.get("engagement_draft", row["engagement_draft_id"])

  @_endpoint
  def create_engagement_draft(self, actor, parent, request_id, display_name):
    account = self._actor(actor, creator=True)
    engagement_draft_id = engagement_drafts.engagement_draft_id_for(_request_id(request_id))
    existing = self.store.get("engagement_draft", engagement_draft_id)
    if existing is not None:
      return existing
    parent = self._engagement_draft_parent(parent)
    self._parent_unlocked(parent)
    try:
      row = engagement_drafts.new_draft(engagement_draft_id, parent, display_name, account.account_id,
                                        datetime.now(timezone.utc).isoformat())
    except engagement_drafts.EngagementDraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    self.store.put("engagement_draft", engagement_draft_id, record=row)
    return self.store.get("engagement_draft", engagement_draft_id)

  @_endpoint
  def get_engagement_draft(self, actor, engagement_draft_id):
    self._actor(actor, creator=True)
    return self._engagement_draft(engagement_draft_id)

  @_endpoint
  def list_engagement_drafts(self, actor, parent):
    """The children of one parent, newest first; a parent that does not exist has none."""
    self._actor(actor, creator=True)
    rows = self._engagement_draft_children(self._engagement_draft_parent(parent, present=False))
    rows.sort(key=lambda row: row["engagement_draft_id"])
    rows.sort(key=lambda row: row["created_at"], reverse=True)
    return [engagement_drafts.draft_list_row(row) for row in rows]

  @_endpoint
  def update_engagement_draft(self, actor, engagement_draft_id, changes):
    """Answers the row and the refs whose files the plugin deletes after this write."""
    account = self._actor(actor, creator=True)
    previous = self._unlocked_engagement_draft(engagement_draft_id)
    if isinstance(changes, dict) and "assets" in changes:
      changes = {**changes, "assets": self._draft_assets(changes["assets"], previous["parent"], previous["assets"])}
    try:
      row, dropped = engagement_drafts.apply_changes(previous, changes)
    except engagement_drafts.EngagementDraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    # RM-133: a pick names a contract the parent tenant holds and nobody replaced (`c_1` when the
    # pick is empty); a draft under a tenant draft has one contract and takes none.
    pick = engagement_drafts.contract_pick(row)
    if isinstance(changes, dict) and engagement_drafts.CONTRACT_PICK in changes:
      if "tenant_id" not in row["parent"]:
        if pick is not None:
          raise AdministrationDenied(400, "contract_unknown")
      else:
        tenant = self.store.get("tenant", row["parent"]["tenant_id"])
        if tenant is None:
          raise AdministrationDenied(404, "not_found")
        self._tenant_contract_sha256(tenant, pick)
    return {"draft": self._write_engagement_draft(row, account, previous), "dropped": dropped}

  def _draft_assets(self, requests, parent, previous):
    """RM-125 phase 2b: an `assets` change as stored entries (an empty list clears them). An asset
    the draft already holds keeps its stored copy, only its ports change; a newly picked one is
    copied from the parent's registered assets now. A later rename or archive of a held asset
    therefore never reaches the draft (contract: remove and re-pick to take a newer copy)."""
    if requests == []:
      return []
    try:
      requests = normalize_asset_requests(requests)
    except EngagementInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    return self._engagement_assets(requests, parent, previous)

  @_endpoint
  def authorize_engagement_draft_upload(self, actor, engagement_draft_id):
    account = self._actor(actor, creator=True)
    self._unlocked_engagement_draft(engagement_draft_id)
    return {"accountId": account.account_id}

  @_endpoint
  def attach_engagement_draft_document(self, actor, engagement_draft_id, document):
    """Bind an uploaded pack (`store_engagement_pack`) to the slot and sign it. Answers the row and
    the ref the slot held before, whose file the plugin deletes after this write."""
    account = self._actor(actor, creator=True)
    previous = self._unlocked_engagement_draft(engagement_draft_id)
    if not valid_doc_ref(document) or document["uploaded_by"] != account.account_id:
      raise AdministrationDenied(400, "document_invalid")
    slot = previous["document"]
    row = {**previous, "document": {**slot, "state": "signed", "document": dict(document)}}
    return {"draft": self._write_engagement_draft(row, account),
            "replaced": slot["document"]["ref"] if slot["document"] is not None else None}

  @_endpoint
  def engagement_draft_document_ref(self, actor, engagement_draft_id):
    self._actor(actor, creator=True)
    document = self._engagement_draft(engagement_draft_id)["document"]["document"]
    if document is None:
      raise AdministrationDenied(404, "not_found")
    return document

  @_endpoint
  def begin_engagement_draft_delete(self, actor, engagement_draft_id):
    """RM-112: a draft whose pack is signed is kept, as a tenant draft holding a signed document."""
    account = self._actor(actor, creator=True)
    row = self._unlocked_engagement_draft(engagement_draft_id)
    if row["document"]["state"] == "signed":
      raise AdministrationDenied(409, "draft_has_signed_documents")
    return {"accountId": account.account_id, "documentRefs": engagement_drafts.document_refs(row)}

  @_endpoint
  def finish_engagement_draft_delete(self, actor, engagement_draft_id, deleted_refs):
    """As `finish_tenant_draft_delete`: the row goes once both its files are gone."""
    self._actor(actor, creator=True)
    row = self._unlocked_engagement_draft(engagement_draft_id)
    if not set(engagement_drafts.document_refs(row)) <= set(deleted_refs):
      raise AdministrationDenied(409, "conflict")
    self.store.delete("engagement_draft", engagement_draft_id)
    return {"engagement_draft_id": engagement_draft_id}

  # RM-125: tenant assets, registered before an engagement picks them, under a live tenant or a
  # tenant draft. Writes: the Super-Tenant Admin only (`assets:manage` on a tenant; the draft rule,
  # full-portfolio Super-Tenant Admin, on a tenant draft, refused `draft_locked` while its marker is
  # set). Reads: every tenant role on a tenant (`reports:view`), the draft rule on a draft. A write
  # answers `{asset, changed}`: the plugin audits only a write that changed the row.

  def _asset_parent(self, actor, parent, operation, present=True):
    """`(account, parent, can_manage)` for a parent id; `operation` is `assets:manage` or
    `reports:view`. With `present`, a draft parent must exist (and be unlocked for a write)."""
    if drafts.valid_draft_id(parent):
      account = self._actor(actor, creator=True)
      if present:
        if operation == "assets:manage":
          self._unlocked_tenant_draft(parent)
        else:
          self._tenant_draft(parent)
      return account, {"draft_id": parent}, True
    if engagement_drafts.valid_tenant_id(parent):
      tenant, account = self._authorized_tenant(actor, parent, operation)
      return account, {"tenant_id": parent}, self._permission(account, tenant, "assets:manage")
    raise AdministrationDenied(400, "invalid_request")

  @staticmethod
  def _parent_id(parent):
    return parent.get("draft_id") or parent.get("tenant_id")

  def _tenant_asset(self, actor, asset_id, operation):
    """The stored asset and the caller's `(account, can_manage)` on its parent."""
    if not tenant_assets.valid_asset_id(asset_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("tenant_asset", asset_id)
    if row is None:
      raise AdministrationDenied(404, "asset_not_found")
    account, _, manage = self._asset_parent(actor, self._parent_id(row["parent"]), operation)
    return row, account, manage

  def _tenant_asset_children(self, parent):
    return [row for row in self.store.list_tenant_assets() if row["parent"] == parent]

  def _asset_link_sources(self, parent):
    """The engagements and engagement drafts an asset of `parent` can be linked from: a tenant's
    engagements whatever their state, and the engagement drafts under the same parent."""
    engagements = self.store.list_engagements(parent["tenant_id"]) if "tenant_id" in parent else []
    return engagements, self._engagement_draft_children(parent)

  def _asset_dto(self, row, sources=None):
    engagements, children = sources if sources is not None else self._asset_link_sources(row["parent"])
    return tenant_assets.asset_dto(row, tenant_assets.links(row["asset_id"], engagements, children, self.clock()))

  def _asset_linked(self, row):
    """Referenced by any engagement or engagement draft: the target is locked, no delete."""
    engagements, children = self._asset_link_sources(row["parent"])
    return any(tenant_assets.entry_references(source["assets"], row["asset_id"])
               for source in (*engagements, *children))

  def _check_asset_unique(self, row):
    if any(other["asset_id"] != row["asset_id"] and other["target_digest"] == row["target_digest"]
           for other in self._tenant_asset_children(row["parent"])):
      raise AdministrationDenied(409, "asset_duplicate")

  def _write_tenant_asset(self, row, account, previous=None):
    """Write a changed row with its attribution; an unchanged one is not written."""
    if previous is not None and row == previous:
      return previous
    row = {**row, "updated_by": account.account_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_asset", row["asset_id"], record=row)
    return self.store.get("tenant_asset", row["asset_id"])

  @_endpoint
  def create_tenant_asset(self, actor, parent, request_id, display_name, target, notes="", environment=None):
    account, parent, _ = self._asset_parent(actor, parent, "assets:manage")
    asset_id = tenant_assets.asset_id_for(_request_id(request_id))
    existing = self.store.get("tenant_asset", asset_id)
    if existing is not None:
      # A replay answers the stored row; the same id under another parent is not a replay.
      if existing["parent"] != parent:
        raise AdministrationDenied(409, "conflict")
      return {"asset": self._asset_dto(existing), "changed": False}
    try:
      row = tenant_assets.new_asset(asset_id, parent, display_name, target, notes, account.account_id,
                                    datetime.now(timezone.utc).isoformat(), environment)
    except tenant_assets.TenantAssetInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    self._check_asset_unique(row)
    self.store.put("tenant_asset", asset_id, record=row)
    return {"asset": self._asset_dto(self.store.get("tenant_asset", asset_id)), "changed": True}

  @_endpoint
  def update_tenant_asset(self, actor, asset_id, changes):
    """Name and notes always; the target and the environment only while no engagement or engagement
    draft names it (RM-131: the environment may change what the engagement agreed to)."""
    previous, account, _ = self._tenant_asset(actor, asset_id, "assets:manage")
    try:
      row = tenant_assets.apply_changes(previous, changes)
    except tenant_assets.TenantAssetInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    if row["target_digest"] != previous["target_digest"]:
      if self._asset_linked(previous):
        raise AdministrationDenied(409, "asset_linked")
      self._check_asset_unique(row)
    elif row.get("environment") != previous.get("environment") and self._asset_linked(previous):
      raise AdministrationDenied(409, "asset_linked")
    return {"asset": self._asset_dto(self._write_tenant_asset(row, account, previous)), "changed": row != previous}

  @_endpoint
  def archive_tenant_asset(self, actor, asset_id, archived):
    """Archived assets are hidden from the pickers and refused on new entries; reversible."""
    if type(archived) is not bool:
      raise AdministrationDenied(400, "invalid_request")
    previous, account, _ = self._tenant_asset(actor, asset_id, "assets:manage")
    if (previous["archived_at"] is not None) == archived:
      return {"asset": self._asset_dto(previous), "changed": False}
    marker = ({"archived_at": datetime.now(timezone.utc).isoformat(), "archived_by": account.account_id}
              if archived else {"archived_at": None, "archived_by": None})
    return {"asset": self._asset_dto(self._write_tenant_asset({**previous, **marker}, account, previous)),
            "changed": True}

  @_endpoint
  def delete_tenant_asset(self, actor, asset_id):
    row, account, _ = self._tenant_asset(actor, asset_id, "assets:manage")
    if self._asset_linked(row):
      raise AdministrationDenied(409, "asset_linked")
    self.store.delete("tenant_asset", asset_id)
    return {"asset_id": asset_id, "parent": row["parent"], "deleted": True, "deleted_by": account.account_id}

  @_endpoint
  def list_tenant_assets(self, actor, parent, include_archived=False):
    """The parent's assets by name; a tenant draft that does not exist has none."""
    if type(include_archived) is not bool:
      raise AdministrationDenied(400, "invalid_request")
    _, parent, manage = self._asset_parent(actor, parent, "reports:view", present=False)
    rows = [row for row in self._tenant_asset_children(parent)
            if include_archived or row["archived_at"] is None]
    rows.sort(key=lambda row: (row["display_name"].casefold(), row["asset_id"]))
    sources = self._asset_link_sources(parent)
    return {"assets": [self._asset_dto(row, sources) for row in rows], "can_manage": manage}

  @_endpoint
  def get_tenant_asset(self, actor, asset_id):
    row, _, manage = self._tenant_asset(actor, asset_id, "reports:view")
    return {"asset": self._asset_dto(row), "can_manage": manage}

  # RM-110: the generated pack (`store_generated_document`), one operation for both draft kinds. The
  # same split as the uploads: the plugin stores the bytes (with the snapshot, one envelope) outside
  # this lock between `authorize_generated_document` and `attach_generated_document`, and discards
  # the file when the attach is refused. The slot's previous generated file goes after the write.

  def _generated_slot(self, draft_id, engagement_draft_id, document_kind, tenant_id=None, contract_id=None):
    """The unlocked draft a generated pack goes to, its slot and the slot's refusal code: exactly one
    of the three id forms names the draft (a tenant draft, an engagement draft, RM-133 a contract
    draft `(tenant_id, contract_id)`), and `document_kind` must be that slot's. A contract draft's
    slot is the row itself (state, document and generated sit at its top level)."""
    if sum(map(bool, (draft_id, engagement_draft_id, contract_id))) != 1:
      raise AdministrationDenied(400, "invalid_request")
    if draft_id:
      row = self._unlocked_tenant_draft(draft_id)
      if document_kind != "contract":
        raise AdministrationDenied(400, "invalid_request")
      return row, row["items"]["contract"], "contract_invalid"
    if contract_id:
      row = self._tenant_contract_draft(tenant_id, contract_id)
      if document_kind != "contract":
        raise AdministrationDenied(400, "invalid_request")
      return row, row, "contract_invalid"
    row = self._unlocked_engagement_draft(engagement_draft_id)
    if document_kind != engagement_drafts.DOCUMENT_KIND:
      raise AdministrationDenied(400, "invalid_request")
    return row, row["document"], "document_invalid"

  @_endpoint
  def authorize_generated_document(self, actor, draft_id, engagement_draft_id, document_kind, snapshot, generated_at,
                                   tenant_id=None, contract_id=None):
    """Everything but the bytes is checked before the plugin stores them: role, the draft and its
    lock, the slot, the snapshot and `generated_at` formats, and that the item is not `signed`."""
    account = self._actor(actor, creator=True)
    row, slot, _ = self._generated_slot(draft_id, engagement_draft_id, document_kind, tenant_id, contract_id)
    try:
      drafts.normalize_snapshot(snapshot)
      drafts.normalize_generated_at(generated_at)
    except drafts.DraftInvalid as exc:
      raise AdministrationDenied(400, exc.code) from None
    if slot["state"] == "signed":
      raise AdministrationDenied(409, "already_signed")
    if engagement_draft_id:
      return {"accountId": account.account_id}
    # RM-127: the contract prints the node plan, so it needs one, and the snapshot must be of it.
    if not row["nodes"]:
      raise AdministrationDenied(409, "draft_incomplete", missing=["field:nodes"])
    nodes = self._snapshot_nodes(snapshot)
    if nodes != row["nodes"]:
      raise AdministrationDenied(409, "draft_changed")
    return {"accountId": account.account_id, "nodes": nodes}

  @staticmethod
  def _snapshot_nodes(snapshot):
    """RM-127: the snapshot's `nodes` (`[{nodeAddress, mode, ...}]`, the console's names and IPs
    beside them) as the draft stores its plan; an absent list is empty, a malformed one invalid."""
    nodes = json.loads(snapshot).get("nodes", [])
    if (not isinstance(nodes, list)
        or any(not isinstance(entry, dict) or not valid_node_address(entry.get("nodeAddress"))
               or entry.get("mode") not in NODE_ASSIGNMENT_MODES for entry in nodes)):
      raise AdministrationDenied(400, "invalid_request")
    return [{"node_address": entry["nodeAddress"], "mode": entry["mode"]} for entry in nodes]

  @_endpoint
  def attach_generated_document(self, actor, draft_id, engagement_draft_id, document_kind, document, snapshot_sha256,
                                generated_at, nodes=None, tenant_id=None, contract_id=None):
    """Write the `generated` block (the stored ref plus the baseline stamps; `uploaded_by` and
    `generated_by` are the generating admin) and set the item `generated`, from `missing`,
    `generated` or `awaiting_signature` (never from `signed`). Answers the row and the ref of the
    generated file the slot held before, whose file the plugin deletes after this write."""
    account = self._actor(actor, creator=True)
    previous, slot, refusal = self._generated_slot(draft_id, engagement_draft_id, document_kind, tenant_id, contract_id)
    if not isinstance(document, dict):
      raise AdministrationDenied(400, refusal)
    generated = {**document, "snapshot_sha256": snapshot_sha256, "generated_at": generated_at,
                 "generated_by": account.account_id}
    # The two contract slots (a tenant draft's, RM-133 a contract draft's) print the node plan.
    with_nodes = not engagement_draft_id
    if with_nodes:
      generated["nodes"] = nodes
    if (not drafts.valid_generated(generated, with_nodes=with_nodes)
        or generated["uploaded_by"] != account.account_id):
      raise AdministrationDenied(400, refusal)
    if slot["state"] == "signed":
      raise AdministrationDenied(409, "already_signed")
    # RM-127: the plan may have changed since `authorize_generated_document` read the snapshot's.
    if with_nodes and nodes != previous["nodes"]:
      raise AdministrationDenied(409, "draft_changed")
    replaced = slot["generated"]["ref"] if slot["generated"] is not None else None
    if draft_id:
      slot = {**slot, "state": "generated", "generated": generated}
      row = self._write_tenant_draft({**previous, "items": {**previous["items"], "contract": slot}}, account)
    elif contract_id:
      row = self._write_tenant_contract_draft({**previous, "state": "generated", "generated": generated}, account)
    else:
      row = self._write_engagement_draft({**previous, "document": {**slot, "state": "generated", "generated": generated}}, account)
    return {"draft": row, "replaced": replaced}

  @staticmethod
  def _generated_ref(generated):
    """The stored ref inside a `generated` block (what `resolve_engagement_pack` answers for it)."""
    return None if generated is None else {key: generated[key] for key in drafts.DOC_REF_KEYS}

  @_endpoint
  def activate_engagement_draft(self, actor, engagement_draft_id, documents=None):
    """One locked step, no marker. `documents` are the draft's packs (`signed`, `generated`) as
    `resolve_engagement_pack` verified them outside this lock, each bound to this draft and the
    pack slot; this method never reads the document store.

    In the contract's order: the parent must be a tenant (`parent_not_active`); an engagement
    `en_<uuid>` already under it means an earlier call crashed after `create_engagement`, so the row
    is deleted and the call answers `replayed`, whoever calls; otherwise the refs must still be the
    draft's, the draft complete, then the engagement is created from the draft alone with the signed
    pack as its `agreement` document and the generated pack, when there is one, as a second `other`
    document, and the row deleted (the files are the engagement's).
    """
    account = self._actor(actor, creator=True)
    row = self._engagement_draft(engagement_draft_id)
    if "draft_id" in row["parent"]:
      raise AdministrationDenied(409, "parent_not_active")
    tenant_id, request_id = row["parent"]["tenant_id"], engagement_draft_id[4:]
    engagement_id = engagement_id_for(request_id)
    existing = self.store.get("engagement", tenant_id, engagement_id)
    if existing is not None:
      self.store.delete("engagement_draft", engagement_draft_id)
      return {"engagementId": engagement_id, "tenantId": tenant_id, "replayed": True,
              "engagementHash": existing["engagement_hash"], "actor": account.account_id}
    slot = row["document"]
    stored = {"signed": slot["document"], "generated": self._generated_ref(slot["generated"])}
    resolved = documents if isinstance(documents, dict) else {}
    if {key: resolved.get(key) for key in stored} != stored:
      raise AdministrationDenied(409, "draft_changed")
    completeness = engagement_drafts.completeness(row)
    if not completeness["complete"]:
      raise AdministrationDenied(409, "draft_incomplete", missing=completeness["missing"],
                                 reasons=completeness["reasons"])
    tenant, account = self._authorized_tenant(actor, tenant_id, "engagements:create")
    # RM-133: the draft's pick, checked again now (the contract may have gone since the pick).
    contract_sha256 = self._tenant_contract_sha256(tenant, engagement_drafts.contract_pick(row))
    generated = slot["generated"]
    packs = [{**stored["signed"], "kind": "agreement", "title": "Engagement pack",
              "comment": "" if generated is None else "baseline sha256 " + generated["sha256"]}]
    if generated is not None:
      packs.append({**stored["generated"], "kind": "other", "title": "Generated engagement pack (unsigned)",
                    "comment": "snapshot sha256 " + generated["snapshot_sha256"]})
    # Instead of "uploader equals creator": each pack's uploader holds the platform role now, as the
    # tenant documents (`_first_preparation_documents`).
    for pack in packs:
      uploader = self.accounts.get_account(pack["uploaded_by"])
      if uploader is None or not uploader.active or not holds_platform_role(uploader):
        raise AdministrationDenied(400, "document_invalid")
    for other in self.store.raw_rows("engagement"):
      bound = other.get("documents") if isinstance(other.get("documents"), list) else []
      if any(isinstance(document, dict) and document.get("ref") == stored["signed"]["ref"] for document in bound):
        raise AdministrationDenied(409, "contract_in_use")
    request = self._engagement_request(
      row["display_name"], row["valid_from"], row["valid_until"],
      row["context"], engagement_drafts.asset_requests(row["assets"]), packs, None, None)
    record = self._engagement_record(account, tenant_id, request_id, request, contract_sha256, packs, None)
    # The draft's own copies (already validated by `completeness`); the library is not read.
    record = self._with_assets(record, normalize_engagement_assets(row["assets"]))
    self.store.put("engagement", tenant_id, engagement_id, record=record)
    self.store.delete("engagement_draft", engagement_draft_id)
    return {"engagementId": engagement_id, "tenantId": tenant_id, "replayed": False,
            "engagementHash": record["engagement_hash"], "actor": account.account_id}

  # RM-133 step 2: contract drafts, a tenant's further contracts prepared on the active tenant. A
  # full-portfolio Super-Tenant Admin only, after the tenant check (as `get_tenant_contract`). The
  # same split as the tenant draft: the service authorizes and writes under this lock; every
  # document read, write and delete is the plugin's, outside it. Activation is one locked call.

  def _tenant_contract_draft(self, tenant_id, contract_id):
    if not engagement_drafts.valid_tenant_id(tenant_id) or not tenant_contracts.valid_contract_id(contract_id):
      raise AdministrationDenied(400, "invalid_request")
    row = self.store.get("tenant_contract_draft", tenant_id, contract_id)
    if row is None:
      raise AdministrationDenied(404, "not_found")
    return row

  def _write_tenant_contract_draft(self, row, account, previous=None):
    """Write a changed row with its attribution; an unchanged one is not written."""
    if previous is not None and row == previous:
      return previous
    row = {**row, "updated_by": account.account_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    self.store.put("tenant_contract_draft", row["tenant_id"], row["contract_id"], record=row)
    return self.store.get("tenant_contract_draft", row["tenant_id"], row["contract_id"])

  @_endpoint
  def create_tenant_contract_draft(self, actor, tenant_id, request_id, supersedes=None):
    """Allocate `c_<n>` from the tenant row's counter and write the draft. The counter goes on the
    tenant row first, so a crash between the two writes leaves a gap, never a collision; a number is
    never reused. A create replayed with the same `request_id` answers the existing draft. RM-133
    step 3: with `supersedes` (`c_<k>`, a contract the tenant holds that nobody replaced) the draft
    is a revision, prefilled from it: its nodes, a term proposed from today."""
    tenant, account = self._platform_tenant(actor, tenant_id)
    if tenant.get("contract") is None:
      raise AdministrationDenied(400, "contract_required")
    request_id = _request_id(request_id)
    existing = next((row for row in self.store.list_tenant_contract_drafts(tenant_id) if row["request_id"] == request_id), None)
    if existing is not None:
      return existing
    supersedes = None if supersedes in (None, "") else supersedes
    nodes = []
    if supersedes is not None:
      if not tenant_contracts.valid_contract_id(supersedes):
        raise AdministrationDenied(400, "contract_unknown")
      exists, superseded_by, nodes = self._contract_lineage(tenant, supersedes)
      if not exists:
        raise AdministrationDenied(400, "contract_unknown")
      if superseded_by is not None:
        raise AdministrationDenied(409, "contract_superseded")
    blocks = _contract_blocks(tenant)
    number = tenant.get("next_contract_no")
    if type(number) is not int or number < tenant_contracts.FIRST_CONTRACT_NO:
      number = tenant_contracts.FIRST_CONTRACT_NO
    while (tenant_contracts.contract_id_for(number) in blocks
           or self.store.get("tenant_contract_draft", tenant_id, tenant_contracts.contract_id_for(number)) is not None):
      number += 1
    contract_id = tenant_contracts.contract_id_for(number)
    self.store.put("tenant", tenant_id, record={**tenant, "next_contract_no": number + 1})
    now = datetime.now(timezone.utc)
    row = tenant_contracts.new_draft(tenant_id, contract_id, request_id, account.account_id, now.isoformat())
    if supersedes is not None:
      row = {**row, "supersedes": supersedes, "nodes": nodes, "effective_from": now.date().isoformat()}
    self.store.put("tenant_contract_draft", tenant_id, contract_id, record=row)
    return self.store.get("tenant_contract_draft", tenant_id, contract_id)

  @_endpoint
  def get_tenant_contract_draft(self, actor, tenant_id, contract_id):
    self._platform_tenant(actor, tenant_id)
    return self._tenant_contract_draft(tenant_id, contract_id)

  @_endpoint
  def list_tenant_contract_drafts(self, actor, tenant_id):
    self._platform_tenant(actor, tenant_id)
    rows = sorted(self.store.list_tenant_contract_drafts(tenant_id), key=lambda row: tenant_contracts.contract_no(row["contract_id"]))
    return [tenant_contracts.draft_list_row(row) for row in rows]

  @_endpoint
  def update_tenant_contract_draft(self, actor, tenant_id, contract_id, changes):
    """Answers the row and the refs whose files the plugin deletes after this write."""
    _, account = self._platform_tenant(actor, tenant_id)
    previous = self._tenant_contract_draft(tenant_id, contract_id)
    try:
      row, dropped = tenant_contracts.apply_changes(previous, changes)
    except (tenant_contracts.TenantContractInvalid, drafts.DraftInvalid) as exc:
      raise AdministrationDenied(400, exc.code) from None
    # RM-127: the signed contract lists the nodes; the copy is dropped first, in its own update.
    if previous["state"] == "signed" and row["nodes"] != previous["nodes"]:
      raise AdministrationDenied(409, "nodes_locked")
    self._check_node_plan(account, previous, row)
    return {"draft": self._write_tenant_contract_draft(row, account, previous), "dropped": dropped}

  @_endpoint
  def authorize_tenant_contract_upload(self, actor, tenant_id, contract_id):
    _, account = self._platform_tenant(actor, tenant_id)
    self._tenant_contract_draft(tenant_id, contract_id)
    return {"accountId": account.account_id}

  @_endpoint
  def attach_tenant_contract_document(self, actor, tenant_id, contract_id, document):
    """Bind an uploaded signed copy (`store_tenant_contract_document`) and sign the draft. Answers
    the row and the ref the slot held before, whose file the plugin deletes after this write."""
    tenant, account = self._platform_tenant(actor, tenant_id)
    previous = self._tenant_contract_draft(tenant_id, contract_id)
    if not valid_doc_ref(document) or document["uploaded_by"] != account.account_id:
      raise AdministrationDenied(400, "contract_invalid")
    # The same bytes as another contract of the tenant would make two contracts share a sha256,
    # which readers resolve by: refused as in use (a fresh upload has a fresh ref, so the ref scan
    # alone would let it through).
    if document["sha256"] in _contract_sha256s(tenant):
      raise AdministrationDenied(409, "contract_in_use")
    replaced = previous["document"]
    row = {**previous, "state": "signed", "document": dict(document)}
    return {"draft": self._write_tenant_contract_draft(row, account),
            "replaced": replaced["ref"] if replaced is not None else None}

  @_endpoint
  def tenant_contract_draft_document_ref(self, actor, tenant_id, contract_id):
    self._platform_tenant(actor, tenant_id)
    document = self._tenant_contract_draft(tenant_id, contract_id)["document"]
    if document is None:
      raise AdministrationDenied(404, "not_found")
    return document

  @_endpoint
  def begin_tenant_contract_draft_delete(self, actor, tenant_id, contract_id):
    """A draft holding a signed copy is kept, as the other drafts; the number is not given back."""
    _, account = self._platform_tenant(actor, tenant_id)
    row = self._tenant_contract_draft(tenant_id, contract_id)
    if row["state"] == "signed":
      raise AdministrationDenied(409, "draft_has_signed_documents")
    return {"accountId": account.account_id, "documentRefs": tenant_contracts.document_refs(row)}

  @_endpoint
  def finish_tenant_contract_draft_delete(self, actor, tenant_id, contract_id, deleted_refs):
    """As `finish_engagement_draft_delete`: the row goes once both its files are gone."""
    self._platform_tenant(actor, tenant_id)
    row = self._tenant_contract_draft(tenant_id, contract_id)
    if not set(tenant_contracts.document_refs(row)) <= set(deleted_refs):
      raise AdministrationDenied(409, "conflict")
    self.store.delete("tenant_contract_draft", tenant_id, contract_id)
    return {"contract_id": contract_id}

  @_endpoint
  def activate_tenant_contract(self, actor, tenant_id, contract_id, documents=None):
    """One locked step, the RM-127 activation applied to one further contract. `documents` are the
    draft's signed copy and generated pack as `resolve_tenant_contract_document` verified them
    outside this lock; this method never reads the document store.

    In the contract's order: a block already on the tenant row means an earlier call crashed after
    the tenant write, so any draft row left is deleted and the call answers `replayed`; otherwise
    the refs must still be the draft's, the draft complete, every uploader a platform account, the
    signed copy's file bound nowhere else, every planned node assignable (a node the tenant holds in
    the same mode is the existing assignment; another mode, or another tenant, refuses and nothing
    is written); then the nodes are assigned, the block written, the draft row deleted.
    """
    tenant, account = self._platform_tenant(actor, tenant_id)
    if not tenant_contracts.valid_contract_id(contract_id):
      raise AdministrationDenied(400, "invalid_request")
    blocks = _contract_blocks(tenant)
    if contract_id in blocks:
      if self.store.get("tenant_contract_draft", tenant_id, contract_id) is not None:
        self.store.delete("tenant_contract_draft", tenant_id, contract_id)
      return {"tenantId": tenant_id, "contractId": contract_id, "replayed": True, "actor": account.account_id}
    row = self._tenant_contract_draft(tenant_id, contract_id)
    stored = {"signed": row["document"], "generated": self._generated_ref(row["generated"])}
    resolved = documents if isinstance(documents, dict) else {}
    if {key: resolved.get(key) for key in stored} != stored:
      raise AdministrationDenied(409, "draft_changed")
    completeness = tenant_contracts.completeness(row)
    if not completeness["complete"]:
      raise AdministrationDenied(409, "draft_incomplete", missing=completeness["missing"])
    for block in (row["document"], row["generated"]):
      uploader = self.accounts.get_account(block["uploaded_by"])
      if uploader is None or not uploader.active or not holds_platform_role(uploader):
        raise AdministrationDenied(400, "contract_invalid")
    self._refuse_documents_in_use({row["document"]["ref"], row["generated"]["ref"]}, exclude=(tenant_id, contract_id))
    if row["document"]["sha256"] in _contract_sha256s(tenant):
      raise AdministrationDenied(409, "contract_in_use")
    # RM-133 step 3: a revision replaces a contract nobody else replaced meanwhile; the replaced
    # contract stays in force for its own engagements and takes no new one.
    replaced = {}
    if row["supersedes"] is not None:
      exists, superseded_by, _ = self._contract_lineage(tenant, row["supersedes"])
      if not exists:
        raise AdministrationDenied(400, "contract_unknown")
      if superseded_by is not None:
        raise AdministrationDenied(409, "contract_superseded")
      if row["supersedes"] == tenant_contracts.FIRST_CONTRACT_ID:
        replaced = {"contract_superseded_by": contract_id}
      else:
        blocks = {**blocks, row["supersedes"]: {**blocks[row["supersedes"]], "superseded_by": contract_id}}
    self._assign_contract_nodes(account, tenant, row["nodes"])
    now = datetime.now(timezone.utc).isoformat()
    block = tenant_contracts.block_for(row, row["document"], row["generated"], account.account_id, now)
    self.store.put("tenant", tenant_id, record={**tenant, **replaced, "contracts": {**blocks, contract_id: block}})
    self.store.delete("tenant_contract_draft", tenant_id, contract_id)
    return {"tenantId": tenant_id, "contractId": contract_id, "replayed": False, "actor": account.account_id}

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
