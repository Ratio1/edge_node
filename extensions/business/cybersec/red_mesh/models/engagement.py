"""Engagement context models (PTES Pre-engagement metadata).

Phase 3 PR-3.1 of the PTES rebuild.

PTES Phase 1 (Pre-engagement Interactions) prescribes the metadata
captured at job creation that later feeds the report's Background,
Scope, Strength of Test, and Limitations sections. RedMesh's job-
creation form historically captured only *technical* parameters
(target, ports, mode, threads). This module adds the *engagement*
parameters as typed dataclasses.

Three distinct concerns are kept in separate dataclasses so that
the form, persistence, and API can address each independently:

  EngagementContext     — who, why, what data, what classification
  RulesOfEngagement     — the three RoE flags workers enforce
  AuthorizationRef      — written permission-to-test (R1FS document
                          CID + signer + third-party auth refs)

All fields default-empty so legacy/quick-launch jobs that do not
populate them continue to work. PR-3.3 wires these onto JobConfig;
PR-3.5 surfaces them as collapsible sections in the frontend
JobForm. The PDF renderer (Phase 6/7) consumes them when present
and falls back to ``Not provided`` placeholders when absent (per
P2 of the architectural principles — optional-but-typed).

Backwards-compat note
---------------------

The legacy ``engagement_metadata`` (free-form dict) field on
JobConfig is preserved during the PR-3.3 transition; pre-existing
jobs in R1FS still load. After PR-3.5 lands and the form emits
the typed shape, the free-form field is officially deprecated;
it is removed in a follow-up cleanup once no in-flight jobs
reference it.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


# ---------------------------------------------------------------------
# Allowed-value constants (single source of truth shared with the
# frontend form via redmeshApi.types.ts).
# ---------------------------------------------------------------------

DATA_CLASSIFICATIONS = (
  "PII",
  "PCI",
  "PHI",
  "Proprietary",
  "Public",
  "Mixed",
)

ASSET_EXPOSURES = (
  "external",     # internet-facing
  "dmz",          # in a DMZ
  "internal",     # private network only
  "airgapped",    # isolated network
)


# ---------------------------------------------------------------------
# Contact
# ---------------------------------------------------------------------


@dataclass
class Contact:
  """A point of contact for the engagement.

  PTES requires both a primary technical contact and a 24/7
  emergency contact (with two contact methods). Emergency contact
  is the one paged when a scan goes wrong (e.g., destabilizes a
  prod host).
  """
  name: str = ""
  email: str = ""
  phone: str = ""
  role: str = ""

  def to_dict(self) -> dict:
    return asdict(self)

  @classmethod
  def from_dict(cls, d: dict | None) -> "Contact | None":
    if not d:
      return None
    return cls(
      name=str(d.get("name", "")),
      email=str(d.get("email", "")),
      phone=str(d.get("phone", "")),
      role=str(d.get("role", "")),
    )

  def is_empty(self) -> bool:
    return not (self.name or self.email or self.phone or self.role)


# ---------------------------------------------------------------------
# EngagementContext — PTES §3.1 Background + §3.2 Overall Posture inputs
# ---------------------------------------------------------------------


@dataclass
class EngagementContext:
  """The 'who, why, what' captured at job creation.

  Drives the PDF Executive Summary's Background subsection (PTES
  §3.1) and the Technical Report's Introduction (PTES §4.1). Every
  field is optional — if the user skips this section, the report
  renders with explicit ``Not provided`` placeholders rather than
  fabricated text.
  """
  client_name: str = ""
  engagement_code: str = ""
  primary_objective: str = ""
  secondary_objective: str = ""
  scope_rationale: str = ""
  data_classification: str = ""        # one of DATA_CLASSIFICATIONS
  asset_exposure: str = ""             # one of ASSET_EXPOSURES
  methodology: str = "PTES + OWASP WSTG + CVSS v3.1"
  point_of_contact: Contact | None = None
  emergency_contact: Contact | None = None

  def to_dict(self) -> dict:
    out: dict[str, Any] = {
      "client_name": self.client_name,
      "engagement_code": self.engagement_code,
      "primary_objective": self.primary_objective,
      "secondary_objective": self.secondary_objective,
      "scope_rationale": self.scope_rationale,
      "data_classification": self.data_classification,
      "asset_exposure": self.asset_exposure,
      "methodology": self.methodology,
      "point_of_contact": self.point_of_contact.to_dict() if self.point_of_contact else None,
      "emergency_contact": self.emergency_contact.to_dict() if self.emergency_contact else None,
    }
    return out

  @classmethod
  def from_dict(cls, d: dict | None) -> "EngagementContext | None":
    if not d:
      return None
    return cls(
      client_name=str(d.get("client_name", "")),
      engagement_code=str(d.get("engagement_code", "")),
      primary_objective=str(d.get("primary_objective", "")),
      secondary_objective=str(d.get("secondary_objective", "")),
      scope_rationale=str(d.get("scope_rationale", "")),
      data_classification=str(d.get("data_classification", "")),
      asset_exposure=str(d.get("asset_exposure", "")),
      methodology=str(d.get("methodology", "PTES + OWASP WSTG + CVSS v3.1")),
      point_of_contact=Contact.from_dict(d.get("point_of_contact")),
      emergency_contact=Contact.from_dict(d.get("emergency_contact")),
    )

  def is_empty(self) -> bool:
    return all([
      not self.client_name, not self.engagement_code,
      not self.primary_objective, not self.secondary_objective,
      not self.scope_rationale, not self.data_classification,
      not self.asset_exposure,
      self.methodology in ("", "PTES + OWASP WSTG + CVSS v3.1"),
      self.point_of_contact is None or self.point_of_contact.is_empty(),
      self.emergency_contact is None or self.emergency_contact.is_empty(),
    ])

  def validate(self) -> list[str]:
    """Return a list of validation errors. Empty list = valid.

    The form is permissive — empty engagement is valid (quick-launch
    UX preserved). When a field IS populated, validate that enum-style
    fields contain a known value.
    """
    errors: list[str] = []
    if self.data_classification and self.data_classification not in DATA_CLASSIFICATIONS:
      errors.append(
        f"data_classification {self.data_classification!r} not in {DATA_CLASSIFICATIONS}"
      )
    if self.asset_exposure and self.asset_exposure not in ASSET_EXPOSURES:
      errors.append(
        f"asset_exposure {self.asset_exposure!r} not in {ASSET_EXPOSURES}"
      )
    return errors


# ---------------------------------------------------------------------
# RulesOfEngagement — PTES Pre-engagement RoE
# ---------------------------------------------------------------------


@dataclass
class RulesOfEngagement:
  """The rules of engagement workers enforce (RM-095: the engagement owns them).

  - authenticated_action: explicit opt-in for one harmless command
    (`id`, `PWD`, `uname`) over a session opened with an accepted
    default credential. Default false: without it the probe reports
    the accepted credential and does nothing with the session (RM-103).
  - stateful_probes_allowed: whether a webapp job may enable stateful
    probes (`allow_stateful_probes`). Default false.
  - ics_safe_mode_required: whether a network job must keep ICS safe
    mode on. Default true.

  The never-enforced `strength_of_test`, `dos_allowed`,
  `post_exploit_rules`, `blackout_windows` and `retest_window_end` were
  dropped in RM-095; `from_dict` ignores them, so archives written
  before still load. DoS is never permitted.
  """
  authenticated_action: bool = False
  stateful_probes_allowed: bool = False
  ics_safe_mode_required: bool = True

  def to_dict(self) -> dict:
    return {
      "authenticated_action": self.authenticated_action is True,
      "stateful_probes_allowed": self.stateful_probes_allowed is True,
      # Fails safe: anything but an explicit false keeps ICS safe mode required.
      "ics_safe_mode_required": self.ics_safe_mode_required is not False,
    }

  @classmethod
  def from_dict(cls, d: dict | None) -> "RulesOfEngagement | None":
    if not d:
      return None
    # Kept as sent, so `validate()` can refuse a non-boolean: these are
    # consents, and `bool("false")` is True.
    return cls(
      authenticated_action=d.get("authenticated_action", False),
      stateful_probes_allowed=d.get("stateful_probes_allowed", False),
      ics_safe_mode_required=d.get("ics_safe_mode_required", True),
    )

  def is_empty(self) -> bool:
    return self.to_dict() == RulesOfEngagement().to_dict()

  def validate(self) -> list[str]:
    return [
      f"{name} must be true or false, got {getattr(self, name)!r}"
      for name in ("authenticated_action", "stateful_probes_allowed", "ics_safe_mode_required")
      if not isinstance(getattr(self, name), bool)
    ]


# ---------------------------------------------------------------------
# AuthorizationRef — PTES Pre-engagement requires written permission
# ---------------------------------------------------------------------


@dataclass
class AuthorizationRef:
  """Reference to the authorization document (permission to test).

  Storage:
    The actual document binary is stored in R1FS (PDF / PNG / JPG).
    document_cid points to the file; document_thumbnail_cid points
    to a server-side-generated page-1 thumbnail used by the PDF
    appendix (full document is by-reference, not embedded).

  Third parties:
    PTES requires separate written authorization for third-party
    assets (cloud, MSSP). third_party_auth_cids is a list of R1FS
    CIDs each pointing to a separate auth document.
  """
  document_cid: str = ""
  document_thumbnail_cid: str = ""
  authorized_signer_name: str = ""
  authorized_signer_role: str = ""
  third_party_auth_cids: list[str] = field(default_factory=list)
  # Server-recorded upload metadata. Populated when the document is
  # uploaded through /upload_authorization so Appendix D can show
  # filename, MIME type, size, byte hash, and upload timestamp
  # without re-fetching the R1FS envelope.
  document_filename: str = ""
  document_mime: str = ""
  document_size_bytes: int = 0
  document_sha256: str = ""
  document_uploaded_at: str = ""

  def to_dict(self) -> dict:
    return {
      "document_cid": self.document_cid,
      "document_thumbnail_cid": self.document_thumbnail_cid,
      "authorized_signer_name": self.authorized_signer_name,
      "authorized_signer_role": self.authorized_signer_role,
      "third_party_auth_cids": list(self.third_party_auth_cids),
      "document_filename": self.document_filename,
      "document_mime": self.document_mime,
      "document_size_bytes": self.document_size_bytes,
      "document_sha256": self.document_sha256,
      "document_uploaded_at": self.document_uploaded_at,
    }

  @classmethod
  def from_dict(cls, d: dict | None) -> "AuthorizationRef | None":
    if not d:
      return None
    raw_third = d.get("third_party_auth_cids") or []
    third_list = [str(c) for c in raw_third if c]
    raw_size = d.get("document_size_bytes", 0)
    try:
      size_bytes = int(raw_size) if raw_size else 0
    except (TypeError, ValueError):
      size_bytes = 0
    return cls(
      document_cid=str(d.get("document_cid", "")),
      document_thumbnail_cid=str(d.get("document_thumbnail_cid", "")),
      authorized_signer_name=str(d.get("authorized_signer_name", "")),
      authorized_signer_role=str(d.get("authorized_signer_role", "")),
      third_party_auth_cids=third_list,
      document_filename=str(d.get("document_filename", "")),
      document_mime=str(d.get("document_mime", "")),
      document_size_bytes=size_bytes,
      document_sha256=str(d.get("document_sha256", "")),
      document_uploaded_at=str(d.get("document_uploaded_at", "")),
    )

  def is_empty(self) -> bool:
    return all([
      not self.document_cid,
      not self.document_thumbnail_cid,
      not self.authorized_signer_name,
      not self.authorized_signer_role,
      not self.third_party_auth_cids,
      not self.document_filename,
      not self.document_mime,
      not self.document_size_bytes,
      not self.document_sha256,
      not self.document_uploaded_at,
    ])

  def has_document(self) -> bool:
    """True when an authorization document has been uploaded."""
    return bool(self.document_cid)


# ---------------------------------------------------------------------
# Kickoff questionnaire bundle (R1FS persistence shape)
# ---------------------------------------------------------------------


@dataclass
class KickoffQuestionnaire:
  """The bundle of engagement-context fields persisted to R1FS as
  ``kickoff_questionnaire.json`` at job-creation time.

  Materialized once at job creation; immutable thereafter (a new
  job is created if any value changes). Its CID is stored on the
  JobArchive so report regeneration can fetch the original kickoff
  context even after engagement-context fields are GDPR-deleted.
  """
  engagement: EngagementContext | None = None
  roe: RulesOfEngagement | None = None
  authorization: AuthorizationRef | None = None
  schema_version: str = "1.0"
  created_at: str = ""

  def to_dict(self) -> dict:
    return {
      "schema_version": self.schema_version,
      "created_at": self.created_at,
      "engagement": self.engagement.to_dict() if self.engagement else None,
      "roe": self.roe.to_dict() if self.roe else None,
      "authorization": self.authorization.to_dict() if self.authorization else None,
    }

  @classmethod
  def from_dict(cls, d: dict | None) -> "KickoffQuestionnaire | None":
    if not d:
      return None
    return cls(
      engagement=EngagementContext.from_dict(d.get("engagement")),
      roe=RulesOfEngagement.from_dict(d.get("roe")),
      authorization=AuthorizationRef.from_dict(d.get("authorization")),
      schema_version=str(d.get("schema_version", "1.0")),
      created_at=str(d.get("created_at", "")),
    )

  def is_empty(self) -> bool:
    return all([
      self.engagement is None or self.engagement.is_empty(),
      self.roe is None or self.roe.is_empty(),
      self.authorization is None or self.authorization.is_empty(),
    ])
