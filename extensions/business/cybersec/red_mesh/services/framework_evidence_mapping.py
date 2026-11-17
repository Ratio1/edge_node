"""Explicit CSF-base translations; curated DNSC map is a complete authoritative override.

Five base rows are conservative RedMesh engineering interpretations, not NIST-issued mappings.
"""
from .evidence_engine import SIGNAL_KINDS

BASE_SIGNALS = {
  "ID.RA-01": "vulnerability_management",
  "PR.DS-02": "crypto_transport_findings",
  "PR.AA-03": "auth_access_findings",
  "PR.AA-05": "auth_access_findings",
  "ID.IM-02": "assessment_performed",
}

# Which control of which pack a scan signal speaks to. Curated from the official requirement text
# (DNSC Order 1/2026 Annex 1): a RedMesh pass shows open vulnerabilities, access and transport
# weaknesses, that a technical assessment took place, and whether SOC export or detection
# correlation ran. Controls about policy, training, supply chain or physical matters are not
# mapped: a scan says nothing about them.
CONTROL_SIGNALS = {
  "ro.dnsc.o1-2026": {
    # Vulnerabilities identified, reviewed, remediated; patches installed.
    "ID.RA-01.1": "vulnerability_management", "ID.RA-01.2": "vulnerability_management",
    "ID.RA-01.3": "vulnerability_management", "ID.RA-01.6": "vulnerability_management",
    "ID.RA-08.1": "vulnerability_management", "ID.RA-08.2": "vulnerability_management",
    "ID.AM-08.2": "vulnerability_management",
    # Identities, MFA, privileges.
    "PR.AA-01.1": "auth_access_findings", "PR.AA-01.2": "auth_access_findings",
    "PR.AA-01.4": "auth_access_findings", "PR.AA-03.2": "auth_access_findings",
    "PR.AA-05.3": "auth_access_findings", "PR.AA-05.4": "auth_access_findings",
    "PR.AA-05.7": "auth_access_findings", "PR.AA-05.9": "auth_access_findings",
    # Cryptographic mechanisms for remote access and data in transit.
    "PR.AA-03.4": "crypto_transport_findings", "PR.DS-02.2": "crypto_transport_findings",
    # A technical assessment took place: risk assessment inputs, security tests, scan analysis.
    "ID.RA-01.5": "assessment_performed", "ID.RA-05.1": "assessment_performed",
    "ID.RA-05.2": "assessment_performed", "ID.IM-02.1": "assessment_performed",
    "DE.AE-03.3": "assessment_performed",
    # Logging, monitoring and automated event review.
    "DE.AE-03.1": "soc_incident_evidence", "DE.AE-02.2": "soc_incident_evidence",
    "DE.CM-09.1": "soc_incident_evidence",
  },
}

PACK_STRATEGIES = {
  "ro.dnsc.o1-2026": {"authoritative": True,
                       "overrides": CONTROL_SIGNALS["ro.dnsc.o1-2026"], "presentation": "legacy"},
  "us.nist.csf-2.0": {"strategy": "identity", "presentation": "candidate"},
}

CANDIDATE_SUMMARIES = {
  "vulnerability_management": "Pass {pass_nr} vulnerability records inform identification; validation requires human review.",
  "crypto_transport_findings": "Pass {pass_nr} transport findings inform review of data-in-transit protection; outcome requires human review.",
  "auth_access_findings": "Pass {pass_nr} authentication or access findings require human distinction and outcome review.",
  "assessment_performed": "Finalized security test pass {pass_nr} informs potential improvements; it does not prove improvements were identified.",
}


def resolve(pack_id, controls):
  """Translate only selected controls; unknown packs deliberately have no inherited mapping."""
  config = PACK_STRATEGIES.get(pack_id, {})
  identity = config.get("strategy") == "identity"
  overrides = config.get("overrides", {})
  out = {}
  for control in controls:
    ref = control["ref_id"]
    kind = overrides.get(ref) if config.get("authoritative") or ref in overrides else BASE_SIGNALS.get(ref) if identity else None
    if kind:
      out[ref] = kind
  return out


def candidate_presentation(pack_id):
  return PACK_STRATEGIES.get(pack_id, {}).get("presentation") == "candidate"


assert all(kind in SIGNAL_KINDS for kind in BASE_SIGNALS.values())
assert all(kind in SIGNAL_KINDS for mapping in CONTROL_SIGNALS.values() for kind in mapping.values())
