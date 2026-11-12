"""Finding classification shared by the NIS2 rulebook and the framework self-assessment.

RM-120 phase 5. The rulebook (`rulebook_assessment.py`) evaluated a scan pass against its checks
with these helpers; the framework maturity self-assessment suggests evidence from the same
signals, so the classification lives here, neutral to either profile. Pure functions over a
pass's findings and the live triage map: no redaction, no storage, no text that names a target.
The rulebook keeps its redacted evidence refs; the self-assessment only names jobs and passes.
"""
from ..models import normalize_triage_status as _normalize_triage_status

SIGNAL_KINDS = ("vulnerability_management", "auth_access_findings", "crypto_transport_findings",
                "assessment_performed", "soc_incident_evidence")
FINDING_SIGNAL_KINDS = SIGNAL_KINDS[:3]
# Open findings at these severities on a mapped control override a passing self-declared verdict
# in the console's warning; the score itself never changes (contract invariant 4).
OVERRIDING_SEVERITIES = ("CRITICAL", "HIGH")

_CLOSED_TRIAGE_STATUSES = {"false_positive", "remediated"}
_GAP_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
_REVIEW_SEVERITIES = {"LOW", "INFO", "INFORMATIONAL", "INCONCLUSIVE"}
_ACCESS_KEYWORDS = {
  "access", "auth", "authorization", "authentication", "credential", "credentials",
  "login", "mfa", "password", "privilege", "session", "token", "cwe-287",
  "cwe-306", "cwe-798", "a01", "a07",
}
_CRYPTO_KEYWORDS = {
  "certificate", "cipher", "cleartext", "crypto", "cryptographic", "encryption",
  "https", "ssl", "tls", "transport", "x509",
}
_SOC_COMPLETED_TOKENS = ("sent", "completed", "success", "ok")


def _finding_id(finding):
  return str(finding.get("finding_id") or finding.get("id") or "").strip()


def _severity(finding):
  return str(finding.get("severity") or "").strip().upper()


def _triage_status(finding, triage_map):
  """The live triage status, whichever vocabulary the value was written in.

  `triage_state` on a finding used a different vocabulary from the one
  `_CLOSED_TRIAGE_STATUSES` is written in, and they overlapped on one value — so
  a finding remediated and marked `fixed` matched nothing and stayed actionable
  after it had been dealt with.
  """
  triage = triage_map.get(_finding_id(finding))
  if isinstance(triage, dict):
    return _normalize_triage_status(triage.get("status"))
  return _normalize_triage_status(
    (finding.get("triage") or {}).get("status") or finding.get("triage_state")
  )


def _is_actionable_finding(finding, triage_map):
  if not isinstance(finding, dict):
    return False
  finding_status = str(finding.get("status") or "").strip().lower()
  if finding_status == "not_vulnerable":
    return False
  if _triage_status(finding, triage_map) in _CLOSED_TRIAGE_STATUSES:
    return False
  return bool(_finding_id(finding) or finding.get("title") or finding.get("description"))


def _search_text(finding):
  parts = [
    finding.get("title"),
    finding.get("description"),
    finding.get("category"),
    finding.get("probe"),
    finding.get("cwe_id"),
    finding.get("owasp_id"),
    finding.get("cve"),
    finding.get("cve_id"),
  ]
  return " ".join(str(part).lower() for part in parts if part)


def _matches_keywords(finding, keywords):
  text = _search_text(finding)
  return any(keyword in text for keyword in keywords)


def actionable_findings(findings, triage_map):
  """The findings a pass still holds open: not `not_vulnerable`, not closed by triage."""
  return [finding for finding in (findings or []) if _is_actionable_finding(finding, triage_map or {})]


def matching_findings(signal_kind, findings):
  """The actionable findings a finding-backed signal kind looks at; empty for the other kinds."""
  if signal_kind == "vulnerability_management":
    return list(findings)
  if signal_kind == "auth_access_findings":
    return [finding for finding in findings if _matches_keywords(finding, _ACCESS_KEYWORDS)]
  if signal_kind == "crypto_transport_findings":
    return [finding for finding in findings if _matches_keywords(finding, _CRYPTO_KEYWORDS)]
  return []


def soc_outcome(soc_event_status, detection_correlation):
  """`completed`, `present` (metadata without a completed outcome) or `absent`."""
  soc = soc_event_status if isinstance(soc_event_status, dict) else None
  detection = detection_correlation if isinstance(detection_correlation, dict) else None
  status_text = " ".join(
    str(item).lower()
    for item in [
      (soc or {}).get("last_status"), (soc or {}).get("status"), (soc or {}).get("outcome"),
      (detection or {}).get("status"),
    ]
    if item
  )
  if any(token in status_text for token in _SOC_COMPLETED_TOKENS):
    return "completed"
  if soc is not None or detection is not None:
    return "present"
  return "absent"


def classify(signal_kind, findings, metadata=None):
  """One signal kind against one pass's actionable findings and job metadata.

  Returns `status` (`gap`, `needs_review`, `supported` or `not_observable`), the `gap` and
  `review` finding counts, and `severities`: how many open CRITICAL and HIGH findings matched.
  """
  metadata = metadata if isinstance(metadata, dict) else {}
  if signal_kind in FINDING_SIGNAL_KINDS:
    matched = matching_findings(signal_kind, findings or [])
    gap = [finding for finding in matched if _severity(finding) in _GAP_SEVERITIES]
    review = [finding for finding in matched if _severity(finding) not in _GAP_SEVERITIES]
    severities = {}
    for finding in gap:
      severity = _severity(finding)
      if severity in OVERRIDING_SEVERITIES:
        severities[severity] = severities.get(severity, 0) + 1
    status = "gap" if gap else "needs_review" if review else "supported"
    return {"status": status, "gap": len(gap), "review": len(review), "severities": severities}
  if signal_kind == "assessment_performed":
    return {"status": "supported", "gap": 0, "review": 0, "severities": {}}
  if signal_kind == "soc_incident_evidence":
    outcome = soc_outcome(metadata.get("soc_event_status"), metadata.get("detection_correlation"))
    return {"status": "supported" if outcome == "completed" else "needs_review",
            "gap": 0, "review": 0, "severities": {}}
  return {"status": "not_observable", "gap": 0, "review": 0, "severities": {}}
