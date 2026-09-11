from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time as _time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..constants import JOB_STATUS_FINALIZED
from ..models import (
  RULEBOOK_ASSESSMENT_SCHEMA,
  RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
  RULEBOOK_SUBMISSION_CONTRACT_VERSION,
  RulebookPendingSubmission,
  RulebookReviewAuditEntry,
  RulebookReviewState,
  RulebookSubmissionReference,
  RulebookSubmissionRegistry,
  VALID_RULEBOOK_ANSWER_VALUES,
  normalize_triage_status as _normalize_triage_status,
  VALID_RULEBOOK_CHECK_STATUSES,
  VALID_RULEBOOK_REVIEW_STATES,
)
from ..repositories import ArtifactRepository, JobStateRepository
from .event_redaction import stable_hmac_pseudonym, strip_sensitive_fields
from .scan_guards import reject_model_test_for_scan_operation


DEFAULT_RULEBOOK_PROFILE_ID = "nis2.eu_baseline.v1"
RULEBOOK_PROFILE_VERSION = "1.0.0"

_SUBMISSION_LOCKS = {}
_SUBMISSION_LOCKS_GUARD = threading.Lock()

_IPV4_RE = re.compile(
  r"(?<![\w.])"
  r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
  r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
  r"(?![\w.])"
)
_SECRET_ASSIGNMENT_RE = re.compile(
  r"(?i)\b(password|passwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*[^\s&,'\"}]+"
)
_BEARER_TOKEN_RE = re.compile(
  r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{8,}"
)
_JWT_RE = re.compile(
  r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])"
)
_PEM_PRIVATE_KEY_RE = re.compile(
  r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
  re.IGNORECASE | re.DOTALL,
)
_PROVIDER_TOKEN_RE = re.compile(
  r"(?<![A-Za-z0-9_-])(?:"
  r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}"
  r"|glpat-[A-Za-z0-9_-]{20,}"
  r"|gh[pousr]_[A-Za-z0-9]{20,}"
  r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"
  r"|xox[baprs]-[A-Za-z0-9-]{10,}"
  r")(?![A-Za-z0-9_-])"
)
_PUBLIC_REFERENCE_RE = re.compile(
  r"(?<![A-Za-z0-9])(?:"
  r"Qm[1-9A-HJ-NP-Za-km-z]{44}"
  r"|b[a-z2-7]{20,}"
  r"|sha256:[A-Fa-f0-9]{64}"
  r")(?![A-Za-z0-9])"
)
_UNLABELLED_TOKEN_RE = re.compile(
  r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-]))"
  r"(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}"
)
_UNLABELLED_HEX_RE = re.compile(
  r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,128}(?![A-Fa-f0-9])"
)

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


NIS2_BASELINE_PROFILE = {
  "profile_id": DEFAULT_RULEBOOK_PROFILE_ID,
  "profile_version": RULEBOOK_PROFILE_VERSION,
  "title": "NIS2 EU Baseline Evidence Readiness",
  "jurisdiction_scope": "EU baseline",
  "source_refs": [
    "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
    "https://digital-strategy.ec.europa.eu/en/policies/nis2-directive",
  ],
  "legal_notice": (
    "This profile maps RedMesh scan evidence to readiness checks. It is not a legal verdict, "
    "certification, or Member State transposition assessment."
  ),
  "checks": [
    {
      "check_id": "NIS2-21-RISK-001",
      "theme": "risk_management",
      "article_refs": ["Article 21(2)(a)", "Article 21(2)(e)"],
      "title": "Risk management and vulnerability treatment evidence",
      "control_intent": "Show that observed technical risks are identified and have treatment evidence.",
      "automated_signals": ["assessment_performed", "actionable_findings"],
      "signal_kind": "vulnerability_management",
      "review_question_id": "nis2.risk.risk_treatment_reviewed",
      "evidence_mapping": "Unresolved medium or higher findings indicate a readiness gap.",
      "limitations": "RedMesh cannot verify governance approval or enterprise risk appetite.",
    },
    {
      "check_id": "NIS2-21-INCIDENT-001",
      "theme": "incident_handling",
      "article_refs": ["Article 21(2)(b)", "Article 23"],
      "title": "Incident handling and SOC evidence",
      "control_intent": "Show that scan findings can feed detection, correlation, or SOC workflows.",
      "automated_signals": ["soc_event_status", "detection_correlation"],
      "signal_kind": "soc_incident_evidence",
      "review_question_id": "nis2.incident.incident_process",
      "evidence_mapping": "SOC export or detection correlation metadata supports technical readiness.",
      "limitations": "Reporting timelines and incident governance remain reviewer-assessed.",
    },
    {
      "check_id": "NIS2-21-BCM-001",
      "theme": "business_continuity",
      "article_refs": ["Article 21(2)(c)"],
      "title": "Business continuity and crisis management evidence",
      "control_intent": "Confirm continuity and crisis processes exist for the assessed service.",
      "automated_signals": [],
      "signal_kind": "manual_only",
      "review_question_id": "nis2.bcm.business_continuity",
      "evidence_mapping": "No direct RedMesh scan signal.",
      "limitations": "Requires reviewer evidence outside the scan archive.",
    },
    {
      "check_id": "NIS2-21-SUPPLY-001",
      "theme": "supply_chain",
      "article_refs": ["Article 21(2)(d)"],
      "title": "Supply-chain security evidence",
      "control_intent": "Confirm supplier and dependency risk handling exists for the assessed service.",
      "automated_signals": [],
      "signal_kind": "manual_only",
      "review_question_id": "nis2.supply.supplier_risk_reviewed",
      "evidence_mapping": "No direct RedMesh scan signal in this baseline.",
      "limitations": "Requires supplier, dependency, and contractual evidence outside RedMesh scan data.",
    },
    {
      "check_id": "NIS2-21-ACCESS-001",
      "theme": "access_control",
      "article_refs": ["Article 21(2)(i)", "Article 21(2)(j)"],
      "title": "Access control and authentication evidence",
      "control_intent": "Identify observable authentication, authorization, credential, or session gaps.",
      "automated_signals": ["auth_access_findings"],
      "signal_kind": "auth_access_findings",
      "review_question_id": "nis2.access.access_controls_reviewed",
      "evidence_mapping": "Unresolved access-control findings indicate a readiness gap.",
      "limitations": "A clean scan does not prove IAM policy or MFA coverage.",
    },
    {
      "check_id": "NIS2-21-CRYPTO-001",
      "theme": "cryptography",
      "article_refs": ["Article 21(2)(h)"],
      "title": "Cryptography and transport protection evidence",
      "control_intent": "Identify observable TLS, certificate, cleartext, or cryptographic weaknesses.",
      "automated_signals": ["crypto_transport_findings"],
      "signal_kind": "crypto_transport_findings",
      "review_question_id": "nis2.crypto.crypto_policy_reviewed",
      "evidence_mapping": "Unresolved crypto or transport findings indicate a readiness gap.",
      "limitations": "RedMesh cannot prove internal key management policy from a network/web scan.",
    },
    {
      "check_id": "NIS2-21-EFFECTIVENESS-001",
      "theme": "effectiveness",
      "article_refs": ["Article 21(2)(f)"],
      "title": "Security effectiveness assessment evidence",
      "control_intent": "Show that a technical assessment was performed and produced retained evidence.",
      "automated_signals": ["completed_scan_pass"],
      "signal_kind": "assessment_performed",
      "review_question_id": "nis2.effectiveness.assessment_reviewed",
      "evidence_mapping": "A completed RedMesh pass supports technical assessment evidence.",
      "limitations": "Management review and policy effectiveness require reviewer evidence.",
    },
    {
      "check_id": "NIS2-23-REPORTING-001",
      "theme": "incident_reporting",
      "article_refs": ["Article 23"],
      "title": "Significant incident reporting readiness",
      "control_intent": "Confirm the operator can evaluate and report significant incidents.",
      "automated_signals": [],
      "signal_kind": "manual_only",
      "review_question_id": "nis2.reporting.reporting_process",
      "evidence_mapping": "No direct RedMesh scan signal.",
      "limitations": "Requires reviewer evidence for notification ownership, thresholds, and timelines.",
    },
  ],
}

_PROFILES = {
  DEFAULT_RULEBOOK_PROFILE_ID: NIS2_BASELINE_PROFILE,
}


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _write_job_record(owner, job_id, job_specs, context):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context=context)
  return _job_repo(owner).put_job(job_id, job_specs)


def _utc_timestamp(epoch=None):
  if epoch is None:
    dt = datetime.now(timezone.utc)
  else:
    dt = datetime.fromtimestamp(float(epoch), timezone.utc)
  return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _target_values(job_config, job_specs=None):
  values = []
  for payload in (job_config or {}, job_specs or {}):
    for key in ("target", "target_url"):
      value = payload.get(key)
      if not value:
        continue
      value = str(value)
      values.append(value)
      try:
        host = urlsplit(value).hostname
      except ValueError:
        host = None
      if host:
        values.append(host)
  return [value for value in dict.fromkeys(values) if value]


def _safe_text(value, *, hmac_secret, redaction_values=None, max_len=1000):
  if value is None:
    return ""
  if isinstance(value, (dict, list)):
    value = strip_sensitive_fields(copy.deepcopy(value))
    text = str(value)
  else:
    text = str(value)
  for raw in sorted(set(redaction_values or []), key=len, reverse=True):
    if raw:
      text = text.replace(raw, stable_hmac_pseudonym(raw, hmac_secret, prefix="target"))

  def _replace_secret(match):
    return f"{match.group(1)}=<redacted>"

  def _replace_ip(match):
    return stable_hmac_pseudonym(match.group(0), hmac_secret, prefix="ip")

  text = _PEM_PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
  text = _BEARER_TOKEN_RE.sub("Authorization: Bearer <redacted>", text)
  text = _JWT_RE.sub("<redacted-jwt>", text)
  text = _SECRET_ASSIGNMENT_RE.sub(_replace_secret, text)
  text = _PROVIDER_TOKEN_RE.sub("<redacted-provider-token>", text)
  public_references = []

  def _preserve_public_reference(match):
    marker = f"publicrefmarker{len(public_references)}"
    public_references.append((marker, match.group(0)))
    return marker

  text = _PUBLIC_REFERENCE_RE.sub(_preserve_public_reference, text)
  text = _UNLABELLED_HEX_RE.sub("<redacted-hex-token>", text)
  text = _UNLABELLED_TOKEN_RE.sub("<redacted-token>", text)
  for marker, public_reference in public_references:
    text = text.replace(marker, public_reference)
  text = _IPV4_RE.sub(_replace_ip, text)
  text = " ".join(text.split())
  return text[:max_len]


def _error(code, job_id, **extra):
  return {
    "status": "error",
    "error": code,
    "job_id": job_id,
    **extra,
  }


def _error_message(payload):
  return str(payload.get("message") or payload.get("error") or "Rulebook assessment failed.")


def _sanitize_error(owner, payload):
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  return {
    "error": _safe_text(payload.get("error") or "rulebook_assessment_failed", hmac_secret=hmac_secret, max_len=120),
    "message": _safe_text(_error_message(payload), hmac_secret=hmac_secret, max_len=280),
    "retryable": bool(payload.get("retryable", True)),
    "at": _utc_timestamp(),
  }


def _profile(profile_id):
  return _PROFILES.get(profile_id or DEFAULT_RULEBOOK_PROFILE_ID)


def list_rulebook_profiles():
  return [
    {
      "profile_id": profile["profile_id"],
      "profile_version": profile["profile_version"],
      "title": profile["title"],
      "jurisdiction_scope": profile["jurisdiction_scope"],
    }
    for profile in _PROFILES.values()
  ]


def _resolve_scan_context(owner, job_id, pass_nr=None):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return None, _error("job_not_found", job_id)

  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_assessment")
  if unsupported:
    return None, {
      **unsupported,
      "error": "model_test_not_supported",
      "error_class": unsupported.get("error_class") or unsupported.get("error"),
    }

  artifacts = _artifact_repo(owner)
  job_cid = job_specs.get("job_cid")
  archive = {}
  if job_cid:
    archive = artifacts.get_archive(job_specs)
    if not isinstance(archive, dict):
      return None, _error("artifact_not_found", job_id, artifact="archive", artifact_cid=job_cid)
    job_config = archive.get("job_config") or artifacts.get_job_config(job_specs) or {}
    passes = archive.get("passes") or []
    if not passes:
      return None, _error("no_completed_passes", job_id)
    if pass_nr is None:
      pass_data = passes[-1]
    else:
      pass_data = next((item for item in passes if item.get("pass_nr") == pass_nr), None)
    if not isinstance(pass_data, dict):
      return None, _error(
        "pass_not_found",
        job_id,
        available_passes=[item.get("pass_nr") for item in passes if isinstance(item, dict)],
      )
    agg_cid = pass_data.get("aggregated_report_cid")
    aggregated = artifacts.get_json(agg_cid) if agg_cid else {}
  else:
    pass_reports = job_specs.get("pass_reports") or []
    if not pass_reports:
      return None, _error("no_completed_passes", job_id)
    if pass_nr is None:
      pass_ref = pass_reports[-1]
    else:
      pass_ref = next((item for item in pass_reports if item.get("pass_nr") == pass_nr), None)
    if not isinstance(pass_ref, dict):
      return None, _error(
        "pass_not_found",
        job_id,
        available_passes=[item.get("pass_nr") for item in pass_reports if isinstance(item, dict)],
      )
    pass_data = artifacts.get_pass_report(pass_ref.get("report_cid"))
    if not isinstance(pass_data, dict):
      return None, _error("artifact_not_found", job_id, artifact="pass_report", artifact_cid=pass_ref.get("report_cid"))
    agg_cid = pass_data.get("aggregated_report_cid")
    aggregated = artifacts.get_json(agg_cid) if agg_cid else {}
    job_config = artifacts.get_job_config(job_specs) or {}

  return {
    "job_specs": job_specs,
    "job_config": job_config if isinstance(job_config, dict) else {},
    "archive": archive if isinstance(archive, dict) else {},
    "pass_data": pass_data,
    "aggregated": aggregated if isinstance(aggregated, dict) else {},
  }, None


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


def _safe_finding_ref(finding, *, hmac_secret, redaction_values, triage_map):
  payload = {
    "type": "finding",
    "finding_id": _safe_text(_finding_id(finding), hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=160),
    "severity": _severity(finding),
    "title": _safe_text(finding.get("title") or "Untitled finding", hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=240),
    "category": _safe_text(finding.get("category") or "", hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=120),
    "probe": _safe_text(finding.get("probe") or "", hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=160),
    "cwe_id": _safe_text(finding.get("cwe_id") or "", hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=80),
    "owasp_id": _safe_text(finding.get("owasp_id") or "", hmac_secret=hmac_secret, redaction_values=redaction_values, max_len=80),
    "triage_status": _triage_status(finding, triage_map) or None,
  }
  return {key: value for key, value in payload.items() if value not in (None, "", [])}


def _source_refs(ctx, actual_pass_nr):
  pass_data = ctx["pass_data"]
  refs = [{"type": "job", "job_id": ctx["job_specs"].get("job_id")}]
  refs.append({"type": "pass", "pass_nr": actual_pass_nr})
  if pass_data.get("aggregated_report_cid"):
    refs.append({"type": "artifact", "artifact_kind": "aggregated_report", "artifact_cid": pass_data.get("aggregated_report_cid")})
  return refs


def _auto_from_findings(check, findings, *, hmac_secret, redaction_values, triage_map):
  gap_findings = [finding for finding in findings if _severity(finding) in _GAP_SEVERITIES]
  review_findings = [
    finding
    for finding in findings
    if _severity(finding) not in _GAP_SEVERITIES or _severity(finding) in _REVIEW_SEVERITIES
  ]
  refs = [
    _safe_finding_ref(finding, hmac_secret=hmac_secret, redaction_values=redaction_values, triage_map=triage_map)
    for finding in gap_findings[:10]
  ]
  if gap_findings:
    return {
      "status": "gap",
      "summary": f"{len(gap_findings)} unresolved medium-or-higher finding(s) match this check.",
      "gap_reason": "Unresolved scan findings need treatment evidence.",
      "evidence_refs": refs,
    }
  if review_findings:
    return {
      "status": "needs_review",
      "summary": f"{len(review_findings)} lower-severity or inconclusive finding(s) need reviewer interpretation.",
      "gap_reason": "",
      "evidence_refs": [
        _safe_finding_ref(finding, hmac_secret=hmac_secret, redaction_values=redaction_values, triage_map=triage_map)
        for finding in review_findings[:10]
      ],
    }
  return {
    "status": "supported",
    "summary": "No unresolved matching findings were observed in the selected RedMesh pass.",
    "gap_reason": "",
    "evidence_refs": [],
  }


def _automated_check_result(check, ctx, *, hmac_secret, redaction_values, triage_map):
  pass_data = ctx["pass_data"]
  findings = [
    finding
    for finding in (pass_data.get("findings") or [])
    if _is_actionable_finding(finding, triage_map)
  ]
  signal_kind = check.get("signal_kind")

  if signal_kind == "vulnerability_management":
    result = _auto_from_findings(check, findings, hmac_secret=hmac_secret, redaction_values=redaction_values, triage_map=triage_map)
  elif signal_kind == "auth_access_findings":
    matched = [finding for finding in findings if _matches_keywords(finding, _ACCESS_KEYWORDS)]
    result = _auto_from_findings(check, matched, hmac_secret=hmac_secret, redaction_values=redaction_values, triage_map=triage_map)
  elif signal_kind == "crypto_transport_findings":
    matched = [finding for finding in findings if _matches_keywords(finding, _CRYPTO_KEYWORDS)]
    result = _auto_from_findings(check, matched, hmac_secret=hmac_secret, redaction_values=redaction_values, triage_map=triage_map)
  elif signal_kind == "assessment_performed":
    result = {
      "status": "supported",
      "summary": "A completed RedMesh scan pass is available as retained technical assessment evidence.",
      "gap_reason": "",
      "evidence_refs": _source_refs(ctx, pass_data.get("pass_nr") or 1),
    }
  elif signal_kind == "soc_incident_evidence":
    soc = ctx["job_specs"].get("soc_event_status") or ctx["archive"].get("soc_event_status")
    detection = ctx["job_specs"].get("detection_correlation") or ctx["archive"].get("detection_correlation")
    status_text = " ".join(
      str(item).lower()
      for item in [
        (soc or {}).get("last_status") if isinstance(soc, dict) else "",
        (soc or {}).get("status") if isinstance(soc, dict) else "",
        (soc or {}).get("outcome") if isinstance(soc, dict) else "",
        (detection or {}).get("status") if isinstance(detection, dict) else "",
      ]
      if item
    )
    if any(token in status_text for token in ("sent", "completed", "success", "ok")):
      result = {
        "status": "supported",
        "summary": "RedMesh has SOC export or detection-correlation metadata for this job.",
        "gap_reason": "",
        "evidence_refs": [{"type": "job_metadata", "fields": ["soc_event_status", "detection_correlation"]}],
      }
    elif isinstance(soc, dict) or isinstance(detection, dict):
      result = {
        "status": "needs_review",
        "summary": "SOC or detection metadata exists but does not show a completed export/correlation outcome.",
        "gap_reason": "",
        "evidence_refs": [{"type": "job_metadata", "fields": ["soc_event_status", "detection_correlation"]}],
      }
    else:
      result = {
        "status": "needs_review",
        "summary": "No SOC export or detection-correlation metadata was observed for this job.",
        "gap_reason": "",
        "evidence_refs": [],
      }
  else:
    result = {
      "status": "not_observable",
      "summary": "This check needs reviewer evidence outside the RedMesh scan archive.",
      "gap_reason": "",
      "evidence_refs": [],
    }

  return {
    "check_id": check["check_id"],
    "title": check["title"],
    "theme": check["theme"],
    "article_refs": list(check.get("article_refs") or []),
    "status": result["status"],
    "automated_status": result["status"],
    "source": "automated" if result["status"] != "not_observable" else "not_observable",
    "summary": result["summary"],
    "gap_reason": result.get("gap_reason") or "",
    "evidence_refs": result.get("evidence_refs") or [],
    "review_question_id": check.get("review_question_id"),
    "review_answer": None,
    "limitations": [check.get("limitations")] if check.get("limitations") else [],
  }


def _apply_review(check_result, review):
  question_id = check_result.get("review_question_id")
  answers = (review.to_dict().get("answers") if review else {}) or {}
  answer = answers.get(question_id)
  if not answer:
    return check_result

  result = dict(check_result)
  result["review_answer"] = answer
  auto_status = result.get("automated_status")
  value = answer.get("value")
  if auto_status == "gap":
    result["status"] = "gap"
    result["source"] = "mixed"
    return result

  if value == "yes":
    result["status"] = "supported"
    result["gap_reason"] = ""
  elif value == "no":
    result["status"] = "gap"
    result["gap_reason"] = "Reviewer indicated evidence is missing or insufficient."
  elif value == "not_applicable":
    result["status"] = "not_applicable"
    result["gap_reason"] = ""
  else:
    result["status"] = "needs_review"
  result["source"] = "reviewer"
  return result


def _status_counts(checks):
  counts = {status: 0 for status in sorted(VALID_RULEBOOK_CHECK_STATUSES)}
  for check in checks:
    status = check.get("status")
    if status in counts:
      counts[status] += 1
  return counts


def _review_view(review, *, hmac_secret):
  if review is None:
    return {"review_state": "draft", "answers": {}}
  payload = review.to_dict()
  payload.pop("last_reopen_idempotency_key", None)
  payload.pop("last_reopen_from_revision", None)
  payload.pop("last_reopen_actor", None)
  payload["note"] = _safe_text(payload.get("note") or "", hmac_secret=hmac_secret, max_len=1000)
  for answer in (payload.get("answers") or {}).values():
    if isinstance(answer, dict):
      answer["note"] = _safe_text(answer.get("note") or "", hmac_secret=hmac_secret, max_len=1000)
  return payload


def _profile_meta(job_specs, profile_id):
  assessments = job_specs.get("rulebook_assessments") or {}
  if not isinstance(assessments, dict):
    return {}
  meta = assessments.get(profile_id)
  return meta if isinstance(meta, dict) else {}


def _meta_pass_nr(meta):
  value = meta.get("latest_pass_nr", meta.get("pass_nr"))
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


def _existing_same_pass_artifact(owner, job_id, profile_id, pass_nr):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return None
  meta = _profile_meta(job_specs, profile_id)
  artifact_cid = meta.get("artifact_cid")
  if not artifact_cid or _meta_pass_nr(meta) != int(pass_nr):
    return None
  if meta.get("run_state") not in (None, "succeeded"):
    return None
  assessment = _artifact_repo(owner).get_json(artifact_cid)
  if not isinstance(assessment, dict):
    return None
  if (
    assessment.get("schema_version") != RULEBOOK_ASSESSMENT_SCHEMA_VERSION
    or assessment.get("artifact_kind") != "generated_assessment"
  ):
    return None
  return meta, assessment


def _history_with_previous(existing_meta, new_meta):
  history = []
  for item in existing_meta.get("history") or []:
    if isinstance(item, dict):
      history.append(dict(item))
  previous_cid = existing_meta.get("artifact_cid")
  if previous_cid and previous_cid != new_meta.get("artifact_cid"):
    previous = {
      "artifact_cid": previous_cid,
      "pass_nr": existing_meta.get("latest_pass_nr", existing_meta.get("pass_nr")),
      "profile_version": existing_meta.get("profile_version"),
      "schema_version": existing_meta.get("schema_version"),
      "artifact_kind": existing_meta.get("artifact_kind"),
      "last_generated_at": existing_meta.get("last_generated_at"),
      "status_counts": existing_meta.get("status_counts"),
      "review_state": existing_meta.get("review_state"),
    }
    if not any(item.get("artifact_cid") == previous_cid for item in history):
      history.append({key: value for key, value in previous.items() if value not in (None, "", [])})
  return history[-20:]


def _write_assessment_meta(owner, job_id, profile_id, meta, *, context):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return None
  assessments = dict(job_specs.get("rulebook_assessments") or {})
  existing_meta = assessments.get(profile_id) if isinstance(assessments.get(profile_id), dict) else {}
  if meta.get("run_state") == "succeeded":
    meta = dict(meta)
    meta["history"] = _history_with_previous(existing_meta, meta)
  assessments[profile_id] = meta
  job_specs["rulebook_assessments"] = assessments
  return _write_job_record(owner, job_id, job_specs, context=context)


def _success_meta(result, artifact_cid):
  generated_at = result["assessment"]["generated_at"]
  return {
    "schema": RULEBOOK_ASSESSMENT_SCHEMA,
    "schema_version": RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
    "artifact_kind": "generated_assessment",
    "profile_id": result["profile_id"],
    "profile_version": result["profile_version"],
    "artifact_cid": artifact_cid,
    "last_generated_at": generated_at,
    "pass_nr": result["pass_nr"],
    "latest_pass_nr": result["pass_nr"],
    "status_counts": result["status_counts"],
    "review_state": result["assessment"]["review_state"].get("review_state", "draft"),
    "auto_enabled": True,
    "run_state": "succeeded",
  }


def _failed_meta(owner, job_id, profile_id, payload):
  profile = _profile(profile_id)
  existing = _profile_meta(owner._get_job_from_cstore(job_id) or {}, profile_id)
  meta = dict(existing)
  meta.update({
    "schema": RULEBOOK_ASSESSMENT_SCHEMA,
    "schema_version": RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
    "profile_id": profile_id,
    "profile_version": profile["profile_version"] if profile else existing.get("profile_version"),
    "auto_enabled": True,
    "run_state": "failed",
    "last_error": _sanitize_error(owner, payload),
  })
  return meta


def build_rulebook_assessment(
  owner,
  job_id,
  profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
  pass_nr=None,
  *,
  include_review=True,
  artifact_kind="generated_assessment",
  submission=None,
):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  ctx, err = _resolve_scan_context(owner, job_id, pass_nr=pass_nr)
  if err:
    return err

  job_specs = ctx["job_specs"]
  actual_pass_nr = ctx["pass_data"].get("pass_nr") or pass_nr or 1
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  redaction_values = _target_values(ctx["job_config"], job_specs)
  target_value = (redaction_values or [job_id or "unknown"])[0]
  target_pseudonym = stable_hmac_pseudonym(target_value, hmac_secret, prefix="target")
  triage_map = _job_repo(owner).list_job_triage(job_id)
  review = _job_repo(owner).get_rulebook_review_model(job_id, profile["profile_id"]) if include_review else None

  checks = []
  for check in profile["checks"]:
    check_result = _automated_check_result(
      check,
      ctx,
      hmac_secret=hmac_secret,
      redaction_values=redaction_values,
      triage_map=triage_map,
    )
    checks.append(_apply_review(check_result, review))

  counts = _status_counts(checks)
  assessment = {
    "schema": RULEBOOK_ASSESSMENT_SCHEMA,
    "schema_version": RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
    "artifact_kind": artifact_kind,
    "job_id": job_id,
    "generated_at": _utc_timestamp(),
    "profile": {
      "profile_id": profile["profile_id"],
      "profile_version": profile["profile_version"],
      "title": profile["title"],
      "jurisdiction_scope": profile["jurisdiction_scope"],
      "source_refs": list(profile.get("source_refs") or []),
      "legal_notice": profile["legal_notice"],
    },
    "scan_context": {
      "target_ref": target_pseudonym,
      "scan_type": job_specs.get("scan_type"),
      "job_status": job_specs.get("job_status"),
      "pass_nr": actual_pass_nr,
      "job_created_at": _utc_timestamp(job_specs.get("date_created")) if job_specs.get("date_created") else None,
      "job_completed_at": _utc_timestamp(job_specs.get("date_completed")) if job_specs.get("date_completed") else None,
      "job_archive_cid": job_specs.get("job_cid"),
      "aggregated_report_cid": ctx["pass_data"].get("aggregated_report_cid"),
      "finding_count": len(ctx["pass_data"].get("findings") or []),
      "worker_count": job_specs.get("worker_count") or len(job_specs.get("workers") or {}),
    },
    "status_counts": counts,
    "checks": checks,
    "review_state": _review_view(review, hmac_secret=hmac_secret),
    "limitations": [
      "Evidence states are based on RedMesh scan data plus reviewer input.",
      "National transposition, governance approval, contracts, and reporting operations need separate review.",
      "A clean technical scan does not prove organization-wide control operation.",
    ],
  }
  if isinstance(submission, dict):
    assessment["submission"] = dict(submission)
  return {
    "status": "ok",
    "job_id": job_id,
    "profile_id": profile["profile_id"],
    "profile_version": profile["profile_version"],
    "pass_nr": actual_pass_nr,
    "status_counts": counts,
    "assessment": assessment,
  }


def generate_rulebook_assessment(owner, job_id, profile_id=DEFAULT_RULEBOOK_PROFILE_ID, pass_nr=None, persist=True, force=True):
  result = build_rulebook_assessment(
    owner,
    job_id,
    profile_id=profile_id,
    pass_nr=pass_nr,
    include_review=not persist,
  )
  if result.get("status") != "ok":
    profile = _profile(profile_id)
    if profile and persist:
      _write_assessment_meta(
        owner,
        job_id,
        profile["profile_id"],
        _failed_meta(owner, job_id, profile["profile_id"], result),
        context="rulebook_assessment_failed",
      )
    return result

  artifact_cid = None
  if persist:
    existing = None if force else _existing_same_pass_artifact(owner, job_id, result["profile_id"], result["pass_nr"])
    if existing:
      meta, assessment = existing
      return {
        **result,
        "assessment": assessment,
        "artifact_cid": meta.get("artifact_cid"),
        "generated": True,
        "cached": True,
      }

    artifact_cid = _artifact_repo(owner).put_json(result["assessment"], show_logs=False)
    if not artifact_cid:
      failed = _error("artifact_write_failed", job_id, profile_id=profile_id)
      _write_assessment_meta(
        owner,
        job_id,
        result["profile_id"],
        _failed_meta(owner, job_id, result["profile_id"], failed),
        context="rulebook_assessment_failed",
      )
      return failed

    _write_assessment_meta(
      owner,
      job_id,
      result["profile_id"],
      _success_meta(result, artifact_cid),
      context="rulebook_assessment",
    )

  return {
    **result,
    "artifact_cid": artifact_cid,
    "generated": bool(artifact_cid),
  }


def ensure_rulebook_assessment(owner, job_id, profile_id=DEFAULT_RULEBOOK_PROFILE_ID, pass_nr=None):
  return generate_rulebook_assessment(
    owner,
    job_id,
    profile_id=profile_id,
    pass_nr=pass_nr,
    persist=True,
    force=False,
  )


def get_rulebook_assessment_status(owner, job_id, profile_id=DEFAULT_RULEBOOK_PROFILE_ID):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "generated": False, "profile_id": profile_id}
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_assessment_status")
  if unsupported:
    return {
      **unsupported,
      "error": "model_test_not_supported",
      "error_class": unsupported.get("error_class") or unsupported.get("error"),
      "found": True,
      "generated": False,
    }
  meta = (job_specs.get("rulebook_assessments") or {}).get(profile["profile_id"])
  if not isinstance(meta, dict) or not meta:
    result = {
      "job_id": job_id,
      "found": True,
      "generated": False,
      "profile_id": profile["profile_id"],
      "profile_version": profile["profile_version"],
      "schema": RULEBOOK_ASSESSMENT_SCHEMA,
      "schema_version": RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
    }
  else:
    result = {
      "job_id": job_id,
      "found": True,
      "generated": bool(meta.get("artifact_cid")) and meta.get("run_state") != "failed",
      **meta,
    }
  result["submission_contract_version"] = RULEBOOK_SUBMISSION_CONTRACT_VERSION
  try:
    review = _job_repo(owner).get_rulebook_review_model(job_id, profile["profile_id"])
    result.update(_submission_public_state(owner, job_id, job_specs, profile, review))
  except ValueError:
    result.update({
      "submission_contract_version": None,
      "submission_contract_unsupported": True,
    })
  return result


def _submission_lock(owner, job_id, profile_id):
  key = f"{getattr(owner, 'cfg_instance_id', '')}:{job_id}:{profile_id}"
  with _SUBMISSION_LOCKS_GUARD:
    lock = _SUBMISSION_LOCKS.get(key)
    if lock is None:
      lock = threading.RLock()
      _SUBMISSION_LOCKS[key] = lock
  return lock


def _empty_submission_registry():
  return RulebookSubmissionRegistry()


def _submission_registry(repo, job_id, profile_id):
  return repo.get_rulebook_submission_registry_model(job_id, profile_id) or _empty_submission_registry()


def _owner_time(owner):
  return float(getattr(owner, "time", _time.time)())


def _latest_pass_nr(owner, job_id):
  ctx, err = _resolve_scan_context(owner, job_id)
  if err:
    return None, err
  raw = ctx["pass_data"].get("pass_nr") or 1
  try:
    return int(raw), None
  except (TypeError, ValueError):
    return None, _error("pass_not_found", job_id)


def _legacy_submission_reference(job_specs, profile, review):
  if review is None or review.review_state != "reviewed":
    return None
  meta = _profile_meta(job_specs, profile["profile_id"])
  cid = str(meta.get("artifact_cid") or "").strip()
  if not cid:
    return None
  try:
    pass_nr = int(meta.get("latest_pass_nr", meta.get("pass_nr", 0)) or 0)
  except (TypeError, ValueError):
    pass_nr = 0
  return RulebookSubmissionReference(
    revision=0,
    cid=cid,
    submitted_at=review.updated_at,
    actor=review.reviewer,
    pass_nr=pass_nr,
    profile_id=profile["profile_id"],
    profile_version=str(meta.get("profile_version") or review.profile_version or profile["profile_version"]),
    schema_version=str(meta.get("schema_version") or "1.0.0"),
    review_revision=review.review_revision,
    legacy=True,
  ).to_dict()


def _submission_reference_view(reference, *, latest_pass_nr, profile_version):
  payload = reference.to_dict() if isinstance(reference, RulebookSubmissionReference) else dict(reference)
  stale_reasons = []
  if latest_pass_nr is not None and int(payload.get("pass_nr", 0) or 0) != int(latest_pass_nr):
    stale_reasons.append("newer_scan_pass")
  if payload.get("profile_version") != profile_version:
    stale_reasons.append("newer_profile_version")
  return {
    **payload,
    "artifact_cid": payload.get("cid"),
    "stale": bool(stale_reasons),
    "stale_reasons": stale_reasons,
  }


def _submission_public_state(owner, job_id, job_specs, profile, review):
  repo = _job_repo(owner)
  registry = _submission_registry(repo, job_id, profile["profile_id"])
  registry_payload = registry.to_dict()
  latest_pass_nr, _ = _latest_pass_nr(owner, job_id)
  references = list(registry_payload.get("submissions") or [])
  legacy_reference = _legacy_submission_reference(job_specs, profile, review)
  if legacy_reference and not any(item.get("cid") == legacy_reference["cid"] for item in references):
    references.append(legacy_reference)
  views = [
    _submission_reference_view(
      reference,
      latest_pass_nr=latest_pass_nr,
      profile_version=profile["profile_version"],
    )
    for reference in sorted(references, key=lambda item: int(item.get("revision", 0) or 0), reverse=True)
  ]
  pending = registry_payload.get("pending")
  latest = views[0] if views else None
  migration_required = bool(review and review.review_state == "reviewed" and legacy_reference is None)
  effective_state = "draft"
  if not pending and latest and review and review.review_state in {"submitted", "reviewed"}:
    effective_state = "submitted"
  operation_state = None
  if pending:
    operation_state = "failed" if pending.get("last_error") else "submitting"
  return {
    "submission_contract_version": RULEBOOK_SUBMISSION_CONTRACT_VERSION,
    "effective_review_state": effective_state,
    "review_revision": review.review_revision if review else 0,
    "latest_submission": latest,
    "submissions": views,
    "submission_operation_state": operation_state,
    "submission_error": (pending or {}).get("last_error") if isinstance(pending, dict) else None,
    "migration_submission_required": migration_required,
  }


def _submission_error(code, job_id, profile_id, message, *, retryable=False, **extra):
  return _error(
    code,
    job_id,
    profile_id=profile_id,
    submission_contract_version=RULEBOOK_SUBMISSION_CONTRACT_VERSION,
    message=message,
    retryable=retryable,
    **extra,
  )


def _unsupported_submission_registry_error(job_id, profile_id):
  return _submission_error(
    "submission_contract_unsupported",
    job_id,
    profile_id,
    "Submission registry contract version is not supported by this backend.",
  )


def get_rulebook_review(owner, job_id, profile_id=DEFAULT_RULEBOOK_PROFILE_ID):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return _error("job_not_found", job_id, profile_id=profile_id)
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_review")
  if unsupported:
    return {
      **unsupported,
      "error": "model_test_not_supported",
      "error_class": unsupported.get("error_class") or unsupported.get("error"),
    }
  if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
    return _error(
      "job_not_finalized",
      job_id,
      profile_id=profile["profile_id"],
      job_status=job_specs.get("job_status"),
    )
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  repo = _job_repo(owner)
  review = repo.get_rulebook_review_model(job_id, profile["profile_id"])
  try:
    submission_state = _submission_public_state(owner, job_id, job_specs, profile, review)
  except ValueError:
    return _submission_error(
      "submission_contract_unsupported",
      job_id,
      profile["profile_id"],
      "Submission registry contract version is not supported by this backend.",
    )
  return {
    "status": "ok",
    "job_id": job_id,
    "profile": {
      "profile_id": profile["profile_id"],
      "profile_version": profile["profile_version"],
      "title": profile["title"],
      "checks": [
        {
          "check_id": check["check_id"],
          "title": check["title"],
          "theme": check["theme"],
          "review_question_id": check.get("review_question_id"),
          "control_intent": check.get("control_intent"),
          "limitations": check.get("limitations"),
        }
        for check in profile["checks"]
      ],
    },
    "found": review is not None,
    "review": _review_view(review, hmac_secret=hmac_secret),
    "audit": repo.get_rulebook_review_audit(job_id, profile["profile_id"]),
    **submission_state,
  }


def _validate_review_answers(profile, answers):
  if answers is None:
    return {}
  if not isinstance(answers, dict):
    raise ValueError("answers must be an object")
  known_questions = {
    check.get("review_question_id")
    for check in profile["checks"]
    if check.get("review_question_id")
  }
  validated = {}
  for question_id, raw_answer in answers.items():
    if question_id not in known_questions:
      raise ValueError(f"Unknown review question: {question_id}")
    payload = raw_answer if isinstance(raw_answer, dict) else {"value": raw_answer}
    answer_value = str(payload.get("value") or "unknown").strip().lower()
    if answer_value not in VALID_RULEBOOK_ANSWER_VALUES:
      raise ValueError(f"Unsupported answer value for {question_id}: {answer_value}")
    validated[question_id] = {
      "value": answer_value,
      "note": str(payload.get("note") or "")[:1000],
    }
  return validated


def _validated_expected_revision(value, job_id, profile_id):
  if value is None:
    return None, _submission_error(
      "review_revision_conflict",
      job_id,
      profile_id,
      "expected_review_revision is required.",
    )
  try:
    revision = int(value)
  except (TypeError, ValueError):
    return None, _submission_error(
      "review_revision_conflict",
      job_id,
      profile_id,
      "expected_review_revision must be a non-negative integer.",
    )
  if revision < 0:
    return None, _submission_error(
      "review_revision_conflict",
      job_id,
      profile_id,
      "expected_review_revision must be a non-negative integer.",
    )
  return revision, None


def _sanitize_review_patch(owner, answers, actor, note):
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  actor = _safe_text(actor or "", hmac_secret=hmac_secret, max_len=200)
  note = _safe_text(note or "", hmac_secret=hmac_secret, max_len=1000)
  now = _owner_time(owner)
  sanitized_answers = {}
  for question_id, answer in answers.items():
    sanitized_answers[question_id] = {
      "value": answer["value"],
      "note": _safe_text(answer.get("note") or "", hmac_secret=hmac_secret, max_len=1000),
      "reviewer": actor,
      "updated_at": now,
    }
  return sanitized_answers, actor, note, now


def _put_review_with_audit(
  owner,
  repo,
  *,
  job_id,
  profile,
  previous,
  state,
  changed_question_ids,
  event_type,
):
  previous_answers = (previous.to_dict().get("answers") if previous else {}) or {}
  current_answers = (state.to_dict().get("answers") if state else {}) or {}
  review_payload = repo.put_rulebook_review(state)
  audit_payload = repo.append_rulebook_review_audit(RulebookReviewAuditEntry(
    job_id=job_id,
    profile_id=profile["profile_id"],
    profile_version=profile["profile_version"],
    review_state=state.review_state,
    reviewer=state.reviewer,
    note=state.note,
    changed_question_ids=list(changed_question_ids or []),
    previous_answers={question_id: previous_answers.get(question_id) for question_id in changed_question_ids or []},
    current_answers={question_id: current_answers.get(question_id) for question_id in changed_question_ids or []},
    timestamp=state.updated_at,
    review_revision=state.review_revision,
  ))
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event(event_type, {
      "job_id": job_id,
      "profile_id": profile["profile_id"],
      "review_state": state.review_state,
      "review_revision": state.review_revision,
      "changed_question_ids": list(changed_question_ids or []),
    })
  return review_payload, audit_payload


def save_rulebook_review_draft(
  owner,
  job_id,
  profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
  answers=None,
  actor="",
  note="",
  expected_review_revision=None,
):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  expected_revision, err = _validated_expected_revision(
    expected_review_revision,
    job_id,
    profile["profile_id"],
  )
  if err:
    return err
  try:
    validated_answers = _validate_review_answers(profile, answers)
  except ValueError as exc:
    return _error("invalid_review_answer", job_id, profile_id=profile["profile_id"], message=str(exc))

  with _submission_lock(owner, job_id, profile["profile_id"]):
    job_specs = owner._get_job_from_cstore(job_id)
    if not isinstance(job_specs, dict):
      return _error("job_not_found", job_id, profile_id=profile["profile_id"])
    if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
      return _error("job_not_finalized", job_id, profile_id=profile["profile_id"])
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_review")
    if unsupported:
      return {**unsupported, "error": "model_test_not_supported"}
    repo = _job_repo(owner)
    previous = repo.get_rulebook_review_model(job_id, profile["profile_id"])
    try:
      registry = _submission_registry(repo, job_id, profile["profile_id"]).to_dict()
    except ValueError:
      return _unsupported_submission_registry_error(job_id, profile["profile_id"])
    if registry.get("pending"):
      return _submission_error(
        "submission_in_progress",
        job_id,
        profile["profile_id"],
        "A submission retry must finish before the draft can change.",
        retryable=True,
      )
    current_revision = previous.review_revision if previous else 0
    if expected_revision != current_revision:
      return _submission_error(
        "review_revision_conflict",
        job_id,
        profile["profile_id"],
        "The review changed. Reload before saving this draft.",
        expected_review_revision=expected_revision,
        current_review_revision=current_revision,
      )
    legacy_reference = _legacy_submission_reference(job_specs, profile, previous)
    if (previous and previous.review_state == "submitted") or legacy_reference:
      return _submission_error(
        "review_already_submitted",
        job_id,
        profile["profile_id"],
        "Reopen the submitted review before editing it.",
      )

    sanitized_answers, actor, note, now = _sanitize_review_patch(owner, validated_answers, actor, note)
    previous_answers = (previous.to_dict().get("answers") if previous else {}) or {}
    current_answers = dict(previous_answers)
    current_answers.update(sanitized_answers)
    changed = sorted(
      question_id
      for question_id in set(previous_answers) | set(current_answers)
      if previous_answers.get(question_id) != current_answers.get(question_id)
    )
    state = RulebookReviewState(
      job_id=job_id,
      profile_id=profile["profile_id"],
      profile_version=profile["profile_version"],
      review_state="draft",
      reviewer=actor,
      note=note,
      answers=current_answers,
      updated_at=now,
      review_revision=current_revision + 1,
    )
    try:
      _put_review_with_audit(
        owner,
        repo,
        job_id=job_id,
        profile=profile,
        previous=previous,
        state=state,
        changed_question_ids=changed,
        event_type="rulebook_review_draft_saved",
      )
    except Exception:
      return _submission_error(
        "review_draft_save_failed",
        job_id,
        profile["profile_id"],
        "Unable to save the review draft.",
        retryable=True,
      )
  return get_rulebook_review(owner, job_id, profile["profile_id"])


def _validate_submission_answers(profile, review):
  answers = (review.to_dict().get("answers") if review else {}) or {}
  missing = []
  comments_required = []
  for check in profile["checks"]:
    question_id = check.get("review_question_id")
    if not question_id:
      continue
    answer = answers.get(question_id)
    if not isinstance(answer, dict) or answer.get("value") not in VALID_RULEBOOK_ANSWER_VALUES:
      missing.append(question_id)
      continue
    if answer.get("value") in {"no", "unknown", "not_applicable"} and not str(answer.get("note") or "").strip():
      comments_required.append(question_id)
  return missing, comments_required


def _submission_fingerprint(assessment):
  canonical = json.dumps(assessment, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
  return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_submission_snapshot(
  owner,
  job_id,
  profile,
  *,
  pass_nr,
  revision,
  submitted_at,
  actor,
  review_revision,
):
  submission_meta = {
    "contract_version": RULEBOOK_SUBMISSION_CONTRACT_VERSION,
    "revision": revision,
    "submitted_at": submitted_at,
    "actor": actor,
    "pass_nr": pass_nr,
    "profile_id": profile["profile_id"],
    "profile_version": profile["profile_version"],
    "review_revision": review_revision,
  }
  built = build_rulebook_assessment(
    owner,
    job_id,
    profile_id=profile["profile_id"],
    pass_nr=pass_nr,
    include_review=True,
    artifact_kind="review_submission",
    submission=submission_meta,
  )
  if built.get("status") != "ok":
    return built
  assessment = built["assessment"]
  assessment["generated_at"] = _utc_timestamp(submitted_at)
  assessment["review_state"].update({
    "review_state": "submitted",
    "reviewer": actor,
    "updated_at": submitted_at,
    "review_revision": review_revision,
  })
  return {
    "status": "ok",
    "assessment": assessment,
    "fingerprint": _submission_fingerprint(assessment),
  }


def _registry_with(registry, *, submissions=None, pending=None, keep_pending=False):
  payload = registry.to_dict() if isinstance(registry, RulebookSubmissionRegistry) else dict(registry)
  if submissions is not None:
    payload["submissions"] = submissions
  if keep_pending or pending is not None:
    payload["pending"] = pending
  else:
    payload.pop("pending", None)
  return RulebookSubmissionRegistry.from_dict(payload)


def _persist_pending_error(repo, job_id, profile_id, registry, pending, payload):
  try:
    next_pending = dict(pending)
    next_pending["last_error"] = payload
    next_pending["updated_at"] = payload.get("at_epoch", next_pending.get("updated_at", 0.0))
    repo.put_rulebook_submission_registry(
      job_id,
      profile_id,
      _registry_with(registry, pending=next_pending, keep_pending=True),
    )
  except Exception:
    pass


def submit_rulebook_review(
  owner,
  job_id,
  profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
  expected_review_revision=None,
  expected_pass_nr=None,
  expected_profile_version=None,
  idempotency_key="",
  actor="",
):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  expected_revision, err = _validated_expected_revision(
    expected_review_revision,
    job_id,
    profile["profile_id"],
  )
  if err:
    return err
  try:
    expected_pass = int(expected_pass_nr)
  except (TypeError, ValueError):
    return _submission_error(
      "submission_pass_stale",
      job_id,
      profile["profile_id"],
      "expected_pass_nr must identify the latest completed pass.",
    )
  idempotency_key = str(idempotency_key or "").strip()
  if not idempotency_key or len(idempotency_key) > 200:
    return _submission_error(
      "submission_idempotency_conflict",
      job_id,
      profile["profile_id"],
      "A bounded idempotency key is required.",
    )
  if str(expected_profile_version or "") != profile["profile_version"]:
    return _submission_error(
      "submission_profile_stale",
      job_id,
      profile["profile_id"],
      "The rulebook profile changed. Reload before submitting.",
      current_profile_version=profile["profile_version"],
    )
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  actor = _safe_text(actor or "", hmac_secret=hmac_secret, max_len=200)
  if not actor:
    return _submission_error(
      "invalid_review_actor",
      job_id,
      profile["profile_id"],
      "A server-derived review actor is required.",
    )

  with _submission_lock(owner, job_id, profile["profile_id"]):
    job_specs = owner._get_job_from_cstore(job_id)
    if not isinstance(job_specs, dict):
      return _error("job_not_found", job_id, profile_id=profile["profile_id"])
    if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
      return _error("job_not_finalized", job_id, profile_id=profile["profile_id"])
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_review")
    if unsupported:
      return {**unsupported, "error": "model_test_not_supported"}
    repo = _job_repo(owner)
    review = repo.get_rulebook_review_model(job_id, profile["profile_id"])
    try:
      registry = _submission_registry(repo, job_id, profile["profile_id"])
    except ValueError:
      return _unsupported_submission_registry_error(job_id, profile["profile_id"])
    registry_payload = registry.to_dict()
    existing_pending = registry_payload.get("pending")

    for reference in registry_payload.get("submissions") or []:
      if reference.get("idempotency_key") != idempotency_key:
        continue
      if existing_pending:
        break
      if (
        int(reference.get("review_revision", -1)) == expected_revision
        and int(reference.get("pass_nr", -1)) == expected_pass
        and reference.get("profile_version") == profile["profile_version"]
        and reference.get("actor") == actor
      ):
        replay_snapshot = _build_submission_snapshot(
          owner,
          job_id,
          profile,
          pass_nr=int(reference["pass_nr"]),
          revision=int(reference["revision"]),
          submitted_at=float(reference["submitted_at"]),
          actor=actor,
          review_revision=expected_revision,
        )
        if replay_snapshot.get("status") != "ok":
          return replay_snapshot
        if replay_snapshot["fingerprint"] != reference.get("fingerprint"):
          return _submission_error(
            "submission_idempotency_conflict",
            job_id,
            profile["profile_id"],
            "The idempotency key was already used for different submission inputs.",
          )
        result = get_rulebook_review(owner, job_id, profile["profile_id"])
        result.update({"submission": _submission_reference_view(
          reference,
          latest_pass_nr=expected_pass,
          profile_version=profile["profile_version"],
        ), "idempotent_replay": True})
        return result
      return _submission_error(
        "submission_idempotency_conflict",
        job_id,
        profile["profile_id"],
        "The idempotency key was already used for different submission inputs.",
      )

    current_revision = review.review_revision if review else 0
    if expected_revision != current_revision:
      return _submission_error(
        "review_revision_conflict",
        job_id,
        profile["profile_id"],
        "The review changed. Reload before submitting.",
        expected_review_revision=expected_revision,
        current_review_revision=current_revision,
      )
    latest_pass, pass_error = _latest_pass_nr(owner, job_id)
    if pass_error:
      return pass_error
    if expected_pass != latest_pass:
      return _submission_error(
        "submission_pass_stale",
        job_id,
        profile["profile_id"],
        "Newer scan evidence exists. Reload before submitting.",
        expected_pass_nr=expected_pass,
        current_pass_nr=latest_pass,
      )

    pending = existing_pending
    if pending and pending.get("idempotency_key") != idempotency_key:
      return _submission_error(
        "submission_in_progress",
        job_id,
        profile["profile_id"],
        "Another submission is pending for this review.",
        retryable=True,
      )
    if review and review.review_state == "submitted" and not pending:
      return _submission_error(
        "review_already_submitted",
        job_id,
        profile["profile_id"],
        "Reopen the review before creating another submission revision.",
      )
    legacy_reference = _legacy_submission_reference(job_specs, profile, review)
    if legacy_reference and not pending:
      return _submission_error(
        "review_already_submitted",
        job_id,
        profile["profile_id"],
        "Reopen the legacy submitted review before creating a native revision.",
      )

    missing, comments_required = _validate_submission_answers(profile, review)
    if missing or comments_required:
      return _submission_error(
        "submission_comments_required",
        job_id,
        profile["profile_id"],
        "Every review question must be answered; No, Unknown, and Not applicable require comments.",
        missing_question_ids=missing,
        comment_required_question_ids=comments_required,
      )

    now = _owner_time(owner)
    target_revision = int((pending or {}).get("target_revision") or (registry.latest_revision + 1))
    submitted_at = float((pending or {}).get("created_at") or now)
    built = _build_submission_snapshot(
      owner,
      job_id,
      profile,
      pass_nr=latest_pass,
      revision=target_revision,
      submitted_at=submitted_at,
      actor=actor,
      review_revision=expected_revision,
    )
    if built.get("status") != "ok":
      return built
    assessment = built["assessment"]
    fingerprint = built["fingerprint"]

    if pending:
      if pending.get("fingerprint") != fingerprint:
        return _submission_error(
          "submission_idempotency_conflict",
          job_id,
          profile["profile_id"],
          "The pending submission no longer matches the canonical review snapshot.",
        )
      pending = {
        **pending,
        "attempt_count": int(pending.get("attempt_count", 1) or 1) + 1,
        "updated_at": now,
        "last_error": None,
      }
    else:
      pending = RulebookPendingSubmission(
        target_revision=target_revision,
        expected_review_revision=expected_revision,
        expected_pass_nr=latest_pass,
        expected_profile_version=profile["profile_version"],
        actor=actor,
        idempotency_key=idempotency_key,
        fingerprint=fingerprint,
        state="prepared",
        created_at=submitted_at,
        updated_at=now,
      ).to_dict()
      try:
        registry = _registry_with(registry, pending=pending, keep_pending=True)
        repo.put_rulebook_submission_registry(job_id, profile["profile_id"], registry)
      except Exception:
        return _submission_error(
          "submission_record_failed",
          job_id,
          profile["profile_id"],
          "Unable to record pending submission state.",
          retryable=True,
        )

    state_order = {"prepared": 0, "artifact_written": 1, "reference_recorded": 2}
    if state_order[pending["state"]] < state_order["artifact_written"]:
      try:
        cid = _artifact_repo(owner).put_json(assessment, show_logs=False)
      except Exception:
        cid = None
      if not cid:
        failure = {
          "error": "submission_persist_failed",
          "message": "Unable to persist the review submission artifact.",
          "retryable": True,
          "at": _utc_timestamp(),
          "at_epoch": now,
        }
        _persist_pending_error(repo, job_id, profile["profile_id"], registry, pending, failure)
        return _submission_error(
          "submission_persist_failed",
          job_id,
          profile["profile_id"],
          failure["message"],
          retryable=True,
        )
      pending = {**pending, "state": "artifact_written", "cid": cid, "updated_at": now}
      try:
        registry = _registry_with(registry, pending=pending, keep_pending=True)
        repo.put_rulebook_submission_registry(job_id, profile["profile_id"], registry)
      except Exception:
        return _submission_error(
          "submission_record_failed",
          job_id,
          profile["profile_id"],
          "The artifact exists but its CID could not be recorded. Retry with the same key.",
          retryable=True,
        )

    submissions = list(registry.to_dict().get("submissions") or [])
    reference = next((item for item in submissions if int(item.get("revision", -1)) == target_revision), None)
    if reference is None:
      reference = RulebookSubmissionReference(
        revision=target_revision,
        cid=pending["cid"],
        submitted_at=submitted_at,
        actor=actor,
        pass_nr=latest_pass,
        profile_id=profile["profile_id"],
        profile_version=profile["profile_version"],
        schema_version=RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
        review_revision=expected_revision,
        idempotency_key=idempotency_key,
        fingerprint=fingerprint,
      ).to_dict()
      submissions.append(reference)
    if state_order[pending["state"]] < state_order["reference_recorded"]:
      pending = {**pending, "state": "reference_recorded", "updated_at": now}
      try:
        registry = _registry_with(registry, submissions=submissions, pending=pending, keep_pending=True)
        repo.put_rulebook_submission_registry(job_id, profile["profile_id"], registry)
      except Exception:
        failure = {
          "error": "submission_record_failed",
          "message": "The submission reference could not be recorded.",
          "retryable": True,
          "at": _utc_timestamp(),
          "at_epoch": now,
        }
        _persist_pending_error(repo, job_id, profile["profile_id"], registry, pending, failure)
        return _submission_error(
          "submission_record_failed",
          job_id,
          profile["profile_id"],
          "The submission reference could not be recorded. Retry with the same key.",
          retryable=True,
        )

    submitted_state = RulebookReviewState(
      job_id=job_id,
      profile_id=profile["profile_id"],
      profile_version=profile["profile_version"],
      review_state="submitted",
      reviewer=actor,
      note=review.note if review else "",
      answers=(review.to_dict().get("answers") if review else {}) or {},
      updated_at=submitted_at,
      review_revision=expected_revision,
    )
    try:
      if not review or review.review_state != "submitted":
        _put_review_with_audit(
          owner,
          repo,
          job_id=job_id,
          profile=profile,
          previous=review,
          state=submitted_state,
          changed_question_ids=[],
          event_type="rulebook_review_submitted",
        )
      committed_registry = RulebookSubmissionRegistry(
        contract_version=RULEBOOK_SUBMISSION_CONTRACT_VERSION,
        latest_revision=max(registry.latest_revision, target_revision),
        submissions=submissions,
        pending=None,
      )
      repo.put_rulebook_submission_registry(job_id, profile["profile_id"], committed_registry)
    except Exception:
      failure = {
        "error": "submission_record_failed",
        "message": "The final submission state was not committed.",
        "retryable": True,
        "at": _utc_timestamp(),
        "at_epoch": now,
      }
      _persist_pending_error(repo, job_id, profile["profile_id"], registry, pending, failure)
      return _submission_error(
        "submission_record_failed",
        job_id,
        profile["profile_id"],
        "The submission is recoverable but its final state was not committed. Retry with the same key.",
        retryable=True,
      )

  result = get_rulebook_review(owner, job_id, profile["profile_id"])
  result.update({
    "submission": _submission_reference_view(
      reference,
      latest_pass_nr=latest_pass,
      profile_version=profile["profile_version"],
    ),
    "idempotent_replay": False,
  })
  return result


def reopen_rulebook_review(
  owner,
  job_id,
  profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
  expected_review_revision=None,
  idempotency_key="",
  actor="",
):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  expected_revision, err = _validated_expected_revision(
    expected_review_revision,
    job_id,
    profile["profile_id"],
  )
  if err:
    return err
  idempotency_key = str(idempotency_key or "").strip()
  if not idempotency_key or len(idempotency_key) > 200:
    return _submission_error(
      "reopen_idempotency_conflict",
      job_id,
      profile["profile_id"],
      "A bounded reopen idempotency key is required.",
    )
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  actor = _safe_text(actor or "", hmac_secret=hmac_secret, max_len=200)
  if not actor:
    return _submission_error("invalid_review_actor", job_id, profile["profile_id"], "A server-derived actor is required.")

  with _submission_lock(owner, job_id, profile["profile_id"]):
    job_specs = owner._get_job_from_cstore(job_id)
    if not isinstance(job_specs, dict):
      return _error("job_not_found", job_id, profile_id=profile["profile_id"])
    if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
      return _error("job_not_finalized", job_id, profile_id=profile["profile_id"])
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_review")
    if unsupported:
      return {**unsupported, "error": "model_test_not_supported"}
    repo = _job_repo(owner)
    review = repo.get_rulebook_review_model(job_id, profile["profile_id"])
    try:
      registry = _submission_registry(repo, job_id, profile["profile_id"])
    except ValueError:
      return _unsupported_submission_registry_error(job_id, profile["profile_id"])
    registry_payload = registry.to_dict()
    if registry_payload.get("pending"):
      return _submission_error(
        "submission_in_progress",
        job_id,
        profile["profile_id"],
        "Finish the pending submission before reopening.",
        retryable=True,
      )
    current_revision = review.review_revision if review else 0
    if review and review.last_reopen_idempotency_key == idempotency_key:
      if (
        review.review_state == "draft"
        and review.last_reopen_from_revision == expected_revision
        and review.last_reopen_actor == actor
      ):
        result = get_rulebook_review(owner, job_id, profile["profile_id"])
        result["idempotent_replay"] = True
        return result
      return _submission_error(
        "reopen_idempotency_conflict",
        job_id,
        profile["profile_id"],
        "The reopen idempotency key was already used for different inputs.",
      )
    if expected_revision != current_revision:
      return _submission_error(
        "review_revision_conflict",
        job_id,
        profile["profile_id"],
        "The review changed. Reload before reopening.",
        current_review_revision=current_revision,
      )
    legacy_reference = _legacy_submission_reference(job_specs, profile, review)
    if not registry_payload.get("submissions") and not legacy_reference:
      return _submission_error(
        "review_not_submitted",
        job_id,
        profile["profile_id"],
        "Only a submitted review can be reopened.",
      )
    if not review or review.review_state not in {"submitted", "reviewed"}:
      return _submission_error(
        "review_not_submitted",
        job_id,
        profile["profile_id"],
        "Only a submitted review can be reopened.",
      )
    now = _owner_time(owner)
    reopened = RulebookReviewState(
      job_id=job_id,
      profile_id=profile["profile_id"],
      profile_version=profile["profile_version"],
      review_state="draft",
      reviewer=actor,
      note=review.note,
      answers=review.to_dict().get("answers") or {},
      updated_at=now,
      review_revision=current_revision + 1,
      last_reopen_idempotency_key=idempotency_key,
      last_reopen_from_revision=current_revision,
      last_reopen_actor=actor,
    )
    try:
      _put_review_with_audit(
        owner,
        repo,
        job_id=job_id,
        profile=profile,
        previous=review,
        state=reopened,
        changed_question_ids=[],
        event_type="rulebook_review_reopened",
      )
    except Exception:
      return _submission_error(
        "review_reopen_failed",
        job_id,
        profile["profile_id"],
        "Unable to reopen the submitted review.",
        retryable=True,
      )
  result = get_rulebook_review(owner, job_id, profile["profile_id"])
  result["idempotent_replay"] = False
  return result


def _update_rulebook_review_locked(
  owner,
  job_id,
  profile,
  job_specs,
  validated_answers,
  reviewer,
  note,
  review_state,
):
  repo = _job_repo(owner)
  previous = repo.get_rulebook_review_model(job_id, profile["profile_id"])
  try:
    registry = _submission_registry(repo, job_id, profile["profile_id"]).to_dict()
  except ValueError:
    return _unsupported_submission_registry_error(job_id, profile["profile_id"])
  formal_history_blocks_legacy_write = bool(
    registry.get("submissions")
    and (
      previous is None
      or previous.review_state != "draft"
      or review_state != "draft"
    )
  )
  if registry.get("pending") or formal_history_blocks_legacy_write or _legacy_submission_reference(job_specs, profile, previous):
    return _submission_error(
      "review_already_submitted",
      job_id,
      profile["profile_id"],
      "Use the explicit reopen operation before changing a submitted review.",
    )
  now = float(getattr(owner, "time", _time.time)())
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-rulebook")
  reviewer = _safe_text(reviewer or "", hmac_secret=hmac_secret, max_len=200)
  note = _safe_text(note or "", hmac_secret=hmac_secret, max_len=1000)
  sanitized_answers = {}
  for question_id, answer in validated_answers.items():
    sanitized_answers[question_id] = {
      "value": answer["value"],
      "note": _safe_text(answer.get("note") or "", hmac_secret=hmac_secret, max_len=1000),
      "reviewer": reviewer,
      "updated_at": now,
    }

  previous_answers = (previous.to_dict().get("answers") if previous else {}) or {}
  current_answers = dict(previous_answers)
  current_answers.update(sanitized_answers)
  changed = sorted(
    question_id
    for question_id in set(previous_answers) | set(current_answers)
    if previous_answers.get(question_id) != current_answers.get(question_id)
  )
  state = RulebookReviewState(
    job_id=job_id,
    profile_id=profile["profile_id"],
    profile_version=profile["profile_version"],
    review_state=review_state,
    reviewer=reviewer,
    note=note,
    answers=current_answers,
    updated_at=now,
    review_revision=(previous.review_revision if previous else 0) + 1,
  )
  review_payload = repo.put_rulebook_review(state)
  audit_payload = repo.append_rulebook_review_audit(RulebookReviewAuditEntry(
    job_id=job_id,
    profile_id=profile["profile_id"],
    profile_version=profile["profile_version"],
    review_state=review_state,
    reviewer=reviewer,
    note=note,
    changed_question_ids=changed,
    previous_answers={question_id: previous_answers.get(question_id) for question_id in changed},
    current_answers={question_id: current_answers.get(question_id) for question_id in changed},
    timestamp=now,
    review_revision=state.review_revision,
  ))
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event("rulebook_review_updated", {
      "job_id": job_id,
      "profile_id": profile["profile_id"],
      "review_state": review_state,
      "review_revision": state.review_revision,
      "changed_question_ids": changed,
    })
  return {
    "status": "ok",
    "job_id": job_id,
    "profile_id": profile["profile_id"],
    "review": review_payload,
    "audit": audit_payload,
  }


def update_rulebook_review(
  owner,
  job_id,
  profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
  answers=None,
  reviewer="",
  note="",
  review_state="draft",
):
  profile = _profile(profile_id)
  if not profile:
    return _error("invalid_profile", job_id, profile_id=profile_id)
  if review_state not in VALID_RULEBOOK_REVIEW_STATES:
    return _error("invalid_review_answer", job_id, profile_id=profile_id, message="Unsupported review_state.")
  try:
    validated_answers = _validate_review_answers(profile, answers)
  except ValueError as exc:
    return _error("invalid_review_answer", job_id, profile_id=profile_id, message=str(exc))
  with _submission_lock(owner, job_id, profile["profile_id"]):
    job_specs = owner._get_job_from_cstore(job_id)
    if not isinstance(job_specs, dict):
      return _error("job_not_found", job_id, profile_id=profile_id)
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "rulebook_review")
    if unsupported:
      return {
        **unsupported,
        "error": "model_test_not_supported",
        "error_class": unsupported.get("error_class") or unsupported.get("error"),
      }
    if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
      return _error(
        "job_not_finalized",
        job_id,
        profile_id=profile["profile_id"],
        job_status=job_specs.get("job_status"),
      )
    return _update_rulebook_review_locked(
      owner,
      job_id,
      profile,
      job_specs,
      validated_answers,
      reviewer,
      note,
      review_state,
    )
