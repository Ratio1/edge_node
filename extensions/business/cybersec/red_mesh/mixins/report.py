"""
Report aggregation mixin for RedMesh pentester API.

Handles merging worker results, credential redaction, and pre-computing
the UI aggregate view for the frontend.
"""

import hashlib as _hashlib
import json as _json
import math as _math
import struct as _struct

from ..worker import PentestLocalWorker
from ..models import UiAggregate
from ..models.finding_identity import (
  worker_attribution_fields as _worker_attribution_fields,
  volatile_non_content_fields as _volatile_non_content_fields,
)
from ..models.finding_schema import is_coverage_result as _is_coverage_result
# Shared with the SIEM event builder, which redacts at the egress boundary
# rather than trusting its caller. See `credential_redaction` for why the rule
# is anchored on the credential phrasing rather than on a bare `a:b` shape.
from ..credential_redaction import (
  CREDENTIAL_TEXT_FIELDS as _CREDENTIAL_TEXT_FIELDS,
  redact_credential_text,
)


# Fields stamped per-worker by _stamp_worker_source. Excluded from the
# dedup signature so the same vulnerability seen by two workers
# collapses to one finding (with one worker's stamp preserved).
# The same fields `finding_identity.content_hash` excludes, plus this module's
# two private ones. They were not excluded here, so the fallback hash — used
# whenever a finding carries no stamped identity — saw the same finding from two
# nodes as two findings: `_stamp_worker_source` adds `worker_source`,
# `observed_at` and `node_ip` before this runs, and cross-worker dedup is the
# one thing this signature exists to do.
_DEDUP_EXCLUDE_FIELDS = frozenset(
  {"_source_worker_id", "_source_node_addr"}
  | set(_worker_attribution_fields())
  | set(_volatile_non_content_fields())
)


_PUBLISH_SAFE_METADATA_KEYS = {
  "api_key_header_name",
  "api_key_location",
  "api_key_query_param",
  "authenticated_probe_path",
  "authenticated_probe_method",
  "allow_non_readonly_auth_validation_method",
  "allow_unverified_auth",
  "bearer_refresh_url",
  "bearer_scheme",
  "bearer_token_header_name",
  "csrf_field",
  "password_field",
  "password_reset_confirm_path",
  "password_reset_path",
  "protected_path",
  "token_path",
  "token_request_method",
  "token_response_field",
}
_SECRET_CONFIG_KEY_PARTS = (
  "password", "passwd", "pwd", "secret", "authorization", "cookie",
  "credential",
)
_SECRET_CONFIG_TOKEN_KEYS = {
  "api_key", "apikey", "token", "access_token", "refresh_token", "id_token",
  "secret_ref",
}


def _is_secret_config_key(key):
  normalized = str(key or "").strip().lower().replace("-", "_")
  if not normalized or normalized.startswith("has_"):
    return False
  if normalized in _PUBLISH_SAFE_METADATA_KEYS:
    return False
  if normalized in _SECRET_CONFIG_TOKEN_KEYS:
    return True
  if normalized.endswith("_token") or normalized.endswith("_api_key"):
    return True
  return any(part in normalized for part in _SECRET_CONFIG_KEY_PARTS)


def _redact_nested_job_config(value):
  if isinstance(value, dict):
    redacted = {}
    for key, item in value.items():
      if _is_secret_config_key(key):
        redacted[key] = "***"
      else:
        redacted[key] = _redact_nested_job_config(item)
    return redacted
  if isinstance(value, list):
    return [_redact_nested_job_config(item) for item in value]
  return value


def _configured_graybox_secret_names_from_report(report):
  """Extract configured API auth field names from report/job target config."""
  if not isinstance(report, dict):
    return ()
  candidates = []
  for key in ("target_config",):
    if isinstance(report.get(key), dict):
      candidates.append(report[key])
  job_config = report.get("job_config")
  if isinstance(job_config, dict) and isinstance(job_config.get("target_config"), dict):
    candidates.append(job_config["target_config"])

  names = []
  for target_config in candidates:
    api_security = target_config.get("api_security") or {}
    auth = api_security.get("auth") or {}
    gateway_auth = api_security.get("gateway_auth") or {}
    for descriptor in (auth, gateway_auth):
      if not isinstance(descriptor, dict):
        continue
      for key in (
        "api_key_header_name", "api_key_query_param",
        "bearer_token_header_name",
      ):
        value = descriptor.get(key)
        if isinstance(value, str) and value and value not in names:
          names.append(value)
  return tuple(names)


def _finding_dedup_key(item):
  """Stable JSON-encoded signature of a finding-shaped dict.

  Strips per-worker chain-of-custody fields so the same vuln seen by
  multiple workers produces an identical key. Falls back to the raw
  JSON for non-finding shapes.
  """
  if not isinstance(item, dict):
    try:
      return _json.dumps(item, sort_keys=True, default=str)
    except (TypeError, ValueError):
      return repr(item)
  # Strip per-worker stamps before hashing.
  stripped = {k: v for k, v in item.items() if k not in _DEDUP_EXCLUDE_FIELDS}
  try:
    return _json.dumps(stripped, sort_keys=True, default=str)
  except (TypeError, ValueError):
    return repr(stripped)


def _dedup_finding_list(findings):
  """Dedup a list of finding dicts by stable signature.

  Preserves order; first occurrence wins (keeps that worker's stamp).
  No-op for None / non-list inputs.
  """
  if not isinstance(findings, list):
    return findings
  seen = set()
  out = []
  for item in findings:
    key = _finding_dedup_key(item)
    if key in seen:
      continue
    seen.add(key)
    out.append(item)
  return out


def _dedup_findings_in_aggregated(aggregated):
  """Walk the known finding-bearing paths in an aggregated report and
  dedup each findings list by stable signature.

  Mutates `aggregated` in place. Targets:
    - service_info[port].findings
    - service_info[port][probe].findings
    - web_tests_info[port].findings
    - web_tests_info[port][method].findings
    - graybox_results[port][probe].findings
    - correlation_findings (top-level)
    - findings (top-level)

  This is the Phase 0 dedup pass — it complements but does not replace
  the per-CVE dedup in mixins/risk.py::_compute_risk_and_findings.
  """
  if not isinstance(aggregated, dict):
    return aggregated

  def _dedup_in_dict_at_findings(container):
    if isinstance(container, dict) and isinstance(container.get("findings"), list):
      container["findings"] = _dedup_finding_list(container["findings"])

  # service_info: nested + legacy flat
  for port_entry in (aggregated.get("service_info") or {}).values():
    if not isinstance(port_entry, dict):
      continue
    _dedup_in_dict_at_findings(port_entry)
    for probe_entry in port_entry.values():
      if isinstance(probe_entry, dict):
        _dedup_in_dict_at_findings(probe_entry)

  # web_tests_info: same shape as service_info
  for port_entry in (aggregated.get("web_tests_info") or {}).values():
    if not isinstance(port_entry, dict):
      continue
    _dedup_in_dict_at_findings(port_entry)
    for method_entry in port_entry.values():
      if isinstance(method_entry, dict):
        _dedup_in_dict_at_findings(method_entry)

  # graybox_results: {port: {probe: {findings}}}
  for port_probes in (aggregated.get("graybox_results") or {}).values():
    if not isinstance(port_probes, dict):
      continue
    for probe_entry in port_probes.values():
      if isinstance(probe_entry, dict):
        _dedup_in_dict_at_findings(probe_entry)

  # Top-level lists
  if isinstance(aggregated.get("correlation_findings"), list):
    aggregated["correlation_findings"] = _dedup_finding_list(
      aggregated["correlation_findings"]
    )
  if isinstance(aggregated.get("findings"), list):
    aggregated["findings"] = _dedup_finding_list(aggregated["findings"])

  return aggregated


def _iter_report_findings(report):
  """Yield every raw finding record from the worker-report paths we publish."""
  if not isinstance(report, dict):
    return

  def _items(value):
    return value if isinstance(value, list) else ()

  for section_name in ("service_info", "web_tests_info"):
    for port_entry in (report.get(section_name) or {}).values():
      if not isinstance(port_entry, dict):
        continue
      for finding in _items(port_entry.get("findings")):
        yield finding
      for probe_entry in port_entry.values():
        if not isinstance(probe_entry, dict):
          continue
        for finding in _items(probe_entry.get("findings")):
          yield finding

  for port_probes in (report.get("graybox_results") or {}).values():
    if not isinstance(port_probes, dict):
      continue
    for probe_entry in port_probes.values():
      if not isinstance(probe_entry, dict):
        continue
      for finding in _items(probe_entry.get("findings")):
        yield finding

  for section_name in ("correlation_findings", "findings"):
    for finding in _items(report.get(section_name)):
      yield finding


def _compact_finding_signature(finding):
  """Return a stable compact type signature without worker-attribution fields."""
  if isinstance(finding, dict):
    # Content fields only. Falling back to `finding_id` was correct when the id
    # was content-derived and is wrong now that it is identity-derived: two
    # content-distinct findings sharing a coarse identity would collapse into
    # one "finding type" in the per-worker counts.
    explicit = finding.get("finding_signature") or finding.get("content_hash")
    if explicit:
      return str(explicit)

  def normalize(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
      numeric = float(value)
      if not _math.isfinite(numeric):
        return None
      if numeric == 0:
        numeric = 0.0
      return "__redmesh_number__:" + _struct.pack(">d", numeric).hex()
    if isinstance(value, dict):
      return {
        key: normalize(item)
        for key, item in value.items()
        if key not in _DEDUP_EXCLUDE_FIELDS
      }
    if isinstance(value, (list, tuple)):
      return [normalize(item) for item in value]
    return value

  try:
    canonical = _json.dumps(
      normalize(finding), sort_keys=True, default=str,
      ensure_ascii=False, separators=(",", ":"),
    )
  except (TypeError, ValueError):
    canonical = repr(normalize(finding))
  stable = canonical.encode("utf-8", errors="replace")
  return "sha256:" + _hashlib.sha256(stable).hexdigest()


class _ReportMixin:
  """Report aggregation and UI view methods for PentesterApi01Plugin."""

  SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
  CONFIDENCE_ORDER = {"certain": 0, "firm": 1, "tentative": 2}

  @staticmethod
  def _count_nested_findings(section):
    """Count findings in a nested {port: {probe: {findings: []}}} section."""
    total = 0
    for per_port in (section or {}).values():
      if not isinstance(per_port, dict):
        continue
      for per_probe in per_port.values():
        if isinstance(per_probe, dict):
          total += len(per_probe.get("findings", []))
    return total

  def _count_all_findings(self, report):
    """Count all findings emitted by network and graybox reporting sections."""
    return sum(1 for _finding in _iter_report_findings(report))

  @staticmethod
  def _summarize_worker_findings(report):
    """Count raw records and unique types before aggregate cross-worker dedup."""
    counts = {}
    signatures = []
    seen_signatures = set()
    nr_findings = 0
    for finding in _iter_report_findings(report):
      nr_findings += 1
      severity = "INFO"
      if isinstance(finding, dict):
        severity = str(finding.get("severity") or "INFO").upper()
      if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "INFO"
      counts[severity] = counts.get(severity, 0) + 1
      signature = _compact_finding_signature(finding)
      if signature not in seen_signatures:
        seen_signatures.add(signature)
        signatures.append(signature)
    return nr_findings, counts, signatures

  @staticmethod
  def _dedupe_items(items):
    """Deduplicate mixed scalar/dict items while preserving first-seen order."""
    import json as _json

    deduped = []
    seen = set()
    for item in items:
      try:
        key = _json.dumps(item, sort_keys=True, default=str)
      except (TypeError, ValueError):
        key = str(item)
      if key in seen:
        continue
      seen.add(key)
      deduped.append(item)
    return deduped

  def _extract_graybox_ui_stats(self, aggregated, latest_pass=None):
    """Extract graybox-specific archive summary values from aggregated data."""
    latest_pass = latest_pass or {}
    scan_metrics = latest_pass.get("scan_metrics") or {}

    service_info = aggregated.get("service_info") or {}
    graybox_results = aggregated.get("graybox_results") or {}

    routes = []
    forms = []
    for methods in service_info.values():
      if not isinstance(methods, dict):
        continue
      discovery = methods.get("_graybox_discovery")
      if not isinstance(discovery, dict):
        continue
      routes.extend(discovery.get("routes") or [])
      forms.extend(discovery.get("forms") or [])

    scenario_total = 0
    scenario_vulnerable = 0
    for probes in graybox_results.values():
      if not isinstance(probes, dict):
        continue
      for probe_data in probes.values():
        if not isinstance(probe_data, dict):
          continue
        for finding in probe_data.get("findings", []):
          if not isinstance(finding, dict):
            continue
          status = finding.get("status")
          if not status:
            continue
          scenario_total += 1
          if status == "vulnerable":
            scenario_vulnerable += 1

    if scan_metrics:
      scenario_total = max(scenario_total, scan_metrics.get("scenarios_total", 0) or 0)
      scenario_vulnerable = max(
        scenario_vulnerable,
        scan_metrics.get("scenarios_vulnerable", 0) or 0,
      )

    return {
      "total_routes_discovered": len(self._dedupe_items(routes)),
      "total_forms_discovered": len(self._dedupe_items(forms)),
      "total_scenarios": scenario_total,
      "total_scenarios_vulnerable": scenario_vulnerable,
    }

  def _local_node_address(self):
    """
    This node's mesh address, for finding attribution.

    It has to be the same *kind* of identifier the comparison buckets on.
    `_compute_node_comparison` groups findings by `_source_node_addr` and then
    looks each participating node up in that map, and the participating set is
    built from `worker_reports` / `selected_peers` keys — mesh addresses, the
    same `ee_addr` that keys `job_specs["workers"]` at close-job time.

    Returning a public IP here instead left every per-node findings list empty,
    because an IP never equals a mesh address: worse than the launcher collapse
    it was meant to fix, which at least matched a real participating node. The
    IP is already carried separately as `node_ip`, which is the display field —
    that is the distinction to preserve, not collapse.
    """
    address = getattr(self, "ee_addr", None)
    return str(address) if address else None

  @staticmethod
  def _stamp_finding_list(findings, worker_id, node_addr):
    """Stamp _source_worker_id / _source_node_addr on each finding.

    Idempotent — setdefault preserves any stamps from upstream Phase
    2 extraction. Non-dict entries are skipped silently.
    """
    for f in findings or []:
      if isinstance(f, dict):
        f.setdefault("_source_worker_id", worker_id)
        f.setdefault("_source_node_addr", node_addr)

  def _stamp_worker_source(self, local_job_status, worker_id, node_addr):
    """Apply worker/node attribution to every finding-bearing structure.

    Handles both the nested network shape ({port: {probe: {findings}}})
    and the legacy flat shape ({port: {findings}}). Production uses
    nested exclusively, but the stamper is shape-robust so migrated
    or hand-built fixture data still gets stamped consistently.
    """
    if not isinstance(local_job_status, dict):
      return
    # service_info: nested + legacy flat.
    for port_entry in (local_job_status.get("service_info") or {}).values():
      if not isinstance(port_entry, dict):
        continue
      self._stamp_finding_list(port_entry.get("findings"),
                               worker_id, node_addr)
      for probe_entry in port_entry.values():
        if isinstance(probe_entry, dict):
          self._stamp_finding_list(probe_entry.get("findings"),
                                   worker_id, node_addr)
    # graybox_results: {port: {probe: {findings}}}
    for port_probes in (local_job_status.get("graybox_results") or {}).values():
      if not isinstance(port_probes, dict):
        continue
      for probe_entry in port_probes.values():
        if isinstance(probe_entry, dict):
          self._stamp_finding_list(probe_entry.get("findings"),
                                   worker_id, node_addr)
    # web_tests_info: mirrors service_info shape.
    for port_entry in (local_job_status.get("web_tests_info") or {}).values():
      if not isinstance(port_entry, dict):
        continue
      self._stamp_finding_list(port_entry.get("findings"),
                               worker_id, node_addr)
      for method_entry in port_entry.values():
        if isinstance(method_entry, dict):
          self._stamp_finding_list(method_entry.get("findings"),
                                   worker_id, node_addr)
    # Top-level lists.
    self._stamp_finding_list(local_job_status.get("correlation_findings"),
                             worker_id, node_addr)
    self._stamp_finding_list(local_job_status.get("findings"),
                             worker_id, node_addr)

  def _get_aggregated_report(self, local_jobs, worker_cls=None, log_details=True):
    """
    Aggregate results from multiple local workers.

    ``log_details=False`` is used at request trust boundaries where aggregate
    content must not be copied into runtime logs on failure.

    Parameters
    ----------
    local_jobs : dict
      Mapping of worker id to result dicts.
    worker_cls : type, optional
      Worker class to resolve aggregation fields from. Defaults to
      PentestLocalWorker for backward compat.

    Returns
    -------
    dict
      Aggregated report with merged open ports, service info, etc.
    """
    dct_aggregated_report = {}
    type_or_func, field = None, None
    try:
      if local_jobs:
        self.P(f"Aggregating reports from {len(local_jobs)} local jobs...")
        for local_worker_id, local_job_status in local_jobs.items():
          # Chain-of-custody: stamp _source_worker_id / _source_node_addr
          # on every finding before merging so the pentest deliverable
          # can trace every finding back to the worker/node that
          # produced it. Idempotent via setdefault — re-aggregation
          # does not overwrite existing stamps from Phase 2.
          # `initiator` is deliberately NOT in this chain. It is the job
          # *launcher's* address, seeded onto every worker on every
          # participating node, so falling back to it stamped one address across
          # the whole mesh: `_compute_node_comparison` then bucketed every
          # finding under one key, and PDF 3.10 credited a single country with
          # all of them. Measured on the client job — 10 distinct worker ids,
          # exactly 1 node address — and on the archived multi-worker runs.
          # This aggregation merges *this node's* local workers, so this node's
          # own address is the correct attribution for all of them.
          node_addr = (
            local_job_status.get("node_addr")
            or self._local_node_address()
            or str(local_worker_id)
          )
          worker_id = (
            local_job_status.get("local_worker_id")
            or str(local_worker_id)
          )
          self._stamp_worker_source(local_job_status, worker_id, node_addr)

          if worker_cls and hasattr(worker_cls, 'get_worker_specific_result_fields'):
            aggregation_fields = worker_cls.get_worker_specific_result_fields()
          else:
            aggregation_fields = PentestLocalWorker.get_worker_specific_result_fields()
          for field in local_job_status:
            if field not in dct_aggregated_report:
              dct_aggregated_report[field] = local_job_status[field]
            elif field in aggregation_fields:
              type_or_func = aggregation_fields[field]
              if field not in dct_aggregated_report:
                field_type = type(local_job_status[field])
                dct_aggregated_report[field] = field_type()
              #endif
              if isinstance(dct_aggregated_report[field], list):
                existing = set(dct_aggregated_report[field])
                merged = existing.union(local_job_status[field])
                try:
                  dct_aggregated_report[field] = sorted(merged)
                except TypeError:
                  dct_aggregated_report[field] = list(merged)
              elif isinstance(dct_aggregated_report[field], dict):
                dct_aggregated_report[field] = self.merge_objects_deep(
                  dct_aggregated_report[field],
                  local_job_status[field])
              else:
                _existing = dct_aggregated_report[field]
                _new = local_job_status[field]
                dct_aggregated_report[field] = type_or_func([_existing, _new])
              # end if aggregation type
            # end if standard (one time) or aggregated fields
          # for each field in this local job
        # for each local job
        self.P(f"Report aggregation done.")
      # endif we have local jobs
    except Exception as exc:
      if log_details:
        self.P("Error during report aggregation: {}:\n{}\n{}\ntype_or_func={}, field={}".format(
          exc, self.trace_info(),
          self.json_dumps(dct_aggregated_report, indent=2),
          type_or_func, field
        ))
      else:
        self.P("Manual report aggregation failed", color='y')
    # Phase 0 dedup pass: collapse findings duplicated across workers
    # because each worker stamps its own _source_worker_id /
    # _source_node_addr before merge. The JSON-key fallback in
    # merge_objects_deep cannot dedup these because the stamps differ.
    _dedup_findings_in_aggregated(dct_aggregated_report)
    return dct_aggregated_report

  def merge_objects_deep(self, obj_a, obj_b):
    """
    Deeply merge two objects (dicts, lists, sets).

    Parameters
    ----------
    obj_a : Any
      First object.
    obj_b : Any
      Second object.

    Returns
    -------
    Any
      Merged object.
    """
    if isinstance(obj_a, dict) and isinstance(obj_b, dict):
      merged = dict(obj_a)
      for key, value_b in obj_b.items():
        if key in merged:
          merged[key] = self.merge_objects_deep(merged[key], value_b)
        else:
          merged[key] = value_b
      return merged
    elif isinstance(obj_a, list) and isinstance(obj_b, list):
      try:
        return list(set(obj_a).union(set(obj_b)))
      except TypeError:
        import json as _json
        seen = set()
        merged = []
        for item in obj_a + obj_b:
          try:
            key = _json.dumps(item, sort_keys=True, default=str)
          except (TypeError, ValueError):
            key = id(item)
          if key not in seen:
            seen.add(key)
            merged.append(item)
        return merged
    elif isinstance(obj_a, set) and isinstance(obj_b, set):
      return obj_a.union(obj_b)
    else:
      return obj_b  # Prefer obj_b in case of conflict

  def _redact_report(self, report):
    """
    Redact credentials from a report before persistence.

    Deep-copies the report and masks password values in findings and
    accepted_credentials lists so that sensitive data is not written
    to R1FS or CStore.

    Parameters
    ----------
    report : dict
      Aggregated scan report.

    Returns
    -------
    dict
      Redacted copy of the report.
    """
    import re as _re
    from copy import deepcopy
    try:
      from ..graybox.findings import scrub_graybox_secrets as _scrub_graybox
    except Exception:
      _scrub_graybox = None
    redacted = deepcopy(report)
    graybox_secret_names = _configured_graybox_secret_names_from_report(redacted)
    # `web_tests_info` has the same probe-result shape and is harvested into the
    # pass report by `_compute_risk_and_findings`, so it needs the same walk. No
    # web probe interpolates a credential today, which is exactly why it was
    # missed — this is the gap class that produced the leak, not a live one.
    def _redact_finding_list(findings):
      for finding in findings or []:
        if not isinstance(finding, dict):
          continue
        for text_key in _CREDENTIAL_TEXT_FIELDS:
          if isinstance(finding.get(text_key), str):
            finding[text_key] = redact_credential_text(finding[text_key])

    for section_key in ("service_info", "web_tests_info"):
      for port_key, methods in (redacted.get(section_key) or {}).items():
        if not isinstance(methods, dict):
          continue
        # Legacy flat shape: findings sitting directly on the port entry rather
        # than under a probe key. `_stamp_worker_source` handles both shapes and
        # has a test for it; redaction skipped the flat one because the loop
        # below requires a dict and a list falls through the `continue`.
        _redact_finding_list(methods.get("findings"))
        for method_key, method_data in methods.items():
          if not isinstance(method_data, dict):
            continue
          # Redact every probe-authored text field, not just evidence. The
          # default-credential probes put the pair in `title` first, and the
          # title is what reaches the SIEM, the PDF cover and the LLM input.
          _redact_finding_list(method_data.get("findings"))
          # The parallel title list. `findings.py:269` writes it into each
          # *probe result* — `service_info[<port>][<probe>]["vulnerabilities"]`
          # — never at the top level of the report, which is where an earlier
          # version of this redaction looked. Nineteen plaintext pairs survived
          # in the client job as a result, and the regression test passed
          # because its fixture used the top-level shape too.
          vulnerabilities = method_data.get("vulnerabilities")
          if isinstance(vulnerabilities, list):
            method_data["vulnerabilities"] = [
              redact_credential_text(item) for item in vulnerabilities
            ]
          # Both key spellings: the HTTP Basic probe writes `accepted`
          # (common.py:438,477) while this only ever read `accepted_credentials`,
          # so that list was archived raw.
          for creds_key in ("accepted_credentials", "accepted"):
            creds = method_data.get(creds_key)
            if isinstance(creds, list):
              method_data[creds_key] = [
                _re.sub(r'^(\S+?):(.+)$', r'\1:***', c) if isinstance(c, str) else c
                for c in creds
              ]
    # The remaining two published finding paths. `_count_all_findings`
    # enumerates six; redaction reached two of them, which is how the leak
    # survived a green suite.
    _redact_finding_list(redacted.get("correlation_findings"))
    _redact_finding_list(redacted.get("findings"))
    # Redact graybox_results credential evidence
    # URL userinfo: mask the secret half, keep the host. Redacting the whole
    # thing loses the one field saying which service was affected.
    _USERINFO_RE = _re.compile(r'(?<=://)([^/@\s:]+):([^/@\s]+)(?=@)')
    # A bare credential pair, narrowed from the previous `(\S+?):(\S+)`, which
    # matched *any* `a:b` and so destroyed exactly the data this phase exists to
    # add: `https://app.test/x` became `https:***`, every curl reproduction and
    # endpoint URL was annihilated, and `12:04:33` became `12:***`.
    #
    # The discrimination is done by the *guards*, not by restricting which
    # characters a secret may contain. Narrowing the secret charset instead was
    # tried and reduced coverage: `admin:p@$$:w0rd!` and
    # `service-user:s3cr3t/with/slash` both leaked, because real passwords
    # contain exactly the characters a URL does.
    #
    # Guards, in order: not already inside a URL or another token; an
    # identifier-like key; no whitespace or `/` immediately after the colon —
    # which is what excludes `https://…`, `Content-Type: application/json` and
    # `PT-A01-01: IDOR`; and a port-shaped secret, which excludes `app.test:8443`
    # and `app.test:8443/health`.
    #
    # That last guard is written as "a port-length digit run that ends the token
    # or continues as a URL", not as "starts with a digit". The looser form was
    # tried and silently reopened the hole this whole rule exists to close: every
    # digit-leading password — `dbuser:1SecretPass`, `root:2024summer`,
    # `user:007bond` — went out unmasked to the archive, the LLM, the exports and
    # the client PDF, and the coverage-floor test stayed green because none of
    # its cases happened to begin with a digit. A five-digit all-numeric secret
    # is indistinguishable from a port and is deliberately conceded to the port.
    _CRED_RE = _re.compile(
      r'(?<![\w.:/-])'
      r'([A-Za-z_][\w.-]{0,63})'
      r':'
      r'(?![\s/])'
      r'(?!\d{1,5}(?:[/?#\s\'"]|$))'
      r'([^\s\'"]{3,64})'
    )
    _PASSWORD_RE = _re.compile(r'((?:password|passwd|pwd)["\']?\s*[:=]\s*)(["\']?)[^\s"\'&]+', _re.I)

    def _redact_graybox_text(value):
      if not isinstance(value, str):
        return value
      if _scrub_graybox is not None:
        value = _scrub_graybox(
          value, secret_field_names=graybox_secret_names,
        )
      value = _USERINFO_RE.sub(r'\1:***', value)
      value = _CRED_RE.sub(r'\1:***', value)
      value = _PASSWORD_RE.sub(r'\1\2***', value)
      if _scrub_graybox is not None:
        value = _scrub_graybox(
          value, secret_field_names=graybox_secret_names,
        )
      return value

    graybox_results = redacted.get("graybox_results", {})
    for port_key, probes in graybox_results.items():
      if not isinstance(probes, dict):
        continue
      for probe_name, probe_data in probes.items():
        if not isinstance(probe_data, dict):
          continue
        for finding in probe_data.get("findings", []):
          if not isinstance(finding, dict):
            continue
          # `url` and `parameter` are here because a probe may set them straight
          # from target-controlled input rather than deriving them from scrubbed
          # evidence — they were the one location field this walk did not cover,
          # and they reach the archive, the PDF and every export.
          for text_key in ("title", "description", "remediation", "error",
                           "url", "parameter"):
            if isinstance(finding.get(text_key), str):
              finding[text_key] = _redact_graybox_text(finding[text_key])
          assets = finding.get("affected_assets")
          if isinstance(assets, list):
            finding["affected_assets"] = [
              {
                **asset,
                **{
                  key: _redact_graybox_text(asset[key])
                  for key in ("host", "url", "parameter")
                  if isinstance(asset.get(key), str)
                },
              }
              if isinstance(asset, dict) else asset
              for asset in assets
            ]
          if isinstance(finding.get("replay_steps"), list):
            finding["replay_steps"] = [
              _redact_graybox_text(step) for step in finding["replay_steps"]
            ]
          evidence = finding.get("evidence", [])
          if isinstance(evidence, list):
            finding["evidence"] = [
              _redact_graybox_text(e)
              for e in evidence
            ]
          artifacts = finding.get("evidence_artifacts", [])
          if isinstance(artifacts, list):
            finding["evidence_artifacts"] = [
              {
                **artifact,
                "summary": _redact_graybox_text(artifact.get("summary", "")),
                "request_snapshot": _redact_graybox_text(artifact.get("request_snapshot", "")),
                "response_snapshot": _redact_graybox_text(artifact.get("response_snapshot", "")),
              }
              if isinstance(artifact, dict) else artifact
              for artifact in artifacts
            ]
        artifacts = probe_data.get("artifacts", [])
        if isinstance(artifacts, list):
          probe_data["artifacts"] = [
            {
              **artifact,
              "summary": _redact_graybox_text(artifact.get("summary", "")),
              "request_snapshot": _redact_graybox_text(artifact.get("request_snapshot", "")),
              "response_snapshot": _redact_graybox_text(artifact.get("response_snapshot", "")),
            }
            if isinstance(artifact, dict) else artifact
            for artifact in artifacts
          ]
    return redacted

  @staticmethod
  def _redact_job_config(config_dict):
    """
    Redact credential fields from a job config dict before persistence.

    Parameters
    ----------
    config_dict : dict
      JobConfig.to_dict() output.

    Returns
    -------
    dict
      Copy with official_password, regular_password, and weak_candidates masked.
    """
    redacted = dict(config_dict)
    if redacted.get("official_password"):
      redacted["official_password"] = "***"
    if redacted.get("regular_password"):
      redacted["regular_password"] = "***"
    if redacted.get("weak_candidates"):
      redacted["weak_candidates"] = ["***"] * len(redacted["weak_candidates"])
    if isinstance(redacted.get("target_config_secrets"), dict):
      redacted["target_config_secrets"] = {
        str(key): "***" for key in redacted["target_config_secrets"]
      }
    if isinstance(redacted.get("target_config"), dict):
      redacted["target_config"] = _redact_nested_job_config(
        redacted["target_config"]
      )
    redacted.pop("secret_ref", None)
    return redacted

  def _resolve_node_country_tag(self, addr):
    """Resolve a node's ISO-2 country from its netmon ``CT:`` tag.

    Fallback for nodes that produced no report (e.g. a fully-timed-out vantage
    point), so every participating node still carries a country. Returns "" when
    netmon is unavailable or the node has no country tag.
    """
    netmon = getattr(self, "netmon", None)
    if netmon is None:
      return ""
    try:
      tags = netmon.get_network_node_tags(addr) or []
    except Exception:
      return ""
    for tag in tags:
      if isinstance(tag, str) and tag.startswith("CT:"):
        return tag[3:].strip().upper()
    return ""

  def _compute_node_comparison(self, latest, job_config):
    """Per-node vantage-point comparison for comparison-mode jobs.

    One entry per participating node — including nodes that never reported —
    carrying country, reachability status, open ports, findings, and per-node
    metrics so the UI/report can compare results across countries.

    Open ports and per-node metrics are node-accurate. Findings are attributed
    via each finding's ``_source_node_addr`` stamp (single-node attribution
    after cross-node dedup); the UI derives per-country "seen-by" sets from
    these per-node finding lists.
    """
    cfg = job_config or {}
    worker_reports = latest.get("worker_reports") or {}
    worker_scan_metrics = latest.get("worker_scan_metrics") or {}
    findings = latest.get("findings") or []

    findings_by_node = {}
    for f in findings:
      addr = f.get("_source_node_addr")
      if not addr:
        continue
      findings_by_node.setdefault(addr, []).append({
        # Same content-only rule as `_compact_finding_signature`: an
        # identity-derived id is not a content signature.
        "signature": f.get("finding_signature") or f.get("content_hash"),
        "severity": f.get("severity", "INFO"),
        "title": f.get("title", ""),
        "port": f.get("port"),
      })

    # Participating nodes = union of report authors, metric authors, and the
    # originally selected peers (the latter surfaces nodes that never reported).
    participating = list(dict.fromkeys(
      list(worker_reports.keys())
      + list(worker_scan_metrics.keys())
      + list(cfg.get("selected_peers") or [])
    ))

    comparison = []
    for addr in participating:
      wr = worker_reports.get(addr) or {}
      worker_metric_entry = worker_scan_metrics.get(addr) or {}
      sm = worker_metric_entry.get("scan_metrics") or {}
      outcomes = sm.get("connection_outcomes") or {}
      response_times = sm.get("response_times") or {}
      has_report = addr in worker_reports
      country = (wr.get("country") or "").upper() or self._resolve_node_country_tag(addr) or "UN"

      # Status reflects REACHABILITY only. Blocking / rate-limiting are advisory
      # detection signals carried in metrics (a node can be reached AND flagged),
      # so they must not override "reached" when the node returned results.
      if not has_report and addr not in worker_scan_metrics:
        status = "failed"
      elif outcomes and outcomes.get("connected", 0) == 0 and outcomes.get("timeout", 0) > 0:
        status = "timeout"
      else:
        status = "reached"

      p95 = response_times.get("p95")
      comparison.append({
        "address": addr,
        "country": country,
        "node_ip": wr.get("node_ip", ""),
        "status": status,
        "open_ports": wr.get("open_ports", []),
        "nr_findings": wr.get("nr_findings", len(findings_by_node.get(addr, []))),
        "finding_counts": wr.get("finding_counts"),
        "finding_signatures": wr.get("finding_signatures"),
        "response_evidence": wr.get("response_evidence"),
        "findings": findings_by_node.get(addr, []),
        "metrics": {
          "connected": outcomes.get("connected", 0),
          "timeout": outcomes.get("timeout", 0),
          "refused": outcomes.get("refused", 0),
          "reset": outcomes.get("reset", 0),
          "error": outcomes.get("error", 0),
          "response_p95_ms": round(p95 * 1000, 1) if isinstance(p95, (int, float)) else None,
          "coverage": sm.get("coverage"),
          "probes_attempted": sm.get("probes_attempted"),
          "probes_completed": sm.get("probes_completed"),
          "probes_failed": sm.get("probes_failed"),
          "phase_durations": sm.get("phase_durations"),
          "total_duration": sm.get("total_duration"),
          "traffic_windows": sm.get("success_rate_over_time"),
          "threads": worker_metric_entry.get("threads"),
          "rate_limited": bool(sm.get("rate_limiting_detected")),
          "blocked": bool(sm.get("blocking_detected")),
        },
      })
    return comparison

  def _compute_ui_aggregate(self, passes, latest_aggregated, job_config=None):
    """Compute pre-aggregated view for frontend from pass reports.

    Parameters
    ----------
    passes : list
      List of pass report dicts (PassReport.to_dict()).
    latest_aggregated : dict
      AggregatedScanData dict for the latest pass.

    Returns
    -------
    UiAggregate
    """
    from collections import Counter

    latest = passes[-1]
    agg = latest_aggregated
    findings = latest.get("findings", []) or []
    scan_type = (job_config or {}).get("scan_type", "network")
    graybox_stats = {
      "total_routes_discovered": 0,
      "total_forms_discovered": 0,
      "total_scenarios": 0,
      "total_scenarios_vulnerable": 0,
    }
    if scan_type == "webapp":
      graybox_stats = self._extract_graybox_ui_stats(agg, latest)

    # Every counter in this object uses the same predicate, or the object
    # contradicts itself: `total_findings` excluding coverage while the severity
    # chart counted it produced a header saying one finding above a chart
    # summing to eleven, in the same payload the PDF and the frontend read.
    real_findings = [f for f in findings if not _is_coverage_result(f)]

    # Severity breakdown
    findings_count = dict(Counter(f.get("severity", "INFO") for f in real_findings))

    # Top findings: CRITICAL + HIGH, sorted by severity then confidence, capped
    # at 10. An `inconclusive` scenario keeps its *declared* severity, so
    # without the filter a scenario that concluded nothing was ranked into the
    # customer-facing top-findings list as a HIGH.
    crit_high = [f for f in real_findings if f.get("severity") in ("CRITICAL", "HIGH")]
    crit_high.sort(key=lambda f: (
      self.SEVERITY_ORDER.get(f.get("severity"), 9),
      self.CONFIDENCE_ORDER.get(f.get("confidence"), 9),
    ))
    top_findings = crit_high[:10]

    # Finding timeline: track persistence across passes (continuous monitoring)
    # Distinct passes, not occurrences: findings can share an id inside one
    # pass (identity is coarse until RM-061), and counting occurrences reported
    # `pass_count: 2` for a single pass — persistence that never happened, in
    # the surface that exists to measure persistence.
    finding_passes = {}
    for p in passes:
      pass_nr = p.get("pass_nr", 0)
      for f in (p.get("findings") or []):
        fid = f.get("finding_id")
        if not fid:
          continue
        finding_passes.setdefault(fid, set()).add(pass_nr)
    finding_timeline = {
      fid: {
        "first_seen": min(nrs), "last_seen": max(nrs), "pass_count": len(nrs),
      }
      for fid, nrs in finding_passes.items()
    }

    # Origin-country breakdown for the latest pass: count participating worker
    # nodes per ISO-2 country (empty country grouped under "UN"/Unknown in the UI).
    worker_reports = latest.get("worker_reports") or {}
    country_counter = Counter(
      (w.get("country") or "UN").upper() for w in worker_reports.values()
    )
    country_breakdown = [
      {"code": code, "count": count}
      for code, count in sorted(country_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    # Geographic vantage-point comparison (comparison_mode jobs only): durable
    # per-node divergence — reachability, open ports, findings, and latency —
    # including nodes that never reported (fully-timed-out vantage points).
    node_comparison = None
    if (job_config or {}).get("comparison_mode"):
      node_comparison = self._compute_node_comparison(latest, job_config) or None

    return UiAggregate(
      total_open_ports=sorted(set(agg.get("open_ports", []))),
      total_services=self._count_services(agg.get("service_info", {})),
      # Findings, not scenario results: a graybox scan emits one entry per
      # scenario whatever the outcome, so `len(findings)` counted the tests run.
      total_findings=len(real_findings),
      findings_count=findings_count if findings_count else None,
      top_findings=top_findings if top_findings else None,
      finding_timeline=finding_timeline if finding_timeline else None,
      latest_risk_score=latest.get("risk_score"),
      latest_risk_breakdown=latest.get("risk_breakdown"),
      latest_quick_summary=latest.get("quick_summary"),
      worker_activity=[
        {
          "id": addr,
          "start_port": w["start_port"],
          "end_port": w["end_port"],
          "open_ports": w.get("open_ports", []),
          "country": (w.get("country") or "").upper(),
        }
        for addr, w in worker_reports.items()
      ] or None,
      country_breakdown=country_breakdown or None,
      node_comparison=node_comparison,
      scan_type=scan_type,
      total_routes_discovered=graybox_stats["total_routes_discovered"],
      total_forms_discovered=graybox_stats["total_forms_discovered"],
      total_scenarios=graybox_stats["total_scenarios"],
      total_scenarios_vulnerable=graybox_stats["total_scenarios_vulnerable"],
    )
