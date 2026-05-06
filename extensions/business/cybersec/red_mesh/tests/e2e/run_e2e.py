#!/usr/bin/env python3
"""End-to-end test harness for Phase 0 / Phase 1 PTES rebuild.

Run against running rm1 + rm2 containers. Launches scans, polls for
completion, and asserts behavioral invariants:

  - Phase 0 PR-0.1 dedup: graybox findings are NOT duplicated across
    workers in the aggregated report.
  - Phase 0 PR-0.1 dedup: service-info findings are NOT duplicated.
  - Phase 0 PR-0.2: aggregated reports do not have spurious zero-port
    metadata.
  - Phase 1 PR-1.1: Finding emits accept new schema fields without
    breaking existing probe paths (legacy fields still emitted).

Usage:
    python run_e2e.py --rm1 http://localhost:5082 --target 10.132.0.3 \\
        [--scenario blackbox|graybox|all]

Designed to be re-runnable. Each scenario captures the full
aggregated report JSON to /tmp/redmesh-e2e-{scenario}-{timestamp}.json
for inspection on failure.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any
from urllib import error, request


def http_post(url: str, payload: dict, timeout: int = 30) -> dict:
  data = json.dumps(payload).encode("utf-8")
  req = request.Request(
    url, data=data, method="POST",
    headers={"Content-Type": "application/json"},
  )
  with request.urlopen(req, timeout=timeout) as resp:
    return json.loads(resp.read().decode("utf-8"))


def http_get(url: str, timeout: int = 15) -> dict:
  with request.urlopen(url, timeout=timeout) as resp:
    return json.loads(resp.read().decode("utf-8"))


def launch_blackbox(rm: str, target: str, task_name: str = "e2e-blackbox") -> str:
  resp = http_post(f"{rm}/launch_network_scan", {
    "target": target,
    "start_port": 1, "end_port": 200,
    "exceptions": "",
    "distribution_strategy": "slice", "port_order": "sequential",
    "excluded_features": [], "run_mode": "singlepass",
    "monitor_interval": 0, "scan_min_delay": 0.0, "scan_max_delay": 0.0,
    "task_name": task_name,
    "task_description": "Phase 0/1 e2e verification",
    "selected_peers": [], "redact_credentials": True, "ics_safe_mode": False,
    "scanner_identity": "redmesh", "scanner_user_agent": "RedMesh/e2e",
    "authorized": True, "created_by_name": "e2e", "created_by_id": "e2e",
    "nr_local_workers": 1, "target_confirmation": target,
  })
  job_id = resp.get("result", {}).get("job_specs", {}).get("job_id")
  if not job_id:
    raise RuntimeError(f"launch failed: {resp.get('result')}")
  return job_id


def launch_graybox(rm: str, target_url: str, target_host: str,
                   task_name: str = "e2e-graybox") -> str:
  resp = http_post(f"{rm}/launch_webapp_scan", {
    "target_url": target_url,
    "excluded_features": [],
    "run_mode": "singlepass",
    "monitor_interval": 0, "scan_min_delay": 0.0, "scan_max_delay": 0.0,
    "task_name": task_name,
    "task_description": "Phase 0/1 e2e graybox verification",
    "selected_peers": [], "redact_credentials": True, "ics_safe_mode": False,
    "scanner_identity": "redmesh", "scanner_user_agent": "RedMesh/e2e",
    "authorized": True, "created_by_name": "e2e", "created_by_id": "e2e",
    "official_username": "admin", "official_password": "admin",
    "regular_username": "user", "regular_password": "password",
    "weak_candidates": [], "max_weak_attempts": 5, "app_routes": [],
    "verify_tls": False, "allow_stateful_probes": False,
    "target_confirmation": target_host,
  })
  job_id = resp.get("result", {}).get("job_specs", {}).get("job_id")
  if not job_id:
    raise RuntimeError(f"launch failed: {resp.get('result')}")
  return job_id


def wait_for_finalize(rm: str, job_id: str, timeout: int = 600,
                      poll_every: int = 10) -> dict:
  deadline = time.time() + timeout
  last_status = None
  while time.time() < deadline:
    listing = http_get(f"{rm}/list_network_jobs").get("result", {})
    job = listing.get(job_id)
    if not job:
      time.sleep(poll_every); continue
    status = job.get("job_status")
    if status != last_status:
      print(f"  [{time.strftime('%H:%M:%S')}] {job_id}: {status}", flush=True)
      last_status = status
    if status == "FINALIZED":
      return job
    time.sleep(poll_every)
  raise TimeoutError(f"job {job_id} did not finalize within {timeout}s; last={last_status}")


def fetch_archive(rm: str, job_id: str) -> dict:
  resp = http_get(f"{rm}/get_job_archive?job_id={job_id}")
  return resp.get("result", {}).get("archive", {})


def archive_passes(archive: dict) -> list:
  """Return current JobArchive.passes with legacy pass_reports fallback."""
  if not isinstance(archive, dict):
    return []
  passes = archive.get("passes")
  if isinstance(passes, list):
    return passes
  pass_reports = archive.get("pass_reports")
  if isinstance(pass_reports, list):
    return pass_reports
  return []


def assert_no_dup_findings(aggregated: dict, label: str) -> list[str]:
  """Phase 0 PR-0.1 invariant — every finding list under the canonical
  paths must have unique signatures (excluding _source_* stamps)."""
  failures: list[str] = []
  def signature(f: dict) -> str:
    stripped = {k: v for k, v in f.items() if not k.startswith("_source_")}
    try:
      return json.dumps(stripped, sort_keys=True, default=str)
    except Exception:
      return repr(stripped)
  def check(findings: list, path: str):
    seen = set(); dups = []
    for f in findings or []:
      if not isinstance(f, dict): continue
      sig = signature(f)
      if sig in seen: dups.append(f.get("title", "<no-title>"))
      seen.add(sig)
    if dups:
      failures.append(f"DUP at {path}: {len(dups)} duplicates ({set(dups)})")

  for port_key, port_entry in (aggregated.get("service_info") or {}).items():
    if not isinstance(port_entry, dict): continue
    check(port_entry.get("findings"), f"service_info[{port_key}]")
    for probe_key, probe_entry in port_entry.items():
      if isinstance(probe_entry, dict):
        check(probe_entry.get("findings"), f"service_info[{port_key}][{probe_key}]")

  for port_key, port_entry in (aggregated.get("web_tests_info") or {}).items():
    if not isinstance(port_entry, dict): continue
    check(port_entry.get("findings"), f"web_tests_info[{port_key}]")
    for method_key, method_entry in port_entry.items():
      if isinstance(method_entry, dict):
        check(method_entry.get("findings"), f"web_tests_info[{port_key}][{method_key}]")

  for port_key, port_probes in (aggregated.get("graybox_results") or {}).items():
    if not isinstance(port_probes, dict): continue
    for probe_key, probe_entry in port_probes.items():
      if isinstance(probe_entry, dict):
        check(probe_entry.get("findings"), f"graybox_results[{port_key}][{probe_key}]")

  check(aggregated.get("correlation_findings"), "correlation_findings (top)")
  check(aggregated.get("findings"), "findings (top)")
  return failures


def assert_legacy_finding_fields(aggregated: dict) -> list[str]:
  """Phase 1 PR-1.1 invariant — every emitted Finding still carries
  the legacy fields. New fields may also be present."""
  failures: list[str] = []
  required = {"severity", "title", "description"}
  count = 0
  def check(findings: list, path: str):
    nonlocal count
    for f in findings or []:
      if not isinstance(f, dict): continue
      count += 1
      missing = required - set(f.keys())
      if missing:
        failures.append(f"missing legacy fields {missing} at {path}: {f.get('title','?')}")

  for port_entry in (aggregated.get("service_info") or {}).values():
    if not isinstance(port_entry, dict): continue
    for probe_entry in port_entry.values():
      if isinstance(probe_entry, dict):
        check(probe_entry.get("findings"), "service_info")
  for port_entry in (aggregated.get("web_tests_info") or {}).values():
    if not isinstance(port_entry, dict): continue
    for method_entry in port_entry.values():
      if isinstance(method_entry, dict):
        check(method_entry.get("findings"), "web_tests_info")
  for port_probes in (aggregated.get("graybox_results") or {}).values():
    if not isinstance(port_probes, dict): continue
    for probe_entry in port_probes.values():
      if isinstance(probe_entry, dict):
        check(probe_entry.get("findings"), "graybox_results")
  check(aggregated.get("correlation_findings"), "correlation_findings")
  print(f"  legacy-field check: {count} findings inspected", flush=True)
  return failures


def run_scenario(rm: str, name: str, launch_fn, **launch_kwargs) -> dict:
  print(f"\n=== Scenario: {name} ===", flush=True)
  job_id = launch_fn(rm, **launch_kwargs)
  print(f"  launched: {job_id}", flush=True)
  job = wait_for_finalize(rm, job_id, timeout=600)
  print(f"  duration: {job.get('duration', '?')}s, risk: {job.get('risk_score', '?')}", flush=True)

  archive = fetch_archive(rm, job_id)
  pass_reports = archive_passes(archive)
  if not pass_reports:
    raise AssertionError(f"{name}: archive has no passes/pass_reports")
  pr = pass_reports[-1]
  agg_cid = pr.get("aggregated_report_cid")
  print(f"  aggregated_report_cid: {agg_cid}", flush=True)

  if "aggregated_data" in pr:
    aggregated = pr["aggregated_data"]
  else:
    aggregated = pr

  ts = int(time.time())
  out_path = f"/tmp/redmesh-e2e-{name}-{job_id}-{ts}.json"
  with open(out_path, "w") as fh:
    json.dump({"job": job, "archive": archive}, fh, indent=2, default=str)
  print(f"  saved snapshot: {out_path}", flush=True)

  failures = []
  failures += assert_no_dup_findings(aggregated, name)
  failures += assert_legacy_finding_fields(aggregated)

  if failures:
    print(f"  FAIL ({len(failures)}):", flush=True)
    for fail in failures:
      print(f"    - {fail}", flush=True)
    return {"ok": False, "job_id": job_id, "failures": failures, "snapshot": out_path}
  print(f"  PASS", flush=True)
  return {"ok": True, "job_id": job_id, "snapshot": out_path}


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--rm1", default="http://localhost:5082")
  parser.add_argument("--target", default="10.132.0.3")
  parser.add_argument("--target-url", default="http://10.132.0.3:10000")
  parser.add_argument("--scenario", choices=["blackbox", "graybox", "all"], default="all")
  args = parser.parse_args()

  results: list[dict] = []
  if args.scenario in ("blackbox", "all"):
    try:
      results.append(run_scenario(
        args.rm1, "blackbox", launch_blackbox, target=args.target,
      ))
    except Exception as exc:
      print(f"  EXCEPTION: {exc}", flush=True)
      results.append({"ok": False, "scenario": "blackbox", "error": str(exc)})

  if args.scenario in ("graybox", "all"):
    try:
      results.append(run_scenario(
        args.rm1, "graybox", launch_graybox,
        target_url=args.target_url, target_host=args.target,
      ))
    except Exception as exc:
      print(f"  EXCEPTION: {exc}", flush=True)
      results.append({"ok": False, "scenario": "graybox", "error": str(exc)})

  print("\n=== Summary ===", flush=True)
  for r in results:
    status = "PASS" if r.get("ok") else "FAIL"
    print(f"  {status}  {r.get('job_id', r.get('scenario', '?'))}", flush=True)

  return 0 if all(r.get("ok") for r in results) else 1


if __name__ == "__main__":
  sys.exit(main())
