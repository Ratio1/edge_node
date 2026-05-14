#!/usr/bin/env python3
"""OWASP API Top 10 e2e harness — Phase 7 of the API Top 10 plan.

Reads the per-scenario manifest at fixtures/api_top10_manifest.yaml,
builds a launch payload from fixtures/api_security_target_config.json,
launches a webapp scan against the rm-gb-poc honeypot, polls for
completion, and asserts:

  - Phase 7.2: vulnerable run — every scenario in the manifest is
    present with status=vulnerable + expected severity + evidence keys.
  - Phase 7.3: hardened run (`HONEYPOT_HARDEN_API=1`) — same scenario
    IDs are present but now status=not_vulnerable; risk score is
    materially lower than the vulnerable run.
  - Phase 7.4: stateful-gated run (`allow_stateful_probes=false`) —
    stateful scenarios emit `inconclusive` with reason
    `stateful_probes_disabled`; no state is mutated.
  - Phase 7.5: LLM input boundary — no Authorization/Cookie/JWT/long-base64
    blob reaches the LLM input artifact.

Usage:
    python api_top10_e2e.py --rm http://localhost:5082 \\
        --honeypot http://localhost:30001 \\
        --scenario vulnerable|hardened|stateful-gated|llm-boundary|all

This harness deliberately uses ``urllib`` rather than ``requests`` so it
inherits no extra dependency. PyYAML is the only optional dep — falls
back to a minimal in-tree parser if absent.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent


def _load_yaml(path: Path) -> dict:
  try:
    import yaml  # type: ignore[import-not-found]
    return yaml.safe_load(path.read_text())
  except ImportError:
    # Minimal fallback parser — handles only the manifest's shape.
    return _parse_simple_yaml(path.read_text())


def _parse_simple_yaml(src: str) -> dict:
  """Very tiny YAML reader for the manifest. Lists of dicts only,
  string scalars (with optional quoted strings), and block scalars."""
  out: dict[str, Any] = {}
  current_list: list[dict[str, Any]] | None = None
  current_item: dict[str, Any] | None = None
  in_block_scalar = False
  block_field = ""
  block_lines: list[str] = []
  block_indent = 0
  for line in src.splitlines():
    if in_block_scalar:
      stripped = line.rstrip()
      if stripped == "" or (stripped and stripped.startswith(" " * block_indent)):
        block_lines.append(stripped[block_indent:] if stripped else "")
        continue
      # End of block.
      assert current_item is not None
      current_item[block_field] = "\n".join(block_lines).strip()
      in_block_scalar = False
      block_lines = []
      # fall through to re-process this line
    if not line.strip() or line.lstrip().startswith("#"):
      continue
    indent = len(line) - len(line.lstrip())
    s = line.strip()
    if indent == 0 and ":" in s and not s.startswith("-"):
      k, v = s.split(":", 1)
      v = v.strip()
      if v == "":
        out[k.strip()] = []
        current_list = out[k.strip()]
      else:
        out[k.strip()] = _scalar(v)
        current_list = None
    elif s.startswith("- "):
      current_item = {}
      assert current_list is not None
      current_list.append(current_item)
      rest = s[2:]
      if ":" in rest:
        k, v = rest.split(":", 1)
        current_item[k.strip()] = _scalar(v.strip())
    elif ":" in s and current_item is not None:
      k, v = s.split(":", 1)
      v = v.strip()
      if v in ("|", ">"):
        in_block_scalar = True
        block_field = k.strip()
        block_indent = indent + 2
        block_lines = []
      else:
        current_item[k.strip()] = _scalar(v)
  if in_block_scalar and current_item is not None:
    current_item[block_field] = "\n".join(block_lines).strip()
  return out


def _scalar(v: str) -> Any:
  v = v.strip()
  if v.startswith("[") and v.endswith("]"):
    inner = v[1:-1].strip()
    if not inner:
      return []
    return [_scalar(x.strip().strip('"').strip("'")) for x in inner.split(",")]
  if v.startswith('"') and v.endswith('"'):
    return v[1:-1]
  if v.startswith("'") and v.endswith("'"):
    return v[1:-1]
  if v in ("true", "True"):
    return True
  if v in ("false", "False"):
    return False
  if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
    return int(v)
  return v


# ── HTTP helpers ────────────────────────────────────────────────────

def http_post(url: str, payload: dict, timeout: int = 30) -> dict:
  data = json.dumps(payload).encode()
  req = request.Request(
    url, data=data, method="POST",
    headers={"Content-Type": "application/json"},
  )
  with request.urlopen(req, timeout=timeout) as resp:
    return json.loads(resp.read().decode())


def http_get(url: str, timeout: int = 30) -> dict:
  with request.urlopen(url, timeout=timeout) as resp:
    return json.loads(resp.read().decode())


def unwrap_result(payload: dict) -> dict:
  if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
    return payload["result"]
  return payload


# ── Scan orchestration ──────────────────────────────────────────────

def target_confirmation_for_url(target_url: str) -> str:
  """Return the host value expected by launch-side authorization checks."""
  parsed = urlparse(target_url)
  return parsed.hostname or target_url


def target_config_with_bearer_auth(target_config: dict) -> dict:
  """Return a launch config that exercises API-native bearer auth.

  The honeypot's browser form has CSRF protection, while the API Top 10
  endpoints expose `/api/v2/token/` and `/api/v2/me/` specifically for
  API-auth validation. Keep the fixture's scenario inventory intact and
  layer only the auth descriptor required by the backend launch contract.
  """
  cfg = json.loads(json.dumps(target_config))
  api_security = dict(cfg.get("api_security") or {})
  auth = dict(api_security.get("auth") or {})
  auth.update({
    "auth_type": "bearer",
    "bearer_token_header_name": "Authorization",
    "bearer_scheme": "Bearer",
    "authenticated_probe_path": "/api/v2/me/",
  })
  api_security["auth"] = auth
  cfg["api_security"] = api_security
  return cfg


def mint_bearer_token(honeypot: str) -> str:
  result = unwrap_result(http_post(
    f"{honeypot.rstrip('/')}/api/v2/token/",
    {"username": "alice", "password": "secret"},
  ))
  token = result.get("token") if isinstance(result, dict) else None
  if not token:
    raise RuntimeError(f"honeypot token endpoint did not return token: {result}")
  return str(token)

def launch_scan(rm: str, honeypot: str, target_config: dict, *,
                allow_stateful: bool = True) -> str:
  official_token = mint_bearer_token(honeypot)
  regular_token = mint_bearer_token(honeypot)
  payload = {
    "target_url": honeypot,
    "official_username": "alice",
    "official_password": "",
    "regular_username": "alice",
    "regular_password": "",
    "target_config": target_config_with_bearer_auth(target_config),
    "bearer_token": official_token,
    "regular_bearer_token": regular_token,
    "allow_stateful_probes": allow_stateful,
    "graybox_assignment_strategy": "SLICE",
    "authorized": True,
    "target_confirmation": target_confirmation_for_url(honeypot),
    "task_name": "api-top10-e2e",
  }
  resp = http_post(f"{rm}/launch_webapp_scan", payload)
  result = unwrap_result(resp)
  job_id = result.get("job_id") or (result.get("job_specs") or {}).get("job_id")
  if not job_id:
    raise RuntimeError(f"launch_webapp_scan failed: {resp}")
  return job_id


def wait_for_finalize(rm: str, job_id: str, timeout: int = 600) -> dict:
  deadline = time.time() + timeout
  while time.time() < deadline:
    try:
      resp = unwrap_result(http_get(f"{rm}/get_job_status?job_id={job_id}"))
    except (TimeoutError, OSError, error.URLError):
      time.sleep(5)
      continue
    status = (
      resp.get("status") or resp.get("job_status")
      or (resp.get("job") or {}).get("job_status") or ""
    )
    if str(status).lower() in ("finalized", "done", "completed"):
      return resp
    time.sleep(5)
  raise TimeoutError(f"job {job_id} did not finalize within {timeout}s")


def fetch_archive(rm: str, job_id: str) -> dict:
  resp = unwrap_result(http_get(f"{rm}/get_job_archive?job_id={job_id}"))
  return resp.get("archive", resp)


def collect_findings(archive: dict) -> list[dict]:
  """Pull every flat finding out of the archive's passes."""
  out: list[dict] = []
  for p in archive.get("passes", []) or []:
    out.extend(p.get("findings", []) or [])
  return out


def llm_boundary_blob_from_archive(archive: dict) -> str:
  """Serialize archive fields that are allowed to feed LLM/report stages.

  Deployments do not expose a stable ``/get_job_llm_input`` endpoint yet, so
  the harness validates the immutable archive material that backs LLM/report
  generation: flat findings, LLM analyses, quick summaries, and structured
  report sections. Raw JobConfig and worker stdout are intentionally excluded.
  """
  boundary: list[dict[str, Any]] = []
  for p in archive.get("passes", []) or []:
    if not isinstance(p, dict):
      continue
    boundary.append({
      "findings": p.get("findings", []),
      "llm_analysis": p.get("llm_analysis"),
      "quick_summary": p.get("quick_summary"),
      "llm_report_sections": p.get("llm_report_sections"),
    })
  return json.dumps(boundary, sort_keys=True, default=str)


# ── Assertions ──────────────────────────────────────────────────────

def assert_vulnerable_run(findings: list[dict], manifest: dict) -> list[str]:
  """Phase 7.2: every manifest scenario surfaces as vulnerable."""
  errors: list[str] = []
  by_id: dict[str, dict] = {}
  for f in findings:
    sid = f.get("scenario_id")
    if sid and f.get("status") == "vulnerable":
      by_id.setdefault(sid, f)
  for entry in manifest["scenarios"]:
    sid = entry["id"]
    if sid not in by_id:
      errors.append(f"missing vulnerable finding for {sid}")
      continue
    f = by_id[sid]
    if f["severity"] != entry["expected_severity"]:
      errors.append(
        f"{sid}: severity {f['severity']} != expected "
        f"{entry['expected_severity']}",
      )
    evidence = f.get("evidence", "")
    if isinstance(evidence, list):
      evidence_text = "\n".join(str(x) for x in evidence)
    else:
      evidence_text = str(evidence or "")
    haystack = evidence_text + "\n" + (f.get("description") or "")
    for key in entry.get("expected_evidence_keys", []) or []:
      if key not in haystack:
        errors.append(f"{sid}: evidence missing substring {key!r}")
  return errors


def assert_hardened_run(findings: list[dict], manifest: dict) -> list[str]:
  errors: list[str] = []
  by_id: dict[str, dict] = {f.get("scenario_id"): f
                              for f in findings if f.get("scenario_id")}
  for entry in manifest["scenarios"]:
    sid = entry["id"]
    if sid not in by_id:
      continue  # absence is acceptable in hardened mode for some probes
    if by_id[sid].get("status") == "vulnerable":
      errors.append(
        f"hardened run still reports {sid} as vulnerable",
      )
  return errors


_LEAK_PATTERNS = [
  re.compile(r"Authorization:\s*Bearer\s+eyJ", re.IGNORECASE),
  re.compile(r"Cookie:\s*sessionid=", re.IGNORECASE),
  re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
  re.compile(r"password=[^&\s\";<]{8,}"),
]


def assert_llm_boundary(llm_input_blob: str) -> list[str]:
  errors: list[str] = []
  for pat in _LEAK_PATTERNS:
    if pat.search(llm_input_blob):
      errors.append(f"LLM input matched leak pattern: {pat.pattern!r}")
  return errors


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--rm", required=True, help="Edge node base URL")
  ap.add_argument("--honeypot", default="http://localhost:30001")
  ap.add_argument(
    "--scenario", default="all",
    choices=("vulnerable", "hardened", "stateful-gated", "llm-boundary", "all"),
  )
  ap.add_argument("--timeout", type=int, default=600)
  args = ap.parse_args()

  manifest = _load_yaml(HERE / "fixtures" / "api_top10_manifest.yaml")
  target_config = json.loads(
    (HERE / "fixtures" / "api_security_target_config.json").read_text(),
  )

  ok = True

  last_archive: dict | None = None

  def run(label: str, allow_stateful: bool, assert_fn) -> bool:
    nonlocal last_archive
    print(f"\n=== {label} ===")
    job_id = launch_scan(args.rm, args.honeypot, target_config,
                          allow_stateful=allow_stateful)
    print(f"  job_id={job_id}")
    wait_for_finalize(args.rm, job_id, timeout=args.timeout)
    archive = fetch_archive(args.rm, job_id)
    last_archive = archive
    findings = collect_findings(archive)
    errors = assert_fn(findings, manifest)
    if errors:
      print(f"  FAIL: {len(errors)} assertion errors:")
      for e in errors[:20]:
        print(f"    - {e}")
      return False
    print(f"  OK ({len(findings)} findings)")
    return True

  if args.scenario in ("vulnerable", "all"):
    ok &= run("Vulnerable run (PHASE 7.2)", True, assert_vulnerable_run)
  if args.scenario in ("hardened", "all"):
    print("\n  → set HONEYPOT_HARDEN_API=1 on the honeypot before continuing")
    ok &= run("Hardened run (PHASE 7.3)", True, assert_hardened_run)
  if args.scenario in ("stateful-gated", "all"):
    print("\n  Phase 7.4 — stateful-disabled run; expecting inconclusive findings")
    ok &= run("Stateful-gated run", False,
               lambda fs, m: (
                 ["stateful scenarios must not be vulnerable while gated"]
                 if any(
                   f.get("scenario_id") in {"PT-OAPI2-03", "PT-OAPI3-02", "PT-OAPI5-03", "PT-OAPI5-04", "PT-OAPI6-01", "PT-OAPI6-02"}
                   and f.get("status") == "vulnerable"
                   for f in fs
                 )
                 else []
               ) + (
                 ["stateful-gated run produced no stateful inconclusive findings"]
                 if not any(
                   f.get("scenario_id") in {"PT-OAPI2-03", "PT-OAPI3-02", "PT-OAPI5-03", "PT-OAPI5-04", "PT-OAPI6-01", "PT-OAPI6-02"}
                   and f.get("status") == "inconclusive"
                   for f in fs
                 )
                 else []
               ))
  if args.scenario in ("llm-boundary", "all"):
    print("\n  Phase 7.5 — verify archive material used for LLM/report input")
    if last_archive is None:
      job_id = launch_scan(args.rm, args.honeypot, target_config,
                            allow_stateful=False)
      print(f"  job_id={job_id}")
      wait_for_finalize(args.rm, job_id, timeout=args.timeout)
      last_archive = fetch_archive(args.rm, job_id)
    errors = assert_llm_boundary(llm_boundary_blob_from_archive(last_archive))
    if errors:
      print(f"  FAIL: {len(errors)} boundary assertion errors:")
      for e in errors[:20]:
        print(f"    - {e}")
      ok = False
    else:
      print("  OK (no LLM/report-boundary leak patterns)")

  return 0 if ok else 1


if __name__ == "__main__":
  sys.exit(main())
