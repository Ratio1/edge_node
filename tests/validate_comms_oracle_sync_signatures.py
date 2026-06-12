#!/usr/bin/env python3
"""Validate persisted local OracleSync agreement signatures.

This check is intentionally tied to ``docker-compose_comms_oracle_sync.yaml``.
It reads the oracle containers' ``epochs_status.pkl`` files, rebuilds the exact
payload signed by OracleSync, and verifies every agreement signature with the
production Ratio1 elliptic-curve verifier.
"""

import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ratio1.bc.base import BCct
from ratio1.bc.ec import BaseBCEllipticCurveEngine


ORACLE_CONTAINERS = ("ratio1_comm_oracle_01", "ratio1_comm_oracle_02")
EPOCHS_STATUS_PATH = "/edge_node/_local_cache/_data/network_monitor/epochs_status.pkl"


class _StubLog:
  """Minimal logger surface required by the blockchain verifier."""

  def __init__(self):
    self.root = tempfile.mkdtemp(prefix="ecomms_sig_verify_")

  def P(self, *args, **kwargs):
    return None

  def get_data_folder(self):
    return self.root

  def get_target_folder(self, subfolder):
    path = os.path.join(self.root, subfolder)
    os.makedirs(path, exist_ok=True)
    return path


def _run(args):
  return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def _copy_epoch_status(container, output_dir):
  output_path = output_dir / f"{container}_epochs_status.pkl"
  _run(["docker", "cp", f"{container}:{EPOCHS_STATUS_PATH}", str(output_path)])
  with output_path.open("rb") as fh:
    return pickle.load(fh)


def _container_address(container):
  code = (
    "import json; "
    "print(json.load(open('/edge_node/_local_cache/_data/local_info.json')).get('address'))"
  )
  return _run(["docker", "exec", container, "python3", "-c", code]).strip()


def _availability_table(data, epoch):
  table = {}
  for node_addr, node_state in data.get("NODES", {}).items():
    epochs = node_state.get("epochs") or {}
    value = epochs.get(epoch, epochs.get(str(epoch)))
    if value is not None:
      table[node_addr] = value
  return table


def _node_names(data):
  return {
    addr: state.get("name")
    for addr, state in data.get("NODES", {}).items()
  }


def _verify_file(container, data, bc_engine, expected_oracle_signers):
  failures = []
  signature_epochs = sorted(int(epoch) for epoch in data.get("SIGNATURES", {}))
  last_sync_epoch = data.get("LAST_SYNC_EPOCH") or 0

  expected_signature_epochs = list(range(1, last_sync_epoch + 1))
  if signature_epochs != expected_signature_epochs:
    failures.append({
      "container": container,
      "type": "signature_epoch_range_mismatch",
      "signature_epochs": signature_epochs,
      "expected_signature_epochs": expected_signature_epochs,
    })

  if last_sync_epoch != max(signature_epochs, default=0):
    failures.append({
      "container": container,
      "type": "last_sync_mismatch",
      "last_sync_epoch": last_sync_epoch,
      "max_signature_epoch": max(signature_epochs, default=0),
    })

  verified = 0
  expected = 0
  signer_counts = set()
  hash_counts = set()
  for epoch in signature_epochs:
    table = _availability_table(data, epoch)
    non_zero_table = {
      node_addr: availability
      for node_addr, availability in table.items()
      if availability != 0
    }
    signatures = data["SIGNATURES"][epoch]
    signer_counts.add(len(signatures))
    hash_counts.add(len(set(sig.get(BCct.HASH) for sig in signatures.values())))
    expected += len(signatures)

    if set(signatures) != set(expected_oracle_signers):
      failures.append({
        "container": container,
        "epoch": epoch,
        "type": "signers_not_equal_oracle_nodes",
        "signers": sorted(signatures),
        "oracle_nodes": expected_oracle_signers,
      })

    for signer, signature_dict in signatures.items():
      if signature_dict.get(BCct.SENDER) != signer:
        failures.append({
          "container": container,
          "epoch": epoch,
          "type": "signer_sender_mismatch",
          "signer": signer,
          "sender": signature_dict.get(BCct.SENDER),
        })
      signed_payload = dict(signature_dict)
      # OracleSync signs only the non-zero availability table plus the epoch.
      # Rebuild that payload exactly before handing it to the production verifier.
      signed_payload["COMPILED_AGREED_MEDIAN_TABLE"] = non_zero_table
      signed_payload["EPOCH"] = epoch
      result = bc_engine.verify(
        dct_data=signed_payload,
        signature=None,
        sender_address=None,
        log_hash_sign_fails=False,
      )
      if result.valid:
        verified += 1
      else:
        failures.append({
          "container": container,
          "epoch": epoch,
          "type": "invalid_signature",
          "signer": signer,
          "message": result.message,
        })

  return {
    "container": container,
    "nodes": len(data.get("NODES", {})),
    "node_names": _node_names(data),
    "last_sync_epoch": last_sync_epoch,
    "faulty_epochs": list(data.get("FAULTY_EPOCHS", [])),
    "signature_epoch_range": [min(signature_epochs), max(signature_epochs)] if signature_epochs else None,
    "signature_epoch_count": len(signature_epochs),
    "verified_signatures": verified,
    "expected_signatures": expected,
    "signer_counts": sorted(signer_counts),
    "hash_count_per_epoch": sorted(hash_counts),
  }, failures


def _cross_check(first_name, first_data, second_name, second_data):
  failures = []
  first_epochs = set(first_data.get("SIGNATURES", {}))
  second_epochs = set(second_data.get("SIGNATURES", {}))
  common_epochs = sorted(first_epochs & second_epochs)
  if first_epochs != second_epochs:
    failures.append({
      "type": "cross_epoch_mismatch",
      first_name: sorted(first_epochs),
      second_name: sorted(second_epochs),
    })

  availability_mismatches = [
    epoch
    for epoch in common_epochs
    if _availability_table(first_data, epoch) != _availability_table(second_data, epoch)
  ]
  signature_mismatches = [
    epoch
    for epoch in common_epochs
    if first_data["SIGNATURES"][epoch] != second_data["SIGNATURES"][epoch]
  ]
  if availability_mismatches:
    failures.append({"type": "availability_mismatch", "epochs": availability_mismatches})
  if signature_mismatches:
    failures.append({"type": "signature_mismatch", "epochs": signature_mismatches})

  return {
    "pair": f"{first_name}_vs_{second_name}",
    "common_epochs": common_epochs,
    "availability_mismatches": availability_mismatches,
    "signature_mismatches": signature_mismatches,
    "same_faulty_epochs": first_data.get("FAULTY_EPOCHS") == second_data.get("FAULTY_EPOCHS"),
    "same_genesis": first_data.get("EE_GENESIS_EPOCH_DATE") == second_data.get("EE_GENESIS_EPOCH_DATE"),
    "same_epoch_intervals": first_data.get("EE_EPOCH_INTERVALS") == second_data.get("EE_EPOCH_INTERVALS"),
    "same_epoch_seconds": first_data.get("EE_EPOCH_INTERVAL_SECONDS") == second_data.get("EE_EPOCH_INTERVAL_SECONDS"),
  }, failures


def main():
  output_dir = Path(tempfile.mkdtemp(prefix="ecomms_epoch_status_"))
  log = _StubLog()
  try:
    bc_engine = BaseBCEllipticCurveEngine(
      log=log,
      name="ecomms_oracle_sync_signature_verify",
      config={},
      eth_enabled=False,
      verbosity=0,
    )
    expected_oracle_signers = sorted(
      _container_address(container)
      for container in ORACLE_CONTAINERS
    )
    snapshots = {
      container: _copy_epoch_status(container=container, output_dir=output_dir)
      for container in ORACLE_CONTAINERS
    }

    summaries = []
    failures = []
    for container, data in snapshots.items():
      summary, container_failures = _verify_file(
        container=container,
        data=data,
        bc_engine=bc_engine,
        expected_oracle_signers=expected_oracle_signers,
      )
      summaries.append(summary)
      failures.extend(container_failures)

    first, second = ORACLE_CONTAINERS
    cross_summary, cross_failures = _cross_check(
      first_name=first,
      first_data=snapshots[first],
      second_name=second,
      second_data=snapshots[second],
    )
    failures.extend(cross_failures)

    print(json.dumps({
      "files": summaries,
      "expected_oracle_signers": expected_oracle_signers,
      "cross_file": cross_summary,
      "failures": failures,
      "status": "ok" if not failures else "failed",
    }, indent=2, default=str))
    return 0 if not failures else 1
  finally:
    shutil.rmtree(output_dir, ignore_errors=True)
    shutil.rmtree(log.root, ignore_errors=True)


if __name__ == "__main__":
  sys.exit(main())
