#!/usr/bin/env python3
"""
Local-only entrypoint for the isolated communication compose testbed.

The production `device.py` intentionally keeps its optional runtime package
install path. The comms testbed does not exercise local LLM serving, so this
entrypoint skips extra packages without changing the tracked production entry.
"""

import multiprocessing as mp
import os
import sys
import warnings

warnings.filterwarnings("ignore")

# This script is copied to /usr/local/bin in the local comms image. Prepending
# /edge_node preserves the import surface that production gets by executing
# /edge_node/device.py, including local-only testbed plugins under plugins/.
EDGE_NODE_ROOT = "/edge_node"
if EDGE_NODE_ROOT not in sys.path:
  sys.path.insert(0, EDGE_NODE_ROOT)

from naeural_core import constants as ct


def _env_flag(name, default=False):
  value = os.environ.get(name)
  if value is None:
    return default
  return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
  try:
    return int(os.environ.get(name, default))
  except Exception:
    return default


_COMMS_ADMIN_PIPELINE = {
  "NET_CONFIG_MONITOR": ct.ADMIN_PIPELINE.get("NET_CONFIG_MONITOR", {}),
  "NET_MON_01": ct.ADMIN_PIPELINE.get("NET_MON_01", {}),
  "NETMON_API_PROBE": {},
}

if _env_flag("EE_ENABLE_LOCAL_ORACLE_SYNC"):
  # OracleSync is intentionally opt-in for the comms testbed. The default
  # NetMon/QoS tests must stay isolated from blockchain/R1FS behavior, while
  # this branch allows supervisor-only containers to run local consensus.
  _COMMS_ADMIN_PIPELINE["ORACLE_SYNC_01"] = {
    **ct.ADMIN_PIPELINE.get("ORACLE_SYNC_01", {}),
    "DEBUG_SYNC": True,
    "DEBUG_SYNC_FULL": _env_flag("EE_ORACLE_SYNC_DEBUG_FULL", False),
    "USE_R1FS": False,
    "USE_R1FS_DURING_CONSENSUS": False,
    "SEND_PERIOD": _env_int("EE_ORACLE_SYNC_SEND_PERIOD", 20),
    "SEND_INTERVAL": _env_int("EE_ORACLE_SYNC_SEND_INTERVAL", 5),
    "SELF_ASSESSMENT_INTERVAL": _env_int("EE_ORACLE_SYNC_SELF_ASSESSMENT_INTERVAL", 60),
  }

# The comms testbed must not start the full edge-node admin surface. By default
# it keeps only NetMon-related plugins; OracleSync is added only by the explicit
# local consensus opt-in above.
ct.ADMIN_PIPELINE = _COMMS_ADMIN_PIPELINE
ct.ADMIN_PIPELINE_FILTER = [
  signature
  for signature in ct.ADMIN_PIPELINE_FILTER
  if signature in set(_COMMS_ADMIN_PIPELINE)
]
ct.ADMIN_PIPELINE_EXCLUSIONS = []

from naeural_core.main.entrypoint import main


if __name__ == "__main__":
  mp.set_start_method("spawn")
  exit_code, _eng = main(additional_packages=[])

  sys_exit = False
  if sys_exit:
    print("Executing sys.exit({})...".format(exit_code))
    sys.exit(exit_code)
  else:
    print("Executing os._exit({})...".format(exit_code))
    os._exit(exit_code)
