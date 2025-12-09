#!/usr/bin/env python3
"""
Benchmark llama-cpp-python under different GGML build flag configurations,
without mutating your base Docker environment.

Overview
--------
This script is designed to be run *inside a Docker container* as an ad-hoc
benchmark tool. It assumes:

  - The **base environment** (the one running this script) already has:
      * pandas
      * any other "normal" project dependencies
    but **does NOT need llama-cpp-python installed**.

  - For each build configuration, we:
      1. Create a dedicated **virtual environment** (venv) that *inherits*
         the base environment's packages via `system_site_packages=True`,
         as documented in the Python venv docs.
      2. Generate (or reuse) a **constraints file** from the base env:
           `pip freeze > base-constraints.txt`
         and install `llama-cpp-python` in the venv with:
           `--constraint base-constraints.txt`
         This ensures *no package that exists in the base env is upgraded
         or downgraded* in the venv; only new packages are allowed.
      3. Set `CMAKE_ARGS` and `FORCE_CMAKE=1` to rebuild llama-cpp-python
         with specific GGML flags, as recommended in the official docs
         (e.g. CUDA, AVX, etc.).
      4. Use the venv's Python to spawn a **worker process** that imports
         `llama_cpp`, loads models via `Llama.from_pretrained`, and runs
         `create_chat_completion` benchmarks.

  - All benchmark results (timings, tokens/sec, error info) are collected
    into a pandas DataFrame, written to CSV, and summarized on stdout.

Notes
-----
- This script intentionally never calls `pip install` into the base environment.
  All `llama-cpp-python` installs happen inside per-build venvs.
- If a given build config requires upgrading a base package (e.g. numpy) to
  satisfy its dependencies, pip will fail due to the constraints file, and
  that build is recorded as an install error instead of silently mutating
  your dependency graph.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import gc
import platform
import subprocess
import sys
import time
import venv
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd  # type: ignore


from benchmark_constants import (
  SQLScenario
)
from utils import (
  InferenceScenario, ModelConfig, BuildFlagDef, BuildConfig,
infer_native_flag_state
)
from ratio1 import Logger


# ============================================================================
# User-editable configuration
# ============================================================================

# 0. Warmup scenarios per model (to stabilize caching, JIT, etc)
WARMUP_SCENARIOS: List[InferenceScenario] = [
  InferenceScenario(
    name="warmup_short",
    messages=[
      {
        "role": "system",
        "content": "You are a marvelous patisserie chef with an attitude.",
      },
      {
        "role": "user",
        "content": "List three popular French pastries and describe why they piss you off.",
      },
    ],
    completion_kwargs={
      "max_tokens": 128,
      "temperature": 0.5,
    },
  )
]

# 1. Inference scenarios: messages + completion kwargs
INFERENCE_SCENARIOS: List[InferenceScenario] = [
  InferenceScenario(
    name="short_sql_task",
    messages=[
      {
        "role": "system",
        "content": "You are a precise SQL expert.",
      },
      {
        "role": "user",
        "content": (
          "Given table `orders(order_id, customer_id, order_date, total_amount)`, "
          "write SQL that returns the top 5 customers by total_amount."
        ),
      },
    ],
    completion_kwargs={
      "max_tokens": 128,
      "temperature": 0.0,
    },
  ),
  InferenceScenario(
    name="longer_reasoning_task",
    messages=[
      {
        "role": "system",
        "content": "You are a helpful assistant that explains your reasoning.",
      },
      {
        "role": "user",
        "content": (
          "Explain step by step how a hash join works in SQL query execution "
          "engines. Keep the explanation under 400 words."
        ),
      },
    ],
    completion_kwargs={
      "max_tokens": 256,
      "temperature": 0.2,
    },
  ),
  InferenceScenario(
    name="long_sql_task",
    messages=[
      {
        "role": "system",
        "content": SQLScenario.SQL_INSTRUCTIONS_SIMPLE
      },
      {
        "role": "user",
        "content": SQLScenario.SQL_QUERIES[0]
      }
    ],
    completion_kwargs={
      "max_tokens": 2048,
      "temperature": 0.3,
    }
  ),
]

# 2. Model configurations: HF repo + filename + Llama.from_pretrained kwargs
MODEL_CONFIGS: List[ModelConfig] = [
  # Example: your DatA-SQL model (adapt / extend as needed)
  ModelConfig(
    name="data_sql_1_5b_q4_k_m",
    repo_id="mradermacher/DatA-SQL-1.5B-i1-GGUF",
    filename="DatA-SQL-1.5B.i1-Q4_K_M.gguf",
    model_kwargs={
      "n_ctx": 4096,
      "seed": 42,
      "n_batch": 512,
      "verbose": False,
    },
  ),
  # Add more ModelConfig entries here if you want to benchmark multiple models.
  ModelConfig(
    name="qwen3_4b_sql_writer_q8_0",
    repo_id="mradermacher/Qwen3-4B-SQL-Writer-GGUF",
    filename="Qwen3-4B-SQL-Writer.Q8_0.gguf",
    model_kwargs={
      "n_ctx": 4096,
      "seed": 42,
      "n_batch": 512,
      "verbose": False,
    },
  ),
  ModelConfig(
    name="meta_llama_3_1_8b_instruct_q4_k_m",
    repo_id="joshnader/Meta-Llama-3.1-8B-Instruct-Q4_K_M-GGUF",
    filename="meta-llama-3.1-8b-instruct-q4_k_m.gguf",
    model_kwargs={
      "n_ctx": 4096,
      "seed": 42,
      "n_batch": 512,
      "verbose": False,
    },
  ),

]

# 3. Build-relevant GGML flags (CPU-focused) and their possible values.
#    These correspond to the main CPU toggles in llama.cpp/ggml's CMake options.
#    NOTE: Leaving all at ["ON", "OFF"] gives 2^6 = 64 build configs.
#    Start with fewer flags or fewer values if that's too heavy.
ONLY_ON = ["ON"]
ONLY_OFF = ["OFF"]
BOTH = ["OFF", "ON"]
BOTH = ONLY_ON
# See also FLAG_DEPENDENCIES above for inter-flag rules.
BUILD_FLAG_DEFS: List[BuildFlagDef] = [
  BuildFlagDef("GGML_NATIVE", BOTH),
  BuildFlagDef("GGML_AVX", BOTH),
  BuildFlagDef("GGML_AVX2", BOTH),
  BuildFlagDef("GGML_AVX512", BOTH),
  BuildFlagDef("GGML_F16C", BOTH),
  BuildFlagDef("GGML_FMA", BOTH),
]

# How many times to repeat each scenario per build+model
DEFAULT_REPEATS: int = 1

# Default paths
DEFAULT_OUTPUT_CSV = "llama_cpp_bench_results.csv"
DEFAULT_TMP_DIR = "llama_cpp_bench_tmp"
DEFAULT_VENVS_DIR = ".llama_cpp_bench_venvs"
DEFAULT_CONSTRAINTS_FILE = ".llama_cpp_base_constraints.txt"
DEFAULT_CACHE_DIR = '_models'


# ============================================================================
# Utility helpers
# ============================================================================


def save_build_mapping(log: Logger, build_configs: List[BuildConfig], path: Path) -> None:
  """
  Save a table mapping build_name to its flag configuration.

  Parameters
  ----------
  build_configs:
      List of BuildConfig objects.
  path:
      CSV path to write the mapping.
  """
  rows = []
  for cfg in build_configs:
    row = {"build_name": cfg.name}
    row.update(cfg.flags)
    rows.append(row)

  df = pd.DataFrame(rows)
  df.to_csv(path, index=False)
  log.P(f"[mapping] Saved build configuration mapping to: {path}")
  return


def generate_build_configs(
    flag_defs: List[BuildFlagDef],
) -> List[BuildConfig]:
  """
  Generate all combinations of build flags as BuildConfig objects.

  This performs a full Cartesian product over each flag's `values`.
  Instead of using a long, descriptive name, we assign a short ID
  like 'b001', 'b002', ... and keep the full flag configuration in
  the BuildConfig.flags dict (and later in the results CSV).

  Parameters
  ----------
  flag_defs:
      List of BuildFlagDef definitions.

  Returns
  -------
  List[BuildConfig]
      All possible build configurations.
  """
  flag_names = [f.name for f in flag_defs]
  value_lists = [f.values for f in flag_defs]

  build_configs: List[BuildConfig] = []
  native_config_found = False

  native_flags = infer_native_flag_state(flag_names)

  for idx, values in enumerate(itertools.product(*value_lists), start=1):
    flags = dict(zip(flag_names, values))
    short_id = f"b{idx:03d}"  # e.g. b001, b002, ...
    # Check if this is the "native" config (GGML_NATIVE=ON)
    is_native = flags.get("GGML_NATIVE") == "ON"
    if is_native:
      # No need to have multiple native configs; only keep the first one
      if native_config_found:
        continue
      native_config_found = True
      short_id = f"{short_id}_native"
      # Override CPU-ish flags with the *real* native state if available
      # (we only touch flags covered by CPUINFO_FLAG_MAP; others stay as generated)
      for name, value in native_flags.items():
        if name in flags:
          flags[name] = value
      # endfor native flags
    # endif native
    build_config = BuildConfig(name=short_id, flags=flags)

    if is_native or build_config.is_valid():
      build_configs.append(build_config)
    # endif valid
  # endfor product

  return build_configs


def collect_system_info() -> Dict[str, Any]:
  """
  Collect basic system info used for later analysis.

  Returns
  -------
  dict
      Basic info such as Python version, OS, machine, and CPU count.
  """
  return {
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "processor": platform.processor(),
    "cpu_count": os.cpu_count(),
  }


def current_script_path() -> Path:
  """
  Resolve the path to this script.

  Returns
  -------
  Path
      Absolute path to the current script file.
  """
  if "__file__" in globals():
    return Path(__file__).resolve()
  return Path(sys.argv[0]).resolve()


def venv_python_path(venv_dir: Path) -> Path:
  """
  Return the path to the Python executable inside a venv.

  This is robust to environments where only `python3` exists (no `python`),
  by checking multiple candidate names.

  Parameters
  ----------
  venv_dir:
      Path to the venv directory.

  Returns
  -------
  Path
      Path to the Python executable inside the venv.

  Raises
  ------
  RuntimeError
      If no suitable Python executable is found in the venv.
  """
  if os.name == "nt":
    subdir = "Scripts"
    candidates = ["python.exe", "python3.exe"]
  else:
    subdir = "bin"
    candidates = ["python", "python3"]

  for name in candidates:
    path = venv_dir / subdir / name
    if path.exists():
      return path

  raise RuntimeError(
    f"Could not find a Python executable in venv {venv_dir} "
    f"(tried {', '.join(candidates)} in {subdir}/)"
  )


def ensure_pip_in_venv(log: Logger, venv_dir: Path) -> None:
  """
  Ensure that `pip` is available inside the given venv.

  If `python -m pip --version` fails, this function attempts to bootstrap
  pip by running `python -m ensurepip --upgrade` inside the venv.

  Raises
  ------
  RuntimeError
      If pip cannot be bootstrapped.
  """
  python_bin = venv_python_path(venv_dir)

  # Check if pip is already available
  check = subprocess.run(
    [str(python_bin), "-m", "pip", "--version"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )
  if check.returncode == 0:
    return  # pip already available

  log.P(f"[venv] pip not found in {venv_dir}, bootstrapping via ensurepip...")

  bootstrap = subprocess.run(
    [str(python_bin), "-m", "ensurepip", "--upgrade"]
  )
  if bootstrap.returncode != 0:
    raise RuntimeError(
      f"Failed to bootstrap pip in venv {venv_dir} "
      f"(exit code {bootstrap.returncode})"
    )
  return


def ensure_venv_for_build(log: Logger, build_name: str, base_dir: Path) -> Path:
  """
  Create (or reuse) a virtual environment for a given build config.

  The venv uses `system_site_packages=True` so it can see the base env's
  site-packages (as described in the venv docs).

  Parameters
  ----------
  log : Logger
    Logging object.
  build_name:
    Name of the build config (used to derive venv path).
  base_dir:
    Base directory under which venvs are stored.

  Returns
  -------
  Path
      Path to the venv directory.
  """
  venv_dir = base_dir / f"venv_{build_name}"
  if not venv_dir.exists():
    log.P(f"[venv] Creating venv for build {build_name} at {venv_dir}")
    builder = venv.EnvBuilder(with_pip=True, system_site_packages=True)
    builder.create(venv_dir)
  else:
    log.P(f"[venv] Reusing existing venv for build {build_name} at {venv_dir}")

  ensure_pip_in_venv(log=log, venv_dir=venv_dir)
  return venv_dir


def generate_base_constraints(log: Logger, constraints_path: Path) -> None:
  """
  Generate a constraints file from the current (base) environment.

  This runs `pip freeze` in the base environment and writes its output
  to `constraints_path`. The file can then be used with pip's
  `--constraint` flag to ensure that any packages which *already exist*
  in the base env are pinned to those versions.

  Parameters
  ----------
  log : Logger
    Logger to use.
  constraints_path:
    Path to the constraints file to create or overwrite.
  """
  log.P(f"[constraints] Generating base constraints at {constraints_path}")
  result = subprocess.run(
    [sys.executable, "-m", "pip", "freeze"],
    check=True,
    capture_output=True,
    text=True,
  )
  constraints_path.write_text(result.stdout)
  return


def build_config_from_env() -> BuildConfig:
  """
  Reconstruct BuildConfig from BENCH_BUILD_CONFIG_JSON env variable.

  Returns
  -------
  BuildConfig

  Raises
  ------
  RuntimeError
      If BENCH_BUILD_CONFIG_JSON is missing or invalid.
  """
  raw = os.environ.get("BENCH_BUILD_CONFIG_JSON")
  if not raw:
    raise RuntimeError("BENCH_BUILD_CONFIG_JSON not set for worker process")

  data = json.loads(raw)
  return BuildConfig(name=data["name"], flags=data["flags"])


# ============================================================================
# Worker mode: run benchmarks for a *single* build config
# ============================================================================


def run_worker(
    results_path: Path,
    repeats: int,
    warmups: int = 0,
    log_prefix: str = "",
    cache_dir: str = DEFAULT_CACHE_DIR,
) -> None:
  """
  Worker entry point: run all (model, scenario) benchmarks for a single build.

  The build configuration is passed via the BENCH_BUILD_CONFIG_JSON env var.
  This function is intended to be executed in a subprocess whose Python
  interpreter comes from the build-specific venv.

  Parameters
  ----------
  results_path:
      Path where the worker should write its JSON results.
  repeats:
      Number of times to repeat each scenario per model.
  warmups:
      Number of warmup runs per scenario per model before timing.
  log_prefix:
      Optional prefix to add to all log messages (e.g. "[worker]").
  cache_dir:
      Path to the directory where downloaded models are stored.
  """
  from llama_cpp import Llama  # imported only in worker mode
  import llama_cpp  # to read __version__
  log = Logger(
    lib_name='TEST_WORKER',
    base_folder='.',
    app_folder='_local_cache',
    max_lines=3000
  )

  build = build_config_from_env()
  system_info = collect_system_info()
  system_info["llama_cpp_python_version"] = getattr(
    llama_cpp, "__version__", "unknown"
  )

  rows: List[Dict[str, Any]] = []

  for model_cfg in MODEL_CONFIGS:
    # Load model once per build+model
    try:
      llm = Llama.from_pretrained(
        repo_id=model_cfg.repo_id,
        filename=model_cfg.filename,
        cache_dir=cache_dir,
        **model_cfg.model_kwargs,
      )
    except BaseException as exc:  # noqa: BLE001
      for scenario in INFERENCE_SCENARIOS:
        rows.append(
          _make_error_row(
            build=build,
            model=model_cfg,
            scenario=scenario,
            system_info=system_info,
            stage="load_model",
            exc=exc,
          )
        )
      # Skip inference for this model
      continue

    # WARMUP RUNS (if any)
    if warmups > 0:
      log.P(f"{log_prefix} Warmup: {warmups} runs per scenario for model {model_cfg.name}")
    for _ in range(warmups):
      for scenario in WARMUP_SCENARIOS:
        try:
          llm.create_chat_completion(
            messages=scenario.messages,
            **scenario.completion_kwargs,
          )
        except BaseException:
          pass  # ignore errors during warmup
    # endfor warmups

    # TIMED RUNS
    log.P(f"{log_prefix} Benchmarking: {model_cfg.name} under build {build.name} with {repeats} repeats of {len(INFERENCE_SCENARIOS)} scenarios")
    for scenario in INFERENCE_SCENARIOS:
      for run_idx in range(repeats):
        try:
          start = time.perf_counter()
          resp = llm.create_chat_completion(
            messages=scenario.messages,
            **scenario.completion_kwargs,
          )
          elapsed = time.perf_counter() - start
        except BaseException as exc:  # noqa: BLE001
          rows.append(
            _make_error_row(
              build=build,
              model=model_cfg,
              scenario=scenario,
              system_info=system_info,
              stage="inference",
              exc=exc,
            )
          )
          continue

        usage = resp.get("usage") or {}
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")

        tokens_per_second: Optional[float] = None
        if completion_tokens and elapsed > 0:
          tokens_per_second = completion_tokens / elapsed
        elif total_tokens and elapsed > 0:
          tokens_per_second = total_tokens / elapsed

        row: Dict[str, Any] = {
          "timestamp": time.time(),
          "build_name": build.name,
          "model_name": model_cfg.name,
          "scenario_name": scenario.name,
          "run_idx": run_idx,
          "status": "ok",
          "stage": "inference",
          "elapsed_s": elapsed,
          "prompt_tokens": prompt_tokens,
          "completion_tokens": completion_tokens,
          "total_tokens": total_tokens,
          "tokens_per_second": tokens_per_second,
          "error_type": None,
          "error_message": None,
          **{f"flag_{k}": v for k, v in build.flags.items()},
          **{f"system_{k}": v for k, v in system_info.items()},
        }
        rows.append(row)
      # endfor repeats
    # endfor scenarios
    # Free up memory before next model
    del llm  # free model memory
    gc.collect()
  # endfor models

  results_path.write_text(json.dumps({"rows": rows}, indent=2))
  return


# ============================================================================
# Controller mode: orchestrate venvs + installs + worker runs
# ============================================================================


def install_llama_cpp_for_build(
    log: Logger,
    build: BuildConfig,
    venv_dir: Path,
    constraints_path: Path,
) -> bool:
  """
  Install (or rebuild) llama-cpp-python inside the given venv for this build.

  The installation is constrained by `constraints_path` so that no package
  that exists in the base environment can be upgraded/downgraded in this
  venv. New dependencies are allowed to be installed freely.

  CMake flags are passed via the `CMAKE_ARGS` environment variable, and
  `FORCE_CMAKE=1` forces a source build even if a wheel is available, as
  documented in llama-cpp-python's README.

  Parameters
  ----------
  log: Logger
    Object for logging.
  build: BuildConfig
    Build configuration whose flags should be used.
  venv_dir: Path
    Path to the venv where llama-cpp-python should be installed.
  constraints_path: Path
    Path to the constraints file generated from the base environment.

  Returns
  -------
  bool
    True if installation succeeded, False otherwise.
  """
  env = os.environ.copy()
  env["CMAKE_ARGS"] = build.to_cmake_args()
  env["FORCE_CMAKE"] = "1"

  python_bin = venv_python_path(venv_dir)

  cmd = [
    str(python_bin),
    "-m",
    "pip",
    "install",
    "--upgrade",
    "--force-reinstall",
    "--no-cache-dir",
    "llama-cpp-python",
    "--constraint",
    str(constraints_path),
  ]

  log_msg = "\n" + "=" * 80
  log_msg += f"\n[install] Building llama-cpp-python for config: {build.name}"
  log_msg += f"\n[install] CMAKE_ARGS={env['CMAKE_ARGS']}"
  log_msg += f"\n[install] Using venv: {venv_dir}"
  log_msg += f"\n[install] Using constraints: {constraints_path}\n"
  log_msg += "=" * 80
  log.P(log_msg)

  result = subprocess.run(cmd, env=env)
  success = result.returncode == 0

  if not success:
    log.P(
      f"[install] ERROR: pip install failed for build config {build.name} "
      f"(exit code {result.returncode})",
      file=sys.stderr,
    )

  return success


def summarize_results(log: Logger, df: pd.DataFrame) -> None:
  """
  Print a human-readable summary of the benchmark results.

  The summary focuses on:
    - Core production metrics per build:
      * success_rate (reliability)
      * median_tps (throughput)
      * p95_latency_s (tail end-to-end latency)
    - Tokens/sec per build configuration (aggregated).
    - Best build per (model, scenario).
    - A table of each build (venv) configuration.
    - An error summary if there were failures.

  Parameters
  ----------
  df:
      DataFrame containing both success and error rows.
  """
  if df.empty:
    log.P("No rows recorded (everything failed?).", color='r')
    return

  success_df = df[df["status"] == "ok"].copy()
  error_df = df[df["status"] != "ok"].copy()

  def _print_flag_table() -> None:
    flag_cols = [c for c in df.columns if c.startswith("flag_")]
    if not flag_cols:
      log.P("(No flag_* columns found; cannot display venv configurations.)")
      return
    cfg_df = (
      df[["build_name"] + flag_cols]
      .drop_duplicates()
      .sort_values("build_name")
      .reset_index(drop=True)
    )
    log_msg = "Build / venv configurations (one row per build_name):\n"
    log_msg += cfg_df.to_string(index=False)
    log.P(log_msg)

  def _print_core_metrics() -> None:
    log.P("Core production metrics per build (success_rate, median_tps, p95_latency_s):")
    success_rate = (
      df.groupby("build_name")["status"]
      .apply(lambda s: (s == "ok").mean())
      .rename("success_rate")
    )
    if success_df.empty:
      metrics_df = success_rate.to_frame().sort_values("success_rate", ascending=False)
    else:
      median_tps = (
        success_df.groupby("build_name")["tokens_per_second"]
        .median()
        .rename("median_tps")
      )
      p95_latency = (
        success_df.groupby("build_name")["elapsed_s"]
        .quantile(0.95)
        .rename("p95_latency_s")
      )
      metrics_df = (
        pd.concat([success_rate, median_tps, p95_latency], axis=1)
        .sort_values("median_tps", ascending=False, na_position="last")
      )
    log.P(metrics_df.to_string(float_format=lambda x: f"{x:.4f}" if isinstance(x, float) else str(x)))

  def _print_performance() -> None:
    if success_df.empty:
      log.P("No successful runs (all rows are errors).")
      return
    agg = (
      success_df.groupby("build_name")["tokens_per_second"]
      .agg(["count", "mean", "std", "min", "max"])
      .sort_values("mean", ascending=False)
    )
    log_msg = "Tokens/sec by build configuration (across models & scenarios):\n"
    log_msg += agg.to_string(float_format=lambda x: f"{x:.2f}" if isinstance(x, float) else str(x))
    log.P(log_msg)

    group_cols = ["model_name", "scenario_name", "build_name"]
    agg_detail = (
      success_df.groupby(group_cols)["tokens_per_second"]
      .mean()
      .reset_index()
    )
    best_rows = (
      agg_detail.sort_values("tokens_per_second", ascending=False)
      .groupby(["model_name", "scenario_name"])
      .head(1)
    )
    log_msg = "Best build per (model, scenario) by mean tokens/sec (higher is better):\n"
    log_msg += best_rows.to_string(index=False, float_format=lambda x: f"{x:.2f}" if isinstance(x, float) else str(x))
    log.P(log_msg)

  def _print_errors() -> None:
    if error_df.empty:
      return
    err_agg = (
      error_df.groupby(["build_name", "stage", "error_type"])
      .size()
      .rename("count")
      .reset_index()
      .sort_values("count", ascending=False)
    )
    err_msg = "Error summary by (build_name, stage, error_type):\n"
    err_msg += err_agg.to_string(index=False)
    log.P(err_msg)

  log.P("=== High-level summary ===")
  _print_flag_table()
  _print_core_metrics()
  _print_performance()
  _print_errors()
  log.P(f"=== Detailed results ===")
  show_detail_results(log=log, df=df)
  return


def show_detail_results(log: Logger, df: pd.DataFrame) -> None:
  """
  Provide scenario-level analysis and an overall build score.

  The scoring system weights reliability most heavily, followed by
  throughput and then latency:
    score = 0.50 * success_rate
          + 0.35 * throughput_norm (vs best in scenario)
          + 0.15 * latency_norm    (best_latency / this_latency)
    success_rate = (number of successful tests) / (total number of tests)
    throughput_norm = normalization of tps(token per second) - best tps will get 1 and
    the other ones will be scaled accordingly
    latency = elapsed time for one inference
  """
  if df.empty:
    log.P("No rows recorded; skipping detailed analysis.")
    return

  scenario_df = df.dropna(subset=["model_name", "scenario_name"]).copy()
  if scenario_df.empty:
    log.P("No model/scenario rows found; skipping detailed analysis.")
    return

  success_df = scenario_df[scenario_df["status"] == "ok"].copy()
  group_keys = ["build_name", "model_name", "scenario_name"]

  def norm_direct(val: Optional[float], best: Optional[float]) -> float:
    if pd.isna(val) or pd.isna(best) or not best or best <= 0:
      return 0.0
    return min(val / best, 1.0)

  def norm_inverse(val: Optional[float], best: Optional[float]) -> float:
    if pd.isna(val) or pd.isna(best) or not val or val <= 0:
      return 0.0
    return min(best / val, 1.0)

  def p95(series: pd.Series) -> Optional[float]:
    return None if series.empty else float(series.quantile(0.95))

  base = (
    scenario_df.groupby(group_keys)["status"]
    .agg(attempts="size", success_count=lambda s: int((s == "ok").sum()))
    .reset_index()
  )
  base["success_rate"] = base["success_count"] / base["attempts"]

  perf = pd.DataFrame(columns=group_keys + ["mean_tps", "median_latency_s", "p95_latency_s"])
  if not success_df.empty:
    perf = (
      success_df.groupby(group_keys)
      .agg(
        mean_tps=("tokens_per_second", "mean"),
        median_latency_s=("elapsed_s", "median"),
        p95_latency_s=("elapsed_s", p95),
      )
      .reset_index()
    )

  metrics = base.merge(perf, on=group_keys, how="left")
  metrics["best_tps_in_scenario"] = metrics.groupby(["model_name", "scenario_name"])["mean_tps"].transform("max")
  metrics["best_latency_in_scenario"] = metrics.groupby(["model_name", "scenario_name"])["median_latency_s"].transform("min")
  metrics["scenario_key"] = metrics["model_name"].astype(str) + "::" + metrics["scenario_name"].astype(str)
  metrics["throughput_norm"] = metrics.apply(lambda r: norm_direct(r.mean_tps, r.best_tps_in_scenario), axis=1)
  metrics["latency_norm"] = metrics.apply(lambda r: norm_inverse(r.median_latency_s, r.best_latency_in_scenario), axis=1)

  w_rel, w_tps, w_lat = 0.50, 0.35, 0.15
  metrics["score"] = (
    w_rel * metrics["success_rate"].fillna(0.0)
    + w_tps * metrics["throughput_norm"].fillna(0.0)
    + w_lat * metrics["latency_norm"].fillna(0.0)
  )

  log_msg = "=== Detailed scenario analysis ==="
  log_msg += "\nScoring weights -> reliability: 0.50, throughput: 0.35, latency: 0.15"
  log.P(log_msg)

  cols = [
    "build_name",
    "attempts",
    "success_rate",
    "mean_tps",
    "median_latency_s",
    "throughput_norm",
    "latency_norm",
    "score",
  ]

  for model_name, scenario_name in (
    metrics[["model_name", "scenario_name"]]
    .drop_duplicates()
    .sort_values(["model_name", "scenario_name"])
    .itertuples(index=False, name=None)
  ):
    rows = metrics[(metrics["model_name"] == model_name) & (metrics["scenario_name"] == scenario_name)]
    if rows.empty:
      continue
    rows = rows.sort_values(["score", "success_rate", "mean_tps"], ascending=False).head(5)
    log_msg = f"Scenario: model={model_name}, case={scenario_name}\n"
    log_msg += rows[cols].to_string(index=False, float_format=lambda x: f"{x:.4f}" if isinstance(x, float) else str(x))
    log.P(log_msg)

  total_scenarios = scenario_df[["model_name", "scenario_name"]].drop_duplicates().shape[0]
  leaderboard = (
    metrics.groupby("build_name")
    .agg(
      total_score=("score", "sum"),
      avg_score=("score", "mean"),
      mean_success_rate=("success_rate", "mean"),
      mean_throughput_norm=("throughput_norm", "mean"),
      mean_latency_norm=("latency_norm", "mean"),
      covered_scenarios=("scenario_key", "nunique"),
    )
    .reset_index()
  )
  leaderboard["scenario_coverage"] = leaderboard["covered_scenarios"] / total_scenarios if total_scenarios else 0.0
  leaderboard = leaderboard.sort_values(["total_score", "avg_score", "mean_success_rate"], ascending=False)

  log_msg = "Overall build leaderboard (higher is better):\n"
  log_msg += leaderboard.to_string(index=False, float_format=lambda x: f"{x:.4f}" if isinstance(x, float) else str(x))
  log.P(log_msg)

  if not leaderboard.empty:
    best = leaderboard.iloc[0]
    log.P(
      f"Best overall build: {best['build_name']} "
      f"(total_score={best['total_score']:.4f}, avg_score={best['avg_score']:.4f}, "
      f"coverage={best['scenario_coverage']:.2f})"
    )
  return


def controller_main(
    output_csv: str,
    tmp_dir: str,
    venvs_dir: str,
    constraints_file: str,
    repeats: int,
    flag_defs: List[BuildFlagDef],
) -> None:
  """
  Controller entry point.

  For each build config:
    1. Create (or reuse) a venv that inherits base site-packages.
    2. Install llama-cpp-python into that venv using GGML flags and
       a constraints file derived from the base env.
    3. Spawn a worker subprocess (using the venv's Python) to run all
       model+scenario benchmarks.
    4. Collect worker results and merge into a single DataFrame.
    5. Save the DataFrame to CSV and print a summary.

  Parameters
  ----------
  output_csv:
      Path to the CSV file to write.
  tmp_dir:
      Directory to store intermediate JSON result files.
  venvs_dir:
      Directory under which per-build venvs will be created.
  constraints_file:
      Path to the base constraints file (pip freeze output).
  repeats:
      Number of repeated runs per (build, model, scenario).
  flag_defs:
      List of BuildFlagDef defining the search space for builds.
  """
  run_ts = time.strftime("%Y%m%d_%H%M%S")
  run_root = Path(tmp_dir).resolve() / run_ts
  run_root.mkdir(parents=True, exist_ok=True)
  log = Logger(
    lib_name='TEST_LLAMA_CPP',
    base_folder='.',
    app_folder='_local_cache',
    max_lines=3000
  )
  log.P(f"[controller] Using run directory: {run_root}")

  output_path = run_root / Path(output_csv).name

  build_configs = generate_build_configs(flag_defs)
  log.P(f"[controller] Generated {len(build_configs)} valid build configurations.")

  # .resolve() to get absolute path for saving mapping
  mapping_path = (output_path.parent / "llama_cpp_build_mapping.csv").resolve()
  save_build_mapping(log=log, build_configs=build_configs, path=mapping_path)

  all_rows: List[Dict[str, Any]] = []
  sys_info = collect_system_info()

  tmp_dir_path = run_root
  tmp_dir_path.mkdir(parents=True, exist_ok=True)

  venvs_dir_path = Path(venvs_dir).resolve()
  venvs_dir_path.mkdir(parents=True, exist_ok=True)

  constraints_path = Path(constraints_file).resolve()
  if not constraints_path.exists():
    generate_base_constraints(log=log, constraints_path=constraints_path)
  else:
    log.P(f"[constraints] Reusing existing constraints file at {constraints_path}")

  script_path = current_script_path()
  n_builds = len(build_configs)

  for build_idx, build in enumerate(build_configs):
    venv_dir = ensure_venv_for_build(log=log, build_name=build.name, base_dir=venvs_dir_path)
    log_idx_prefix = f"[worker][{build_idx + 1}/{n_builds}]"

    # 1. Install / rebuild llama-cpp-python for this build in its venv
    if not install_llama_cpp_for_build(log=log, build=build, venv_dir=venv_dir, constraints_path=constraints_path):
      for model_cfg in MODEL_CONFIGS:
        for scenario in INFERENCE_SCENARIOS:
          all_rows.append(
            {
              "timestamp": time.time(),
              "build_name": build.name,
              "model_name": model_cfg.name,
              "scenario_name": scenario.name,
              "run_idx": 0,
              "status": "install_error",
              "stage": "install",
              "elapsed_s": None,
              "prompt_tokens": None,
              "completion_tokens": None,
              "total_tokens": None,
              "tokens_per_second": None,
              "error_type": "InstallError",
              "error_message": (
                f"pip install failed for build {build.name}"
              ),
              **{f"flag_{k}": v for k, v in build.flags.items()},
              **{f"system_{k}": v for k, v in sys_info.items()},
            }
          )
      continue

    # 2. Spawn worker subprocess for this build
    result_path = tmp_dir_path / f"bench_results_{build.name}.json"
    if result_path.exists():
      result_path.unlink()

    worker_env = os.environ.copy()
    # Avoid accidentally re-triggering rebuilds in the worker:
    worker_env.pop("CMAKE_ARGS", None)
    worker_env.pop("FORCE_CMAKE", None)
    worker_env["BENCH_BUILD_CONFIG_JSON"] = json.dumps(
      {"name": build.name, "flags": build.flags}
    )

    python_bin = venv_python_path(venv_dir)
    cmd = [
      str(python_bin),
      str(script_path),
      "--worker",
      "--results-path",
      str(result_path),
      "--repeats",
      str(repeats),
      "--log-prefix",
      log_idx_prefix,
    ]

    log_msg = "\n" + "-" * 80
    log_msg += f"\n{log_idx_prefix} Running benchmarks for build config: {build.name}\n"
    log_msg += "-" * 80
    log.P(log_msg)

    worker_proc = subprocess.run(cmd, env=worker_env)
    if worker_proc.returncode != 0:
      log.P(
        f"{log_idx_prefix} ERROR: Worker failed for build {build.name} "
        f"(exit code {worker_proc.returncode})",
        color='r'
      )
      for model_cfg in MODEL_CONFIGS:
        for scenario in INFERENCE_SCENARIOS:
          all_rows.append(
            {
              "timestamp": time.time(),
              "build_name": build.name,
              "model_name": model_cfg.name,
              "scenario_name": scenario.name,
              "run_idx": 0,
              "status": "worker_error",
              "stage": "worker",
              "elapsed_s": None,
              "prompt_tokens": None,
              "completion_tokens": None,
              "total_tokens": None,
              "tokens_per_second": None,
              "error_type": "WorkerError",
              "error_message": (
                f"Worker subprocess failed for build {build.name}"
              ),
              **{f"flag_{k}": v for k, v in build.flags.items()},
              **{f"system_{k}": v for k, v in sys_info.items()},
            }
          )
      continue

    if not result_path.exists():
      log.P(
        f"{log_idx_prefix} WARNING: Result file {result_path} not found for build "
        f"{build.name}",
        color='r'
      )
      continue

    data = json.loads(result_path.read_text())
    rows = data.get("rows", [])
    all_rows.extend(rows)

  df = pd.DataFrame(all_rows)
  csv_path = output_path
  df.to_csv(csv_path, index=False)
  log.P(f"Saved raw benchmark results to: {csv_path}")

  summarize_results(log=log, df=df)
  return


# ============================================================================
# CLI entry point
# ============================================================================


def parse_args() -> argparse.Namespace:
  """
  Parse command-line arguments for controller / worker modes.

  Returns
  -------
  argparse.Namespace
      Parsed arguments.
  """
  parser = argparse.ArgumentParser(
    description=(
      "Benchmark llama-cpp-python under different GGML CPU flags using "
      "per-build virtual environments and a constraints file derived "
      "from the base Docker environment."
    )
  )
  parser.add_argument(
    "--worker",
    action="store_true",
    help="Internal: run in worker mode (do not use directly).",
  )
  parser.add_argument(
    "--results-path",
    type=str,
    default=None,
    help="(worker mode) Path to JSON results file.",
  )
  parser.add_argument(
    "--repeats",
    type=int,
    default=DEFAULT_REPEATS,
    help="Number of repetitions per (build, model, scenario).",
  )
  parser.add_argument(
    "--output-csv",
    type=str,
    default=DEFAULT_OUTPUT_CSV,
    help="(controller mode) Path to output CSV file.",
  )
  parser.add_argument(
    "--tmp-dir",
    type=str,
    default=DEFAULT_TMP_DIR,
    help="(controller mode) Directory for intermediate JSON result files.",
  )
  parser.add_argument(
    "--venvs-dir",
    type=str,
    default=DEFAULT_VENVS_DIR,
    help="(controller mode) Directory for per-build virtual environments.",
  )
  parser.add_argument(
    "--constraints-file",
    type=str,
    default=DEFAULT_CONSTRAINTS_FILE,
    help=(
      "(controller mode) Path to constraints file derived from base env. "
      "Will be created if it does not exist."
    ),
  )
  parser.add_argument(
    "--log-prefix",
    type=str,
    default="[worker]",
    help="(worker mode) Prefix to add to log messages.",
  )
  parser.add_argument(
    "--cache_dir",
    type=str,
    default=DEFAULT_CACHE_DIR,
    help="(worker mode) Directory for downloaded models.",
  )
  return parser.parse_args()


def main() -> None:
  """
  Main entry point.

  Dispatches to either controller or worker mode based on CLI args.
  """
  args = parse_args()

  if args.worker:
    if not args.results_path:
      raise ValueError("--results-path is required in worker mode")
    run_worker(
      results_path=Path(args.results_path),
      repeats=args.repeats,
      log_prefix=args.log_prefix,
      cache_dir=args.cache_dir
    )
  else:
    controller_main(
      output_csv=args.output_csv,
      tmp_dir=args.tmp_dir,
      venvs_dir=args.venvs_dir,
      constraints_file=args.constraints_file,
      repeats=args.repeats,
      flag_defs=BUILD_FLAG_DEFS,
    )


if __name__ == "__main__":
  main()
