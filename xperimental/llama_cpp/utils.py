import traceback
import time
import os

from dataclasses import dataclass
from typing import Any, Dict, List, Set, Optional
from benchmark_constants import (
  FLAG_DEPENDENCIES,
  CPUINFO_FLAG_MAP
)


# ============================================================================
# Data classes for configuration
# ============================================================================


@dataclass
class InferenceScenario:
  """
  Description of a single chat-completion benchmark scenario.

  Attributes
  ----------
  name:
      Human-readable identifier for this scenario.
  messages:
      List of OpenAI-style chat messages passed to `create_chat_completion`.
  completion_kwargs:
      Extra keyword arguments for `create_chat_completion`
      (e.g. temperature, max_tokens, top_p, etc).
  """

  name: str
  messages: List[Dict[str, Any]]
  completion_kwargs: Dict[str, Any]


@dataclass
class ModelConfig:
  """
  Description of a model to load via llama_cpp.Llama.from_pretrained.

  Attributes
  ----------
  name:
      Human-readable identifier for this model configuration.
  repo_id:
      Hugging Face Hub repo-id containing GGUF models.
  filename:
      GGUF filename within the repo to load.
  model_kwargs:
      Extra keyword arguments passed to `Llama.from_pretrained`,
      e.g. n_ctx, n_batch, n_threads, seed, etc.
  """

  name: str
  repo_id: str
  filename: str
  model_kwargs: Dict[str, Any]


@dataclass
class BuildFlagDef:
  """
  Definition of a single GGML CMake flag and its allowed values.

  Attributes
  ----------
  name:
      CMake option name, e.g. "GGML_AVX2".
  values:
      Allowed values for the flag, almost always ["ON", "OFF"].
  """

  name: str
  values: List[str]


@dataclass
class BuildConfig:
  """
  Concrete build configuration: one value for each GGML flag.

  Attributes
  ----------
  name:
      Human-readable identifier derived from the flags.
  flags:
      Mapping from GGML flag name (e.g. "GGML_AVX2") to its value
      (e.g. "ON" or "OFF").
  """

  name: str
  flags: Dict[str, str]

  def to_cmake_args(self) -> str:
    """
    Render this build config as a CMake argument string.

    Returns
    -------
    str
        A space-separated string like "-DGGML_AVX=ON -DGGML_AVX2=ON".
    """
    parts = [f"-D{key}={value}" for key, value in self.flags.items()]
    return " ".join(parts)

  def is_valid(self) -> bool:
    """
    Check if this build configuration is valid.

    Currently, this checks for known invalid combinations of flags.
    Extend this method if you know of other invalid combinations.

    Returns
    -------
    bool
        True if the configuration is valid, False otherwise.
    """
    for (flag, dependency) in FLAG_DEPENDENCIES:
      if isinstance(dependency, str):
        dependency = [dependency]
      # endif str to list
      if self.flags.get(flag) == "ON":
        for dep in dependency:
          if self.flags.get(dep) != "ON":
            return False
        # endfor dependencies
      # endif flag ON
    # endfor dependencies
    return True
# endclass BuildConfig


# ============================================================================
# Utility helpers
# ============================================================================


def _read_cpuinfo_flags() -> Set[str]:
  """
  Read the CPU feature flags from /proc/cpuinfo (Linux).

  Returns
  -------
  Set[str]
      Set of flag tokens (e.g. {"fpu", "sse4_2", "avx", "avx2", ...}).
      If /proc/cpuinfo is not available, returns an empty set.
  """
  flags: Set[str] = set()

  # Only implemented for Linux; on other OSes we just return empty.
  cpuinfo_path = "/proc/cpuinfo"
  if not os.path.exists(cpuinfo_path):
    return flags

  try:
    with open(cpuinfo_path, "r", encoding="utf-8") as f:
      for line in f:
        # Example: "flags\t\t: fpu vme de pse tsc ... avx avx2 fma ..."
        if line.lower().startswith("flags"):
          _, value = line.split(":", 1)
          flags.update(value.strip().split())
          # One "flags" line is enough (they are repeated per core)
          break
  except OSError:
    # If anything goes wrong, fall back to an empty set
    return set()

  return flags


def infer_native_flag_state(flag_names: List[str]) -> Dict[str, str]:
  """
  Infer GGML flag values ("ON"/"OFF") for a native build from CPU features.

  This uses /proc/cpuinfo to decide which instruction-set flags should be
  ON for the *current* CPU when building with GGML_NATIVE=ON.

  Only flags present in CPUINFO_FLAG_MAP are overridden; other flags are
  left untouched.

  Parameters
  ----------
  flag_names:
      List of GGML flag names participating in the grid search.

  Returns
  -------
  Dict[str, str]
      Mapping from flag name to "ON"/"OFF" for native-mode overrides.
  """
  cpu_flags = _read_cpuinfo_flags()
  if not cpu_flags:
    # No reliable CPU info (non-Linux, restricted container, etc.).
    # In that case we don't override anything; the generated flags remain
    # as-is from the Cartesian product.
    return {}

  overrides: Dict[str, str] = {}
  for name in flag_names:
    tokens = CPUINFO_FLAG_MAP.get(name)
    if not tokens:
      continue
    # If *any* of the mapped CPU tokens is present, treat this GGML flag as ON
    has_feature = any(tok in cpu_flags for tok in tokens)
    overrides[name] = "ON" if has_feature else "OFF"

  return overrides


def _make_error_row(
    build: BuildConfig,
    model: Optional[ModelConfig],
    scenario: Optional[InferenceScenario],
    system_info: Dict[str, Any],
    stage: str,
    exc: BaseException,
) -> Dict[str, Any]:
  """
  Create a standardized error row for the results table.

  Parameters
  ----------
  build:
      Build configuration being benchmarked.
  model:
      Model configuration (if applicable / known at error time).
  scenario:
      Inference scenario (if applicable / known at error time).
  system_info:
      System info dictionary from `collect_system_info`.
  stage:
      High-level stage where the error occurred: "install", "load_model",
      "inference", etc.
  exc:
      The exception that was raised.

  Returns
  -------
  dict
      Row with error details and context.
  """
  return {
    "timestamp": time.time(),
    "build_name": build.name,
    "model_name": model.name if model else None,
    "scenario_name": scenario.name if scenario else None,
    "run_idx": 0,
    "status": "error",
    "stage": stage,
    "elapsed_s": None,
    "prompt_tokens": None,
    "completion_tokens": None,
    "total_tokens": None,
    "tokens_per_second": None,
    "error_type": type(exc).__name__,
    "error_message": "".join(
      traceback.format_exception_only(type(exc), exc)
    ).strip(),
    **{f"flag_{k}": v for k, v in build.flags.items()},
    **{f"system_{k}": v for k, v in system_info.items()},
  }


