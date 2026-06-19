"""
Thin Docker isolation runner for llm_security_probe.py.

This wrapper keeps the probe implementation pure while running it in a
constrained edge-node-like container with explicit mounts and env propagation.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:
  from .llm_security_probe import (
    _raise_if_sensitive_api_url,
    _redact_target,
  )
except ImportError:
  from llm_security_probe import (
    _raise_if_sensitive_api_url,
    _redact_target,
  )


DEFAULT_IMAGE = "ratio1/base_edge_node_amd64_cpu:latest"
DEFAULT_LLAMA_CPP_PACKAGE = "llama-cpp-python"
CONTAINER_PY_DEPS_DIR = "/redmesh-py"
CONTAINER_PROBE_DIR = "/probe"
PROBE_SCRIPT = "/probe/llm_security_probe.py"


@dataclass(frozen=True)
class IsolatedProbeConfig:
  repo_root: Path
  image: str = DEFAULT_IMAGE
  cache_dir: Path | None = None
  output_dir: Path | None = None
  network: str = "none"
  memory: str = "8g"
  cpus: str = "4"
  pids_limit: int = 256
  user: str | None = None
  host_gateway: bool = False
  install_llama_cpp_python: bool = True
  llama_cpp_package: str = DEFAULT_LLAMA_CPP_PACKAGE


def _repo_root_from_here() -> Path:
  return Path(__file__).resolve().parents[4]


def _probe_file(repo_root: Path) -> Path:
  return (
    repo_root /
    "extensions/business/cybersec/red_mesh/llm_security_probe.py"
  )


def _docker_base_command(config: IsolatedProbeConfig) -> list[str]:
  cache_dir = config.cache_dir or Path(tempfile.mkdtemp(prefix="redmesh-hf-cache-"))
  output_dir = config.output_dir or Path(tempfile.mkdtemp(prefix="redmesh-probe-out-"))
  cache_dir.mkdir(parents=True, exist_ok=True)
  output_dir.mkdir(parents=True, exist_ok=True)
  runner_script = f"exec python3 {PROBE_SCRIPT} \"$@\""
  if config.install_llama_cpp_python:
    runner_script = (
      f"mkdir -p {CONTAINER_PY_DEPS_DIR}/tmp && "
      "python3 -m pip install --no-cache-dir "
      f"--target {CONTAINER_PY_DEPS_DIR} "
      "cmake ninja && "
      f"TMPDIR={CONTAINER_PY_DEPS_DIR}/tmp "
      f"PATH={CONTAINER_PY_DEPS_DIR}/bin:${{PATH:-}} "
      f"PYTHONPATH={CONTAINER_PY_DEPS_DIR}:${{PYTHONPATH:-}} "
      "python3 -m pip install --no-cache-dir "
      f"--target {CONTAINER_PY_DEPS_DIR} "
      f"{config.llama_cpp_package} && "
      f"PATH={CONTAINER_PY_DEPS_DIR}/bin:${{PATH:-}} "
      f"PYTHONPATH={CONTAINER_PY_DEPS_DIR}:${{PYTHONPATH:-}} {runner_script}"
    )
  return [
    "docker",
    "run",
    "--rm",
    "--network",
    config.network,
    *(
      ["--add-host", "host.docker.internal:host-gateway"]
      if config.host_gateway else []
    ),
    "--memory",
    config.memory,
    "--cpus",
    config.cpus,
    "--pids-limit",
    str(config.pids_limit),
    "--read-only",
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=1g",
    "--tmpfs",
    f"{CONTAINER_PY_DEPS_DIR}:rw,exec,nosuid,nodev,size=2g",
    "--user",
    config.user or f"{os.getuid()}:{os.getgid()}",
    "-e",
    "PYTHONDONTWRITEBYTECODE=1",
    "-e",
    "HF_HOME=/model-cache",
    "-e",
    "HF_HUB_CACHE=/model-cache/hub",
    "-v",
    f"{_probe_file(config.repo_root)}:{PROBE_SCRIPT}:ro",
    "-v",
    f"{cache_dir.resolve()}:/model-cache:rw",
    "-v",
    f"{output_dir.resolve()}:/probe-output:rw",
    "-w",
    CONTAINER_PROBE_DIR,
    "--entrypoint",
    "bash",
    config.image,
    "-lc",
    runner_script,
    "redmesh-probe",
  ]


def build_probe_command(config: IsolatedProbeConfig, probe_args: list[str],
                        env_names: tuple[str, ...] = ()) -> list[str]:
  if "api" in probe_args:
    api_index = probe_args.index("api")
    if len(probe_args) > api_index + 1:
      _raise_if_sensitive_api_url(probe_args[api_index + 1])
  command = _docker_base_command(config)
  env_flags = []
  for name in env_names:
    if name and os.environ.get(name) is not None:
      env_flags.extend(["-e", name])
  insert_at = command.index("--entrypoint") + 2
  return command[:insert_at] + env_flags + command[insert_at:] + probe_args


def _redact_command_for_display(command: list[str]) -> list[str]:
  return [
    _redact_target(item) if item.startswith(("http://", "https://")) else item
    for item in command
  ]


def run_isolated_probe(config: IsolatedProbeConfig, probe_args: list[str],
                       env_names: tuple[str, ...] = (),
                       dry_run: bool = False) -> subprocess.CompletedProcess:
  command = build_probe_command(config, probe_args, env_names=env_names)
  if dry_run:
    print(" ".join(_redact_command_for_display(command)))
    return subprocess.CompletedProcess(command, 0)
  return subprocess.run(command, check=False)


def _base_probe_args(output_file: str | None, command: str,
                     target: str) -> tuple[list[str], list[str]]:
  probe_args = []
  if output_file:
    probe_args.extend(["--output-file", output_file])
  probe_args.extend([command, target])
  return probe_args, []


def _require_env(parser: argparse.ArgumentParser, env_name: str) -> None:
  if not os.environ.get(env_name):
    parser.error(f"environment variable {env_name!r} is not set")


def _forward_env_arg(parser: argparse.ArgumentParser, probe_args: list[str],
                     env_names: list[str], flag: str, env_name: str | None) -> None:
  if not env_name:
    return
  _require_env(parser, env_name)
  probe_args.extend([flag, env_name])
  env_names.append(env_name)


def _append_probe_arg(probe_args: list[str], flag: str,
                      value: object | None) -> None:
  if value is not None and value != "":
    probe_args.extend([flag, str(value)])


def _main(argv=None) -> int:
  parser = argparse.ArgumentParser(
    description="Run RedMesh LLM security probes inside an isolated container."
  )
  parser.add_argument("--image", default=DEFAULT_IMAGE)
  parser.add_argument("--repo-root", default=str(_repo_root_from_here()))
  parser.add_argument("--cache-dir", default=None)
  parser.add_argument("--output-dir", default=None)
  parser.add_argument("--network", default="none")
  parser.add_argument("--memory", default="8g")
  parser.add_argument("--cpus", default="4")
  parser.add_argument("--pids-limit", type=int, default=256)
  parser.add_argument("--user", default=None)
  parser.add_argument("--host-gateway", action="store_true",
                      help="Expose host.docker.internal for local mock APIs")
  parser.add_argument("--skip-llama-cpp-install", action="store_true",
                      help="Do not pip-install llama-cpp-python before running")
  parser.add_argument("--llama-cpp-package", default=DEFAULT_LLAMA_CPP_PACKAGE)
  parser.add_argument("--dry-run", action="store_true")
  parser.add_argument("--output-file", default=None)

  sub = parser.add_subparsers(dest="command", required=True)
  api = sub.add_parser("api")
  api.add_argument("url")
  api.add_argument("--model", default=None)
  api.add_argument("--max-tokens", type=int, default=None)
  api.add_argument("--reasoning-effort", default=None)
  api.add_argument("--cache-file", default=None)
  api.add_argument("--auth-env", default=None)
  api.add_argument("--header-env", action="append", default=[])
  api.add_argument("--prompt-profile", default=None)

  hf = sub.add_parser("hf-gguf")
  hf.add_argument("model_identifier")
  hf.add_argument("--filename", default=None)
  hf.add_argument("--hf-token-env", default=None)
  hf.add_argument("--n-ctx", type=int, default=2048)
  hf.add_argument("--n-gpu-layers", type=int, default=0)
  hf.add_argument("--chat-format", default=None)
  hf.add_argument("--prompt-profile", default=None)
  hf.add_argument("--allow-completion-fallback", action="store_true")

  args = parser.parse_args(argv)
  config = IsolatedProbeConfig(
    repo_root=Path(args.repo_root).resolve(),
    image=args.image,
    cache_dir=Path(args.cache_dir).resolve() if args.cache_dir else None,
    output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
    network=args.network,
    memory=args.memory,
    cpus=args.cpus,
    pids_limit=args.pids_limit,
    user=args.user,
    host_gateway=args.host_gateway,
    install_llama_cpp_python=not args.skip_llama_cpp_install,
    llama_cpp_package=args.llama_cpp_package,
  )

  if args.command == "api":
    try:
      _raise_if_sensitive_api_url(args.url)
    except ValueError as exc:
      parser.error(str(exc))
    probe_args, env_names = _base_probe_args(args.output_file, "api", args.url)
    for flag, value in (
      ("--model", args.model),
      ("--max-tokens", args.max_tokens),
      ("--reasoning-effort", args.reasoning_effort),
      ("--prompt-profile", args.prompt_profile),
      ("--cache-file", args.cache_file),
    ):
      _append_probe_arg(probe_args, flag, value)
    _forward_env_arg(parser, probe_args, env_names, "--auth-env", args.auth_env)
    for header_env in args.header_env:
      _forward_env_arg(parser, probe_args, env_names, "--header-env", header_env)
  else:
    probe_args, env_names = _base_probe_args(
      args.output_file,
      "hf-gguf",
      args.model_identifier,
    )
    _append_probe_arg(probe_args, "--filename", args.filename)
    _forward_env_arg(
      parser,
      probe_args,
      env_names,
      "--hf-token-env",
      args.hf_token_env,
    )
    for flag, value in (
      ("--n-ctx", args.n_ctx),
      ("--n-gpu-layers", args.n_gpu_layers),
      ("--chat-format", args.chat_format),
      ("--prompt-profile", args.prompt_profile),
    ):
      _append_probe_arg(probe_args, flag, value)
    if args.allow_completion_fallback:
      probe_args.append("--allow-completion-fallback")

  result = run_isolated_probe(
    config,
    probe_args,
    env_names=tuple(env_names),
    dry_run=args.dry_run,
  )
  return int(result.returncode)


if __name__ == "__main__":
  raise SystemExit(_main())
