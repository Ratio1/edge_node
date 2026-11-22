"""Prompt packs: how a model is prompted and how its reply is read, as data.

A pack is a directory holding `edgeguard-pack.json` plus the files it names
(system prompt, optional allowlist `schema.json`). The pipeline pins the
sha256 of the manifest (`PROMPT_PACK: {path, sha256}` for a local directory or
`{repo, revision, path, sha256}` for Hugging Face); the manifest pins the sha256
of every other file. Packs hold only JSON and text: nothing in them is executed.

Only what the plugin can honour is accepted. Decoding (temperature, stop,
chat-template kwargs) belongs to the worker's serving config, so a pack that
carries it is refused.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

FORMAT_VERSION = 1
MANIFEST_NAME = "edgeguard-pack.json"
PARSER_RAW_CYPHER = "raw_cypher"
PARSER_DECISION_JSON = "decision_json"
PARSERS = (PARSER_RAW_CYPHER, PARSER_DECISION_JSON)
QUERY_DECISIONS = ("answer", "partial")
DECLINE_DECISIONS = ("clarify", "out_of_scope", "refuse")
_QUERY_ROLES = {"cypher", "note"}
_MANIFEST_KEYS = {
  "format_version", "pack_id", "pack_version", "files", "system_prompt", "schema", "schema_version",
  "max_tokens", "parser", "field_map", "grounding", "prompt_contract",
}
_SERVING_KEYS = {"temperature", "top_p", "stop", "chat_format", "chat_template_kwargs", "repeat_penalty"}
_SCHEMA_KEYS = ("labels", "relationship_types", "properties")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PACK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_LOCAL_KEYS = {"path", "sha256"}
_HF_KEYS = {"repo", "revision", "path", "sha256"}
MAX_TOKENS_LIMIT = 8192
MAX_FILE_BYTES = 1024 * 1024  # a pack is a prompt and a few lists: refuse anything larger unread
_COMMIT = re.compile(r"^[0-9a-f]{40}$")

_VENDORED_DIR = Path(__file__).resolve().parent / "prompts" / "packs" / "cypher_2026_11_08"
# Released pipelines name this profile; it resolves to the pack vendored in the repo.
LEGACY_PROFILE_PACKS = {
  "decision_json_v2026_11_08": {
    "path": str(_VENDORED_DIR),
    "sha256": "9815f8ccc6eacdbac6bf7fee9517975bad621486488ca1e5e89e520a080cc30e",
  },
}


class PromptPackError(ValueError):
  """A pack that must not be served; the message names the pack and the reason."""

  def __init__(self, label: str, reason: str):
    super().__init__(f"{label}: {reason}")


@dataclass(frozen=True)
class PromptPack:
  pack_id: str
  pack_version: str
  manifest_sha256: str
  system_prompt: str
  max_tokens: int
  parser: str
  field_map: Optional[Dict[str, Dict[str, str]]]
  grounding: bool
  schema_allowed: Optional[Dict[str, set]]
  schema_version: str
  prompt_contract: str

  @property
  def template_version(self) -> str:
    return f"edgeguard-pack-{self.pack_id}-{self.pack_version}"


def _sha256(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _plain_name(label: str, name: Any) -> str:
  if not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
    raise PromptPackError(label, f"file name {name!r} must be a plain name inside the pack directory")
  return name


def _read_capped(label: str, name: str, path: Path) -> bytes:
  try:
    if path.stat().st_size > MAX_FILE_BYTES:
      raise PromptPackError(label, f"file {name!r} is larger than {MAX_FILE_BYTES} bytes")
    return path.read_bytes()
  except OSError as exc:
    raise PromptPackError(label, f"file {name!r} is unreadable ({type(exc).__name__})") from None


def _local_fetcher(label: str, root: Path) -> Callable[[str], bytes]:
  root = root.resolve()

  def fetch(name: str) -> bytes:
    path = root / _plain_name(label, name)
    if not path.is_file():
      raise PromptPackError(label, f"missing file {name!r}")
    if root not in path.resolve().parents:  # a symlink that leaves the directory
      raise PromptPackError(label, f"file {name!r} resolves outside the pack directory")
    return _read_capped(label, name, path)

  return fetch


def _hf_fetcher(label: str, source: Mapping[str, Any], token: Optional[str], download: Optional[Callable]) -> Callable[[str], bytes]:
  prefix = str(source.get("path") or "").strip("/")
  if ".." in prefix.split("/"):
    raise PromptPackError(label, "path must not contain '..'")
  if not source.get("repo") or not _COMMIT.match(str(source.get("revision") or "")):
    raise PromptPackError(label, "a Hugging Face source needs repo and a 40-hex commit revision")
  if download is None:
    try:
      from huggingface_hub import hf_hub_download as download
    except ImportError:
      raise PromptPackError(label, "huggingface_hub is not installed") from None

  def fetch(name: str) -> bytes:
    filename = f"{prefix}/{_plain_name(label, name)}" if prefix else _plain_name(label, name)
    try:
      local = download(repo_id=source["repo"], filename=filename, revision=source["revision"], token=token)
    except Exception as exc:  # the class name only: never echo a message that could carry the token
      raise PromptPackError(label, f"download of {name!r} failed ({type(exc).__name__})") from None
    return _read_capped(label, name, Path(local))

  return fetch


def _check_field_map(label: str, parser: str, field_map: Any) -> Optional[Dict[str, Dict[str, str]]]:
  if parser == PARSER_RAW_CYPHER:
    if field_map is not None:
      raise PromptPackError(label, "field_map is only for the decision_json parser")
    return None
  if not isinstance(field_map, dict):
    raise PromptPackError(label, "the decision_json parser needs a field_map")
  for decision in QUERY_DECISIONS + DECLINE_DECISIONS:
    if decision not in field_map:
      raise PromptPackError(label, f"field_map has no entry for decision {decision!r}")
  if set(field_map) - set(QUERY_DECISIONS + DECLINE_DECISIONS):
    raise PromptPackError(label, f"field_map names unknown decisions {sorted(set(field_map) - set(QUERY_DECISIONS + DECLINE_DECISIONS))}")
  for decision, roles in field_map.items():
    allowed = _QUERY_ROLES if decision in QUERY_DECISIONS else {"message"}
    required = "cypher" if decision in QUERY_DECISIONS else "message"
    valid = isinstance(roles, dict) and required in roles and set(roles) <= allowed
    if not valid or not all(isinstance(v, str) and v for v in roles.values()):
      raise PromptPackError(label, f"field_map entry for {decision!r} must map {required!r} (roles {sorted(allowed)}) to field names")
  return field_map


def load_pack(
  source: Mapping[str, Any],
  *,
  label: str,
  hf_token: Optional[str] = None,
  hf_download: Optional[Callable] = None,
) -> PromptPack:
  """Load and validate one pack; raise `PromptPackError` naming `label` and the reason."""
  if not isinstance(source, Mapping):
    raise PromptPackError(label, "PROMPT_PACK must be a mapping")
  hf = "repo" in source
  unknown = set(source) - (_HF_KEYS if hf else _LOCAL_KEYS)
  if unknown:
    raise PromptPackError(label, f"unknown PROMPT_PACK keys {sorted(unknown)}")
  pinned = source.get("sha256")
  if not isinstance(pinned, str) or not _SHA256.match(pinned):
    raise PromptPackError(label, "PROMPT_PACK needs the sha256 of the manifest")
  if hf:
    fetch = _hf_fetcher(label, source, hf_token, hf_download)
  else:
    if not source.get("path"):
      raise PromptPackError(label, "PROMPT_PACK needs a path")
    fetch = _local_fetcher(label, Path(os.path.expanduser(str(source["path"]))))

  raw = fetch(MANIFEST_NAME)
  if _sha256(raw) != pinned:
    raise PromptPackError(label, f"{MANIFEST_NAME} sha256 {_sha256(raw)} does not match the pinned {pinned}")
  try:
    manifest = json.loads(raw.decode("utf-8"))
  except ValueError:
    raise PromptPackError(label, f"{MANIFEST_NAME} is not valid JSON") from None
  if not isinstance(manifest, dict):
    raise PromptPackError(label, f"{MANIFEST_NAME} must hold one JSON object")
  for key in sorted(set(manifest) - _MANIFEST_KEYS):
    hint = "; decoding belongs to the worker serving config" if key in _SERVING_KEYS else ""
    raise PromptPackError(label, f"unknown key {key!r}{hint}")
  if manifest.get("format_version") != FORMAT_VERSION:
    raise PromptPackError(label, f"format_version must be {FORMAT_VERSION}")
  pack_id, version = manifest.get("pack_id"), manifest.get("pack_version")
  if not isinstance(pack_id, str) or not _PACK_ID.match(pack_id) or not isinstance(version, str) or not version:
    raise PromptPackError(label, "pack_id and pack_version must be non-empty strings (pack_id: letters, digits, _.-)")
  parser = manifest.get("parser")
  if parser not in PARSERS:
    raise PromptPackError(label, f"unknown parser {parser!r}; known parsers are {list(PARSERS)}")
  field_map = _check_field_map(label, parser, manifest.get("field_map"))
  max_tokens = manifest.get("max_tokens")
  if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not 0 < max_tokens <= MAX_TOKENS_LIMIT:
    raise PromptPackError(label, f"max_tokens must be an integer from 1 to {MAX_TOKENS_LIMIT}")
  grounding = manifest.get("grounding", False)
  if not isinstance(grounding, bool):
    raise PromptPackError(label, "grounding must be true or false")
  contract = manifest.get("prompt_contract")
  if not isinstance(contract, str) or not contract:
    raise PromptPackError(label, "prompt_contract must be a non-empty string")

  files = manifest.get("files")
  if not isinstance(files, dict):
    raise PromptPackError(label, "files must map each file name to its sha256")
  contents = {}
  for name, digest in files.items():
    data = fetch(name)
    if not isinstance(digest, str) or _sha256(data) != digest:
      raise PromptPackError(label, f"file {name!r} sha256 {_sha256(data)} does not match the manifest")
    contents[name] = data

  def named(key: str, required: bool) -> Optional[bytes]:
    name = manifest.get(key)
    if name is None and not required:
      return None
    if name not in contents:
      raise PromptPackError(label, f"{key} {name!r} is not listed in files")
    return contents[name]

  try:
    system_prompt = named("system_prompt", True).decode("utf-8")
    schema_raw = named("schema", False)
    schema = json.loads(schema_raw) if schema_raw is not None else None
  except ValueError:
    raise PromptPackError(label, "system_prompt must be UTF-8 text and schema must be JSON") from None
  schema_allowed = None
  if schema is not None:
    if not isinstance(schema, dict) or set(schema) != set(_SCHEMA_KEYS) or not all(
      isinstance(schema[k], list) and schema[k] and all(isinstance(v, str) for v in schema[k]) for k in _SCHEMA_KEYS
    ):
      raise PromptPackError(label, f"schema must hold non-empty string lists {list(_SCHEMA_KEYS)}")
    schema_allowed = {key: set(schema[key]) for key in _SCHEMA_KEYS}
  return PromptPack(
    pack_id=pack_id, pack_version=version, manifest_sha256=pinned, system_prompt=system_prompt,
    max_tokens=max_tokens, parser=parser, field_map=field_map, grounding=grounding,
    schema_allowed=schema_allowed, schema_version=str(manifest.get("schema_version") or f"{pack_id}@{version}"),
    prompt_contract=contract,
  )
