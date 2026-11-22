"""Prompt packs: loader, validator, plugin wiring and parity with the pre-pack decision-JSON path."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.edgeguard.tests.decision_json_parity import (
  FIXTURE_PATH,
  MODEL_KEY,
  SEMAPHORE,
  capture,
)
from extensions.business.cybersec.edgeguard.tests.test_api import TEST_GENERATION_WORKERS, _Response, _make_api
from extensions.business.cybersec.edgeguard.edgeguard_prompt_pack import (
  LEGACY_PROFILE_PACKS,
  MANIFEST_NAME,
  PromptPackError,
  load_pack,
)

VENDORED = Path(LEGACY_PROFILE_PACKS["decision_json_v2026_11_08"]["path"])
VENDORED_SHA = LEGACY_PROFILE_PACKS["decision_json_v2026_11_08"]["sha256"]


def _sha(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _write_pack(root: Path, **changes) -> dict:
  """Copy the vendored pack into `root` with manifest `changes` applied (None deletes a key); return the PROMPT_PACK source."""
  for name in ("system_prompt.txt", "schema.json"):
    shutil.copy(VENDORED / name, root / name)
  manifest = json.loads((VENDORED / MANIFEST_NAME).read_bytes())
  for key, value in changes.items():
    if value is None:
      manifest.pop(key, None)
    else:
      manifest[key] = value
  raw = (json.dumps(manifest, indent=1) + "\n").encode()
  (root / MANIFEST_NAME).write_bytes(raw)
  return {"path": str(root), "sha256": _sha(raw)}


class PackLoaderTests(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.root = Path(self._tmp.name)
    self.addCleanup(self._tmp.cleanup)

  def _refused(self, source, *needles, **kwargs):
    with self.assertRaises(PromptPackError) as raised:
      load_pack(source, label="pack-under-test", **kwargs)
    for needle in needles:
      self.assertIn(needle, str(raised.exception))
    self.assertIn("pack-under-test", str(raised.exception))

  def test_valid_pack_loads_with_its_settings(self):
    pack = load_pack(_write_pack(self.root), label="p")

    self.assertEqual((pack.pack_id, pack.max_tokens, pack.parser, pack.grounding), ("cypher_2026_11_08", 512, "decision_json", False))
    self.assertEqual(_sha(pack.system_prompt.encode()), "da06f1e43e6102b9c04adaa4b361ef1d81e2a4e3ac3d3759525689a7cf47a2eb")
    self.assertIn("USES_TOOL", pack.schema_allowed["relationship_types"])
    self.assertEqual(pack.manifest_sha256, _sha((self.root / MANIFEST_NAME).read_bytes()))

  def test_wrong_manifest_sha_is_refused(self):
    source = _write_pack(self.root)
    self._refused({**source, "sha256": "0" * 64}, "does not match the pinned")

  def test_a_modified_file_is_refused(self):
    source = _write_pack(self.root)
    (self.root / "system_prompt.txt").write_bytes((self.root / "system_prompt.txt").read_bytes() + b" ")
    self._refused(source, "system_prompt.txt", "does not match the manifest")

  def test_unknown_parser_is_refused(self):
    self._refused(_write_pack(self.root, parser="regex"), "unknown parser 'regex'")

  def test_field_map_missing_a_decision_is_refused(self):
    field_map = json.loads((VENDORED / MANIFEST_NAME).read_bytes())["field_map"]
    del field_map["refuse"]
    self._refused(_write_pack(self.root, field_map=field_map), "no entry for decision 'refuse'")

  def test_missing_file_is_refused(self):
    source = _write_pack(self.root)
    (self.root / "schema.json").unlink()
    self._refused(source, "missing file 'schema.json'")

  def test_unknown_key_is_refused_and_decoding_keys_point_to_the_serving_config(self):
    self._refused(_write_pack(self.root, colour="red"), "unknown key 'colour'")
    self._refused(_write_pack(self.root, temperature=0.0), "unknown key 'temperature'", "serving config")

  def test_file_names_and_symlinks_cannot_leave_the_pack_directory(self):
    outside = self.root / "outside"
    outside.mkdir()
    pack_dir = self.root / "pack"
    pack_dir.mkdir()
    (outside / "evil.txt").write_text("x")
    source = _write_pack(pack_dir, files={"../outside/evil.txt": _sha(b"x")})
    self._refused(source, "plain name")
    source = _write_pack(pack_dir)
    (pack_dir / "system_prompt.txt").unlink()
    (pack_dir / "system_prompt.txt").symlink_to(outside / "evil.txt")
    self._refused(source, "outside the pack directory")

  def test_hugging_face_source_downloads_with_the_token_and_never_reports_it(self):
    source_dir = self.root / "hf"
    source_dir.mkdir()
    local = _write_pack(source_dir)
    calls = []

    def download(repo_id, filename, revision, token):
      calls.append((repo_id, filename, revision, token))
      return str(source_dir / filename.rsplit("/", 1)[-1])

    commit = "a" * 40
    source = {"repo": "org/model", "revision": commit, "path": "packs/p", "sha256": local["sha256"]}
    pack = load_pack(source, label="hf", hf_token="hf_secret_token", hf_download=download)

    self.assertEqual(pack.pack_id, "cypher_2026_11_08")
    self.assertEqual(calls[0], ("org/model", "packs/p/edgeguard-pack.json", commit, "hf_secret_token"))

    def failing(**_kwargs):
      raise OSError("401 for token hf_secret_token")

    with self.assertRaises(PromptPackError) as raised:
      load_pack(source, label="hf", hf_token="hf_secret_token", hf_download=failing)
    self.assertNotIn("hf_secret_token", str(raised.exception))
    self.assertNotIn("hf_secret_token", repr(raised.exception.__cause__))
    self._refused({**source, "revision": "main"}, "40-hex commit", hf_download=download)

  def test_oversized_file_is_refused_before_it_is_read(self):
    source = _write_pack(self.root)
    (self.root / "system_prompt.txt").write_bytes(b"x" * (1024 * 1024 + 1))
    self._refused(source, "system_prompt.txt", "larger than")


def _worker(**entry):
  return {"SEMAPHORE": SEMAPHORE, "PATH": "/create_chat_completion", "DISPLAY_NAME": "decision fixture model", **entry}


def _plugin(worker):
  return _make_api(
    edgeguard_generation_workers={MODEL_KEY: worker, **TEST_GENERATION_WORKERS},
    worker_semaphore_env={SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53009"}},
  )


class PluginWiringTests(unittest.TestCase):
  def test_profile_and_pack_together_are_refused(self):
    plugin = _plugin(_worker(PROMPT_PROFILE="direct_cypher", PROMPT_PACK=LEGACY_PROFILE_PACKS["decision_json_v2026_11_08"]))

    with self.assertRaises(PromptPackError) as raised:
      plugin._prompt_profile(MODEL_KEY)

    self.assertIn("both PROMPT_PROFILE and PROMPT_PACK", str(raised.exception))

  def test_unhashable_profile_name_is_a_pack_error_not_a_type_error(self):
    plugin = _plugin(_worker(PROMPT_PROFILE=["direct_cypher"]))

    with self.assertRaises(PromptPackError):
      plugin._prompt_profile(MODEL_KEY)

  def test_config_update_with_a_bad_pack_is_refused(self):
    plugin = _plugin(_worker(PROMPT_PACK={"path": str(VENDORED), "sha256": "1" * 64}))
    plugin.P = lambda *args, **kwargs: None

    with self.assertRaises(PromptPackError):
      plugin.on_config()

  def test_good_config_update_still_runs_the_parent_hook(self):
    plugin = _plugin(_worker(PROMPT_PACK={"path": str(VENDORED), "sha256": VENDORED_SHA}))
    calls = []
    with patch.object(type(plugin).__mro__[1], "on_config", create=True, new=lambda _self: calls.append(1)):
      plugin.on_config()

    self.assertEqual(calls, [1])

  def test_startup_refuses_a_bad_pack_with_a_log_line_naming_it(self):
    plugin = _plugin(_worker(PROMPT_PACK={"path": str(VENDORED), "sha256": "1" * 64}))
    logs = []
    plugin.P = lambda message, *args, **kwargs: logs.append(str(message))
    plugin._resolve_secret = lambda **_kwargs: None

    with patch.object(type(plugin).__mro__[1], "on_init", create=True, new=lambda _self: None):
      with self.assertRaises(PromptPackError):
        plugin.on_init()

    self.assertTrue(any("refuses to start" in m and MODEL_KEY in m and VENDORED.name in m and "does not match" in m for m in logs), logs)

  def test_old_profile_name_resolves_to_the_vendored_pack_and_health_lists_it(self):
    plugin = _plugin(_worker(PROMPT_PROFILE="decision_json_v2026_11_08"))
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
      health = plugin.health()

    self.assertEqual(health["prompt_packs"], {MODEL_KEY: {
      "pack_id": "cypher_2026_11_08", "pack_version": "5e12777d5a.1", "sha256": VENDORED_SHA,
    }})

  def test_raw_cypher_pack_makes_one_attempt_with_the_pack_prompt(self):
    with tempfile.TemporaryDirectory() as tmp:
      source = _write_pack(Path(tmp), parser="raw_cypher", field_map=None, max_tokens=256)
      plugin = _plugin(_worker(PROMPT_PACK=source))
      session = MagicMock()
      session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
      text = "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5"
      session.post.return_value = _Response(payload={"result": {"TEXT_RESPONSE": text, "FULL_OUTPUT": {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}], "usage": {"completion_tokens": 9}}}})
      with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
        result = plugin.generate(request="Which indicators exist?", model_key=MODEL_KEY)

    self.assertEqual(result["status"], "accepted", result.get("validation_feedback"))
    self.assertEqual(session.post.call_args.kwargs["json"]["max_tokens"], 256)
    self.assertEqual(session.post.call_count, 1)


class ParityTests(unittest.TestCase):
  """The pack path reproduces the pre-pack worker payloads and response bodies (fixture from the old code)."""

  @classmethod
  def setUpClass(cls):
    cls.golden = json.loads(FIXTURE_PATH.read_text())

  # The two deliberate differences from the pre-pack code (EG-037 phase 2); the rest stays frozen. The
  # schema digest moved because three prod-graph property names joined the allowlist: the golden value is
  # replaced by the expected new one, so a further change to the schema surface still fails here.
  OLD_SCHEMA_DIGEST = "e8dfc616cfffc0ab8177d3b3b0c124019da09f06474a9daabe97801dfceebd2b"
  NEW_SCHEMA_DIGEST = "a9a57ba60dcb4a2dad8c532ae3e95e155bc4c8e3fd29ec7b698ce19d31407c65"

  @staticmethod
  def _drop_rejected_decision_fields(value):
    """The actual output only: a rejected response now carries `decision`/`decision_note`."""
    if isinstance(value, dict):
      if value.get("status") == "rejected":
        value = {k: v for k, v in value.items() if k not in ("decision", "decision_note")}
      return {k: ParityTests._drop_rejected_decision_fields(v) for k, v in value.items()}
    return value

  @staticmethod
  def _expected_from_golden(value):
    """The golden only: the old schema digest becomes the expected new one."""
    if isinstance(value, dict):
      return {k: ParityTests._expected_from_golden(v) for k, v in value.items()}
    return ParityTests.NEW_SCHEMA_DIGEST if value == ParityTests.OLD_SCHEMA_DIGEST else value

  def _assert_parity(self, worker):
    actual = self._drop_rejected_decision_fields(capture(worker))
    golden = self._expected_from_golden(self.golden)
    for section in golden:
      with self.subTest(section=section):
        self.assertEqual(actual[section], golden[section])

  def test_pack_worker_entry_reproduces_the_golden_output(self):
    self._assert_parity(_worker(PROMPT_PACK=LEGACY_PROFILE_PACKS["decision_json_v2026_11_08"]))


if __name__ == "__main__":
  unittest.main()
