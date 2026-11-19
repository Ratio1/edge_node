"""v0.13 prompt-only revision p6: vendored prompt, v0.13 validation, and worked examples the guard accepts."""

import hashlib
import tempfile
import unittest
from pathlib import Path

# test_api installs the naeural_core stubs at import time, so it comes first.
from extensions.business.cybersec.edgeguard.tests.test_api import TEST_GENERATION_WORKERS, _make_api
from extensions.business.cybersec.edgeguard.edgeguard_api import PROMPT_PROFILE_V0_13_P6
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (
  RESULT_SHAPE_OTHER,
  EdgeGuardCypherGuardError,
  classify_result_shape,
  normalize_user_literal_text,
  schema_sets,
)
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard_v0_13 import (
  EDGEGUARD_SCHEMA_V0_13,
  SCHEMA_VERSION_V0_13,
  V0_13_P6_SYSTEM_PROMPT_PATH,
  V0_13_P6_SYSTEM_PROMPT_SHA256,
  build_v0_13_pattern_schema_system_prompt,
  load_v0_13_p6_system_prompt,
)

P6_MODEL_KEY = "v0-13-p6-fixture-model"
P6_WORKERS = {
  P6_MODEL_KEY: {
    "SEMAPHORE": "edgeguard_llm_v0_13",
    "PATH": "/create_chat_completion",
    "PROMPT_PROFILE": PROMPT_PROFILE_V0_13_P6,
    "DISPLAY_NAME": "v0.13 p6 fixture model",
    "MODEL_REPO": "example-org/v0-13-fixture-gguf",
    "MODEL_FILE": "v0-13-fixture.Q4_K_M.gguf",
  },
  **TEST_GENERATION_WORKERS,
}


def _examples(prompt):
  block = prompt[prompt.index("Examples (question => query):\n"):prompt.index("Read-only:")]
  return [line.split(" => ", 1) for line in block.splitlines()[1:] if " => " in line]


class V0_13P6PromptTests(unittest.TestCase):
  def test_vendored_prompt_is_pinned(self):
    data = V0_13_P6_SYSTEM_PROMPT_PATH.read_bytes()
    self.assertEqual(hashlib.sha256(data).hexdigest(), V0_13_P6_SYSTEM_PROMPT_SHA256)
    self.assertEqual(load_v0_13_p6_system_prompt(), data.decode("utf-8"))

  def test_a_modified_prompt_file_is_refused(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = Path(tmp) / "prompt.txt"
      path.write_bytes(V0_13_P6_SYSTEM_PROMPT_PATH.read_bytes() + b" ")
      with self.assertRaises(EdgeGuardCypherGuardError):
        load_v0_13_p6_system_prompt(path)

  def test_prompt_teaches_the_direct_sector_links(self):
    prompt = load_v0_13_p6_system_prompt()
    self.assertIn("TARGETS Sector: Indicator Malware ThreatActor", prompt)


class V0_13P6ProfileTests(unittest.TestCase):
  def test_profile_serves_the_p6_prompt_and_validates_against_the_v0_13_artifact(self):
    plugin = _make_api(edgeguard_generation_workers=P6_WORKERS)

    messages = plugin._generation_messages(P6_MODEL_KEY, "Show indicators")
    profile = plugin._cypher_validation_profile(P6_MODEL_KEY)

    self.assertEqual(messages[0]["content"], load_v0_13_p6_system_prompt())
    self.assertNotEqual(messages[0]["content"], build_v0_13_pattern_schema_system_prompt())
    self.assertTrue(profile["use_v0_11"])
    self.assertIs(profile["schema_artifact"], EDGEGUARD_SCHEMA_V0_13)
    self.assertEqual(profile["schema_version"], SCHEMA_VERSION_V0_13)
    self.assertEqual(profile["schema_allowed"], schema_sets(EDGEGUARD_SCHEMA_V0_13))

  def test_prompt_contract_reports_the_p6_prompt(self):
    plugin = _make_api(edgeguard_generation_workers=P6_WORKERS)

    entry = {p["model_key"]: p for p in plugin.prompt_contract()["profiles"]}[P6_MODEL_KEY]

    self.assertEqual(entry["system_prompt_sha256"], V0_13_P6_SYSTEM_PROMPT_SHA256)
    self.assertEqual(entry["cypher_schema_version"], SCHEMA_VERSION_V0_13)

  def test_correction_turn_keeps_the_v0_11_conversation_shape(self):
    plugin = _make_api(edgeguard_generation_workers=P6_WORKERS)

    messages = plugin._generation_messages(
      P6_MODEL_KEY, "Show indicators", rejected_cypher="MATCH (n) RETURN n",
      validation_feedback="bad", retry_index=1, retry_limit=2,
    )

    self.assertEqual([m["role"] for m in messages], ["system", "user", "assistant", "user"])

  def test_every_worked_example_passes_the_production_checks(self):
    """An example the API would refuse teaches the model to fail: guard, shape rule and literal grounding."""
    plugin = _make_api(edgeguard_generation_workers=P6_WORKERS)
    examples = _examples(load_v0_13_p6_system_prompt())
    self.assertGreaterEqual(len(examples), 10)

    for question, cypher in examples:
      with self.subTest(question=question):
        checked = plugin.check_cypher(cypher=cypher, model_key=P6_MODEL_KEY)
        self.assertTrue(checked["accepted"], checked.get("validation_feedback"))
        accepted = checked.get("accepted_cypher") or cypher
        self.assertNotEqual(classify_result_shape(accepted), RESULT_SHAPE_OTHER)
        grounded = plugin._apply_literal_grounding_guard(
          {"accepted": True, "accepted_cypher": accepted}, accepted, normalize_user_literal_text(question),
          use_v0_11=True, schema_artifact=EDGEGUARD_SCHEMA_V0_13,
        )
        self.assertTrue(grounded["accepted"], grounded.get("validation_feedback"))


if __name__ == "__main__":
  unittest.main()
