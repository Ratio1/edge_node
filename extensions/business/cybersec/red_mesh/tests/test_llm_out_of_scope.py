"""RM-086 item 6: the LLM's coverage gaps are split from out-of-scope matters.

The client got "environment-variable storage" (which an external scan of one
target cannot assess) listed beside "non-standard SSH ports" (a real limitation
of the scan). `out_of_scope` is additive: outputs without it still validate and
render one list.
"""
import unittest

from .conftest import mock_plugin_modules  # noqa: F401
from extensions.business.cybersec.red_mesh.models.llm_output import (
  LlmReportSections,
  render_legacy_llm_fields,
)
from extensions.business.cybersec.red_mesh.services.llm_structured import (
  LEGACY_SYSTEM_PROMPT,
  LOCAL_CYBERSECQWEN_PROMPT,
  get_report_sections_json_schema,
)


class TestOutOfScope(unittest.TestCase):

  def test_round_trips_and_defaults_to_empty(self):
    sections = LlmReportSections.from_dict({
      "coverage_gaps": ["Non-standard SSH ports were not probed."],
      "out_of_scope": ["Environment-variable secret storage on the host."],
    })
    self.assertEqual(sections.coverage_gaps, ("Non-standard SSH ports were not probed.",))
    self.assertEqual(sections.out_of_scope, ("Environment-variable secret storage on the host.",))
    self.assertEqual(sections.to_dict()["out_of_scope"], ["Environment-variable secret storage on the host."])
    self.assertEqual(LlmReportSections.from_dict({"coverage_gaps": ["x"]}).out_of_scope, ())
    self.assertEqual(LlmReportSections.from_dict({"out_of_scope": "not a list"}).out_of_scope, ())

  def test_legacy_markdown_renders_the_second_list_under_its_own_heading(self):
    markdown, _summary = render_legacy_llm_fields({
      "executive_headline": "One HIGH finding.",
      "coverage_gaps": ["Non-standard SSH ports were not probed."],
      "out_of_scope": ["Secondary hosts behind the load balancer."],
    })
    self.assertIn("## Coverage Gaps", markdown)
    self.assertIn("## Outside Engagement Scope", markdown)
    self.assertLess(markdown.index("## Coverage Gaps"), markdown.index("## Outside Engagement Scope"))
    self.assertIn("Secondary hosts behind the load balancer.", markdown)

  def test_schema_accepts_the_key_without_requiring_it(self):
    schema = get_report_sections_json_schema()
    properties = schema["properties"]
    self.assertIn("out_of_scope", properties)
    self.assertEqual(properties["out_of_scope"]["type"], "array")
    self.assertEqual(properties["out_of_scope"]["maxItems"], properties["coverage_gaps"]["maxItems"])
    self.assertNotIn("out_of_scope", schema.get("required", []))

  def test_every_prompt_defines_the_split(self):
    from extensions.business.cybersec.red_mesh.services.llm_structured import (
      LOCAL_REPORT_CHUNKS, REMOTE_RICH_USER_PROMPT_TEMPLATE,
    )
    chunk_prompts = [chunk.prompt for chunk in LOCAL_REPORT_CHUNKS if "coverage_gaps" in chunk.prompt]
    self.assertTrue(chunk_prompts)
    for prompt in (LEGACY_SYSTEM_PROMPT, LOCAL_CYBERSECQWEN_PROMPT, REMOTE_RICH_USER_PROMPT_TEMPLATE,
                   *chunk_prompts):
      self.assertIn("out_of_scope", prompt)
      self.assertIn("coverage_gaps", prompt)

  def test_a_fabricated_cve_in_out_of_scope_is_caught(self):
    from extensions.business.cybersec.red_mesh.models.llm_output import validate_llm_output
    sections = LlmReportSections.from_dict({
      "executive_headline": "One HIGH finding.", "background_draft": "Scope.",
      "overall_posture": "Posture.", "recommendation_summary": ["Patch."],
      "attack_chain_narratives": [], "coverage_gaps": [],
      "out_of_scope": ["CVE-2099-99999 on the mail relay is not assessed."],
      "conclusion": "Done.",
    })
    result = validate_llm_output(sections, findings=[])
    self.assertTrue(any("CVE-2099-99999" in str(issue) for issue in getattr(result, "issues", result)),
                    result)


if __name__ == "__main__":
  unittest.main()
