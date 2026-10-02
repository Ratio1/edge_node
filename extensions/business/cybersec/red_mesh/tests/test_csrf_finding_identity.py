"""CSRF finding identity: one finding per page + form action (RM-117 item 1).

Job `22f4998c` printed two "POST form at / missing CSRF token" findings on
port 80 with one `finding_id`: the action lived only in `evidence`, the probe
set no asset, so `dedup_key` fell back to the title, which names the page and
not the form. The action is now an identity input through the finding's asset.
"""

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.findings import probe_port_scope
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

from .conftest import DummyOwner, PentestLocalWorker


def _page(*forms):
  return "<html><body>" + "".join(forms) + "</body></html>"


def _form(action=None, body='<input type="text" name="q">'):
  attr = f' action="{action}"' if action is not None else ""
  return f'<form method="POST"{attr}>{body}</form>'


class _Host(_RiskScoringMixin):
  pass


class TestCsrfFindingIdentity(unittest.TestCase):

  def _worker(self):
    worker = PentestLocalWorker(
      owner=DummyOwner(), target="example.com", job_id="job-csrf",
      initiator="init@example", local_id_prefix="1", worker_target_ports=[80],
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return worker

  def _run(self, pages):
    """`pages` maps a probed path to its HTML; other paths answer 404."""
    def fake_get(url, **_kwargs):
      resp = MagicMock()
      path = url.split("example.com", 1)[1] or "/"
      resp.status_code = 200 if path in pages else 404
      resp.text = pages.get(path, "")
      resp.headers = {}
      return resp
    with patch("requests.get", side_effect=fake_get), probe_port_scope(80):
      return self._worker()._web_test_csrf("example.com", 80)["findings"]

  def test_two_forms_with_different_actions_on_one_page_are_two_findings(self):
    findings = self._run({"/": _page(_form("/users/sign_in"), _form("/users"))})
    self.assertEqual(len(findings), 2)
    self.assertEqual(len({f["finding_id"] for f in findings}), 2)

  def test_the_asset_names_the_page_and_the_form_action(self):
    [finding] = self._run({"/login": _page(_form("/session"))})
    self.assertEqual(finding["affected_assets"], [{
      "host": "example.com", "port": 80, "url": "/login",
      "parameter": "/session", "method": "POST",
    }])

  def test_one_action_on_two_pages_is_two_findings(self):
    form = _form("/session")
    findings = self._run({"/": _page(form), "/login": _page(form)})
    self.assertEqual(len({f["finding_id"] for f in findings}), 2)

  def test_volatile_parts_of_the_action_do_not_move_the_id(self):
    [clean] = self._run({"/": _page(_form("/search"))})
    for volatile in ("/search?t=1712345", "/search#top", "/search;jsessionid=ABC123",
                     "/search?a=1&amp;b=2"):
      with self.subTest(action=volatile):
        [finding] = self._run({"/": _page(_form(volatile))})
        self.assertEqual(finding["finding_id"], clean["finding_id"])
        self.assertIn(volatile, finding["evidence"])

  def test_entities_in_the_action_are_decoded(self):
    [finding] = self._run({"/": _page(_form("/a&amp;b"))})
    self.assertEqual(finding["affected_assets"][0]["parameter"], "/a&b")

  def test_the_action_is_read_from_the_form_tag_not_its_body(self):
    body = '<button formaction="/elsewhere">Go</button><div data-action="/other"></div>'
    [finding] = self._run({"/contact": _page(_form(body=body))})
    self.assertEqual(finding["affected_assets"][0]["parameter"], "/contact")

  def test_forms_posting_to_one_place_stay_one_identity(self):
    """Stated limit: two forms without an action post back to the page, so
    they are the same unprotected endpoint and share an id."""
    findings = self._run({"/": _page(_form(), _form())})
    self.assertEqual(len({f["finding_id"] for f in findings}), 1)

  def test_the_probe_time_id_survives_the_flat_walk(self):
    findings = self._run({"/": _page(_form("/users/sign_in"), _form("/users"))})
    _risk, flat = _Host()._compute_risk_and_findings({
      "target": "example.com", "port_protocols": {"80": "http"},
      "web_tests_info": {"80": {"_web_test_csrf": {"findings": findings}}},
    })
    self.assertEqual(
      sorted(f["finding_id"] for f in flat),
      sorted(f["finding_id"] for f in findings),
    )
    for item in flat:
      self.assertEqual(item["affected_assets"][0]["url"], "/")


if __name__ == "__main__":
  unittest.main()
