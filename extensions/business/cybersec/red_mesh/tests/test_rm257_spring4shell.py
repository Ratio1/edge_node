"""RM-257 phase 3a: the Spring4Shell indicator needs Java/Spring evidence, on both detection paths."""
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.tests.test_rm198_detection_checks import _worker

_GET = "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get"
_POST = "extensions.business.cybersec.red_mesh.worker.web.injection.requests.post"
_PLAIN = {"Content-Type": "text/html"}
# vulhub 4300: Joomla on PHP 7.4 behind Apache, hex PHP session cookie
_PHP = {"Server": "Apache/2.4.38", "X-Powered-By": "PHP/7.4.3", "Set-Cookie": "PHPSESSID=9f86d081884c7d659a2feaa0c55ad015"}
_EVIDENCE = {
  "none_php": (_PHP, "Joomla! Error: 500"),
  "whitelabel": (_PLAIN, "<h1>Whitelabel Error Page</h1>"),
  "coyote": ({"Server": "Apache-Coyote/1.1"}, "Bad Request"),
  "jsessionid": ({"Set-Cookie": "JSESSIONID=ABC; Path=/"}, "Bad Request"),
}
# (branch, URLs[0] status, expected finding confidence). first: control and classLoader both 200, URLs[0] vs control
# differential; elif: control rejected (400), classLoader 200, URLs[0] alone decides.
_CASES = [("first", 400, "firm"), ("first", 500, "firm"), ("elif", 200, "tentative"), ("elif", 400, "firm"), ("elif", 500, "firm")]


def _resp(status, text="<html>App</html>", headers=_PLAIN):
  r = MagicMock()
  r.status_code, r.text, r.ok, r.headers = status, text, status < 400, headers
  return r


def _spring4shell(branch, urls_status, headers, text):
  def fake_get(url, **kw):
    if "/actuator" in url:
      return _resp(404, "")
    if "INVALID_RM_CTRL.URLs" in url:
      return _resp(200)
    if "INVALID_RM_CTRL" in url:
      return _resp(200 if branch == "first" else 400, "Bad Request")
    if "classLoader.URLs" in url:
      return _resp(urls_status, text, headers)
    return _resp(200)
  with patch(_GET, side_effect=fake_get), patch(_POST, return_value=_resp(404, "")):
    result = _worker(ports=(80,))._web_test_spring_actuator("1.2.3.4", 80)
  return [f for f in result["findings"] if "Spring4Shell" in f["title"]]


class TestSpring4ShellEvidence(unittest.TestCase):
  def test_branch_by_evidence_table(self):
    for branch, status, confidence in _CASES:
      for name, (headers, text) in _EVIDENCE.items():
        hits = _spring4shell(branch, status, headers, text)
        want = 0 if name == "none_php" else 1
        self.assertEqual(len(hits), want, f"{branch} {status} {name}")
        if want:
          self.assertEqual(hits[0]["confidence"], confidence, f"{branch} {status} {name}")
