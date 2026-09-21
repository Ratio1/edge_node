"""
CVSS v3.1 base score from a vector string.

The probe registry carries a static `cvss_template` per probe and the client
report printed those vectors with no number beside the severity badge
(RM-064 item 3). This module turns the vector into the base score the
specification defines, so the badge and the vector can be reconciled.

Base metrics only. Temporal and environmental groups are ignored when
present, which is what "base score" means.
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value):
  """CVSS v3.1 Appendix A `Roundup`: smallest number, to one decimal, >= value."""
  integer = round(value * 100000)
  if integer % 10000 == 0:
    return integer / 100000.0
  return (math.floor(integer / 10000) + 1) / 10.0


def parse_vector(vector):
  """Return the base metrics of a `CVSS:3.x/…` vector as a dict, or None."""
  if not isinstance(vector, str):
    return None
  parts = vector.strip().split("/")
  if not parts or not parts[0].startswith("CVSS:3."):
    return None
  metrics = {}
  for part in parts[1:]:
    if ":" not in part:
      return None
    key, value = part.split(":", 1)
    metrics[key] = value
  if any(key not in metrics for key in _BASE_METRICS):
    return None
  return metrics


def cvss31_base_score(vector):
  """CVSS v3.1 base score for a vector string, or None when it cannot be scored."""
  metrics = parse_vector(vector)
  if metrics is None:
    return None
  try:
    scope_changed = {"U": False, "C": True}[metrics["S"]]
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    iss = 1 - (
      (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    )
    exploitability = (
      8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
      * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
    )
  except KeyError:
    return None
  if scope_changed:
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
  else:
    impact = 6.42 * iss
  if impact <= 0:
    return 0.0
  if scope_changed:
    return _roundup(min(1.08 * (impact + exploitability), 10))
  return _roundup(min(impact + exploitability, 10))


def severity_band(score):
  """CVSS v3.1 qualitative rating for a base score: NONE/LOW/MEDIUM/HIGH/CRITICAL."""
  if score is None:
    return None
  if score == 0:
    return "NONE"
  if score < 4.0:
    return "LOW"
  if score < 7.0:
    return "MEDIUM"
  if score < 9.0:
    return "HIGH"
  return "CRITICAL"
