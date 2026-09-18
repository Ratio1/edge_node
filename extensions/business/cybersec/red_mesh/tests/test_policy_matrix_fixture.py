"""The role -> operation matrix fixture is emitted from the policy it describes (RM-084).

`_ROLE_OPERATIONS` in `tenancy/policy.py` is the one source of the matrix. The Navigator decides the
same questions from `tenant-policy-matrix.v1.json` (its `policy-matrix-parity.test.ts`), so the
fixture has to be *this* table, not a hand-kept copy of it: a role gaining an operation here and not
there is a button the UI offers and the backend refuses, or the reverse.

This test rebuilds the fixture from the policy and fails when the stored copy differs. After an
intended policy change, regenerate it and carry the same file to the hub (canonical) and the Navigator:

    REDMESH_WRITE_MATRIX_FIXTURE=1 .venv/bin/python -m pytest -q \\
      extensions/business/cybersec/red_mesh/tests/test_policy_matrix_fixture.py
"""
import json
import os
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.tenancy.policy import (
  PLATFORM_ROLES,
  TENANT_LOCAL_ROLES,
  _ROLE_OPERATIONS,
)

FIXTURE = Path(__file__).resolve().parents[1] / "tenancy" / "fixtures" / "tenant-policy-matrix.v1.json"
SOURCE = "edge-node extensions/business/cybersec/red_mesh/tenancy/policy.py _ROLE_OPERATIONS"


def emit_matrix():
  """The fixture text for the current policy: membership roles only, every list sorted."""
  roles = sorted(PLATFORM_ROLES | TENANT_LOCAL_ROLES)
  matrix = {
    "schemaVersion": 1,
    "source": SOURCE,
    "platformRoles": sorted(PLATFORM_ROLES),
    "tenantRoles": sorted(TENANT_LOCAL_ROLES),
    "operations": {role: sorted(_ROLE_OPERATIONS[role]) for role in roles},
  }
  return json.dumps(matrix, indent=2) + "\n"


class TestPolicyMatrixFixture(unittest.TestCase):
  def test_the_stored_fixture_is_the_policy(self):
    emitted = emit_matrix()
    if os.environ.get("REDMESH_WRITE_MATRIX_FIXTURE") == "1":
      FIXTURE.write_text(emitted, encoding="utf-8")
    self.assertEqual(FIXTURE.read_text(encoding="utf-8"), emitted,
                     "tenant-policy-matrix.v1.json has drifted from _ROLE_OPERATIONS; regenerate it "
                     "(see the module docstring) and copy it to the hub and the Navigator")

  def test_every_membership_role_has_an_entry(self):
    self.assertLessEqual(PLATFORM_ROLES | TENANT_LOCAL_ROLES, set(_ROLE_OPERATIONS))


if __name__ == "__main__":
  unittest.main()
