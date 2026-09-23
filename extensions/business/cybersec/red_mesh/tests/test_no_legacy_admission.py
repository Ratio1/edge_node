"""The legacy admission surface stays deleted (RM-084 P6).

P6 removed the unscoped read path (`LegacyReadAccess`), the staged rollout (`ExecutionRollout`,
`TENANT_EXECUTION_ENABLED`/`_STAGE`, the `execution_rollout` store record), actor-only admission
(`_admit_actor_only`), and the account role (`AccountView.role` / `app_role` /
`tenant_memberships_present`). Each was a way for a caller with no tenant to be admitted, and each
would come back quietly: a helper re-added for a test, a config key copied from an old deployment.

This is the backend half of the grep gate; the Navigator's is `no-legacy-auth-surface.test.ts`. It
reads the production modules' syntax, not their text, so a docstring recounting the history does not
trip it and a renamed-but-identical reintroduction still has to pass review to get in.
"""
import ast
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]

REMOVED_IDENTIFIERS = frozenset({
  "LegacyReadAccess", "ExecutionRollout", "read_execution_rollout", "_admit_actor_only",
  "tenant_memberships_present", "app_role",
})
REMOVED_STRINGS = frozenset({
  "TENANT_EXECUTION_ENABLED", "TENANT_EXECUTION_STAGE", "execution_rollout",
  "navigatorAccountGeneration", "navigatorAccountState", "appRole",
})


def _production_modules():
  for path in sorted(PACKAGE.rglob("*.py")):
    if "tests" not in path.relative_to(PACKAGE).parts:
      yield path


def _identifiers(tree):
  for node in ast.walk(tree):
    if isinstance(node, ast.Name):
      yield node.id
    elif isinstance(node, ast.Attribute):
      yield node.attr
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
      yield node.name
    elif isinstance(node, ast.arg):
      yield node.arg
    elif isinstance(node, ast.keyword) and node.arg:
      yield node.arg
    elif isinstance(node, ast.alias):
      yield node.asname or node.name.rsplit(".", 1)[-1]


def _string_constants(tree):
  docstrings = set()
  for node in ast.walk(tree):
    if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
      body = getattr(node, "body", [])
      if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        docstrings.add(id(body[0].value))
  for node in ast.walk(tree):
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
      yield node.value


class TestNoLegacyAdmission(unittest.TestCase):
  def test_the_package_is_scanned(self):
    # A path mistake would make every assertion below vacuously true.
    modules = list(_production_modules())
    self.assertGreater(len(modules), 20)
    self.assertIn("pentester_api_01.py", {path.name for path in modules})

  def test_no_removed_identifier_is_defined_or_referenced(self):
    offenders = []
    for path in _production_modules():
      tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
      for name in set(_identifiers(tree)) & REMOVED_IDENTIFIERS:
        offenders.append(f"{path.relative_to(PACKAGE)}: {name}")
    self.assertEqual(offenders, [])

  def test_no_removed_config_key_or_record_field_is_used(self):
    offenders = []
    for path in _production_modules():
      tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
      for value in set(_string_constants(tree)) & REMOVED_STRINGS:
        offenders.append(f"{path.relative_to(PACKAGE)}: {value!r}")
    self.assertEqual(offenders, [])

  def test_the_resolved_identity_has_no_role_to_consult(self):
    from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView
    from dataclasses import fields
    self.assertEqual({field.name for field in fields(AccountView)},
                     {"account_id", "active", "state", "tenant_memberships", "account_generation"})


if __name__ == "__main__":
  unittest.main()
