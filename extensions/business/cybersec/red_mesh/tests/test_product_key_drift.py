"""Product-key drift guard (RM-061 R3).

Every product string a probe feeds into `check_cves` must be a product key of the static CVE
catalog (`cve_db.py` matches `entry.product != product`, so a misspelt key silently never fires).
Keys the catalog holds but no probe passes are the inventory's `PRODUCTS_WITHOUT_PROBE`.

Keys are read from the source with `ast`, because the maps are class or function locals:
  - the first argument of every `check_cves("literal", ...)` call;
  - the product column of `_GENERIC_BANNER_PATTERNS`, `_DNS_PRODUCT_PATTERNS`, `_SSH_LIBRARY_PATTERNS`;
  - the values of `_HTTP_PRODUCT_MAP`, `_smtp_product_map` and any dict literal used as `{...}.get(...)`;
  - the first element of the tuples `_mysql_cve_target` returns.
"""
import ast
import pathlib
import unittest

from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE
from extensions.business.cybersec.red_mesh.detection_inventory import PRODUCTS_WITHOUT_PROBE

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATTERN_LISTS = {"_GENERIC_BANNER_PATTERNS", "_DNS_PRODUCT_PATTERNS", "_SSH_LIBRARY_PATTERNS"}
VALUE_MAPS = {"_HTTP_PRODUCT_MAP", "_smtp_product_map"}
# Probe-side keys with no catalog row yet, each with the reason it is allowed.
# The static catalog carries no row for them, so a static-mode scan reports no CVE for these products. Not typos:
# the probes name the product correctly and tests/test_cve_probe_routing.py pins the DNS keys. Whether the
# generated vulnerability database (RM-169) holds rows for them was not checked here.
ALLOWED_WITHOUT_CATALOG_ROW = {
  "dnsmasq": "DNS probe key; no static catalog row",
  "powerdns": "DNS probe key; no static catalog row",
  "unbound": "DNS probe key; no static catalog row",
  "paramiko": "SSH probe key; no static catalog row",
}


def _str(node):
  return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _collect():
  """Return {product key: set of 'file:line' sources}."""
  found = {}

  def add(key, path, node):
    if key:
      found.setdefault(key, set()).add(f"{path.relative_to(ROOT)}:{node.lineno}")

  for path in sorted(ROOT.rglob("*.py")):
    if "tests" in path.relative_to(ROOT).parts:
      continue
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
      if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name == "check_cves" and node.args:
          add(_str(node.args[0]), path, node)
        if name == "get" and isinstance(func.value, ast.Dict) and "worker" in path.relative_to(ROOT).parts:
          for value in func.value.values:
            add(_str(value), path, node)
      elif isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {t.id for t in targets if isinstance(t, ast.Name)}
        if names & VALUE_MAPS and isinstance(node.value, ast.Dict):
          for value in node.value.values:
            add(_str(value), path, node)
        if names & PATTERN_LISTS and isinstance(node.value, (ast.List, ast.Tuple)):
          for item in node.value.elts:
            if isinstance(item, ast.Tuple) and item.elts:
              add(_str(item.elts[-1]), path, item)
      elif isinstance(node, ast.FunctionDef) and node.name == "_mysql_cve_target":
        for ret in ast.walk(node):
          if isinstance(ret, ast.Return) and isinstance(ret.value, ast.Tuple) and ret.value.elts:
            add(_str(ret.value.elts[0]), path, ret)
  return found


class TestProductKeyDrift(unittest.TestCase):

  def test_every_probe_product_key_is_a_catalog_key(self):
    catalog = {entry.product for entry in CVE_DATABASE}
    drift = {key: sorted(src) for key, src in _collect().items()
             if key not in catalog and key not in ALLOWED_WITHOUT_CATALOG_ROW}
    self.assertEqual(drift, {}, "product keys a probe passes that no catalog row carries (typo or missing rows)")

  def test_extraction_reaches_every_source_kind(self):
    # Guards the guard: a refactor that renames a map must not leave the scan empty.
    found = _collect()
    for key in ("apache", "nginx", "exim", "opensmtpd", "proftpd", "tightvnc", "bind", "libssh",
                "mariadb", "wordpress", "samba", "elasticsearch"):
      self.assertIn(key, found)
    self.assertGreaterEqual(len(found), 35)

  def test_products_without_probe_are_catalog_keys_no_probe_passes(self):
    catalog = {entry.product for entry in CVE_DATABASE}
    self.assertTrue(PRODUCTS_WITHOUT_PROBE <= catalog)
    self.assertEqual(PRODUCTS_WITHOUT_PROBE & set(_collect()), set())


if __name__ == "__main__":
  unittest.main()
