#!/usr/bin/env python3
"""Pin validation and database verification for the fetch-vulndb action (stdlib only).

  verify_vulndb.py pin PIN_JSON            print build_id/asset/sha256 as key=value lines
  verify_vulndb.py verify PIN_JSON SQLITE  check sha256_sqlite, user_version, meta.build_id
  verify_vulndb.py local-pin SQLITE OUT    write an origin=local pin (VULNDB_PATH builds)
"""
import hashlib
import importlib.util
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

REPO = "Ratio1/redmesh-vulndb"
ASSET = "vulndb.sqlite.zst"
_SHA = re.compile(r"[0-9a-f]{64}")
_BUILD_ID = re.compile(r"vulndb-[0-9a-f]{6,64}")


def _supported_models():
    path = Path(__file__).resolve().parents[3] / "extensions/business/cybersec/red_mesh/vulndb/models.py"
    spec = importlib.util.spec_from_file_location("_vulndb_models", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SUPPORTED_MODELS


def load_pin(pin_path):
    """Return the pin, or raise ValueError when a field cannot be trusted."""
    pin = json.loads(Path(pin_path).read_text(encoding="utf-8"))
    if pin.get("origin") is not None:
        raise ValueError("pin has origin %r: a local pin must not reach CI" % pin["origin"])
    if pin.get("schema") != 1:
        raise ValueError("unsupported pin schema %r" % pin.get("schema"))
    if pin.get("repo") != REPO:
        raise ValueError("pin repo must be %s" % REPO)
    if pin.get("asset") != ASSET:
        raise ValueError("pin asset must be %s" % ASSET)
    if not _BUILD_ID.fullmatch(str(pin.get("build_id"))):
        raise ValueError("bad build_id")
    for key in ("sha256", "sha256_sqlite"):
        if not _SHA.fullmatch(str(pin.get(key))):
            raise ValueError("bad %s" % key)
    for key in ("size", "size_zst"):
        value = pin.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("bad %s" % key)
    return pin


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_sqlite(pin, sqlite_path, supported=None):
    """Raise ValueError unless the file matches the pin and a known MODEL."""
    supported = _supported_models() if supported is None else supported
    if Path(sqlite_path).stat().st_size != pin["size"]:
        raise ValueError("size mismatch")
    if sha256_file(sqlite_path) != pin["sha256_sqlite"]:
        raise ValueError("sha256_sqlite mismatch")
    conn = sqlite3.connect("file:%s?mode=ro" % quote(str(Path(sqlite_path).resolve())), uri=True)
    try:
        model = conn.execute("PRAGMA user_version").fetchone()[0]
        if model not in supported:
            raise ValueError("MODEL %s not in supported %s" % (model, tuple(supported)))
        row = conn.execute("SELECT v FROM meta WHERE k = 'build_id'").fetchone()
    finally:
        conn.close()
    if row is None or row[0] != pin["build_id"]:
        raise ValueError("meta.build_id %r does not match pin %r" % (row and row[0], pin["build_id"]))


def write_local_pin(sqlite_path, out_path):
    """Write a pin for a local database: no release, so no built_at (verified like a pin)."""
    conn = sqlite3.connect("file:%s?mode=ro" % quote(str(Path(sqlite_path).resolve())), uri=True)
    try:
        row = conn.execute("SELECT v FROM meta WHERE k = 'build_id'").fetchone()
    finally:
        conn.close()
    if row is None:
        raise ValueError("database has no meta.build_id")
    pin = {"schema": 1, "repo": REPO, "build_id": row[0], "origin": "local",
           "sha256_sqlite": sha256_file(sqlite_path), "size": Path(sqlite_path).stat().st_size}
    Path(out_path).write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")


def main(argv):
    try:
        if len(argv) == 3 and argv[1] == "pin":
            pin = load_pin(argv[2])
            for key in ("build_id", "asset", "sha256", "size", "size_zst"):
                print("%s=%s" % (key, pin[key]))
        elif len(argv) == 4 and argv[1] == "verify":
            verify_sqlite(load_pin(argv[2]), argv[3])
            print("vulndb verified")
        elif len(argv) == 4 and argv[1] == "local-pin":
            write_local_pin(argv[2], argv[3])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ValueError, OSError, sqlite3.Error) as exc:
        print("vulndb check failed: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
