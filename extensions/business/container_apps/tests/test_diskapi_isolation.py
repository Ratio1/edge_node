"""
Unit tests for the diskapi path-reorganization and per-plugin isolation logic.

Covers:
  - Sanitization of pathological stream_id / instance_id components
  - Tier-1 cache-root hard rejection
  - Tier-2 plugin-isolation deprecation warning
  - Auto-routing of _to_data save/load shortcuts
  - Flat-path fallback for legacy callers with deprecation warning
  - `_get_plugin_absolute_base` returns None outside plugin context
"""

import importlib.util
import os
import pickle
import shutil
import sys
import tempfile
import types
import unittest


def _load_diskapi_module():
  """
  Load `naeural_core.business.mixins_base.diskapi` as a standalone module.

  The package `__init__` pulls in matplotlib (via utilsapi) which conflicts
  with NumPy 2.x in the test env. Loading the file directly with stub
  dependencies sidesteps the problem and lets us exercise the real code.
  """
  # Stub naeural_core package roots + the transitive imports diskapi.py needs.
  if 'naeural_core' not in sys.modules:
    sys.modules['naeural_core'] = types.ModuleType('naeural_core')
  if 'naeural_core.constants' not in sys.modules:
    ct = types.ModuleType('naeural_core.constants')
    ct.RESTRICTED_LOCATIONS = [
      '_bin',
      'config_startup.json',
      '_data/e2.pem',
      '_data/box_configuration/config_app.txt',
      'whitelist_commands.json',
    ]
    sys.modules['naeural_core.constants'] = ct
    sys.modules['naeural_core'].constants = ct
  if 'naeural_core.ipfs' not in sys.modules:
    ipfs = types.ModuleType('naeural_core.ipfs')
    class _R1FSEngine: pass
    ipfs.R1FSEngine = _R1FSEngine
    sys.modules['naeural_core.ipfs'] = ipfs
  for pkg in (
    'naeural_core.local_libraries',
    'naeural_core.local_libraries.vision',
  ):
    if pkg not in sys.modules:
      sys.modules[pkg] = types.ModuleType(pkg)
  if 'naeural_core.local_libraries.vision.ffmpeg_writer' not in sys.modules:
    ffmpeg = types.ModuleType('naeural_core.local_libraries.vision.ffmpeg_writer')
    class _FFmpegWriter: pass
    ffmpeg.FFmpegWriter = _FFmpegWriter
    sys.modules['naeural_core.local_libraries.vision.ffmpeg_writer'] = ffmpeg
  if 'cv2' not in sys.modules:
    sys.modules['cv2'] = types.ModuleType('cv2')

  diskapi_path = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', '..',
    'naeural_core', 'naeural_core', 'business', 'mixins_base', 'diskapi.py',
  )
  diskapi_path = os.path.abspath(diskapi_path)
  spec = importlib.util.spec_from_file_location('diskapi_under_test', diskapi_path)
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


_diskapi_mod = _load_diskapi_module()
_DiskAPIMixin = _diskapi_mod._DiskAPIMixin


class _FakeLogger:
  """Temp-dir-backed logger exposing the subset of methods diskapi needs."""

  def __init__(self, base):
    self._base = base
    os.makedirs(os.path.join(base, 'data'), exist_ok=True)
    os.makedirs(os.path.join(base, 'output'), exist_ok=True)
    os.makedirs(os.path.join(base, 'models'), exist_ok=True)

  def get_base_folder(self):
    return self._base

  def get_data_folder(self):
    return os.path.join(self._base, 'data')

  def get_target_folder(self, name):
    return os.path.join(self._base, name)

  def save_pickle(self, data, fn, folder, subfolder_path=None,
                  compressed=False, verbose=True, locking=True):
    dst = self.get_target_folder(folder)
    if subfolder_path:
      dst = os.path.join(dst, subfolder_path)
    os.makedirs(dst, exist_ok=True)
    path = os.path.join(dst, fn)
    with open(path, 'wb') as f:
      pickle.dump(data, f)
    return path

  def load_pickle(self, fn, folder, subfolder_path=None,
                  decompress=False, verbose=True, locking=True):
    src = self.get_target_folder(folder)
    if subfolder_path:
      src = os.path.join(src, subfolder_path)
    path = os.path.join(src, fn)
    if not os.path.isfile(path):
      return None
    with open(path, 'rb') as f:
      return pickle.load(f)


class _TestPlugin(_DiskAPIMixin):
  """
  Minimal plugin-like class combining the diskapi mixin with the identity
  attributes it reads via getattr (from BasePluginExecutor in production).
  """

  def __init__(self, logger, stream_id='pipe', instance_id='inst'):
    super().__init__()
    self.log = logger
    self._stream_id = stream_id
    self.cfg_instance_id = instance_id
    self.warnings = []
    self.P_calls = []

  def P(self, msg, color=None, **kwargs):
    self.P_calls.append(msg)
    if 'DEPRECATION' in str(msg):
      self.warnings.append(msg)

  def sanitize_name(self, name):
    import re
    return re.sub(r'[^\w\.-]', '_', name)

  def _safe_path_component(self, raw):
    s = self.sanitize_name(str(raw))
    if s in ('', '.', '..'):
      s = '_'
    return s

  def _get_instance_data_subfolder(self):
    sid = self._safe_path_component(self._stream_id)
    iid = self._safe_path_component(self.cfg_instance_id)
    return 'pipelines_data/{}/{}'.format(sid, iid)

  def get_data_folder(self):
    return self.log.get_data_folder()


class _BareMixinPlugin(_DiskAPIMixin):
  """
  Diskapi mixin user WITHOUT the BasePluginExecutor identity attributes.
  Used to verify no-plugin-context degradation keeps pre-refactor behavior.
  """

  def __init__(self, logger):
    super().__init__()
    self.log = logger

  def sanitize_name(self, name):
    import re
    return re.sub(r'[^\w\.-]', '_', name)


class SanitizationTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix='diskapi_san_')
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

  def _make_plugin(self, stream_id, instance_id):
    return _TestPlugin(_FakeLogger(self.tmp), stream_id, instance_id)

  def test_dot_dot_instance_id_becomes_underscore(self):
    p = self._make_plugin('pipe', '..')
    self.assertEqual(p._get_instance_data_subfolder(), 'pipelines_data/pipe/_')

  def test_single_dot_instance_id_becomes_underscore(self):
    p = self._make_plugin('pipe', '.')
    self.assertEqual(p._get_instance_data_subfolder(), 'pipelines_data/pipe/_')

  def test_empty_instance_id_becomes_underscore(self):
    p = self._make_plugin('pipe', '')
    self.assertEqual(p._get_instance_data_subfolder(), 'pipelines_data/pipe/_')

  def test_slash_in_stream_id_is_replaced(self):
    p = self._make_plugin('a/b', 'inst')
    # `/` → `_`, so `a/b` → `a_b`. Still a single safe directory component.
    sub = p._get_instance_data_subfolder()
    self.assertEqual(sub, 'pipelines_data/a_b/inst')

  def test_traversal_attempt_sanitized(self):
    p = self._make_plugin('pipe', '../../../../tmp/evil')
    sub = p._get_instance_data_subfolder()
    # Slashes become _, dots are preserved as literal name chars.
    self.assertEqual(sub, 'pipelines_data/pipe/.._.._.._.._tmp_evil')
    # Resolved under the data folder must remain inside pipelines_data/
    full = os.path.join(p.get_data_folder(), sub)
    self.assertTrue(
      os.path.realpath(full).startswith(
        os.path.realpath(os.path.join(p.get_data_folder(), 'pipelines_data'))
      ),
      f'resolved path escaped pipelines_data: {os.path.realpath(full)}',
    )


class HelpersTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix='diskapi_helpers_')
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.p = _TestPlugin(_FakeLogger(self.tmp))

  def test_get_instance_data_root_in_plugin_context(self):
    self.assertEqual(self.p._get_instance_data_root(), 'pipelines_data/pipe/inst')

  def test_get_plugin_absolute_base(self):
    base = self.p._get_plugin_absolute_base()
    self.assertEqual(base, os.path.join(self.p.get_data_folder(), 'pipelines_data/pipe/inst'))

  def test_resolve_data_subfolder_default(self):
    self.assertEqual(
      self.p._resolve_data_subfolder(),
      'pipelines_data/pipe/inst/plugin_data',
    )

  def test_resolve_data_subfolder_sibling(self):
    self.assertEqual(
      self.p._resolve_data_subfolder('logs'),
      'pipelines_data/pipe/inst/logs',
    )

  def test_resolve_data_subfolder_no_plugin_context(self):
    bare = _BareMixinPlugin(_FakeLogger(self.tmp))
    self.assertIsNone(bare._get_instance_data_root())
    self.assertIsNone(bare._get_plugin_absolute_base())
    self.assertIsNone(bare._resolve_data_subfolder())
    self.assertEqual(bare._resolve_data_subfolder('anything'), 'anything')


class PickleSaveLoadTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix='diskapi_save_')
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.p = _TestPlugin(_FakeLogger(self.tmp))

  def _instance_path(self, *parts):
    return os.path.join(
      self.p.get_data_folder(), 'pipelines_data', 'pipe', 'inst', *parts,
    )

  def test_save_auto_routes_to_plugin_data(self):
    self.p.diskapi_save_pickle_to_data({'k': 1}, 'state.pkl')
    self.assertTrue(os.path.isfile(self._instance_path('plugin_data', 'state.pkl')))

  def test_save_with_subfolder_routes_to_sibling(self):
    self.p.diskapi_save_pickle_to_data([1, 2, 3], 'logs.pkl', subfolder='logs')
    self.assertTrue(os.path.isfile(self._instance_path('logs', 'logs.pkl')))
    # Must NOT end up in plugin_data/logs/
    self.assertFalse(os.path.isfile(self._instance_path('plugin_data', 'logs', 'logs.pkl')))

  def test_save_load_roundtrip(self):
    self.p.diskapi_save_pickle_to_data({'k': 'v'}, 'rt.pkl')
    self.assertEqual(self.p.diskapi_load_pickle_from_data('rt.pkl'), {'k': 'v'})

  def test_load_nonexistent_returns_none_no_warning(self):
    self.p.warnings = []
    self.assertIsNone(self.p.diskapi_load_pickle_from_data('missing.pkl'))
    self.assertEqual(self.p.warnings, [])

  def test_load_flat_fallback_with_deprecation(self):
    # Pre-create a legacy flat file
    data_folder = self.p.get_data_folder()
    flat_path = os.path.join(data_folder, 'legacy.pkl')
    with open(flat_path, 'wb') as f:
      pickle.dump({'legacy': True}, f)
    # New-path copy doesn't exist → should fall back
    self.p.warnings = []
    obj = self.p.diskapi_load_pickle_from_data('legacy.pkl')
    self.assertEqual(obj, {'legacy': True})
    self.assertTrue(any('DEPRECATION' in w for w in self.p.warnings),
                    f'expected deprecation warning, got {self.p.warnings!r}')

  def test_load_with_subfolder_does_not_fallback(self):
    data_folder = self.p.get_data_folder()
    flat_path = os.path.join(data_folder, 'x.pkl')
    with open(flat_path, 'wb') as f:
      pickle.dump({'flat': True}, f)
    # Caller passes a subfolder → no fallback; returns None
    self.p.warnings = []
    self.assertIsNone(self.p.diskapi_load_pickle_from_data('x.pkl', subfolder='logs'))
    self.assertEqual(self.p.warnings, [])


class IsolationTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix='diskapi_iso_')
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.p = _TestPlugin(_FakeLogger(self.tmp))

  def test_cross_plugin_save_warns_but_succeeds(self):
    self.p.warnings = []
    # Target another plugin's folder via ../ — still within cache root.
    self.p.diskapi_save_pickle_to_data(
      {'sneaky': True}, 'x.pkl',
      subfolder='../other_stream/other_inst/plugin_data',
    )
    self.assertTrue(any('DEPRECATION' in w for w in self.p.warnings),
                    f'expected tier-2 warning, got {self.p.warnings!r}')

  def test_save_traversal_out_of_cache_raises(self):
    # Enough `..` segments to traverse out of any reasonable cache root.
    # After realpath resolution, the path ends up outside the logger base →
    # tier-1 rejects.
    deep_escape = '../' * 40 + 'tmp_escape'
    with self.assertRaises(AssertionError):
      self.p.diskapi_save_pickle_to_data({}, 'evil.pkl', subfolder=deep_escape)

  def test_restricted_location_rejected(self):
    # With a bare-mixin plugin (no plugin context), subfolder='../_bin'
    # resolves (via realpath) to <base>/_bin — one of RESTRICTED_LOCATIONS.
    bare = _BareMixinPlugin(_FakeLogger(self.tmp))
    with self.assertRaises(AssertionError):
      bare.diskapi_save_pickle_to_data({}, 'secret.pkl', subfolder='../_bin')


class BareContextTests(unittest.TestCase):
  """Outside a plugin context, diskapi methods keep pre-refactor behavior."""

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix='diskapi_bare_')
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.p = _BareMixinPlugin(_FakeLogger(self.tmp))

  def test_save_load_without_plugin_context_roundtrip(self):
    self.p.diskapi_save_pickle_to_data({'x': 1}, 'plain.pkl')
    self.assertEqual(self.p.diskapi_load_pickle_from_data('plain.pkl'), {'x': 1})

  def test_save_lands_in_flat_data_folder(self):
    self.p.diskapi_save_pickle_to_data({'x': 1}, 'flat.pkl')
    self.assertTrue(os.path.isfile(os.path.join(self.p.log.get_data_folder(), 'flat.pkl')))


if __name__ == '__main__':
  unittest.main()
