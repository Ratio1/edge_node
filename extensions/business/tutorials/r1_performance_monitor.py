"""
R1 Performance Monitor Plugin - benchmarks CStore (ChainStore) performance:
write/read latency, cross-node propagation, throughput, and hash operation timings.

Pipeline config for deployment:

```json
{
    "NAME": "r1_perf_monitor",
    "TYPE": "Void",
    "PLUGINS": [{
        "SIGNATURE": "R1_PERFORMANCE_MONITOR",
        "INSTANCES": [{
            "INSTANCE_ID": "DEFAULT",
            "CHAINSTORE_PEERS": ["0xai_PEER_NODE_ADDRESS"]
        }]
    }]
}
```
"""

from collections import deque
from datetime import datetime as dt

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31236,
  'ASSETS': 'nothing',
  'ALLOW_EMPTY_INPUTS': True,
  'PROCESS_DELAY': 30,

  'BACKGROUND_EXPERIMENTS_ENABLED': False,
  'AUTO_EXPERIMENT_TYPES': ['write_latency', 'read_latency', 'round_trip', 'hash_ops'],
  'MAX_RESULTS': 1000,
  'PERF_HKEY': 'r1_perf_monitor',
  'PAYLOAD_SIZES': [10, 100, 1024, 10240, 102400],
  'BURST_COUNT': 20,
  'DEBUG': True,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

EXPERIMENT_DISPATCH = {
  'write_latency': '_run_write_latency',
  'read_latency': '_run_read_latency',
  'round_trip': '_run_round_trip',
  'hash_ops': '_run_hash_ops',
  'payload_size_sweep': '_run_payload_size_sweep',
  'throughput_burst': '_run_throughput_burst',
  'cross_node_propagation': '_run_cross_node_propagation',
}


class R1PerformanceMonitorPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self):
    super(R1PerformanceMonitorPlugin, self).on_init()
    self.__results = deque(maxlen=self.cfg_max_results)
    self.__background_enabled = self.cfg_background_experiments_enabled
    self.__auto_experiment_types = list(self.cfg_auto_experiment_types)
    self.__process_delay = self.cfg_process_delay
    self.__experiment_index = 0
    self.__start_time = self.time()
    self.__last_experiment = None
    self.__last_experiment_time = None
    self.P(f"R1PerformanceMonitorPlugin v{__VER__} started on {self.node_addr}")
    return

  # ---- Timing helpers ----

  def _timed_chainstore_set(self, key, value):
    start = self.time()
    success = False
    try:
      result = self.chainstore_set(key=key, value=value, debug=self.cfg_debug)
      success = bool(result)
    except Exception as e:
      self.P(f"chainstore_set error: {e}", color='r')
    latency_ms = (self.time() - start) * 1000
    return {
      'op_type': 'set',
      'key': key,
      'latency_ms': round(latency_ms, 3),
      'success': success,
      'payload_size_bytes': len(str(value).encode('utf-8')) if value is not None else 0,
    }

  def _timed_chainstore_get(self, key):
    start = self.time()
    success = False
    value = None
    try:
      value = self.chainstore_get(key=key, debug=self.cfg_debug)
      success = value is not None
    except Exception as e:
      self.P(f"chainstore_get error: {e}", color='r')
    latency_ms = (self.time() - start) * 1000
    return {
      'op_type': 'get',
      'key': key,
      'latency_ms': round(latency_ms, 3),
      'success': success,
      'value': value,
    }

  def _timed_chainstore_hset(self, hkey, key, value):
    start = self.time()
    success = False
    try:
      result = self.chainstore_hset(hkey=hkey, key=key, value=value, debug=self.cfg_debug)
      success = bool(result)
    except Exception as e:
      self.P(f"chainstore_hset error: {e}", color='r')
    latency_ms = (self.time() - start) * 1000
    return {
      'op_type': 'hset',
      'key': f"{hkey}.{key}",
      'latency_ms': round(latency_ms, 3),
      'success': success,
      'payload_size_bytes': len(str(value).encode('utf-8')) if value is not None else 0,
    }

  def _timed_chainstore_hget(self, hkey, key):
    start = self.time()
    success = False
    try:
      value = self.chainstore_hget(hkey=hkey, key=key, debug=self.cfg_debug)
      success = value is not None
    except Exception as e:
      self.P(f"chainstore_hget error: {e}", color='r')
    latency_ms = (self.time() - start) * 1000
    return {
      'op_type': 'hget',
      'key': f"{hkey}.{key}",
      'latency_ms': round(latency_ms, 3),
      'success': success,
    }

  def _timed_chainstore_hgetall(self, hkey):
    start = self.time()
    success = False
    result_data = None
    try:
      result_data = self.chainstore_hgetall(hkey=hkey, debug=self.cfg_debug)
      success = result_data is not None
    except Exception as e:
      self.P(f"chainstore_hgetall error: {e}", color='r')
    latency_ms = (self.time() - start) * 1000
    return {
      'op_type': 'hgetall',
      'key': hkey,
      'latency_ms': round(latency_ms, 3),
      'success': success,
      'result_data': result_data,
    }

  # ---- Summary computation ----

  def _compute_summary(self, operations):
    latencies = [op['latency_ms'] for op in operations if 'latency_ms' in op]
    if not latencies:
      return {
        'min_ms': 0, 'max_ms': 0, 'mean_ms': 0,
        'p50_ms': 0, 'p95_ms': 0, 'p99_ms': 0,
        'total_ops': 0, 'success_rate': 0,
      }
    sorted_lats = sorted(latencies)
    n = len(sorted_lats)
    success_count = sum(1 for op in operations if op.get('success', False))
    return {
      'min_ms': round(sorted_lats[0], 3),
      'max_ms': round(sorted_lats[-1], 3),
      'mean_ms': round(sum(sorted_lats) / n, 3),
      'p50_ms': round(sorted_lats[int(n * 0.50)], 3),
      'p95_ms': round(sorted_lats[min(int(n * 0.95), n - 1)], 3),
      'p99_ms': round(sorted_lats[min(int(n * 0.99), n - 1)], 3),
      'total_ops': n,
      'success_rate': round(success_count / len(operations), 4) if operations else 0,
    }

  def _store_result(self, result):
    self.__results.append(result)
    return

  def _make_result_envelope(self, experiment_type, operations):
    summary = self._compute_summary(operations)
    # Remove internal fields from operations before storing
    clean_ops = []
    for op in operations:
      clean_op = {k: v for k, v in op.items() if k not in ('value', 'result_data')}
      clean_ops.append(clean_op)
    result = {
      'experiment_type': experiment_type,
      'timestamp': dt.now().isoformat(),
      'node_id': self.node_id,
      'node_addr': self.node_addr,
      'operations': clean_ops,
      'summary': summary,
    }
    self._store_result(result)
    self.__last_experiment = experiment_type
    self.__last_experiment_time = dt.now().isoformat()
    return result

  # ---- Experiment runners ----

  def _run_write_latency(self, params=None):
    key = f"perf_w_{self.uuid(8)}"
    value = f"test_value_{self.uuid(8)}"
    op = self._timed_chainstore_set(key, value)
    return self._make_result_envelope('write_latency', [op])

  def _run_read_latency(self, params=None):
    key = f"perf_r_{self.uuid(8)}"
    value = f"test_value_{self.uuid(8)}"
    # Write first (untimed for this experiment)
    self.chainstore_set(key=key, value=value, debug=self.cfg_debug)
    # Timed read
    op = self._timed_chainstore_get(key)
    return self._make_result_envelope('read_latency', [op])

  def _run_round_trip(self, params=None):
    key = f"perf_rt_{self.uuid(8)}"
    value = f"test_value_{self.uuid(8)}"
    write_op = self._timed_chainstore_set(key, value)
    read_op = self._timed_chainstore_get(key)
    # Verify correctness
    read_value = read_op.pop('value', None)
    if read_value != value:
      read_op['details'] = f"value mismatch: expected={value}, got={read_value}"
      read_op['success'] = False
    else:
      read_op['details'] = 'value verified'
    return self._make_result_envelope('round_trip', [write_op, read_op])

  def _run_hash_ops(self, params=None):
    hkey = self.cfg_perf_hkey
    field_key = f"perf_h_{self.uuid(8)}"
    field_value = f"hash_value_{self.uuid(8)}"
    hset_op = self._timed_chainstore_hset(hkey, field_key, field_value)
    hget_op = self._timed_chainstore_hget(hkey, field_key)
    hgetall_op = self._timed_chainstore_hgetall(hkey)
    # Remove internal data from hgetall
    hgetall_op.pop('result_data', None)
    return self._make_result_envelope('hash_ops', [hset_op, hget_op, hgetall_op])

  def _run_payload_size_sweep(self, params=None):
    sizes = self.cfg_payload_sizes
    if params and 'sizes' in params:
      sizes = params['sizes']
    operations = []
    for size in sizes:
      key = f"perf_ps_{size}_{self.uuid(6)}"
      value = 'x' * size
      op = self._timed_chainstore_set(key, value)
      op['payload_size_bytes'] = size
      operations.append(op)
    return self._make_result_envelope('payload_size_sweep', operations)

  def _run_throughput_burst(self, params=None):
    count = self.cfg_burst_count
    if params and 'count' in params:
      count = params['count']
    operations = []
    burst_start = self.time()
    for i in range(count):
      key = f"perf_tb_{self.uuid(6)}_{i}"
      value = f"burst_{i}"
      op = self._timed_chainstore_set(key, value)
      operations.append(op)
    burst_elapsed = self.time() - burst_start
    ops_per_sec = count / burst_elapsed if burst_elapsed > 0 else 0
    result = self._make_result_envelope('throughput_burst', operations)
    result['summary']['burst_elapsed_sec'] = round(burst_elapsed, 3)
    result['summary']['ops_per_sec'] = round(ops_per_sec, 2)
    return result

  def _run_cross_node_propagation(self, params=None):
    hkey = self.cfg_perf_hkey
    now = self.time()
    beacon_key = f"beacon_{self.node_addr}"
    beacon_value = {
      'timestamp': now,
      'node_id': self.node_id,
      'node_addr': self.node_addr,
    }
    # Write our beacon
    write_op = self._timed_chainstore_hset(hkey, beacon_key, beacon_value)
    # Read all beacons
    hgetall_op = self._timed_chainstore_hgetall(hkey)
    all_beacons = hgetall_op.pop('result_data', None) or {}
    operations = [write_op, hgetall_op]
    # Check for other nodes' beacons
    for bkey, bval in all_beacons.items():
      if not bkey.startswith('beacon_'):
        continue
      if bkey == beacon_key:
        continue
      if isinstance(bval, dict) and 'timestamp' in bval:
        delay_ms = (now - bval['timestamp']) * 1000
        operations.append({
          'op_type': 'propagation_check',
          'key': bkey,
          'latency_ms': round(abs(delay_ms), 3),
          'success': True,
          'details': f"beacon from {bval.get('node_id', 'unknown')}, age={round(abs(delay_ms))}ms",
        })
    return self._make_result_envelope('cross_node_propagation', operations)

  # ---- Peers info helper ----

  def _get_peers_info(self):
    self_addr = self.node_addr
    configured_peers = list(self.cfg_chainstore_peers or [])
    try:
      whitelist_peers = list(self.bc.get_whitelist(with_prefix=True))
    except Exception:
      whitelist_peers = []
    # Check online status for all candidate peers (configured + whitelist)
    all_candidates = set(configured_peers) | set(whitelist_peers)
    all_candidates.discard(self_addr)
    online_peers = []
    for peer in all_candidates:
      try:
        if self.netmon.network_node_is_online(peer):
          online_peers.append(peer)
      except Exception:
        pass
    # Effective peers = union of configured + online whitelist, minus self
    effective = set(configured_peers) | set(online_peers)
    effective.discard(self_addr)
    effective_peers = sorted(effective)
    total_effective = len(effective_peers)
    return {
      'self_addr': self_addr,
      'self_alias': self.node_id,
      'configured_peers': configured_peers,
      'whitelist_peers': whitelist_peers,
      'online_peers': sorted(online_peers),
      'effective_peers': effective_peers,
      'total_effective': total_effective,
      'min_confirmations': total_effective // 2 + 1,
    }

  # ---- HTTP Endpoints ----

  @BasePlugin.endpoint(method='get', require_token=False)
  def get_status(self):
    """Get plugin status, node info, background state, result count."""
    return {
      'ok': True,
      'plugin': 'R1PerformanceMonitor',
      'version': __VER__,
      'node_id': self.node_id,
      'node_addr': self.node_addr,
      'ee_ver': str(getattr(self, 'ee_ver', '')),
      'evm_network': str(getattr(self, 'evm_network', '')),
      'background_enabled': self.__background_enabled,
      'process_delay': self.__process_delay,
      'auto_experiment_types': self.__auto_experiment_types,
      'total_results': len(self.__results),
      'uptime_seconds': round(self.time() - self.__start_time, 1),
      'last_experiment': self.__last_experiment,
      'last_experiment_time': self.__last_experiment_time,
    }

  @BasePlugin.endpoint(method='get', require_token=False)
  def get_peers(self):
    """Returns chainstore peers info."""
    return self._get_peers_info()

  @BasePlugin.endpoint(method='post', require_token=False)
  def run_experiment(self, experiment_type: str, params: dict = None):
    """Trigger an experiment and return the result."""
    if experiment_type not in EXPERIMENT_DISPATCH:
      return {
        'error': f"Unknown experiment type: {experiment_type}",
        'available_types': list(EXPERIMENT_DISPATCH.keys()),
      }
    method_name = EXPERIMENT_DISPATCH[experiment_type]
    method = getattr(self, method_name)
    result = method(params=params)
    return result

  @BasePlugin.endpoint(method='get', require_token=False)
  def get_results(self, experiment_type: str = None, limit: int = 50, since: str = None):
    """Get stored results with optional filters."""
    results = list(self.__results)
    if experiment_type:
      results = [r for r in results if r['experiment_type'] == experiment_type]
    if since:
      results = [r for r in results if r['timestamp'] >= since]
    # Most recent first
    results = list(reversed(results))
    if limit:
      results = results[:limit]
    return {
      'results': results,
      'total': len(results),
      'filtered_by': {
        'experiment_type': experiment_type,
        'limit': limit,
        'since': since,
      },
    }

  @BasePlugin.endpoint(method='get', require_token=False)
  def get_summary(self):
    """Aggregated stats grouped by experiment type."""
    grouped = {}
    for result in self.__results:
      exp_type = result['experiment_type']
      if exp_type not in grouped:
        grouped[exp_type] = []
      grouped[exp_type].extend(result.get('operations', []))
    summary = {}
    for exp_type, operations in grouped.items():
      summary[exp_type] = self._compute_summary(operations)
      summary[exp_type]['experiment_count'] = sum(
        1 for r in self.__results if r['experiment_type'] == exp_type
      )
    return summary

  @BasePlugin.endpoint(method='post', require_token=False)
  def configure(self, background_enabled: bool = None, process_delay: int = None, auto_experiments: list = None):
    """Toggle background experiments and configure runtime parameters."""
    changes = {}
    if background_enabled is not None:
      self.__background_enabled = background_enabled
      changes['background_enabled'] = background_enabled
    if process_delay is not None:
      self.__process_delay = max(5, process_delay)
      changes['process_delay'] = self.__process_delay
    if auto_experiments is not None:
      valid = [e for e in auto_experiments if e in EXPERIMENT_DISPATCH]
      self.__auto_experiment_types = valid
      changes['auto_experiment_types'] = valid
    return {
      'ok': True,
      'changes': changes,
      'current': {
        'background_enabled': self.__background_enabled,
        'process_delay': self.__process_delay,
        'auto_experiment_types': self.__auto_experiment_types,
      },
    }

  @BasePlugin.endpoint(method='post', require_token=False)
  def reset(self):
    """Clear all accumulated results."""
    count = len(self.__results)
    self.__results.clear()
    self.__experiment_index = 0
    return {
      'ok': True,
      'cleared': count,
    }

  # ---- Background loop ----

  def process(self):
    if not self.__background_enabled:
      return

    # Write cross-node beacon
    hkey = self.cfg_perf_hkey
    beacon_key = f"beacon_{self.node_addr}"
    beacon_value = {
      'timestamp': self.time(),
      'node_id': self.node_id,
      'node_addr': self.node_addr,
    }
    self.chainstore_hset(hkey=hkey, key=beacon_key, value=beacon_value, debug=self.cfg_debug)

    # Run background experiment if enabled
    if self.__auto_experiment_types:
      exp_type = self.__auto_experiment_types[self.__experiment_index % len(self.__auto_experiment_types)]
      self.__experiment_index += 1
      method_name = EXPERIMENT_DISPATCH.get(exp_type)
      if method_name:
        method = getattr(self, method_name)
        self.P(f"Background experiment: {exp_type}")
        method()
    return
