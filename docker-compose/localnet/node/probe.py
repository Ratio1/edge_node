"""
In-process metrics sampler for localnet nodes (test bed only).

The sampler measures the same things in the same way on every code version,
so an old and a new node can be compared without relying on log lines that
only one of them prints. It never changes what the node does: it counts the
inputs handed to each plugin, reads public counters of the plugins and of
the process, and appends one JSON line per period to a file.

What is recorded per plugin instance
------------------------------------
recv      inputs handed to the plugin by the dispatcher (``add_inputs`` calls)
dropped   inputs that pushed the oldest queued input out of a full queue
queue     inputs waiting right now
qmax      queue capacity
handled   recv - dropped - queue
hz        plugin loop rate as the plugin reports it
iter      loop iterations so far
errors    plugin loop exceptions so far
pn, pm    calls of the plugin's ``process`` so far and their mean wall time in seconds, from the
          plugin's own ``process`` timer (the core times every call while its logger runs with
          DEBUG; both None otherwise), so a reader gets the mean process time of any window

Per sample, besides process and control-group counters: ``main_iter``, the node's main-loop iterations so
far, and two readings of the oracle-only secret: ``osec_env`` (its variable is in this process's ``os.environ``)
and ``osec`` (``osec_check`` of the value the SDK holds in memory, None when it holds none, ``"n/a"`` for an SDK
without the holder). The period is ``R1_LOCALNET_PROBE_PERIOD`` seconds (default 5; ``init --probe-period``).
"""

# SHA-256 of the check of the oracle-only secret (osec_check).
import hashlib
import json
import os
import threading
import time


def _read_proc_status():
  res = {}
  try:
    with open('/proc/self/status', 'rt') as fh:
      for line in fh:
        if line.startswith(('VmRSS:', 'VmHWM:', 'Threads:')):
          key, val = line.split(':', 1)
          res[key] = int(val.strip().split()[0])
  except Exception:
    pass
  return res


def _read_cgroup():
  # The whole container (node process, web servers, managers), not only this process.
  res = {}
  try:
    with open('/sys/fs/cgroup/memory.current', 'rt') as fh:
      res['cg_mem'] = int(fh.read().strip())
    with open('/sys/fs/cgroup/cpu.stat', 'rt') as fh:
      for line in fh:
        key, _, val = line.partition(' ')
        if key in ('usage_usec', 'throttled_usec'):
          res['cg_' + key] = int(val)
  except Exception:
    pass
  return res


# The seed variable of the oracle-only secret (the SDK's ``dAuth.DAUTH_ORACLE_SECRET_ENV_KEY``, from SDK 3.5.72).
ORACLE_SECRET_ENV = 'EE_ORACLE_R1FS_SECRET'


def osec_check(value):
  """
  Oracle secret check: a short hash of an oracle-only secret, the same as the host tool's ``lnlib.common.osec_check``.

  Kept here because the probe runs inside the node process and imports nothing from the tool's packages.

  Parameters
  ----------
  value : str
    The secret.

  Returns
  -------
  str
    12 lowercase hex characters.

  Examples
  --------
  >>> len(osec_check('ab' * 32))
  12
  """
  # SHA-256 of a fixed context and the value, cut to 48 bits, as the host computes it.
  return hashlib.sha256(b'localnet-osec-check:' + value.encode()).hexdigest()[:12]


def _oracle_secret_state():
  """
  Oracle secret state: where this node process keeps the oracle-only secret, read from inside the process.

  Returns
  -------
  dict
    ``osec_env``: True when the variable is in ``os.environ`` (a seed's process before its engine build, or a node
    whose SDK never removes it); ``osec``: ``osec_check`` of the value the SDK holds in memory, None when it holds
    none, or ``"n/a"`` when the SDK has no holder (the previous release).

  Examples
  --------
  >>> _oracle_secret_state()   # a worker on SDK 3.5.72
  {'osec_env': False, 'osec': None}
  """
  # The SDK's engine class, from the overlay the node runs (already imported by the node at this point).
  from ratio1.bc.base import BaseBlockEngine
  # The reader of the in-memory holder; an SDK of the previous release has none.
  reader = getattr(BaseBlockEngine, 'oracle_secret', None)
  # The value this process holds, never written anywhere: only its check is.
  held = reader() if reader is not None else None
  # The variable's presence and the check of the held value.
  return {'osec_env': ORACLE_SECRET_ENV in os.environ,
          'osec': 'n/a' if reader is None else (None if held is None else osec_check(held))}


def _open_fds():
  try:
    return len(os.listdir('/proc/self/fd'))
  except Exception:
    return None


class Probe(threading.Thread):
  def __init__(self, out_path, period=5.0):
    super().__init__(name='localnet_probe', daemon=True)
    self.out_path = out_path
    self.period = float(period)
    self.eng = None
    self._errors = 0
    self._t0 = time.time()
    return

  # -- wiring ---------------------------------------------------------------

  def install_counters(self):
    """Count dispatcher hand-offs per plugin instance at class level."""
    from naeural_core.business.base.base_plugin_biz import BasePluginExecutor
    original = BasePluginExecutor.add_inputs
    if getattr(original, '_localnet_wrapped', False):
      return

    def add_inputs(plugin, inp):
      try:
        if inp:
          queue = plugin.__dict__.get('_BasePluginExecutor__upstream_inputs_deque')
          if queue is not None and not plugin.is_outside_working_hours:
            stats = plugin.__dict__.get('_localnet_stats')
            if stats is None:
              stats = plugin.__dict__['_localnet_stats'] = [0, 0]
            stats[0] += 1
            if queue.maxlen is not None and len(queue) >= queue.maxlen:
              stats[1] += 1
      except Exception:
        pass
      return original(plugin, inp)

    add_inputs._localnet_wrapped = True
    BasePluginExecutor.add_inputs = add_inputs
    return

  def attach(self, eng):
    self.eng = eng
    return

  # -- sampling -------------------------------------------------------------

  def _plugins(self):
    """
    One sample of every running plugin instance of the node.

    Reads public attributes and counters only (queues, loop rate, iterations, the plugin's ``process`` timer); it
    never calls into a plugin, so the node does the same with and without the probe.

    Returns
    -------
    dict
      ``<stream>|<signature>|<instance>`` -> the fields listed in the module docstring (``recv`` ... ``pm``); a
      plugin whose attributes could not be read is left out and counted in ``probe_errors``.

    Examples
    --------
    >>> sorted(Probe('/out/probe.jsonl')._plugins())
    []
    """
    res = {}
    manager = getattr(self.eng, '_business_manager', None)
    if manager is None:
      return res
    instances = getattr(manager, '_dct_current_instances', None) or {}
    for _hash, plugin in list(instances.items()):
      try:
        signature = str(getattr(plugin, '_signature', None) or plugin.__class__.__name__)
        instance = str(getattr(plugin, 'cfg_instance_id', '') or '')
        stream = str(getattr(plugin, '_stream_id', '') or '')
        stats = plugin.__dict__.get('_localnet_stats') or [0, 0]
        queue = plugin.__dict__.get('_BasePluginExecutor__upstream_inputs_deque')
        qlen = len(queue) if queue is not None else 0
        row = {
          'recv': stats[0],
          'dropped': stats[1],
          'queue': qlen,
          'qmax': queue.maxlen if queue is not None else None,
          'handled': max(0, stats[0] - stats[1] - qlen),
          'hz': getattr(plugin, 'actual_plugin_resolution', None),
          'iter': getattr(plugin, 'current_process_iteration', None),
          'errors': getattr(plugin, 'n_plugin_exceptions', None),
        }
        # The plugin's own "process" timer: the core's logger keeps it per plugin section, with the number of
        # timed calls and their running mean (an empty dict when the logger does not time, or before the first call).
        timer = ((getattr(getattr(plugin, 'log', None), 'timers', None) or {}).get(getattr(plugin, '_timers_section', None)) or {}).get('process') or {}
        # Calls so far and their mean wall time (s): a window's mean is (pm2 * pn2 - pm1 * pn1) / (pn2 - pn1).
        row.update(pn=timer.get('COUNT'), pm=timer.get('MEAN'))
        res['{}|{}|{}'.format(stream, signature, instance)] = row
      except Exception:
        self._errors += 1
    return res

  def sample(self):
    """
    One sample of the process, its control group and, once the node is attached, its plugins and main loop.

    Returns
    -------
    dict
      ``t`` (epoch seconds), ``up`` (seconds since the probe started), ``cpu`` (process CPU seconds), open file
      descriptors, process and control-group counters and, with the node attached, ``plugins`` (per plugin
      instance: inputs, queue, loop rate and iterations), ``main_iter`` (main-loop iterations so far) and the
      oracle-only secret's ``osec_env`` and ``osec`` (``_oracle_secret_state``).

    Examples
    --------
    >>> Probe('/out/probe.jsonl').sample()['up'] >= 0
    True
    """
    row = {
      't': round(time.time(), 3),
      'up': round(time.time() - self._t0, 1),
      'cpu': round(time.process_time(), 2),
      'fds': _open_fds(),
      'probe_errors': self._errors,
    }
    row.update(_read_proc_status())
    row.update(_read_cgroup())
    if self.eng is not None:
      row['plugins'] = self._plugins()
      # Iterations of the node's main loop so far (the "itr" of its heartbeat line), so a reader can find the
      # pauses of the main loop at the probe's resolution instead of the heartbeat line's 20 s average.
      row['main_iter'] = self.eng._main_loop_counts['ITER']
      # Where the oracle-only secret is kept, from the node's own Python: in os.environ and in the SDK's holder.
      row.update(_oracle_secret_state())
    return row

  def run(self):
    os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
    while True:
      time.sleep(self.period)
      try:
        row = self.sample()
        with open(self.out_path, 'at') as fh:
          fh.write(json.dumps(row, separators=(',', ':')) + '\n')
      except Exception:
        self._errors += 1
    return
