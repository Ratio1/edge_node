import os


if os.environ.get("EE_ENABLE_NETMON_API_PROBE", "").strip().lower() not in {"1", "true", "yes"}:
  raise RuntimeError("NETMON_API_PROBE is disabled outside the explicit local ECOMMS testbed.")


from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = "0.1.0"


_CONFIG = {
  **BasePlugin.CONFIG,

  "PORT": 3000,
  "ASSETS": None,
  "TEMPLATE": "basic_server",
  "TUNNEL_ENGINE_ENABLED": False,
  "NGROK_ENABLED": False,
  "NGROK_USE_API": False,
  "PROCESS_DELAY": 0,
  "REQUEST_TIMEOUT": 30,
  "LOG_REQUESTS": False,
  "DEBUG_TIMINGS": False,
  "PROFILE_LOG_PER_REQUEST": False,

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG["VALIDATION_RULES"],
  },
}


class NetmonApiProbePlugin(BasePlugin):
  """
  Local-only ECOMMS testbed probe for live NetworkMonitor API behavior.

  This local plugin is intentionally wired only by `.config_startup_comms.json`. It
  exposes read-only snapshots of the actual in-process ``self.netmon`` methods
  so the Docker testbed can compare direct-heartbeat and summary-backed paths
  without adding diagnostic behavior to production branches.
  """
  CONFIG = _CONFIG

  def on_init(self):
    super(NetmonApiProbePlugin, self).on_init()
    self.P("NETMON_API_PROBE is enabled for the local ECOMMS testbed only.", color="y")
    return

  def _json_safe(self, value):
    if value is None or isinstance(value, (str, int, float, bool)):
      return value
    if isinstance(value, dict):
      return {
        str(self._json_safe(k)): self._json_safe(v)
        for k, v in value.items()
      }
    if isinstance(value, (list, tuple, set)):
      return [self._json_safe(v) for v in value]
    return str(value)

  def _call_netmon(self, name, callback):
    try:
      return {
        "ok": True,
        "value": self._json_safe(callback()),
      }
    except Exception as exc:
      return {
        "ok": False,
        "error": str(exc),
        "error_type": exc.__class__.__name__,
        "method": name,
      }

  def _resolve_target(self, target_eeid=None, addr=None):
    resolved_addr = addr
    if resolved_addr is None and target_eeid is not None:
      resolved_addr = self.netmon.network_node_addr(target_eeid, include_prefix=True)
    if resolved_addr is None:
      resolved_addr = self.node_addr

    eeid = self._call_netmon(
      "network_node_eeid",
      lambda: self.netmon.network_node_eeid(resolved_addr),
    )
    return resolved_addr, eeid

  @BasePlugin.endpoint(method="get", require_token=False)
  def probe_nodes(self):
    return {
      "ok": True,
      "observer": {
        "eeid": self.node_id,
        "addr": self.node_addr,
        "is_supervisor": self.is_supervisor_node,
      },
      "all_nodes": self._call_netmon("all_nodes", lambda: self.netmon.all_nodes),
      "available_nodes": self._call_netmon("available_nodes", lambda: self.netmon.available_nodes),
      "accessible_nodes": self._call_netmon("accessible_nodes", lambda: self.netmon.accessible_nodes),
      "known_nodes": self._call_netmon("network_known_nodes", self.netmon.network_known_nodes),
      "nodes_status": self._call_netmon("network_nodes_status", self.netmon.network_nodes_status),
    }

  @BasePlugin.endpoint(method="get", require_token=False)
  def probe_node(self, target_eeid=None, addr=None):
    target_addr, eeid = self._resolve_target(target_eeid=target_eeid, addr=addr)
    return {
      "ok": True,
      "observer": {
        "eeid": self.node_id,
        "addr": self.node_addr,
        "is_supervisor": self.is_supervisor_node,
      },
      "target": {
        "requested_eeid": target_eeid,
        "addr": target_addr,
        "addr_from_eeid_prefixed": self._call_netmon(
          "network_node_addr_prefixed",
          lambda: self.netmon.network_node_addr(target_eeid, include_prefix=True) if target_eeid else None,
        ),
        "addr_from_eeid_unprefixed": self._call_netmon(
          "network_node_addr_unprefixed",
          lambda: self.netmon.network_node_addr(target_eeid, include_prefix=False) if target_eeid else None,
        ),
        "eeid": eeid,
      },
      "methods": {
        "info_available": self._call_netmon(
          "network_node_info_available",
          lambda: self.netmon.network_node_info_available(target_addr),
        ),
        "status": self._call_netmon(
          "network_node_status",
          lambda: self.netmon.network_node_status(target_addr, min_uptime=0),
        ),
        "simple_status": self._call_netmon(
          "network_node_simple_status",
          lambda: self.netmon.network_node_simple_status(target_addr),
        ),
        "last_seen_sec": self._call_netmon(
          "network_node_last_seen",
          lambda: self.netmon.network_node_last_seen(target_addr, as_sec=True),
        ),
        "is_online_direct_default": self._call_netmon(
          "network_node_is_online",
          lambda: self.netmon.network_node_is_online(target_addr),
        ),
        "is_online_summary_allowed": self._call_netmon(
          "network_node_is_online_allow_summary",
          lambda: self.netmon.network_node_is_online(target_addr, allow_summary=True),
        ),
        "is_available": self._call_netmon(
          "network_node_is_available",
          lambda: self.netmon.network_node_is_available(target_addr),
        ),
        "is_accessible": self._call_netmon(
          "network_node_is_accessible",
          lambda: self.netmon.network_node_is_accessible(target_addr),
        ),
        "last_heartbeat": self._call_netmon(
          "network_node_last_heartbeat",
          lambda: self.netmon.network_node_last_heartbeat(target_addr),
        ),
        "history": self._call_netmon(
          "network_node_history",
          lambda: self.netmon.network_node_history(target_addr, minutes=60, hb_step=1),
        ),
        "today_heartbeats": self._call_netmon(
          "network_node_today_heartbeats",
          lambda: list(self.netmon.network_node_today_heartbeats(target_addr)),
        ),
        "pipelines": self._call_netmon(
          "network_node_pipelines",
          lambda: self.netmon.network_node_pipelines(target_addr),
        ),
        "apps": self._call_netmon(
          "network_node_apps",
          lambda: self.netmon.network_node_apps(target_addr),
        ),
        "is_supervisor": self._call_netmon(
          "network_node_is_supervisor",
          lambda: self.netmon.network_node_is_supervisor(target_addr),
        ),
        "whitelist": self._call_netmon(
          "network_node_whitelist",
          lambda: self.netmon.network_node_whitelist(target_addr),
        ),
        "is_secured": self._call_netmon(
          "network_node_is_secured",
          lambda: self.netmon.network_node_is_secured(target_addr),
        ),
        "version": self._call_netmon(
          "network_node_version",
          lambda: self.netmon.network_node_version(target_addr),
        ),
        "py_ver": self._call_netmon(
          "network_node_py_ver",
          lambda: self.netmon.network_node_py_ver(target_addr),
        ),
        "remote_time": self._call_netmon(
          "network_node_remote_time",
          lambda: self.netmon.network_node_remote_time(target_addr),
        ),
        "deploy_type": self._call_netmon(
          "network_node_deploy_type",
          lambda: self.netmon.network_node_deploy_type(target_addr),
        ),
        "local_tz": self._call_netmon(
          "network_node_local_tz",
          lambda: self.netmon.network_node_local_tz(target_addr),
        ),
        "local_utc": self._call_netmon(
          "network_node_local_tz_utc",
          lambda: self.netmon.network_node_local_tz(target_addr, as_zone=False),
        ),
        "r1fs_id": self._call_netmon(
          "network_node_r1fs_id",
          lambda: self.netmon.network_node_r1fs_id(target_addr),
        ),
        "r1fs_online": self._call_netmon(
          "network_node_r1fs_online",
          lambda: self.netmon.network_node_r1fs_online(target_addr),
        ),
        "r1fs_relay": self._call_netmon(
          "network_node_r1fs_relay",
          lambda: self.netmon.network_node_r1fs_relay(target_addr),
        ),
        "comm_relay": self._call_netmon(
          "network_node_comm_relay",
          lambda: self.netmon.network_node_comm_relay(target_addr),
        ),
      },
    }
