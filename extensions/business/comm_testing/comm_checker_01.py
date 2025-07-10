from naeural_core.business.base.network_processor import NetworkProcessorPlugin as BasePlugin


_CONFIG = {
  **BasePlugin.CONFIG,

  "ACCEPT_SELF": True,
  "ALLOW_EMPTY_INPUTS": True,
  "SHOW_STATS_PERIOD": 4 * 60,  # seconds
  "MAX_MESSAGES_PER_SECOND": 10,  # Maximum messages per second to send
  "TRANSITION_DURATION": 60,  # seconds, how long to wait after changing the additional data size

  "ADDITIONAL_DATA_SIZES": [
    0,  # No additional data
    50000,  # 50 KB
  ],  # List of additional data sizes to use in the payloads
  "ADDITIONAL_DATA_SIZE_DURATION": 120,  # seconds, how long will a data size value be valid until changed

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG["VALIDATION_RULES"],
  }
}


NODES_DATA_MUTEX = "comm_checker_01_nodes_data_mutex"


class CommChecker01Plugin(BasePlugin):
  def on_init(self):
    self.nodes_data_per_additional_size = {}
    self.local_cnt = self.defaultdict(int)
    self.last_show_stats_ts = None
    self.last_payload_sent_ts = None
    self.start_ts = self.time()
    self.__last_additional_data_size = self.get_additional_data_sizes()[0]
    self.__transition_start_ts = None
    self.__transition_passed = True
    return

  def get_additional_data_sizes(self):
    return self.cfg_additional_data_sizes or [0]

  def get_transition_duration(self):
    return self.cfg_transition_duration or 0  # seconds

  def get_additional_data_size_duration(self):
    # 0 means the additional data size is not changing
    return self.cfg_additional_data_size_duration or 0  # seconds

  def register_payload(
      self, sender, payload,
      additional_data_size,
      payload_ts,
      current_ts,
  ):
    """
    Register the payload data from the sender.
    """
    if additional_data_size not in self.nodes_data_per_additional_size:
      self.nodes_data_per_additional_size[additional_data_size] = {}
    # endif new additional data size
    curr_nodes_data = self.nodes_data_per_additional_size[additional_data_size]
    if sender not in curr_nodes_data:
      curr_nodes_data[sender] = {
        "address": sender,
        "alias": payload.get(self.ct.PAYLOAD_DATA.EE_ID, "Unknown"),
        "received_payload_idxs": set(),
        "received_payload_ts": self.deque(maxlen=200),
        "received_payload_lps": self.deque(maxlen=200)
      }
    # endif new sender
    received_payload_idx = payload.get("PAYLOAD_IDX")
    if received_payload_idx is not None:
      curr_nodes_data[sender]["received_payload_idxs"].add(received_payload_idx)
      curr_nodes_data[sender]["received_payload_ts"].append(current_ts)
      elapsed = current_ts - payload_ts
      curr_nodes_data[sender]["received_payload_lps"].append(elapsed)
      # self.P(f"IDX {received_payload_idx} from {sender} took {elapsed:2f}s, ")
    # endif payload index
    return

  @BasePlugin.payload_handler()
  def handle_payload(self, payload):
    """
    Handle incoming payloads from the network.
    """
    sender = payload.get(self.ct.PAYLOAD_DATA.EE_SENDER)
    additional_data = payload.get("ADDITIONAL_DATA")
    payload_timestamp = payload.get("CHECK_PAYLOAD_TIMESTAMP")
    current_timestamp = self.time()
    if additional_data is not None and payload_timestamp is not None:
      additional_size = len(additional_data)
      with self.managed_lock_resource(NODES_DATA_MUTEX):
        self.register_payload(
          sender=sender,
          payload=payload,
          additional_data_size=additional_size,
          payload_ts=payload_timestamp,
          current_ts=current_timestamp,
        )
      # endwith managed lock
    return

  def handle_additional_data_change(
      self,
      last_value,
      current_value
  ):
    with self.managed_lock_resource(NODES_DATA_MUTEX):
      current_nodes_data = self.nodes_data_per_additional_size.get(current_value, {})
      nodes_addrs = list(current_nodes_data.keys())
      for node_addr in nodes_addrs:
        # No need to reset the indexes, since the counter is per additional data size.
        # current_nodes_data[node_addr]["received_payload_idxs"] = set()
        current_nodes_data[node_addr]["received_payload_ts"].clear()
        current_nodes_data[node_addr]["received_payload_lps"].clear()
      # endfor nodes
    # endwith managed lock
    return

  def should_send_payload(self):
    current_additional_data_size = self.get_additional_data_size()
    if current_additional_data_size != self.__last_additional_data_size:
      self.handle_additional_data_change(
        last_value=self.__last_additional_data_size,
        current_value=current_additional_data_size
      )
      self.__last_additional_data_size = current_additional_data_size
      self.__transition_start_ts = self.time()
      self.__transition_passed = False
      log_str = f"Changing additional data size to {self.__last_additional_data_size} bytes."
      log_str += f"Transition will pause payload sending for {self.get_transition_duration()} seconds."
      self.P(log_str)
    # endif additional data size changed

    if not self.__transition_passed:
      elapsed = self.time() - self.__transition_start_ts
      self.__transition_passed = (elapsed > self.get_transition_duration())
      if not self.__transition_passed:
        # self.P(f"In transition[elapsed:{elapsed:.2f}s], waiting for {self.get_transition_duration()} seconds before sending payloads.")
        return False
    # endif transition not passed yet

    max_per_second = self.cfg_max_messages_per_second or 0.0001
    return self.last_payload_sent_ts is None or (self.time() - self.last_payload_sent_ts) > (1 / max_per_second)

  def get_additional_data_size(self):
    elapsed = self.time() - self.start_ts
    full_interval_length = self.get_additional_data_size_duration() + self.get_transition_duration()
    if full_interval_length <= 0:
      return self.__last_additional_data_size
    additional_data_interval = int(elapsed / full_interval_length)
    additional_data_sizes = self.get_additional_data_sizes()
    curr_size = additional_data_sizes[additional_data_interval % len(additional_data_sizes)]
    return curr_size

  def maybe_send_payload(self):
    if self.should_send_payload():
      additional_data_size = self.get_additional_data_size()
      self.local_cnt[additional_data_size] += 1
      payload_cnt = self.local_cnt[additional_data_size]
      payload = {
        self.ct.PAYLOAD_DATA.EE_ID: self.eeid,
        self.ct.PAYLOAD_DATA.EE_SENDER: self.ee_addr,
        "PAYLOAD_IDX": payload_cnt,
        "ADDITIONAL_DATA": "x" * additional_data_size,
        "CHECK_PAYLOAD_TIMESTAMP": self.time(),
      }
      self.last_payload_sent_ts = self.time()
      self.create_and_send_payload(
        **payload
      )
    # endif should send payload
    return

  def get_stats_str_for_additional_size(self, additional_size, line_prefix=""):
    log_str = f"{line_prefix}Local payload count: {self.local_cnt[additional_size]}\n"
    curr_node_data = self.nodes_data_per_additional_size.get(additional_size) or {}
    log_str += f"{line_prefix}{len(curr_node_data)} nodes seen so far:\n"
    # Show stats for each node
    for node, data in curr_node_data.items():
      received_set = data["received_payload_idxs"]
      node_alias = data["alias"]
      if len(received_set) == 0:
        continue
      min_idx = min(received_set)
      max_idx = max(received_set)
      cnt_max = max_idx - min_idx + 1
      cnt_recv = len(received_set)
      cnt_missed = cnt_max - cnt_recv
      recv_prc = cnt_recv / cnt_max
      log_str += f"{line_prefix}\t`{node_alias}` <{node}>: rcv: {cnt_recv} | msd: {cnt_missed} | acc: {recv_prc:.2%}"
      log_str += f"| min: {min_idx} | max: {max_idx}\n"
      if len(data["received_payload_ts"]) > 0:
        avg_latency = sum(data["received_payload_lps"]) / len(data["received_payload_lps"])
        log_str += f"{line_prefix}\t\tAverage latency: {avg_latency:.2f} seconds\n"
        start_ts = data["received_payload_ts"][0]
        end_ts = data["received_payload_ts"][-1]
        avg_msg_per_second = len(data["received_payload_ts"]) / (end_ts - start_ts) if end_ts > start_ts else 0
        log_str += f"{line_prefix}\t\tAverage messages per second: {avg_msg_per_second:.2f}\n"
    # endfor nodes
    return log_str

  def maybe_show_stats(self):
    if self.last_show_stats_ts is None or (self.time() - self.last_show_stats_ts) > self.cfg_show_stats_period:
      self.last_show_stats_ts = self.time()
      elapsed = self.time() - self.start_ts
      log_str = f"COMM_CHECKER_01 STATS after {elapsed:2f} seconds:\n"
      with self.managed_lock_resource(NODES_DATA_MUTEX):
        additional_sizes = sorted(list(self.nodes_data_per_additional_size.keys()))
        for additional_size in additional_sizes:
          log_str += f"\tAdditional size: {additional_size} bytes:\n"
          log_str += self.get_stats_str_for_additional_size(
            additional_size=additional_size,
            line_prefix=f"\t[sz={additional_size}]"
          )
        # endfor additional sizes
      # endwith managed lock
      self.P(log_str)
    # endif last show stats ts
    return

  def process(self):
    super(CommChecker01Plugin, self).process()
    self.maybe_send_payload()
    self.maybe_show_stats()
    return
