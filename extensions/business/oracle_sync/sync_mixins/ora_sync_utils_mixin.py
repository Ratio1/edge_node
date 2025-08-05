from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import (
  OracleSyncCt,
  
  FULL_AVAILABILITY_THRESHOLD,
  POTENTIALLY_FULL_AVAILABILITY_THRESHOLD,
  
  ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD,
  ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN,
  ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD,
  ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD,

  ORACLE_SYNC_IGNORE_REQUESTS_SECONDS,
  
  DEBUG_MODE,
  VALUE_STANDARDS
)


class _OraSyncUtilsMixin:
  """
  Mixin class for Oracle Sync utilities.
  This class provides utility methods for Oracle Sync operations.
  """
  """R1FS UTILS SECTION"""
  if True:
    def r1fs_warmup_passed(self):
      """
      Check if the R1FS warmup has passed.

      Returns
      -------
      bool: True if the warmup has passed, False otherwise
      """
      return self.r1fs.is_ipfs_warmed

    def r1fs_add_data_to_message(
        self,
        message_dict: dict,
        data_dict: dict,
        data_key: str,
        debug=None
    ):
      """
      Helper method for adding data to a message with the help of R1FS.
      This method will attempt to load the data in the R1FS and add only the CID to the message.
      If the R1FS adding fails, the data will be added entirely to the message.
      If R1FS adding succeeds, only the retrieved CID will be added to the message.
      In both cases the data_key will be used

      Parameters
      ----------
      message_dict : dict
          The message dictionary to which the data should be added
      data_dict : dict
          The data dictionary to be added to the message
      data_key : str
          The key of the data in the message_dict

      Returns
      -------
      success : bool
          True if the data was successfully added to the message, False otherwise
      """
      r1fs_show_logs = debug is None or debug
      debug = self.cfg_debug_sync if debug is None else debug
      success = False
      if self.cfg_use_r1fs:
        try:
          if self.r1fs_warmup_passed():
            data_cid = self.r1fs.add_pickle(data_dict, show_logs=r1fs_show_logs)
            if data_cid is not None:
              message_dict[data_key] = data_cid
              if debug:
                self.P(f'Successfully added data to R1FS using CID {data_cid}.')
              success = True
            else:
              if debug:
                self.P(f"Failed to add data to R1FS. Adding data entirely to message.", color='r')
              message_dict[data_key] = self.deepcopy(data_dict)
            # endif data_cid is not None
          else:
            if debug:
              self.P(f"R1FS warmup period has not passed. Adding data entirely to message.", color='r')
            message_dict[data_key] = self.deepcopy(data_dict)
        except Exception as e:
          if debug:
            self.P(f"Failed to add data to R1FS. Adding data entirely to message. Error: {e}", color='r')
          message_dict[data_key] = self.deepcopy(data_dict)
      else:
        if debug:
          self.P(f"R1FS use is disabled. Adding data entirely to message.")
        message_dict[data_key] = self.deepcopy(data_dict)
        success = True
      # endif R1FS use
      return success

    def r1fs_get_data_from_message(
        self,
        message_dict: dict,
        data_key: str,
        debug=True
    ):
      """
      Helper method for getting data from a message with the help of R1FS.
      This method will check if the received value for the data_key is a CID or the data itself.
      Will then attempt to extract the data from the R1FS using the CID if needed and add it back
      to the message.

      Parameters
      ----------
      message_dict : dict
          The message dictionary from which the data should be extracted
      data_key : str
          The key of the data in the message_dict
      debug : bool, optional
          Whether to print debug messages, by default True

      Returns
      -------
      dict or None
          The data dictionary extracted from the message.
          If the extraction fails the method will return None.
      """
      res = None
      # 1. Extract the data from the message.
      data_from_message = message_dict.get(data_key)
      if data_from_message is None:
        # 1.1. No data found in message.
        if debug:
          self.P(f"Failed to extract data from {data_key}. Nothing provided.", color='r')
      else:
        # 1.2. Data found in message. Check if CID or data.
        if isinstance(data_from_message, str):
          # 2.1. Data is a CID. Attempt to get the data from R1FS.
          if debug:
            self.P(f"Attempting to get data from R1FS using CID {data_from_message}.")
          res = self.r1fs_get_pickle(cid=data_from_message, debug=debug)
          if res is not None and debug:
            self.P(f"Successfully retrieved data from R1FS using CID {data_from_message}.")
        else:
          # 2.2. Data is not a CID. Use the data directly.
          res = data_from_message
          if debug:
            self.P(f'Using data directly from message for {data_key}.')
        # endif CID or data
      # endif extraction successful
      message_dict[data_key] = res
      return res

    def r1fs_get_pickle(self, cid: str, debug=True):
      """
      Get the data from the IPFS using the CID.
      The CID will be used for retrieving the file from the IPFS.
      That file should be a pickle file.

      Parameters
      ----------
      cid : str
          The CID of the data
      debug : bool, optional
          Print debug messages, by default True

      Returns
      -------
      dict
          The data from the IPFS
      """
      total_retries = 5
      retrieved_data = None
      sleep_time = 3
      for i in range(total_retries):
        try:
          data_fn = self.r1fs.get_file(cid=cid, show_logs=debug)
          data_full_path = self.os_path.abspath(data_fn)
          retrieved_data = self.diskapi_load_pickle_from_output(filename=data_full_path)
          if retrieved_data is not None:
            break
        except Exception as e:
          if debug:
            self.P(f"Failed try {i + 1}/{total_retries} to retrieve data from IPFS using CID {cid}.")
          self.sleep(sleep_time)
        # endtry to retrieve data
      # endif retries
      if retrieved_data is None:
        if debug:
          self.P(f"Failed to retrieve data from IPFS using CID {cid} from {total_retries} retries.", color='r')
      return retrieved_data
  """END R1FS UTILS SECTION"""

  """NODES UTILS SECTION"""
  if True:
    def get_all_nodes(self):
      """
      Utility method for converting addresses in self.netmon.all_nodes to full addresses.
      This is temporary, since self.all_nodes and self._network_heartbeats have the node addresses in different formats.
      Returns
      -------
      list : list of full addresses
      """
      lst_nodes_short = self.netmon.all_nodes
      return [
        self.bc.maybe_add_prefix(node_addr)
        for node_addr in lst_nodes_short
      ]

    def get_oracle_list(self):
      if DEBUG_MODE:
        # We use get_all_nodes instead of netmon.all_nodes because we want to use the full addresses
        # instead of the short ones.
        return [node_addr for node_addr in self.get_all_nodes() if self.netmon.network_node_is_supervisor(node_addr)]
      return self._oracle_list

    def update_participant_oracles(
        self, updated_participant_oracles: list,
        state: str = None,
    ):
      """
      Update the participant oracles depending on what oracles took part in the
      last sync state.
      Parameters
      ----------
      updated_participant_oracles : list
          The list of updated participant oracles.
          This should be a list of addresses of the oracles that took part in the last sync state.
          If an oracle is not in this list, it will be considered as not participating.
      state : str, optional
          The state of the sync process. If provided, this will be used for logging purposes.
      """
      lst_oracle_addrs = list(self.is_participating.keys())
      disappearing_oracles = []
      total_previous_participants = sum(self.is_participating.values())
      for oracle_addr in lst_oracle_addrs:
        was_participating = self.is_participating.get(oracle_addr, False)
        currently_participating = oracle_addr in updated_participant_oracles
        self.is_participating[oracle_addr] = was_participating and currently_participating
        if was_participating and not currently_participating:
          disappearing_oracles.append(oracle_addr)
        # endif was participating and not currently participating
      # endfor
      total_current_participants = sum(self.is_participating.values())
      if state is not None:
        log_str = f"Updating participating oracles based on {state = }.\n"
        log_str += f"{total_previous_participants} previous participants => "
        log_str += f"{total_current_participants} current participants.\n"
        if len(disappearing_oracles) > 0:
          log_str += f"{len(disappearing_oracles)} oracles disappeared:"
          log_str += "".join([
            f"\n\t{self.netmon.network_node_eeid(oracle_addr)} <{oracle_addr}>"
            for oracle_addr in disappearing_oracles
          ])
        # endif disappearing oracles
        self.P(log_str, boxed=True)
      # endif state is not None
      return

    def maybe_refresh_oracle_list(self):
      if DEBUG_MODE:
        return
      if self._last_oracle_list_refresh is None or self.time() - self._last_oracle_list_refresh_attempt > self.cfg_oracle_list_refresh_interval:
        self.P(f'Refreshing oracle list.')
        current_oracle_list, _ = self.bc.get_oracles()
        if len(current_oracle_list) == 0:
          self.P(f'NO ORACLES FOUND. BLOCKCHAIN ERROR', boxed=True, color='r')
        else:
          self._oracle_list = current_oracle_list
          self._last_oracle_list_refresh = self.time()
        # endif current_oracle_list retrieved successfully
        self._last_oracle_list_refresh_attempt = self.time()
      # endif refresh time
      return

    def total_participating_oracles(self):
      oracle_list = self.get_oracle_list()
      total_participating_oracles = sum(self.is_participating.values())
      if total_participating_oracles == 0:
        # In case the node is unaware of any participating oracles,
        # all oracles are considered.
        total_participating_oracles = len(oracle_list)
      # endif total_participating_oracles
      return total_participating_oracles

    def min_oracle_reports_received(
        self, ignore_tolerance: bool = False,
        tolerance: int = ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD
    ):
      oracle_list = self.get_oracle_list()
      if oracle_list is None or len(oracle_list) == 0:
        return 9999999999999999999
      if not isinstance(tolerance, int):
        tolerance = ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD
      # endif tolerance is not int
      total_oracles = self.total_participating_oracles()
      # In case we ignore the tolerance, we will use the total number of oracles.
      threshold = (total_oracles - tolerance) if not ignore_tolerance else total_oracles
      return max(threshold, 1)

    def _is_oracle(self, node: str):
      """
      Check if the node is an oracle.

      Parameters
      ----------
      node : str
          The node to check

      Returns
      -------
      bool : True if the node is an oracle, False otherwise
      """
      return node in self.get_oracle_list()

    def oracle_sync_get_node_local_availability(self, node: str, skip_log=False):
      """
      Get the local availability of a node for last epoch.
      Parameters
      ----------
      node : str
          The node to get the local availability

      Returns
      -------
      int : The local availability of the node
      """
      if not skip_log and self.cfg_debug_sync_full:
        self.P(f"Getting local availability for {node}")
      return self.netmon.epoch_manager.get_node_previous_epoch(node)

    def _was_full_online(self, node: str, previous_availability: int = None):
      """
      Check if the node was full online in the previous epoch.

      Parameters
      ----------
      node : str
          The node to check

      Returns
      -------
      bool : True if the node was full online in the previous epoch, False otherwise
      """
      if previous_availability is None:
        previous_availability = self.oracle_sync_get_node_local_availability(node, skip_log=True)
      if self.cfg_debug_sync_full:
        self.P(f"Checking if {node} was full online in the previous epoch. "
               f"Local availability value: {previous_availability}")
      return previous_availability >= FULL_AVAILABILITY_THRESHOLD

    def _was_potentially_full_online(self, node: str, previous_availability: int = None):
      """
      Check if the node was potentially full online in the previous epoch.
      For details about the potentially full online, check the `POTENTIALLY_FULL_AVAILABILITY_THRESHOLD` constant
      or the `__update_potentially_full_online_threshold` method from ora_sync_states_mixin.py.

      Parameters
      ----------
      node : str
          The node to check

      Returns
      -------
      bool : True if the node was potentially full online in the previous epoch, False otherwise
      """
      if previous_availability is None:
        previous_availability = self.oracle_sync_get_node_local_availability(node, skip_log=True)
      # endif previous_availability is None

      return previous_availability >= self._potentially_full_availability_threshold

    def _count_half_of_valid_oracles(self):
      """
      Count the number of oracles that are expected to participate in the sync process.

      Returns
      -------
      int : The number of oracles that are expected to participate in the sync process
      """
      return sum(self.is_participating.values()) / 2
  """END NODES UTILS SECTION"""

  """GENERIC UTILS SECTION"""
  if True:
    def _get_current_state(self):
      """
      Get the current state of the state machine.

      Returns
      -------
      str : The current state of the state machine
      """
      return self.state_machine_api_get_current_state(self.state_machine_name)

    def _maybe_early_stop_phase(
        self,
        data: dict,
        phase: str,
        tables_str: str,
        ignore_tolerance: bool = False,
        tolerance: int = ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD
    ):
      """
      Check to see if the current phase should be stopped early.
      This can be done during the sharing phases in case we already have enough
      data collected.

      Parameters
      -------
      data : dict
        The data collected during the current phase.
        This can be a local table, median table, or agreed median table.
      phase : str
        The current phase of the sync process.
      tables_str : str
        A string representation of the tables involved in the phase.
      ignore_tolerance : bool
        If True, the tolerance will be 0 (there has to be data from all the oracles).
        If False, the early stop will happen if there is data collected from at least
        (all_oracles - tolerance) oracles.
      tolerance : int
        The number of oracles that can be ignored for the early stop.
        This will be used only if ignore_tolerance is False.
        Default is ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD.

      Returns
      -------
      res : bool
        True if the phase should be stopped early, False otherwise.
      """
      n_received = len(data)
      threshold = self.min_oracle_reports_received(
        ignore_tolerance=ignore_tolerance,
        tolerance=tolerance,
      )
      total_participating_oracles = self.total_participating_oracles()
      if n_received >= threshold:
        log_str = f"Received {n_received}/{total_participating_oracles} {tables_str} from oracles.\n"
        log_str += f"{n_received} >= {threshold}, thus early stopping {phase} is possible."
        self.P(log_str, boxed=True)
        return True
      # endif early stop
      return False

    def log_received_message(
        self,
        sender: str,
        stage: str,
        data: dict,
        return_str: bool = False,
    ):
      is_duplicated = sender in data.keys()
      current_count = len(data) + (1 - is_duplicated)
      duplicated_str = "(duplicated)" if is_duplicated else ""
      progress_str = f"[{current_count}/{self.total_participating_oracles()}]"
      sender_alias = self.netmon.network_node_eeid(sender)
      log_str = f"{progress_str}Received message{duplicated_str} from oracle `{sender_alias}` <{sender}>: {stage = }"

      if return_str:
        return log_str
      self.P(log_str)
      return

    def _maybe_squeeze_epoch_dictionaries(self, lst_epoch_dictionaries: list[dict]):
      """
      Squeeze the epoch dictionaries to reduce their size.
      This method will iterate over the list of epoch dictionaries(dictionaries with
      epoch indexes as keys on the first level).
      Each epoch dictionary that contains full data (instead of just CIDs) will be squeezed by replacing every key
      on the second level with a unique ID.

      For example, a possible input list of dictionaries would look like this:
      [
        {  # the availability table for every epoch
          "0": {"node1_addr": 1, "node2_addr": 0},
          "1": {"node1_addr": 1, "node3_addr": 1},
          ...
        },
        {  # the signatures for every epoch
          "0": {"node1_addr": "signature1", "node2_addr": "signature2"},
          "1": {"node1_addr": "signature3", "node3_addr": "signature4"},
          ...
        }
      ]
      For this, the squeezed dictionaries will be:
      [
        {
          "0": {"0": 1, "1": 0},
          "1": {"0": 1, "2": 1},
          ...
        },
        {
          "0": {"0": "signature1", "1": "signature2"},
          "1": {"0": "signature3", "2": "signature4"},
          ...
        }
      ]
      and the keys mapping will be:
      {
        "0": "node1_addr",
        "1": "node2_addr",
        "2": "node3_addr",
        ...
      }

      Parameters
      ----------
      lst_epoch_dictionaries : list[dict]
        A list of dictionaries with epoch indexes as keys on the first level.
        Each dictionary should contain the full data for each epoch, with node addresses as keys
        and their availability as values.

      Returns
      -------
      lst_squeezed_epoch_dictionaries : list[dict]
        A list of squeezed dictionaries with epoch indexes as keys on the first level.
        Each dictionary will contain the squeezed data, with unique IDs as keys on the second level.
      id_to_keys : dict
        A dictionary mapping unique IDs to their corresponding keys.
        This will be used to reconstruct the full dictionaries later.
        If the dictionaries already contain CIDs, this will be {}.
      """
      squeezed_epoch_dictionaries = []
      id_to_keys = {}
      keys_to_ids = {}

      if not self.cfg_squeeze_epoch_dictionaries:
        # TODO: in future this will be moved to stronger debug mode
        if self.cfg_debug_sync:
          self.P(f"Skipping squeezing of epoch dictionaries, because 'SQUEEZE_EPOCH_DICTIONARIES' is False.")
        return lst_epoch_dictionaries, id_to_keys

      initial_total_size = sum([
        len(self.json_dumps(dct=epoch_dict))
        for epoch_dict in lst_epoch_dictionaries
      ]) if len(lst_epoch_dictionaries) else 0
      if self.cfg_debug_sync:
        self.P(f"Squeezing epoch dictionaries, because 'SQUEEZE_EPOCH_DICTIONARIES' is True.")

      for epoch_dict in lst_epoch_dictionaries:
        squeezed_epoch_dict = {}
        for epoch, epoch_content in epoch_dict.items():
          if isinstance(epoch_content, str):
            # The epoch content is a CID, so we don't need to squeeze it.
            squeezed_epoch_dict[epoch] = epoch_content
            continue

          # If the epoch content is a dict, we need to squeeze it.
          squeezed_content_dict = {}
          for key, value in epoch_content.items():
            if key not in keys_to_ids:
              keys_to_ids[key] = str(len(keys_to_ids))
            # endif first time the current key is seen
            key_id = keys_to_ids[key]
            squeezed_content_dict[key_id] = value
            id_to_keys[key_id] = key
          # end for node address
          squeezed_epoch_dict[epoch] = squeezed_content_dict
        # end for epoch
        squeezed_epoch_dictionaries.append(squeezed_epoch_dict)
      # end for epoch dictionary

      squeezed_total_size = sum([
        len(self.json_dumps(dct=epoch_dict))
        for epoch_dict in squeezed_epoch_dictionaries
      ]) if len(squeezed_epoch_dictionaries) else 0

      if self.cfg_debug_sync:
        self.P(f"Squeezed dictionaries from initial total size: {initial_total_size} to {squeezed_total_size}.")

      return squeezed_epoch_dictionaries, id_to_keys

    def _maybe_unsqueeze_epoch_dictionaries(
        self,
        lst_squeezed_epoch_dictionaries: list[dict],
        id_to_keys: dict
    ):
      """
      Un-squeeze the epoch dictionaries to restore the original structure.
      This is the inverse operation of `__maybe_squeeze_epoch_dictionaries`.
      Parameters
      ----------
      lst_squeezed_epoch_dictionaries : list[dict]
        A list of squeezed dictionaries with epoch indexes as keys on the first level.
        Each dictionary will contain the squeezed data, with unique IDs as keys on the second level.
      id_to_keys : dict
        A dictionary mapping unique IDs to their corresponding keys.
        This will be used to reconstruct the full dictionaries.
        If the dictionaries already contain CIDs, this will be {}.

      Returns
      -------
      lst_unsqueezed_epoch_dictionaries : list[dict]
        A list of un-squeezed dictionaries with epoch indexes as keys on the first level.
        Each dictionary will contain the full data for each epoch, with node addresses as keys
        and their availability as values.
      """
      if len(id_to_keys) < 1:
        # If there are no IDs to keys, we assume the dictionaries are already in the correct format.
        # This can happen if the initial dictionaries contained CIDs instead of full data.
        return lst_squeezed_epoch_dictionaries

      lst_unsqueezed_epoch_dictionaries = []
      for squeezed_epoch_dict in lst_squeezed_epoch_dictionaries:
        unsqueezed_epoch_dict = {}
        for epoch, epoch_content in squeezed_epoch_dict.items():
          unsqueezed_content_dict = {}
          for key_id, value in epoch_content.items():
            key = id_to_keys[key_id]
            unsqueezed_content_dict[key] = value
          # end for node id
          unsqueezed_epoch_dict[epoch] = unsqueezed_content_dict
        # end for epoch
        lst_unsqueezed_epoch_dictionaries.append(unsqueezed_epoch_dict)
      # end for epoch dictionary
      return lst_unsqueezed_epoch_dictionaries
  """END GENERIC UTILS SECTION"""

  """CHECKERS SECTION"""
  if True:
    def _check_enough_oracles(self, participating_oracles: list[str], show_logs: bool = True):
      blockchain_oracles = self.get_oracle_list()
      # TODO: review if is_online or is_potentially_full_online is better here.
      online_oracles = [oracle for oracle in blockchain_oracles if self.netmon.network_node_is_online(oracle)]

      blockchain_min_threshold = len(blockchain_oracles) * ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD
      online_min_threshold = len(online_oracles) * ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD
      cnt_participating = len(participating_oracles)

      participating_str = ''.join([
        f"\n\t{self.netmon.network_node_eeid(oracle)} <{oracle}>"
        for oracle in participating_oracles
      ])

      if cnt_participating <= blockchain_min_threshold:
        log_msg = "Not enough participating oracles!"
        log_msg += f"{cnt_participating}/{len(blockchain_oracles)} <= {ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD}"
        log_msg += f" (blockchain presence threshold: {blockchain_min_threshold})"
        log_msg += f"\nParticipating oracles:{participating_str}"
        if show_logs:
          self.P(log_msg, color='r')
        return False
      if cnt_participating <= online_min_threshold:
        log_msg = "Not enough online oracles!"
        log_msg += f"{cnt_participating}/{len(online_oracles)} <= {ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD}"
        log_msg += f" (online presence threshold: {online_min_threshold})"
        log_msg += f"\nParticipating oracles:{participating_str}"
        if show_logs:
          self.P(log_msg, color='r')
        return False
      if show_logs:
        log_msg = f"Consensus possible: "
        log_msg += f"{cnt_participating}/{len(blockchain_oracles)} > {ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD}"
        log_msg += f"{cnt_participating}/{len(online_oracles)} > {ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD}"
        log_msg += f" (bc thr: {blockchain_min_threshold})"
        log_msg += f" (on thr: {online_min_threshold})"
        log_msg += f"part: {participating_str}"
        self.P(log_msg, boxed=True, color='g')
      # endif show_logs
      return True

    def _check_exception_occurred(self):
      return self.exception_occurred

    def _check_no_exception_occurred(self):
      return not self._check_exception_occurred()

    def _check_too_close_to_epoch_change(self, show_logs: bool = True):
      current_epoch_end = self.netmon.epoch_manager.get_current_epoch_end(
        current_epoch=self._current_epoch
      )
      current_time = self.datetime.now()

      left_from_current_epoch = current_epoch_end - current_time
      if left_from_current_epoch.total_seconds() < ORACLE_SYNC_IGNORE_REQUESTS_SECONDS:
        if self.cfg_debug_sync and show_logs:
          warn_msg = f"Too close to epoch change."
          warn_msg += f"Left from current epoch: {left_from_current_epoch.total_seconds()} seconds."
          warn_msg += f"Ignoring request."
          self.P(warn_msg, color='r')
        return True
      return False

    def _check_received_oracle_data_for_values(
        self, sender: str, oracle_data: dict,
        expected_variable_names: list[str],
        expected_stage: str = None,
        verify: bool = True
    ):
      """
      Generic method for checking values received in `oracle_data`.
      Additionally, this will also log the errors found.
      Parameters
      ----------
      sender : str
          The sender of the message
      oracle_data : dict
          The data received from the oracle
      expected_variable_names : list[str]
          The list of expected variable names in `oracle_data`
          Will be used to retrieve the standards from `VALUE_STANDARDS`
      expected_stage : str, optional
          The expected stage of the message. If None, this will be skipped.
      verify : bool, optional
          If True, oracle_data has to contain `EE_SIGN` key with the signature of the data in it.

      Returns
      -------
      bool : True if the received values are ok, False otherwise
      """
      # This can also happen if oracle is processing message not meant for OracleSync.
      if not isinstance(oracle_data, dict) and self.cfg_debug_sync:
        self.P(f"Received message from oracle {sender} with wrong type for oracle_data: "
               f"{type(oracle_data) = }. Expected dict", color='r')
        return False

      sentinel = object()
      expected_values = {
        name: oracle_data.get(name, sentinel)
        for name in expected_variable_names
      }
      lst_items = list(expected_values.items())
      # Keys not included in data.
      missing_fields = [field for field, value in lst_items if value == sentinel]
      is_missing = [value == sentinel for field, value in lst_items]
      # Keys included in data but with value None.
      none_fields = [field for field, value in lst_items if value is None]
      is_none = [value is None for field, value in lst_items]
      # Expected types, if any
      lst_items_with_expected_type = [
        (field, value, VALUE_STANDARDS.get(field, {}).get('type', None))
        for field, value in lst_items
      ]
      invalid_type_fields = [
        (field, value, expected_type)
        for (field, value, expected_type) in lst_items_with_expected_type
        if expected_type is not None and not isinstance(value, expected_type)
      ]
      is_invalid_type = [
        expected_type is not None and not isinstance(value, expected_type)
        for (field, value, expected_type) in lst_items_with_expected_type
      ]

      received_fields = list(oracle_data.keys())

      if any(is_missing):
        self.P(f"Received message from oracle {sender} with missing fields: "
               f"{missing_fields}. All {received_fields = }", color='r')
        return False

      if any(is_none):
        self.P(f"Received message from oracle {sender} with `None` fields: "
               f"{none_fields}. All {received_fields = }", color='r')
        return False

      if any(is_invalid_type):
        msg = f"Received message from oracle {sender} with wrong type for fields:\n"
        msg += '\n'.join([
          f"\t{field} is {type(value)}. Expected {expected_type}"
          for field, value, expected_type in invalid_type_fields
        ])
        msg += f'All received fields {received_fields}'
        self.P(msg, color='r')
        return False

      # Extract data from CIDs if there are any.
      # This is also done here in case the verification is needed.
      for var_name in expected_variable_names:
        maybe_cid = VALUE_STANDARDS.get(var_name, {}).get('maybe_cid', False)
        if maybe_cid:
          self.r1fs_get_data_from_message(
            message_dict=oracle_data,
            data_key=var_name,
          )
          retrieved_data = oracle_data.get(var_name)
          if retrieved_data is None:
            self.P(
              f"Received message from oracle {sender} and failed to retrieve data for {var_name} from R1FS."
              f"Ignoring...",
              color='r'
            )
            return False
        # endif maybe_cid
      # endfor var_name

      if expected_stage is not None:
        # In case this is either None or not present, the error will be already logged.
        if not isinstance(expected_stage, list):
          expected_stage = [expected_stage]
        stage = oracle_data.get(OracleSyncCt.STAGE, sentinel)
        if stage not in expected_stage:
          self.P(f"Received message from oracle {sender} with wrong stage: "
                 f"{stage = }. Expected {expected_stage}", color='r')
          return False
        # endif stage not as expected
      # endif expected_stage specified

      if verify:
        result = self.bc.verify(dct_data=oracle_data, str_signature=None, sender_address=None)
        if not result.valid:
          self.P(f"Invalid signature from oracle {sender}: {result.message}", color='r')
          return False
        # endif valid signature
      # endif verify

      return True

    def _check_received_announced_participants_ok(self, sender, oracle_data):
      """
      Check if the received announced participants data is ok. Print the error message if not.
      Parameters
      ----------
      sender : str
        The sender of the message
      oracle_data : dict
        The data received from the oracle

      Returns
      -------
      bool : True if the received announced participants data is ok, False otherwise
      """
      if not self._check_received_oracle_data_for_values(
        sender=sender,
        oracle_data=oracle_data,
        expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.ANNOUNCED_PARTICIPANTS],
        expected_stage=self.STATES.S11_ANNOUNCE_PARTICIPANTS,
        verify=True,
      ):
        return False
      # endif generic checks

      announced_participants = oracle_data[OracleSyncCt.ANNOUNCED_PARTICIPANTS]
      for node_addr in announced_participants:
        if not self.bc.address_is_valid(node_addr):
          self.P(f"Invalid address {node_addr} in announced participants from oracle {sender}. Ignoring...", color='r')
          return False
        # endif invalid address
        if node_addr not in self.get_oracle_list():
          self.P(f"Node {node_addr} is not an oracle. Ignoring...", color='r')
          return False
      # endfor announced_participants

      return True

    def _check_received_local_table_ok(self, sender, oracle_data):
      """
      Check if the received value table is ok. Print the error message if not.

      Parameters:
      ----------
      sender : str
        The sender of the message
      oracle_data : dict
        The data received from the oracle

      Returns:
      -------
      bool : True if the received value table is ok, False otherwise
      """
      if not self._check_received_oracle_data_for_values(
          sender=sender,
          oracle_data=oracle_data,
          expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
          expected_stage=self.STATES.S2_SEND_LOCAL_TABLE,
          verify=True,
      ):
        return False
      # endif generic checks

      # If the previous checks passed, we can safely assume that the keys are in the dictionary.
      local_table = oracle_data[OracleSyncCt.LOCAL_TABLE]

      if not self.is_participating.get(sender, False) and local_table is not None:
        local_table_str = f'{local_table = }'
        if not self.cfg_debug_sync and len(local_table_str) > 100:
          local_table_str = f'{local_table_str[:100]}...'
        self.P(f"Node {sender} should not have sent value {local_table_str}. ignoring...", color='r')
        return False

      if self.is_participating.get(sender, False) and local_table is None:
        self.P(f"Oracle {sender} should have sent value. ignoring...", color='r')
        return False

      return True

    def _check_received_signed_values_ok(self, sender, dct_values, dict_name, check_identity=True):
      """
      Check if a dictionary of data signed by the sender is ok. Print the error message if not.
      Parameters
      ----------
      sender : str
          The sender of the message
      dct_values : dict
          The dictionary of values signed by the sender. Should look like:
          {
            "key1": {
              "DATA_KEY1": "data_value1",
              "DATA_KEY2": "data_value2",
              "EE_SIGN": "signature1",
              "EE_ETH_SENDER": "sender",
              "EE_ETH_SIGN": "str",
              "EE_HASH": "str",
              "EE_SENDER": "str"
            },
            "key2": {
              "DATA_KEY1": "data_value1",
              "EE_SIGN": "signature2",
              "EE_ETH_SENDER": "sender",
              "EE_ETH_SIGN": "str",
              "EE_HASH": "str",
              "EE_SENDER": "str"
            },
          }
      dict_name : str
          The name of the dictionary of values
      check_identity : bool, optional
          If True, check if the sender is the same as the EE_SENDER in the values, by default True

      Returns
      -------
      bool : True if the received values are ok, False otherwise
      """
      verify_results = [
        self.bc.verify(dct_data=dct_value, str_signature=None, sender_address=None)
        for dct_value in dct_values.values()
      ]
      verified_all = all(
        result.valid
        for result in verify_results
      ) and len(verify_results) > 0

      if not verified_all:
        messages = [result.message for result in verify_results if not result.valid]
        str_messages = '\n'.join([
          f'\t{message}'
          for message in messages
        ])
        reason_str = f'\n{str_messages}' if self.cfg_debug_sync_full else ''
        self.P(f"Invalid {dict_name} from oracle {sender}: Verification failed:{reason_str}", color='r')
        return False
      # verified_all

      if check_identity:
        senders = set(dct_value.get('EE_SENDER') for dct_value in dct_values.values())

        is_own_message = len(senders) == 1 and list(senders)[0] == sender
        if not is_own_message:
          self.P(f'Invalid {dict_name} from oracle {sender}: Sender sent data from {list(senders)}', color='r')
        # endif is_own_message
      # endif check_identity
      return True

    def _check_received_multi_signed_values_ok(self, sender, dct_values, dict_name):
      """
      Check if a dictionary of values signed by multiple senders is ok. Print the error message if not.
      Parameters
      ----------
      sender : str
          The sender of the message
      dct_values : dict
          The dictionary of values signed by multiple senders. Should look like:
          {
            "key1": {
              "VALUE": "value1",
              "SIGNATURES": [
                {
                  "VALUE": "value1",
                  "EE_SIGN": "signature11",
                  "EE_ETH_SENDER": "sender11",
                  "EE_ETH_SIGN": "str",
                  "EE_HASH": "str",
                  "EE_SENDER": "str"
                },
                {
                  "VALUE": "value1",
                  "EE_SIGN": "signature12",
                  "EE_ETH_SENDER": "sender12",
                  "EE_ETH_SIGN": "str",
                  "EE_HASH": "str",
                  "EE_SENDER": "str"
                }
                ...
              ]
            },
            "key2": {
              "VALUE": "value2",
              "SIGNATURES": [
                {
                  "VALUE": "value2",
                  "EE_SIGN": "signature21",
                  "EE_ETH_SENDER": "sender21",
                  "EE_ETH_SIGN": "str",
                  "EE_HASH": "str",
                  "EE_SENDER": "str"
                },
                {
                  "VALUE": "value2",
                  "EE_SIGN": "signature22",
                  "EE_ETH_SENDER": "sender22",
                  "EE_ETH_SIGN": "str",
                  "EE_HASH": "str",
                  "EE_SENDER": "str"
                }
                ...
              ]
            },
          }
      dict_name : str
          The name of the dictionary of values

      Returns
      -------
      bool : True if the received values are ok, False otherwise
      """
      # Firstly, all signatures should be valid.
      verify_results = [
        [
          self.bc.verify(dct_data=dct_signature, str_signature=None, sender_address=None)
          for dct_signature in dct_value['SIGNATURES']
        ]
        for dct_value in dct_values.values()
      ]
      median_signatures_ok = all(
        all(result.valid for result in value_results) and len(value_results) > 0
        for value_results in verify_results
      ) and len(verify_results) > 0
      if not median_signatures_ok:
        messages = [
          message
          for value_results in verify_results
          for message in [result.message for result in value_results if not result.valid]
        ]
        str_messages = '\n'.join([
          f'\t{message}'
          for message in messages
        ])
        reason_str = f'\n{str_messages}' if self.cfg_debug_sync_full else ''
        self.P(f"Invalid {dict_name} from oracle {sender}: Verification failed{reason_str}", color='r')
        return False
      # endif median_signatures_ok

      values_same_as_signatures = all(
        all(dct_node['VALUE'] == signature['VALUE'] for signature in dct_node['SIGNATURES'])
        and len(dct_node['SIGNATURES']) > 0
        for dct_node in dct_values.values()
      ) and len(dct_values) > 0
      if not values_same_as_signatures:
        self.P(f"Invalid {dict_name} from oracle {sender}: Values in signatures do not match", color='r')
        return False
      # endif values_same_as_signatures

      return True

    def _check_median_computed(self):
      return self.median_table is not None and len(self.median_table) > 0

    def _check_median_not_computed(self):
      return self.median_table is None or len(self.median_table) == 0

    def _check_received_median_table_ok(self, sender, oracle_data):
      """
      Check if the received median is ok. Print the error message if not.

      Parameters:
      ----------
      sender : str
        The sender of the message
      oracle_data : dict
        The data received from the oracle

      Returns:
      -------
      bool : True if the received median is ok, False otherwise
      """
      if not self._check_received_oracle_data_for_values(
          sender=sender,
          oracle_data=oracle_data,
          expected_variable_names=[
            OracleSyncCt.STAGE, OracleSyncCt.MEDIAN_TABLE,
          ],
          expected_stage=self.STATES.S4_SEND_MEDIAN_TABLE,
          verify=True,
      ):
        return False

      median = oracle_data[OracleSyncCt.MEDIAN_TABLE]

      # in the is_participating dictionary, only oracles that were seen
      # as full online are marked as True
      if not self.is_participating.get(sender, False):
        self.P(f"Oracle {sender} should not have sent median {median}. ignoring...", color='r')
        return False

      if median is None:
        self.P(f"Oracle {sender} could not compute median. ignoring...", color='r')
        return False

      # Rebuilding the original signed data dictionaries.
      # For additional info check method _compute_median_table
      dct_values_for_checking = {
        node: {
          **dct_node,
          # self._current_epoch - 1, since the median table is for the previous epoch
          OracleSyncCt.EPOCH: self._current_epoch - 1,
          OracleSyncCt.NODE: node,
        }
        for node, dct_node in median.items()
      }

      # Check all received availability values
      if not self._check_received_signed_values_ok(
          sender=sender,
          dct_values=dct_values_for_checking,
          dict_name='median table',
          check_identity=True,
      ):
        return False

      return True

    def _check_agreement_signature(
        self, sender: str, signature_dict: dict, epoch: int = None,
        compiled_agreed_median_table: dict = None, debug: bool = False
    ):
      """
      Check the agreement signature.
      If no compiled_agreed_median_table is provided, the method will use the one from the cache.
      In case the cached compiled agreed median table is used for verifying the signature,
      it means the sender had the same compiled agreed median table as the receiver.
      Parameters
      ----------
      sender : str
          The sender of the message
      signature_dict : dict
          The signature of the compiled agreed median table
      epoch : int, optional
          The epoch for which the compiled agreed median table is received, by default None
      compiled_agreed_median_table : dict
          The compiled agreed median table received from an oracle for a particular epoch.
          If None, the method will use the one from the cache, by default None
      debug : bool, optional
          Whether to print debug messages, by default False

      Returns
      -------
      bool : True if the compiled agreed median table is valid, False otherwise
      """
      if signature_dict is None:
        if debug:
          self.P(f"Invalid agreement signature for {epoch=} from oracle {sender}: No signature provided", color='r')
        return False

      if compiled_agreed_median_table is None:
        compiled_agreed_median_table = self.compiled_agreed_median_table

      if epoch is None:
        # In case no epoch is specified, it means the agreement checking is for the last epoch finished.
        # Thus, the epoch is the current epoch - 1.
        epoch = self._current_epoch - 1

      if debug:
        self.P(f"DEBUG Received agreement signature for epoch {epoch} from oracle {sender}")

      # Rebuild the original signed data dictionary.
      # For additional info check method
      # _receive_agreement_signature_and_maybe_send_agreement_signature

      non_zero_agreed_median_table = {
        node: availability for node, availability in compiled_agreed_median_table.items()
        if availability != 0
      }

      data_to_verify = {
        **signature_dict,
        OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE: non_zero_agreed_median_table,
        OracleSyncCt.EPOCH: epoch,
      }

      # Check if the compiled agreed median table is signed by the oracle
      verify_result = self.bc.verify(dct_data=data_to_verify, str_signature=None, sender_address=None)
      if not verify_result.valid:
        if self.cfg_debug_sync_full:
          self.P(f"DEBUG FULL invalid verify dictionary: {data_to_verify}")
        if debug:
          self.P(f"Invalid agreement signature for {epoch=} from oracle {sender}:{verify_result.message}", color='r')
        return False
      return True

    def _check_received_agreement_signature_ok(self, sender, oracle_data):
      """
      Check if the received signature for agreement is ok. Print the error message if not.

      Parameters:
      ----------
      sender : str
        The sender of the message
      oracle_data : dict
        The data received from the oracle

      Returns:
      -------
      bool : True if the received agreed value is ok, False otherwise
      """
      if not self._check_received_oracle_data_for_values(
          sender=sender,
          oracle_data=oracle_data,
          expected_variable_names=[
            OracleSyncCt.STAGE, OracleSyncCt.AGREEMENT_SIGNATURE
          ],
          expected_stage=self.STATES.S6_SEND_AGREED_MEDIAN_TABLE,
          # No need to verify here, since the agreement signature itself is signed and verified
          # in the self._check_agreement_signature method
          verify=False,
      ):
        return False

      signature_dict = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURE]

      # In the is_participating dictionary, only oracles that were seen
      # as full online are marked as True
      # If the signature was None it wouldn't have passed the previous check.
      if not self.is_participating.get(sender, False):
        self.P(f"Oracle {sender} should not have sent signature for agreement. ignoring...", color='r')
        return False

      if not self._check_agreement_signature(
          sender=sender,
          signature_dict=signature_dict
      ):
        return False

      if sender != signature_dict.get('EE_SENDER'):
        self.P(
          f"Agreement signature from oracle {sender} does not match the sender! Possible impersonation attack!",
          color='r'
        )
        return False
      # endif identity check
      return True

    def _check_received_agreement_signatures_ok(self, sender: str, oracle_data: dict):
      """
      Check if the received agreement signatures are ok. Print the error message if not.
      Parameters
      ----------
      sender : str
          The sender of the message
      oracle_data : dict
          The data received from the oracle

      Returns
      -------
      bool : True if the received agreement signatures are ok, False otherwise
      """
      if not self._check_received_oracle_data_for_values(
          sender=sender,
          oracle_data=oracle_data,
          expected_variable_names=[
            OracleSyncCt.STAGE, OracleSyncCt.AGREEMENT_SIGNATURES
          ],
          expected_stage=self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES,
          # No need to verify here, since the agreement signature itself is signed and verified
          # in the self._check_agreement_signature method
          verify=False,
      ):
        return False

      # In the is_participating dictionary, only oracles that were seen
      # as full online are marked as True
      # If the signature was None it wouldn't have passed the previous check.
      if not self.is_participating.get(sender, False):
        self.P(f"Oracle {sender} should not have sent signatures for agreement exchange. ignoring...", color='r')
        return False

      agreement_signatures = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURES]

      for sig_sender, signature_dict in agreement_signatures.items():
        if not self.is_participating.get(sig_sender, False):
          self.P(f"Oracle {sig_sender} should not have sent signature for agreement. ignoring...", color='r')
          # TODO: review if this should make the entire message invalid
          # One node can be seen as potentially full online by some oracles and not by others.
          # But for the node to actually participate in the agreement, it has to see itself as full online.
          # That can not happen if the node is not seen as potentially full online by at least another
          # participating oracle.
          return False
        # endif not expected to participate
        if not self._check_agreement_signature(
            sender=sig_sender,
            signature_dict=signature_dict
        ):
          self.P(f"Invalid agreement signature from oracle {sig_sender}!", color='r')
          return False
        # endif agreement signature
      # endfor agreement signatures
      return True

    def _check_received_epoch__agreed_median_table_ok(self, sender, oracle_data):
      """
      Check if the received agreed value is ok. Print the error message if not.
      This method is used to check if the message received is valid. The checking
      of each agreed median table is done in the _check_agreed_median_table method.

      Parameters
      ----------
      sender : str
          The sender of the message
      oracle_data : dict
          The data received from the oracle
      """
      if not self._check_received_oracle_data_for_values(
          sender=sender,
          oracle_data=oracle_data,
          expected_variable_names=[
            OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE, OracleSyncCt.EPOCH_KEYS,
            OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES,
            OracleSyncCt.EPOCH__IS_VALID,
            # This might not need checking
            # OracleSyncCt.ID_TO_NODE_ADDRESS
          ],
          expected_stage=self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
          verify=False,
      ):
        return False

      epoch__agreed_median_table = oracle_data[OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE]
      epoch__agreement_signatures = oracle_data[OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES]
      epoch__is_valid = oracle_data[OracleSyncCt.EPOCH__IS_VALID]
      epoch_keys = oracle_data[OracleSyncCt.EPOCH_KEYS]

      # Because json does not support int keys, we also send the int keys in a list.
      lst_epoch_str_keys = set([str(epoch) for epoch in epoch_keys])
      lst_keys_from_table = set([str(x) for x in list(epoch__agreed_median_table.keys())])
      lst_keys_from_signatures = set([str(x) for x in list(epoch__agreement_signatures.keys())])
      lst_keys_from_is_valid = set([str(x) for x in list(epoch__is_valid.keys())])

      max_epoch, min_epoch = max(epoch_keys), min(epoch_keys)
      if len(epoch_keys) != max_epoch - min_epoch + 1:
        self.P(f'Epoch keys are not continuous! {epoch_keys = }. Skipping', color='r')
        return False
      # endif keys not continuous

      if set(lst_epoch_str_keys) != set(lst_keys_from_table):
        self.P(
          f'Epoch keys missmatch between list and table keys on request from {sender = }! Skipping',
          color='r'
        )
        return False
      # endif keys missmatch

      if set(lst_epoch_str_keys) != set(lst_keys_from_signatures):
        self.P(
          f'Epoch keys missmatch between list and agreement signature keys on request from {sender = }! Skipping',
          color='r'
        )
        return False
      # endif keys missmatch

      if set(lst_epoch_str_keys) != set(lst_keys_from_is_valid):
        self.P(
          f'Epoch keys missmatch between list and is_valid keys on request from {sender = }! Skipping',
          color='r'
        )
        return False

      return True

    def _check_agreed_median_table(
        self, sender: str, agreed_median_table: dict,
        epoch_signatures: dict, epoch: int,
        epoch_is_valid: bool, debug: bool = True
    ):
      """
      Check if the agreed median table is valid.

      Parameters
      ----------
      sender : str
          The sender of the message.
      agreed_median_table : dict
          The agreed median table received from an oracle for a particular epoch.
      epoch_signatures: dict
          The oracle signatures for the given agreed_median_table.
      epoch: int
          The epoch for which the agreement table was received.
      epoch_is_valid: bool
          The validity of the epoch.
      debug: bool, optional
          Whether to print debug messages, by default True
      """
      if not epoch_is_valid:
        if debug:
          self.P(f"For epoch {epoch} from {sender} no consensus was reached. Skipping...", color='r')
        return False

      if agreed_median_table is None:
        if debug:
          self.P(f"Received agreed median table from oracle {sender} is None. ignoring...", color='r')
        return False

      if epoch_signatures is None:
        if debug:
          self.P(f"Received epoch {epoch} signatures table from oracle {sender} is None. Ignoring...", color='r')
        return False

      if len(epoch_signatures) == 0:
        if debug:
          self.P(f"Received empty epoch {epoch} signatures table from oracle {sender}. Ignoring...", color='r')
        return False

      if self.cfg_debug_sync_full:
        self.P(f"DEBUG Received agreed median table from oracle {sender}: {agreed_median_table}")

      for oracle_addr, oracle_signature in epoch_signatures.items():
        if not self._check_agreement_signature(
            sender=sender, signature_dict=oracle_signature,
            epoch=epoch, compiled_agreed_median_table=agreed_median_table,
            debug=debug
        ):
          if debug:
            self.P(f'Invalid signature of {oracle_addr} in signatures received from {sender}!', color='r')
          # endif debug_sync
          return False
        # endif agreement signature ok for received table
      # endfor signatures
      return True
  """END CHECKERS SECTION"""
# endclass _OraSyncUtilsMixin

