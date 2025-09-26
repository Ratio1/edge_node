from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import (
  OracleSyncCt,

  EPOCH_MAX_VALUE,
  FULL_AVAILABILITY_THRESHOLD,
  POTENTIALLY_FULL_AVAILABILITY_THRESHOLD,

  ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD,
  ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN,

  LOCAL_TABLE_SEND_MULTIPLIER,
  REQUEST_AGREEMENT_TABLE_MULTIPLIER,
  SIGNATURES_EXCHANGE_MULTIPLIER,
)


class _OraSyncStatesCallbacksMixin:
  """
  Mixin class that defines states callbacks for OracleSync01 plugin.
  """
  """S0_WAIT_FOR_EPOCH_CHANGE CALLBACKS"""
  if True:
    def _send_epoch__agreed_median_table(self, start_epoch, end_epoch):
      dct_epoch__agreed_median_table = {}
      dct_epoch__signatures = {}
      dct_epoch__is_valid = {}
      newly_uploaded_epochs = []

      epoch_keys = list(range(start_epoch, end_epoch + 1))
      # TODO: Refactor this to retrieve all the data in one call and separate the data for each epoch after.
      valid_epochs, invalid_epochs = [], []
      added_agreement_success, added_agreement_failed = [], []
      added_signatures_success, added_signatures_failed = [], []
      already_uploaded, epochs_with_empty = [], []
      for epoch in epoch_keys:
        availability_table, dct_signatures, agreement_cid, signatures_cid = self.netmon.epoch_manager.get_epoch_availability(
          epoch=epoch, return_additional=True
        )
        current_epoch_is_valid = self.netmon.epoch_manager.is_epoch_valid(epoch)
        epoch_key = str(epoch)
        dct_epoch__is_valid[epoch_key] = self.netmon.epoch_manager.is_epoch_valid(epoch)

        if current_epoch_is_valid:
          valid_epochs.append(epoch)
        else:
          invalid_epochs.append(epoch)

        not_added_to_r1fs = current_epoch_is_valid and (agreement_cid is None or signatures_cid is None)
        if (not self.cfg_use_r1fs) or not_added_to_r1fs:
          # The agreement or the signatures were never uploaded in the R1FS, so we try to upload them now.
          agreement_success, newly_added_agreement = self.maybe_add_data_to_message(
            message_dict=dct_epoch__agreed_median_table,
            data_dict=availability_table,
            data_key=epoch_key,
            data_cid=agreement_cid,
            debug=self.cfg_debug_sync_full,
          )

          signatures_success, newly_added_signatures = self.maybe_add_data_to_message(
            message_dict=dct_epoch__signatures,
            data_dict=dct_signatures,
            data_key=epoch_key,
            data_cid=signatures_cid,
            debug=self.cfg_debug_sync_full,
          )

          if newly_added_signatures or newly_added_agreement:
            newly_uploaded_epochs.append(epoch)
          # endif newly added signatures or agreement
          if agreement_success:
            added_agreement_success.append(epoch)
          else:
            added_agreement_failed.append(epoch)
          # endif agreement success
          if signatures_success:
            added_signatures_success.append(epoch)
          else:
            added_signatures_failed.append(epoch)
          # endif signatures success
          if agreement_success and signatures_success:
            # Save the epoch CIDs, in order to not upload it again
            if self.cfg_use_r1fs:
              agreement_cid = dct_epoch__agreed_median_table[epoch_key]
              signatures_cid = dct_epoch__signatures[epoch_key]
              self.netmon.epoch_manager.add_cid_for_epoch(
                epoch=epoch,
                agreement_cid=agreement_cid,
                signatures_cid=signatures_cid,
                debug=self.cfg_debug_sync_full,
              )
            # endif use_r1fs
          # endif both addings successful
        else:
          # Here either the epoch is not valid or the agreement was already uploaded.
          if agreement_cid is not None and signatures_cid is not None:
            # The agreement was already uploaded, so we just add the cid to the message.
            already_uploaded.append(epoch)
            if self.cfg_debug_sync_full:
              self.P(f"Agreement and signatures for epoch {epoch} were already uploaded. Adding the CIDs to the message.")
            dct_epoch__agreed_median_table[epoch_key] = agreement_cid
            dct_epoch__signatures[epoch_key] = signatures_cid
          else:
            # The epoch is not valid, so we just add an empty object.
            epochs_with_empty.append(epoch)
            if self.cfg_debug_sync_full:
              self.P(f"Epoch {epoch} is not valid. Both availability table and signatures will be empty objects.")
            dct_epoch__agreed_median_table[epoch_key] = {}
            # We also remove the signatures for this epoch.
            dct_epoch__signatures[epoch_key] = {}
          # endif agreement_cid is not None
        # endif agreement needs uploading
      # end for epoch keys

      if self.cfg_debug_sync:
        stats_msg = f'{len(valid_epochs)} valid | {len(invalid_epochs)} invalid'
        stats_msg += f' | {len(added_agreement_success)}a {len(added_signatures_success)}s added'
        stats_msg += f' | {len(added_agreement_failed)}a {len(added_signatures_failed)}s failed'
        stats_msg += f' | {len(already_uploaded)} already uploaded | {len(epochs_with_empty)} empty'
        self.P(f"Epochs: {stats_msg}.")
      # endif debug_sync

      if len(newly_uploaded_epochs) > 0:
        self.P(f"Uploaded agreements for epochs: {newly_uploaded_epochs}. Saving the epoch manager status.")
        # Here, the epoch manager cache data does not need to also be forcefully update.
        # The only updates done are for the epochs CIDs
        self.netmon.epoch_manager.save_status()
        self.P(f"Epoch manager status saved.")
      # endif newly uploaded epochs

      if self.cfg_debug_sync:
        self.P(f'Broadcasting availability_tables from {start_epoch} to {end_epoch}.')
      # endif debug_sync

      if self.cfg_debug_sync_full:
        msg = f'DEBUG Showing full availability tables from {start_epoch} to {end_epoch}:\n'
        msg += f'{self.json_dumps(dct_epoch__agreed_median_table)}\n'
        msg += f'Each epoch with the following validity:\n{self.json_dumps(dct_epoch__is_valid)}\n'
        msg += f'and the following signatures:\n{self.json_dumps(dct_epoch__signatures)}'
        msg = "#" * 80 + "\n" + msg + "#" * 80
        self.P(msg)
      # endif debug_sync_full

      [squeezed_availabilities, squeezed_signatures], id_to_node_address = self._maybe_squeeze_epoch_dictionaries(
        lst_epoch_dictionaries=[dct_epoch__agreed_median_table, dct_epoch__signatures]
      )
      oracle_data = {
        OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: squeezed_availabilities,
        OracleSyncCt.ID_TO_NODE_ADDRESS: id_to_node_address,
        OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES: squeezed_signatures,
        OracleSyncCt.EPOCH__IS_VALID: dct_epoch__is_valid,
        OracleSyncCt.EPOCH_KEYS: epoch_keys,
        OracleSyncCt.STAGE: self._get_current_state(),
      }
      self.add_payload_by_fields(
        oracle_data=oracle_data,
      )
      return

    def _maybe_process_request_agreed_median_table(self, dct_message: dict):
      """
      Process the request in case it is a request for the agreed median table.
      Parameters
      ----------
      payload : dict
          The payload of the message

      Returns
      -------
      bool : True if the request was processed, False otherwise
      """
      processed = False
      sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
      oracle_data = dct_message.get('ORACLE_DATA')
      if oracle_data is None:
        return processed
      stage = oracle_data.get(OracleSyncCt.STAGE)
      request_agreed_median_table = oracle_data.get(OracleSyncCt.REQUEST_AGREED_MEDIAN_TABLE)
      start_epoch = oracle_data.get('START_EPOCH')
      end_epoch = oracle_data.get('END_EPOCH')

      if stage != self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE:
        # received a message from a different stage
        return processed

      if start_epoch is None or end_epoch is None:
        # received a message with missing epochs
        return processed

      if self._check_too_close_to_epoch_change():
        return processed

      if request_agreed_median_table:
        sender_alias = self.netmon.network_node_eeid(sender)
        self.P(
          f"Received request from oracle `{sender_alias}` <{sender}>: {stage = }, {start_epoch = }, {end_epoch = }")
        self._send_epoch__agreed_median_table(start_epoch, end_epoch)
        processed = True
      # endif request_agreed_median_table
      return processed

    def _receive_requests_from_oracles_and_send_responses(self):
      """
      Receive requests from the oracles and send responses.
      """
      if self.cfg_debug_sync_full:
        self.P(f"Parsing received messages from oracles.[{self._get_current_state()}]")
      cnt = 0
      for dct_message in self.get_received_messages_from_oracles():
        cnt += 1
        self._maybe_process_request_agreed_median_table(dct_message)
      if self.cfg_debug_sync_full:
        self.P(f"Processed {cnt} messages from oracles.[{self._get_current_state()}]")
      return

    def _check_epoch_finished(self):
      """
      Check if the epoch has changed.

      Returns
      -------
      bool : True if the epoch has changed, False otherwise
      """
      return self._current_epoch != self.netmon.epoch_manager.get_current_epoch()
  """END S0_WAIT_FOR_EPOCH_CHANGE CALLBACKS"""

  """S11_ANNOUNCE_PARTICIPANTS CALLBACKS"""
  if True:
    def get_announce_participants_send_interval(self):
      return self.cfg_send_interval / 3

    def get_announce_participants_timeout(self):
      return self.cfg_send_period / 2

    def _update_potentially_full_online_threshold(self):
      """
      Update the threshold for potentially full online oracles.
      For reference, see the `POTENTIALLY_FULL_AVAILABILITY_THRESHOLD` constant.
      For an oracle to be able to participate in the sync process, its availability score
      from the previous epoch should be at least FULL_AVAILABILITY_THRESHOLD.
      This means, it can be offline for (MAX_EPOCH_VALUE - FULL_AVAILABILITY_THRESHOLD) units of time.
      (A full epoch has MAX_EPOCH_VALUE units of time.)
      However, the time that the current node was offline is unknown when computing
      the availability score of other nodes.
      Thus, the current node will presume that the other nodes were fully online during that time.
      This means that the threshold for availability score for the other nodes will be decreased by
      that unknown time.
      Because that period of time is unknown, the decreased threshold will be further referred as
      "potentially full online threshold", since a remote node can be potentially full online, but
      still not be able to participate in the sync process.
      Before setting this, the default threshold will be the `POTENTIALLY_FULL_AVAILABILITY_THRESHOLD`
      constant.
      """
      # 1. Retrieve the local availability of the current node.
      # This should be the most reliable value, since it is computed by the current node.
      local_availability = self.oracle_sync_get_node_local_availability(self.node_addr)
      # 2. Compute the unknown units of time.
      cnt_unknown_units_of_time = EPOCH_MAX_VALUE - local_availability
      # 3. Update the threshold for potentially full online oracles.
      initial_value = self._potentially_full_availability_threshold
      self._potentially_full_availability_threshold = FULL_AVAILABILITY_THRESHOLD - cnt_unknown_units_of_time
      log_str = f"Updated potentially full online threshold from {initial_value} to {self._potentially_full_availability_threshold}."
      self.P(log_str, color='g', boxed=True)
      return

    def _announce_and_observe_participants(self):
      """
      Announce the other oracles about the current node's participation in the sync process and
      observe the other oracles' announcements.
      When announcing its own participation, the node will also announce all the other
      oracles that were already announced and are eligible to participate.
      """
      # Start of sync checking
      if True:
        self.netmon.epoch_manager.maybe_close_epoch()
        # Check if the current epoch is valid.
        prev_epoch = self.netmon.epoch_manager.get_time_epoch() - 1
        if prev_epoch < 0:
          self.P(f'Previous epoch below 0: {prev_epoch}. Cannot participate in sync. '
                 f'This is likely because the genesis date is in the future.')
          return
        # Check if the current node can participate in the sync process.
        # The logs will be shown only the first time passing through this method.
        show_logs = self.first_time_announce_participants is None and self.cfg_debug_sync
        if self._cannot_participate_in_sync(show_logs=show_logs):
          is_oracle = self._is_oracle(self.node_addr)
          reason_str = "not an oracle" if not is_oracle else "not full online"
          self.P(
            f"I cannot participate in the sync process({reason_str}). I will not announce my participation.",
            color="r"
          )
          return
        # endif cannot participate in sync
      # endif start of sync checking

      # Announce the current node's participation and all the other eligible oracles
      # the current node is aware of.
      if True:
        if self.first_time_announce_participants is None:
          self.first_time_announce_participants = self.time()
          self._announced_participating.add(self.node_addr)
          self._update_potentially_full_online_threshold()
        # endif first iteration

        # Check if should announce the participants this time.
        send_interval = self.get_announce_participants_send_interval()
        last_ts = self.last_time_announce_participants
        if last_ts is None or self.time() - last_ts >= send_interval:
          log_str = f"Announcing {len(self._announced_participating)} participants:"
          log_str += "".join([
            f"\n\t{self.netmon.network_node_eeid(oracle)} <{oracle}> {self.oracle_sync_get_node_local_availability(oracle)}"
            for oracle in self._announced_participating
          ])
          self.P(log_str)

          oracle_data = {
            OracleSyncCt.ANNOUNCED_PARTICIPANTS: list(self._announced_participating),
            OracleSyncCt.STAGE: self._get_current_state(),
          }
          self.bc.sign(oracle_data, add_data=True, use_digest=True)
          self.add_payload_by_fields(oracle_data=oracle_data)
          self.last_time_announce_participants = self.time()
        # endif need to announce
      # endif announce participants

      # Observe the other oracles' announcements.
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')
        if oracle_data is None:
          continue

        if not self._check_received_announced_participants_ok(sender, oracle_data):
          continue
        # Retrieve all the announced oracles from the message.
        # Check each of them to see if they are indeed oracles and
        # if they were active enough in the previous epoch from the
        # point of view of the current node.
        announced_participants = oracle_data[OracleSyncCt.ANNOUNCED_PARTICIPANTS]

        for node_addr in announced_participants:
          if not self._was_potentially_full_online(node_addr):
            if self.cfg_debug_sync:
              log_str = f"Node {node_addr} was not potentially full online in the previous epoch. "
              log_str += f"Will not keep it as a valid participant."
              self.P(log_str, color='r')
            # endif debug
            continue
          else:
            self._announced_participating.add(node_addr)
        # endfor node_addr in announced_participants
        sender_alias = self.netmon.network_node_eeid(sender)
        sorted_participants = sorted(self._announced_participating)
        log_str = f"Received {len(announced_participants)} announced participants({len(sorted_participants)} in total) "
        log_str += f"from `{sender_alias}` <{sender}>: {sorted_participants}"
        self.P(log_str)
      # endfor messages from oracles
      return

    def _can_participate_and_announcement_timeout(self):
      timeout_passed = False
      # This can be None if the current oracle does not participate
      if self.first_time_announce_participants is not None:
        timeout_passed = (self.time() - self.first_time_announce_participants) > self.get_announce_participants_timeout()
      # This sequence of checks is important in order to avoid computing the local availability multiple times.
      return timeout_passed and self._can_participate_in_sync()
  """END S11_ANNOUNCE_PARTICIPANTS CALLBACKS"""

  """S1_COMPUTE_LOCAL_TABLE CALLBACKS"""
  if True:
    def _compute_local_table(self):
      """
      Compute the local table for the current node.
      If the node is not a supervisor, the local table will be empty.
      This method is only called after the finishing of the previous epoch.
      """
      # node is supervisor, compute local table
      self.local_table = {
        # self.netmon.epoch_manager.get_node_previous_epoch uses self._data
        # self._data uses full address
        node: self.oracle_sync_get_node_local_availability(node, skip_log=True)
        # node: self.netmon.epoch_manager.get_node_previous_epoch(node)
        # self.netmon.all_nodes uses self.all_heartbeats
        # self.all_heartbeats uses self._network_heartbeats
        # self._network_heartbeats uses short address
        for node in self.get_all_nodes()
      }

      lst_announced = []
      lst_out = []
      for oracle in self.get_oracle_list():
        oracle_prev_availability = self.local_table.get(oracle)
        oracle_alias = self.netmon.network_node_eeid(oracle)
        _is_participating = oracle in self._announced_participating
        if _is_participating:
          lst_announced.append((oracle, oracle_alias, oracle_prev_availability))
        else:
          lst_out.append((oracle, oracle_alias, oracle_prev_availability))
        self.is_participating[oracle] = _is_participating
        # endif oracle announced
      # endfor

      prev_epoch = self.netmon.epoch_manager.get_time_epoch() - 1
      log_msg = f"Start of sync process for epoch {prev_epoch}:\n"
      announced_str = "\n\t".join(
        f"`{oracle_alias}` <{oracle}> ({availability})"
        for oracle, oracle_alias, availability in lst_announced
      )
      out_str = "\n\t".join(
        f"`{oracle_alias}` <{oracle}> ({availability})"
        for oracle, oracle_alias, availability in lst_out
      )
      log_msg += f"POTENTIAL_THRESHOLD={self._potentially_full_availability_threshold} | "
      log_msg += f"FULL_THRESHOLD={FULL_AVAILABILITY_THRESHOLD}"
      log_msg += f"\n{len(lst_announced)} oracles that will participate:\n\t{announced_str}\n"
      log_msg += f"\n{len(lst_out)} oracles that will not participate:\n\t{out_str}\n"
      self.P(log_msg)
      self.P(f"Computed local table {self.local_table}")
      return

    def _can_participate_in_sync(self, show_logs=False):
      """
      Check if the current node can participate in the sync process.
      A node can participate if it is a supervisor and was full online in the previous epoch.

      Returns
      -------
      bool : True if the node can participate in the sync process, False otherwise
      """
      return self._is_oracle(self.node_addr) and self._was_full_online(self.node_addr, show_logs=show_logs)

    def _cannot_participate_in_sync(self, show_logs=False):
      """
      Check if the current node cannot participate in the sync process.
      A node can participate if it is a supervisor and was full online in the previous epoch.

      Returns
      -------
      bool : True if the node cannot participate in the sync process, False otherwise
      """
      return not self._can_participate_in_sync(show_logs=show_logs)
  """END S1_COMPUTE_LOCAL_TABLE CALLBACKS"""

  """S2_SEND_LOCAL_TABLE CALLBACKS"""
  if True:
    def _receive_local_table_and_maybe_send_local_table(self):
      """
      Receive the local table from the oracles and
      send the local table to the oracles each `self.cfg_send_interval` seconds.
      """
      # Send value to oracles
      if True:
        if self.first_time_local_table_sent is None:
          self.first_time_local_table_sent = self.time()
          self.dct_local_tables[self.node_addr] = self.local_table
        # endif first iteration of the current state

        early_stop_report = self.check_early_stop_report(self.STATES.S2_SEND_LOCAL_TABLE)
        send_time = (self.last_time_local_table_sent is None) or (self.time() - self.last_time_local_table_sent >= self.cfg_send_interval)
        if early_stop_report or send_time:
          self.P(f"Sending {self.local_table=}")

          oracle_data = {
            OracleSyncCt.LOCAL_TABLE: self.local_table,
            OracleSyncCt.STAGE: self._get_current_state()
          }
          self.bc.sign(oracle_data, add_data=True, use_digest=True)
          if self.cfg_use_r1fs_during_consensus:
            # Will add cid to the message instead of self.local_table if
            # the upload to R1FS is successful.
            self.r1fs_add_data_to_message(
              message_dict=oracle_data,
              data_dict=self.local_table,
              data_key=OracleSyncCt.LOCAL_TABLE
            )
          # endif use r1fs during consensus

          self.add_payload_by_fields(oracle_data=oracle_data)
          self.last_time_local_table_sent = self.time()
        # endif need to send
      # endif send

      # Receive values from oracles
      # Obs: there is no need for supervisor check on sender, since the messages
      # are already filtered in handle_received_messages
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')
        if oracle_data is None:
          continue

        # If local_table was sent as a CID this check method will also download it.
        if not self._check_received_local_table_ok(sender, oracle_data):
          continue

        stage = oracle_data[OracleSyncCt.STAGE]
        local_table = oracle_data[OracleSyncCt.LOCAL_TABLE]

        log_str = self.log_received_message(
          sender=sender,
          stage=stage,
          data=self.dct_local_tables,
          return_str=True
        )
        if self.cfg_debug_sync_full:
          log_str += f", local_table=\n{local_table}"
        # endif debug_sync
        self.P(log_str)
        self.dct_local_tables[sender] = local_table
      # end for
      return

    def _send_local_table_timeout(self):
      """
      Check if the exchange phase of the local table has finished.

      Returns
      -------
      bool: True if the exchange phase of the local table has finished, False otherwise
      """
      timeout_reached = (self.time() - self.first_time_local_table_sent) > (
            self.cfg_send_period * LOCAL_TABLE_SEND_MULTIPLIER)
      early_stopping = self._maybe_early_stop_phase(
        data=self.dct_local_tables,
        phase=self.STATES.S2_SEND_LOCAL_TABLE,
        tables_str="local tables",
      )
      return early_stopping or timeout_reached
  """END S2_SEND_LOCAL_TABLE CALLBACKS"""

  """S3_COMPUTE_MEDIAN_TABLE CALLBACKS"""
  if True:
    def _compute_simple_median_table(self, median_table):
      """
      Compute a simple median table with only the values.
      This method is used to print the median table in a more readable format.

      Parameters
      ----------
      median_table : dict
          The median table to simplify

      Returns
      -------
      dict : The simplified median table
      """
      if median_table is None:
        return None
      simple_median_table = {}
      for node, dct_node in median_table.items():
        simple_median_table[node] = dct_node['VALUE']

      return simple_median_table

    def _compute_median_table(self):
      """
      Compute the median table from the local tables received from the oracles.
      For each node that was seen in the local tables, compute the median value and sign it.
      self.dct_local_tables  has the following format:
      {
        "oracle1": {
          "node1_addr": "int_availability_node11",
          "node2_addr": "int_availability_node12",
          ...
        },
        "oracle2": {
          "node1_addr": "int_availability_node21",
          "node2_addr": "int_availability_node22",
          ...
        },

        ...
      }
      """
      # should not have received any None values
      valid_local_tables = [x for x in self.dct_local_tables.values() if x is not None]

      self.update_participant_oracles(
        updated_participant_oracles=list(self.dct_local_tables.keys()),
        # The provided state is S2_SEND_LOCAL_TABLE, since the median table is computed
        # from the local tables sent in S2_SEND_LOCAL_TABLE state.
        state=self.STATES.S2_SEND_LOCAL_TABLE
      )

      if not self._check_enough_oracles(participating_oracles=list(self.dct_local_tables.keys())):
        self.P("Could not compute median.", color='r')
        return
      # endif not enough oracles
      # compute median for each node in list
      self.median_table = {}

      all_nodes_in_local_tables = set().union(*(set(value_table.keys()) for value_table in valid_local_tables))
      for node in all_nodes_in_local_tables:
        # default value 0 because if node not in value_table, it means it was not seen
        all_node_local_table_values = (value_table.get(node, 0) for value_table in valid_local_tables)
        # Filter out the None values in case of faulty oracle tables.
        valid_node_local_table_values = list(x for x in all_node_local_table_values if x is not None)

        # compute median and sign -- signature will be used in the next step
        median_value = round(self.np.median(valid_node_local_table_values))
        local_value = self.local_table.get(node, 0)
        median_error = abs(local_value - median_value)
        if median_error > ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN:
          # TODO: record this error and maybe add it to signed package for BC storage.
          str_msg = f"{node} median error: {local_value=} | {median_value=} | {median_error} > {ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN}"
          self.P(str_msg, color='r', boxed=True)
        # endif median_error
        self.median_table[node] = {
          'VALUE': median_value,
          # self._current_epoch - 1, since the consensus is for the previous epoch
          OracleSyncCt.EPOCH: self._current_epoch - 1,
          OracleSyncCt.NODE: node
        }
        self.bc.sign(self.median_table[node], add_data=True, use_digest=True)
        # No reason to leave these keys in the dictionary, since they can be added again when verifying.
        self.median_table[node].pop(OracleSyncCt.EPOCH)
        self.median_table[node].pop(OracleSyncCt.NODE)
      # end for all_nodes

      self.P(f"Computed median table {self._compute_simple_median_table(self.median_table)}")
      return
  """END S3_COMPUTE_MEDIAN_TABLE CALLBACKS"""

  """S4_SEND_MEDIAN_TABLE CALLBACKS"""
  if True:
    def _receive_median_table_and_maybe_send_median_table(self):
      """
      Receive the median table from the oracles and
      send the median table to the oracles each `self.cfg_send_interval` seconds.
      self.median_table and median_table extracted from oracle_data should have the following format:
      {
        "node1_addr": {
          "VALUE": "int_median_value1",
          "EE_SIGN": "signature1",
          "EE_ETH_SENDER": "sender",
          "EE_ETH_SIGN": "str",
          "EE_HASH": "str",
          "EE_SENDER": "str",
        },
        "node2_addr": {
          "VALUE": "int_median_value2",
          "EE_SIGN": "signature2",
          "EE_ETH_SENDER": "sender",
          "EE_ETH_SIGN": "str",
          "EE_HASH": "str",
          "EE_SENDER": "str",
        },
        ...
      }
      """
      # Send median to oracles
      if True:
        if self.first_time_median_table_sent is None:
          self.first_time_median_table_sent = self.time()
          # Even if the current oracle did not manage to compute its own median table it can still
          # compute the agreement from the received tables.
          if self.median_table is not None:
            self.dct_median_tables[self.node_addr] = self.median_table
        # endif first iteration of the current state

        early_stop_report = self.check_early_stop_report(self.STATES.S4_SEND_MEDIAN_TABLE)
        send_time = (self.last_time_median_table_sent is None) or (self.time() - self.last_time_median_table_sent >= self.cfg_send_interval)
        if early_stop_report or send_time:
          if self.cfg_debug_sync:
            self.P(f"Sending median {self._compute_simple_median_table(self.median_table)}")
          # endif debug_sync
          oracle_data = {
            OracleSyncCt.STAGE: self._get_current_state(),
            OracleSyncCt.MEDIAN_TABLE: self.median_table,
          }
          self.bc.sign(oracle_data, add_data=True, use_digest=True)
          if self.cfg_use_r1fs_during_consensus:
            # Will add cid to the message instead of self.median_table if
            # the upload to R1FS is successful.
            self.r1fs_add_data_to_message(
              message_dict=oracle_data,
              data_dict=self.median_table,
              data_key=OracleSyncCt.MEDIAN_TABLE
            )
          # endif use r1fs during consensus
          self.add_payload_by_fields(oracle_data=oracle_data)
          self.last_time_median_table_sent = self.time()
        # endif need to send
      # endif send

      # Receive medians from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        # In case the median table was uploaded in R1FS this check method will
        # also download it.
        if not self._check_received_median_table_ok(sender, oracle_data):
          continue

        stage = oracle_data[OracleSyncCt.STAGE]
        median_table = oracle_data[OracleSyncCt.MEDIAN_TABLE]

        simple_median = self._compute_simple_median_table(median_table)
        if self.cfg_debug_sync:
          log_str = self.log_received_message(
            sender=sender,
            stage=stage,
            data=self.dct_median_tables,
            return_str=True,
          )
          if self.cfg_debug_sync_full:
            log_str += f", {simple_median = }"
          # endif debug_sync_full
          self.P(log_str)
        # endif debug_sync

        self.dct_median_tables[sender] = median_table
      # end for
      return

    def _send_median_table_timeout(self):
      """
      Check if the exchange phase of the median table has finished.

      Returns
      -------
      bool: True if the exchange phase of the median table has finished, False otherwise
      """
      timeout_reached = (self.time() - self.first_time_median_table_sent) > self.cfg_send_period
      early_stopping = self._maybe_early_stop_phase(
        data=self.dct_median_tables,
        phase=self.STATES.S4_SEND_MEDIAN_TABLE,
        tables_str="median tables",
      )
      return early_stopping or timeout_reached
  """END S4_SEND_MEDIAN_TABLE CALLBACKS"""

  """S5_COMPUTE_AGREED_MEDIAN_TABLE CALLBACKS"""
  if True:
    def _compute_simple_agreed_value_table(self, agreed_value_table):
      """
      Compute a simple agreed value table with only the values.
      This method is used to print the agreed value table in a more readable format.

      Parameters
      ----------
      agreed_value_table : dict
          The agreed value table to simplify

      Returns
      -------
      dict : The simplified agreed value table
      """
      if agreed_value_table is None:
        return None
      simple_agreed_value_table = {}
      for node, dct_node in agreed_value_table.items():
        if dct_node.get('VALUE', 0) > 0:
          simple_agreed_value_table[node] = dct_node['VALUE']
        # endif node has value > 0
      # end for node

      return simple_agreed_value_table

    def _compute_agreed_median_table(self):
      """
      Compute the agreed median table from the median tables received from the oracles.
      For each node that was seen in the median tables, compute the most frequent median value.
      After this step, we should have the final availability values for the last epoch in
      self.compiled_agreed_median_table.
      The next steps are only for collecting signatures and maybe adapting the availability table
      format.
      dct_median_tables has the following format:
      {
        "oracle1_addr": {
          "node1_addr": {
            "VALUE": "int_median_value11",
            "EE_SIGN": "signature11",
            "EE_ETH_SENDER": "sender1",
            "EE_ETH_SIGN": "str",
            "EE_HASH": "str",
            "EE_SENDER": "str",
          },
          "node2_addr": {
            "VALUE": "int_median_value12",
            "EE_SIGN": "signature12",
            "EE_ETH_SENDER": "sender1",
            "EE_ETH_SIGN": "str",
            "EE_HASH": "str",
            "EE_SENDER": "str",
          },
          ...
        },
        ...
      }
      """
      self.update_participant_oracles(
        updated_participant_oracles=list(self.dct_median_tables.keys()),
        # The provided state is S4_SEND_MEDIAN_TABLE, since the median table is computed
        # from the local tables sent in S4_SEND_MEDIAN_TABLE state.
        state=self.STATES.S4_SEND_MEDIAN_TABLE
      )

      if not self._check_enough_oracles(participating_oracles=list(self.dct_median_tables.keys())):
        self.P("Could not compute agreed median table.", color='r')
        return
      # endif not enough oracles

      # expecting all median tables to contain all nodes
      # but some errors can occur, so this does no harm
      all_nodes = set().union(*(set(value_table.keys()) for value_table in self.dct_median_tables.values()))

      # keep in a dictionary a list with all median signed values for each node
      dct_node_median_signed_values = {}
      for node in all_nodes:
        dct_node_median_signed_values[node] = [
          median_table[node]
          for median_table in self.dct_median_tables.values()
          if node in median_table
        ]
      # end for node

      # compute the frequency of each median value for each node
      faulty_nodes = []
      min_frequency = self._count_half_of_valid_oracles()
      for node in all_nodes:
        dct_median_frequency = {}
        total_cnt_medians = len(dct_node_median_signed_values[node])
        for median in (dct_median.get('VALUE', 0) for dct_median in dct_node_median_signed_values[node]):
          if median not in dct_median_frequency:
            dct_median_frequency[median] = 0
          dct_median_frequency[median] += 1
        # end for median

        max_count = max(dct_median_frequency.values())
        most_frequent_median = next(k for k, v in dct_median_frequency.items() if v == max_count)

        # get all median table values that have the most frequent median
        # we do this because in the median table we find both the value and the signature
        lst_dct_freq_median = [
          dct_median
          for dct_median in dct_node_median_signed_values[node]
          if dct_median.get('VALUE', 0) == most_frequent_median
        ]

        median_frequency = len(lst_dct_freq_median)
        if median_frequency > min_frequency:
          if self.cfg_debug_sync_full:
            self.P(f"Computed agreed median table for node {node}: {most_frequent_median}. "
                   f"Dct freq {dct_median_frequency}")
          # endif debug_sync
          self.agreed_median_table[node] = {
            'VALUE': most_frequent_median,
            'SIGNATURES': lst_dct_freq_median,
          }
        else:
          # If the frequency of the most frequent median is not above the minimum frequency,
          # but the total number of oracles that reported this node is also not above the minimum frequency,
          # then the node is considered faulty and will not be included in the agreed median table.
          # This is done in order to resist attacks where malicious oracles report fictive nodes.
          # In case enough oracles reported this node, but they could not reach consensus,
          # it means that the network is under heavy attack or there is a serious system failure.
          if total_cnt_medians <= min_frequency:
            faulty_nodes.append({
              'NODE': node,
              'MOST_FREQUENT_MEDIAN': most_frequent_median,
              'FREQUENCY': median_frequency,
              'TOTAL_FREQUENCY': total_cnt_medians,
            })
          else:
            all_valid_oracles = []
            dct_value_senders = {}
            for dct_median in dct_node_median_signed_values[node]:
              curr_value = dct_median.get('VALUE', 0)
              dct_value_senders[curr_value] = dct_value_senders.get(curr_value, [])
              dct_value_senders[curr_value].append(dct_median.get('EE_SENDER'))
            # end for dct_median
            log_str = f"Failed to compute agreed median table for node {node}. "
            log_str += f"Could not achieve consensus. Highest median frequency is {median_frequency} <= "
            log_str += f"{min_frequency}. Dct freq:\n{self.json_dumps(dct_median_frequency, indent=2)}\n"
            log_str += f"Senders for each value:\n{self.json_dumps(dct_value_senders, indent=2)}\n"
            log_str += f"{self.json_dumps(self.dct_median_tables, indent=2)}\n"
            log_str += f"Current oracle will request epoch consensus from the other oracles. If no consensus is reached"
            log_str += f"epoch {self._current_epoch - 1} will be marked as faulty."
            self.P(log_str, color='r')
            # Failure at this point is a serious issue, since it means that the oracles did not reach consensus.
            # This can happen in only 2 cases:
            # 1. The network is attacked through malicious oracles or other means(e.g. oracle impersonation).
            # 2. Massive system failure in the network that led to all oracles failing to reach consensus.
            self.compiled_agreed_median_table = None
            return
          # endif not enough reports for node
        # endif median_frequency above min_frequency
      # end for

      if len(self.agreed_median_table) == 0:
        log_str = "Failed to compute agreed median table. Not enough online oracles"
        log_str += f"Current oracle will request epoch consensus from the other oracles. If no consensus is reached"
        log_str += f"epoch {self._current_epoch - 1} will be marked as faulty."
        self.P(log_str, color='r')
        self.compiled_agreed_median_table = None
        return
      # endif agreed_median_table empty
      if len(faulty_nodes) > 0:
        log_str = f"{len(faulty_nodes)} faulty nodes(<{min_frequency} reports) detected and not included:\n"
        log_str += "\n".join(
          f"\n\t{self.get_sender_str(faulty_node['NODE'])} | V:{faulty_node['MOST_FREQUENT_MEDIAN']} | "
          f"Frq: {faulty_node['FREQUENCY']} | T: {faulty_node['TOTAL_FREQUENCY']}"
          for faulty_node in faulty_nodes
        )
        self.P(log_str)
      # endif faulty nodes detected

      self.compiled_agreed_median_table = self._compute_simple_agreed_value_table(self.agreed_median_table)
      self.P(f"Successfully computed agreed median table from {len(self.dct_median_tables)} median tables.")

      self.current_epoch_computed = True
      return

    def _agreement_reached(self):
      """
      Check if the agreement table was successfully computed in `__compute_agreed_median_table`.
      Returns
      -------
      bool : True if the self.compiled_agreed_median_table is not None, False otherwise
      """
      return self.compiled_agreed_median_table is not None and len(self.compiled_agreed_median_table) > 0

    def _agreement_not_reached(self):
      """
      Check if the agreement table was not successfully computed in `__compute_agreed_median_table`.
      Returns
      -------
      bool : True if the self.compiled_agreed_median_table is None, False otherwise
      """
      return not self._agreement_reached()

  """END S5_COMPUTE_AGREED_MEDIAN_TABLE CALLBACKS"""

  """S6_SEND_AGREED_MEDIAN_TABLE CALLBACKS"""
  if True:
    def _receive_agreement_signature_and_maybe_send_agreement_signature(self):
      """
      Receive signatures for the compiled agreed median table from oracles and
      send own signature for the same agreement table to the oracles each `self.cfg_send_interval` seconds.
      Obs: this is used for gathering and validating signatures for the agreement.
      The compiled agreed median table should have the following format:
      {
        "node1_addr": "int_agreed_median_value1",
        "node2_addr": "int_agreed_median_value2",
        ...
      }
      It will not be sent, due to the fact that we only need to verify
      the signature using the cached table to know if the received table is
      the same as the cached one.
      """
      # Send agreed value to oracles
      if True:
        is_first_iteration = False
        if self.first_time__agreement_signature_sent is None:
          self.first_time__agreement_signature_sent = self.time()
          is_first_iteration = True
        # endif first iteration of the current state

        early_stop_report = self.check_early_stop_report(self.STATES.S6_SEND_AGREED_MEDIAN_TABLE)
        send_time = (self.last_time__agreement_signature_sent is None) or (self.time() - self.last_time__agreement_signature_sent >= self.cfg_send_interval)
        if early_stop_report or send_time:
          # Remove 0 values from the compiled agreed median table.
          # This is done to both reduce the size of the signed data and to avoid
          # additional zero values appearing when verifying the table.
          non_zero_compiled_agreed_table = {k: v for k, v in self.compiled_agreed_median_table.items() if v != 0}

          signature_dict = {
            OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE: non_zero_compiled_agreed_table,
            # self._current_epoch - 1, since the consensus is for the previous epoch
            OracleSyncCt.EPOCH: self._current_epoch - 1,
          }
          self.bc.sign(signature_dict, add_data=True, use_digest=True)
          signature_dict.pop(OracleSyncCt.EPOCH)
          signature_dict.pop(OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE)

          oracle_data = {
            # The compiled agreed median table itself will not be sent,
            # since we only need to verify the signature to know if the table is the same as
            # the cached one.
            OracleSyncCt.STAGE: self._get_current_state(),
            OracleSyncCt.AGREEMENT_SIGNATURE: signature_dict
          }

          if is_first_iteration:
            self.compiled_agreed_median_table_signatures[self.node_addr] = signature_dict
          # endif first iteration

          if self.cfg_debug_sync:
            self.P(f"Sending agreement signature for: {non_zero_compiled_agreed_table}")
          self.add_payload_by_fields(oracle_data=oracle_data)
          self.last_time__agreement_signature_sent = self.time()
        # endif need to send
      # endif send

      # Receive agreed values from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        if not self._check_received_agreement_signature_ok(sender, oracle_data):
          continue

        signature_dict = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURE]

        if self.cfg_debug_sync:
          stage = oracle_data[OracleSyncCt.STAGE]
          log_str = self.log_received_message(
            sender=sender,
            stage=stage,
            data=self.compiled_agreed_median_table_signatures,
            return_str=True
          )
          if self.cfg_debug_sync_full:
            log_str += f", {signature_dict = }"
          # endif debug_sync_full
          self.P(log_str)
        # endif debug_sync
        self.compiled_agreed_median_table_signatures[sender] = signature_dict
      # endfor received messages
      return

    def _send_agreement_signature_timeout(self):
      """
      Check if the exchange phase of the agreed median table has finished.

      Returns
      -------
      bool: True if the exchange phase of the agreed median table has finished, False otherwise
      """
      timeout_reached = (self.time() - self.first_time__agreement_signature_sent) > self.cfg_send_period
      early_stopping = self._maybe_early_stop_phase(
        data=self.compiled_agreed_median_table_signatures,
        phase=self.STATES.S6_SEND_AGREED_MEDIAN_TABLE,
        tables_str="agreement tables",
      )
      return early_stopping or timeout_reached
  """END S6_SEND_AGREED_MEDIAN_TABLE CALLBACKS"""

  """S10_EXCHANGE_AGREEMENT_SIGNATURES CALLBACKS"""
  if True:
    def _exchange_agreement_signatures(self):
      """
      Exchange agreement signatures between oracles.
      """
      # Send signatures to oracles
      if True:
        if self.first_time__agreement_signatures_exchanged is None:
          self.first_time__agreement_signatures_exchanged = self.time()

        early_stop_report = self.check_early_stop_report(self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES)
        last_sent_time = self.last_time__agreement_signatures_exchanged
        if early_stop_report or last_sent_time is None or self.time() - last_sent_time >= self.cfg_send_interval:
          oracle_data = {
            OracleSyncCt.STAGE: self._get_current_state(),
            OracleSyncCt.AGREEMENT_SIGNATURES: self.compiled_agreed_median_table_signatures,
          }
          self.add_payload_by_fields(oracle_data=oracle_data)
          self.last_time__agreement_signatures_exchanged = self.time()
        # endif need to send
      # endif send

      # Receive signatures from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        if not self._check_received_agreement_signatures_ok(sender, oracle_data):
          continue

        signatures_dict = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURES]
        # add the received signatures to the compiled agreed median table signatures
        self.compiled_agreed_median_table_signatures = {
          **signatures_dict,
          **self.compiled_agreed_median_table_signatures
        }

        if self.cfg_debug_sync:
          stage = oracle_data[OracleSyncCt.STAGE]
          senders = list(signatures_dict.keys())
          total_number_of_oracles = self.total_participating_oracles()
          sender_str = self.get_sender_str(sender)
          self.P(
            f"Received {len(signatures_dict)}/{total_number_of_oracles} agreement signatures from oracle {sender_str}: {stage = }, {senders = }")
        # endif debug_sync
      # endfor received messages
      return

    def _exchange_signatures_timeout(self):
      """
      Check if the exchange phase of the agreement signatures has finished.

      Returns
      -------
      bool: True if the exchange phase of the agreement signatures has finished, False otherwise
      """
      timeout_reached = (self.time() - self.first_time__agreement_signatures_exchanged) > (
          self.cfg_send_period * SIGNATURES_EXCHANGE_MULTIPLIER)
      early_stopping = self._maybe_early_stop_phase(
        data=self.compiled_agreed_median_table_signatures,
        phase=self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES,
        tables_str="agreement signatures",
        ignore_tolerance=True
      )
      return early_stopping or timeout_reached
  """END S10_EXCHANGE_AGREEMENT_SIGNATURES CALLBACKS"""

  """S7_UPDATE_EPOCH_MANAGER CALLBACKS"""
  if True:
    def _update_epoch_manager_with_agreed_median_table(
        self, epoch=None, compiled_agreed_median_table=None, agreement_signatures=None,
        epoch_is_valid=None, agreement_cid=None, signatures_cid=None, debug=True
    ):
      """
      Update the epoch manager with the compiled agreed median table and the agreement signatures for the epoch.
      If all parameters are None, update the last epoch with `self.compiled_agreed_median_table` and
      `self.compiled_agreed_median_table_signatures`.

      Otherwise, update the target epoch with the compiled agreed median table.
      If a consensus for the specified epoch was not reached, mark the epoch as faulty.

      Parameters
      ----------
      epoch : int, optional
          The epoch to update, by default None
      compiled_agreed_median_table : dict, optional
          The compiled agreed median table to add to epoch manager history, by default None
      agreement_signatures : dict, optional
          The agreement signatures to add to epoch manager history, by default None
      epoch_is_valid : bool, optional
          The validity of the epoch, by default None.
          An epoch will be valid if consensus was reached for it.
      agreement_cid : str, optional
          The CID of the agreement table, by default None
      signatures_cid : str, optional
          The CID of the agreement signatures, by default None
      debug : bool, optional
          Print debug messages, by default True
      """
      # Check if this is a single call in the consensus process or part
      # of the agreement request process that may include multiple updates.
      is_single_call = False
      if epoch is None:
        # update previous epoch, since if this method is called without epoch,
        # it is part of the consensus process for the previous epoch.
        # TODO: should we switch to self.netmon.epoch_manager.get_current_epoch() - 1 everywhere?
        #  both should be equivalent
        epoch = self._current_epoch - 1
        is_single_call = True
      # end if

      if compiled_agreed_median_table is None:
        compiled_agreed_median_table = self.compiled_agreed_median_table
      # end if

      if agreement_signatures is None:
        agreement_signatures = self.compiled_agreed_median_table_signatures

      if epoch_is_valid is None:
        signers = list(agreement_signatures.keys())
        oracle_list = self.get_oracle_list()
        oracle_signers = [oracle for oracle in oracle_list if oracle in signers]
        epoch_is_valid = len(oracle_signers) > 0
      # endif epoch_is_valid

      if epoch <= self._last_epoch_synced:
        if debug:
          self.P("Epoch manager history already updated with this epoch", color='r')
        return

      if epoch > self._last_epoch_synced + 1:
        if debug:
          self.P(f"Detected a skip in epoch sync algorithm. "
                 f"Last known epoch synced {self._last_epoch_synced} "
                 f"Current epoch {epoch}", color='r')
        # If we skip the update here, the epoch manager will not be able to update in case
        # it receives the agreed median table for several epochs at once(maybe
        # at init when syncing with other active oracles).
        # Obs: this method is also used for the update from S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE
        # maybe handle that update differently?

        # return

      if self.cfg_debug_sync_full:
        valid_str = "VALID" if epoch_is_valid else "INVALID"
        self.P(
          f'Attempting to update with the following {valid_str} agreed median table:\n{compiled_agreed_median_table}')
      # endif debug_sync_full

      if epoch_is_valid:
        success = self.netmon.epoch_manager.update_epoch_availability(
          epoch=epoch,
          availability_table=compiled_agreed_median_table,
          agreement_signatures=agreement_signatures,
          debug=self.cfg_debug_sync_full,
          agreement_cid=agreement_cid,
          signatures_cid=signatures_cid
        )
      else:
        success = self.netmon.epoch_manager.mark_epoch_as_faulty(
          epoch=epoch,
          debug=debug
        )
      # endif epoch_is_valid

      if success:
        if debug:
          valid_str = "VALID" if epoch_is_valid else "INVALID"
          announced_cnt = len(self._announced_participating)
          log_str = f'Successfully synced epoch {epoch} with {valid_str} agreed median table '
          log_str += f'and {len(agreement_signatures)} agreement signatures from '
          log_str += f'{announced_cnt} announced participants at the start.\n'
          log_str += f"Initially announced participants:"
          log_str += "".join([
            f"\n\t`{self.netmon.network_node_eeid(node_addr)}` <{node_addr}>"
            for node_addr in self._announced_participating
          ])
          lst_participants_and_state = [
            (set(self.dct_local_tables.keys()), self.STATES.S2_SEND_LOCAL_TABLE),
            (set(self.dct_median_tables.keys()), self.STATES.S4_SEND_MEDIAN_TABLE),
            (set(self.compiled_agreed_median_table_signatures.keys()), self.STATES.S6_SEND_AGREED_MEDIAN_TABLE),
          ]
          initially_announced_participants = self._announced_participating
          for current_participants, state in lst_participants_and_state:
            missing_participants = initially_announced_participants - current_participants
            log_str += f"\n\t{len(missing_participants)} missing participants during `{state}`:"
            log_str += "".join([
              f"\n\t\t`{self.netmon.network_node_eeid(node_addr)}` <{node_addr}>"
              for node_addr in missing_participants
            ])
            initially_announced_participants = current_participants
          # endfor participants and states
          self.P(log_str)

          if self.cfg_debug_sync_full:
            self.P(f'DEBUG EM data after update:\n{self.netmon.epoch_manager.data}')
        self._last_epoch_synced = epoch
        # In case of multiple updates, the save is only needed after the last update.
        if is_single_call:
          self.netmon.epoch_manager.maybe_update_cached_data(force=True)
          self.netmon.epoch_manager.save_status()
        # endif part of consensus process
      return
  """END S7_UPDATE_EPOCH_MANAGER CALLBACKS"""

  """S8_SEND_REQUEST_AGREED_MEDIAN_TABLE CALLBACKS"""
  if True:
    def handle_received_agreed_median_table(self, dct_message: dict):
      success = False
      sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
      oracle_data = dct_message.get('ORACLE_DATA')

      if not self._check_received_epoch__agreed_median_table_ok(sender, oracle_data):
        return success

      first_needed_epoch = self._last_epoch_synced + 1
      last_needed_epoch = self._current_epoch - 1
      epochs_range = range(first_needed_epoch, last_needed_epoch + 1)

      # In case the message contains more than the needed epoch keys
      # only the needed keys will be downloaded from R1FS if needed.
      needed_epoch_keys = [
        str(x)
        for x in epochs_range
      ]

      # sort epoch_keys in ascending order
      epoch_keys = oracle_data[OracleSyncCt.EPOCH_KEYS]
      received_epochs = sorted(list(set(epoch_keys)))
      # filter received epochs to keep only the needed ones
      received_epochs = [
        epoch for epoch in received_epochs
        if epoch in epochs_range
      ]

      stage = oracle_data[OracleSyncCt.STAGE]
      log_str = self.log_received_message(
        sender=sender,
        data=self.dct_agreed_availability_signatures,
        stage=stage,
        return_str=True
      )
      log_str += f", {received_epochs = }\n"
      log_str += f"Keeping only tables for epochs [{first_needed_epoch}, {last_needed_epoch}]"
      self.P(log_str)

      cnt_expected_epochs = last_needed_epoch - first_needed_epoch + 1
      enough_data_received = len(received_epochs) == cnt_expected_epochs
      limits_received = first_needed_epoch in received_epochs and last_needed_epoch in received_epochs

      if not enough_data_received or not limits_received:
        # Expected epochs in range [last_epoch_synced + 1, current_epoch - 1]
        # received epochs don t contain the full range
        if self.cfg_debug_sync:
          min_epoch = min(received_epochs) if len(received_epochs) > 0 else None
          max_epoch = max(received_epochs) if len(received_epochs) > 0 else None
          cnt_epochs = len(received_epochs)
          msg = f'Expected epochs {cnt_epochs} in range [{first_needed_epoch}, {last_needed_epoch}] '
          msg += f'and received only {len(received_epochs)} epochs (min: {min_epoch}, max: {max_epoch}). '
          msg += f'Ignoring...'
          self.P(msg, color='r')
        return success
      # endif received epochs not containing the full requested interval

      # Here, both the agreed median table and the agreement signatures should have the same keys,
      # but as string instead of int. We also know that in epoch_keys we have
      # the keys in int format. Thus, we need to convert the keys of the received tables
      dct_epoch_agreed_median_table = oracle_data[OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE]
      dct_epoch_agreed_median_table = {
        k: v
        for k, v in dct_epoch_agreed_median_table.items() if k in needed_epoch_keys
      }
      agreement_success, dct_epoch_agreed_median_table, dct_epoch_agreement_cid = self.r1fs_get_data_from_nested_message(
        nested_message_dict=dct_epoch_agreed_median_table,
        return_cids=True,
      )
      sender_str = self.get_sender_str(sender)
      if not agreement_success:
        if self.cfg_debug_sync:
          self.P(f"Failed to download agreed median table from R1FS for oracle {sender_str}. Ignoring", color='r')
        return success
      # endif not agreement_success
      dct_epoch_agreement_signatures = oracle_data[OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES]
      dct_epoch_agreement_signatures = {
        k: v
        for k, v in dct_epoch_agreement_signatures.items() if k in needed_epoch_keys
      }
      signatures_success, dct_epoch_agreement_signatures, dct_epoch_signatures_cid = self.r1fs_get_data_from_nested_message(
        nested_message_dict=dct_epoch_agreement_signatures,
        return_cids=True,
        process_only_keys=needed_epoch_keys
      )
      if not signatures_success:
        if self.cfg_debug_sync:
          self.P(f"Failed to download agreement signatures from R1FS for oracle {sender_str}. Ignoring", color='r')
        return success
      # endif not signatures_success
      dct_epoch_is_valid = oracle_data[OracleSyncCt.EPOCH__IS_VALID]
      id_to_node_address = oracle_data.get(OracleSyncCt.ID_TO_NODE_ADDRESS, {})
      # Unsqueeze the epoch dictionaries if they are squeezed.
      [dct_epoch_agreed_median_table, dct_epoch_agreement_signatures] = self._maybe_unsqueeze_epoch_dictionaries(
        lst_squeezed_epoch_dictionaries=[dct_epoch_agreed_median_table, dct_epoch_agreement_signatures],
        id_to_keys=id_to_node_address,
      )

      # convert to dict with int keys
      dct_epoch_agreed_median_table = {
        # In case the agreement table is sent through R1FS, the keys will already be in int format.
        epoch: dct_epoch_agreed_median_table[str(epoch)]
        for epoch in received_epochs
      }
      dct_epoch_agreement_signatures = {
        epoch: dct_epoch_agreement_signatures[str(epoch)]
        for epoch in received_epochs
      }
      dct_epoch_is_valid = {
        epoch: dct_epoch_is_valid[str(epoch)]
        for epoch in received_epochs
      }
      dct_epoch_agreement_cid = {
        epoch: dct_epoch_agreement_cid.get(str(epoch))
        for epoch in received_epochs
      }
      dct_epoch_signatures_cid = {
        epoch: dct_epoch_signatures_cid.get(str(epoch))
        for epoch in received_epochs
      }
      if self.cfg_debug_sync_full:
        msg = f"DEBUG Decoded following dct_epoch_agreed_median_table:\n"
        msg += f"{dct_epoch_agreed_median_table}\n"
        msg += f'With the following validities: {dct_epoch_is_valid}\n'
        msg += f"And the following signatures: {dct_epoch_agreement_signatures}\n"
        self.P(msg)
      # endif debug_sync_full

      for epoch, agreed_median_table in dct_epoch_agreed_median_table.items():
        # At this point we did not need to convert the keys of the dictionaries yet,
        # because in valid messages both the agreement table and the agreement signatures
        # should have the same keys and in the checked sub-dictionaries there weren't any
        # non-string keys to begin with.
        # However, we converted it before in order for the epoch key to be in int format,
        # since at the verification of the signatures we also need the epoch as int.
        epoch_signatures = dct_epoch_agreement_signatures.get(epoch)
        epoch_is_valid = dct_epoch_is_valid.get(epoch)
        if self.cfg_debug_sync_full:
          msg = f'##########################\n'
          msg += f'DEBUG Received availability table for epoch {epoch} from {sender = } with values:\n'
          msg += f'{agreed_median_table}\n AND signatures:\n{epoch_signatures}\n###################'
          self.P(msg)
        # endif debug_sync_full

        if not self._check_agreed_median_table(
            sender=sender, agreed_median_table=agreed_median_table,
            epoch_signatures=epoch_signatures, epoch=epoch,
            epoch_is_valid=epoch_is_valid,
            debug=False
        ):
          # if one signature for the received table is invalid, ignore the entire message
          if self.cfg_debug_sync:
            self.P(f"Received invalid availability table from {sender = }[{epoch=} invalid]. Ignoring", color='r')
          return success
      # end for epoch agreed table

      self.dct_agreed_availability_table[sender] = {
        # No need for get here, since in S0 we send a continuous range of epochs.
        i: dct_epoch_agreed_median_table[i]
        for i in epochs_range
      }
      self.dct_agreed_availability_signatures[sender] = {
        # No need for get here, since in S0 we send a continuous range of epochs.
        i: dct_epoch_agreement_signatures[i]
        for i in epochs_range
      }
      self.dct_agreed_availability_is_valid[sender] = {
        # No need for get here, since in S0 we send a continuous range of epochs.
        i: dct_epoch_is_valid[i]
        for i in epochs_range
      }
      self.dct_agreed_availability_cid[sender] = {
        i: dct_epoch_agreement_cid.get(i)
        for i in epochs_range
      }
      self.dct_agreement_signatures_cid[sender] = {
        i: dct_epoch_signatures_cid.get(i)
        for i in epochs_range
      }
      success = True
      return success

    def _receive_agreed_median_table_and_maybe_request_agreed_median_table(self):
      """
      Receive the agreed median table from the oracles and
      request the agreed median table from the oracles each `self.cfg_send_interval` seconds.

      - if node receives the agreed median table for the last epoch, update the epoch manager
      - if node connects at 00:01, receives availability from 2 days ago, transition back to this state, then to s0
      - if node connects at 0X:00, receives availability from prev day, transition back to s0
      """

      if self.first_time_request_agreed_median_table_sent is not None:
        # Receive agreed values from oracles
        for dct_message in self.get_received_messages_from_oracles():
          success = self.handle_received_agreed_median_table(dct_message=dct_message)
        # end for received messages
      # endif first agreement request sent

      # Return if no need to sync; the last epoch synced is the previous epoch
      if self._last_epoch_synced_is_previous_epoch():
        self.P("Last epoch synced is the previous epoch. No need to sync")
        return

      # Send request to get agreed value from oracles
      if self.first_time_request_agreed_median_table_sent is None:
        self.first_time_request_agreed_median_table_sent = self.time()

      if self.last_time_request_agreed_median_table_sent is not None and self.time() - self.last_time_request_agreed_median_table_sent < self.cfg_send_interval:
        return

      oracle_data = {
        OracleSyncCt.STAGE: self._get_current_state(),
        OracleSyncCt.REQUEST_AGREED_MEDIAN_TABLE: True,
        'START_EPOCH': self._last_epoch_synced + 1,
        'END_EPOCH': self._current_epoch - 1,
      }

      # TODO: log the number of the request
      current_time = self.time()
      elapsed_time = round(current_time - self.first_time_request_agreed_median_table_sent, 1)
      self.P(
        f"Request for agreed median table for epochs {self._last_epoch_synced + 1} to {self._current_epoch - 1}"
        f"[e:{elapsed_time}/t:{self.get_request_agreement_timeout()}]")
      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time_request_agreed_median_table_sent = self.time()
      return

    def get_request_agreement_timeout(self):
      return self.cfg_send_period * REQUEST_AGREEMENT_TABLE_MULTIPLIER

    def _send_request_agreed_median_table_timeout(self):
      """
      Check if the exchange phase of the agreed median table has finished.

      Returns
      -------
      bool: True if the exchange phase of the agreed median table has finished, False otherwise
      """
      # In case the first request was not sent, the timeout is not expired.
      if self.first_time_request_agreed_median_table_sent is None:
        return False
      # 10 times the normal period because we want to make sure that oracles can respond
      wait_threshold = self.get_request_agreement_timeout()
      timeout_expired = self.time() - self.first_time_request_agreed_median_table_sent > wait_threshold
      early_stopping = self._maybe_early_stop_phase(
        data=self.dct_agreed_availability_table,
        phase=self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
        tables_str="agreement tables",
        # Here, tolerance is 1, since at least the current oracle is not able
        # to respond.
        tolerance=1,
      )
      return not self._last_epoch_synced_is_previous_epoch() and (early_stopping or timeout_expired)

    def _last_epoch_synced_is_previous_epoch(self):
      """
      Check if the agreed median table for the last epoch has been received.

      Returns
      -------
      bool: True if the agreed median table for the last epoch has been received, False otherwise
      """
      return self._last_epoch_synced == self._current_epoch - 1

    def _last_epoch_synced_is_not_previous_epoch(self):
      """
      Check if the agreed median table for the last epoch has not been received.

      Returns
      -------
      bool: True if the agreed median table for the last epoch has not been received, False otherwise
      """
      return not self._last_epoch_synced_is_previous_epoch()

  """END S8_SEND_REQUEST_AGREED_MEDIAN_TABLE CALLBACKS"""

  """S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE CALLBACKS"""
  if True:
    def _reset_for_agreement_request_retry(self):
      log_str = f"Failed to compute requested agreed median table.\n"
      log_str += f"Resetting to initial state and retrying the agreement request."
      self.P(log_str, color='r', boxed=True)
      self._reset_to_initial_state()
      return


    def _mark_requested_epochs_as_faulty(self):
      # If no agreed median table received, mark all requested epochs as invalid.
      requested_start_epoch = self._last_epoch_synced + 1
      requested_end_epoch = self._current_epoch - 1
      self.P(
        f"No agreed median table received. "
        f"Marking all requested epochs (from {requested_start_epoch} to {requested_end_epoch}) as invalid!",
        color='r'
      )
      for epoch in range(requested_start_epoch, requested_end_epoch + 1):
        self.netmon.epoch_manager.mark_epoch_as_faulty(epoch=epoch, debug=self.cfg_debug_sync_full)
      # endfor epoch
      return

    def _compute_requested_agreed_median_table(self):
      """
      Compute the agreed median table from the received tables and received signatures.

      self.dct_agreed_availability_table = {
        "oracle1": {
          "epoch1": {
            "node1": "int_agreed_median_value111",
            "node2": "VALUE": "int_agreed_median_value112",
          ...
          },
          "epoch2": {
            "node1": "int_agreed_median_value121",
            "node2": "int_agreed_median_value122",
          ...
          }
        },
        "oracle2": {
          "epoch1": {
            "node1": "int_agreed_median_value211",
            "node2": "int_agreed_median_value212",
          ...
          }
        }
        ...
      }
      AND
      self.dct_agreed_availability_signatures = {
        "oracle1": {
          "epoch1": {
            "signer_oracle111": {
              "EE_SIGN: "signature111",
              "EE_SENDER": "signer_oracle111",
              ...
            },
            "signer_oracle112": {
              "EE_SIGN: "signature112",
              "EE_SENDER": "signer_oracle112",
              ...
            }
          },
          "epoch2": {
            "signer_oracle121": {
              "EE_SIGN: "signature121",
              "EE_SENDER": "signer_oracle121",
              ...
            },
            "signer_oracle122": {
              "EE_SIGN: "signature122",
              "EE_SENDER": "signer_oracle122",
              ...
            }
          }
        },
        "oracle2": {
          "epoch1": {
            "signer_oracle211": {
              "EE_SIGN: "signature211",
              "EE_SENDER": "signer_oracle211",
              ...
            },
            "signer_oracle212": {
              "EE_SIGN: "signature212",
              "EE_SENDER": "signer_oracle212",
              ...
            }
          },
          "epoch2": {
            "signer_oracle221": {
              "EE_SIGN: "signature221",
              "EE_SENDER": "signer_oracle221",
              ...
            },
            "signer_oracle222": {
              "EE_SIGN: "signature222",
              "EE_SENDER": "signer_oracle222",
              ...
            }
          }
        }
      }
      AND
      self.dct_agreed_availability_is_valid = {
        "oracle1": {
          "epoch1": "bool_is_valid11",
          "epoch2": "bool_is_valid12"
        },
        "oracle2": {
          "epoch1": "bool_is_valid21",
          "epoch2": "bool_is_valid22"
        }
      }
      AND
      self.dct_agreed_availability_cid = {
        "oracle1": {
          "epoch1": "cid111",
          "epoch2": "cid112"
        },
        "oracle2": {
          "epoch1": "cid211",
          "epoch2": "cid212"
        }
      }
      """
      # TODO: since faulty epochs were introduced, we might consider computing the received agreement
      #  for each epoch separately and then mark the faulty epochs as invalid.
      #  This should not be necessary if the oracles are honest, but it can be a good measure
      # 0. Check if there are any received tables
      if len(self.dct_agreed_availability_table) == 0:
        self._mark_requested_epochs_as_faulty()
        return
      # endif no agreed median table received

      # 1. Compute hashes for every availability table for faster frequency computing.
      dct_agreement_hashes = {
        oracle_address: self.get_hash(self.json_dumps(dct_epoch_availability_table), algorithm='sha256')
        for oracle_address, dct_epoch_availability_table in self.dct_agreed_availability_table.items()
      }

      # 2. Compute the frequency of each availability table for each epoch.
      hash_frequencies = {}
      for hash_value in dct_agreement_hashes.values():
        hash_frequencies[hash_value] = hash_frequencies.get(hash_value, 0) + 1

      # 3. Get the most frequent hash.
      max_frequency = max(hash_frequencies.values())

      # 4. Check if the most frequent hash has the minimum number of occurrences.
      if max_frequency <= (len(dct_agreement_hashes) // 2):
        self.P(
          f"Failed to compute requested agreed median table. "
          f"Could not achieve consensus. Highest hash frequency is {max_frequency}, while the minimum required"
          f"frequency is {len(dct_agreement_hashes) // 2}."
          f"Hash frequencies:\n{self.json_dumps(hash_frequencies, indent=2)}\n"
          f"Agreement hashes:\n{self.json_dumps(dct_agreement_hashes, indent=2)}",
          color='r'
        )
        # This is a situation without recovery -- it can happen if the network is attacked
        # either the node is malicious or some oracles are malicious.
        # In this case all requested epochs will be marked as faulty.
        self._mark_requested_epochs_as_faulty()
        return
      # endif max_frequency above minimum required

      # 5. Get the candidates with the most frequent hash.
      candidates = [
        oracle_address for oracle_address, hash_value in dct_agreement_hashes.items()
        if hash_frequencies[hash_value] == max_frequency
      ]

      # 6. Get a random candidate.
      chosen_oracle = self.np.random.choice(candidates)

      # 7. Update epoch manager with the agreed median table.
      epoch__agreed_median_table = self.dct_agreed_availability_table[chosen_oracle]
      epoch__agreement_signatures = self.dct_agreed_availability_signatures[chosen_oracle]
      epoch__agreed_is_valid = self.dct_agreed_availability_is_valid[chosen_oracle]
      epoch__agreed_cid = self.dct_agreed_availability_cid[chosen_oracle]
      epoch__signatures_cid = self.dct_agreement_signatures_cid[chosen_oracle]
      for epoch, agreement_table in epoch__agreed_median_table.items():
        agreement_signatures = epoch__agreement_signatures[epoch]
        epoch_is_valid = epoch__agreed_is_valid[epoch]
        agreement_cid = epoch__agreed_cid[epoch]
        signatures_cid = epoch__signatures_cid[epoch]
        self._update_epoch_manager_with_agreed_median_table(
          epoch=epoch,
          compiled_agreed_median_table=agreement_table,
          agreement_signatures=agreement_signatures,
          epoch_is_valid=epoch_is_valid,
          agreement_cid=agreement_cid,
          signatures_cid=signatures_cid,
          debug=self.cfg_debug_sync_full
        )
      # endfor epoch
      self.P(f"Successfully computed requested agreed median table from {len(candidates)} oracles. ")
      # Save the epoch manager status after the update.
      self.netmon.epoch_manager.save_status()
      self.netmon.epoch_manager.maybe_update_cached_data(force=True)
      return
  """END S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE CALLBACKS"""
