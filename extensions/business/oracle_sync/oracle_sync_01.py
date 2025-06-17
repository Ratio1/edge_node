"""
This plugin is used to synchronize the availability tables between the oracles.
Initially thought as a way to synchronize the last availability table, it was 
extended to synchronize the availability tables for all epochs.

This plugin works with a state machine, to better separate the different stages of the sync process.
It works as follows:

On connection, the plugin requests the availability tables for its missing epochs from the online oracles.
Then, in a loop
0. Wait for the epoch to change
1. Compute the local table of availability
  - if the node cannot participate in the sync process, it will request the availability table from the other oracles
  - otherwise, it will continue to the next stage
2. Exchange the local table of availability between oracles
3. Compute the median table of availability, based on the local tables received from the oracles 
  - for each node in the table, compute the median value and sign it
4. Exchange the median table of availability between oracles
5. Compute the agreed median table of availability, based on the median tables received from the oracles
  - for each node in the table, compute the most frequent median value
  - sign the final agreed table (only the non-zero values)
6. Exchange the agreed median table of availability + signature between oracles
6'. Extra step for exchanging the gathered signatures between oracles
7. Update the epoch manager with the agreed median table
Jump to 0

Pipeline config:
{
  "NAME": "oracle_sync",
  "PLUGINS": [
    {
      "INSTANCES": [
        {
          "INSTANCE_ID": "default",
        }
      ],
      "SIGNATURE": "ORACLE_SYNC_01"
    }
  ],
  "TYPE": "NetworkListener",
  "PATH_FILTER" : [None, None, "ORACLE_SYNC_01", None],
  "MESSAGE_FILTER" : {},
}


To deploy for the first time:
1. Set `last_epoch_synced = X-1` in epoch manager
2. Start boxes in epoch X-1, let them run through epoch X-1, and let them enter in epoch X
3. During epoch X, deploy the plugin on all oracles
4. The plugins will skip the first sync process, because current epoch (X)
   is the same as the last epoch synced (X-1) + 1
4. Let all oracles run through epoch X, until they enter epoch X+1
5. When they enter epoch X+1, the plugin will start the sync process
"""

from naeural_core.business.base.network_processor import NetworkProcessorPlugin
from naeural_core.constants import SUPERVISOR_MIN_AVAIL_PRC, EPOCH_MAX_VALUE

"""
TODO list:
- rename states so that STATE8 becomes STATE0 and STATES 0-7 become 1-8
"""

MAX_RECEIVED_MESSAGES_SIZE = 1000
DEBUG_MODE = False
SIGNATURES_EXCHANGE_MULTIPLIER = 5
REQUEST_AGREEMENT_TABLE_MULTIPLIER = 60 if DEBUG_MODE else 20
LOCAL_TABLE_SEND_MULTIPLIER = 3 if DEBUG_MODE else 1

# Full availability means that the node was seen online for at least SUPERVISOR_MIN_AVAIL_PRC% of the time.
FULL_AVAILABILITY_THRESHOLD = round(SUPERVISOR_MIN_AVAIL_PRC * EPOCH_MAX_VALUE)
# While full availability is according to the SUPERVISOR_MIN_AVAIL_PRC, potentially full availability
# takes into consideration that the 2 accepted periods of offline time could have been in different intervals.
# Thus, the accepted offline time will be doubled and the threshold will be
# EPOCH_MAX_VALUE - 2 * (EPOCH_MAX_VALUE - FULL_AVAILABILITY_THRESHOLD).

POTENTIALLY_FULL_AVAILABILITY_THRESHOLD = EPOCH_MAX_VALUE - 2 * (EPOCH_MAX_VALUE - FULL_AVAILABILITY_THRESHOLD)
ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD = 1
ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN = EPOCH_MAX_VALUE - POTENTIALLY_FULL_AVAILABILITY_THRESHOLD


_CONFIG = {
  **NetworkProcessorPlugin.CONFIG,
  # Only the oracles should sync the availability tables
  "RUNS_ONLY_ON_SUPERVISOR_NODE": True,

  # Jobs should have a bigger inputs queue size, because they have to process everything
  'MAX_INPUTS_QUEUE_SIZE': 500,

  # Allow empty inputs in order to send pings from time to time
  'ALLOW_EMPTY_INPUTS': True,
  'PROCESS_DELAY': 0,

  'SEND_PERIOD': 30,  # seconds
  'SEND_INTERVAL': 15,  # seconds

  # This flag will be enabled after further testing of R1FS.
  "USE_R1FS": False,

  'EPOCH_START_SYNC': 0,
  # TODO: disable this flag in the future after further testing
  'DEBUG_SYNC': True,
  # More powerful debug sync
  'DEBUG_SYNC_FULL': False,
  'ORACLE_LIST_REFRESH_INTERVAL': 300,  # seconds

  'VALIDATION_RULES': {
    **NetworkProcessorPlugin.CONFIG['VALIDATION_RULES'],
  },
}

if DEBUG_MODE:
  # In the case of debug mode, messages may need to be sent more often.
  _CONFIG['SEND_PERIOD'] = 10
  _CONFIG['SEND_INTERVAL'] = 5
# endif DEBUG_MODE

__VER__ = '0.1.0'


class OracleSyncCt:
  MEDIAN_TABLE = 'MEDIAN_TABLE'
  AGREED_MEDIAN_TABLE = 'AGREED_MEDIAN_TABLE'
  COMPILED_AGREED_MEDIAN_TABLE = 'COMPILED_AGREED_MEDIAN_TABLE'
  LOCAL_TABLE = 'LOCAL_TABLE'
  REQUEST_AGREED_MEDIAN_TABLE = 'REQUEST_AGREED_MEDIAN_TABLE'
  EPOCH__AGREED_MEDIAN_TABLE = 'EPOCH__AGREED_MEDIAN_TABLE'
  EPOCH__AGREEMENT_SIGNATURES = 'EPOCH__AGREEMENT_SIGNATURES'
  EPOCH__IS_VALID = 'EPOCH__IS_VALID'
  EPOCH_KEYS = 'EPOCH_KEYS'
  STAGE = 'STAGE'
  EPOCH = 'EPOCH'
  NODE = 'NODE'
  AGREEMENT_SIGNATURE = 'AGREEMENT_SIGNATURE'
  AGREEMENT_SIGNATURES = 'AGREEMENT_SIGNATURES'
  AVAILABILITIES = 'AVAILABILITIES'



VALUE_STANDARDS = {
  OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: {
    # 'type': dict,
    'type': (str, dict),
    'maybe_cid': True
  },
  OracleSyncCt.EPOCH_KEYS: {
    'type': list,
  },
  OracleSyncCt.STAGE: {
    'type': str,
  },
  OracleSyncCt.LOCAL_TABLE: {
    # 'type': dict,
    'type': (str, dict),
    'maybe_cid': True
  },
  OracleSyncCt.MEDIAN_TABLE: {
    # 'type': dict,
    'type': (str, dict),
    'maybe_cid': True
  },
  OracleSyncCt.AGREED_MEDIAN_TABLE: {
    'type': dict,
  },
  'EE_SIGN': {
    'type': str,
  }
}


class OracleSync01Plugin(NetworkProcessorPlugin):

  class STATES:
    S0_WAIT_FOR_EPOCH_CHANGE = 'WAIT_FOR_EPOCH_CHANGE'
    S1_COMPUTE_LOCAL_TABLE = 'COMPUTE_LOCAL_TABLE'
    S2_SEND_LOCAL_TABLE = 'SEND_LOCAL_TABLE'
    S3_COMPUTE_MEDIAN_TABLE = 'COMPUTE_MEDIAN_TABLE'
    S4_SEND_MEDIAN_TABLE = 'SEND_MEDIAN_TABLE'
    S5_COMPUTE_AGREED_MEDIAN_TABLE = 'COMPUTE_AGREED_MEDIAN_TABLE'
    S6_SEND_AGREED_MEDIAN_TABLE = 'SEND_AGREED_MEDIAN_TABLE'
    S7_UPDATE_EPOCH_MANAGER = 'UPDATE_EPOCH_MANAGER'
    S8_SEND_REQUEST_AGREED_MEDIAN_TABLE = 'SEND_REQUEST_AGREED_MEDIAN_TABLE'
    S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE = 'COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE'
    S10_EXCHANGE_AGREEMENT_SIGNATURES = 'EXCHANGE_AGREEMENT_SIGNATURES'

  def STATES_TO_INT(self, state):
    return {
      self.STATES.S0_WAIT_FOR_EPOCH_CHANGE: 0,
      self.STATES.S1_COMPUTE_LOCAL_TABLE: 1,
      self.STATES.S2_SEND_LOCAL_TABLE: 2,
      self.STATES.S3_COMPUTE_MEDIAN_TABLE: 3,
      self.STATES.S4_SEND_MEDIAN_TABLE: 4,
      self.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE: 5,
      self.STATES.S6_SEND_AGREED_MEDIAN_TABLE: 6,
      self.STATES.S7_UPDATE_EPOCH_MANAGER: 7,
      self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE: 8,
      self.STATES.S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE: 9,
      self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES: 10,
    }[state]

  def P(self, msg, **kwargs):
    if hasattr(self, 'cfg_debug_sync_full') and self.cfg_debug_sync_full and hasattr(self, 'state_machine_name'):
      try:
        curr_state = self.__get_current_state()
        prefix = f'S{self.STATES_TO_INT(curr_state)}'
        msg = f'{prefix} {msg} [{curr_state}]'
      except Exception as e:
        pass
    return super().P(msg, **kwargs)

  def on_init(self):
    while self.netmon.epoch_manager is None:
      self.P(f"Waiting for epoch manager to be initialized for {self.__name__} to start.")
      self.sleep(1)
    # endwhile
    if self.cfg_use_r1fs:
      it = 0
      sleep_time = 5
      log_period = 24
      start_time = self.time()
      while not self.r1fs.is_ipfs_warmed:
        it += 1
        if it % log_period == 0:
          elapsed_time = self.time() - start_time
          self.P(f"R1FS is not warmed up yet.[Elapsed: {elapsed_time:.2f}s] ")
        self.sleep(sleep_time)
      # endwhile
      elapsed_time = self.time() - start_time
      self.P(f"R1FS is warmed up after {elapsed_time:.2f} seconds.")
    # endif not cfg_use_r1fs
    self.__oracle_list = []
    self.__last_oracle_list_refresh = None
    self.maybe_refresh_oracle_list()
    self.__reset_to_initial_state()

    self.P(f"{FULL_AVAILABILITY_THRESHOLD=} | {POTENTIALLY_FULL_AVAILABILITY_THRESHOLD=}", boxed=True)

    # All oracles start in the state S8_SEND_REQUEST_AGREED_MEDIAN_TABLE
    # because they have to request the agreed median table and wait to receive
    # the agreed median table from the previous epochs.
    self.state_machine_name = 'OracleSyncPlugin'
    self.__received_messages_from_oracles = self.deque(maxlen=MAX_RECEIVED_MESSAGES_SIZE)
    self.state_machine_api_init(
      name=self.state_machine_name,
      state_machine_transitions=self._prepare_job_state_transition_map(),
      initial_state=self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
      on_successful_step_callback=self.state_machine_api_callback_do_nothing,
    )
    return

  def get_all_nodes(self):
    """
    Utility method for converting addresses in self.netmon.all_nodes to full addresses.
    This is temporary, since self.all_nodes and self.__network_heartbeats have the node addresses in different formats.
    Returns
    -------
    list : list of full addresses
    """
    lst_nodes_short = self.netmon.all_nodes
    return [
      self.bc.maybe_add_prefix(node_addr)
      for node_addr in lst_nodes_short
    ]

  # State machine callbacks
  if True:
    def _prepare_job_state_transition_map(self):
      job_state_transition_map = {
        self.STATES.S0_WAIT_FOR_EPOCH_CHANGE: {
          'STATE_CALLBACK': self.__receive_requests_from_oracles_and_send_responses,
          'DESCRIPTION': "Wait for the epoch to change during the day.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S1_COMPUTE_LOCAL_TABLE,
              'TRANSITION_CONDITION': self.__check_epoch_finished,
              'ON_TRANSITION_CALLBACK': self.__reset_to_initial_state,
              'DESCRIPTION': "If the epoch has changed, compute the local table of availability",
            },
          ],
        },
        self.STATES.S1_COMPUTE_LOCAL_TABLE: {
          # Because the transition conditions are mutually exclusive,
          # we cannot remain in this state for more than one step.
          'STATE_CALLBACK': self.__compute_local_table,
          'DESCRIPTION': "Compute the local table of availability",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S2_SEND_LOCAL_TABLE,
              'TRANSITION_CONDITION': self.__can_participate_in_sync,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the node can participate, join the sync process",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__cannot_participate_in_sync,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the node cannot participate, periodically request the agreed median table from the oracles",
            }
          ],
        },
        self.STATES.S2_SEND_LOCAL_TABLE: {
          'STATE_CALLBACK': self.__receive_local_table_and_maybe_send_local_table,
          'DESCRIPTION': "Exchange local table of availability between oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S3_COMPUTE_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__send_local_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, compute the median table",
            }
          ],
        },
        self.STATES.S3_COMPUTE_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__compute_median_table,
          'DESCRIPTION': "Compute the median table of availability, based on the local tables received from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S4_SEND_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__check_median_computed,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Begin the exchange process of the median tables between oracles",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__check_median_not_computed,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Median computing failed, wait for other oracles to reach consensus and request form them",
            },
          ],
        },
        self.STATES.S4_SEND_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__receive_median_table_and_maybe_send_median_table,
          'DESCRIPTION': "Exchange median table of availability between oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__send_median_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, compute the agreed median table",
            },
          ],
        },
        self.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__compute_agreed_median_table,
          'DESCRIPTION': "Compute the agreed median table of availability, based on the median tables received from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S6_SEND_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__agreement_reached,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Begin the exchange process of the agreed median tables between oracles",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__agreement_not_reached,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the agreement is not reached, request the agreed median table from the other oracles."
                             "In the unlikely case that no epoch agreement is reached at all, all oracles will"
                             "transition to the request agreed median table state and will then "
                             "mark the epoch as faulty.",
            }
          ],
        },
        self.STATES.S6_SEND_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__receive_agreement_signature_and_maybe_send_agreement_signature,
          'DESCRIPTION': "Each oracle will gather and check agreement signatures from the other oracles.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES,
              'TRANSITION_CONDITION': self.__send_agreement_signature_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the gathering phase time expires, oracles will start exchanging "
                             "agreement signatures again. This time they will exchange all their "
                             "gathered signatures instead of just one.",
            }
          ],
        },
        self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES: {
          'STATE_CALLBACK': self.__exchange_agreement_signatures,
          'DESCRIPTION': "Exchange agreement signatures between oracles.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S7_UPDATE_EPOCH_MANAGER,
              'TRANSITION_CONDITION': self.__exchange_signatures_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, update the epoch manager with the "
                             "compiled agreed median table and the accumulated signatures.",
            }
          ],
        },
        self.STATES.S7_UPDATE_EPOCH_MANAGER: {
          'STATE_CALLBACK': self.__update_epoch_manager_with_agreed_median_table,
          'DESCRIPTION': "Update the epoch manager with the agreed median table",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self.state_machine_api_callback_always_true,
              'ON_TRANSITION_CALLBACK': self.__reset_to_initial_state,
              'DESCRIPTION': "Wait for the epoch to change to start a new sync process",
            }
          ],
        },
        self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__receive_agreed_median_table_and_maybe_request_agreed_median_table,
          'DESCRIPTION': "Wait for the oracles to send the agreed median table and periodically request the agreed median table from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self.__send_request_agreed_median_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the request phase time expires, compute the agreed median table from the received tables",
            },
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self.__last_epoch_synced_is_previous_epoch,
              'ON_TRANSITION_CALLBACK': self.__reset_to_initial_state,
              'DESCRIPTION': "If the last epoch synced is the previous epoch, start a new sync process",
            }
          ],
        },
        self.STATES.S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self.__compute_requested_agreed_median_table,
          'DESCRIPTION': "Compute the agreed median table of availability, based on the received tables",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self.state_machine_api_callback_always_true,
              'ON_TRANSITION_CALLBACK': self.__reset_to_initial_state,
              'DESCRIPTION': "Begin the exchange process of the agreed median tables between oracles",
            }
          ],
        },
      }
      return job_state_transition_map

    def __reset_to_initial_state(self):
      """
      Reset the plugin to the initial state.
      """
      self.P(f'Resetting to initial state')
      self.__current_epoch = self.netmon.epoch_manager.get_current_epoch()
      self.current_epoch_computed = False

      self.should_expect_to_participate = {}

      self.local_table = {}
      self.dct_local_tables = {}
      self.first_time_local_table_sent = None
      self.last_time_local_table_sent = None

      self.median_table = None
      self.dct_median_tables = {}
      self.first_time_median_table_sent = None
      self.last_time_median_table_sent = None

      self.agreed_median_table = {}
      self.compiled_agreed_median_table = {}
      self.compiled_agreed_median_table_signatures = {}
      self.first_time__agreement_signature_sent = None
      self.last_time__agreement_signature_sent = None
      self.first_time__agreement_signatures_exchanged = None
      self.last_time__agreement_signatures_exchanged = None

      # This will be used in case the oracle starts and needs syncing with the other oracles
      # about the previous epochs.
      self.dct_agreed_availability_table = {}
      self.dct_agreed_availability_signatures = {}
      self.dct_agreed_availability_is_valid = {}
      self.dct_agreed_availability_cid = {}

      self.__last_epoch_synced = self.netmon.epoch_manager.get_last_sync_epoch()
      self.first_time_request_agreed_median_table_sent = None
      self.last_time_request_agreed_median_table_sent = None
      self.P(f'Current epoch: {self.__current_epoch}, Last epoch synced: {self.__last_epoch_synced}.')
      return

    # S0_WAIT_FOR_EPOCH_CHANGE
    def __send_epoch__agreed_median_table(self, start_epoch, end_epoch):
      dct_epoch__agreed_median_table = {}
      dct_epoch__signatures = {}
      dct_epoch__is_valid = {}
      newly_uploaded_epochs = []

      epoch_keys = list(range(start_epoch, end_epoch + 1))
      # TODO: Refactor this to retrieve all the data in one call and separate the data for each epoch after.
      valid_epochs, invalid_epochs = [], []
      added_success, added_failed = [], []
      already_uploaded, epochs_with_empty = [], []
      for epoch in epoch_keys:
        availability_table, dct_signatures, agreement_cid = self.netmon.epoch_manager.get_epoch_availability(
          epoch=epoch, return_additional=True
        )
        current_epoch_is_valid = self.netmon.epoch_manager.is_epoch_valid(epoch)
        epoch_key = str(epoch)
        dct_epoch__signatures[epoch_key] = dct_signatures
        dct_epoch__is_valid[epoch_key] = self.netmon.epoch_manager.is_epoch_valid(epoch)

        if current_epoch_is_valid:
          valid_epochs.append(epoch)
        else:
          invalid_epochs.append(epoch)

        if agreement_cid is None and current_epoch_is_valid:
          # The agreement was never uploaded in the R1FS, so we try to upload it now.
          # This will add the agreement table for the current epoch to `dct_epoch__agreed_median_table`
          # regardless of the success of the upload.
          # In case of success, the value added will be the cid, otherwise the full table.
          success = self.r1fs_add_data_to_message(
            message_dict=dct_epoch__agreed_median_table,
            data_dict=availability_table,
            data_key=epoch_key,
            debug=self.cfg_debug_sync_full
          )
          if success:
            # In case of success the cid needs to also be added to the epoch_manager
            agreement_cid = dct_epoch__agreed_median_table[epoch_key]
            self.netmon.epoch_manager.add_cid_for_epoch(
              epoch=epoch, agreement_cid=agreement_cid,
              debug=self.cfg_debug_sync_full
            )
            added_success.append(epoch)
            newly_uploaded_epochs.append(epoch)
          else:
            added_failed.append(epoch)
            # self.P(f"Failed to upload agreement for epoch {epoch}.")
          # endif success
        else:
          # Here either the epoch is not valid or the agreement was already uploaded.
          if agreement_cid is not None:
            # The agreement was already uploaded, so we just add the cid to the message.
            already_uploaded.append(epoch)
            if self.cfg_debug_sync_full:
              self.P(f"Agreement for epoch {epoch} was already uploaded. Adding the CID to the message.")
            dct_epoch__agreed_median_table[epoch_key] = agreement_cid
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
        stats_msg += f' | {len(added_success)} added | {len(added_failed)} failed'
        stats_msg += f' | {len(already_uploaded)} already uploaded | {len(epochs_with_empty)} empty'
        self.P(f"Epochs: {stats_msg}.")
      # endif debug_sync

      if len(newly_uploaded_epochs) > 0:
        self.P(f"Uploaded agreements for epochs: {newly_uploaded_epochs}. Saving the epoch manager status.")
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

      oracle_data = {
        OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: dct_epoch__agreed_median_table,
        OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES: dct_epoch__signatures,
        OracleSyncCt.EPOCH__IS_VALID: dct_epoch__is_valid,
        OracleSyncCt.EPOCH_KEYS: epoch_keys,
        OracleSyncCt.STAGE: self.__get_current_state(),
      }
      self.add_payload_by_fields(
        oracle_data=oracle_data,
      )
      return

    def __maybe_process_request_agreed_median_table(self, dct_message: dict):
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

      if request_agreed_median_table:
        self.P(f"Received request from oracle {sender}: {stage = }, {start_epoch = }, {end_epoch = }")
        self.__send_epoch__agreed_median_table(start_epoch, end_epoch)
        processed = True
      # endif request_agreed_median_table
      return processed

    def __receive_requests_from_oracles_and_send_responses(self):
      """
      Receive requests from the oracles and send responses.
      """
      if self.cfg_debug_sync_full:
        self.P(f"Parsing received messages from oracles.[{self.__get_current_state()}]")
      cnt = 0
      for dct_message in self.get_received_messages_from_oracles():
        cnt += 1
        self.__maybe_process_request_agreed_median_table(dct_message)
      if self.cfg_debug_sync_full:
        self.P(f"Processed {cnt} messages from oracles.[{self.__get_current_state()}]")
      return

    def __check_epoch_finished(self):
      """
      Check if the epoch has changed.

      Returns
      -------
      bool : True if the epoch has changed, False otherwise
      """
      return self.__current_epoch != self.netmon.epoch_manager.get_current_epoch()

    # S1_COMPUTE_LOCAL_TABLE
    def __compute_local_table(self):
      """
      Compute the local table for the current node.
      If the node is not a supervisor, the local table will be empty.
      This method is only called after the finishing of the previous epoch.
      """

      self.netmon.epoch_manager.maybe_close_epoch()

      # if current node is not supervisor, just return
      if not self.__is_oracle(self.node_addr):
        self.P("I am not a supervisor. I will not participate in the sync process")
        self.local_table = {}
        return

      if self.cfg_debug_sync:
        self.P(f'All nodes: {self.get_all_nodes()}')

      prev_epoch = self.netmon.epoch_manager.get_time_epoch() - 1
      if prev_epoch < 0:
        self.local_table = {}
        self.P(f'Previous epoch below 0: {prev_epoch}. Cannot compute local table. '
               f'This is likely because the genesis date is in the future.')
        return

      # if self is not full online, it should not participate in the sync process
      if not self.__was_full_online(self.node_addr):
        self.P("I was not full online. I will not participate in the sync process and will not compute local table.", color='r')
        return

      # node is supervisor, compute local table
      self.local_table = {
        # self.netmon.epoch_manager.get_node_previous_epoch uses self.__data
        # self.__data uses full address
        node: self.netmon.epoch_manager.get_node_previous_epoch(node)
        # self.netmon.all_nodes uses self.all_heartbeats
        # self.all_heartbeats uses self.__network_heartbeats
        # self.__network_heartbeats uses short address
        for node in self.get_all_nodes()
      }

      # if self is full online, it should participate in the sync process
      # mark oracles that were seen full online in the previous epoch as True
      for oracle in self.get_oracle_list():
        self.should_expect_to_participate[oracle] = self.__was_potentially_full_online(oracle)

      self.P(f"Computed local table {self.local_table}")
      return

    def __can_participate_in_sync(self):
      """
      Check if the current node can participate in the sync process.
      A node can participate if it is a supervisor and was full online in the previous epoch.

      Returns
      -------
      bool : True if the node can participate in the sync process, False otherwise
      """
      return self.__is_oracle(self.node_addr) and self.__was_full_online(self.node_addr)

    def __cannot_participate_in_sync(self):
      """
      Check if the current node cannot participate in the sync process.
      A node can participate if it is a supervisor and was full online in the previous epoch.

      Returns
      -------
      bool : True if the node cannot participate in the sync process, False otherwise
      """
      return not self.__can_participate_in_sync()

    # S2_SEND_LOCAL_TABLE
    def __receive_local_table_and_maybe_send_local_table(self):
      """
      Receive the local table from the oracles and 
      send the local table to the oracles each `self.cfg_send_interval` seconds.
      """
      # Receive values from oracles
      # Obs: there is no need for supervisor check on sender, since the messages
      # are already filtered in handle_received_messages
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')
        if oracle_data is None:
          continue

        # If local_table was sent as a CID this check method will also download it.
        if not self.__check_received_local_table_ok(sender, oracle_data):
          continue

        stage = oracle_data[OracleSyncCt.STAGE]
        local_table = oracle_data[OracleSyncCt.LOCAL_TABLE]

        log_str = f"Received message from oracle {sender}: {stage = }"
        if self.cfg_debug_sync:
          log_str += f", local_table=\n{local_table}"
        # endif debug_sync
        self.P(log_str)
        self.dct_local_tables[sender] = local_table
      # end for

      # Send value to oracles
      if self.first_time_local_table_sent is None:
        self.first_time_local_table_sent = self.time()

      if self.last_time_local_table_sent is not None and self.time() - self.last_time_local_table_sent < self.cfg_send_interval:
        return

      self.P(f"Sending {self.local_table=}")

      oracle_data = {
        OracleSyncCt.LOCAL_TABLE: self.local_table,
        OracleSyncCt.STAGE: self.__get_current_state()
      }
      self.bc.sign(oracle_data, add_data=True, use_digest=True)
      # Will add cid to the message instead of self.local_table if
      # the upload to R1FS is successful.
      self.r1fs_add_data_to_message(
        message_dict=oracle_data,
        data_dict=self.local_table,
        data_key=OracleSyncCt.LOCAL_TABLE
      )

      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time_local_table_sent = self.time()
      return

    def __send_local_table_timeout(self):
      """
      Check if the exchange phase of the local table has finished.

      Returns
      -------
      bool: True if the exchange phase of the local table has finished, False otherwise
      """
      return self.time() - self.first_time_local_table_sent > self.cfg_send_period * LOCAL_TABLE_SEND_MULTIPLIER

    # S3_COMPUTE_MEDIAN_TABLE
    def __check_median_computed(self):
      return self.median_table is not None and len(self.median_table) > 0

    def __check_median_not_computed(self):
      return self.median_table is None or len(self.median_table) == 0

    def __compute_median_table(self):
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
      self.dct_local_tables[self.node_addr] = self.local_table
      valid_local_tables = [x for x in self.dct_local_tables.values() if x is not None]
      valid_local_tables_count = len(valid_local_tables)

      if valid_local_tables_count <= self.__count_half_of_valid_oracles():
        self.median_table = None
        self.P("Could not compute median. Too few valid values", color='r', boxed=True)
        return

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
          # self.__current_epoch - 1, since the consensus is for the previous epoch
          OracleSyncCt.EPOCH: self.__current_epoch - 1,
          OracleSyncCt.NODE: node
        }
        self.bc.sign(self.median_table[node], add_data=True, use_digest=True)
        # No reason to leave these keys in the dictionary, since they can be added again when verifying.
        self.median_table[node].pop(OracleSyncCt.EPOCH)
        self.median_table[node].pop(OracleSyncCt.NODE)
      # end for all_nodes

      self.P(f"Computed median table {self.__compute_simple_median_table(self.median_table)}")
      return

    # S4_SEND_MEDIAN_TABLE
    def __receive_median_table_and_maybe_send_median_table(self):
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
      # Receive medians from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        # In case the median table was uploaded in R1FS this check method will
        # also download it.
        if not self.__check_received_median_table_ok(sender, oracle_data):
          continue

        stage = oracle_data[OracleSyncCt.STAGE]
        median_table = oracle_data[OracleSyncCt.MEDIAN_TABLE]

        simple_median = self.__compute_simple_median_table(median_table)
        if self.cfg_debug_sync:
          self.P(f"Received message from oracle {sender}: {stage = }, {simple_median = }")
        # endif debug_sync

        self.dct_median_tables[sender] = median_table
      # end for

      # Send median to oracles
      if self.first_time_median_table_sent is None:
        self.first_time_median_table_sent = self.time()

      if self.last_time_median_table_sent is not None and self.time() - self.last_time_median_table_sent < self.cfg_send_interval:
        return

      if self.cfg_debug_sync:
        self.P(f"Sending median {self.__compute_simple_median_table(self.median_table)}")
      # endif debug_sync
      oracle_data = {
        OracleSyncCt.STAGE: self.__get_current_state(),
        OracleSyncCt.MEDIAN_TABLE: self.median_table,
      }
      self.bc.sign(oracle_data, add_data=True, use_digest=True)
      # Will add cid to the message instead of self.median_table if
      # the upload to R1FS is successful.
      self.r1fs_add_data_to_message(
        message_dict=oracle_data,
        data_dict=self.median_table,
        data_key=OracleSyncCt.MEDIAN_TABLE
      )
      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time_median_table_sent = self.time()
      return

    def __send_median_table_timeout(self):
      """
      Check if the exchange phase of the median table has finished.

      Returns
      -------
      bool: True if the exchange phase of the median table has finished, False otherwise
      """
      return self.time() - self.first_time_median_table_sent > self.cfg_send_period

    # S5_COMPUTE_AGREED_MEDIAN_TABLE
    def __compute_agreed_median_table(self):
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
      # Even if the current oracle did not manage to compute its own median table it can still
      # compute the agreement from the received tables.
      if self.median_table is not None:
        self.dct_median_tables[self.node_addr] = self.median_table
      # endif current oracle did not manage to compute its own median table

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
      for node in all_nodes:
        dct_median_frequency = {}
        for median in (dct_median['VALUE'] for dct_median in dct_node_median_signed_values[node]):
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
          if dct_median['VALUE'] == most_frequent_median
        ]

        median_frequency = len(lst_dct_freq_median)
        min_frequency = self.__count_half_of_valid_oracles()
        if median_frequency > min_frequency:
          if self.cfg_debug_sync:
            self.P(f"Computed agreed median table for node {node}: {most_frequent_median}. "
                   f"Dct freq {dct_median_frequency}")
          # endif debug_sync
          self.agreed_median_table[node] = {
            'VALUE': most_frequent_median,
            'SIGNATURES': lst_dct_freq_median,
          }
        else:
          all_valid_oracles = []
          self.P(f"Failed to compute agreed median table for node {node}. "
                 f"Could not achieve consensus. Highest median frequency is {median_frequency}, while the minimum frequency is"
                 f"{min_frequency}. Dct freq:\n{self.json_dumps(dct_median_frequency, indent=2)}\n"
                 f"{self.json_dumps(self.dct_median_tables, indent=2)}", color='r')
          self.P(
            f"Current oracle will request epoch consensus from the other oracles. If no consensus is reached"
            f"epoch {self.__current_epoch - 1} will be marked as faulty.",
            color='r'
          )
          # Failure at this point is a serious issue, since it means that the oracles did not reach consensus.
          # This can happen in only 2 cases:
          # 1. The network is attacked through malicious oracles or other means(e.g. oracle impersonation).
          # 2. Massive system failure in the network that led to all oracles failing to reach consensus.
          self.compiled_agreed_median_table = None
          return
        # endif median_frequency above min_frequency
      # end for

      if len(self.agreed_median_table) == 0:
        self.P("Failed to compute agreed median table. Not enough online oracles", color='r')
        self.P(
          f"Current oracle will request epoch consensus from the other oracles. If no consensus is reached"
          f"epoch {self.__current_epoch - 1} will be marked as faulty.",
          color='r'
        )
        self.compiled_agreed_median_table = None
        return
      # endif agreed_median_table empty

      self.compiled_agreed_median_table = self.__compute_simple_agreed_value_table(self.agreed_median_table)

      self.current_epoch_computed = True
      return

    def __agreement_reached(self):
      """
      Check if the agreement table was successfully computed in `__compute_agreed_median_table`.
      Returns
      -------
      bool : True if the self.compiled_agreed_median_table is not None, False otherwise
      """
      return self.compiled_agreed_median_table is not None

    def __agreement_not_reached(self):
      """
      Check if the agreement table was not successfully computed in `__compute_agreed_median_table`.
      Returns
      -------
      bool : True if the self.compiled_agreed_median_table is None, False otherwise
      """
      return not self.__agreement_reached()

    # S6_SEND_AGREED_MEDIAN_TABLE
    def __receive_agreement_signature_and_maybe_send_agreement_signature(self):
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
      # Receive agreed values from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        if not self.__check_received_agreement_signature_ok(sender, oracle_data):
          continue

        signature_dict = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURE]
        self.compiled_agreed_median_table_signatures[sender] = signature_dict

        if self.cfg_debug_sync:
          stage = oracle_data[OracleSyncCt.STAGE]
          self.P(f"Received agreement signature message from oracle {sender}: {stage = }, {signature_dict = }")
        # endif debug_sync
      # end for

      # Send agreed value to oracles
      if self.first_time__agreement_signature_sent is None:
        self.first_time__agreement_signature_sent = self.time()

      if self.last_time__agreement_signature_sent is not None and self.time() - self.last_time__agreement_signature_sent < self.cfg_send_interval:
        return

      # Remove 0 values from the compiled agreed median table.
      # This is done to both reduce the size of the signed data and to avoid
      # additional zero values appearing when verifying the table.
      non_zero_compiled_agreed_table = {k: v for k, v in self.compiled_agreed_median_table.items() if v != 0}

      signature_dict = {
        OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE: non_zero_compiled_agreed_table,
        # self.__current_epoch - 1, since the consensus is for the previous epoch
        OracleSyncCt.EPOCH: self.__current_epoch - 1,
      }
      self.bc.sign(signature_dict, add_data=True, use_digest=True)
      signature_dict.pop(OracleSyncCt.EPOCH)
      signature_dict.pop(OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE)

      oracle_data = {
        # The compiled agreed median table itself will not be sent,
        # since we only need to verify the signature to know if the table is the same as
        # the cached one.
        OracleSyncCt.STAGE: self.__get_current_state(),
        OracleSyncCt.AGREEMENT_SIGNATURE: signature_dict
      }

      if self.cfg_debug_sync:
        self.P(f"Sending agreement signature for: {non_zero_compiled_agreed_table}")
      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time__agreement_signature_sent = self.time()
      return

    # S10_EXCHANGE_AGREEMENT_SIGNATURES
    def __exchange_agreement_signatures(self):
      """
      Exchange agreement signatures between oracles.
      """
      # Receive signatures from oracles
      for dct_message in self.get_received_messages_from_oracles():
        sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
        oracle_data = dct_message.get('ORACLE_DATA')

        if not self.__check_received_agreement_signatures_ok(sender, oracle_data):
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
          self.P(f"Received {len(signatures_dict)} agreement signatures from oracle {sender}: {stage = }, {senders = }")
        # endif debug_sync
      # end for

      # Send signatures to oracles
      if self.first_time__agreement_signatures_exchanged is None:
        self.first_time__agreement_signatures_exchanged = self.time()

      last_sent_time = self.last_time__agreement_signatures_exchanged
      if last_sent_time is not None and self.time() - last_sent_time < self.cfg_send_interval:
        return

      oracle_data = {
        OracleSyncCt.STAGE: self.__get_current_state(),
        OracleSyncCt.AGREEMENT_SIGNATURES: self.compiled_agreed_median_table_signatures,
      }
      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time__agreement_signatures_exchanged = self.time()
      return

    def __send_agreement_signature_timeout(self):
      """
      Check if the exchange phase of the agreed median table has finished.

      Returns
      -------
      bool: True if the exchange phase of the agreed median table has finished, False otherwise
      """
      return self.time() - self.first_time__agreement_signature_sent > self.cfg_send_period

    def __exchange_signatures_timeout(self):
      """
      Check if the exchange phase of the agreement signatures has finished.

      Returns
      -------
      bool: True if the exchange phase of the agreement signatures has finished, False otherwise
      """
      return self.time() - self.first_time__agreement_signatures_exchanged > self.cfg_send_period * SIGNATURES_EXCHANGE_MULTIPLIER

    # S7_UPDATE_EPOCH_MANAGER
    def __update_epoch_manager_with_agreed_median_table(
        self, epoch=None, compiled_agreed_median_table=None, agreement_signatures=None,
        epoch_is_valid=None, agreement_cid=None, debug=True
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
      debug : bool, optional
          Print debug messages, by default True
      """

      if epoch is None:
        # update previous epoch, since if this method is called without epoch,
        # it is part of the consensus process for the previous epoch.
        # TODO: should we switch to self.netmon.epoch_manager.get_current_epoch() - 1 everywhere?
        #  both should be equivalent
        epoch = self.__current_epoch - 1
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

      if epoch <= self.__last_epoch_synced:
        if debug:
          self.P("Epoch manager history already updated with this epoch", color='r')
        return

      if epoch > self.__last_epoch_synced + 1:
        if debug:
          self.P(f"Detected a skip in epoch sync algorithm. "
                 f"Last known epoch synced {self.__last_epoch_synced} "
                 f"Current epoch {epoch}", color='r')
        # If we skip the update here, the epoch manager will not be able to update in case
        # it receives the agreed median table for several epochs at once(maybe
        # at init when syncing with other active oracles).
        # Obs: this method is also used for the update from S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE
        # maybe handle that update differently?

        # return

      if self.cfg_debug_sync_full:
        valid_str = "VALID" if epoch_is_valid else "INVALID"
        self.P(f'Attempting to update with the following {valid_str} agreed median table:\n{compiled_agreed_median_table}')
      # endif debug_sync_full

      if epoch_is_valid:
        success = self.netmon.epoch_manager.update_epoch_availability(
          epoch=epoch,
          availability_table=compiled_agreed_median_table,
          agreement_signatures=agreement_signatures,
          debug=self.cfg_debug_sync_full,
          agreement_cid=agreement_cid
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
          self.P(f'Successfully synced epoch {epoch} with {valid_str} agreed median table!')
          if self.cfg_debug_sync_full:
            self.P(f'DEBUG EM data after update:\n{self.netmon.epoch_manager.data}')
        self.__last_epoch_synced = epoch
      return

    # S8_SEND_REQUEST_AGREED_MEDIAN_TABLE
    def __receive_agreed_median_table_and_maybe_request_agreed_median_table(self):
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
          sender = dct_message.get(self.ct.PAYLOAD_DATA.EE_SENDER)
          oracle_data = dct_message.get('ORACLE_DATA')

          if not self.__check_received_epoch__agreed_median_table_ok(sender, oracle_data):
            continue

          # Here, both the agreed median table and the agreement signatures should have the same keys,
          # but as string instead of int. We also know that in epoch_keys we have
          # the keys in int format. Thus, we need to convert the keys of the received tables
          dct_epoch_agreed_median_table = oracle_data[OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE]
          dct_epoch_agreement_signatures = oracle_data[OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES]
          dct_epoch_is_valid = oracle_data[OracleSyncCt.EPOCH__IS_VALID]
          dct_epoch_agreement_cid = {}
          epoch_keys = oracle_data[OracleSyncCt.EPOCH_KEYS]

          # sort epoch_keys in ascending order
          received_epochs = sorted(epoch_keys)

          # Maybe download the epochs data from R1FS if the data is not present in the message.
          for epoch in received_epochs:
            msg_received_data = dct_epoch_agreed_median_table.get(str(epoch))
            retrieved_data = self.r1fs_get_data_from_message(
              message_dict=dct_epoch_agreed_median_table,
              data_key=str(epoch),
              debug=self.cfg_debug_sync_full
            )
            if retrieved_data is not None and isinstance(msg_received_data, str):
              # Received a CID in the message and successfully retrieved the data from R1FS.
              dct_epoch_agreement_cid[epoch] = msg_received_data
            # endif retrieval from R1FS successful
          # endfor epochs
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
          if self.cfg_debug_sync_full:
            msg = f"DEBUG Decoded following dct_epoch_agreed_median_table:\n"
            msg += f"{dct_epoch_agreed_median_table}\n"
            msg += f'With the following validities: {dct_epoch_is_valid}\n'
            msg += f"And the following signatures: {dct_epoch_agreement_signatures}\n"
            self.P(msg)
          # endif debug_sync_full

          message_invalid = False
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

            if not self.__check_agreed_median_table(
                sender=sender, agreed_median_table=agreed_median_table,
                epoch_signatures=epoch_signatures, epoch=epoch,
                epoch_is_valid=epoch_is_valid,
                debug=False
            ):
              # if one signature for the received table is invalid, ignore the entire message
              message_invalid = True
              break
          # end for epoch agreed table

          if message_invalid:
            if self.cfg_debug_sync:
              self.P(f"Received invalid availability table from {sender = }. Ignoring", color='r')
            continue
          # endif

          if self.__last_epoch_synced + 1 not in received_epochs or self.__current_epoch - 1 not in received_epochs:
            # Expected epochs in range [last_epoch_synced + 1, current_epoch - 1]
            # received epochs don t contain the full range
            if self.cfg_debug_sync:
              min_epoch = min(received_epochs) if len(received_epochs) > 0 else None
              max_epoch = max(received_epochs) if len(received_epochs) > 0 else None
              msg = (f'Expected epochs in range [{self.__last_epoch_synced + 1}, {self.__current_epoch - 1}] '
                     f'and received only {len(received_epochs)} epochs (min: {min_epoch}, max: {max_epoch}). '
                     f'Ignoring...')
              self.P(msg, color='r')
            continue
          # endif received epochs not containing the full requested interval

          self.P(f"Received availability for epochs {received_epochs} from {sender = }. Keeping only "
                 f"tables for epochs [{self.__last_epoch_synced + 1}, {self.__current_epoch - 1}]")
          epochs_range = range(self.__last_epoch_synced + 1, self.__current_epoch)
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
        # end for received messages
      # endif first agreement request sent

      # Return if no need to sync; the last epoch synced is the previous epoch
      if self.__last_epoch_synced_is_previous_epoch():
        self.P("Last epoch synced is the previous epoch. No need to sync")
        return

      # Send request to get agreed value from oracles
      if self.first_time_request_agreed_median_table_sent is None:
        self.first_time_request_agreed_median_table_sent = self.time()

      if self.last_time_request_agreed_median_table_sent is not None and self.time() - self.last_time_request_agreed_median_table_sent < self.cfg_send_interval:
        return

      oracle_data = {
        OracleSyncCt.STAGE: self.__get_current_state(),
        OracleSyncCt.REQUEST_AGREED_MEDIAN_TABLE: True,
        'START_EPOCH': self.__last_epoch_synced + 1,
        'END_EPOCH': self.__current_epoch - 1,
      }

      # TODO: log the number of the request
      current_time = self.time()
      elapsed_time = round(current_time - self.first_time_request_agreed_median_table_sent, 1)
      self.P(f"Request for agreed median table for epochs {self.__last_epoch_synced + 1} to {self.__current_epoch - 1}"
             f"[e:{elapsed_time}/t:{self.get_request_agreement_timeout()}]")
      self.add_payload_by_fields(oracle_data=oracle_data)
      self.last_time_request_agreed_median_table_sent = self.time()
      return

    def get_request_agreement_timeout(self):
      return self.cfg_send_period * REQUEST_AGREEMENT_TABLE_MULTIPLIER

    def __send_request_agreed_median_table_timeout(self):
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

      n_received = len(self.dct_agreed_availability_table)
      if n_received >= self.min_oracle_reports_received():
        self.P(f'Received {n_received}/{self.min_oracle_reports_received()} reports. Early stopping `SEND_REQUEST_AGREED_MEDIAN_TABLE`')
        return True
      # Early stopping

      return not self.__last_epoch_synced_is_previous_epoch() and timeout_expired

    def __last_epoch_synced_is_previous_epoch(self):
      """
      Check if the agreed median table for the last epoch has been received.

      Returns
      -------
      bool: True if the agreed median table for the last epoch has been received, False otherwise
      """
      return self.__last_epoch_synced == self.__current_epoch - 1

    # S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE
    def __mark_requested_epochs_as_faulty(self):
      # If no agreed median table received, mark all requested epochs as invalid.
      requested_start_epoch = self.__last_epoch_synced + 1
      requested_end_epoch = self.__current_epoch - 1
      self.P(
        f"No agreed median table received. "
        f"Marking all requested epochs (from {requested_start_epoch} to {requested_end_epoch}) as invalid!",
        color='r'
      )
      for epoch in range(requested_start_epoch, requested_end_epoch + 1):
        self.netmon.epoch_manager.mark_epoch_as_faulty(epoch=epoch, debug=self.cfg_debug_sync_full)
      # endfor epoch
      return

    def __compute_requested_agreed_median_table(self):
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
        self.__mark_requested_epochs_as_faulty()
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
        self.__mark_requested_epochs_as_faulty()
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
      for epoch, agreement_table in epoch__agreed_median_table.items():
        agreement_signatures = epoch__agreement_signatures[epoch]
        epoch_is_valid = epoch__agreed_is_valid[epoch]
        agreement_cid = epoch__agreed_cid[epoch]
        self.__update_epoch_manager_with_agreed_median_table(
          epoch=epoch,
          compiled_agreed_median_table=agreement_table,
          agreement_signatures=agreement_signatures,
          epoch_is_valid=epoch_is_valid,
          agreement_cid=agreement_cid,
          debug=self.cfg_debug_sync_full
        )
      # endfor epoch
      return

  # Utils
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

    def get_oracle_list(self):
      if DEBUG_MODE:
        # We use get_all_nodes instead of netmon.all_nodes because we want to use the full addresses
        # instead of the short ones.
        return [node_addr for node_addr in self.get_all_nodes() if self.netmon.network_node_is_supervisor(node_addr)]
      return self.__oracle_list

    def maybe_refresh_oracle_list(self):
      if DEBUG_MODE:
        return
      if self.__last_oracle_list_refresh is None or self.time() - self.__last_oracle_list_refresh < self.cfg_oracle_list_refresh_interval:
        self.P(f'Refreshing oracle list.')
        self.__oracle_list, _ = self.bc.get_oracles()
        if len(self.__oracle_list) == 0:
          self.P(f'NO ORACLES FOUND. BLOCKCHAIN ERROR', boxed=True, color='r')
        self.__last_oracle_list_refresh = self.time()
      # endif refresh time
      return

    def min_oracle_reports_received(self):
      oracle_list = self.get_oracle_list()
      if oracle_list is None or len(oracle_list) == 0:
        return 9999999999999999999
      return max(len(oracle_list) - ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD, 1)

    def __is_oracle(self, node: str):
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

    def oracle_sync_get_node_local_availability(self, node: str):
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
      if self.cfg_debug_sync:
        self.P(f"Getting local availability for {node}")
      return self.netmon.epoch_manager.get_node_previous_epoch(node)

    def __was_full_online(self, node: str):
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
      if self.cfg_debug_sync:
        self.P(f"Checking if {node} was full online in the previous epoch. "
               f"Local availability value: {self.oracle_sync_get_node_local_availability(node)}")
      return self.oracle_sync_get_node_local_availability(node) >= FULL_AVAILABILITY_THRESHOLD

    def __was_potentially_full_online(self, node: str):
      """
      Check if the node was potentially full online in the previous epoch.
      For details about the potentially full online, check the `POTENTIALLY_FULL_AVAILABILITY_THRESHOLD` constant.

      Parameters
      ----------
      node : str
          The node to check

      Returns
      -------
      bool : True if the node was potentially full online in the previous epoch, False otherwise
      """
      return self.oracle_sync_get_node_local_availability(node) >= POTENTIALLY_FULL_AVAILABILITY_THRESHOLD

    def __get_current_state(self):
      """
      Get the current state of the state machine.

      Returns
      -------
      str : The current state of the state machine
      """
      return self.state_machine_api_get_current_state(self.state_machine_name)

    def __count_half_of_valid_oracles(self):
      """
      Count the number of oracles that are expected to participate in the sync process.

      Returns
      -------
      int : The number of oracles that are expected to participate in the sync process
      """
      return sum(self.should_expect_to_participate.values()) / 2

    @NetworkProcessorPlugin.payload_handler()
    def handle_received_payloads(self, payload: dict):
      """
      Handle the received payloads from this specific plugin signature.

      Parameters
      ----------
      payload : dict
          The received payloads
      """
      sender = payload.get(self.ct.PAYLOAD_DATA.EE_SENDER)
      if not self.__is_oracle(sender):
        return
      self.__received_messages_from_oracles.append(payload)
      return

    def get_received_messages_from_oracles(self):
      """
      Get the messages received from the oracles.
      This method returns a generator for memory efficiency.

      Returns
      -------
      generator : The messages received from the oracles
      """
      # retrieve messages from self.__received_messages_from_oracles
      dct_messages = list(self.__received_messages_from_oracles)
      self.__received_messages_from_oracles.clear()
      # This will return a generator that will be used in the next steps.
      received_messages = (dct_messages[i] for i in range(len(dct_messages)))

      return received_messages

    def __check_received_oracle_data_for_values(
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

    def __check_received_local_table_ok(self, sender, oracle_data):
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
      if not self.__check_received_oracle_data_for_values(
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

      if not self.should_expect_to_participate.get(sender, False) and local_table is not None:
        local_table_str = f'{local_table = }'
        if not self.cfg_debug_sync and len(local_table_str) > 100:
          local_table_str = f'{local_table_str[:100]}...'
        self.P(f"Node {sender} should not have sent value {local_table_str}. ignoring...", color='r')
        return False

      if self.should_expect_to_participate.get(sender, False) and local_table is None:
        self.P(f"Oracle {sender} should have sent value. ignoring...", color='r')
        return False

      return True

    def __check_received_signed_values_ok(self, sender, dct_values, dict_name, check_identity=True):
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
        self.P(f"Invalid {dict_name} from oracle {sender}: Verification failed:{reason_str }", color='r')
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

    def __check_received_multi_signed_values_ok(self, sender, dct_values, dict_name):
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

    def __check_received_median_table_ok(self, sender, oracle_data):
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
      if not self.__check_received_oracle_data_for_values(
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

      # in the should_expect_to_participate dictionary, only oracles that were seen
      # as full online are marked as True
      if not self.should_expect_to_participate.get(sender, False):
        self.P(f"Oracle {sender} should not have sent median {median}. ignoring...", color='r')
        return False

      if median is None:
        self.P(f"Oracle {sender} could not compute median. ignoring...", color='r')
        return False

      # Rebuilding the original signed data dictionaries.
      # For additional info check method __compute_median_table
      dct_values_for_checking = {
        node: {
          **dct_node,
          # self.__current_epoch - 1, since the median table is for the previous epoch
          OracleSyncCt.EPOCH: self.__current_epoch - 1,
          OracleSyncCt.NODE: node,
        }
        for node, dct_node in median.items()
      }

      # Check all received availability values
      if not self.__check_received_signed_values_ok(
        sender=sender,
        dct_values=dct_values_for_checking,
        dict_name='median table',
        check_identity=True,
      ):
        return False

      return True

    def __check_agreement_signature(
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
        epoch = self.__current_epoch - 1

      if debug:
        self.P(f"DEBUG Received agreement signature for epoch {epoch} from oracle {sender}")

      # Rebuild the original signed data dictionary.
      # For additional info check method
      # __receive_agreement_signature_and_maybe_send_agreement_signature

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

    def __check_received_agreement_signature_ok(self, sender, oracle_data):
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
      if not self.__check_received_oracle_data_for_values(
        sender=sender,
        oracle_data=oracle_data,
        expected_variable_names=[
          OracleSyncCt.STAGE, OracleSyncCt.AGREEMENT_SIGNATURE
        ],
        expected_stage=self.STATES.S6_SEND_AGREED_MEDIAN_TABLE,
        # No need to verify here, since the agreement signature itself is signed and verified
        # in the self.__check_agreement_signature method
        verify=False,
      ):
        return False

      signature_dict = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURE]

      # In the should_expect_to_participate dictionary, only oracles that were seen
      # as full online are marked as True
      # If the signature was None it wouldn't have passed the previous check.
      if not self.should_expect_to_participate.get(sender, False):
        self.P(f"Oracle {sender} should not have sent signature for agreement. ignoring...", color='r')
        return False

      if not self.__check_agreement_signature(
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

    def __check_received_agreement_signatures_ok(self, sender: str, oracle_data: dict):
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
      if not self.__check_received_oracle_data_for_values(
        sender=sender,
        oracle_data=oracle_data,
        expected_variable_names=[
          OracleSyncCt.STAGE, OracleSyncCt.AGREEMENT_SIGNATURES
        ],
        expected_stage=self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES,
        # No need to verify here, since the agreement signature itself is signed and verified
        # in the self.__check_agreement_signature method
        verify=False,
      ):
        return False

      # In the should_expect_to_participate dictionary, only oracles that were seen
      # as full online are marked as True
      # If the signature was None it wouldn't have passed the previous check.
      if not self.should_expect_to_participate.get(sender, False):
        self.P(f"Oracle {sender} should not have sent signatures for agreement exchange. ignoring...", color='r')
        return False

      agreement_signatures = oracle_data[OracleSyncCt.AGREEMENT_SIGNATURES]

      for sig_sender, signature_dict in agreement_signatures.items():
        if not self.should_expect_to_participate.get(sig_sender, False):
          self.P(f"Oracle {sig_sender} should not have sent signature for agreement. ignoring...", color='r')
          # TODO: review if this should make the entire message invalid
          # One node can be seen as potentially full online by some oracles and not by others.
          # But for the node to actually participate in the agreement, it has to see itself as full online.
          # That can not happen if the node is not seen as potentially full online by at least another
          # participating oracle.
          return False
        # endif not expected to participate
        if not self.__check_agreement_signature(
          sender=sig_sender,
          signature_dict=signature_dict
        ):
          self.P(f"Invalid agreement signature from oracle {sig_sender}!", color='r')
          return False
        # endif agreement signature
      # endfor agreement signatures
      return True

    def __check_received_epoch__agreed_median_table_ok(self, sender, oracle_data):
      """
      Check if the received agreed value is ok. Print the error message if not.
      This method is used to check if the message received is valid. The checking
      of each agreed median table is done in the __check_agreed_median_table method.

      Parameters
      ----------
      sender : str
          The sender of the message
      oracle_data : dict
          The data received from the oracle
      """
      if not self.__check_received_oracle_data_for_values(
        sender=sender,
        oracle_data=oracle_data,
        expected_variable_names=[
          OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE, OracleSyncCt.EPOCH_KEYS,
          OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES,
          OracleSyncCt.EPOCH__IS_VALID
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

    def __check_agreed_median_table(
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
        return True

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
        if not self.__check_agreement_signature(
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

    def __compute_simple_median_table(self, median_table):
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

    def __compute_simple_agreed_value_table(self, agreed_value_table):
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
        simple_agreed_value_table[node] = dct_node['VALUE']

      return simple_agreed_value_table

  def process(self):
    self.state_machine_api_step(self.state_machine_name)
    return
