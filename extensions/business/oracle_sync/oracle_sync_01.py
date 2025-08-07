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
from extensions.business.oracle_sync.sync_mixins.ora_sync_utils_mixin import _OraSyncUtilsMixin
from extensions.business.oracle_sync.sync_mixins.ora_sync_states_mixin import _OraSyncStatesCallbacksMixin
from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import (
  DEBUG_MODE,

  FULL_AVAILABILITY_THRESHOLD,
  POTENTIALLY_FULL_AVAILABILITY_THRESHOLD,

  SUPERVISOR_MIN_AVAIL_PRC,
  MAX_RECEIVED_MESSAGES_SIZE,
  ORACLE_SYNC_USE_R1FS,
)

"""
TODO list:
- rename states so that STATE8 becomes STATE0 and STATES 0-7 become 1-8
"""


_CONFIG = {
  **NetworkProcessorPlugin.CONFIG,
  # Only the oracles should sync the availability tables
  "RUNS_ONLY_ON_SUPERVISOR_NODE": True,

  # Jobs should have a bigger inputs queue size, because they have to process everything
  'MAX_INPUTS_QUEUE_SIZE': 500,

  # Allow empty inputs in order to send pings from time to time
  'ALLOW_EMPTY_INPUTS': True,
  'PROCESS_DELAY': 0,

  'SEND_PERIOD': 90,  # seconds
  'SEND_INTERVAL': 30,  # seconds

  # This flag will be enabled after further testing of R1FS.
  "USE_R1FS": ORACLE_SYNC_USE_R1FS,

  'EPOCH_START_SYNC': 0,
  # TODO: disable this flag in the future after further testing
  'DEBUG_SYNC': True,
  # More powerful debug sync
  'DEBUG_SYNC_FULL': False,
  'ORACLE_LIST_REFRESH_INTERVAL': 300,  # seconds
  "SELF_ASSESSMENT_INTERVAL": 30 * 60,  # seconds

  'SQUEEZE_EPOCH_DICTIONARIES': True,

  'VALIDATION_RULES': {
    **NetworkProcessorPlugin.CONFIG['VALIDATION_RULES'],
  },
}

if DEBUG_MODE:
  # In the case of debug mode, messages may need to be sent more often.
  _CONFIG['SEND_PERIOD'] = 20
  _CONFIG['SEND_INTERVAL'] = 5
# endif DEBUG_MODE

__VER__ = '0.1.0'


class OracleSync01Plugin(
  NetworkProcessorPlugin,
  _OraSyncStatesCallbacksMixin,
  _OraSyncUtilsMixin,
):

  def P(self, msg, **kwargs):
    if hasattr(self, 'cfg_debug_sync_full') and self.cfg_debug_sync_full and hasattr(self, 'state_machine_name'):
      try:
        curr_state = self._get_current_state()
        prefix = f'S{self.STATES_TO_INT(curr_state)}'
        msg = f'{prefix} {msg} [{curr_state}]'
      except Exception as e:
        pass
    return super().P(msg, **kwargs)

  """STATES DEFINITION SECTION"""
  if True:
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
      S11_ANNOUNCE_PARTICIPANTS = 'ANNOUNCE_PARTICIPANTS'

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
        self.STATES.S11_ANNOUNCE_PARTICIPANTS: 11,
      }[state]

    def _prepare_job_state_transition_map(self):
      job_state_transition_map = {
        self.STATES.S0_WAIT_FOR_EPOCH_CHANGE: {
          'STATE_CALLBACK': self._receive_requests_from_oracles_and_send_responses,
          'DESCRIPTION': "Wait for the epoch to change during the day.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S11_ANNOUNCE_PARTICIPANTS,
              'TRANSITION_CONDITION': self._check_epoch_finished,
              'ON_TRANSITION_CALLBACK': self._reset_to_initial_state,
              'DESCRIPTION': "If the epoch has changed, compute the local table of availability",
            },
          ],
        },
        self.STATES.S11_ANNOUNCE_PARTICIPANTS: {
          'STATE_CALLBACK': self._announce_and_observe_participants,
          'DESCRIPTION': "In this step each oracle will announce if it participates in the sync "
                         "process or not based on its self-assessment.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S1_COMPUTE_LOCAL_TABLE,
              'TRANSITION_CONDITION': self._can_participate_and_announcement_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After this step the oracle will compute its local table of availability.",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._cannot_participate_in_sync,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the node cannot participate, periodically request the agreed "
                             "median table from the oracles",
            }
          ]
        },
        self.STATES.S1_COMPUTE_LOCAL_TABLE: {
          # Because the transition conditions are mutually exclusive,
          # we cannot remain in this state for more than one step.
          'STATE_CALLBACK': self._compute_local_table,
          'DESCRIPTION': "Compute the local table of availability",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S2_SEND_LOCAL_TABLE,
              # 'TRANSITION_CONDITION': self._can_participate_in_sync,
              # This will always happen because the current oracle already checked
              # if it can participate in the sync process.
              'TRANSITION_CONDITION': self._check_no_exception_occurred,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the node can participate, join the sync process",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._check_exception_occurred,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the node cannot participate, periodically request the agreed median table from the oracles",
            }
          ],
        },
        self.STATES.S2_SEND_LOCAL_TABLE: {
          'STATE_CALLBACK': self._receive_local_table_and_maybe_send_local_table,
          'DESCRIPTION': "Exchange local table of availability between oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S3_COMPUTE_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._send_local_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, compute the median table",
            }
          ],
        },
        self.STATES.S3_COMPUTE_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._compute_median_table,
          'DESCRIPTION': "Compute the median table of availability, based on the local tables received from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S4_SEND_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._check_median_computed,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Begin the exchange process of the median tables between oracles",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._check_median_not_computed,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Median computing failed, wait for other oracles to reach consensus and request form them",
            },
          ],
        },
        self.STATES.S4_SEND_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._receive_median_table_and_maybe_send_median_table,
          'DESCRIPTION': "Exchange median table of availability between oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._send_median_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, compute the agreed median table",
            },
          ],
        },
        self.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._compute_agreed_median_table,
          'DESCRIPTION': "Compute the agreed median table of availability, based on the median tables received from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S6_SEND_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._agreement_reached,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "Begin the exchange process of the agreed median tables between oracles",
            },
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._agreement_not_reached,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "If the agreement is not reached, request the agreed median table from the other oracles."
                             "In the unlikely case that no epoch agreement is reached at all, all oracles will"
                             "transition to the request agreed median table state and will then "
                             "mark the epoch as faulty.",
            }
          ],
        },
        self.STATES.S6_SEND_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._receive_agreement_signature_and_maybe_send_agreement_signature,
          'DESCRIPTION': "Each oracle will gather and check agreement signatures from the other oracles.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES,
              'TRANSITION_CONDITION': self._send_agreement_signature_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the gathering phase time expires, oracles will start exchanging "
                             "agreement signatures again. This time they will exchange all their "
                             "gathered signatures instead of just one.",
            }
          ],
        },
        self.STATES.S10_EXCHANGE_AGREEMENT_SIGNATURES: {
          'STATE_CALLBACK': self._exchange_agreement_signatures,
          'DESCRIPTION': "Exchange agreement signatures between oracles.",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S7_UPDATE_EPOCH_MANAGER,
              'TRANSITION_CONDITION': self._exchange_signatures_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the exchange phase time expires, update the epoch manager with the "
                             "compiled agreed median table and the accumulated signatures.",
            }
          ],
        },
        self.STATES.S7_UPDATE_EPOCH_MANAGER: {
          'STATE_CALLBACK': self._update_epoch_manager_with_agreed_median_table,
          'DESCRIPTION': "Update the epoch manager with the agreed median table",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self.state_machine_api_callback_always_true,
              'ON_TRANSITION_CALLBACK': self._reset_to_initial_state,
              'DESCRIPTION': "Wait for the epoch to change to start a new sync process",
            }
          ],
        },
        self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._receive_agreed_median_table_and_maybe_request_agreed_median_table,
          'DESCRIPTION': "Wait for the oracles to send the agreed median table and periodically request the agreed median table from the oracles",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._send_request_agreed_median_table_timeout,
              'ON_TRANSITION_CALLBACK': self.state_machine_api_callback_do_nothing,
              'DESCRIPTION': "After the request phase time expires, compute the agreed median table from the received tables",
            },
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self._last_epoch_synced_is_previous_epoch,
              'ON_TRANSITION_CALLBACK': self._reset_to_initial_state,
              'DESCRIPTION': "If the last epoch synced is the previous epoch, start a new sync process",
            }
          ],
        },
        self.STATES.S9_COMPUTE_REQUESTED_AGREED_MEDIAN_TABLE: {
          'STATE_CALLBACK': self._compute_requested_agreed_median_table,
          'DESCRIPTION': "Compute the agreed median table of availability, based on the received tables",
          'TRANSITIONS': [
            {
              'NEXT_STATE': self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
              'TRANSITION_CONDITION': self._last_epoch_synced_is_not_previous_epoch,
              'ON_TRANSITION_CALLBACK': self._reset_for_agreement_request_retry,
              'DESCRIPTION': "If the agreement could not be computed retry."
            },
            {
              'NEXT_STATE': self.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
              'TRANSITION_CONDITION': self._last_epoch_synced_is_previous_epoch,
              'ON_TRANSITION_CALLBACK': self._reset_to_initial_state,
              'DESCRIPTION': "Begin the exchange process of the agreed median tables between oracles",
            }
          ],
        },
      }
      return job_state_transition_map
  """END STATES DEFINITION SECTION"""

  def on_init(self):
    while self.netmon.epoch_manager is None:
      self.P(f"Waiting for epoch manager to be initialized for {self._name__} to start.")
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
    self._oracle_list = []
    self._last_oracle_list_refresh = None
    self._last_oracle_list_refresh_attempt = None
    self._last_self_assessment_ts = None

    self._self_assessment_data = {
      'series': self.deque(maxlen=10),
      'last_avail' : None,
      'recorded_epoch' : None,
    }

    self.maybe_refresh_oracle_list()
    current_oracle_list = self.get_oracle_list()
    while current_oracle_list is not None and len(current_oracle_list) == 0:
      sleep_period = 5
      self.P(f"No oracles found. Re-attempting to refresh the oracle list in {sleep_period} seconds.")
      self.sleep(sleep_period)
      self.maybe_refresh_oracle_list()
      current_oracle_list = self.get_oracle_list()
    # endwhile oracle list is empty
    self._reset_to_initial_state()

    self.P(
      f"{FULL_AVAILABILITY_THRESHOLD=} | {POTENTIALLY_FULL_AVAILABILITY_THRESHOLD=}",
      boxed=True
    )

    # All oracles start in the state S8_SEND_REQUEST_AGREED_MEDIAN_TABLE
    # because they have to request the agreed median table and wait to receive
    # the agreed median table from the previous epochs.
    self.state_machine_name = 'OracleSyncPlugin'
    self._received_messages_from_oracles = self.deque(maxlen=MAX_RECEIVED_MESSAGES_SIZE)
    self.state_machine_api_init(
      name=self.state_machine_name,
      state_machine_transitions=self._prepare_job_state_transition_map(),
      initial_state=self.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE,
      on_successful_step_callback=self.state_machine_api_callback_do_nothing,
    )
    return

  def _reset_to_initial_state(self):
    """
    Reset the plugin to the initial state.
    """
    self.P(f'Resetting to initial state')
    self._current_epoch = self.netmon.epoch_manager.get_current_epoch()
    self.current_epoch_computed = False
    self.exception_occurred = False

    self.is_participating = {}

    self._potentially_full_availability_threshold = POTENTIALLY_FULL_AVAILABILITY_THRESHOLD

    self._announced_participating = set()
    self.first_time_announce_participants = None
    self.last_time_announce_participants = None

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

    self._last_epoch_synced = self.netmon.epoch_manager.get_last_sync_epoch()
    self.first_time_request_agreed_median_table_sent = None
    self.last_time_request_agreed_median_table_sent = None
    self.P(f'Current epoch: {self._current_epoch}, Last epoch synced: {self._last_epoch_synced}.')
    return

  # """STATE MACHINE CALLBACKS SECTION"""
  # if True:
  #   
  # """END STATE MACHINE SECTION"""

  # """UTILS SECTION"""
  # if True:
  # 
  # """END UTILS SECTION"""

  """MESSAGE HANDLING UTILS SUBSECTION"""
  if True:
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
      if not self._is_oracle(sender):
        return
      self._received_messages_from_oracles.append(payload)
      return

    def get_received_messages_from_oracles(self):
      """
      Get the messages received from the oracles.
      This method returns a generator for memory efficiency.

      Returns
      -------
      generator : The messages received from the oracles
      """
      # retrieve messages from self._received_messages_from_oracles
      dct_messages = list(self._received_messages_from_oracles)
      self._received_messages_from_oracles.clear()
      # This will return a generator that will be used in the next steps.
      received_messages = (dct_messages[i] for i in range(len(dct_messages)))

      return received_messages
  """END MESSAGE HANDLING UTILS SUBSECTION"""

  def maybe_self_assessment(self):
    """
    Perform self-assessment throughout the epoch to know the local availability so far and
    to predict the final availability of the node at the end of the epoch.
    """
    if self._get_current_state() != self.STATES.S0_WAIT_FOR_EPOCH_CHANGE:
      return
    elapsed = self.time() - self._last_self_assessment_ts if self._last_self_assessment_ts is not None else None
    if self._last_self_assessment_ts is not None and elapsed < self.cfg_self_assessment_interval:
      return
    self._last_self_assessment_ts = self.time()
    total_seconds_availability, total_seconds_from_start = self.netmon.epoch_manager.get_current_epoch_availability(
      return_absolute=True,
      return_max=True
    )
    
    total_epoch_seconds = self.netmon.epoch_manager.epoch_length
    seconds_left = total_epoch_seconds - total_seconds_from_start
    prc_node_availability = total_seconds_availability / total_epoch_seconds
    prc_max_availability = total_seconds_from_start / total_epoch_seconds
    prc_missed_availability = prc_max_availability - prc_node_availability
    prc_max_predicted_availability = 1 - prc_missed_availability
    prc_predicted_availability = prc_max_predicted_availability
    
    will_participate_on_max = prc_max_predicted_availability >= SUPERVISOR_MIN_AVAIL_PRC        
    comparing_str_on_max = f"{'>=' if will_participate_on_max else '<='} {SUPERVISOR_MIN_AVAIL_PRC:.2%}"
    comparing_str_on_max += f" => {'will' if will_participate_on_max else 'will not'} participate in the sync process."
        
    diff, mean_degrade = 0.0, 0.0
    if self.netmon.epoch_manager.get_current_epoch() != self._self_assessment_data['recorded_epoch']:
      # Reset the self-assessment data if the epoch has changed
      self._self_assessment_data['series'] = []
      self._self_assessment_data['last_avail'] = None
      self._self_assessment_data['recorded_epoch'] = self.netmon.epoch_manager.get_current_epoch()
    # endif
    if self._self_assessment_data['last_avail'] is not None:
      # If the last availability is recorded, compute the difference
      diff = prc_node_availability - self._self_assessment_data['last_avail']
      self._self_assessment_data['series'].append(diff)
      if len(self._self_assessment_data['series']) > 1:
        # Compute the mean degrade per interval
        mean_degrade = self.np.mean(self._self_assessment_data['series'])
        mean_degrade_per_second = mean_degrade / self.cfg_self_assessment_interval
        future_degrade = mean_degrade_per_second * seconds_left
        # now compute the predicted availability at the end of the epoch        
        prc_predicted_availability = prc_max_predicted_availability - future_degrade # 1 - prc_missed_availability - future_degrade
    # endif

    will_participate = prc_predicted_availability >= SUPERVISOR_MIN_AVAIL_PRC        
    comparing_str = f"{'>=' if will_participate else '<='} {SUPERVISOR_MIN_AVAIL_PRC:.2%}"
    comparing_str += f" => {'will' if will_participate else 'will not'} participate in the sync process."

    self._self_assessment_data['last_avail'] = prc_node_availability
    
    log_str = f"Current self-assessment:\n"
    log_str += f'\tTime until epoch end:    {seconds_left / 3600:.2f} hours\n'
    log_str += f"\tNode current avail:      {prc_node_availability:.2%}\n"
    log_str += f"\tPassed from epoch:       {prc_max_availability:.2%}\n"
    log_str += f"\tMissed avail so far:     {prc_missed_availability:.2%}\n"
    log_str += f"\tDegrade from last check: {diff:.2%}\n"
    log_str += f"\tMean degrading per hour: {mean_degrade:.2%}\n"
    log_str += f"\tMaximal at epoch end:    {prc_max_predicted_availability:.2%}{comparing_str_on_max}\n"
    log_str += f"\tPredicted at epoch end:  {prc_predicted_availability:.2%}{comparing_str}\n"

    self.P(log_str, color='g')
    return

  def process(self):
    try:
      self.maybe_refresh_oracle_list()
      self.state_machine_api_step(self.state_machine_name)
      self.maybe_self_assessment()
    except Exception as e:
      sleep_period = 0.1
      self.exception_occurred = True
      self.P(f"Exception during process:\n{self.trace_info()}\nSleeping for {sleep_period} seconds.", color='r')
      self.sleep(sleep_period)
    # endtry-except
    return
