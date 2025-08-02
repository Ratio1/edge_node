from naeural_core.constants import SUPERVISOR_MIN_AVAIL_PRC, EPOCH_MAX_VALUE

MAX_RECEIVED_MESSAGES_SIZE = 1000
DEBUG_MODE = False
SIGNATURES_EXCHANGE_MULTIPLIER = 2
REQUEST_AGREEMENT_TABLE_MULTIPLIER = 5 if DEBUG_MODE else 2
LOCAL_TABLE_SEND_MULTIPLIER = 3 if DEBUG_MODE else 2

if DEBUG_MODE:
  SUPERVISOR_MIN_AVAIL_PRC = 0.4

# Full availability means that the node was seen online for at least SUPERVISOR_MIN_AVAIL_PRC% of the time.
FULL_AVAILABILITY_THRESHOLD = round(SUPERVISOR_MIN_AVAIL_PRC * EPOCH_MAX_VALUE)
# While full availability is according to the SUPERVISOR_MIN_AVAIL_PRC, potentially full availability
# takes into consideration that the 2 accepted periods of offline time could have been in different intervals.
# Thus, the accepted offline time will be doubled and the threshold will be
# EPOCH_MAX_VALUE - 2 * (EPOCH_MAX_VALUE - FULL_AVAILABILITY_THRESHOLD).

POTENTIALLY_FULL_AVAILABILITY_THRESHOLD = EPOCH_MAX_VALUE - 2 * (EPOCH_MAX_VALUE - FULL_AVAILABILITY_THRESHOLD)
# Maybe review this in the future, as new oracles appear
ORACLE_SYNC_ACCEPTED_REPORTS_THRESHOLD = 0
ORACLE_SYNC_ACCEPTED_MEDIAN_ERROR_MARGIN = EPOCH_MAX_VALUE - POTENTIALLY_FULL_AVAILABILITY_THRESHOLD

ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD = 0.3
ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD = 0.4

class OracleSyncCt:
  MEDIAN_TABLE = 'MEDIAN_TABLE'
  AGREED_MEDIAN_TABLE = 'AGREED_MEDIAN_TABLE'
  COMPILED_AGREED_MEDIAN_TABLE = 'COMPILED_AGREED_MEDIAN_TABLE'
  ANNOUNCED_PARTICIPANTS = 'ANNOUNCED_PARTICIPANTS'
  LOCAL_TABLE = 'LOCAL_TABLE'
  REQUEST_AGREED_MEDIAN_TABLE = 'REQUEST_AGREED_MEDIAN_TABLE'
  EPOCH__AGREED_MEDIAN_TABLE = 'EPOCH__AGREED_MEDIAN_TABLE'
  EPOCH__AGREEMENT_SIGNATURES = 'EPOCH__AGREEMENT_SIGNATURES'
  EPOCH__IS_VALID = 'EPOCH__IS_VALID'
  EPOCH_KEYS = 'EPOCH_KEYS'
  ID_TO_NODE_ADDRESS = 'ID_TO_NODE_ADDRESS'
  STAGE = 'STAGE'
  EPOCH = 'EPOCH'
  NODE = 'NODE'
  AGREEMENT_SIGNATURE = 'AGREEMENT_SIGNATURE'
  AGREEMENT_SIGNATURES = 'AGREEMENT_SIGNATURES'
  AVAILABILITIES = 'AVAILABILITIES'
# endclass OracleSyncCt


VALUE_STANDARDS = {
  OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: {
    # 'type': dict,
    'type': (str, dict),
    'maybe_cid': True
  },
  OracleSyncCt.ID_TO_NODE_ADDRESS: {
    'type': dict,
  },
  OracleSyncCt.EPOCH_KEYS: {
    'type': list,
  },
  OracleSyncCt.STAGE: {
    'type': str,
  },
  OracleSyncCt.ANNOUNCED_PARTICIPANTS: {
    "type": list,
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

