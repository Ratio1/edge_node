from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.0.0.1'

# Constants
HISTORY_FILE_PATH = 'sensibo_history.pickle'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PROCESS_DELAY': 30,
  'ALLOW_EMPTY_INPUTS': False,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class MaintenanceMonitoringPlugin(BasePlugin):
  """
  Plugin for monitoring temperature and humidity using Sensibo devices.
  """
  CONFIG = _CONFIG
  SIGNATURE = 'MAINTENANCE_MONITORING'  # This is the signature used in pipeline config

  def on_init(self):
    """Initialize the plugin"""
    self.P(f"Initializing MaintenanceMonitoringPlugin v{__VER__}")
    self.__pod_uid = None
    # Store measurement history
    self.__measurement_history = []
    # Store anomalies history
    self.__anomalies_history = []
    # Maximum number of history entries to keep
    self.__max_history_size = 1000
    # Load measurement history from pickle file
    self._load_measurement_history(HISTORY_FILE_PATH)
    return

  def _load_measurement_history(self, file_path):
    """Generic function to load data from pickle file"""
    try:
      data = self.diskapi_load_pickle_from_data(file_path)
      if data:
        self.__measurement_history = data
        self.P(f"Loaded {len(data)} records from {file_path}")
      else:
        self.P(f"No file found at {file_path}, starting with empty data")
    except Exception as e:
      self.P(f"Error loading data from {file_path}: {str(e)}", color='r')
      # Keep the default empty list in case of error
      
  def _save_measurement_history(self):
    """Save measurement history to pickle file if modified"""

    try:
      # Save data to file
      self.diskapi_save_pickle_to_data(self.__measurement_history, HISTORY_FILE_PATH)
      self.P(f"Saved {len(self.__measurement_history)} records to {HISTORY_FILE_PATH}")
      self.__history_modified = False
    except Exception as e:
      self.P(f"Error saving data to {HISTORY_FILE_PATH}: {str(e)}", color='r')


  def _fetch_measurements(self):
    """Fetch temperature and humidity data from the Sensibo API"""
    try:
      data = self.dataapi_struct_data()
      self.P("Fetching measurements from Sensibo DCT Plugin: " + self.json_dumps(data, indent=2))

    except Exception as e:
      self.P(f"Error fetching measurements: {str(e)}", color='r')
      return None, None

  def _check_anomalies(self, temperature, humidity):
    """Check for anomalies in temperature and humidity data"""
    anomalies = {}
    
    return anomalies

  def process(self):
    """Main processing method called every PROCESS_DELAY seconds"""

    self.P(f"Fetching measurements")
    # Only fetch if enough time has passed
    measurements = self._fetch_measurements()

    payload = self._create_payload(
      measurements = measurements
    )
    return payload
