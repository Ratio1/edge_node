from naeural_core.business.base import BasePluginExecutor as BasePlugin

__VER__ = '0.0.0.1'

# Constants
HISTORY_FILE_PATH = 'sensibo_history.pickle'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PROCESS_DELAY': 60,  # Process every 60 seconds
  'ALLOW_EMPTY_INPUTS': True,  # Allow running without input data
  'API_URL': 'https://home.sensibo.com/api/v2',
  'API_KEY': None,  # Sensibo API key should be configured in instance config
  'POD_UID': None,  # If not provided, will automatically fetch the first available pod UID from the account
  
  # Anomaly detection parameters
  'ANOMALY_THRESHOLD': 3.0,  # Z-score threshold for anomaly detection
  'MIN_SAMPLES_FOR_ANOMALY': 10,  # Minimum samples needed for anomaly detection

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
    # Maximum number of history entries to keep
    self.__max_history_size = 1000
    # Flag to track if history has been modified
    self.__history_modified = False
    # Load measurement history from pickle file
    self._load_measurement_history()
    self._fetch_pod_uid()  # Fetch pod UID on initialization
    return

  def _load_measurement_history(self):
    """Load measurement history from pickle file"""
    try:
      data = self.diskapi_load_pickle_from_data(HISTORY_FILE_PATH)
      if data:
        self.__measurement_history = data
        self.P(f"Loaded {len(self.__measurement_history)} historical measurements from {HISTORY_FILE_PATH}")
      else:
        self.P(f"No history file found at {HISTORY_FILE_PATH}, starting with empty history")
    except Exception as e:
      self.P(f"Error loading measurement history: {str(e)}", color='r')
      # Start with empty history in case of error
      self.__measurement_history = []
      
  def _save_measurement_history(self):
    """Save measurement history to pickle file if modified"""
    if not self.__history_modified:
      return
      
    try:
      # Save history to file
      self.diskapi_save_pickle_to_data(self.__measurement_history, HISTORY_FILE_PATH)
      self.P(f"Saved {len(self.__measurement_history)} measurements to {HISTORY_FILE_PATH}")
      self.__history_modified = False
    except Exception as e:
      self.P(f"Error saving measurement history: {str(e)}", color='r')

  def _fetch_pod_uid(self):
    """Fetch the pod UID from Sensibo API"""
    try:
      url = f"{self.cfg_api_url}/users/me/pods"
      params = {
        'apiKey': self.cfg_api_key
      }
      response = self.requests.get(url, params=params)
      data = response.json()

      if 'result' in data and len(data['result']) > 0:
        # Get the first pod's UID
        self.__pod_uid = data['result'][0]['id']
        self.P(f"Successfully fetched pod UID: {self.__pod_uid}")
        return True
      else:
        self.P("No pods found in the account", color='r')
        return False

    except Exception as e:
      self.P(f"Error fetching pod UID: {str(e)}", color='r')
      return False

  def _fetch_measurements(self):
    """Fetch temperature and humidity data from the Sensibo API"""
    if not self.__pod_uid:
      if not self._fetch_pod_uid():
        return None, None

    try:
      url = f"{self.cfg_api_url}/pods/{self.__pod_uid}/measurements"
      params = {
        'apiKey': self.cfg_api_key,
        'fields': 'temperature,humidity'
      }
      response = self.requests.get(url, params=params)
      data = response.json()

      if 'result' in data and len(data['result']) > 0:
        latest_measurement = data['result'][0]
        temperature = latest_measurement.get('temperature')
        humidity = latest_measurement.get('humidity')
        measurement_time = latest_measurement.get('time', {}).get('time')

        # Add to history
        if temperature is not None and humidity is not None:
          history_entry = {
            'temperature': temperature,
            'humidity': humidity,
            'timestamp': measurement_time
          }
          self.__measurement_history.append(history_entry)
          # Limit history size
          if len(self.__measurement_history) > self.__max_history_size:
            self.__measurement_history.pop(0)
          # Mark history as modified
          self.__history_modified = True
          # Save history after modification
          self._save_measurement_history()

        self.P(f"Fetched measurements - Temperature: {temperature}°C, Humidity: {humidity}%, Time: {measurement_time}")
        return temperature, humidity
      else:
        self.P("No measurement data available", color='y')
        return None, None

    except Exception as e:
      self.P(f"Error fetching measurements: {str(e)}", color='r')
      return None, None

  def _check_anomalies(self, temperature, humidity):
    """Check for anomalies in temperature and humidity data"""
    anomalies = {}
    
    # Need enough samples for statistical significance
    if len(self.__measurement_history) >= self.cfg_min_samples_for_anomaly:
      # Extract historical values
      temp_history = [entry.get('temperature') for entry in self.__measurement_history 
                      if entry.get('temperature') is not None]
      humid_history = [entry.get('humidity') for entry in self.__measurement_history 
                       if entry.get('humidity') is not None]
      
      # Check temperature anomaly using z-score
      if temperature is not None and len(temp_history) >= self.cfg_min_samples_for_anomaly:
        temp_mean = self.np.mean(temp_history)
        temp_std = self.np.std(temp_history)
        if temp_std > 0:  # Avoid division by zero
          temp_zscore = abs((temperature - temp_mean) / temp_std)
          if temp_zscore > self.cfg_anomaly_threshold:
            anomalies['temperature'] = {
              'value': temperature,
              'z_score': temp_zscore,
              'threshold': self.cfg_anomaly_threshold,
              'mean': temp_mean,
              'std': temp_std
            }
            self.P(f"ANOMALY DETECTED: Temperature {temperature}°C has z-score {temp_zscore:.2f}", color='r')
      
      # Check humidity anomaly using z-score
      if humidity is not None and len(humid_history) >= self.cfg_min_samples_for_anomaly:
        humid_mean = self.np.mean(humid_history)
        humid_std = self.np.std(humid_history)
        if humid_std > 0:  # Avoid division by zero
          humid_zscore = abs((humidity - humid_mean) / humid_std)
          if humid_zscore > self.cfg_anomaly_threshold:
            anomalies['humidity'] = {
              'value': humidity,
              'z_score': humid_zscore,
              'threshold': self.cfg_anomaly_threshold,
              'mean': humid_mean,
              'std': humid_std
            }
            self.P(f"ANOMALY DETECTED: Humidity {humidity}% has z-score {humid_zscore:.2f}", color='r')
    
    return anomalies

  def process(self):
    """Main processing method called every PROCESS_DELAY seconds"""

    self.P(f"Fetching measurements")
    # Only fetch if enough time has passed
    temperature, humidity = self._fetch_measurements()
    
    # Check for anomalies
    anomalies = {}
    if temperature is not None and humidity is not None:
      anomalies = self._check_anomalies(temperature, humidity)
    
    self.P("Measurements history:")
    self.P(self.__measurement_history)
    
    if temperature is not None and humidity is not None:
      payload = self._create_payload(
        temperature=temperature,
        humidity=humidity,
        pod_uid=self.__pod_uid,
        timestamp=self.time_to_str(),
        anomalies=anomalies
      )
      return payload

    return None
