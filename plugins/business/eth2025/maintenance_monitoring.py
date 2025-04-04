from naeural_core.business.base import BasePluginExecutor as BasePlugin

__VER__ = '0.0.0.1'

# Constants
HISTORY_FILE_PATH = 'sensibo_history.pickle'
# Store measurements for the last 2 hours
HISTORY_TIME_WINDOW = 2 * 60 * 60  # 2 hours in seconds

_CONFIG = {
  **BasePlugin.CONFIG,

  'PROCESS_DELAY': 30,
  'ALLOW_EMPTY_INPUTS': False,

  'ANOMALY_PROBABILITY_THRESHOLD': 0.8,

  "AIHO_ANOMALIES_URL": "https://api.aiho.ai/new_predictive_maintenance_event",
  "AIHO_HISTORY_URL": "https://api.aiho.ai/new_predictive_maintenance_measurements",

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
    # Flag to track if history has been modified
    self.__history_modified = False

    self._last_history_sent_time = None
    return

  def _get_current_time_iso(self):
    """Get current time in ISO format using self methods"""
    # Assuming there's a time_iso method or something similar in the base plugin
    return self.datetime.now().isoformat()

  def _is_timestamp_newer(self, timestamp1, timestamp2):
    """Compare two ISO timestamps to check if timestamp1 is newer than or equal to timestamp2"""
    try:
      # Handle 'Z' timezone indicator by replacing it with +00:00
      if isinstance(timestamp1, str) and timestamp1.endswith('Z'):
        timestamp1 = timestamp1.replace('Z', '+00:00')
      if isinstance(timestamp2, str) and timestamp2.endswith('Z'):
        timestamp2 = timestamp2.replace('Z', '+00:00')

      dt1 = self.datetime.fromisoformat(timestamp1)
      dt2 = self.datetime.fromisoformat(timestamp2)
      return dt1 >= dt2
    except Exception as e:
      self.P(f"Error comparing timestamps: {str(e)}", color='r')
      # Alternative comparison method using epoch time
      try:
        # Try to convert ISO to epoch
        epoch1 = self.datetime.fromisoformat(timestamp1).timestamp()
        epoch2 = self.datetime.fromisoformat(timestamp2).timestamp()
        return epoch1 >= epoch2
      except Exception:
        # If all else fails, just use string comparison (works for ISO format)
        return timestamp1 >= timestamp2

  def _get_cutoff_time_iso(self):
    """Get cutoff time for pruning in ISO format"""
    # Calculate cutoff time directly from epoch time
    current_epoch = self.time()
    cutoff_epoch = current_epoch - HISTORY_TIME_WINDOW
    # Convert to ISO format
    return self.datetime.fromtimestamp(cutoff_epoch).isoformat()

  def _create_iso_timestamp_from_time(self, time_value=None):
    """Create an ISO timestamp from a time value (epoch)"""
    if time_value is None:
      time_value = self.time()

    if isinstance(time_value, (int, float)):
      return self.datetime.fromtimestamp(time_value).isoformat()
    elif isinstance(time_value, str):
      # Handle 'Z' timezone indicator in input timestamps
      if time_value.endswith('Z'):
        return time_value.replace('Z', '+00:00')
      return time_value

    return self.datetime.now().isoformat()

  def _prune_old_measurements(self):
    """Remove measurements older than the history time window"""
    cutoff_time_iso = self._get_cutoff_time_iso()

    original_length = len(self.__measurement_history)
    # Filter measurements based on ISO format timestamps
    new_history = []
    for m in self.__measurement_history:
      if 'timestamp' in m:
        try:
          if self._is_timestamp_newer(m['timestamp'], cutoff_time_iso):
            new_history.append(m)
        except Exception as e:
          self.P(f"Error comparing timestamps: {str(e)}", color='r')
          # Keep the measurement if we can't compare (benefit of doubt)
          new_history.append(m)

    self.__measurement_history = new_history

    if len(self.__measurement_history) < original_length:
      self.__history_modified = True
      self.P(f"Pruned {original_length - len(self.__measurement_history)} old records from history")

  def _fetch_measurements(self):
    """Fetch temperature and humidity data from the Sensibo API"""
    try:
      data = self.dataapi_struct_data()
      self.P("Fetching measurements from Sensibo DCT Plugin: " + self.json_dumps(data, indent=2))
      return data
    except Exception as e:
      self.P(f"Error fetching measurements: {str(e)}", color='r')
      return None

  def _add_measurement_to_history(self, measurement):
    """Add a new measurement to the history with a timestamp"""
    if not measurement:
      return

    # Add timestamp if not already present
    if 'timestamp' not in measurement:
      measurement['timestamp'] = self._get_current_time_iso()
    else:
      # Ensure timestamp is in ISO format
      if not isinstance(measurement['timestamp'], str):
        measurement['timestamp'] = self._create_iso_timestamp_from_time(measurement['timestamp'])

    # Add to history
    self.__measurement_history.append(measurement)
    self.__history_modified = True

    # Prune old measurements
    # self._prune_old_measurements()

  def _check_anomalies(self, temperature, humidity):
    """Check for anomalies in temperature and humidity data"""
    # Extract temperature and humidity data separately
    temp_data = []
    humidity_data = []

    for measurement in self.__measurement_history:
      if 'temperature' in measurement:
        temp_data.append(measurement['temperature'])
      if 'humidity' in measurement:
        humidity_data.append(measurement['humidity'])

    # Skip if we don't have enough data points
    if len(temp_data) < 5 or len(humidity_data) < 5:  # Minimum samples needed for meaningful anomaly detection
      self.P("Not enough data points for anomaly detection")
      return []

    # Convert to numpy arrays (required format for anomaly detection)
    # Reshape to make 2D arrays with one feature
    temp_data_np = self.np.array(temp_data).reshape(-1, 1)
    humidity_data_np = self.np.array(humidity_data).reshape(-1, 1)

    # Call the anomaly detection API for each data type
    try:
      # Process temperature anomalies
      temp_result = self.mlapi_anomaly_fit_predict(
        x_train=temp_data_np,
        x_test=temp_data_np,
        proba=True
      )


      # Get current datetime for results
      dt = self.datetime.now()
      res = {}

      # Process humidity anomalies
      humidity_result = self.mlapi_anomaly_fit_predict(
        x_train=humidity_data_np,
        x_test=humidity_data_np,
        proba=True
      )

      # Set ISO format timestamp
      res['read_time'] = dt.isoformat()

      # Combine anomaly results
      anomalies = []

      self.P("Processing temperature and humidity anomalies...")

      # Process temperature anomalies
      temp_anomalies = []
      try:
        for idx, [item] in enumerate(temp_result):
          # Convert to float and compare with threshold
          prob_value = float(item)
          if prob_value > self.cfg_anomaly_probability_threshold:
            temp_anomalies.append(idx)
            self.P(f"ALERT: Temperature anomaly detected at index {idx} with probability {prob_value}", color='r')
      except Exception as e:
        self.P(f"Error processing temperature anomalies: {str(e)}", color='r')

      # Process detected temperature anomalies
      for idx in temp_anomalies:
        if idx < len(self.__measurement_history):
          anomaly_record = self.__measurement_history[idx]
          anomalies.append({
            'timestamp': anomaly_record.get('timestamp', self._get_current_time_iso()),
            'temperature': anomaly_record.get('temperature', None),
            'humidity': anomaly_record.get('humidity', None),
            'reason_key': 'temperature'
          })

      # Process humidity anomalies
      humidity_anomalies = []
      # Process detected humidity anomalies
      for idx in humidity_anomalies:
        if idx < len(self.__measurement_history):
          # Check if this anomaly is not already reported from temperature
          already_reported = False
          for existing_anomaly in anomalies:
            # Compare ISO format timestamps - direct string comparison should work
            if existing_anomaly['timestamp'] == self.__measurement_history[idx].get('read_time', self._get_current_time_iso()):
              # Update reason for existing anomaly
              existing_anomaly['reason_key'] = 'both' # both temperature and humidity
              already_reported = True
              break

          if not already_reported:
            anomaly_record = self.__measurement_history[idx]
            anomalies.append({
              'timestamp': anomaly_record.get('timestamp', self._get_current_time_iso()),
              'temperature': anomaly_record.get('temperature', None),
              'humidity': anomaly_record.get('humidity', None),
              'reason_key': 'humidity'
            })

      self.P(f"Detected {len(anomalies)} anomalies in temperature and humidity data")
      return anomalies

    except Exception as e:
      self.P(f"Error in anomaly detection: {str(e)}", color='r')
      return []

  def process(self):
    """Main processing method called every PROCESS_DELAY seconds"""

    self.P(f"Fetching measurements")
    # Only fetch if enough time has passed
    measurements = self._fetch_measurements()

    if measurements:
      # Add measurements to history
      self._add_measurement_to_history(measurements)

    # Send measurement history to AIHO every 60 seconds
    current_time = self.time()
    if self._last_history_sent_time is None or current_time - self._last_history_sent_time >= 60:
      self.P("Sending measurement history to AIHO")
      # Create request data with measurement history
      history_data = {
        'measurements': self.__measurement_history,
        'timestamp': self._get_current_time_iso(),
        'device_id': self.__pod_uid,
        'propertyId': 1
      }
      # Send POST request with history data
      try:
        self.requests.post(url=self.cfg_aiho_history_url, json=history_data)
        self.P(f"Sent {len(self.__measurement_history)} measurement records to {self.cfg_aiho_history_url}")
        # Update last sent time
        self._last_history_sent_time = current_time
      except Exception as e:
        self.P(f"Error sending measurement history to AIHO: {str(e)}", color='r')

    # Check for anomalies using the latest data
    anomalies = []
    if measurements and 'temperature' in measurements and 'humidity' in measurements:
      temperature = measurements.get('temperature')
      humidity = measurements.get('humidity')
      anomalies = self._check_anomalies(temperature, humidity)
      self.P('anomalies:')
      self.P(anomalies)

      # Only send POST request if anomalies exist
      if anomalies:
        # Create request data to send to AIHO
        request_data = {
          'anomalies': anomalies,
          'timestamp': self._get_current_time_iso(),
          'device_id': self.__pod_uid,
          'propertyId': 1
        }
        # Send POST request with anomalies data
        self.requests.post(url=self.cfg_aiho_anomalies_url, json=request_data)
        self.P(f"Sent {len(anomalies)} anomalies to {self.cfg_aiho_anomalies_url}")

    payload = self._create_payload(
      measurements=measurements,
      anomalies=anomalies
    )
    return payload
