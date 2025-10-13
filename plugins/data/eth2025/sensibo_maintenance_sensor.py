from naeural_core.data.base import DataCaptureThread

_CONFIG = {

  **DataCaptureThread.CONFIG,

  "CAP_RESOLUTION": 0.003,
  "SENSIBO_API_KEY": "",
  "SENSIBO_DEVICE_NAME": "R1 Sensibo",
  "SENSIBO_POD_UID": "",  # If provided, will use this instead of looking up by device name
  "VERBOSITY": 1,  # 0=minimal, 1=normal, 2=verbose, 3=debug

  'VALIDATION_RULES': {
    **DataCaptureThread.CONFIG['VALIDATION_RULES'],
  },
}

_SERVER = 'https://home.sensibo.com/api/v2'


class SensiboMaintenanceSensorDataCapture(DataCaptureThread):
  CONFIG = _CONFIG


  def _log(self, message, verbosity_level=1, color=None):
    """
    Conditional logging based on verbosity level.

    Args:
      message: The message to log
      verbosity_level: Minimum verbosity level required to show this message
      color: Optional color for the message
    """
    if self.cfg_verbosity >= verbosity_level:
      self.P(message, color=color)

  def on_init(self):
    super().on_init()
    self._log("Initializing SensiboMaintenanceSensorDataCapture", verbosity_level=1)
    self._api_key = None
    self._uid = None
    self._device_name = None
    self._last_acquisition_time = None
    return

  def __get_data(self, path, **params):
    self._log(f"Making API request to: {_SERVER + path}", verbosity_level=3)
    params['apiKey'] = self._api_key
    response = self.requests.get(_SERVER + path, params=params)
    response.raise_for_status()
    self._log(f"API request successful, status: {response.status_code}", verbosity_level=3)
    return response.json()

  def __list_devices(self):
    self._log("Fetching list of Sensibo devices", verbosity_level=2)
    result = self.__get_data('/users/me/pods', fields='id,room')
    self._log("Sensibo device info:\n{}".format(self.json.dumps(result, indent=4)), verbosity_level=2)
    devices = {x['room']['name']: x['id'] for x in result['result']}
    self._log(f"Found {len(devices)} devices: {list(devices.keys())}", verbosity_level=1)
    return devices

  def __get_measurement(self, pod_uid=None):
    if pod_uid is None:
      pod_uid = self._uid
    self._log(f"Fetching measurements for pod UID: {pod_uid}", verbosity_level=2)
    results = self.__get_data('/pods/{}/measurements'.format(pod_uid))
    results = results['result']
    self._log(f"Received {len(results)} measurement records", verbosity_level=2)

    for res in results:
      if 'time' in res:
        str_dt = res['time']['time']
        dt = self.datetime.strptime(str_dt, '%Y-%m-%dT%H:%M:%S.%fZ')
        delay = res['time']['secondsAgo']
        res['read_time'] = dt.isoformat()
        res['read_time_str'] = str_dt
        res['read_delay'] = delay
        self._log(f"Processed timestamp: {str_dt} (delay: {delay}s)", verbosity_level=3)

    self._log("Measurement data:\n{}".format(self.json.dumps(results, indent=4)), verbosity_level=2)
    return results

  def connect(self):  # MANDATORY
    if self.has_connection and self._uid:
      self._log("Connection already established, skipping new connect", verbosity_level=2)
      return True

    self._log("Connecting to Sensibo API", verbosity_level=0)
    self._api_key = (self.cfg_sensibo_api_key or '').strip()
    if not self._api_key:
      self._log("SENSIBO_API_KEY is missing", verbosity_level=0, color='r')
      self.has_connection = False
      return False

    self._log(
      f"Using API key prefix: {self._api_key[:8]}...",
      verbosity_level=2,
    )

    pod_uid = (self.cfg_sensibo_pod_uid or '').strip()
    if pod_uid:
      self._uid = pod_uid
      self.has_connection = True
      self._log(f"Using provided pod UID: {self._uid}", verbosity_level=0)
      return True

    self._device_name = (self.cfg_sensibo_device_name or '').strip()
    if not self._device_name:
      self._log("SENSIBO_DEVICE_NAME is missing", verbosity_level=0, color='r')
      self.has_connection = False
      return False

    self._log(f"Looking up device by name: {self._device_name}", verbosity_level=1)
    try:
      devices = self.__list_devices()
    except Exception as exc:
      self._log(f"Failed to list Sensibo devices: {exc}", verbosity_level=0, color='r')
      self.has_connection = False
      return False

    if self._device_name not in devices:
      available = ', '.join(devices.keys()) if devices else 'none'
      self._log(
        f"Device '{self._device_name}' not found. Available devices: {available}",
        verbosity_level=0,
        color='r',
      )
      self.has_connection = False
      return False

    self._uid = devices[self._device_name]
    self.has_connection = True
    self._log(
      f"Successfully connected to device '{self._device_name}' with UID: {self._uid}",
      verbosity_level=0,
    )
    return True

  def _release(self):  # MANDATORY
    self._log("Releasing Sensibo connection", verbosity_level=2)
    self._uid = None
    self._api_key = None
    self._device_name = None
    self.has_connection = False
    return

  def __get_data_from_sensibo(self):
    self._log("Fetching latest data from Sensibo", verbosity_level=2)
    res = self.__get_measurement(self._uid)
    latest_data = res[-1] if res else None
    if latest_data:
      self._log(f"Retrieved latest measurement: temp={latest_data.get('temperature', 'N/A')}°C, humidity={latest_data.get('humidity', 'N/A')}%", verbosity_level=1)
    else:
      self._log("No measurement data available", verbosity_level=0, color='r')
    return latest_data

  def data_step(self):  # MANDATORY
    self._maybe_reconnect()
    if not self.has_connection:
      self._log("Unable to establish connection to Sensibo API", verbosity_level=0, color='r')
      return

    current_time = self.datetime.now()
    self._log(f"Starting data acquisition step at {current_time.isoformat()}", verbosity_level=3)

    # Check if 30 seconds have elapsed since the last acquisition
    if self._last_acquisition_time is not None:
      elapsed_seconds = (current_time - self._last_acquisition_time).total_seconds()
      self._log(f"Time since last acquisition: {elapsed_seconds:.1f} seconds", verbosity_level=3)
      if elapsed_seconds < 30:
        self._log(f"Skipping data acquisition, only {elapsed_seconds:.1f} seconds elapsed (< 30s required)", verbosity_level=2)
        return
    else:
      self._log("First data acquisition, no previous time recorded", verbosity_level=2)

    try:
      _obs = self.__get_data_from_sensibo()
      self._last_acquisition_time = current_time

      if _obs:
        self._log(f"Successfully acquired data: {self.json.dumps(_obs, indent=2)}", verbosity_level=2)
        self._add_inputs(
          [
            self._new_input(img=None, struct_data=_obs, metadata=self._metadata.__dict__.copy()),
          ]
        )
        self._log("Data added to input queue", verbosity_level=3)
      else:
        self._log("No data acquired from Sensibo", verbosity_level=0, color='r')

    except Exception as e:
      self._log(f"Error during data acquisition: {str(e)}", verbosity_level=0, color='r')
      raise

    self._log("Data step completed", verbosity_level=3)
    return
