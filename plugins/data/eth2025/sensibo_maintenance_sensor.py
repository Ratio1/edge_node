from naeural_core.data.base import DataCaptureThread

_CONFIG = {

  **DataCaptureThread.CONFIG,

  "PROCESS_DELAY": 40,

  "SENSIBO_API_KEY": "8F8dpe6w3bYbE2cfucSwxRJd6dczL0",
  "SENSIBO_DEVICE_NAME": "R1 Sensibo",
  "SENSIBO_POD_UID": "Zxcm5pQX",  # If provided, will use this instead of looking up by device name

  'VALIDATION_RULES': {
    **DataCaptureThread.CONFIG['VALIDATION_RULES'],
  },
}

_SERVER = 'https://home.sensibo.com/api/v2'


class SensiboMaintenanceSensorDataCapture(DataCaptureThread):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(SensiboMaintenanceSensorDataCapture, self).__init__(**kwargs)
    return

  def startup(self):
    super().startup()
    return

  def _init(self):
    self._maybe_reconnect()
    return

  def __get_data(self, path, **params):
    params['apiKey'] = self._api_key
    response = self.requests.get(_SERVER + path, params=params)
    response.raise_for_status()
    return response.json()

  def __list_devices(self):
    result = self.__get_data('/users/me/pods', fields='id,room')
    self.P("Sensibo device info:\n{}".format(self.json.dumps(result, indent=4)))
    return {x['room']['name']: x['id'] for x in result['result']}

  def __get_measurement(self, pod_uid=None):
    if pod_uid is None:
      pod_uid = self._uid
    results = self.__get_data('/pods/{}/measurements'.format(pod_uid))
    results = results['result']
    for res in results:
      if 'time' in res:
        str_dt = res['time']['time']
        dt = self.datetime.strptime(str_dt, '%Y-%m-%dT%H:%M:%S.%fZ')
        delay = res['time']['secondsAgo']
        res['read_time'] = dt.isoformat()
        res['read_time_str'] = str_dt
        res['read_delay'] = delay
    self.P("Measurement data:\n{}".format(self.json.dumps(results, indent=4)))
    return results

  def _maybe_reconnect(self):  # MANDATORY
    if self.has_connection:
      return
    self.has_connection = True
    self._api_key = self.cfg_sensibo_api_key
    
    # Use the pod UID directly if provided
    if hasattr(self, 'cfg_sensibo_pod_uid') and self.cfg_sensibo_pod_uid:
      self._uid = self.cfg_sensibo_pod_uid
      return
      
    # Otherwise look up the device by name
    self._device_name = self.cfg_sensibo_device_name
    devices = self.__list_devices()
    self._uid = devices[self._device_name]
    return

  def __get_data_from_sensibo(self):
    res = self.__get_measurement(self._uid)
    return res[-1]

  def _run_data_aquisition_step(self):  # MANDATORY
    _obs = self.__get_data_from_sensibo()

    self._add_inputs(
      [
        self._new_input(img=None, struct_data=_obs, metadata=self._metadata.__dict__.copy()),
      ]
    )
    return

