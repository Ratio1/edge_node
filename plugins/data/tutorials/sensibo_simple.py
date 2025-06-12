"""
{
    "LIVE_FEED": true,
    "NAME": "sensibo_simple_direct",
    "PLUGINS": [

        {
            "INSTANCES": [
                {
                    "INSTANCE_ID": "DEFAULT",
                    "PROCESS_DELAY" : 0,
                    "PRC_GOLD": 0.98
                }
            ],
            "SIGNATURE": "BASIC_SENSIBO_01"
        }

    ],
    
    "RECONNECTABLE" : true,
    "CAP_RESOLUTION" : 0.5,
    "TYPE": "SensiboSimple",
    
    "SENSIBO_DEVICE_NAME" : "Alex's device",
    "SENSIBO_API_KEY" : "0B073b470DeXHoqmXmdeBpVzBbHcLh",
    
    "URL" : ""

}

Steps to replicate/create a new basic REST-based data capture plugin:

1. Create/clone from this template
2. Connect to the REST API and get the data
3. Prepare a basic business plugin that will consume the data and maybe applies some basic business logic
4. Launch the pipeline with the DCT `Type` of the new plugin and the simple/basic business plugin
5. Consume from SDK the payloads generated from the basic plugin
6. Create a serving process plugin if needed that will consume the DCT and generate inferences/predictions to the business plugin
7. Now you can modify the business plugin to apply more complex logic that will also use the inferences/predictions from the serving process plugin


"""

from naeural_core.data.base import DataCaptureThread

_CONFIG = {
  
  **DataCaptureThread.CONFIG,
  
  "SENSIBO_API_KEY"       : "0B073b470DeXHoqmXmdeBpVzBbHcLh",
  "SENSIBO_DEVICE_NAME"   : "Alex's device",
  
  
  'VALIDATION_RULES' : {
    **DataCaptureThread.CONFIG['VALIDATION_RULES'],
  },
}

_SERVER = 'https://home.sensibo.com/api/v2'

class SensiboSimpleDataCapture(DataCaptureThread):

  CONFIG = _CONFIG

  
  def on_init(self):
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
        res['read_time'] = dt
        res['read_time_str']  = str_dt
        res['read_delay'] = delay        
    return results

   
  def connect(self): # MANDATORY
    if self.has_connection:
      return
    self.has_connection = True
    self._device_name = self.cfg_sensibo_device_name
    self._api_key = self.cfg_sensibo_api_key
    devices = self.__list_devices()
    self._uid = devices[self._device_name]
    return  
  
  
  def __get_data_from_sensibo(self):
    res = self.__get_measurement(self._uid)
    return res[-1]  
    
    
  def data_step(self): # MANDATORY    
    _obs = self.__get_data_from_sensibo()    

    self._add_inputs(
      [
        self._new_input(img=None, struct_data=_obs, metadata=self._metadata.__dict__.copy()),
      ]
    )
    return 
      
  