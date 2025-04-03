from naeural_core.business.base import BasePluginExecutor as BasePlugin

__VER__ = '0.0.0.1'

_CONFIG = {
    **BasePlugin.CONFIG,

    'PROCESS_DELAY': 60,  # Process every 60 seconds
    'ALLOW_EMPTY_INPUTS': True,  # Allow running without input data
    'API_URL': 'https://home.sensibo.com/api/v2',
    'API_KEY': None,  # Sensibo API key should be configured in instance config
    'POD_UID': None,  # If not provided, will automatically fetch the first available pod UID from the account

    'VALIDATION_RULES': {
        **BasePlugin.CONFIG['VALIDATION_RULES'],
    },
}

class TemperatureMonitoringPlugin(BasePlugin):
    """
    Plugin for monitoring temperature and humidity using Sensibo devices.
    """
    CONFIG = _CONFIG
    SIGNATURE = 'TEMPERATURE_MONITORING'  # This is the signature used in pipeline config

    def on_init(self):
        """Initialize the plugin"""
        self.P(f"Initializing TemperatureMonitoringPlugin v{__VER__}")
        self.__last_fetch_time = 0
        self.__pod_uid = None
        self._fetch_pod_uid()  # Fetch pod UID on initialization
        return

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
                
                self.P(f"Fetched measurements - Temperature: {temperature}°C, Humidity: {humidity}%")
                return temperature, humidity
            else:
                self.P("No measurement data available", color='y')
                return None, None
                
        except Exception as e:
            self.P(f"Error fetching measurements: {str(e)}", color='r')
            return None, None

    def process(self):
        """Main processing method called every PROCESS_DELAY seconds"""
        current_time = self.time()

        # Only fetch if enough time has passed
        if current_time - self.__last_fetch_time >= self.cfg_process_delay:
            temperature, humidity = self._fetch_measurements()
            self.__last_fetch_time = current_time
            
            if temperature is not None and humidity is not None:
                payload = self._create_payload(
                    temperature=temperature,
                    humidity=humidity,
                    pod_uid=self.__pod_uid,
                    timestamp=self.time_to_str(),
                )
                return payload
        
        return None
