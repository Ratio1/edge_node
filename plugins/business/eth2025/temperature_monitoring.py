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
        self.__pod_uid = None
        # Store measurement history
        self.__measurement_history = []
        # Maximum number of history entries to keep
        self.__max_history_size = 1000
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
                
                self.P(f"Fetched measurements - Temperature: {temperature}°C, Humidity: {humidity}%, Time: {measurement_time}")
                return temperature, humidity
            else:
                self.P("No measurement data available", color='y')
                return None, None
                
        except Exception as e:
            self.P(f"Error fetching measurements: {str(e)}", color='r')
            return None, None

    def process(self):
        """Main processing method called every PROCESS_DELAY seconds"""

        self.P(f"Fetching measurements")
        # Only fetch if enough time has passed
        temperature, humidity = self._fetch_measurements()
        
        if temperature is not None and humidity is not None:
            payload = self._create_payload(
                temperature=temperature,
                humidity=humidity,
                pod_uid=self.__pod_uid,
                timestamp=self.time_to_str(),
            )
            return payload
        
        return None
