"""
{
    "CAP_RESOLUTION": 0.5,
    "LIVE_FEED": true,
    "NAME": "test",
    "PLUGINS": [

        {
            "INSTANCES": [
                {
                    "INSTANCE_ID": "DEFAULT"
                }
            ],
            "SIGNATURE": "A_SIMPLE_PLUGIN"
        }
        
    ],
    "TYPE": "ExampleDatastream", 
    "URL": ""
} 

"""
from naeural_core.data.base import BaseStructuredDataCapture

_CONFIG = {
  **BaseStructuredDataCapture.CONFIG,
  'VALIDATION_RULES' : {
    **BaseStructuredDataCapture.CONFIG['VALIDATION_RULES'],
  },
}

class ExampleDatastreamDataCapture(BaseStructuredDataCapture):
  
  def connect(self):
    return True
  
  # custom stuff      
  def get_data(self):
    val = round(self.np.abs(self.np.random.normal()), 2)
    data_observation = {'OBS' : val}
    return data_observation
  