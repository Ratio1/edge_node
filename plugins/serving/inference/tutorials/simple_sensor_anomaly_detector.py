"""

TODO:

1. Review and fix Sensibo DCT
2. Configure outlier proba
3. fit-predict at each step
4. Add plugin with alert set to 2-3 successive positives

"""

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess
from naeural_core.utils.basic_anomaly_model import BasicAnomalyModel

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,
  
  "PICKED_INPUT" : "STRUCT_DATA",
  
  "RUNS_ON_EMPTY_INPUT" : False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
      
  },

}

class SimpleSensorAnomalyDetector(BaseServingProcess):

  
  def on_init(self):
    self._counter = 0
    # check some params that can be re-configured from biz plugins or (lower priority) 
    # serving env in config_startup.txt
    
    self.model = BasicAnomalyModel()
    return
  
    
  def pre_process(self, inputs): 
    debug = False
    lst_inputs = inputs.get('DATA', [])
    serving_params = inputs.get('SERVING_PARAMS', [])
    if len(serving_params) > 0:
      if isinstance(serving_params[0], dict):
        debug = serving_params[0].get('SHOW_EXTRA_DEBUG', False)
      if debug:
        self.P("Inference step info:\n - Detected 'SERVING_PARAMS': {}\n - Inputs: {}".format(
          self.json_dumps(serving_params, indent=4), 
          self.json_dumps(inputs, indent=4)
        ))

    preprocessed = []
    for i, inp in enumerate(lst_inputs):
      params = serving_params[i].get('TEST_INFERENCE_PARAM', None) if i < len(serving_params) else None
      preprocessed.append([
          inp.get('OBS') if isinstance(inp, dict) else 0,
          params,
        ]
      )
    return preprocessed
  

  def predict(self, inputs):
    self._counter += 1
    dummy_result = []
    for inp in inputs:
      # for each stream input    
      input_data = inp[0]
      input_params = inp[1]  
      model = lambda x: int(round(x)) % 2 == 0
      dummy_result.append(
        [model(input_data), self._counter, input_data, input_params]
      )
    dummy_result = self.np.array(dummy_result)
    return dummy_result


  def post_process(self, preds):
    result = [{'pred': x[0], 'cnt': x[1], 'inp':x[2], 'cfg':x[3]} for x in preds]
    return result
  
  