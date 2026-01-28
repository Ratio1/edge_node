BASE_AGENT_MIXIN_CONFIG = {
  'OBJECT_TYPE': [],
  "ALLOW_EMPTY_INPUTS": False,  # if this is set to true the on-idle will be triggered continuously the process
  "DEBUG_LOGGING_ENABLED": True,

  "VALIDATION_RULES": {
  },
}


class _BaseAgentMixin(object):
  def filter_valid_inference(self, inference):
    return isinstance(inference, dict) and inference.get("IS_VALID", True)

  def filter_valid_inferences(self, inferences, return_idxs=False):
    res = []
    idxs = []
    for idx, inf in enumerate(inferences):
      if self.filter_valid_inference(inference=inf):
        res.append(inf)
        idxs.append(idx)
    # endfor inferences
    return res if not return_idxs else (res, idxs)

  def inference_to_response(self, inference, model_name, input_data):
    return inference

  def handle_single_inference(self, inference: dict, model_name: str = None, input_data: dict = None):
    """
    Method for handling a single inference, along with the input data that generated it.

    Parameters
    ----------
    inference : dict
      The inference dictionary
    model_name: str, optional
      The name of the model
    input_data: dict, optional
      The input data
    """
    request_id = inference.get('REQUEST_ID', None)
    self.Pd(f"Processing inference for request ID: {request_id}, model: {model_name}")
    request_result = self.inference_to_response(
      inference=inference,
      model_name=model_name,
      input_data=input_data
    )
    current_payload_kwargs = {
      'result': request_result,
      'request_id': request_id,
    }
    self.add_payload_by_fields(**current_payload_kwargs)
    return

  def handle_inferences(self, inferences, data=None):
    """
    Method for handling list of inferences, along with the input data that generated them.
    This will filter the valid inference and handle them using handle_single_inference()

    Parameters
    ----------
    inferences : list
      Array of inference dictionaries
    data : dict or list, optional
      List of inputs or dictionary of {int_idx: input_data}
    """
    if not isinstance(inferences, list):
      return
    if len(inferences) > 0 and not isinstance(inferences[0], dict):
      return
    model_name = inferences[0].get('MODEL_NAME', None) if len(inferences) > 0 else None
    cnt_initial_inferences = len(inferences)
    inferences, valid_idxs = self.filter_valid_inferences(inferences, return_idxs=True)
    self.Pd(f"Filtered {cnt_initial_inferences} inferences to {len(inferences)} valid inferences.")
    filtered_data = None
    if data is not None:
      filtered_data = [
        data[idx] for idx in valid_idxs
      ]
      if len(filtered_data) > 0:
        self.Pd(f"Received requests: {self.json_dumps(self.shorten_str(filtered_data), indent=2)}")
    # endif data is not None

    for idx, inf in enumerate(inferences):
      current_input = filtered_data[idx] if filtered_data else {}
      self.handle_single_inference(
        inference=inf,
        model_name=model_name,
        input_data=current_input,
      )
    # endfor inferences
    return

