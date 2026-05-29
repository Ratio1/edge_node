from naeural_core.data.base import DataCaptureThread


_CONFIG = {
  **DataCaptureThread.CONFIG,
  "CAP_RESOLUTION": 1,
  "VALIDATION_RULES": {
    **DataCaptureThread.CONFIG["VALIDATION_RULES"],
  },
}


class DeeployTestbedStreamDataCapture(DataCaptureThread):
  CONFIG = _CONFIG

  def on_init(self):
    self._metadata.update(counter=0)
    return

  def connect(self):
    return True

  def data_step(self):
    counter = self._metadata.counter
    self._metadata.counter = counter + 1
    self._add_struct_data_input(obs={"counter": counter})
    return
