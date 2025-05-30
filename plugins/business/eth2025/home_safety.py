from naeural_core.business.base.cv_plugin_executor import CVPluginExecutor as BasePlugin


_CONFIG = {
  **BasePlugin.CONFIG,
  'PROCESS_DELAY': 0,

  'ALERT_DATA_COUNT'              : 2,
  "ALERT_RAISE_VALUE"             : 0.75,
  "ALERT_LOWER_VALUE"             : 0.25,
  'ALERT_RAISE_CONFIRMATION_TIME' : 15,
  'ALERT_LOWER_CONFIRMATION_TIME' : 15,
  "ALERT_MODE"                    : 'mean',

  'LIVE_FEED': True,
  "AI_ENGINE": "lowres_general_detector",
  "COLOR_TAGGING": True,
  "DEBUG_DETECTIONS": False,
  "OBJECT_TYPE": ["person"],
  "CONFIDENCE_THRESHOLD": 0.3,
  # "POINTS": [[], [], [], []], # RULE: the last point === the first point || Top Left & Bottom Right
  "DEBUGGING_MODE": False,

  "AIHO_URL": "https://api.aiho.ai/new_home_security_event",

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES']
  },
}


class HomeSafetyPlugin(BasePlugin):
  """
  Demo plugin for checking the video object detection.
  """

  def _draw_witness_image(self, img, inferences, **kwargs):
    """
    Draw the inferences on the image.
    """
    for inference in inferences:
      box_tlbr = inference[self.consts.TLBR_POS]
      lbl = inference[self.consts.TYPE]
      lbl += f" | {inference.get(self.consts.COLOR_TAG)}"

      img = self._painter.draw_detection_box(
        image=img,
        top=box_tlbr[0],
        left=box_tlbr[1],
        bottom=box_tlbr[2],
        right=box_tlbr[3],
        label=lbl,
        prc=inference[self.consts.PROB_PRC],
        color=self.consts.DARK_GREEN
      )
    return img

  def process(self):
    instance_inferences = self.dataapi_image_instance_inferences()

    # Check for objects with tracking time greater than alert threshold
    self.P(f"Nr of people in image {len(instance_inferences)}")
    if len(instance_inferences) > 0:
      self.alerter_add_observation(1)
    else:
      self.alerter_add_observation(0)

    is_new_raise = self.alerter_is_new_raise()
    is_new_lower = self.alerter_is_new_lower()

    if is_new_raise or is_new_lower:
      is_alert = self.alerter_is_alert()

      np_witness = self.get_witness_image(
        draw_witness_image_kwargs={
          "inferences": instance_inferences,
        }
      )
      base64_img = self.img_to_base64(np_witness)
      request = {
        "propertyId": 1,
        "base64img": base64_img,
        "isAlert": is_alert,
      }
      self.requests.post(url=self.cfg_aiho_url, json=request)

