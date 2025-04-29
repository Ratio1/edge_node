from naeural_core.serving.default_inference.th_yf8s import ThYf8s as BaseServingProcess

_CONFIG = {
  
  **BaseServingProcess.CONFIG,
  'VALIDATION_RULES' : {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

  "COVERED_SERVERS": ['th_yf8s'],
  "SECOND_STAGE_MODEL_NAME" : None,

  "CUSTOM_DOWNLOADABLE_MODEL" : True,
  "CUSTOM_DOWNLOADABLE_MODEL_URL" : None,
}

__VER__ = '0.1.0.0'


class ThYoloSecondStage(BaseServingProcess):
  """
  This particular model requires upstream configuration given from the plugin
  and cannot be loaded as is unless is defined in a child class with CUSTOM_DOWNLOADABLE_MODEL = False
  """

  CONFIG = _CONFIG
  
  def __init__(self, **kwargs):
    super(ThYoloSecondStage, self).__init__(**kwargs)
    self.second_stage_model = None
    self._has_second_stage_classifier = True
    return

  def on_init(self):
    super(ThYoloSecondStage, self).on_init()
    preprocess_tuples = [
      (self.str_to_preprocess(x[0]), x[1]) for x in self.get_second_stage_preprocess_definitions
    ]
    self._lst_preprocess_transforms = [
      x[0](**x[1])
      for x in preprocess_tuples if x[0] is not None
    ]
    self._transform = self.tv.transforms.Compose(self._lst_preprocess_transforms)
    return

  @property
  def get_second_stage_class_names(self):
    return self.config_model['SECOND_STAGE_CLASS_NAMES']

  @property
  def get_second_stage_preprocess_definitions(self):
    return self.config_model.get('SECOND_STAGE_PREPROCESS_DEFINITIONS', [])

  @property
  def get_second_stage_input_size(self):
    return self.config_model['SECOND_STAGE_INPUT_SIZE']

  @property
  def get_second_stage_target_class(self):
    target_classes = self.config_model.get('SECOND_STAGE_TARGET_CLASS', "person")
    if not isinstance(target_classes, list):
      return [target_classes]
    return target_classes

  def _second_stage_model_load(self):
    # this method defines default behavior for second stage model load
    trace_url = self.cfg_second_stage_model_trace_url
    if trace_url is None:
      return

    trace_fn = trace_url.split('/')[-1].split('?')[0]
    config = {
      'ths': (trace_fn, trace_url)
    }
    self.second_stage_model, cfg, self.second_stage_fn = self.prepare_model(
      backend_model_map=config,
      forced_backend='ths',
      return_config=True,
      batch_size=self.cfg_max_batch_second_stage
    )
    self.graph_config[self.second_stage_fn] = cfg
    self._second_stage_model_warmup()
    return

  def model_call(self, model, th_inputs):
    # this method defines default behavior for model call
    return model.predict(th_inputs) if hasattr(model, 'predict') else model(th_inputs)

  def _second_stage_model_warmup(self):
    # this method defines default behavior for second stage model warmup

    if self.second_stage_model is None:
      return

    self.model_warmup_helper(
      model=self.second_stage_model,
      input_shape=(3, *self.get_second_stage_input_size),
      max_batch_size=self.cfg_max_batch_second_stage
    )
    return

  def _pre_process_images(self, images, **kwargs):
    return super(ThYoloSecondStage, self)._pre_process_images(
      images=images,
      return_original=True,
      half_original=self.cfg_fp16,
      **kwargs
    )

  def _post_process(self, preds):
    ### TODO: Match each image / bounding box to each second stage prediction
    yolo_preds, second_preds = preds
    lst_yolo_results = super(ThYoloSecondStage, self)._post_process(preds)
    if second_preds is not None:
      for i, yolo_result in enumerate(lst_yolo_results):
        for j, crop_results in enumerate(yolo_result):
          if crop_results['TYPE'] in self.get_second_stage_target_class:
            crop_results[self.cfg_model_instance_id] = {
              self.ct.TYPE: self.get_second_stage_class_names[second_preds[i][j][1]],
              self.ct.PROB_PRC: second_preds[i][j][0]
            }
          #endif
        #endfor
      #endfor
    #endif
    return lst_yolo_results

  def is_prob_tensor(self, t, dim: int = 1,
                   atol: float = 1e-4, rtol: float = 1e-3) -> bool:
    """
    Heuristic: tensor is in [0,1] and sums to 1 on `dim`.
    Works for softmaxed class scores.
    """
    if t.dtype.is_floating_point is False:
      return False
    if not self.th.all((t >= 0) & (t <= 1)):
      return False
    # sum-to-1 check (allows small numerical drift)
    ones = self.th.ones(t.size(dim), device=t.device)
    return self.th.allclose(t.sum(dim=dim), ones, atol=atol, rtol=rtol)

  def maybe_softmax(self, th_x):
    """
    This will be removed in the future.
    Applies softmax to the input tensor if it is not already a probability distribution.
    Parameters
    ----------
    th_x : torch.Tensor
        The input tensor to be processed.

    Returns
    -------

    """
    if self.is_prob_tensor(th_x):
      return th_x
    return self.th.nn.functional.softmax(th_x, dim=1)


  def _second_stage_classifier(self, pred_nms, th_inputs):
    crop_imgs = []
    identity = []

    masks = []
    self._start_timer("crop")

    apply_custom_transforms = len(self._transform.transforms) > 0
    idxs = [self.class_names.index(_class_name) for _class_name in self.get_second_stage_target_class]

    if apply_custom_transforms:
      images_to_crop = self.resized_input_images
    else:
      images_to_crop = th_inputs

    for i, pred in enumerate(pred_nms):
      pred_mask = self.th.any(self.th.stack([self.th.eq(pred[:, 5], idx) for idx in idxs], dim=0), dim=0)
      masks.append(pred_mask.tolist())
      for i_crop in range(pred.shape[0]):
        crop_imgs.append(
          self.tv.transforms.functional.crop(
            images_to_crop[i],
            left=max(pred[i_crop, 0].int(), 0),
            top=max(pred[i_crop, 1].int(), 0),
            width=pred[i_crop, 2].int() - pred[i_crop, 0].int() + 1,
            height=pred[i_crop, 3].int() - pred[i_crop, 1].int() + 1,
          )
        )
      identity = identity + [i] * pred.shape[0]
    #endfor
    self._stop_timer("crop")

    if apply_custom_transforms:
      self._start_timer("full_preprocess")
      batch = self._transform(crop_imgs)
      self._stop_timer("full_preprocess")
    else:
      self._start_timer("resize")
      batch, _ = self.th_resize_with_pad(
        crop_imgs,
        w=self.get_second_stage_input_size[0],
        h=self.get_second_stage_input_size[1],
        normalize=False
      )
      self._stop_timer("resize")
    #endif

    self._start_timer("second_stage_fw")
    out = self.model_call(model=self.second_stage_model, th_inputs=batch)
    out = self.maybe_softmax(out)
    self.P(f"Second stage model output: {out}")
    out = self.th.max(out, dim=1)#.tolist()
    results = []
    self._stop_timer("second_stage_fw")

    k = 0
    for i in range(len(pred_nms)):
      results.append(
        [(self.np.round(out[0].tolist()[k+j], 2), self.np.round(out[1].tolist()[k+j], 2))
         if masks[i][j] else None
         for j in range(len(masks[i]))]
      )
      k += len(masks[i])
    return results
