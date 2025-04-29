import abc
import torch as th
from plugins.serving.pipelines.base_exe_eng import BaseExeEngTrainingPipeline
from plugins.serving.pipelines.architectures.marketplace import get_model_architectures_list, get_factory_config


class CustomTrainingPipeline(BaseExeEngTrainingPipeline, abc.ABC):
  score_key = 'dev_acc'
  score_mode = 'max'

  def __init__(self, **kwargs):
    super(CustomTrainingPipeline, self).__init__(**kwargs)
    model_arch = self.config.get('MODEL_ARCHITECTURE')
    if model_arch is None:
      model_catalog = get_model_architectures_list()
      raise ValueError(f'MODEL_ARCHITECTURE not provided! Please use on of the following: {model_catalog}')
    # endif model_arch not provided
    classes = self.config.get('CLASSES')
    if classes is None or not isinstance(classes, list):
      raise ValueError(
        f'CLASSES not provided or incorrect format! Please provide list of classes instead of {classes}'
      )
    # endif classes not provided
    classes = [cls.strip() if isinstance(cls, str) else cls for cls in classes]
    grid_search = self.config.get('GRID_SEARCH', {})
    factory_config = get_factory_config(model_arch)['GRID_SEARCH']
    self.config['GRID_SEARCH'] = {**factory_config, **grid_search}
    self.config['GRID_SEARCH']['GRID'] = {**factory_config['GRID'], **grid_search.get('GRID', {})}
    self.config['GRID_SEARCH']['GRID']['classes'] = [classes]
    self.config['GRID_SEARCH']['GRID']['model_type'] = [model_arch]
    self.config['GRID_SEARCH']['GRID']['output_size'] = [len(classes)]
    self.config['GRID_SEARCH']['DATA_PARAMS'].append('classes')
    self.config['GRID_SEARCH']['CALLBACKS_PARAMS'] = self.config['GRID_SEARCH'].get('CALLBACKS_PARAMS', [])
    self.config['GRID_SEARCH']['CALLBACKS_PARAMS'].append('classes')
    # if no model params are specified there is no need to add model_type to the list
    # since it will be automatically populated later.
    if len(self.config['GRID_SEARCH'].get('MODEL_PARAMS', [])) > 0:
      self.config['GRID_SEARCH']['MODEL_PARAMS'].append('model_type')
    self._metadata['CLASSES'] = {val: idx for (idx, val) in enumerate(classes)}
    return

  def model_loss(self, **dct_grid_option):
    return th.nn.CrossEntropyLoss()


