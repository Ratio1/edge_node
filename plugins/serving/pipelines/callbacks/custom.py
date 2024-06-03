
from typing import List
import numpy as np
from core.local_libraries.nn.th.training.callbacks.softmax_classification import SoftmaxClassificationTrainingCallbacks


class CustomTrainingCallbacks(SoftmaxClassificationTrainingCallbacks):
  def __init__(self, **kwargs):
    super(CustomTrainingCallbacks, self).__init__(**kwargs)
    return

  def _lst_augmentations(self, **kwargs) -> List:
    return []

  def _get_y(self, lst_y: List[np.ndarray]):
    y = np.vstack(lst_y)
    y = np.argmax(y, axis=1)
    return y

  def _get_y_hat(self, lst_y_hat: List[np.ndarray]):
    y_hat = np.vstack(lst_y_hat)
    y_hat = np.argmax(y_hat, axis=1)
    return y_hat
