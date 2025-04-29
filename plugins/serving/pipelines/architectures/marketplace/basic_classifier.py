from naeural_core.local_libraries.nn.th.layers import InputPlaceholder
from naeural_core.local_libraries.nn.th.utils import get_activation
import torch as th
import math

_CONFIG = {
  'GRID_SEARCH': {
    'GRID': {
      'input_size': [(320, 256)],
      'hidden1': [
        100,
        # 200,
        128
      ],
      'hidden2': [50, 64],
      'output_size': [2],
      'activation': ['relu'],
      'lr': [1e-3, 5e-4]
    },

    'DATA_PARAMS': ['input_size'],
    'TRAINER_PARAMS': ['lr'],
    'MODEL_PARAMS': [
      'input_size', 'hidden1', 'hidden2', 'activation', 'output_size'
    ],
    'EXCEPTIONS': [
      {'hidden1': [100, 200], 'hidden2': [64]},
      {'hidden1': [128], 'hidden2': [50]}
    ]
  }
}


class BasicClassifierModelFactory(th.nn.Module):
  """
  Model factory class.
  The name of the class should be <SIGNATURE>ModelFactory (where <SIGNATURE> is the name of the file)
  """
  def __init__(
      self, input_size=(320, 256), hidden1=128, hidden2=32,
      activation='relu', output_size=2, **kwargs
  ):
    super(BasicClassifierModelFactory, self).__init__()
    self._input_size = input_size
    self.blocks = th.nn.ModuleList()
    input_dim = 3, *input_size
    th_inp = InputPlaceholder(input_dim=input_dim)
    self.blocks.append(th_inp)
    flatten_layer = th.nn.Flatten()
    self.blocks.append(flatten_layer)
    in_size = math.prod(list(input_dim))
    for out_size in [hidden1, hidden2]:
      linear_layer = th.nn.Linear(in_size, out_size)
      self.blocks.append(linear_layer)
      activation_layer = get_activation(activation)
      self.blocks.append(activation_layer)
      in_size = out_size
    # endfor hidden layers
    final = th.nn.Linear(hidden2, output_size)
    self.blocks.append(final)
    self.softmax = th.nn.Softmax(dim=1)
    return

  def forward(self, th_x):
    for block in self.blocks:
      th_x = block(th_x)
    return th_x

  @th.jit.export
  def predict(self, th_x):
    th_x = self.forward(th_x)
    th_x = self.softmax(th_x)
    return th_x
