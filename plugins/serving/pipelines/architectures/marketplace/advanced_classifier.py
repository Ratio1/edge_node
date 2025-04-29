import torch as th

from naeural_core.local_libraries.nn.th.utils import auto_normalize
from naeural_core.local_libraries.nn.th.layers import InputPlaceholder
from naeural_core.local_libraries.nn.th.conv_templates import CNNColumn, ReadoutFC, ReadoutConv


_CONFIG = {
  'GRID_SEARCH' : {
    'GRID' : {
      'nr_filters_per_block': [
        [(32, 5, 5), (64, 3, 3)],
        [(16, 3, 3), (32, 3, 3), (64, 3, 3)],
        [(16, 3, 3)]
      ],
      'input_size': [
        (320, 256),
        (160, 128),
        # (384, 576)
      ],
      'activation': [
        'relu',
        # 'selu'
      ],
      'output_size': [
        2
      ],
      'nconv': [
        2,
        # 3
      ],
      'dropout': [
        # 0,
        0.5,
        # 0.7
      ],
      'embedding_type': [
        # 'flatten',
        'gmp/gap'
      ],
      'scale_min_max': [
        (0, 1),
        # (-1, 1)
      ],
      'skipping': [
        # 'residual',
        'skip',
        'both'
      ],
      'resize_conv': [
        False,
        # True
      ],
      'lst_conv_sizes': [
        [32],
        [64, 16]
      ],
      'use_conv_dropout': [
        # False,
        True
      ],
      'level_analysis': [2],
      'max_patience': [8],
      'max_fails': [16]
    },

    'DATA_PARAMS' : ['input_size'],
    'CALLBACKS_PARAMS' : ['level_analysis'],
    'TRAINER_PARAMS': ['max_patience', 'max_fails'],
    "MODEL_PARAMS": [
      'nr_filters_per_block', 'input_size', 'activation', 'output_size', 'nconv', 'dropout', 'embedding_type',
      'scale_min_max', 'skipping', 'resize_conv', 'lst_conv_sizes', 'use_conv_dropout'
    ],
    'EXCEPTIONS': [
      {
        'skipping': [
          'skip',
          'residual'
        ],
        'resize_conv': [
          True  # unimportant if False or True
        ]
      },
      {
        'input_size': [(160, 128)],
        'lst_conv_sizes': [[64, 16]]
      }
    ],
    'FIXED': [
    ]
  }
}


class AdvancedClassifierModelFactory(th.nn.Module):
  def __init__(
      self, nr_filters_per_block, input_size=(384, 512), activation='relu6',
      output_size=2, nconv=1, dropout=0, embedding_type='flatten',
      scale_min_max=(0, 1), skipping='residual', resize_conv=False,
      lst_conv_sizes=[64], use_conv_dropout=False, **kwargs
  ):
    super(AdvancedClassifierModelFactory, self).__init__()

    self.blocks = th.nn.ModuleList()
    self._scale_min, self._scale_max = scale_min_max
    input_dim = 3, input_size[0], input_size[1]
    th_inp = InputPlaceholder(input_dim=input_dim)
    self.blocks.append(th_inp)
    if isinstance(dropout, tuple):
      dropout, dropout_type = dropout
    else:
      dropout_type = 'classic'

    self.backbone = CNNColumn(
      lst_filters=nr_filters_per_block,
      layer_norm=False,
      input_dim=input_dim,
      nconv=nconv,
      act=activation,
      dropout=dropout,
      dropout_type=dropout_type,
      skipping=skipping,
      resize_conv=resize_conv
    )
    input_dim = self.backbone.output_dim

    self.pre_readout = ReadoutConv(
      lst_convs=lst_conv_sizes,
      in_channels=input_dim[0],
      input_dim=input_dim,
      act=activation,
      dropout=dropout if use_conv_dropout else 0,
      embedding_type=embedding_type
    )

    self.readout = ReadoutFC(
      lst_fc_sizes=[output_size],
      in_features=self.pre_readout.output_size,
      dropout=dropout,
      act=activation
    )

    self.softmax = th.nn.Softmax(dim=1)
    return

  def post_backbone(self, th_x):
    th_x = self.pre_readout(th_x)
    th_x = self.readout(th_x)
    return th_x

  def forward(self, th_x):
    th_x = auto_normalize(th_x, scale_min=self._scale_min, scale_max=self._scale_max)
    th_x = th_x.to(next(self.parameters()).dtype)
    th_x = self.backbone(th_x)
    th_x = self.post_backbone(th_x)
    return th_x

  @th.jit.export
  def predict(self, th_x):
    th_x = self(th_x)
    th_x = self.softmax(th_x)
    return th_x
