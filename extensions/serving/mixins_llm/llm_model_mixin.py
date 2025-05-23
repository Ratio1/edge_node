import torch as th

from transformers import AutoTokenizer as LlmTokenizer
from transformers import AutoModelForCausalLM as LlmForCausalLM
from transformers import BitsAndBytesConfig


class LlmModelMixin(object):
  def __init__(self, *args, **kwargs):
    super(LlmModelMixin, self).__init__(*args, **kwargs)
    return


  def _get_placement_summary(self, indent=4):
    """Logs the device map from the model.

    Parameters
    ----------
      None.
    """

    def str_device(dev):
      str_place = dev
      str_place = str_place if str_place in ['cpu', 'disk'] else 'cuda:' + str_place
      return str_place

    str_indent = " " * indent
    result = ""
    if hasattr(self.model, 'hf_device_map'):
      self.placement = self.model.hf_device_map
      device = None
      prev_layer = None
      n = 0
      if len(self.placement) == 1:
        _layer = list(self.placement.keys())[0]
        result = str(self.placement[_layer])
      else:
        for layer in self.placement:
          if device != self.placement[layer]:
            if device is not None:
              result = result + prev_layer + ']({} layers): {}\n'.format(n, str_device(self.placement[layer]))
              n = 0
            device = self.placement[layer]
            result = result + str_indent + '[{} to '.format(layer)
            prev_layer = layer
          n += 1
        result = result + layer + ']({} layers): {}\n'.format(n, str_device(self.placement[layer]))
    return result


  def _get_model_load_config(self):
    return self.log.get_model_load_config(
      model_name=self.cfg_model_name,
      token=self.hf_token,
      has_gpu=self.has_gpu,
      weights_size=self.cfg_model_weights_size,
      device_map=self._get_device_map(),
      cache_dir=self.cache_dir,
      use_flash_attention=self.cfg_use_flash_attention
    )

  def load_tokenizer(self, model_id, cache_dir, token):
    """
    Load the tokenizer from the model and set up padding.
    Parameters
    ----------
    model_id : str
        the model identifier
    cache_dir : str
        the cache directory
    token : str
        the token to use for authentication
    Returns
    -------

    """
    self.tokenizer = LlmTokenizer.from_pretrained(
      model_id,
      cache_dir=cache_dir,
      use_auth_token=token,
    )

    # Fix for missing system roles in transformers.
    self._set_tokenizer_chat_template()
    return

  def _load_tokenizer(self):
    """Loads the tokenizer from the model and sets up padding.
    """
    # Load the tokenizer and output to log.
    cache_dir = self.cache_dir
    token = self.hf_token
    model_id = self.cfg_model_name
    self.P("Loading tokenizer for {} in '{}'...".format(model_id, cache_dir))
    self.load_tokenizer(model_id, cache_dir, token)

    # Use the unknown token as the padding token. It seems that at least
    # when quantized llama2 will look at the embeddings of padding tokens
    # so we should use something that is as ignorable as possible
    # embedding-wise.
    self.tokenizer.padding_side = 'right'
    if self.tokenizer.pad_token is None:
      self.tokenizer.pad_token = self.tokenizer.unk_token
    if self.tokenizer.pad_token is None:
      self.tokenizer.pad_token = self.tokenizer.eos_token

    self.padding_id = self.tokenizer.pad_token_id
    if self.padding_id is None:
      self.padding_id = self.tokenizer.unk_token_id
    if self.padding_id is None:
      self.padding_id = self.tokenizer.eos_token_id
    self.P(
      'Settting padding token to {} and padding token id to {}'
      .format(
        self.tokenizer.pad_token, self.tokenizer.pad_token_id
      )
    )

    self.P("  Loaded `{}` tokenizer".format(self.tokenizer.__class__.__name__))
    return

  def load_pretrained_model(self, model_id, **kwargs):
    """
    Load the pretrained model with the given model id and additional parameters.
    Parameters
    ----------
    model_id  : str - the model identifier
    kwargs : dict - additional parameters

    Returns
    -------
    model : _BaseAutoModelClass - the loaded model
    """
    return LlmForCausalLM.from_pretrained(model_id, **kwargs)

  def _load_model(self):
    """
    Load the model from the given configured model name and set up padding.
    Will first set up the model loading configuration and then load the model

    """
    model_id = self.cfg_model_name
    model_params, quantization_params = self._get_model_load_config()
    self.P("Loading {} with following parameters:\n{}\nQuantization params: {}".format(
      model_id,
      self.json_dumps(model_params, indent=4),
      self.json_dumps(quantization_params, indent=4),
      )
    )

    quantization_config = None
    if quantization_params is not None:
      quantization_config = BitsAndBytesConfig(**quantization_params)
    model_params['quantization_config'] = quantization_config

    self.P(f'Trying to load pretrained for {model_id} with the following params:\n {model_params}')

    self.model = self.load_pretrained_model(model_id, **model_params)

    compiled = self.cfg_th_compile
    if compiled:
      compile_mode = self.cfg_th_compile_mode
      self.P("Compiling model")
      self.model = th.compile(
        self.model,
        fullgraph=True,
        mode=compile_mode
      )
    #endif compile model

    self.P("  Loaded `{}` model".format(self.model.__class__.__name__))

    # Set the padding token to the chosen (<unk>) token.
    self.model.config.pad_token_id = self.padding_id
    self.P('Setting padding token ID to {}'.format(self.model.config.pad_token_id))

    # When the entire model is on the GPU we expect to get a {'':0} device map
    # which doesn't really tell us where the model is, only that it is on one
    # device. Additionally print the model device to avoid this corner case.
    self.P("Model {} loaded with dev map:\n{}".format(model_id, self._get_placement_summary()))
    device = next(self.model.parameters()).device
    self.P("First weight is on device: {}".format(device))

    return
