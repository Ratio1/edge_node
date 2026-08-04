"""Isolated integration with Core's pure CmdAPI pipeline builder."""


def build_pipeline_config(plugin, **kwargs):
  """Build pipeline config without registering or dispatching a command."""
  builder = getattr(plugin, "cmdapi_build_pipeline_config", None)
  if not callable(builder):
    raise RuntimeError("Core CmdAPI pure pipeline builder is unavailable.")
  pipeline = builder(**kwargs)
  if not isinstance(pipeline, dict):
    raise RuntimeError("Core CmdAPI pipeline builder returned invalid metadata.")
  return pipeline


def dispatch_pipeline_config(plugin, node_address, pipeline):
  """Dispatch an already built and redacted pipeline config."""
  dispatcher = getattr(plugin, "cmdapi_start_pipeline", None)
  if not callable(dispatcher):
    raise RuntimeError("Core CmdAPI pipeline dispatcher is unavailable.")
  dispatcher(config=pipeline, node_address=node_address)
