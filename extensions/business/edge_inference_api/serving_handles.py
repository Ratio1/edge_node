"""Serving-manager handle derivation shared by the inference API plugins.

The orchestrator (``naeural_core.business.business_manager.fetch_ai_engines``)
decides how a plugin's ``AI_ENGINE`` and ``STARTUP_AI_ENGINE_PARAMS`` become
serving processes. These helpers mirror those rules exactly so a plugin
tags requests for, and polls readiness of, the serving the node actually
started:

- engine names are lowercased;
- with a string ``AI_ENGINE`` the startup params are the engine's own block
  unless they are keyed by the lowercased engine name; with a list they must
  be keyed by lowercased engine name (exact key);
- a ``MODEL_INSTANCE_ID`` in that block (any value that is not None) makes
  the handle ``(engine, instance_id)``, otherwise the handle is the engine.
"""


def configured_engines(ai_engine):
  """Lowercased engine names from an AI_ENGINE value (string or list)."""
  if isinstance(ai_engine, str):
    ai_engine = [ai_engine]
  if not isinstance(ai_engine, (list, tuple)):
    return []
  return [engine.strip().lower() for engine in ai_engine if isinstance(engine, str) and engine.strip()]


def startup_params_for_engine(ai_engine, engine, startup_params):
  """The STARTUP_AI_ENGINE_PARAMS block that applies to ``engine``."""
  if not isinstance(startup_params, dict):
    return {}
  engine_key = str(engine).strip().lower()
  if isinstance(ai_engine, str) and engine_key not in startup_params:
    return startup_params
  block = startup_params.get(engine_key, {})
  return block if isinstance(block, dict) else {}


def serving_handle(ai_engine, engine, startup_params):
  """``engine`` or ``(engine, MODEL_INSTANCE_ID)`` as the orchestrator keys it."""
  engine_key = str(engine).strip().lower()
  instance_id = startup_params_for_engine(ai_engine, engine, startup_params).get('MODEL_INSTANCE_ID')
  if instance_id is not None:
    return (engine_key, instance_id)
  return engine_key


def serving_name(resolved_handle):
  """The serving manager's uppercase name for a resolved (serving process) handle."""
  if isinstance(resolved_handle, (list, tuple)):
    return '_'.join(str(part).upper() for part in resolved_handle)
  return str(resolved_handle).upper()
