from .web_discovery_mixin import _WebDiscoveryMixin
from .web_hardening_mixin import _WebHardeningMixin
from .web_api_mixin import _WebApiExposureMixin
from .web_injection_mixin import _WebInjectionMixin


class _WebTestsMixin(
  _WebDiscoveryMixin,
  _WebHardeningMixin,
  _WebApiExposureMixin,
  _WebInjectionMixin,
):
  """Backward-compatible combined mixin -- prefer importing individual mixins."""
  pass
