from .discovery import _WebDiscoveryMixin
from .hardening import _WebHardeningMixin
from .api_exposure import _WebApiExposureMixin
from .injection import _WebInjectionMixin


class _WebTestsMixin(
  _WebDiscoveryMixin,
  _WebHardeningMixin,
  _WebApiExposureMixin,
  _WebInjectionMixin,
):
  """Combined web tests mixin."""
  pass
