from ._base import _ServiceProbeBase
from .common import _ServiceCommonMixin
from .database import _ServiceDatabaseMixin
from .infrastructure import _ServiceInfraMixin
from .tls import _ServiceTlsMixin


class _ServiceInfoMixin(
  _ServiceCommonMixin,
  _ServiceDatabaseMixin,
  _ServiceInfraMixin,
  _ServiceTlsMixin,
):
  """Combined service probes mixin."""
  pass
