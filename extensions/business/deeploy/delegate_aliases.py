"""Optional CSP delegate labels stored independently of on-chain permissions."""

import re
import unicodedata

from .deeploy_const import DEEPLOY_KEYS

DELEGATE_ALIASES_HKEY = "deeploy_delegate_aliases_v1"
DELEGATE_ALIAS_MAX_LENGTH = 80
DELEGATE_ALIASES_MAX_COUNT = 10
ETH_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class _DelegateAliasesMixin:
  """Validate and persist optional delegate metadata without changing permissions."""

  @staticmethod
  def _delegate_alias_address(value):
    """
    Normalize an Ethereum address.

    Parameters
    ----------
    value : str
        Address supplied by the caller or authenticated blockchain adapter.

    Returns
    -------
    str
        Lowercase nonzero Ethereum address.

    Examples
    --------
    >>> _DelegateAliasesMixin._delegate_alias_address('0x' + 'a' * 40)
    '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    """
    if not isinstance(value, str) or not ETH_ADDRESS.fullmatch(value):  # Reject malformed keys before storage access.
      raise ValueError("Invalid delegate alias address.")
    if int(value[2:], 16) == 0:  # Zero is never a registered escrow or delegate.
      raise ValueError("Delegate alias address cannot be zero.")
    return value.lower()  # EVM address casing must not create separate labels.

  @staticmethod
  def _normalize_delegate_alias(value):
    """
    Validate optional human-readable alias text.

    Parameters
    ----------
    value : str
        Label; an empty or whitespace-only string clears the label.

    Returns
    -------
    str
        Trimmed label of at most 80 Unicode code points.

    Examples
    --------
    >>> _DelegateAliasesMixin._normalize_delegate_alias('  Automation  ')
    'Automation'
    """
    if not isinstance(value, str):  # Missing/null values must not accidentally clear a label.
      raise ValueError("'alias' must be a string.")
    if any(unicodedata.category(char).startswith('C') for char in value):  # Reject hidden/control characters, including bidi controls.
      raise ValueError("Alias cannot contain control or format characters.")
    alias = value.strip()  # Store the same label the UI displays.
    if len(alias) > DELEGATE_ALIAS_MAX_LENGTH:  # Bound each shared metadata record.
      raise ValueError("Alias must contain at most 80 characters.")
    return alias

  def _delegate_alias_scope(self, auth_result):
    """
    Derive storage scope from authenticated chain state.

    Parameters
    ----------
    auth_result : dict
        Existing Deeploy authentication result.

    Returns
    -------
    tuple[str, str, str]
        Network, escrow, and owner used for isolation and authorization.

    Examples
    --------
    >>> network, escrow, owner = plugin._delegate_alias_scope(auth_result)
    """
    network = self.bc.get_evm_network()  # The server selects the network, never a caller-controlled key.
    if not isinstance(network, str) or not network:  # Fail closed if network context is unavailable.
      raise ValueError("Delegate alias network is unavailable.")
    escrow = self._delegate_alias_address(auth_result.get(DEEPLOY_KEYS.SENDER_ESCROW))  # Scope survives CSP ownership transfers.
    owner = self._delegate_alias_address(auth_result.get(DEEPLOY_KEYS.ESCROW_OWNER))  # Owner is resolved by existing signed-request auth.
    return network, escrow, owner

  def _delegate_alias_is_member(self, address, escrow, owner):
    """
    Check current membership using the existing blockchain adapter.

    Parameters
    ----------
    address, escrow, owner : str
        Normalized target delegate, authenticated escrow and owner.

    Returns
    -------
    bool
        Whether the target is an active delegate of this CSP.

    Examples
    --------
    >>> plugin._delegate_alias_is_member(delegate, escrow, owner)
    True
    """
    if address == owner:  # Owners are not delegate entries.
      return False
    details = self.bc.get_user_escrow_details(self.bc.eth_addr_to_checksum_address(address))  # Web3 requires checksum inputs even though storage keys are lowercase.
    return bool(details.get('isActive')) and str(details.get('escrowAddress', '')).lower() == escrow  # Prevent cross-CSP labels and revoked delegates.

  def deeploy_load_delegate_aliases(self, auth_result, addresses):
    """
    Load labels for requested active delegates in the authenticated escrow.

    Parameters
    ----------
    auth_result : dict
        Existing Deeploy authentication result for an owner or active delegate.
    addresses : list[str]
        At most 10 addresses from the client's delegate list.

    Returns
    -------
    dict[str, str]
        Nonempty aliases keyed by lowercase addresses. Missing/revoked entries
        are omitted; malformed records are skipped with a count-only warning.

    Examples
    --------
    >>> plugin.deeploy_load_delegate_aliases(auth_result, [])
    {}
    """
    if not isinstance(addresses, list) or len(addresses) > DELEGATE_ALIASES_MAX_COUNT:  # Bound per-request chain and storage reads.
      raise ValueError("'delegate_addresses' must be a list of at most 10 addresses.")
    normalized = list(dict.fromkeys(self._delegate_alias_address(value) for value in addresses))  # Validate all input before external reads and deduplicate it.
    network, escrow, owner = self._delegate_alias_scope(auth_result)  # Derive the tenant exclusively from authenticated state.
    aliases = {}
    invalid_count = 0  # Aggregate corrupt metadata into one bounded warning per request.
    for address in normalized:
      if address == owner:  # Owners are not delegate entries and require no metadata read.
        continue
      value = self.chainstore_hget(hkey=DELEGATE_ALIASES_HKEY, key=f"{network}:{escrow}:{address}")  # Individual keys avoid unrelated-write conflicts.
      if value is not None:  # Existing delegates need no migration or default record.
        try:
          alias = self._normalize_delegate_alias(value)  # Validate each persisted record independently.
        except ValueError:
          invalid_count += 1  # A corrupt optional label must not hide valid neighboring entries.
          continue
        if alias and self._delegate_alias_is_member(address, escrow, owner):  # Probe only valid nonempty records; stale delegates still cannot expose labels.
          aliases[address] = alias  # Empty tombstones and missing/corrupt records need no target RPC.
    if invalid_count:
      self.P(f"Skipped {invalid_count} invalid delegate alias record(s).", color='y')  # Never log untrusted alias content, storage keys, or exception details.
    return aliases

  def deeploy_set_delegate_alias(self, sender, auth_result, address, alias):
    """
    Set or clear one optional alias as the CSP escrow owner.

    Parameters
    ----------
    sender : str
        Verified signer of the complete request.
    auth_result : dict
        Existing Deeploy authentication result.
    address : str
        Target active delegate address.
    alias : str
        Label or an empty string to clear it.

    Returns
    -------
    dict
        Normalized ``delegate_address`` and ``alias`` after a successful write.

    Examples
    --------
    >>> plugin.deeploy_set_delegate_alias(owner, auth_result, delegate, '')
    {'delegate_address': delegate, 'alias': ''}
    """
    network, escrow, owner = self._delegate_alias_scope(auth_result)  # Resolve CSP scope before accepting a metadata mutation.
    if self._delegate_alias_address(sender) != owner:  # Delegates can read labels but cannot change them.
      raise ValueError("Only the escrow owner can update delegate aliases.")
    address = self._delegate_alias_address(address)  # Canonicalize the per-address storage key.
    alias = self._normalize_delegate_alias(alias)  # Validate before any side effect.
    if not self._delegate_alias_is_member(address, escrow, owner):  # Reject inactive, owner, or unrelated targets.
      raise ValueError("Address is not an active delegate of this escrow.")
    saved = self.chainstore_hset(hkey=DELEGATE_ALIASES_HKEY, key=f"{network}:{escrow}:{address}", value=alias)  # Empty tombstones preserve clear operations through replication.
    if not saved:  # A storage failure must not be presented as a successful rename.
      raise ValueError("Failed to save delegate alias to CStore.")
    return {"delegate_address": address, "alias": alias}
