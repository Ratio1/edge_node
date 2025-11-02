"""
chainstore_response_mixin.py

A reusable mixin that provides chainstore response functionality for plugins.

This mixin implements a standard pattern for sending plugin startup confirmations
or other lifecycle events to the chainstore, enabling asynchronous callback mechanisms
for distributed plugin orchestration.

Design Pattern:
--------------
This follows the Mixin Pattern, which allows plugins to compose behaviors by
inheriting from multiple specialized classes. The mixin provides:

1. Template Method Pattern: reset/set methods as templates
2. Strategy Pattern: Subclasses can override _get_chainstore_response_data()
3. Observer Pattern: Chainstore acts as the message broker for observers

Usage:
------
1. Inherit from this mixin in your plugin class
2. Call _reset_chainstore_response() at the START of plugin initialization
3. Call _send_chainstore_response() at the END of successful initialization
4. Optionally override _get_chainstore_response_data() for custom response data
5. Configure via CHAINSTORE_RESPONSE_KEY in plugin config

Example:
--------
```python
class MyPlugin(BasePluginBiz, _ChainstoreResponseMixin):
  _CONFIG = {
    **BasePluginBiz.CONFIG,
    'CHAINSTORE_RESPONSE_KEY': None,
  }

  def on_init(self):
    super().on_init()
    # Reset the key at start
    self._reset_chainstore_response()

    # ... plugin initialization ...

    # Send confirmation once after successful init
    self._send_chainstore_response()
    return
```

Architecture Benefits:
---------------------
1. Single Responsibility: Mixin only handles chainstore response logic
2. Open/Closed: Plugins can extend response data without modifying mixin
3. DRY: Eliminates code duplication across multiple plugin types
4. Testability: Mixin can be tested independently
5. Composability: Can be mixed with other functionality mixins
6. Simplicity: Single write - no retries, no confirmations

Configuration:
-------------
CHAINSTORE_RESPONSE_KEY (str, optional):
  The key under which to store the response in chainstore.
  If None or not set, no response will be sent/reset.
  This is typically set by orchestration systems like Deeploy.

Security Considerations:
-----------------------
- Response keys should be generated with sufficient entropy to prevent guessing
- Response data should not contain sensitive information (passwords, tokens, etc.)

"""


class _ChainstoreResponseMixin:
  """
  Mixin providing chainstore response functionality for plugin lifecycle events.

  This mixin enables plugins to send confirmation data to a distributed chainstore
  when important lifecycle events occur (e.g., plugin startup, state changes).

  The mixin uses the Template Method pattern to provide a standard flow while
  allowing subclasses to customize the response data through hook methods.

  Key principle: Reset at start, set once at end.
  """

  def _get_chainstore_response_key(self):
    """
    Get the chainstore response key from configuration.

    This method follows the Dependency Inversion Principle by depending on
    configuration abstraction rather than concrete implementation details.

    Returns:
        str or None: The response key if configured, None otherwise.
    """
    return getattr(self, 'cfg_chainstore_response_key', None)

  def _get_chainstore_response_data(self):
    """
    Template method hook: Build the response data dictionary.

    This method can be overridden by subclasses to provide custom response data.
    The default implementation returns a basic structure that should be
    extended by specialized plugins.

    Design Pattern: Template Method Pattern
    - This is the "hook" method that subclasses can override
    - The parent method _send_chainstore_response() is the "template"

    Best Practice: When overriding, call super() first then extend:
    ```python
    def _get_chainstore_response_data(self):
      data = super()._get_chainstore_response_data()
      data.update({
        'custom_field': self.custom_value,
      })
      return data
    ```

    Returns:
        dict: Response data to be stored in chainstore.
              Should be JSON-serializable.

    Security Note:
        Never include sensitive data like passwords, private keys, or tokens
        in the response data. This data may be visible to multiple nodes.
    """
    # Base implementation provides minimal structure
    # Subclasses should override and extend this
    return {
      'plugin_signature': self.__class__.__name__,
      'instance_id': getattr(self, 'cfg_instance_id', None),
      'timestamp': self.time_to_str(self.time()) if hasattr(self, 'time_to_str') else None,
    }

  def _should_send_chainstore_response(self):
    """
    Determine if a chainstore response should be sent.

    This method implements validation logic to ensure responses are only
    sent when properly configured. Can be overridden for custom logic.

    Returns:
        bool: True if response should be sent, False otherwise.
    """
    response_key = self._get_chainstore_response_key()
    if response_key is None:
      return False

    if not isinstance(response_key, str) or len(response_key) == 0:
      self.P(
        "CHAINSTORE_RESPONSE_KEY is configured but invalid (must be non-empty string)",
        color='r'
      )
      return False

    return True

  def _reset_chainstore_response(self):
    """
    Reset (clear) the chainstore response key at plugin start.

    This should be called at the very beginning of plugin initialization to
    signal that the plugin is starting up. The orchestration system can monitor
    this key - if it's None/empty, it means the plugin is still initializing.

    After successful initialization, call _send_chainstore_response() to set
    the actual response data.

    Returns:
        bool: True if reset was performed, False if key not configured.

    Example:
        ```python
        def on_init(self):
            super().on_init()
            self._reset_chainstore_response()  # Clear at start
            # ... initialization code ...
            self._send_chainstore_response()    # Set after success
            return
        ```
    """
    if not self._should_send_chainstore_response():
      return False

    response_key = self._get_chainstore_response_key()
    self.P(f"Resetting chainstore response key '{response_key}'")

    try:
      # Set to None to signal "initializing" state
      result = self.chainstore_set(response_key, None)
      if result:
        self.P(f"Successfully reset chainstore key '{response_key}'")
        return True
      else:
        self.P(f"Failed to reset chainstore key '{response_key}'", color='y')
        return False
    except Exception as e:
      self.P(f"Error resetting chainstore key '{response_key}': {e}", color='r')
      return False

  def _send_chainstore_response(self, custom_data=None):
    """
    Send plugin response data to chainstore (single write).

    This is the main template method that sends the response after successful
    plugin initialization. It should be called exactly once at the end of
    on_init() after all setup is complete.

    Design Pattern: Template Method Pattern
    - Defines the skeleton of the algorithm
    - Delegates data building to hook method (_get_chainstore_response_data)

    Args:
        custom_data (dict, optional): Additional data to merge into response.
            If provided, will be merged with default response data.
            This allows callers to add context-specific information without
            overriding _get_chainstore_response_data().

    Returns:
        bool: True if response was sent successfully, False otherwise.

    Example:
        ```python
        # Send default response data
        self._send_chainstore_response()

        # Send with additional context
        self._send_chainstore_response(custom_data={
          'deployment_status': 'ready',
          'health_check_passed': True,
        })
        ```

    Implementation Notes:
        - Single write (no retries, no confirmations)
        - Gracefully handles chainstore_set failures without raising exceptions
        - Call _reset_chainstore_response() at plugin start before calling this
    """
    # Validation: Check if response should be sent
    if not self._should_send_chainstore_response():
      return False

    response_key = self._get_chainstore_response_key()

    self.P(f"Sending chainstore response to key '{response_key}'", color='b')

    # Build response data using template method hook
    try:
      response_data = self._get_chainstore_response_data()

      # Merge custom data if provided
      if custom_data is not None:
        if not isinstance(custom_data, dict):
          self.P(
            f"custom_data must be a dict, got {type(custom_data)}",
            color='r'
          )
        else:
          response_data.update(custom_data)

    except Exception as e:
      self.P(
        f"Error building chainstore response data: {e}",
        color='r'
      )
      return False

    # Send single write to chainstore
    try:
      self.P(f"Setting '{response_key}' to: {self.json_dumps(response_data)}")

      # Single write - no retries, no confirmations
      result = self.chainstore_set(response_key, response_data)

      if result:
        self.P(f"Successfully sent chainstore response to '{response_key}'", color='g')
        return True
      else:
        self.P(f"Failed to send chainstore response (chainstore_set returned False)", color='y')
        return False

    except Exception as e:
      self.P(f"Error sending chainstore response: {e}", color='r')
      return False
