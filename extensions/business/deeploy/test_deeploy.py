import unittest

from naeural_core.utils.fastapi_utils import PostponedRequest

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS


class _BCStub:
  """
  Minimal blockchain stub for deeploy tests.
  """
  def __init__(self):
    self.submitted = []

  def node_addr_to_eth_addr(self, node):
    """
    Convert internal node address to eth-style address.

    Parameters
    ----------
    node : str
        Internal node address.

    Returns
    -------
    str
        Stubbed eth address.
    """
    return f"eth_{node}"

  def submit_node_update(self, job_id, nodes):
    """
    Record a submit_node_update call.

    Parameters
    ----------
    job_id : int
        Job identifier.
    nodes : list[str]
        Target node addresses.
    """
    self.submitted.append((job_id, list(nodes)))


class _InputsStub(dict):
  """
  Dict-like object that exposes keys as attributes.
  """
  def __getattr__(self, item):
    """
    Fetch values via attribute access.

    Parameters
    ----------
    item : str
        Attribute name.

    Returns
    -------
    Any
        Value from the dictionary.
    """
    try:
      return self[item]
    except KeyError:
      raise AttributeError(item)


class _DeeployStub(DeeployManagerApiPlugin):
  """
  Deeploy manager stub with minimal dependencies for unit testing.
  """
  def __init__(self):
    pass

  def time(self):
    """
    Return current mocked time.

    Returns
    -------
    float
        Current mocked timestamp.
    """
    return self._now

  def _get_response(self, dct_data):
    """
    Return response payload without wrapping.

    Parameters
    ----------
    dct_data : dict
        Response data.

    Returns
    -------
    dict
        Response data passed through.
    """
    return dct_data

  def create_postponed_request(self, solver_method, method_kwargs=None):
    """
    Create a PostponedRequest instance.

    Parameters
    ----------
    solver_method : callable
        Solver method to call during polling.
    method_kwargs : dict, optional
        Solver keyword arguments.

    Returns
    -------
    PostponedRequest
        Deferred request handle.
    """
    if method_kwargs is None:
      method_kwargs = {}
    return PostponedRequest(solver_method=solver_method, method_kwargs=method_kwargs)

  def chainstore_get(self, key):
    """
    Lookup a chainstore key in local stub storage.

    Parameters
    ----------
    key : str
        Chainstore key.

    Returns
    -------
    Any
        Stored value or None.
    """
    return self._chainstore.get(key)

  def P(self, *args, **kwargs):
    """
    No-op logger.
    """
    return

  def Pd(self, *args, **kwargs):
    """
    No-op debug logger.
    """
    return

  def json_dumps(self, obj, **kwargs):
    """
    Serialize JSON for debug output.

    Parameters
    ----------
    obj : Any
        Object to serialize.

    Returns
    -------
    str
        JSON string.
    """
    import json
    return json.dumps(obj)

  # Deeploy API stubs for endpoint tests
  def _DeeployManagerApiPlugin__ensure_eth_balance(self):
    """
    Stub balance check.

    Returns
    -------
    bool
        Always True in tests.
    """
    return True

  def deeploy_verify_and_get_inputs(self, request, require_sender_is_oracle=False, no_hash=True):
    """
    Stub request verification.

    Parameters
    ----------
    request : dict
        Raw request.
    require_sender_is_oracle : bool, optional
        Oracle enforcement flag.
    no_hash : bool, optional
        Hashing flag.

    Returns
    -------
    tuple
        (sender, inputs) tuple for testing.
    """
    inputs = _InputsStub(request)
    return "sender", inputs

  def deeploy_get_auth_result(self, inputs):
    """
    Stub auth result payload.

    Parameters
    ----------
    inputs : dict
        Request inputs.

    Returns
    -------
    dict
        Auth result with escrow owner.
    """
    return {DEEPLOY_KEYS.ESCROW_OWNER: "owner"}

  def deeploy_check_payment_and_job_owner(self, inputs, owner, is_create=False, debug=False):
    """
    Stub payment/ownership check.

    Parameters
    ----------
    inputs : dict
        Request inputs.
    owner : str
        Expected owner.
    is_create : bool, optional
        Create flag.
    debug : bool, optional
        Debug flag.

    Returns
    -------
    bool
        Always True in tests.
    """
    return True

  def _get_online_apps(self, job_id=None, owner=None):
    """
    Stub online app discovery.

    Parameters
    ----------
    job_id : int, optional
        Job identifier.
    owner : str, optional
        Owner address.

    Returns
    -------
    dict
        Minimal app map for tests.
    """
    if job_id is None:
      return {}
    return {"node1": {"app1": {"dummy": True}}}

  def _check_nodes_availability(self, inputs, skip_resource_check=False):
    """
    Stub node availability check.

    Parameters
    ----------
    inputs : dict
        Request inputs.
    skip_resource_check : bool, optional
        Resource check flag.

    Returns
    -------
    list[str]
        Single node address for tests.
    """
    return ["node2"]

  def scale_up_job(self, new_nodes, update_nodes, job_id, owner, running_apps_for_job, wait_for_responses=True):
    """
    Stub scale-up operation.

    Parameters
    ----------
    new_nodes : list[str]
        New nodes to deploy on.
    update_nodes : list[str]
        Existing nodes to update.
    job_id : int
        Job identifier.
    owner : str
        Owner address.
    running_apps_for_job : dict
        Running apps mapping.
    wait_for_responses : bool, optional
        Wait flag (ignored).

    Returns
    -------
    tuple
        (dct_status, str_status, response_keys)
    """
    response_keys = {"node1": ["k1"]}
    return {}, DEEPLOY_STATUS.PENDING, response_keys


class DeeployPostponedTests(unittest.TestCase):
  """
  Unit tests for postponed deeploy flow.
  """
  def setUp(self):
    """
    Initialize stub plugin instance.
    """
    self.plugin = _DeeployStub.__new__(_DeeployStub)
    self.plugin._now = 1_000.0
    self.plugin.cfg_postponed_poll_interval = 0.5
    self.plugin.cfg_request_timeout = 10
    self.plugin._chainstore = {}
    self.plugin.bc = _BCStub()
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests = {}

  def test_check_pipeline_responses_no_keys(self):
    """
    Ensure empty response keys resolve immediately.
    """
    dct_status, str_status, done = self.plugin._check_pipeline_responses_once({})
    self.assertEqual(dct_status, {})
    self.assertEqual(str_status, DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertTrue(done)

  def test_check_pipeline_responses_partial(self):
    """
    Ensure partial responses remain pending.
    """
    response_keys = {"nodeA": ["k1", "k2"]}
    self.plugin._chainstore["k1"] = {"ok": True}
    dct_status, str_status, done = self.plugin._check_pipeline_responses_once(response_keys)
    self.assertIn("k1", dct_status)
    self.assertNotIn("k2", dct_status)
    self.assertEqual(str_status, DEEPLOY_STATUS.PENDING)
    self.assertFalse(done)

  def test_solve_postponed_pipeline_timeout(self):
    """
    Ensure pipeline pending state times out correctly.
    """
    pending_id = "pid1"
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests[pending_id] = {
      'kind': 'pipeline',
      'response_keys': {"nodeA": ["k1"]},
      'dct_status': {},
      'start_time': 0,
      'timeout': 1,
      'next_check_ts': 0,
      'base_result': {
        DEEPLOY_KEYS.APP_ID: "app1",
        DEEPLOY_KEYS.REQUEST: {"x": 1},
        DEEPLOY_KEYS.AUTH: {"a": 2},
      },
      'confirm': {},
    }
    self.plugin._now = 5
    res = self.plugin.solve_postponed_deploy_request(pending_id)
    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.TIMEOUT)
    self.assertEqual(res[DEEPLOY_KEYS.APP_ID], "app1")

  def test_solve_postponed_scale_up_timeout(self):
    """
    Ensure scale-up pending state times out with expected fields.
    """
    pending_id = "pid2"
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests[pending_id] = {
      'kind': 'scale_up',
      'response_keys': {"nodeA": ["k1"]},
      'dct_status': {},
      'start_time': 0,
      'timeout': 1,
      'next_check_ts': 0,
      'job_id': 123,
      'is_confirmable_job': True,
      'request': {"req": 1},
      'auth': {"auth": 2},
    }
    self.plugin._now = 5
    res = self.plugin.solve_postponed_deploy_request(pending_id)
    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.TIMEOUT)
    self.assertEqual(res[DEEPLOY_KEYS.JOB_ID], 123)
    self.assertIn(DEEPLOY_KEYS.REQUEST, res)
    self.assertIn(DEEPLOY_KEYS.AUTH, res)

  def test_solve_postponed_returns_postponed_when_not_ready(self):
    """
    Ensure solver returns PostponedRequest when gating interval not reached.
    """
    pending_id = "pid3"
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests[pending_id] = {
      'kind': 'pipeline',
      'response_keys': {"nodeA": ["k1"]},
      'dct_status': {},
      'start_time': 0,
      'timeout': 100,
      'next_check_ts': self.plugin._now + 5,
      'base_result': {},
      'confirm': {},
    }
    res = self.plugin.solve_postponed_deploy_request(pending_id)
    self.assertIsInstance(res, PostponedRequest)

  def test_solve_postponed_pipeline_success_confirms(self):
    """
    Ensure successful pipeline confirms blockchain update.
    """
    pending_id = "pid4"
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests[pending_id] = {
      'kind': 'pipeline',
      'response_keys': {"nodeA": ["k1", "k2"]},
      'dct_status': {},
      'start_time': 0,
      'timeout': 100,
      'next_check_ts': 0,
      'base_result': {
        DEEPLOY_KEYS.APP_ID: "app1",
        DEEPLOY_KEYS.REQUEST: {},
        DEEPLOY_KEYS.AUTH: {},
      },
      'confirm': {
        'nodes_changed': True,
        'confirmation_nodes': ["nodeA"],
        'is_confirmable_job': True,
        'job_id': 77,
      },
    }
    self.plugin._chainstore["k1"] = {"ok": True}
    self.plugin._chainstore["k2"] = {"ok": True}
    res = self.plugin.solve_postponed_deploy_request(pending_id)
    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(self.plugin.bc.submitted, [(77, ["eth_nodeA"])])

  def test_solve_postponed_missing_pending(self):
    """
    Ensure missing pending ID returns failure.
    """
    res = self.plugin.solve_postponed_deploy_request("missing")
    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)


class DeeployEndpointTests(unittest.TestCase):
  """
  Endpoint-level tests for deeploy manager API.
  """
  def setUp(self):
    """
    Initialize stub plugin instance.
    """
    self.plugin = _DeeployStub.__new__(_DeeployStub)
    self.plugin._now = 1_000.0
    self.plugin.cfg_postponed_poll_interval = 0.5
    self.plugin.cfg_request_timeout = 10
    self.plugin._chainstore = {}
    self.plugin.bc = _BCStub()
    self.plugin._DeeployManagerApiPlugin__pending_deploy_requests = {}

  def test_create_pipeline_returns_postponed(self):
    """
    Ensure create_pipeline returns PostponedRequest on pending state.
    """
    def _process_pipeline_request(request, is_create=True, async_mode=False):
      return {'__pending__': {'kind': 'pipeline', 'response_keys': {"n": ["k"]}, 'dct_status': {},
                              'start_time': self.plugin._now, 'timeout': 10, 'next_check_ts': 0,
                              'base_result': {}, 'confirm': {}}}
    self.plugin._process_pipeline_request = _process_pipeline_request
    res = self.plugin.create_pipeline({})
    self.assertIsInstance(res, PostponedRequest)

  def test_update_pipeline_returns_postponed(self):
    """
    Ensure update_pipeline returns PostponedRequest on pending state.
    """
    def _process_pipeline_request(request, is_create=True, async_mode=False):
      return {'__pending__': {'kind': 'pipeline', 'response_keys': {"n": ["k"]}, 'dct_status': {},
                              'start_time': self.plugin._now, 'timeout': 10, 'next_check_ts': 0,
                              'base_result': {}, 'confirm': {}}}
    self.plugin._process_pipeline_request = _process_pipeline_request
    res = self.plugin.update_pipeline({})
    self.assertIsInstance(res, PostponedRequest)

  def test_create_pipeline_passthrough(self):
    """
    Ensure create_pipeline returns direct result when not pending.
    """
    def _process_pipeline_request(request, is_create=True, async_mode=False):
      return {"status": "ok"}
    self.plugin._process_pipeline_request = _process_pipeline_request
    res = self.plugin.create_pipeline({})
    self.assertEqual(res["status"], "ok")

  def test_scale_up_job_workers_returns_postponed(self):
    """
    Ensure scale_up_job_workers returns PostponedRequest when response keys exist.
    """
    req = {
      DEEPLOY_KEYS.JOB_ID: 10,
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: True,
    }
    res = self.plugin.scale_up_job_workers(req)
    self.assertIsInstance(res, PostponedRequest)

  def test_scale_up_job_workers_command_delivered(self):
    """
    Ensure scale_up_job_workers returns command-delivered when no keys exist.
    """
    def scale_up_job(new_nodes, update_nodes, job_id, owner, running_apps_for_job, wait_for_responses=True):
      return {}, DEEPLOY_STATUS.PENDING, {}
    self.plugin.scale_up_job = scale_up_job
    req = {
      DEEPLOY_KEYS.JOB_ID: 10,
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
    }
    res = self.plugin.scale_up_job_workers(req)
    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)


if __name__ == "__main__":
  unittest.main()
