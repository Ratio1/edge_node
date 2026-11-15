"""A job whose secret record the chain store refuses for its size is told so by the Deeploy API, and only then.

The whole path with the real pieces: the API's request handler, the coordinator's admission, the SDK's dAuth
client, the dAuth endpoint and its custody code. Only the HTTP call between client and endpoint, the chain store
and R1FS are stand-ins.
"""
# Copies of request bodies that a test then changes.
import copy
# The test framework.
import unittest
# The API stand-in keeps per-node plugin lists in one.
from collections import defaultdict
# The answer object of the stand-in for the HTTP call.
from types import SimpleNamespace
# Replaces the SDK's HTTP call and its clock.
from unittest.mock import patch

# The API on a host without a node (it also puts a stand-in for the web-app base class in place, so first).
from extensions.business.deeploy.tests.test_process_request import _BCStub, _ProcessRequestStub
# Sends a create request through the API's own request handler.
from extensions.business.deeploy.tests.support import submit_deployment
# The coordinator and the dAuth node over separate public and secret stores.
from extensions.business.deeploy.tests import lifecycle_custody_support as custody
# The dAuth plugin, for its real reconciliation endpoint.
from extensions.business.dauth.dauth_manager import DauthManagerPlugin
# The node constants the API stand-in reads.
from naeural_core import constants as ct


# What the job's owner is told: the SDK client's own text for the reason code "record_too_large".
TOO_LARGE = ("The deployment's secret record is larger than the store accepts: "
             "the job must target fewer nodes or carry smaller configurations.")
# The dAuth endpoint's answer to every failed reconciliation, as before.
FAILED = {'error': 'dAuth secret reconciliation failed'}
# The API's answer when it cannot tell whether a deployment was accepted, as before.
UNCERTAIN = {'status_code': 503, 'status': 'error', 'error': {
  'code': 'ADMISSION_UNAVAILABLE',
  'message': 'Deployment acceptance is uncertain. Retry with the same request_id.', 'retryable': True}}


class _Stack:
  """One coordinator with its API, one dAuth server with its endpoint, and the HTTP call between them."""

  def __init__(self, test):
    """
    Build both sides on fresh stores and route the SDK's custody calls to the real dAuth endpoint.

    Parameters
    ----------
    test : unittest.TestCase
      The running test; its cleanup removes the two patches.

    Returns
    -------
    None

    Examples
    --------
    >>> stack = _Stack(self)
    >>> stack.create()["status_code"]
    202
    """
    # The shared stores and clock of both sides.
    self.state = custody.State()
    # The coordinator: the real admission, operations and SDK custody call.
    self.coordinator = custody.Coordinator(self.state)
    # The dAuth node: the real custody code over the secret stores.
    self.custodian = custody.Custodian(self.state)
    # The dAuth plugin without its start-up: only its reconciliation endpoint runs.
    self.manager = DauthManagerPlugin.__new__(DauthManagerPlugin)
    # A registered dAuth oracle.
    self.manager._dauth_server_enabled = True
    # The endpoint's own dictionary comes back; this stand-in signs it below, as the fixture does.
    self.manager._DauthManagerPlugin__get_response = lambda data: data
    # The endpoint serves requests with the dAuth node's real handler.
    self.manager.process_dauth_reconcile_secrets_request = self.custodian.process_dauth_reconcile_secrets_request
    # The address the endpoint logs a failed request with.
    self.manager.get_request_client_ip = lambda: '203.0.113.7'
    # The endpoint's log lines are not under test here.
    self.manager.P = lambda *args, **kwargs: None
    # Every signed request body the endpoint got, and what it answered before the server fields and signature.
    self.bodies, self.answers = [], []
    # Changes an answer before it is signed; a test sets it to stand in for a dAuth server of another release.
    self.rewrite = None
    # The SDK posts to the endpoint below.
    http = patch('ratio1.bc.base.requests.post', side_effect=self.post)
    # From now on.
    http.start()
    # Until the test ends.
    test.addCleanup(http.stop)
    # The SDK stamps its requests with the shared clock.
    clock = patch('ratio1.bc.base.time', side_effect=lambda: self.state.now)
    # From now on.
    clock.start()
    # Until the test ends.
    test.addCleanup(clock.stop)
    # The Deeploy API on a host without a node: its real request handler up to admission.
    self.api = _ProcessRequestStub()
    # What that handler reads on a plugin.
    self.api.ct, self.api.bc, self.api.cfg_deeploy_verbose = ct, _BCStub(), 0
    # Its copy and container helpers.
    self.api.deepcopy, self.api.defaultdict = copy.deepcopy, defaultdict
    # Its name helper: a name without a slash.
    self.api.sanitize_name = lambda value: str(value).replace("/", "_")
    # Its id helper: a fixed suffix for the app's name.
    self.api.uuid = lambda size=7: "abc1234"[:size]
    # Admission is the coordinator's real one, in place of the stand-in's recording copy.
    self.api._admit_prepared_deployment = self.coordinator._admit_prepared_deployment

  def serve(self, body):
    """
    Answer one request body with the real dAuth endpoint.

    Parameters
    ----------
    body : dict
      The signed request body.

    Returns
    -------
    dict
      The endpoint's answer without the request's nonce, before server fields and signature.

    Examples
    --------
    >>> stack.serve({"nonce": "n1"})   # not signed
    {'error': 'dAuth secret reconciliation failed'}
    """
    # The endpoint, whole: registration, the handler and its answer to a failure.
    answer = self.manager.reconcile_job_secrets(body)
    # Without the nonce it echoes.
    return {key: value for key, value in answer.items() if key != 'nonce'}

  def post(self, url, json, timeout):
    """
    Stand in for the HTTP call: serve the body with the real endpoint, then add what a server adds and sign.

    Parameters
    ----------
    url : str
      The reconcile address the SDK posts to; not checked here.
    json : dict
      The posted document; its ``body`` is the signed request.
    timeout : tuple
      The SDK's HTTP timeout; not used here.

    Returns
    -------
    types.SimpleNamespace
      A response with status 200 whose ``json()`` returns ``{'result': answer}``.

    Examples
    --------
    >>> stack.post('https://dauth/reconcile_job_secrets', {'body': body}, (10, 60)).status_code
    200
    """
    # Kept for the tests that send a changed copy of it again.
    self.bodies.append(copy.deepcopy(json['body']))
    # The real endpoint's answer.
    result = self.manager.reconcile_job_secrets(json['body'])
    # Kept as the endpoint gave it.
    self.answers.append({key: value for key, value in result.items() if key != 'nonce'})
    if self.rewrite:
      # The answer of a dAuth server of another release.
      self.rewrite(result)
    # The fields every dAuth server adds before it signs; the SDK names a refusing server by its alias.
    result.update(server_alias=self.custodian.address, server_version='fixture', server_time='1970-01-01 00:00:00',
                  server_current_epoch=0, server_uptime='0:00:00')
    # Signed by the dAuth node, as every answer is.
    self.custodian.bc.sign(result)
    # What the SDK's HTTP call returns.
    return SimpleNamespace(status_code=200, json=lambda: {'result': result})

  def refuse(self, word):
    """
    Make the write of the target secret record end as ``word``; every other write is stored and confirmed.

    Parameters
    ----------
    word : str
      'before' or 'after' (see ``Node.chainstore_hset``), or an outcome word of the chain store.

    Returns
    -------
    None

    Examples
    --------
    >>> stack.refuse('refused_too_large')
    """
    # Only the target copy of the job's secret record.
    self.state.fail_write = lambda namespace, key: (
      word if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':deploy') else None)

  def create(self):
    """
    Send a create request for job 7 on node A through the API's request handler.

    Returns
    -------
    dict
      The API's answer, as the handler builds it.

    Examples
    --------
    >>> stack.create()["status"]
    'accepted'
    """
    # A small native app with one plugin, on one node.
    return submit_deployment(self.api, {
      "job_id": 7, "app_alias": "native", "job_app_type": "native", "pipeline_input_type": "void",
      "pipeline_input_uri": None, "pipeline_params": {}, "target_nodes": ["A"],
      "plugins": [{"plugin_signature": "CUSTOM_EXEC_01", "CODE": ""}],
    }, is_create=True)


class SecretRecordSizeRefusalTests(unittest.TestCase):

  def test_a_job_whose_secret_record_is_refused_for_its_size_is_told_so_by_the_api(self):
    """When the chain store refuses the job's secret record for its size, the API answers 400 with a text that
    says what to change, and the dAuth answer carries the fixed code and the unchanged error text; before, the
    API answered 503 "acceptance is uncertain" and the operation failed 120 s later without a cause."""
    # Both sides, with the real endpoint between them.
    stack = _Stack(self)
    # A create that works, first: the path is whole.
    self.assertEqual(stack.create()["status_code"], 202)
    # A fresh stack whose chain store refuses the secret record as too large.
    stack = _Stack(self)
    # The store's outcome word for a record over its size cap.
    stack.refuse('refused_too_large')
    # The API's answer to the job's owner.
    self.assertEqual(stack.create(), {'status_code': 400, 'status': 'error', 'error': {
      'code': 'INVALID_DEPLOYMENT_REQUEST', 'message': TOO_LARGE, 'retryable': False}})
    # The dAuth endpoint answered the unchanged error text and one more field: the fixed reason code.
    self.assertEqual(stack.answers, [{**FAILED, 'reason': 'record_too_large'}])

  def test_every_other_failed_preparation_is_answered_as_before(self):
    """A secret record's write that fails for any other reason gets the dAuth answer of before, without a reason,
    and the API's 503: not confirmed, lost, or refused by the store as too deep or not encodable."""
    # 'before' and 'after' are the fixture's two failures; the others are outcome words of the chain store.
    for word in ('before', 'after', 'unconfirmed', 'refused_too_deep', 'refused_unencodable', 'refused_not_member'):
      # Each reports on its own, on a fresh stack.
      with self.subTest(failure=word):
        # Both sides.
        stack = _Stack(self)
        # The write fails this way.
        stack.refuse(word)
        # The API cannot tell whether the deployment was accepted, as before.
        self.assertEqual(stack.create(), UNCERTAIN)
        # The dAuth answer is exactly the one of before: no reason field.
        self.assertEqual(stack.answers, [FAILED])

  def test_the_reason_code_is_not_given_to_a_request_that_fails_an_earlier_check(self):
    """The code is answered only to a request that passed every check before the write: the same request sent
    again unsigned, changed after signing, with a nonce that expired, by a sender that is no protocol oracle, with
    an operation another node signed, or to a node that is no dAuth oracle gets the answer of every failure."""
    # Both sides; the chain store refuses the secret record as too large for the whole test.
    stack = _Stack(self)
    # So a request that passes every check is answered with the code.
    stack.refuse('refused_too_large')
    # The create whose preparation is refused.
    stack.create()
    # The signed preparation request the coordinator sent.
    body = stack.bodies[0]
    # Sent again as it is, it gets the code again: the checks below are what keeps it from the others.
    self.assertEqual(stack.serve(copy.deepcopy(body)), {**FAILED, 'reason': 'record_too_large'})
    # The same request without its signature.
    unsigned = {key: value for key, value in body.items() if key != 'EE_SIGN'}
    # The same request with a field changed after it was signed.
    changed = {**copy.deepcopy(body), 'job_id': '8'}
    # The same request with the operation signed by another node, and the body signed again by the sender.
    foreign = copy.deepcopy(body)
    # Another node signs the operation as its own.
    custody.Engine('other').sign(foreign['operation'])
    # The sender signs the body that carries it.
    stack.coordinator.engine.sign(foreign)
    # None of the three passes the signature and coordinator checks.
    for name, request in (('unsigned', unsigned), ('changed', changed), ('foreign operation', foreign)):
      # Each reports on its own.
      with self.subTest(request=name):
        # The answer of every failure, without a reason.
        self.assertEqual(stack.serve(request), FAILED)
    # A sender that is not a protocol oracle: the dAuth node's oracle list names another address.
    with patch.object(stack.custodian.engine, 'web3_get_oracles', lambda: ['0xsomeone'], create=True):
      # The answer of every failure.
      self.assertEqual(stack.serve(copy.deepcopy(body)), FAILED)
    # The nonce is 121 s old: past the 120 s a secret request may take.
    stack.state.now += 121
    # The answer of every failure.
    self.assertEqual(stack.serve(copy.deepcopy(body)), FAILED)
    # Back in time, on a node that is not a registered dAuth oracle.
    stack.state.now -= 121
    # Not registered.
    stack.manager._dauth_server_enabled = False
    # Its own fixed answer, as before, without a reason.
    self.assertEqual(stack.serve(copy.deepcopy(body)), {'error': 'dAuth server is not registered as a dAuth oracle'})

  def test_a_dauth_server_of_the_previous_release_is_answered_as_before(self):
    """A dAuth server of the previous release sends no reason: the same refusal without the field gets the API's
    503, as before, also when the cause was the record's size."""
    # Both sides.
    stack = _Stack(self)
    # The store refuses the secret record as too large.
    stack.refuse('refused_too_large')
    # The dAuth server answers as the previous release does: the error text only.
    stack.rewrite = lambda answer: answer.pop('reason')
    # The API cannot tell whether the deployment was accepted, as before.
    self.assertEqual(stack.create(), UNCERTAIN)


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
