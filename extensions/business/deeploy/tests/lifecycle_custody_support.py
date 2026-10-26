"""Offline cross-stack fixture with physically separate public and secret stores."""
import copy
import hashlib
import importlib.util
import json
import threading
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from naeural_core import constants as ct
from naeural_core.utils.plugins_base.bc_wrapper import BCWrapper
from ratio1.bc.base import BaseBlockEngine
from ratio1.const.base import BCct, dAuth
from extensions.business.dauth.dauth_mixin import _DauthMixin
from extensions.business.dauth.deployment_secrets import _DauthDeploymentSecretsMixin
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.deeploy_job_mixin import _DeeployJobMixin
from extensions.business.deeploy.deployment_operations import _DeploymentOperationsMixin, NODE_OPERATIONS_HKEY
from extensions.business.deeploy.deployment_mutations import _DeploymentMutationsMixin


AUTH = {'EE_SIGN', 'EE_SENDER', 'EE_ETH_SENDER', 'EE_ETH_SIGN', 'EE_HASH'}
_cmdapi_spec = importlib.util.spec_from_file_location('custody_cmdapi', Path(ct.__file__).parent / 'business/mixins_base/cmdapi.py')
_cmdapi = importlib.util.module_from_spec(_cmdapi_spec)
_cmdapi_spec.loader.exec_module(_cmdapi)


class Engine:
  reconcile_dauth_job_secrets = BaseBlockEngine.reconcile_dauth_job_secrets

  def __init__(self, address):
    self.address = address
    self.evm_network = 'test'

  def sign(self, dct_data, **kwargs):
    value = dct_data
    value[BCct.SIGN_CANON_V] = BaseBlockEngine.SIGN_CANON_V_CURRENT
    value.update(EE_SENDER=self.address, EE_ETH_SENDER='0x' + self.address)
    value['EE_SIGN'] = self.digest(value)

  @staticmethod
  def digest(value):
    unsigned = {key: item for key, item in value.items() if key not in AUTH}
    return hashlib.sha256((value.get('EE_SENDER', '') + json.dumps(unsigned, sort_keys=True)).encode()).hexdigest()

  def verify(self, dct_data, **kwargs):
    value = dct_data
    return SimpleNamespace(valid=value.get('EE_SIGN') == self.digest(value), sender=value.get('EE_SENDER'), message='fixture')

  def get_network_data(self, network):
    return {dAuth.EvmNetData.DAUTH_URL_KEY: 'https://dauth/get_auth_data'}

  def node_address_to_eth_address(self, address):
    return '0x' + address

  def web3_get_oracles(self):
    return ['0xoracle']

  def web3_is_dauth_oracle(self, address, network=None):
    return address == '0xdauth'


class Blobs:
  def __init__(self):
    self.data = {}
    self.deleted = []
    self.uploads = 0

  def calculate_json_cid(self, value, **kwargs):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

  def add_json(self, value, **kwargs):
    self.uploads += 1
    cid = "folder-{}-{}".format(self.uploads, self.calculate_json_cid(value))
    self.data[cid] = copy.deepcopy(value)
    return cid

  def get_json(self, cid, **kwargs):
    return copy.deepcopy(self.data.get(cid))

  def delete_file(self, cid, **kwargs):
    self.deleted.append(cid)
    self.data.pop(cid, None)


class State:
  def __init__(self):
    self.public, self.secrets = {}, {}
    self.blobs = Blobs()
    self.now = 1000
    self.fail_write = None
    self.writes = []


class Node:
  def configure(self, state, address, custodian=False):
    self.state = state
    self.address = address
    self.custodian = custodian
    self.engine = Engine(address)
    self.bc = BCWrapper(self.engine, owner=self)
    self.ct = self.const = ct
    self.r1fs = state.blobs
    self.deepcopy = copy.deepcopy
    self.json_dumps = json.dumps
    self.defaultdict = defaultdict
    self.uuid = lambda length: 'a' * length
    self.cmdapi_build_pipeline_config = _cmdapi.build_cmdapi_stream_config
    self.evm_network = 'test'
    self.cfg_deeploy_verbose = 0
    self.cfg_dauth_verbose = False
    self.cfg_deployment_readiness_timeout = 60
    self._dauth_registry_internal_peers = ['dauth']
    self._deployment_plans = {}
    self._deployment_plan_cache_lock = threading.Lock()
    self._deployment_preparations = {}
    self._deployment_operations_event = threading.Event()
    self._deployment_operations_stop = threading.Event()
    self._get_response = lambda value: value
    self._operation_peers = lambda: ['oracle', 'dauth']
    self.netmon = SimpleNamespace(network_known_pipelines=lambda: self.known)
    self.known = {}
    self.commands = []
    self.engine.web3_get_job_details = lambda job_id: {'escrowOwner': 'owner'}

  def P(self, *args, **kwargs):
    pass

  def Pd(self, *args, **kwargs):
    pass

  def time(self):
    return self.state.now

  def storage(self, namespace):
    if namespace in ('DAUTH_JOB_SECRET_REVISIONS', 'DAUTH_JOB_SECRETS'):
      if not self.custodian:
        raise AssertionError('Coordinator accessed protected storage: ' + namespace)
      return self.state.secrets
    return self.state.public

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.storage(hkey).get((hkey, str(key))))

  def chainstore_hgetall(self, hkey):
    return {key: copy.deepcopy(value) for (namespace, key), value in self.storage(hkey).items() if namespace == hkey}

  def chainstore_hset(self, hkey, key, value, **kwargs):
    store = self.storage(hkey)
    self.state.writes.append((self.address, hkey, key))
    fail = self.state.fail_write and self.state.fail_write(hkey, key)
    if fail != 'before':
      store[hkey, str(key)] = copy.deepcopy(value)
    return not fail

  def chainstore_hsync(self, hkey, **kwargs):
    self.storage(hkey)
    return {'hkey': hkey}

  def cmdapi_start_pipeline(self, config, node_address):
    self.commands.append((node_address, copy.deepcopy(config)))


class Coordinator(Node, _DeploymentMutationsMixin, _DeploymentOperationsMixin, _DeeployMixin, _DeeployJobMixin):
  def __init__(self, state):
    self.configure(state, 'oracle')


class Custodian(Node, _DauthMixin, _DauthDeploymentSecretsMixin, _DeeployMixin, _DeeployJobMixin):
  def __init__(self, state):
    self.configure(state, 'dauth', True)


def pipeline(secret='fresh-token', revision=0):
  return {'NAME': 'app', 'OWNER': 'owner', 'TYPE': 'void',
          'DEEPLOY_SPECS': {'job_id': 7, 'revision': revision, 'current_target_nodes': ['A']},
          'PLUGINS': [{'SIGNATURE': 'TEST_APP', 'INSTANCES': [
            {'INSTANCE_ID': 'worker', 'ENV': {'CF_TUNNEL_TOKEN': secret}},
          ]}]}


def connect(test, state, custodian):
  def post(url, json, timeout):
    try:
      result = custodian.process_dauth_reconcile_secrets_request(json['body'])
    except (ValueError, RuntimeError):
      result = {'nonce': json['body']['nonce'], 'error': 'custody rejected'}
    custodian.bc.sign(result)
    return SimpleNamespace(status_code=200, json=lambda: {'result': result})
  http = patch('ratio1.bc.base.requests.post', side_effect=post)
  mocked = http.start()
  test.addCleanup(http.stop)
  clock = patch('ratio1.bc.base.time', side_effect=lambda: state.now)
  clock.start()
  test.addCleanup(clock.stop)
  return mocked


def report(state, operation, attempt, status):
  nodes = operation['nodes'] if attempt == 'deploy' else operation['previous_nodes']
  for node in nodes:
    revision = operation['target_revision'] if attempt == 'deploy' else operation['previous_revision']
    item = dict(operation_id=operation['operation_id'], app_id=operation['app_id'], attempt=attempt,
                node_addr=node, coordinator='oracle', revision=revision,
                status=status, updated_at=state.now, sequence=int(state.now),
                instances=[dict(signature=signature, instance_id=instance, status=status)
                           for signature, instance in operation['instances' if attempt == 'deploy' else 'previous_instances'][node]])
    Engine(node).sign(item)
    state.public[NODE_OPERATIONS_HKEY, node + '|' + attempt] = item
