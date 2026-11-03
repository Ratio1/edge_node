# MQTT broker allocation and failover

## Contract

dAuth reads the whitespace-separated `EE_MQTT_HOST_SEED`, removes blank and
duplicate entries, and advances its round-robin primary once per request. For a
seed `A B C D`, successive responses contain:

| `EE_MQTT_HOST` | `EE_MQTT_HOSTS` |
| --- | --- |
| A | `["A", "B", "C", "D"]` |
| B | `["B", "C", "D", "A"]` |
| C | `["C", "D", "A", "B"]` |
| D | `["D", "A", "B", "C"]` |

The primary remains a string for older clients. The alternatives are an array
inside the existing signed dAuth response; SDK environment completion encodes it
as JSON. The raw allocation seed remains a supervisor-only key. If the seed is
missing or blank, dAuth uses `EE_MQTT_HOST` and sends a one-element list.

## Receiving nodes and SDK sessions

Core's `CommunicationManager` and SDK session setup forward `EE_MQTT_HOSTS` into
MQTT `HOSTS` when the effective primary matches `EE_MQTT_HOST`. Explicit `HOSTS`
takes precedence, including `[]` to disable alternatives. Other local or custom
broker configurations do not inherit the list.

The SDK `MQTTWrapper`, also used by Core, tries the primary first and advances
after a socket error, rejected CONNACK, or CONNACK timeout. Each call visits all
candidates at least once before returning failure, even with Core's default
burst budget of two. Failed client generations are stopped before replacement.
A successful endpoint stays selected for reconnects; there is no automatic move
back to the originally allocated primary. Selection is per communicator and
does not mutate the shared session configuration.

Wrapper connection logs and Core communication status show the active endpoint.
Heartbeat `COMM_RELAY` and SDK startup summaries still describe the allocated
primary, which can differ after failover.

Core retains its existing backoff and `WORK_OFFLINE`/retry-exhaustion behavior
after a failed burst. The broker list is resolved on the first connection and
requires restart to change. Message replay or guaranteed application execution
after disconnect is outside this contract.

All candidates must expose the same port, credentials, TLS trust settings, and
messaging network. Communicators and nodes can land on different members, so
the broker cluster or bridges must route messages between them.

## Rollout and rollback

1. Deploy the SDK failover implementation, then Core's list forwarding, to
   receiving nodes. Keep this pair together in runtime images.
2. Deploy Edge's dAuth list response. Older clients continue using the scalar
   primary; updated clients still support old single-host responses.
3. In staging, make the allocated primary unavailable from one receiving node.
   Verify connection and topic delivery through a later candidate, then verify
   subscriptions and delivery again after disconnect/reconnect. Confirm that
   messages cross broker members using the deployed cluster/bridge topology.
4. Verify the all-unavailable case returns to the existing backoff rather than
   leaking client threads or looping without a pause.

To disable alternatives, set `COMMUNICATION.PARAMS.HOSTS` to `[]` in the effective
node app configuration and restart. SDK sessions can likewise set `HOSTS: []`.
Reverting the receiver changes restores single-host behavior; the extra dAuth
field is backward compatible. No service or production configuration changes
are required by the source changes themselves.

## Verification

- Edge: `python -m unittest extensions.business.dauth.test_dauth_registry_gating`
  covers rotated four-broker responses, whitespace/duplicates, missing seeds,
  and existing supervisor key gating.
- SDK: `python -m unittest discover -s tests -p 'test_mqtt_*.py'` covers failover,
  generation cleanup, reconnects, subscriptions, and existing transport behavior.
  Set `EE_TEST_MQTT_HOST` and `EE_TEST_MQTT_PORT` only to an isolated test broker
  to enable real delivery/reconnect tests; otherwise those tests are skipped.
- Core: `python -m unittest naeural_core.business.test_framework.test_comm_heartbeat_policy`
  with the updated SDK covers runtime forwarding and explicit/custom host
  precedence.

Production cluster connectivity remains an operator staging check; automated
verification must not authenticate against or disrupt production brokers.
