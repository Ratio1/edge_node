# Deeploy Delete Testbed

This local-only testbed validates Deeploy delete command emission against two
running edge nodes and a private Mosquitto broker.

Run from the repository root:

```bash
docker compose -f docker-compose/deeploy-testbed.yaml up -d --build
PYTHONPATH=/mnt/c/repos/naeural_core:/mnt/c/repos/naeural_client:. /home/bleot/venvs/umbrella313/bin/python docker-compose/deeploy-testbed/validate_delete_workflow.py
docker compose -f docker-compose/deeploy-testbed.yaml down -v
```

The validation script creates one Deeploy-like multi-plugin app pipeline on
each local node, calls the real `delete_pipeline_from_nodes()` path, and asserts
that each node receives exactly one `DELETE_CONFIG` for the app.

The app uses testbed-only data/business plugins mounted into the node containers
under the normal root plugin search paths.

The compose stack intentionally overrides the node command with
`device_no_extra_packages.py` so this minimal config-command workflow does not
spend startup time building optional serving packages. The containers still use
`Dockerfile_devnet` and still run `naeural_core.main.entrypoint.main()`, so
comms, config handling, plugin loading, stream create/delete, and command
processing are exercised by real local nodes.

Mosquitto is used here as the smallest private MQTT broker needed to validate
the Deeploy command path. This testbed does not claim EMQX parity and does not
cover EMQX auth, ACL, retained/session behavior, or production backpressure
tuning.

`EE_DAUTH_URL` is set to `N/A` in compose to avoid contacting live dAuth/Cap
services during local validation.

## Same-host update and rollback

Run the rehearsal from the Edge checkout with the matching Core and SDK source paths, an Edge development Python environment and a local image containing Git, Python 3 and a shell.

```bash
export DEEPLOY_TEST_IMAGE='your-local-image-id'
export PYTHONPATH=".:$CORE_CHECKOUT:$SDK_CHECKOUT:$CORE_CHECKOUT/naeural_core/business/test_framework"
python -c 'import seaborn, runpy; runpy.run_path("docker-compose/deeploy-testbed/validate_same_host_repair.py", run_name="__main__")'
```

The script drives the coordinator and dAuth through a successful update and a forced process failure. It checks live HTTP responses, Git commits and command order on two disposable workers, including after rollback. The SDK encrypts and decrypts the configuration challenge with disposable keys. A local mock connector checks the rotated credential. Command transport, receipt signing, the ledger, R1FS and ChainStore use test doubles. Docker runs on the host and the test removes its own containers on exit.
