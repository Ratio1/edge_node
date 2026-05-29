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
