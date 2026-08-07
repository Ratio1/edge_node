# CockroachDB Verify-Full Testbed

This local-only bed starts three real edge runtimes on a private broker. The
validator then uses the edge certificate-preparation helper and the published
CockroachDB service image to run a three-node SQL cluster on the same isolated
network. No dAuth, Cloudflare, remote node, or live Deeploy resource is used.

Run from the `edge_node` worktree root:

```bash
docker compose -f docker-compose/deeploy-crdb-verify-full.yaml config --quiet
docker compose -f docker-compose/deeploy-crdb-verify-full.yaml up -d --build
PYTHONPATH=/mnt/c/repos/naeural_client:. /home/bleot/venvs/umbrella313/bin/python \
  docker-compose/deeploy-crdb-verify-full/validate_workflow.py
docker compose -f docker-compose/deeploy-crdb-verify-full.yaml down -v --remove-orphans
```

The validator checks DNS hostname verification, wrong-host/wrong-CA/plaintext
rejection, password authentication, three-node membership, data persistence
across full certificate regeneration, delayed third-node convergence, and a
packet capture with unique SQL canaries. It deletes raw captures, certificates,
containers, networks, and CockroachDB stores before exiting.

The direct SQL runtime is deliberate: it isolates the certificate and wire
contract from Cloudflare availability while still using the exact published
CockroachDB binary image. Certificates are produced through the production
secure-config preparation path and consumed from its emitted per-node overlays.
Manager update/replay behavior and dapp payload construction are covered by
focused tests; this bed does not simulate wallet payment/signing or dispatch the
database containers through live Container App Runner instances.
