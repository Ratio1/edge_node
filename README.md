# Ratio1 Edge Node

## Need, Objective, Purpose
- **Need**: Edge devices need a secure runtime that can join the Ratio1 network, execute pipelines, and expose operational APIs without manual broker/infrastructure assembly.
- **Objective**: Package a runnable node image plus extension/plugin surfaces so operators can run nodes and developers can add domain logic.
- **Purpose**: This repository is the edge-node layer that wires runtime entrypoints (`device.py`, `constants.py`) to upstream `naeural_core` and extends behavior through `extensions/` and `plugins/`.

## Usability & Features

### Quickstart

#### Prerequisites
- Docker (or Docker Desktop on Windows/macOS).
- A persistent Docker volume for `_local_cache`.
- A populated `.env` when running local source-based images (`debug.sh`).

#### Option A: Run official image (single node)
```bash
docker run -d --rm --name r1node --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:devnet
```

GPU host variant:
```bash
docker run -d --rm --name r1node --gpus all --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:devnet
```

Inspect and stop:
```bash
docker exec r1node get_node_info
docker stop r1node
```

#### Option B: Local source image (single node)
1. Copy `.env.template` to `.env` and fill required values.
2. Run:
```bash
./debug.sh
```

#### Option C: Local debug compose (3 nodes)
`docker-compose/debug-docker-compose.yaml` uses image `local_edge_node`, so build that tag first:
```bash
docker build -t local_edge_node -f Dockerfile_devnet .
docker-compose -f docker-compose/debug-docker-compose.yaml up -d
docker-compose -f docker-compose/debug-docker-compose.yaml down
```
If your Docker installation uses Compose v2 plugin syntax, use `docker compose` instead of `docker-compose`.

### Examples

#### Node operations
```bash
# Read node identity/status
docker exec r1node get_node_info

# Read node performance history
docker exec r1node get_node_history

# Authorize a client/node address to send work
docker exec r1node add_allowed <address> [alias]

# Update alias (restart required)
docker exec r1node change_alias <new_alias>
docker restart r1node
```

#### Multi-node orchestration
```bash
# Mainnet-oriented multi-node compose
docker-compose -f docker-compose/prod-docker-compose.yaml up -d
docker-compose -f docker-compose/prod-docker-compose.yaml down
```

#### Plugin/tutorial entry points
- Business tutorial plugins: `plugins/business/tutorials/`
- Data tutorial plugins: `plugins/data/tutorials/`
- Serving/model test scaffolding: `plugins/serving/model_testing/`

### Configuration

#### Environment template
Use `.env.template` as base for local/dev runs.

Key groups in `.env.template`:
- Node/runtime: `EE_ID`, `EE_SUPERVISOR`, `EE_DEVICE`
- MinIO/S3: `EE_MINIO_*`
- MQTT: `EE_MQTT_*`
- Tunnel/auth/token settings: `EE_NGROK_*`, `EE_GITVER`, `EE_OPENAI`, `EE_HF_TOKEN`

#### Startup and app config files
- `.config_startup.json`: default startup behavior.
- `.config_app.json`: communication/upload configuration.
- `.config_startup_cluster.json` + `.config_app_cluster.json`: cluster-oriented variants.

#### Network tags and Dockerfiles
- `Dockerfile_devnet` sets `EE_EVM_NET=devnet`
- `Dockerfile_testnet` sets `EE_EVM_NET=testnet`
- `Dockerfile_mainnet` sets `EE_EVM_NET=mainnet`

### Outputs

Most runtime artifacts are written under `_local_cache/` (mounted volume):
- Node identity/status JSON: `_local_cache/_data/local_info.json`
- Node history JSON: `_local_cache/_data/local_history.json`
- Allowed senders list: `_local_cache/authorized_addrs`
- Logs: `_local_cache/_logs/`
- Produced/downloaded files: `_local_cache/_output/`
- Model/cache data: `_local_cache/_models/`, `_local_cache/_data/`

### Troubleshooting

- `docker-compose` debug stack fails with image not found:
  - Cause: compose expects `local_edge_node`.
  - Fix: `docker build -t local_edge_node -f Dockerfile_devnet .`

- `debug.sh` and compose behave differently:
  - `debug.sh` builds/runs `local_node` directly.
  - debug compose files use `local_edge_node`.

- Windows helper `docker-compose/debug_start.bat` fails on Dockerfile:
  - It references `Dockerfile_dev` (not present in repo).
  - Use `Dockerfile_devnet` instead.

- `get_node_info`/`get_node_history` reports missing files:
  - Ensure container has started fully and `_local_cache` volume is mounted.

- Kubernetes manifests require manual validation before production use:
  - `k8s/README.md`, `k8s/edgenode-deploy.yaml`, `k8s/edgenode-sa.yaml`, and `k8s/edgenode-storage.yaml` contain naming/path mismatches that should be reconciled first.

## Technical Details

### Architecture
- `device.py` is the runtime entrypoint and calls `naeural_core.main.entrypoint.main(...)`.
- `constants.py` extends upstream admin pipeline constants and environment-driven app behavior.
- Core runtime execution contracts come from `naeural_core`; this repository is mainly extension/config packaging.

### Modules
- `extensions/business/`: web APIs and operational plugins (deeploy, dauth, oracle sync, tunnels, r1fs, container apps, cybersec, etc.).
- `extensions/data/`: listener/capture integrations.
- `extensions/serving/`: serving base classes and default inference adapters.
- `plugins/`: tutorial/sample business/data/serving modules.
- `cmds/`: in-container operational commands exposed as executables.
- `docker/`, `docker-compose/`, `k8s/`: deployment variants.

### Dependencies
- Python deps in `requirements.txt` (examples: `ratio1`, `kmonitor`, `decentra-vision`, OpenVINO/ONNX runtime packages, `sqlfluff`, `openai`, `ngrok`).
- Docker builds also install `naeural-core` (`pip install --no-deps naeural-core`).
- Typical cross-repo dev setup:
```bash
pip install -r requirements.txt
pip install -e ../naeural_core ../ratio1_sdk
```

### Testing
- Broad tutorial test discovery:
```bash
python3 -m unittest discover -s plugins -p "*test*.py"
```
- Focused suite example:
```bash
python3 -m unittest extensions.business.cybersec.red_mesh.test_redmesh
```
- For integration-sensitive changes, also run targeted tests in sibling repos (`naeural_core`, `ratio1_sdk`).

### Security
- Do not commit populated `.env` files.
- Keep credentials injected through env vars (`$EE_*`) instead of hardcoded values.
- Treat `cmds/reset_node_keys` and related key-reset commands as sensitive operations.
- Review `k8s/` secrets/config manifests before applying to any shared cluster.

## Related Repositories
- `ratio1/naeural_core`: upstream runtime engine and plugin contracts.
- `ratio1/ratio1_sdk`: SDK and client workflows used to submit workloads.

## Citation

If you use the Ratio1 Edge Node in your research or projects, please cite it as follows:

```bibtex
@misc{Ratio1EdgeNode,
  author = {Ratio1.AI},
  title = {Ratio1: Edge Node},
  year = {2024-2025},
  howpublished = {\url{https://github.com/Ratio1/edge_node}},
}
```

Additional publications and references:

```bibtex
@inproceedings{Damian2025CSCS,
  author    = {Damian, Andrei Ionut and Bleotiu, Cristian and Grigoras, Marius and
               Butusina, Petrica and De Franceschi, Alessandro and Toderian, Vitalii and
               Tapus, Nicolae},
  title     = {Ratio1 meta-{OS} -- decentralized {MLOps} and beyond},
  booktitle = {2025 25th International Conference on Control Systems and Computer Science (CSCS)},
  year      = {2025},
  pages     = {258--265},
  address   = {Bucharest, Romania},
  month     = {May 27--30},
  doi       = {10.1109/CSCS66924.2025.00046},
  isbn      = {979-8-3315-7343-0},
  issn      = {2379-0482},
  publisher = {IEEE}
}

@misc{Damian2025arXiv,
  title         = {Ratio1 -- AI meta-OS},
  author        = {Damian, Andrei and Butusina, Petrica and De Franceschi, Alessandro and
                   Toderian, Vitalii and Grigoras, Marius and Bleotiu, Cristian},
  year          = {2025},
  month         = {September},
  eprint        = {2509.12223},
  archivePrefix = {arXiv},
  primaryClass  = {cs.OS},
  doi           = {10.48550/arXiv.2509.12223}
}
```

## Contact

For further information, visit our website at [https://ratio1.ai](https://ratio1.ai) or reach out to us via email at [support@ratio1.ai](mailto:support@ratio1.ai).

## Project Financing Disclaimer

This project incorporates open-source components developed with the support of financing grants **SMIS 143488** and **SMIS 156084**, provided by the Romanian Competitiveness Operational Programme. We extend our gratitude for this support, which has been instrumental in advancing our work and enabling us to share these resources with the community.

The content and information within this repository reflect the authors' views and do not necessarily represent those of the funding agencies. The grants have specifically supported certain aspects of this open-source project, facilitating broader dissemination and collaborative development.

For inquiries regarding the funding and its impact on this project, please contact the authors directly.

## License
Apache 2.0. See `LICENSE`.
