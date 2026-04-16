# RedMesh Test Layers

This suite is intentionally layered so refactors can target one architecture boundary at a time.

## Repositories

- `test_repositories.py`

## Launch and Orchestration Services

- `test_launch_service.py`
- `test_state_machine.py`
- `test_api.py`
- `test_integration.py`
- `test_regressions.py`

## Workers and Graybox Runtime

- `test_base_worker.py`
- `test_worker.py`
- `test_auth.py`
- `test_discovery.py`
- `test_safety.py`
- `test_target_config.py`

## Probe Families

- `test_probes.py`
- `test_probes_access.py`
- `test_probes_business.py`
- `test_probes_injection.py`
- `test_probes_misconfig.py`

## Normalization and Contracts

- `test_normalization.py`
- `test_graybox_finding.py`
- `test_jobconfig_webapp.py`
- `test_contracts.py`
- `test_hardening.py`

## Suggested Layered Runs

```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest -q extensions/business/cybersec/red_mesh/tests/test_repositories.py
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest -q extensions/business/cybersec/red_mesh/tests/test_launch_service.py extensions/business/cybersec/red_mesh/tests/test_api.py extensions/business/cybersec/red_mesh/tests/test_integration.py extensions/business/cybersec/red_mesh/tests/test_regressions.py
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest -q extensions/business/cybersec/red_mesh/tests/test_worker.py extensions/business/cybersec/red_mesh/tests/test_auth.py extensions/business/cybersec/red_mesh/tests/test_discovery.py extensions/business/cybersec/red_mesh/tests/test_safety.py
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest -q extensions/business/cybersec/red_mesh/tests/test_normalization.py extensions/business/cybersec/red_mesh/tests/test_graybox_finding.py extensions/business/cybersec/red_mesh/tests/test_contracts.py
```
