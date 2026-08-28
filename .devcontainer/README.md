# Edge Node Development Container

The development container provides the repository's intended Python and system-tool environment. The
host checkout is bind-mounted at `/edge_node`; source files are not copied into the image.

## Configuration

- `devcontainer.json` uses `.devcontainer/Dockerfile` with the repository root as its build context.
- The container and hostname are both fixed to `r1edge`, and Docker is started with `--privileged`.
  Inspect existing containers before starting another checkout because the fixed name can conflict.
- The default configuration is CPU-oriented. GPU access is shown only as a commented example and is
  not enabled by the checked-in configuration.
- The Dockerfile follows the mutable `ratio1/base_edge_node_amd64_cpu:latest` base image used by the
  runtime Dockerfiles. A rebuild can therefore change the environment even without a repository diff.
- The Dockerfile installs the root `requirements.txt`, upgrades `naeural_core`, and adds development
  tools including Kubo, Cloudflared, Ninja, and Codex.
- `.devcontainer/requirements.txt` is currently unused by both `devcontainer.json` and the Dockerfile.
  Changing it alone does not change the image.

## Build and Start

Run commands from the repository root:

```bash
devcontainer read-configuration --workspace-folder . --include-merged-configuration
devcontainer build --workspace-folder .
devcontainer up --workspace-folder .
```

The first command validates and displays the resolved configuration without building the image. Use a
full rebuild after changes to `.devcontainer/Dockerfile`, `devcontainer.json`, or root
`requirements.txt`, and when validating a newer mutable base image.

## Verify the Environment

After the container starts, verify the actual interpreter and core imports rather than relying on the
base-image tag:

```bash
devcontainer exec --workspace-folder . python3 --version
devcontainer exec --workspace-folder . \
  python3 -c "import naeural_core, ratio1; print('core imports ok')"
```

Python 3.13 is the current expectation, but this repository does not pin the interpreter independently
of the mutable base image. Record the observed version and image/build context when reporting an
environment-sensitive result.

For broader repository commands and safety boundaries, return to the root [`AGENTS.md`](../AGENTS.md).
