#FROM ratio1/base_edge_node:x86_64-py3.10.12-th2.3.1.cu121-tr4.43.3-d
FROM ratio1/base_edge_node:x86_64-py3.10.12-th2.3.1.cu121-tr4.43.3-dnctk

# Install IPFS
# The line below was creating issues due to flaky external repos
# RUN apt-get update && apt-get install -y wget && apt-get install -y tar
# Install tools needed for the next steps without hitting flaky external repos
RUN set -eux; \
    # disable NodeSource (if present) so apt won't read it
    rm -f /etc/apt/sources.list.d/nodesource*.list /etc/apt/sources.list.d/nodesource*.sources || true; \
    apt-get update -o Acquire::Retries=3; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    wget tar ca-certificates \
    ninja-build; \
    rm -rf /var/lib/apt/lists/*
         
RUN wget https://dist.ipfs.tech/kubo/v0.32.1/kubo_v0.32.1_linux-amd64.tar.gz && \
  tar -xvzf kubo_v0.32.1_linux-amd64.tar.gz && \
  cd kubo && \
  bash install.sh
# End Install IPFS

# Install Cloudflared
ARG CLOUDFLARED_VERSION=2025.7.0

RUN set -eux; \
    # --- map architecture names to Cloudflare’s file names -------
    arch="$(uname -m)";                     \
    case "$arch" in                         \
      x86_64)  arch=amd64  ;;               \
      aarch64 | arm64) arch=arm64 ;;        \
      armv7l)  arch=armv7  ;;               \
      *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac;                                   \
    # --- download the pinned release --------------------------------
    curl -L "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${arch}" \
         -o /usr/local/bin/cloudflared;     \
    chmod +x /usr/local/bin/cloudflared;    \
    # --- (optional) show version so it appears in build logs --------
    cloudflared --version
# End Install Cloudflared

# COPY ./cmds /usr/local/bin/
# RUN chmod +x /usr/local/bin/*

RUN npm install -g @openai/codex

WORKDIR /edge_node
#COPY . .
COPY requirements.txt .
# RUN rm -rf /edge_node/cmds

# set a generic env variable 
ENV AINODE_DOCKER=Yes
# set a generic env variable 
ENV AINODE_DOCKER_SOURCE=develop
# set default Execution Engine id
ENV EE_ID=E2dkr
# Temporary fix:
ENV AINODE_ENV=$AI_ENV
ENV AINODE_ENV_VER=$AI_ENV_VER
# configure default config_startup file
ENV EE_CONFIG=.config_startup.json

ENV EE_ETH_ENABLED=true
ENV EE_HB_CONTAINS_PIPELINES=0
ENV EE_HB_CONTAINS_ACTIVE_PLUGINS=1
ENV EE_EPOCH_MANAGER_DEBUG=1

ENV EE_NETMON_ADDRESS_INDEX=true
ENV EE_NETMON_SEND_CURRENT_NETWORK_EACH=50
ENV EE_NETMON_SEND_ONLY_ONLINE=true

ENV EE_EVM_NET=devnet


# also can use EE_DEVICE to define target such as cuda:0 or cuda:1 instead of cpu
# althouh this is not recommended as it should be in .env file
# ENV EE_DEVICE=cuda:0

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir --no-deps --upgrade naeural_core

RUN pip install --no-cache-dir --no-deps --force-reinstall \
    llama-cpp-python \
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu

CMD ["python3","device.py"]
