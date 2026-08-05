ARG BASE_IMAGE=ratio1/base_edge_node_amd64_cpu:latest
FROM ${BASE_IMAGE}

ARG KUBO_VERSION=v0.35.0
RUN set -eux; \
    curl -fsSLo kubo.tar.gz https://dist.ipfs.tech/kubo/${KUBO_VERSION}/kubo_${KUBO_VERSION}_linux-amd64.tar.gz; \
    tar -xzf kubo.tar.gz; \
    cd kubo && bash install.sh; \
    cd / && rm -rf kubo kubo.tar.gz

WORKDIR /edge_node

COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt
RUN uv pip install --system --no-cache --no-deps naeural-core
RUN CMAKE_ARGS="-DGGML_CUDA=OFF" uv pip install --system --no-cache llama-cpp-python

COPY ./cmds /usr/local/bin/
RUN chmod +x /usr/local/bin/*

COPY . .
RUN rm -rf /edge_node/cmds

ENV AINODE_DOCKER=Yes
ENV AINODE_DOCKER_SOURCE=feat/per-node-biz-config
ENV EE_DD=0
ENV EE_CONFIG=.config_startup.json
ENV EE_ETH_ENABLED=false
ENV EE_EVM_NET=devnet
ENV EE_DEVICE=cpu

CMD ["python3", "device.py"]
