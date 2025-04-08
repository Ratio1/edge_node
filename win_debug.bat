docker build -t local_edge_node -f Dockerfile_devnet .
docker run --rm --privileged --gpus=all -v r1v_devnet:/edge_node/_local_cache local_edge_node