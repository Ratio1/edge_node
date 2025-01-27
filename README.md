# Ratio1 Edge Node (Naeural Edge Protocol Edge Node)

Welcome to the **Ratio1 Edge Node** repository, formerly known as the **Naeural Edge Protocol Edge Node**. As a pivotal component of the Ratio1 ecosystem, this Edge Node software empowers a decentralized, privacy-preserving, and secure edge computing network. By enabling a collaborative network of edge nodes, Ratio1 facilitates the secure sharing of resources and the seamless execution of computation tasks across diverse devices.

## Introduction

The Ratio1 Edge Node is a meta Operating System designed to operate on edge devices, providing them the essential functionality required to join and thrive within the Ratio1 network. Each Edge Node manages the device’s resources, executes computation tasks efficiently, and communicates securely with other nodes in the network. Leveraging the powerful Ratio1 core libraries (formely knwon as Naeural Edge Protocol libraries) `naeural_core` and `naeural_client`— the Ratio1 Edge Node offers out-of-the-box usability starting in 2025. Users can deploy the Edge Node and SDK (`naeural_client`) effortlessly without the need for intricate configurations, local subscriptions, tenants, user accounts, passwords, or broker setups.

## Running the Edge Node

> Note on requirements: the minimal hardware requirements to run a Ratio1 Edge Node are a 64-bit CPU, 6GB of RAM, 2 cores (vCores just fine) and 10GB of storage. The Edge Node is compatible with Linux, Windows, and macOS operating systems. Make sure you have Docker installed on your machine before proceeding so for Windows and Mac probably you will need to install Docker Desktop.


Deploying a Ratio1 Edge Node within a development network is straightforward. Execute the following Docker command to launch the node making sure you mount a persistent volume to the container to preserve the node data between restarts:

```bash
docker run -d --rm -name r1node --pull=always -v r1vol:/edge_node/_local_cache/ naeural/edge_node:develop
```

- `-d`: Runs the container in the background.
- `--rm`: Removes the container upon stopping.
- `--name r1node`: Assigns the name `r1node` to the container.
- `--pull=always`: Ensures the latest image version is always pulled.
- `naeural/edge_node:develop`: Specifies the Docker image to run.
- `-v r1vol:/edge_node/_local_cache/`: Mounts the `r1vol` volume to the `/edge_node/_local_cache/` directory within the container.

This command initializes the Ratio1 Edge Node in development mode, automatically connecting it to the Ratio1 development network and preparing it to receive computation tasks while ensuring that all node data is stored in `r1vol`, preserving it between container restarts.

If for some reason you encounter issues when running the Edge Node, you can try to run the container with the `--platform linux/amd64` flag to ensure that the container runs on the correct platform.

```bash
docker run -d --rm --name r1node --platform linux/amd64 --pull=always -v r1vol:/edge_node/_local_cache/ naeural/edge_node:develop
```
Also, if you have GPU(s) on your machine, you can enable GPU support by adding the `--gpus all` flag to the Docker command. This flag allows the Edge Node to utilize the GPU(s) for computation tasks.

```bash
docker run -d --rm --name r1node --gpus all --pull=always -v r1vol:/edge_node/_local_cache/ naeural/edge_node:develop
```

This will ensure that your node will be able to utilize the GPU(s) for computation tasks and will accept training and inference jobs that require GPU acceleration.


## Inspecting the Edge Node

After launching the Ratio1 Edge Node, you can inspect its status and view its self-generated identity by executing:

```bash
docker exec r1node get_node_info
```

This command retrieves comprehensive information about the node, including its current status and unique identity within the network such as below
```json
{
  "address": "0xai_A2pPf0lxZSZkGONzLOmhzndncc1VvDBHfF-YLWlsrG9m",
  "alias": "5ac5438a2775",
  "eth_address": "0xc440cdD0BBdDb5a271de07d3378E31Cb8D9727A5",
  "version_long": "v2.5.36 | core v7.4.23 | SDK 2.6.15",
  "version_short": "v2.5.36",
  "info": {
    "whitelist": []
  }
}
```

## Adding an Allowed Address

To authorize a specific address—such as an SDK address—to send computation tasks to your node, add it to the node’s whitelist with the following command:

```bash
docker exec r1node add_allowed <address> [<alias>]
```

- `<address>`: The address of the SDK permitted to send computation tasks to the node.
- `<alias>`: (Optional) A friendly alias for the address.

Upon execution, the node’s status will update, indicating that it is now ready to accept computation tasks from the specified SDK or Edge Node address.

Running the command with valid node address and alias:

```bash
docker exec r1node add_allowed 0xai_AthDPWc_k3BKJLLYTQMw--Rjhe3B6_7w76jlRpT6nDeX some-node-alias
```
will result in a result such as:

```json
{
  "address": "0xai_A2pPf0lxZSZkGONzLOmhzndncc1VvDBHfF-YLWlsrG9m",
  "alias": "5ac5438a2775",
  "eth_address": "0xc440cdD0BBdDb5a271de07d3378E31Cb8D9727A5",
  "version_long": "v2.5.36 | core v7.4.23 | SDK 2.6.15",
  "version_short": "v2.5.36",
  "info": {
    "whitelist": [
      "0xai_AthDPWc_k3BKJLLYTQMw--Rjhe3B6_7w76jlRpT6nDeX"
    ]
  }
}
```

## Inspecting the node performance / load history

To inspect the node's performance and load history, execute the following command:

```bash
docker exec r1node get_node_history
```

This command will output a raw JSON that can be parsed for detailed information about the node's performance and load history.
```json
{
    "cpu_load": [
        15.9,
        15.8
    ],
    "cpu_temp": [
        null,
        null
    ],
    "epoch": 21,
    "epoch_avail": 0.0024,
    "gpu_load": [
        null,
        null
    ],
    "gpu_occupied_memory": [
        null,
        null
    ],
    "gpu_total_memory": [
        null,
        null
    ],
    "occupied_memory": [
        12.1,
        12.1
    ],
    "timestamps": [
        "2025-01-24 22:03:29.809281",
        "2025-01-24 22:03:49.890208"
    ],
    "total_memory": [
        15.6,
        15.6
    ],
    "uptime": "06:18:03",
    "version": "2.6.1"
}
```

In the above example we expanded the JSON into a human readable format for better understanding. 

## Reset the Edge Node address

If for any reason you need to reset the node address, you can do so by executing the following command:

```bash
docker exec r1node reset_node_keys
```

## Stopping the Edge Node

To gracefully stop and remove the Ratio1 Edge Node container, use:

```bash
docker stop r1node
```

This command halts the container and ensures it is removed from the system.

## License

This project is licensed under the **Apache 2.0 License**. For detailed information, please refer to the [LICENSE](LICENSE) file.

## Contact

For further information, visit our website at [https://ratio1.ai](https://ratio1.ai) or reach out to us via email at [support@ratio1.ai](mailto:support@ratio1.ai).

## Project Financing Disclaimer

This project incorporates open-source components developed with the support of financing grants **SMIS 143488** and **SMIS 156084**, provided by the Romanian Competitiveness Operational Programme. We extend our gratitude for this support, which has been instrumental in advancing our work and enabling us to share these resources with the community.

The content and information within this repository reflect the authors' views and do not necessarily represent those of the funding agencies. The grants have specifically supported certain aspects of this open-source project, facilitating broader dissemination and collaborative development.

For inquiries regarding the funding and its impact on this project, please contact the authors directly.

## Citation

If you use the Ratio1 Edge Node in your research or projects, please cite it as follows:

```bibtex
@misc{Ratio1EdgeNode,
  author = {Ratio1.AI},
  title = {Ratio1: Edge Node},
  year = {2024-2025},
  howpublished = {\url{https://github.com/NaeuralEdgeProtocol/edge_node}},
}
```
