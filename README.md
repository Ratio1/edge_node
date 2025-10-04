# Ratio1 Edge Node 

Welcome to the **Ratio1 Edge Node** repository, formerly known as the **Naeural Edge Protocol Edge Node**. As a pivotal component of the Ratio1 ecosystem, this Edge Node software empowers a decentralized, privacy-preserving, and secure edge computing network. By enabling a collaborative network of edge nodes, Ratio1 facilitates the secure sharing of resources and the seamless execution of computation tasks across diverse devices.

Documentation sections:
- [Introduction](#introduction)
- [Running the Edge Node](#running-the-edge-node)
- [Inspecting the Edge Node](#inspecting-the-edge-node)
- [Adding an Allowed Address](#adding-an-allowed-address)
- [Inspecting the node performance](#inspecting-the-node-performance)
- [Reset the Edge Node address](#reset-the-edge-node-address)
- [Changing the alias of the node](#changing-the-alias-of-the-node)
- [Stopping the Edge Node](#stopping-the-edge-node)
- [Running multiple nodes on the same machine](#running-multiple-nodes-on-the-same-machine)


## Introduction

The Ratio1 Edge Node is a meta Operating System designed to operate on edge devices, providing them the essential functionality required to join and thrive within the Ratio1 network. Each Edge Node manages the device’s resources, executes computation tasks efficiently, and communicates securely with other nodes in the network. Leveraging the powerful Ratio1 core libraries (formely known as Naeural Edge Protocol libraries) `naeural_core` and `ratio1`— the Ratio1 Edge Node offers out-of-the-box usability starting in 2025. Users can deploy the Edge Node and SDK (`ratio1`) effortlessly without the need for intricate configurations, local subscriptions, tenants, user accounts, passwords, or broker setups.

## Related Repositories

- [ratio1/naeural_core](https://github.com/ratio1/naeural_core) provides the modular pipeline engine that powers data ingestion, processing, and serving inside this node. Extend or troubleshoot runtime behavior by mirroring the folder layout in `extensions/` against the upstream modules.
- [Ratio1/ratio1_sdk](https://github.com/Ratio1/ratio1_sdk) is the client toolkit for building and dispatching jobs to Ratio1 nodes. Its tutorials pair with the workflows in `plugins/business/tutorials/` and are the best place to validate end-to-end scenarios.

When developing custom logic, install the three repositories in the same virtual environment (`pip install -e . ../naeural_core ../ratio1_sdk`) so interface changes remain consistent across the stack.

## Running the Edge Node

> Note on requirements: the minimal hardware requirements to run a Ratio1 Edge Node are a 64-bit CPU, 6GB of RAM, 2 cores (vCores just fine) and 10GB of storage. The Edge Node is compatible with Linux, Windows, and macOS operating systems. Make sure you have Docker installed on your machine before proceeding so for Windows and Mac probably you will need to install Docker Desktop.


Deploying a Ratio1 Edge Node within a development network is straightforward. Execute the following Docker command to launch the node making sure you mount a persistent volume to the container to preserve the node data between restarts:

```bash
docker run -d --rm --name r1node --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:develop
```

- `-d`: Runs the container in the background.
- `--rm`: Removes the container upon stopping.
- `--name r1node`: Assigns the name `r1node` to the container.
- `--pull=always`: Ensures the latest image version is always pulled.
- `ratio1/edge_node:develop`: Specifies the Docker image to run.
- `-v r1vol:/edge_node/_local_cache/`: Mounts the `r1vol` volume to the `/edge_node/_local_cache/` directory within the container.

This command initializes the Ratio1 Edge Node in development mode, automatically connecting it to the Ratio1 development network and preparing it to receive computation tasks while ensuring that all node data is stored in `r1vol`, preserving it between container restarts.


If for some reason you encounter issues when running the Edge Node, you can try to run the container with the `--platform linux/amd64` flag to ensure that the container runs on the correct platform.

```bash
docker run -d --rm --name r1node --platform linux/amd64 --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:develop
```
Also, if you have GPU(s) on your machine, you can enable GPU support by adding the `--gpus all` flag to the Docker command. This flag allows the Edge Node to utilize the GPU(s) for computation tasks.

```bash
docker run -d --rm --name r1node --gpus all --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:develop
```

This will ensure that your node will be able to utilize the GPU(s) for computation tasks and will accept training and inference jobs that require GPU acceleration.

### Running multiple Edge Nodes on the same machine

If you want to run multiple Edge Nodes on the same machine, you can do so by specifying different names for each container but more importantly, you need to specify different volumes for each container to avoid conflicts between the nodes. You can do this by creating a new volume for each node and mounting it to the container as follows:

```bash
docker run -d --rm --name r1node1 --pull=always -v r1vol1:/edge_node/_local_cache/ ratio1/edge_node:develop
docker run -d --rm --name r1node2 --pull=always -v r1vol2:/edge_node/_local_cache/ ratio1/edge_node:develop
```

Now you can run multiple Edge Nodes on the same machine without any conflicts between them.
>NOTE: If you are running multiple nodes on the same machine it is recommended to use docker-compose to manage the nodes. You can find an example of how to run multiple nodes on the same machine using docker-compose in the [Running multiple nodes on the same machine](#running-multiple-nodes-on-the-same-machine) section.


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

If you have multiple nodes running on the same machine, you can inspect the status of each node by specifying the node name in the command:

```bash
docker exec r1node1 get_node_info
docker exec r1node2 get_node_info
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

## Developing With the Ratio1 SDK

The [Ratio1 SDK](https://github.com/Ratio1/ratio1_sdk) is the recommended way to build, test, and ship workloads to your node. Install it alongside the edge node source:

```bash
pip install -e ../ratio1_sdk
```

- Use the `nepctl` (formerly `r1ctl`) CLI that ships with the SDK to inspect the network, configure clients, and dispatch jobs.
- Explore `ratio1_sdk/tutorials/` for end-to-end examples; most have matching runtime counterparts in `plugins/business/tutorials/` inside this repository.
- SDK releases 2.6+ perform automatic dAuth configuration. After whitelisting your client, you can submit jobs without additional secrets.

## Extending Pipelines With naeural_core

Edge node execution relies on the [ratio1/naeural_core](https://github.com/ratio1/naeural_core) package. When building custom data sources or business logic:

- Mirror the structure of `naeural_core` modules (`data`, `serving`, `business`, etc.) under `extensions/` so plugin discovery stays consistent.
- Develop and run unit tests in the cloned `naeural_core` repository before importing the new module here; its abstractions (`manager.Manager`, `CustomPluginTemplate`, etc.) define the contracts used by `device.py`.
- Keep configuration defaults in sync by reusing `naeural_core/constants.py` values or extending them via local `CONFIG` dictionaries.

## Inspecting the node performance

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

Lets suppose you have the following node data:

```bash
>docker exec r1node get_node_info

{
  "address": "0xai_A6sQdZKb_kqpE4yfFEpLrOwK3dRh-NL6qaWHUUY45LAp",
  "alias": "sold-mile-70",
  "eth_address": "0x2Be13d18ab1Dcdaf48bBC3477881E3695AEb95F3",
  "version_long": "v2.6.19 | core v7.6.0 | SDK 2.6.23",
  "version_short": "v2.6.19",
  "info": {
    "whitelist": [
      "0xai_AthDPWc_k3BKJLLYTQMw--Rjhe3B6_7w76jlRpT6nDeX"
    ]
}
```

If for any reason you need to reset the node address, you can do so by executing the following command:

```bash
docker exec r1node reset_node_keys
docker restart r1node
```

following this you can check the node info again and you will see that the address has been reset.

```bash
docker exec r1node get_node_info
{
  "address": "0xai_ApM1AbzLq1VtsLIidmvzt1Nv4Cyl5Wed0fHNMoZv9u4X",
  "alias": "sold-mile-70",
  "eth_address": "0x417a73B7E4971BcefaAe46981ad177C417928371",
  "version_long": "v2.6.19 | core v7.6.0 | SDK 2.6.23",
  "version_short": "v2.6.19",
  "info": {
    "whitelist": [
      "0xai_AthDPWc_k3BKJLLYTQMw--Rjhe3B6_7w76jlRpT6nDeX"
    ]
}
```

## Changing the alias of the node

Although the alias is not really used most of the time some users might want to change it. To do so you can run the following command:

```bash
docker exec r1node change_alias <new_alias>
```

Then you have to restart your node for the changes to take effect:

```bash
docker restart r1node
```


## Stopping the Edge Node

To gracefully stop and remove the Ratio1 Edge Node container, use:

```bash
docker stop r1node
```

This command halts the container and ensures it is removed from the system.


## Running multiple nodes on the same machine

If you want to run multiple nodes on the same machine the best option is to use docker-compose. You can create a `docker-compose.yml` file with the following content:

```yaml
services:
  r1node1:
    image: ratio1/edge_node:testnet
    container_name: r1node1
    platform: linux/amd64
    restart: always
    volumes:
      - r1vol1:/edge_node/_local_cache
    labels:
      - "com.centurylinklabs.watchtower.enable=true"         
      - "com.centurylinklabs.watchtower.stop-signal=SIGINT"          

  r1node2:
    image: ratio1/edge_node:testnet
    container_name: r1node2
    platform: linux/amd64
    restart: always
    volumes:
      - r1vol2:/edge_node/_local_cache
    labels:
      - "com.centurylinklabs.watchtower.enable=true"         
      - "com.centurylinklabs.watchtower.stop-signal=SIGINT"          

  #  you can add other nodes here ...

  watchtower:
    image: containrrr/watchtower
    platform: linux/amd64
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_POLL_INTERVAL=60 # Check every 1 minute
      - WATCHTOWER_CHECK_NEW_IMAGES=true      
      - WATCHTOWER_LABEL_ENABLE=true  

volumes:
  r1vol1:
  r1vol2:
  # you can add other volumes here ...      
```

If you are using MacOS (M1 or better) we recommend to use the arm64 image for the watchtower service. You can do so by changing the image to `containrrr/watchtower:arm64v8-latest` in the `docker-compose.yml` file.

Then you can run the following command to start the nodes in the folder where the `docker-compose.yml` file is located:

```bash
docker-compose up -d
```

If you want to always pull the latest image you can add the `--pull=always` flag to the `docker-compose up` command.

```bash
docker-compose up -d --pull=always
```

and you can stop the nodes by running in the same folder:

```bash
docker-compose down
```


Now, lets dissect the `docker-compose.yml` file:
  - we have a variable number of nodes - in our case 2 nodes - `r1node1` and `r1node2` as services (we commented out the third node for simplicity)
  - each node is using the `ratio1/edge_node:testnet` image
  - each node has own unique volume mounted to it
  - we have a watchtower service that will check for new images every 1 minute and will update the nodes if a new image is available

>NOTE: Please note that running multiple nodes on same box is not advised for machine that do not have multiple GPUs and plenty of RAM. 


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
  howpublished = {\url{https://github.com/Ratio1/edge_node}},
}
```
