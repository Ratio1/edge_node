FROM aidamian/base_edge_node:x86_64-py3.10.12-th2.3.1.cu121-tr4.43.3


COPY ./cmds /usr/local/bin/
RUN chmod +x /usr/local/bin/*


WORKDIR /edge_node
COPY . .
RUN rm -rf /edge_node/cmds

# set a generic env variable 
ENV AINODE_DOCKER=Yes
# set a generic env variable 
ENV AINODE_DOCKER_SOURCE=main
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

ENV EE_DAUTH_URL=https://dauth-main.ratio1.ai/get_auth_data

#### TO BE REMOVED AND TESTED !!!
ENV TZ=Europe/Bucharest
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
#### END TO BE REMOVED

# also can use EE_DEVICE to define target such as cuda:0 or cuda:1 instead of cpu
# althouh this is not recommended as it should be in .env file
# ENV EE_DEVICE cuda:0

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir --no-deps naeural-core

CMD ["python3","device.py"]
