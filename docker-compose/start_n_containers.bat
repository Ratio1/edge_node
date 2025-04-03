@echo off
setlocal enabledelayedexpansion

REM DEPLOY DEBUG FLAGS
set DEPLOY_DEBUG=false
set USE_LOCAL_IMAGE=true


REM Hardcoded number of containers
set NUM_CONTAINERS=1
set NUM_SUPERVISORS=1


if !USE_LOCAL_IMAGE! == true (
    set CONTAINER_IMAGE=local_edge_node
) else (
    set CONTAINER_IMAGE=ratio1/edge_node:develop
)

if !DEPLOY_DEBUG! == true (
    set ENV_FILE=.env_deploy
    set CONFIG_FILE=.config_startup.json
    set GENERIC_CONTAINER_VOLUME=00debug_cluster/ratio1_0
) else (
    set ENV_FILE=.env_cluster
    set CONFIG_FILE=.config_startup_cluster.json
    set GENERIC_CONTAINER_VOLUME=00cluster/ratio1_0
)

REM Use command parameter to set if the containers will be repeered at start.
REM The default is false.
set PEER=false


REM Generic names for containers and edge nodes
set GENERIC_EDGE_NODE_ID=cr1en_
set GENERIC_CONTAINER_ID=ratio1_0
set GENERIC_WINDOW_TITLE=Cluster_Container

REM Loop through all arguments
for %%A in (%*) do (
    echo Argument: %%A
    if /i "%%A"=="--peer" (
        echo Found --peer argument
        set PEER=true
    )
)

REM Validate the PEER value
if /i "%PEER%" neq "true" if /i "%PEER%" neq "false" (
    echo Invalid value for --peer. Expected "true" or "false".
    exit /b 1
)

REM Watchtower service for automatic updates
set WATCHTOWER_IMAGE=containrrr/watchtower
set WATCHTOWER_CONTAINER=watchtower
set WATCHTOWER_LABEL=com.centurylinklabs.watchtower.enable=true

REM Generate the list of container IDs dynamically
for /l %%i in (1,1,%NUM_CONTAINERS%) do (
    REM Generic container ID and edge node ID
    set CONTAINER_IDS[%%i]=!GENERIC_CONTAINER_ID!%%i
    set EDGE_NODE_IDS[%%i]=!GENERIC_EDGE_NODE_ID!%%i
    set CONTAINER_VOLUMES[%%i]=!GENERIC_CONTAINER_VOLUME!%%i

    REM Check if the container is a supervisor
    if %%i leq %NUM_SUPERVISORS% (
        set CONTAINER_IS_SUPERVISOR[%%i]=true
    ) else (
        set CONTAINER_IS_SUPERVISOR[%%i]=false
    )
)


REM Generate docker-compose.yaml dynamically
echo services: > docker-compose.yaml
for /l %%i in (1,1,%NUM_CONTAINERS%) do (
    REM Generic container ID and edge node ID
    set CONTAINER_ID=!CONTAINER_IDS[%%i]!
    set EDGE_NODE_ID=!EDGE_NODE_IDS[%%i]!
    set CONTAINER_VOLUME=!CONTAINER_VOLUMES[%%i]!

    REM Generate the service for the container
    echo   !CONTAINER_ID!: >> docker-compose.yaml
    echo     image: !CONTAINER_IMAGE! >> docker-compose.yaml
@REM     echo     deploy: >> docker-compose.yaml
@REM     echo       resources: >> docker-compose.yaml
@REM     echo         limits: >> docker-compose.yaml
@REM     echo           cpus: '1' >> docker-compose.yaml
@REM     echo           memory: 4G >> docker-compose.yaml
    echo     container_name: !CONTAINER_ID! >> docker-compose.yaml
@REM     echo     restart: always >> docker-compose.yaml
    echo     environment: >> docker-compose.yaml
    REM The line below will use the EE_ID_0%%i from the !ENV_FILE! file.
    REM This can be done in case there need to be custom IDs for each container.
@REM     echo       EE_ID: ^${EE_ID_0%%i?You must set the EE_ID_0%%i environment variable^} >> docker-compose.yaml
    echo       EE_ID: !EDGE_NODE_ID! >> docker-compose.yaml
    echo       EE_SUPERVISOR: !CONTAINER_IS_SUPERVISOR[%%i]! >> docker-compose.yaml
    echo       EE_CONFIG: !CONFIG_FILE! >> docker-compose.yaml
    echo     env_file: !ENV_FILE! >> docker-compose.yaml
    echo     volumes: >> docker-compose.yaml
    echo       - ./!CONTAINER_VOLUME!:/edge_node/_local_cache >> docker-compose.yaml
    REM Empty line for readability
    echo. >> docker-compose.yaml

    REM Create directories for the volumes if they don't exist
    if not exist "!CONTAINER_VOLUME!" (
        mkdir "!CONTAINER_VOLUME!"
    )
)

REM Add the watchtower service
echo. >> docker-compose.yaml
echo   !WATCHTOWER_CONTAINER!: >> docker-compose.yaml
echo     image: !WATCHTOWER_IMAGE! >> docker-compose.yaml
@REM echo     container_name: !WATCHTOWER_CONTAINER! >> docker-compose.yaml
echo     volumes: >> docker-compose.yaml
echo       - /var/run/docker.sock:/var/run/docker.sock >> docker-compose.yaml
echo     environment: >> docker-compose.yaml
echo       - WATCHTOWER_CLEANUP=true >> docker-compose.yaml
echo       - WATCHTOWER_POLL_INTERVAL=60 # Check every 1 minute >> docker-compose.yaml
echo       - WATCHTOWER_CHECK_NEW_IMAGES=true >> docker-compose.yaml
echo       - WATCHTOWER_LABEL_ENABLE=true >> docker-compose.yaml
echo. >> docker-compose.yaml


REM Maybe unnecessary
@REM REM Empty line for readability
@REM echo. >> docker-compose.yaml
@REM echo volumes: >> docker-compose.yaml
@REM for /l %%i in (1,1,%NUM_CONTAINERS%) do (
@REM     echo   !CONTAINER_VOLUMES[%%i]!: >> docker-compose.yaml
@REM )

REM Pull the containers
docker-compose pull

REM Start the containers
docker-compose up -d

REM Wait for a moment to ensure containers are up
timeout /t 5 /nobreak >nul

REM Open logs for each container in a separate PowerShell window
for /l %%i in (1,1,%NUM_CONTAINERS%) do (
    set TITLE_SET_COMMAND=$host.ui.RawUI.WindowTitle = '!GENERIC_WINDOW_TITLE! !CONTAINER_IDS[%%i]!'
    start powershell -NoExit -Command "!TITLE_SET_COMMAND!; docker-compose logs -f -n 1000 !CONTAINER_IDS[%%i]!"
)

echo Containers are starting, and logs are being followed...
echo For stopping the containers, run the stop.bat script.

if /i "%PEER%" neq "true" (
    echo Peering is disabled. To enable peering, run the peer_n_containers.bat script with `--peer` flag.
    exit /b 0
)

REM Wait for a moment to ensure containers are up and the local_address.txt files are generated
echo Waiting for containers to start in order to peer them...
timeout /t 10 /nobreak >nul

REM Peering containers
echo Peering containers...

SET PATH_TO_LOCAL_ADDRESS_FILE_TXT=/edge_node/_local_cache/_data/local_address.txt
SET PATH_TO_LOCAL_ADDRESS_FILE_JSON=/edge_node/_local_cache/_data/local_info.json
REM The old format of the local_address file is a text file.
SET USE_JSON_FILE=true
REM Define the Python code as a variable for parsing the JSON
set "PYTHON_CODE=import json, sys; data = json.load(sys.stdin); print(data['address'], data['alias'])"

REM Loop over containers to extract local_address.txt and parse it.
for /l %%i in (1, 1, %NUM_CONTAINERS%) do (
    if %USE_JSON_FILE% == true (
        REM Parse the local_address.json file.
        echo Extracting local address for container !EDGE_NODE_IDS[%%i]! from !PATH_TO_LOCAL_ADDRESS_FILE_JSON!

        REM Use Python to extract address and alias from local_address.json
        for /f "delims=" %%a in ('docker exec !CONTAINER_IDS[%%i]! sh -c "cat !PATH_TO_LOCAL_ADDRESS_FILE_JSON! | python3 -c \"!PYTHON_CODE!\""') do (
            REM Store the address in the NODE_ADDRESSES array.
            set NODE_ADDRESSES[%%i]=%%a
        )
    ) else (
        REM This is for the old format of the local_address file. Only left for backward compatibility.
        REM Parse the container's local_address.txt file.
        echo Extracting local address for container !EDGE_NODE_IDS[%%i]! from !PATH_TO_LOCAL_ADDRESS_FILE_TXT!
        for /f "tokens=1,2" %%a in ('docker exec !CONTAINER_IDS[%%i]! cat !PATH_TO_LOCAL_ADDRESS_FILE_TXT!') do (
            REM Store the address in the NODE_ADDRESSES array.
            set NODE_ADDRESSES[%%i]=%%a
        )
    )
    echo Local address for container !EDGE_NODE_IDS[%%i]!: !NODE_ADDRESSES[%%i]!
)

echo Local addresses for all containers:

REM Generate authorized_addrs file for each container
for /l %%i in (1, 1, %NUM_CONTAINERS%) do (
    REM Set the path to the authorized_addrs file
    set AUTH_PATH="./!CONTAINER_VOLUMES[%%i]!/authorized_addrs"

    REM Clear the file.
    echo. > !AUTH_PATH!

    echo Authorized addresses for container !EDGE_NODE_IDS[%%i]!:

    REM Iterate through all the containers
    for /l %%j in (1, 1, %NUM_CONTAINERS%) do (
        if %%i==%%j (
            REM Skip the current container
        ) else (
            if !CONTAINER_IS_SUPERVISOR[%%j]! == true (
                REM Supervisors are always authorized
                echo   !NODE_ADDRESSES[%%j]!  !EDGE_NODE_IDS[%%j]!
                echo !NODE_ADDRESSES[%%j]!  !EDGE_NODE_IDS[%%j]! >> !AUTH_PATH!
            ) else (
                REM Custom logic for authorizing non-supervisor containers.
                set /a i_parity=%%i %% 2
                set /a j_parity=%%j %% 2
                if !i_parity! == !j_parity! (
                    REM Containers with the same parity are authorized
                    echo   !NODE_ADDRESSES[%%j]!  !EDGE_NODE_IDS[%%j]!
                    echo !NODE_ADDRESSES[%%j]!  !EDGE_NODE_IDS[%%j]! >> !AUTH_PATH!
                )
            )
        )
    )
)


echo Peering is complete. In case of peering issues, try running the peer_n_containers.bat script with the correct NUM_CONTAINERS and NUM_SUPERVISORS values.
echo For stopping the containers, run the stop.bat script.
