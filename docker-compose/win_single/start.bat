@echo off

REM Pull the latest images
docker-compose pull

REM Start the containers
docker-compose up -d

echo Containers are starting...
