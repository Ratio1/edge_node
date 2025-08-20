
setlocal enabledelayedexpansion

REM Stop the containers
docker-compose stop

echo Done.

timeout /t 5 /nobreak >nul

echo Exiting script.