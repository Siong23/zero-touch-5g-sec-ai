@echo off
REM deploy_docker.bat - Docker deployment script for Windows

echo Starting AEGIS-5G Docker deployment...

REM Check if Docker is running
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not installed or not running
    echo Please install Docker Desktop and make sure it's running
    pause
    exit /b 1
)

REM Create necessary directories for volume mounts
if not exist "logs" mkdir logs
if not exist "staticfiles" mkdir staticfiles
if not exist "media" mkdir media

REM Stop existing containers
echo Stopping existing containers...
docker-compose down

REM Build the application
echo Building Docker image...
docker-compose build --no-cache

REM Start the services
echo Starting services...
docker-compose up -d

REM Wait a moment for services to start
timeout /t 5 /nobreak >nul

REM Check if containers are running
docker-compose ps

echo.
echo Deployment completed!
echo.
echo Your application is now running at:
echo - Main app: http://localhost:8000
echo - With Nginx: http://localhost:80
echo.
echo To view logs: docker-compose logs -f web
echo To stop: docker-compose down
echo.
pause