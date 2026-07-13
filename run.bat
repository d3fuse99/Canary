@echo off
title Canary Active Defense Core
echo Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit
)
echo Checking dependencies...
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo Library psutil is missing. Installing...
    pip install psutil
)
echo Starting Canary Core Engine...
python server.py
pause