@echo off
title Canary Active Defense Core v1.3.1
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
    pip install psutil==5.9.8
)
echo Starting Canary Core Engine v1.3.1...
python server.py
pause