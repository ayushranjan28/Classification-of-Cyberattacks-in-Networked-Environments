@echo off
title AI-SOC Intrusion Prevention System

:: Check for Administrator privileges (required for Windows Firewall rules)
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo   AI-Based Predictive Intrusion Prevention System
echo ========================================================
echo.

:: Start the Streamlit Dashboard in the background
echo Starting Streamlit Dashboard...
start /B python -m streamlit run dashboard/app.py --server.port 8501

:: Wait a moment for Streamlit to initialize
timeout /t 3 /nobreak >nul

:: Open the default browser to the dashboard
echo Opening dashboard...
start http://localhost:8501

:: Start the Sniffer Daemon in the current console
echo.
echo Starting Live Network Sniffer (Active Defense Mode)...
echo Press Ctrl+C to terminate the entire system.
echo.
python live_capture/sniffer.py
