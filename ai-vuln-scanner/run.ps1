$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    Write-Host "Virtual environment is missing. Running setup first..."
    & .\setup.ps1
}

& .\.venv\Scripts\python.exe server.py
