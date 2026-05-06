$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $python = "py"
    } else {
        Write-Error "Python was not found. Install Python 3.10+ and try again."
    }
} else {
    $python = "python"
}

& $python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host ""
Write-Host "Setup complete."
Write-Host "Run the app with: .\run.ps1"
