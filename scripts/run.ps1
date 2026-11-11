$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

# PQC features (ML-KEM / ML-DSA / SLH-DSA) need OpenSSL 3.5+. Git-for-Windows' openssl is usually older.
$ossl = if ($env:OPENSSL_BIN) { $env:OPENSSL_BIN } else { "openssl" }
try { $ver = & $ossl version 2>$null } catch { $ver = "not found" }
if ($ver -notmatch "OpenSSL (3\.([5-9]|[1-9][0-9])|[4-9]\.)") {
    Write-Warning "OpenSSL 3.5+ not found ($ver). PQC features will be degraded."
    Write-Warning "Recommended on Windows: Docker Desktop (docker compose up --build) or WSL2 + scripts/run.sh. See NEXT_STEPS.md."
} else {
    Write-Host "Using $ver" -ForegroundColor Green
}

python -m pip install -q -r requirements.txt
Write-Host "Starting Quantum Guard on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
