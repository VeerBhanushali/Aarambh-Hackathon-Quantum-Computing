# Quantum Guard — Cloudflare Tunnel Connector for quantumguard-backend.veerbhanushali.in
# Exposes the local OpenSSL 3.6.1 Worker (http://127.0.0.1:8000) on:
#   https://quantumguard-backend.veerbhanushali.in
# so your Vercel Next.js app (https://quantumguard-lab.veerbhanushali.in) uses it as OPENSSL_WORKER_URL!

param(
    [string]$TunnelToken = ""
)

$ErrorActionPreference = "Continue"

if ($TunnelToken -ne "") {
    Write-Host "Starting Named Cloudflare Tunnel with Token for quantumguard-backend.veerbhanushali.in..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel run --token $TunnelToken
} else {
    Write-Host "Step 1: Authenticating cloudflared with your Cloudflare account (veerbhanushali.in)..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel login

    Write-Host "Step 2: Creating tunnel 'quantumguard-backend'..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel create quantumguard-backend

    Write-Host "Step 3: Routing DNS quantumguard-backend.veerbhanushali.in -> tunnel..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel route dns -f quantumguard-backend quantumguard-backend.veerbhanushali.in

    Write-Host "Step 4: Running tunnel -> http://127.0.0.1:8000 (OpenSSL 3.6.1 Worker for Vercel)..." -ForegroundColor Green
    .\cloudflared.exe tunnel --url http://127.0.0.1:8000 run quantumguard-backend
}
