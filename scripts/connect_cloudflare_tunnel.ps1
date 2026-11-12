# Quantum Guard — Cloudflare Tunnel Connector for quantumguard-lab.veerbhanushali.in
# Connects your local Full-Stack Next.js (port 3000) + OpenSSL 3.6.1 Worker (port 8000)
# directly to https://quantumguard-lab.veerbhanushali.in

param(
    [string]$TunnelToken = ""
)

$ErrorActionPreference = "Stop"

if ($TunnelToken -ne "") {
    Write-Host "Starting Named Cloudflare Tunnel with Token for quantumguard-lab.veerbhanushali.in..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel run --token $TunnelToken
} else {
    Write-Host "Step 1: Authenticating cloudflared with your Cloudflare account (veerbhanushali.in)..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel login

    Write-Host "Step 2: Creating tunnel 'quantumguard-lab'..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel create quantumguard-lab

    Write-Host "Step 3: Routing DNS quantumguard-lab.veerbhanushali.in -> tunnel..." -ForegroundColor Cyan
    .\cloudflared.exe tunnel route dns quantumguard-lab quantumguard-lab.veerbhanushali.in

    Write-Host "Step 4: Running tunnel -> http://127.0.0.1:3000 (Next.js Full-Stack + OpenSSL Worker)..." -ForegroundColor Green
    .\cloudflared.exe tunnel --url http://127.0.0.1:3000 run quantumguard-lab
}
