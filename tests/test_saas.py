"""Tests for SaaS Auth (RBAC), Supabase persistence, Target Scan & Login-Gated Reports."""
from __future__ import annotations

import secrets
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_saas_status_and_auth_gated_report():
    st = client.get("/api/saas/status").json()
    assert st["app_domain"] == "quantumguard-lab.veerbhanushali.in"
    assert "ciso" in st["roles"]

    sample_scan = {
        "host": "cloudflare.com",
        "verdict": "Post-Quantum Ready (Hybrid Key Exchange)",
        "readiness_score": 85,
        "kex_status": "hybrid",
        "pqc_probe": {"negotiated_group": "X25519MLKEM768", "handshake_ms": 42},
        "certificate": {"signature_algorithm": "ecdsa-with-SHA256", "issuer": "Cloudflare"},
        "tls12_accepted": True,
        "reasons": ["Negotiated X25519MLKEM768"],
        "remediation_waves": [
            {
                "wave": 1,
                "title": "Wave 1",
                "current": "X25519MLKEM768",
                "recommended": "X25519MLKEM768",
                "config_snippet": "Groups X25519MLKEM768",
                "status": "APPLIED",
            }
        ],
    }

    # Unauthenticated report request must be blocked (401)
    unauth = client.post("/api/saas/report-email", json={"scan_data": sample_scan})
    assert unauth.status_code == 401

    # Register a new user with RBAC role
    unique_email = f"ciso_{secrets.token_hex(4)}@veerbhanushali.in"
    reg = client.post(
        "/api/auth/register",
        json={
            "email": unique_email,
            "password": "QuantumSafePassword123!",
            "full_name": "Veer Bhanushali",
            "organization": "Quantum Guard Lab",
            "role": "ciso",
        },
    )
    assert reg.status_code == 200, reg.text
    reg_data = reg.json()
    token = reg_data["token"]
    assert reg_data["user"]["role"] == "ciso"

    # Login with the same user
    lg = client.post(
        "/api/auth/login",
        json={"email": unique_email, "password": "QuantumSafePassword123!"},
    )
    assert lg.status_code == 200
    assert lg.json()["user"]["email"] == unique_email

    # Authenticated HTML report unlock works
    rep_html = client.post(
        "/api/saas/report-html",
        headers={"Authorization": f"Bearer {token}"},
        json={"scan_data": sample_scan},
    )
    assert rep_html.status_code == 200
    assert "Post-Quantum Readiness Report: cloudflare.com" in rep_html.text

    # Authenticated email endpoint works
    rep_mail = client.post(
        "/api/saas/report-email",
        headers={"Authorization": f"Bearer {token}"},
        json={"to_email": unique_email, "scan_data": sample_scan},
    )
    assert rep_mail.status_code == 200
    assert rep_mail.json()["target_host"] == "cloudflare.com"
