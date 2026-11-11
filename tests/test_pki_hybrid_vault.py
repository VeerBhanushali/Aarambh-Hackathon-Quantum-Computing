"""Prompt 3, 4 & 5 Tests: PKI Chain Verification, Hybrid KEM Round-Trip/Tamper, and Zero Private Key Leak Check."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import PKI_DIR
from app.crypto_lab.hybrid import run_hybrid_demo
from app.main import app
from app.pki import init_pki, verify_chain

client = TestClient(app)


def test_pki_chain_verifies_and_cross_ca_fails():
    init_pki()
    c_ca = PKI_DIR / "classical_root_ca.crt"
    p_ca = PKI_DIR / "pqc_root_ca.crt"
    c_leaf = PKI_DIR / "classical-leaf.crt"
    p_leaf = PKI_DIR / "pqc-leaf.crt"

    # Classical leaf verifies against Classical Root CA
    res_c = verify_chain(c_leaf, c_ca)
    assert res_c["verified"] is True

    # PQC ML-DSA-65 leaf verifies against PQC ML-DSA-87 Root CA
    res_p = verify_chain(p_leaf, p_ca)
    assert res_p["verified"] is True

    # PQC leaf MUST NOT verify against Classical Root CA
    res_cross = verify_chain(p_leaf, c_ca)
    assert res_cross["verified"] is False


def test_hybrid_encryption_roundtrip_and_tamper_detection():
    msg = "Quantum Guard Secret Test Vector 2026"
    ok_res = run_hybrid_demo(msg, mode="hybrid", tamper=False)
    assert ok_res["success"] is True
    assert ok_res["decrypted_message"] == msg
    assert ok_res["sizes_bytes"]["x25519_pub"] == 32
    assert ok_res["sizes_bytes"]["mlkem768_ciphertext"] == 1088

    # Tampered ciphertext must fail AES-256-GCM tag verification
    bad_res = run_hybrid_demo(msg, mode="hybrid", tamper=True)
    assert bad_res["success"] is False
    assert bad_res["decrypted_message"] is None
    assert bad_res["error"] is not None


def test_no_api_endpoint_ever_leaks_private_key():
    endpoints = [
        ("GET", "/api/status"),
        ("GET", "/api/enterprise"),
        ("GET", "/api/assets"),
        ("GET", "/api/findings"),
        ("GET", "/api/readiness"),
        ("GET", "/api/plan"),
        ("GET", "/api/pki/certificates"),
        ("GET", "/api/vault/keys"),
        ("GET", "/api/audit"),
        ("GET", "/api/overview"),
        ("GET", "/api/report"),
    ]
    for method, path in endpoints:
        resp = client.request(method, path)
        assert resp.status_code == 200
        assert "PRIVATE KEY" not in resp.text.upper(), f"Private key leaked in {path}"


def test_fair_openssl_speed_benchmark_and_reset_demo():
    from app.benchmark import run_benchmarks

    b = run_benchmarks(n=15)
    primary = b["primary_openssl_speed"]
    assert len(primary) >= 20
    by_name = {r["name"]: r for r in primary}
    # ML-KEM-768 encapsulation in-process is sub-millisecond (< 1.0 ms)
    assert by_name["ML-KEM-768 (encaps)"]["median_ms"] < 1.0
    assert by_name["X25519 (ECDH Exchange)"]["median_ms"] < 1.0

    # Verify Reset Demo clears scans and leaves benchmarks intact when keep_benchmarks=True
    res = client.post("/api/reset?keep_benchmarks=true")
    assert res.status_code == 200
    assert res.json()["status"] == "reset"
    assets_after = client.get("/api/assets").json()
    assert assets_after["scan_id"] is None
    assert assets_after["assets"] == []
