"""Tests for the live internet scanner (#1) and the Q-Day harvest-now-decrypt-later replay (#2)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.capabilities import detect_capabilities
from app.crypto_lab.hybrid import run_qday_replay
from app.discovery.live import _verify_result, assess_live, normalize_host
from app.main import app

client = TestClient(app)
needs_mlkem = pytest.mark.skipif(not detect_capabilities().get("openssl_mlkem"), reason="needs OpenSSL 3.5+ (ML-KEM)")


@pytest.mark.parametrize(
    "raw,expected",
    [("https://WWW.Example.com/login?x=1", "www.example.com"), ("example.com:443", "example.com"), ("example.com.", "example.com")],
)
def test_normalize_host_accepts_public_names(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", ["localhost", "127.0.0.1", "10.0.0.5", "example.com:8443", "", "a b.com", "[::1]"])
def test_normalize_host_rejects_unsafe_input(raw):
    with pytest.raises(ValueError):
        normalize_host(raw)


def test_live_scan_api_rejects_internal_targets():
    for host in ("localhost", "127.0.0.1", "169.254.169.254"):
        res = client.post("/api/live-scan", json={"host": host})
        assert res.status_code == 400 and res.json()["error"] is True


def _probe(connected=True, kex="X25519", sig="ECDSA-P256"):
    return {"connected": connected, "kex_alg": kex, "sig_alg": sig}


def test_assess_live_hybrid_site_is_ready():
    v = assess_live(_probe(kex="X25519MLKEM768"), _probe(), tls12_ok=False)
    assert v["kex_status"] == "hybrid" and v["score"] == 10


def test_assess_live_classical_site_is_not_ready():
    v = assess_live(_probe(kex="X25519"), _probe(), tls12_ok=True)
    assert v["kex_status"] == "vulnerable" and v["score"] == 80
    assert any("TLS 1.2" in r for r in v["reasons"])


def test_assess_live_unreachable():
    v = assess_live(_probe(connected=False), _probe(connected=False), tls12_ok=False)
    assert v["verdict"] == "Unreachable" and v["score"] is None


def test_verify_result_detects_untrusted_chain():
    raw = "issuer=O=Corp Proxy, CN=MITM CA\nVerify return code: 20 (unable to get local issuer certificate)\n"
    r = _verify_result(raw)
    assert r["verified"] is False and "Corp Proxy" in r["issuer"]
    assert _verify_result("Verify return code: 0 (ok)")["verified"] is True


@needs_mlkem
def test_qday_classical_is_broken_and_hybrid_survives():
    msg = "secret until 2051"
    res = run_qday_replay(msg)
    c, h = res["sessions"]["classical"], res["sessions"]["hybrid"]
    assert c["attacker_decrypted"] is True and c["attacker_plaintext"] == msg
    assert c["attacker_key_fp"] == c["true_key_fp"]
    assert h["attacker_decrypted"] is False and h["attacker_plaintext"] is None
    assert h["attacker_key_fp"] != h["true_key_fp"]
    assert h["recorded"]["mlkem_ciphertext"] == 1088


@needs_mlkem
def test_qday_api_returns_no_key_material():
    res = client.post("/api/lab/qday", json={"message": "x"})
    assert res.status_code == 200
    assert "PRIVATE KEY" not in res.text.upper()
