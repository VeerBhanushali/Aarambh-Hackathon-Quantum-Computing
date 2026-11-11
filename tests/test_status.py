"""Prompt 0 & Prompt 1 Tests: Capabilities, S_Client Parser, and Enterprise Discovery."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.discovery.network import parse_s_client_output
from app.main import app

client = TestClient(app)


def test_status_endpoint_capabilities():
    res = client.get("/api/status")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    caps = body["capabilities"]
    assert caps["openssl_ge_35"] is True
    assert caps["openssl_mlkem"] is True
    assert caps["openssl_mldsa"] is True
    assert caps["openssl_slhdsa"] is True


def test_s_client_parser_on_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_s_client_pqc.txt"
    raw = fixture_path.read_text(encoding="utf-8")
    parsed = parse_s_client_output(raw)
    assert parsed["connected"] is True
    assert parsed["protocol"] == "TLSv1.3"
    assert parsed["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert parsed["group"] == "X25519MLKEM768"
    assert parsed["peer_signature_type"] == "mldsa65"
    assert parsed["kex_alg"] == "X25519MLKEM768"
    assert parsed["sig_alg"] == "ML-DSA-65"
    assert parsed["sym_alg"] == "AES-256-GCM"
