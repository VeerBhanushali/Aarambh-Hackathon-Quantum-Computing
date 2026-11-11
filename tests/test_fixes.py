"""Regression tests for the review fixes: key encryption at rest, idempotent PKI, honest benchmarks."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.benchmark import _cmp, _compute_takeaways, run_openssl_speed_suite
from app.capabilities import detect_capabilities
from app.config import CERTS_DIR, PKI_DIR
from app.discovery.network import parse_s_client_output
from app.main import app
from app.pki import ensure_bootstrap_certs, init_pki, list_certificates
from app.vault import materialize_keys

client = TestClient(app)
HAS_PQC = bool(detect_capabilities().get("openssl_mldsa"))
needs_pqc = pytest.mark.skipif(not HAS_PQC, reason="needs OpenSSL 3.5+ with ML-DSA (set OPENSSL_BIN)")


def test_no_plaintext_private_keys_at_rest():
    ensure_bootstrap_certs()
    init_pki()
    plaintext = [p.name for d in (CERTS_DIR, PKI_DIR) for p in d.glob("*.key")]
    assert plaintext == [], f"plaintext keys left on disk: {plaintext}"
    assert list(PKI_DIR.glob("*.key.enc")), "expected encrypted keys"


def test_materialize_keys_decrypts_then_deletes():
    init_pki()
    key = PKI_DIR / "classical-leaf.key"
    assert not key.exists()
    with materialize_keys(key):
        assert key.exists()
        assert b"PRIVATE KEY" in key.read_bytes()
    assert not key.exists()


def test_init_pki_is_idempotent():
    init_pki()
    before = len(list_certificates()["certificates"])
    init_pki()
    init_pki()
    assert len(list_certificates()["certificates"]) == before


def test_parser_reports_leaf_key_not_issuer_signature():
    raw = "Protocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nPeer signature type: mldsa65\nNegotiated TLS1.3 group: X25519MLKEM768\n"
    parsed = parse_s_client_output(raw)
    assert parsed["sig_alg"] == "ML-DSA-65"
    assert parsed["kex_alg"] == "X25519MLKEM768"


def test_comparison_wording_comes_from_numbers():
    assert _cmp(0.15, 0.06) == "2.5x slower than"
    assert _cmp(0.02, 0.2) == "10.0x faster than"
    assert _cmp(1.0, 1.05) == "about the same speed as"
    rows = [
        {"name": "ML-DSA-65 (sign)", "median_ms": 0.8, "note": ""},
        {"name": "ML-DSA-65 (verify)", "median_ms": 0.15, "note": ""},
        {"name": "ECDSA P-256 (sign)", "median_ms": 0.02, "note": ""},
        {"name": "ECDSA P-256 (verify)", "median_ms": 0.06, "note": ""},
    ]
    text = " ".join(_compute_takeaways(rows))
    assert "2.5x slower than ECDSA" in text


def test_openssl_speed_rows_do_not_invent_p95():
    rows = run_openssl_speed_suite(seconds=1)
    assert rows, "openssl speed produced no rows"
    assert all(r["p95_ms"] is None and r["cpu_ms"] is None for r in rows)


@needs_pqc
def test_strict_policy_has_accepted_pqc_control():
    res = client.post("/api/lab/policy-tests").json()
    strict = [t for t in res["tests"] if t["id"] == "strict_pqc_policy"][0]
    assert strict["passed"] is True
    assert strict["control_pqc_client_accepted"] is True


@needs_pqc
def test_vault_rejects_root_ca_rotation():
    init_pki()
    keys = client.get("/api/vault/keys").json()["keys"]
    root = next(k for k in keys if k["purpose"] == "root-ca")
    res = client.post(f"/api/vault/rotate/{root['id']}").json()
    assert res["error"] is True
