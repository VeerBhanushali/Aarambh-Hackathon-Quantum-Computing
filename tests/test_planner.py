"""Prompt 2 Tests: Planner Wave Grouping and Public vs Internal Certificate Recommendations."""
from __future__ import annotations

from app.planner import build_item_recommendation


def test_public_vs_internal_cert_recommendation():
    pub_finding = {
        "id": 1,
        "asset_id": 10,
        "source": "network",
        "location": "customer-api (127.0.0.1:9442)",
        "usage": "tls_authentication",
        "algorithm": "ECDSA-P256",
        "protocol": "TLSv1.3",
        "score": 70,
        "severity": "high",
        "hndl_urgent": 0,
        "details": {"service": "customer-api", "exposure": "public"},
    }
    pub_rec = build_item_recommendation(pub_finding)
    assert pub_rec["wave"] == 2
    assert "Dual-Cert" in pub_rec["recommended_target"]
    assert "Public CAs do not yet issue ML-DSA" in pub_rec["rationale"]
    assert pub_rec["target_profile"] == "hybrid_mlkem_ecdsa"

    int_finding = {
        "id": 2,
        "asset_id": 11,
        "source": "network",
        "location": "hr-records (127.0.0.1:9444)",
        "usage": "tls_authentication",
        "algorithm": "ECDSA-P256",
        "protocol": "TLSv1.3",
        "score": 65,
        "severity": "high",
        "hndl_urgent": 0,
        "details": {"service": "hr-records", "exposure": "internal"},
    }
    int_rec = build_item_recommendation(int_finding)
    assert int_rec["wave"] == 2
    assert "ML-DSA-65 Leaf Certificate" in int_rec["recommended_target"]
    assert int_rec["target_profile"] == "hybrid_mlkem_mldsa"


def test_wave_grouping_kex_vs_root_slhdsa():
    kex_finding = {
        "id": 3,
        "asset_id": 12,
        "source": "network",
        "location": "payments-core (127.0.0.1:9443)",
        "usage": "key_exchange",
        "algorithm": "X25519",
        "protocol": "TLSv1.3",
        "score": 95,
        "severity": "critical",
        "hndl_urgent": 1,
        "details": {"service": "payments-core", "exposure": "internal"},
    }
    kex_rec = build_item_recommendation(kex_finding)
    assert kex_rec["wave"] == 1
    assert "X25519MLKEM768" in kex_rec["recommended_target"]
    assert kex_rec["auto_applicable"] is True

    root_finding = {
        "id": 4,
        "asset_id": 13,
        "source": "certificate",
        "location": "pki/classical_root_ca.crt",
        "usage": "ca_certificate",
        "algorithm": "ECDSA-P384",
        "protocol": "X.509",
        "score": 65,
        "severity": "high",
        "hndl_urgent": 0,
        "details": {"exposure": "internal"},
    }
    root_rec = build_item_recommendation(root_finding)
    assert root_rec["wave"] == 3
    assert "SLH-DSA" in root_rec["recommended_target"]
    assert "FIPS 205" in root_rec["standard"]
