"""Prompt 2 Tests: Risk Engine (Status Categories, Mosca HNDL Boundary, Score Capping)."""
from __future__ import annotations

import json

from app.risk import assess_asset


def test_broken_algorithm_scores_100_critical():
    asset = {
        "algorithm": "MD5",
        "usage": "hashing",
        "protocol": "application",
        "details_json": json.dumps({"exposure": "internal", "data_secrecy_years": 5}),
    }
    res = assess_asset(asset, years_to_crqc=10, migration_years=3)
    assert res["score"] == 100
    assert res["severity"] == "critical"
    assert res["hndl_urgent"] == 0
    assert "Broken today" in res["ir8547_status"]


def test_hndl_mosca_boundary_true_and_false():
    # Case 1: secrecy (8) + migration (3) = 11 > CRQC (10) -> HNDL Urgent (1)
    asset_urgent = {
        "algorithm": "X25519",
        "usage": "key_exchange",
        "protocol": "TLSv1.3",
        "details_json": json.dumps({"exposure": "internal", "data_secrecy_years": 8}),
    }
    res_true = assess_asset(asset_urgent, years_to_crqc=10, migration_years=3)
    assert res_true["hndl_urgent"] == 1
    assert res_true["score"] == 95  # 80 base + 15 HNDL
    assert res_true["severity"] == "critical"

    # Case 2: secrecy (7) + migration (3) = 10 <= CRQC (10) -> HNDL False (0)
    asset_not_urgent = {
        "algorithm": "X25519",
        "usage": "key_exchange",
        "protocol": "TLSv1.3",
        "details_json": json.dumps({"exposure": "internal", "data_secrecy_years": 7}),
    }
    res_false = assess_asset(asset_not_urgent, years_to_crqc=10, migration_years=3)
    assert res_false["hndl_urgent"] == 0
    assert res_false["score"] == 80


def test_signatures_not_exposed_to_hndl():
    asset_sig = {
        "algorithm": "RSA-2048",
        "usage": "tls_authentication",
        "protocol": "TLSv1.3",
        "details_json": json.dumps({"exposure": "internal", "data_secrecy_years": 25}),
    }
    res = assess_asset(asset_sig, years_to_crqc=10, migration_years=3)
    assert res["hndl_urgent"] == 0
    assert res["score"] == 65
    assert res["severity"] == "high"


def test_score_capping_at_100():
    asset = {
        "algorithm": "ECDH-P256",
        "usage": "key_exchange",
        "protocol": "TLSv1.0",
        "details_json": json.dumps({"exposure": "public", "data_secrecy_years": 25}),
    }
    res = assess_asset(asset, years_to_crqc=10, migration_years=3)
    assert res["score"] == 100
    assert res["severity"] == "critical"


def test_hybrid_and_pqc_scores():
    asset_hyb = {
        "algorithm": "X25519MLKEM768",
        "usage": "key_exchange",
        "protocol": "TLSv1.3",
        "details_json": json.dumps({"exposure": "public", "data_secrecy_years": 25}),
    }
    res_hyb = assess_asset(asset_hyb, years_to_crqc=10, migration_years=3)
    assert res_hyb["score"] == 10
    assert res_hyb["severity"] == "low"
    assert res_hyb["hndl_urgent"] == 0

    asset_pqc = {
        "algorithm": "ML-DSA-65",
        "usage": "tls_authentication",
        "protocol": "TLSv1.3",
        "details_json": json.dumps({"exposure": "internal", "data_secrecy_years": 25}),
    }
    res_pqc = assess_asset(asset_pqc, years_to_crqc=10, migration_years=3)
    assert res_pqc["score"] == 0
    assert res_pqc["severity"] == "ok"
