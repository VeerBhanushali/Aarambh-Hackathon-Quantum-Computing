"""Quantum Vulnerability Assessment Engine: NIST IR 8547 status, Mosca shelf-life check, and 0-100 risk scoring."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from app.config import lookup_algorithm
from app.db import get_assumptions, get_conn, query_all, query_one


def assess_asset(
    asset: Dict[str, Any],
    years_to_crqc: int = 10,
    migration_years: int = 3,
) -> Dict[str, Any]:
    """Compute NIST IR 8547 status, Mosca HNDL urgency, 0-100 score, severity, and reasons for one asset."""
    alg = asset.get("algorithm", "unknown")
    usage = asset.get("usage", "")
    protocol = asset.get("protocol", "") or ""
    details_raw = asset.get("details_json", "{}")
    details = json.loads(details_raw) if isinstance(details_raw, str) else (details_raw or {})

    meta = lookup_algorithm(alg)
    q_status = meta.get("quantum_status", "vulnerable")
    alg_type = meta.get("type", "unknown")

    exposure = details.get("exposure", "internal")
    secrecy_years = int(details.get("data_secrecy_years", 5))

    reasons: List[str] = []
    base_score = 0

    # 1. Determine NIST IR 8547 status and base score
    if q_status == "broken":
        ir8547_status = "Broken today - critical, independent of quantum"
        base_score = 100
        reasons.append(f"{alg} is classically broken/prohibited ({meta.get('standard')}); replace immediately.")
    elif q_status == "vulnerable":
        ir8547_status = "Deprecated after 2030, disallowed after 2035 (NIST IR 8547)"
        if alg_type in ("kex", "kem") or usage in ("key_exchange",):
            base_score = 80
            reasons.append(
                f"{alg} key establishment is vulnerable to Shor's algorithm and exposed to Harvest-Now-Decrypt-Later."
            )
        else:
            base_score = 65
            reasons.append(
                f"{alg} digital signature/authentication is vulnerable to Shor's algorithm ({ir8547_status})."
            )
    elif q_status == "hybrid":
        ir8547_status = "Transitional - acceptable; hybrid combines classical and PQC"
        base_score = 10
        reasons.append(f"{alg} combines classical + FIPS 203 ML-KEM; remains secure if either component holds.")
    elif q_status == "pqc":
        ir8547_status = "Quantum-resistant (FIPS 203/204/205)"
        base_score = 0
        reasons.append(f"{alg} is a standardized NIST Post-Quantum algorithm ({meta.get('standard')}).")
    elif q_status == "weak":
        ir8547_status = "Acceptable with Grover note (128-bit symmetric key)"
        base_score = 15
        reasons.append(
            f"{alg} has 128-bit key length; Grover's algorithm halves effective strength—prefer AES-256 for long-lived data."
        )
    else:  # symmetric_ok
        ir8547_status = "Quantum-resistant symmetric/hash (256-bit+)"
        base_score = 0
        reasons.append(f"{alg} provides sufficient post-quantum bit security against Grover's algorithm.")

    # 2. Protocol check (TLS 1.2 cannot carry ML-KEM groups; TLS 1.0/1.1 critical)
    proto_up = protocol.upper()
    if "TLSV1.0" in proto_up or "TLSV1.1" in proto_up:
        base_score = max(base_score, 90)
        reasons.append(f"Protocol {protocol} is critically obsolete.")
    elif "TLSV1.2" in proto_up:
        base_score = max(base_score, 40)
        reasons.append("TLS 1.2 warning: cannot negotiate TLS 1.3 hybrid ML-KEM key exchange groups; upgrade to TLS 1.3.")

    # 3. Mosca's theorem (Harvest-Now-Decrypt-Later check)
    # Apply HNDL ONLY to key-establishment assets (signatures are not exposed to HNDL)
    is_kex = alg_type in ("kex", "kem") or usage == "key_exchange"
    hndl_urgent = 0
    if is_kex:
        if q_status == "vulnerable":
            total_shelf = secrecy_years + migration_years
            if total_shelf > years_to_crqc:
                hndl_urgent = 1
                reasons.append(
                    f"Mosca HNDL URGENT: data secrecy ({secrecy_years}y) + migration ({migration_years}y) = {total_shelf}y > years to CRQC ({years_to_crqc}y)."
                )
            else:
                reasons.append(
                    f"Mosca check: secrecy ({secrecy_years}y) + migration ({migration_years}y) <= CRQC ({years_to_crqc}y)."
                )
        else:
            reasons.append("Key establishment protected against HNDL by post-quantum ML-KEM.")
    elif alg_type == "signature" or "sig" in usage or "auth" in usage or "cert" in usage or "key" in usage:
        reasons.append("Signatures/certificates authenticate active sessions and are not exposed to passive HNDL.")

    # 4. Compute final 0-100 score (capped at 100)
    score = base_score
    if hndl_urgent:
        score += 15
    if exposure == "public" and score > 0 and q_status in ("vulnerable", "broken", "weak"):
        score += 5
        reasons.append("Public network exposure (+5 risk score).")

    score = min(100, max(0, score))

    # 5. Severity mapping: >=80 critical, >=60 high, >=35 medium, >=10 low, else ok
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score >= 10:
        severity = "low"
    else:
        severity = "ok"

    return {
        "severity": severity,
        "score": score,
        "ir8547_status": ir8547_status,
        "hndl_urgent": hndl_urgent,
        "reasons": reasons,
    }


def evaluate_scan_risks(scan_id: int) -> Dict[str, Any]:
    """Evaluate all assets of scan_id, store rows in findings table, and return readiness summary."""
    assumptions = get_assumptions()
    years_to_crqc = assumptions["years_to_crqc"]
    migration_years = assumptions["migration_years"]

    assets = query_all("SELECT * FROM assets WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
    conn = get_conn()
    try:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0}
        hndl_count = 0

        for asset in assets:
            res = assess_asset(asset, years_to_crqc=years_to_crqc, migration_years=migration_years)
            sev = res["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            if res["hndl_urgent"]:
                hndl_count += 1

            conn.execute(
                """
                INSERT INTO findings (scan_id, asset_id, severity, score, ir8547_status, hndl_urgent, reasons_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    asset["id"],
                    sev,
                    res["score"],
                    res["ir8547_status"],
                    res["hndl_urgent"],
                    json.dumps(res["reasons"]),
                ),
            )
        conn.commit()
    finally:
        conn.close()

    total = len(assets)
    ok_or_low = counts["ok"] + counts["low"]
    readiness_pct = round((ok_or_low / total) * 100.0, 1) if total > 0 else 0.0

    return {
        "scan_id": scan_id,
        "total_assets": total,
        "severity_counts": counts,
        "hndl_urgent_count": hndl_count,
        "readiness_score": readiness_pct,
        "assumptions": assumptions,
    }


def get_findings_for_scan(scan_id: int | None = None) -> Dict[str, Any]:
    """Fetch joined findings + assets for the given (or latest) scan."""
    if scan_id is None:
        latest = query_one("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        if not latest:
            return {"scan_id": None, "findings": [], "summary": get_readiness_summary()}
        scan_id = int(latest["id"])

    rows = query_all(
        """
        SELECT f.id, f.scan_id, f.asset_id, f.severity, f.score, f.ir8547_status, f.hndl_urgent, f.reasons_json,
               a.source, a.location, a.algorithm, a.family, a.usage, a.protocol, a.details_json
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = ?
        ORDER BY f.score DESC, f.hndl_urgent DESC, f.id ASC
        """,
        (scan_id,),
    )
    items: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d.pop("reasons_json", "[]"))
        d["details"] = json.loads(d.pop("details_json", "{}"))
        items.append(d)

    return {
        "scan_id": scan_id,
        "findings": items,
        "summary": get_readiness_summary(scan_id),
    }


def get_readiness_summary(scan_id: int | None = None) -> Dict[str, Any]:
    """Compute organization readiness score and severity distribution for a scan."""
    assumptions = get_assumptions()
    if scan_id is None:
        latest = query_one("SELECT id, kind FROM scans ORDER BY id DESC LIMIT 1")
        if not latest:
            return {
                "scan_id": None,
                "total_assets": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0},
                "hndl_urgent_count": 0,
                "readiness_score": 0.0,
                "network_readiness_score": 0.0,
                "assumptions": assumptions,
            }
        scan_id = int(latest["id"])

    rows = query_all(
        """
        SELECT f.severity, f.hndl_urgent, a.source
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = ?
        """,
        (scan_id,),
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0}
    hndl_count = 0
    net_total = 0
    net_ok_low = 0

    for r in rows:
        sev = r["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        if r["hndl_urgent"]:
            hndl_count += 1
        if r["source"] == "network":
            net_total += 1
            if sev in ("ok", "low"):
                net_ok_low += 1

    total = len(rows)
    ok_low = counts["ok"] + counts["low"]
    readiness = round((ok_low / total) * 100.0, 1) if total > 0 else 0.0
    net_readiness = round((net_ok_low / net_total) * 100.0, 1) if net_total > 0 else 0.0

    # Also check before vs after readiness
    before_scan = query_one("SELECT id FROM scans WHERE kind = 'before' ORDER BY id DESC LIMIT 1")
    after_scan = query_one("SELECT id FROM scans WHERE kind = 'after' ORDER BY id DESC LIMIT 1")

    return {
        "scan_id": scan_id,
        "total_assets": total,
        "severity_counts": counts,
        "hndl_urgent_count": hndl_count,
        "readiness_score": readiness,
        "network_readiness_score": net_readiness,
        "before_scan_id": before_scan["id"] if before_scan else None,
        "after_scan_id": after_scan["id"] if after_scan else None,
        "assumptions": assumptions,
    }
