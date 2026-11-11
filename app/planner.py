"""Post-Quantum Migration Planner: Recommendations by Wave, One-Click Auto-Apply, and Before/After Comparison."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.enterprise import reconfigure
from app.pki import init_pki
from app.risk import get_findings_for_scan, get_readiness_summary

CRYPTO_AGILITY_PSEUDOCODE = """# Crypto-Agility Wrapper Pattern (FIPS 204 ML-DSA / Classical Fallback)
class SignatureProvider:
    def __init__(self, alg: str = "ML-DSA-65"):
        self.alg = alg
    def sign(self, key, message: bytes) -> bytes:
        return crypto_backend.sign(self.alg, key, message)"""


def build_item_recommendation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Build a single migration recommendation item for a finding above 'low' severity."""
    source = finding["source"]
    usage = finding["usage"]
    alg = finding["algorithm"]
    protocol = finding.get("protocol") or ""
    details = finding.get("details", {})
    exposure = details.get("exposure", "internal")
    service = details.get("service")

    target = "ML-DSA-65"
    standard = "FIPS 204"
    effort = "medium"
    auto_applicable = False
    target_profile = None
    rationale = ""
    wave = 2
    code_hint = None

    # Rule 1: Network TLS 1.2 prerequisite + key exchange -> X25519MLKEM768 hybrid (FIPS 203)
    if source == "network" and usage == "key_exchange":
        target = "X25519MLKEM768 (TLS 1.3 Hybrid)"
        standard = "FIPS 203 (ML-KEM-768) + RFC 7748"
        effort = "low"
        auto_applicable = True
        wave = 1
        if "1.2" in protocol:
            rationale = (
                "Upgrade TLS 1.2 -> TLS 1.3 (prerequisite) and enable X25519MLKEM768 hybrid key exchange "
                "to neutralize Harvest-Now-Decrypt-Later (HNDL) immediately."
            )
        else:
            rationale = (
                "Enable X25519MLKEM768 hybrid key exchange (FIPS 203) so sessions are protected against HNDL "
                "while retaining classical X25519 assurance."
            )
        target_profile = "hybrid_mlkem_ecdsa" if exposure == "public" else "hybrid_mlkem_mldsa"

    # Rule 2: Public vs Internal Service TLS Certificates
    elif source == "network" and usage == "tls_authentication":
        auto_applicable = True
        wave = 2
        if exposure == "public":
            target = "Classical ECDSA + ML-DSA-65 Dual-Cert (Hybrid TLS 1.3)"
            standard = "FIPS 204 + FIPS 186-5 (Dual-Cert Transition)"
            effort = "medium"
            target_profile = "hybrid_mlkem_ecdsa"
            rationale = (
                "Public CAs do not yet issue ML-DSA certificates to browsers; keep classical ECDSA leaf for public "
                "interoperability and serve ML-DSA-65 via dual-cert to PQC-capable clients."
            )
        else:
            target = "ML-DSA-65 Leaf Certificate (Internal PQC CA)"
            standard = "FIPS 204 (ML-DSA-65)"
            effort = "low"
            target_profile = "hybrid_mlkem_mldsa"
            rationale = (
                "Internal service under enterprise PKI control: migrate directly to an ML-DSA-65 certificate "
                "issued by the internal PQC Root CA."
            )

    # Rule 3: Network AES-128 -> AES-256
    elif source == "network" and usage == "symmetric_encryption":
        target = "AES-256-GCM"
        standard = "FIPS 197 / SP 800-38D"
        effort = "low"
        auto_applicable = True
        wave = 2
        target_profile = "hybrid_mlkem_ecdsa" if exposure == "public" else "hybrid_mlkem_mldsa"
        rationale = "Upgrade cipher suite from AES-128 to AES-256-GCM to maintain full security margin under Grover's algorithm."

    # Rule 4: Broken hashes/ciphers in code (MD5/SHA-1/DES/3DES/RC4)
    elif source == "code" and alg in ("MD5", "SHA-1", "DES", "3DES", "RC4"):
        is_hash = alg in ("MD5", "SHA-1")
        target = "SHA-256" if is_hash else "AES-256-GCM"
        standard = "FIPS 180-4" if is_hash else "FIPS 197 / SP 800-38D"
        effort = "low"
        auto_applicable = False
        wave = 1
        rationale = (
            f"Replace classically broken {alg} at {finding['location']} with {target} immediately "
            f"(file: {details.get('file')}, line: {details.get('line')})."
        )
        code_hint = f"# File {finding['location']} — Replace {alg} with {target}"

    # Rule 5: TLS 1.2 in static config
    elif source == "code" and usage == "tls_config":
        target = "TLS 1.3 + X25519MLKEM768"
        standard = "RFC 8446 + FIPS 203"
        effort = "low"
        auto_applicable = False
        wave = 1
        rationale = f"Upgrade static config at {finding['location']} from TLSv1.2 to TLSv1.3 first (prerequisite for ML-KEM)."

    # Rule 6: RSA/ECDSA/DSA/DH in source code -> ML-DSA / ML-KEM via crypto-agility wrapper
    elif source == "code":
        is_kex = usage == "key_exchange" or alg in ("ECDH-P256", "DH")
        target = "X25519MLKEM768 Hybrid KEM" if is_kex else "ML-DSA-65 via Crypto-Agility Wrapper"
        standard = "FIPS 203" if is_kex else "FIPS 204"
        effort = "high"
        auto_applicable = False
        wave = 3 if not is_kex else 1
        rationale = (
            f"Refactor hardcoded {alg} at {finding['location']} behind a crypto-agility interface so algorithms "
            "can be swapped via configuration."
        )
        code_hint = CRYPTO_AGILITY_PSEUDOCODE

    # Rule 7: Long-lived Root CA / Firmware / Code-signing / Private Keys -> SLH-DSA (FIPS 205) or ML-DSA-87
    elif source in ("certificate", "key"):
        if "ca" in usage or "root" in finding["location"].lower() or source == "key":
            target = "SLH-DSA-SHA2-128s (or ML-DSA-87 for TLS PKI)"
            standard = "FIPS 205 (SLH-DSA) / FIPS 204"
            effort = "medium"
            auto_applicable = False
            wave = 3
            rationale = (
                "For long-lived root CAs, firmware signing, and archival keys, NIST FIPS 205 (SLH-DSA) provides a "
                "conservative stateless hash-based signature option relying only on hash function security despite larger signatures."
            )
        else:
            target = "ML-DSA-65 Leaf Certificate"
            standard = "FIPS 204"
            effort = "low"
            auto_applicable = False
            wave = 2
            rationale = "Re-issue leaf certificate from the internal PQC Root CA using ML-DSA-65."

    return {
        "finding_id": finding["id"],
        "asset_id": finding["asset_id"],
        "wave": wave,
        "wave_title": {
            1: "Wave 1: HNDL-Urgent Key Exchange & Broken Primitives",
            2: "Wave 2: TLS Certificates, PKI & Dual-Cert Serving",
            3: "Wave 3: Application Code Signing, Crypto-Agility & Long-Lived Root Keys (SLH-DSA)",
        }[wave],
        "priority_score": finding["score"] + (20 if finding["hndl_urgent"] else 0),
        "severity": finding["severity"],
        "hndl_urgent": bool(finding["hndl_urgent"]),
        "source": source,
        "location": finding["location"],
        "service": service,
        "exposure": exposure,
        "usage": usage,
        "current_algorithm": alg,
        "recommended_target": target,
        "standard": standard,
        "effort": effort,
        "rationale": rationale,
        "auto_applicable": auto_applicable,
        "target_profile": target_profile,
        "code_hint": code_hint,
        "status": "pending",
    }


def generate_plan(scan_id: int | None = None) -> Dict[str, Any]:
    """Generate a prioritized Post-Quantum Migration Plan for all findings above 'low' severity."""
    data = get_findings_for_scan(scan_id)
    actual_scan_id = data["scan_id"]
    if actual_scan_id is None:
        return {"scan_id": None, "items": [], "waves": {}, "status": "empty"}

    findings = data["findings"]
    items: List[Dict[str, Any]] = []
    for f in findings:
        if f["severity"] in ("critical", "high", "medium"):
            items.append(build_item_recommendation(f))

    # Sort: critical/highest score first, HNDL first within ties, Wave ascending
    items.sort(key=lambda x: (-int(x["hndl_urgent"]), -int(x["priority_score"]), int(x["wave"])))
    for idx, item in enumerate(items, start=1):
        item["priority_rank"] = idx

    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO plans (scan_id, created_at, items_json, status) VALUES (?, ?, ?, 'ready')",
            (actual_scan_id, utc_now_iso(), json.dumps(items)),
        )
        conn.commit()
        plan_id = int(cur.lastrowid or 1)
    finally:
        conn.close()

    log_audit("planner", "generate_plan", f"plan_id={plan_id}", f"Generated {len(items)} migration items across 3 waves")
    return _format_plan_response(plan_id, actual_scan_id, items, "ready")


def _format_plan_response(plan_id: int, scan_id: int, items: List[Dict[str, Any]], status: str) -> Dict[str, Any]:
    waves: Dict[str, List[Dict[str, Any]]] = {"wave_1": [], "wave_2": [], "wave_3": []}
    resolved = 0
    auto_count = 0
    for it in items:
        w_key = f"wave_{it['wave']}"
        waves.setdefault(w_key, []).append(it)
        if it.get("status") == "applied":
            resolved += 1
        if it.get("auto_applicable"):
            auto_count += 1

    total = len(items)
    progress_pct = round((resolved / total) * 100.0, 1) if total > 0 else 0.0
    auto_progress_pct = round((resolved / auto_count) * 100.0, 1) if auto_count > 0 else 0.0

    return {
        "plan_id": plan_id,
        "scan_id": scan_id,
        "status": status,
        "total_items": total,
        "auto_applicable_count": auto_count,
        "resolved_count": resolved,
        "progress_pct": progress_pct,
        "auto_progress_pct": auto_progress_pct,
        "items": items,
        "waves": waves,
    }


def get_latest_plan() -> Dict[str, Any]:
    """Return the most recent migration plan or generate one if findings exist."""
    row = query_one("SELECT * FROM plans ORDER BY id DESC LIMIT 1")
    if not row:
        return generate_plan()

    items = json.loads(row["items_json"] or "[]")
    return _format_plan_response(row["id"], row["scan_id"], items, row["status"])


def apply_plan() -> Dict[str, Any]:
    """Initialize PKI leaves and automatically reconfigure all auto-applicable enterprise services."""
    init_pki()
    plan = get_latest_plan()
    if not plan.get("items"):
        plan = generate_plan()

    items = plan.get("items", [])
    applied_services: Dict[str, str] = {}

    for item in items:
        if item.get("auto_applicable") and item.get("service") and item.get("target_profile"):
            svc_name = item["service"]
            target_prof = item["target_profile"]
            # Internal services get full hybrid_mlkem_mldsa; public services get hybrid_mlkem_ecdsa
            if item.get("exposure") == "internal":
                target_prof = "hybrid_mlkem_mldsa"
            applied_services[svc_name] = target_prof
            item["status"] = "applied"

    reconfigured_list: List[Dict[str, Any]] = []
    for svc_name, prof in applied_services.items():
        res = reconfigure(svc_name, prof, actor="planner_auto_apply")
        reconfigured_list.append(res)

    if plan.get("plan_id"):
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE plans SET items_json = ?, status = 'applied' WHERE id = ?",
                (json.dumps(items), plan["plan_id"]),
            )
            conn.commit()
        finally:
            conn.close()

    log_audit(
        "planner",
        "apply_plan",
        f"plan_id={plan.get('plan_id')}",
        f"Auto-applied PQC/Hybrid profiles to {len(reconfigured_list)} enterprise services",
    )
    updated_plan = get_latest_plan()
    updated_plan["reconfigured_services"] = reconfigured_list
    return updated_plan


def compare_before_after() -> Dict[str, Any]:
    """Compare 'before' scan vs 'after' scan per-asset severity and readiness score."""
    before_scan = query_one("SELECT id, started_at FROM scans WHERE kind = 'before' ORDER BY id DESC LIMIT 1")
    after_scan = query_one("SELECT id, started_at FROM scans WHERE kind = 'after' ORDER BY id DESC LIMIT 1")

    if not before_scan:
        return {"available": False, "message": "Run a 'before' scan first."}

    b_id = int(before_scan["id"])
    b_summary = get_readiness_summary(b_id)
    b_findings = get_findings_for_scan(b_id)["findings"]

    if not after_scan:
        return {
            "available": False,
            "before_scan_id": b_id,
            "before_readiness": b_summary["readiness_score"],
            "before_network_readiness": b_summary["network_readiness_score"],
            "message": "Apply migration plan and run an 'after' scan to compare.",
        }

    a_id = int(after_scan["id"])
    a_summary = get_readiness_summary(a_id)
    a_findings = get_findings_for_scan(a_id)["findings"]

    # Map network & key assets by (location, usage)
    after_map: Dict[tuple, Dict[str, Any]] = {}
    for af in a_findings:
        after_map[(af["location"], af["usage"])] = af

    comparisons: List[Dict[str, Any]] = []
    for bf in b_findings:
        key = (bf["location"], bf["usage"])
        af = after_map.get(key)
        if af:
            comparisons.append(
                {
                    "location": bf["location"],
                    "source": bf["source"],
                    "usage": bf["usage"],
                    "before_algorithm": bf["algorithm"],
                    "after_algorithm": af["algorithm"],
                    "before_severity": bf["severity"],
                    "after_severity": af["severity"],
                    "before_score": bf["score"],
                    "after_score": af["score"],
                    "improved": af["score"] < bf["score"],
                }
            )

    return {
        "available": True,
        "before_scan_id": b_id,
        "after_scan_id": a_id,
        "before_readiness": b_summary["readiness_score"],
        "after_readiness": a_summary["readiness_score"],
        "readiness_delta": round(a_summary["readiness_score"] - b_summary["readiness_score"], 1),
        "before_network_readiness": b_summary["network_readiness_score"],
        "after_network_readiness": a_summary["network_readiness_score"],
        "network_readiness_delta": round(
            a_summary["network_readiness_score"] - b_summary["network_readiness_score"], 1
        ),
        "comparisons": comparisons,
    }
