"""CycloneDX Cryptographic Bill of Materials (CBOM) Exporter and Scan Orchestrator."""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List

from app.config import lookup_algorithm
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.discovery.certs import scan_certs_and_keys
from app.discovery.code import scan_code
from app.discovery.network import scan_network


def run_full_scan(kind: str = "before") -> Dict[str, Any]:
    """Run network, code, and certificate/key scanners and evaluate risk findings."""
    if kind not in ("before", "after"):
        kind = "before"

    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO scans (kind, started_at, status) VALUES (?, ?, 'running')",
            (kind, utc_now_iso()),
        )
        conn.commit()
        scan_id = int(cur.lastrowid or 1)
    finally:
        conn.close()

    net_assets = scan_network(scan_id)
    code_assets = scan_code(scan_id)
    cert_assets = scan_certs_and_keys(scan_id)

    # Evaluate quantum risk findings for all discovered assets
    from app.risk import evaluate_scan_risks

    risk_summary = evaluate_scan_risks(scan_id)

    conn = get_conn()
    try:
        conn.execute(
            "UPDATE scans SET finished_at = ?, status = 'completed' WHERE id = ?",
            (utc_now_iso(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()

    log_audit(
        "discovery",
        f"scan_{kind}",
        f"scan_id={scan_id}",
        f"Discovered {len(net_assets)} network, {len(code_assets)} code, {len(cert_assets)} cert/key assets",
    )
    return {
        "scan_id": scan_id,
        "kind": kind,
        "counts": {
            "network": len(net_assets),
            "code": len(code_assets),
            "cert_and_key": len(cert_assets),
            "total": len(net_assets) + len(code_assets) + len(cert_assets),
        },
        "risk_summary": risk_summary,
    }


def export_cbom(scan_id: int) -> Dict[str, Any]:
    """Export all assets of a scan as a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON."""
    scan = query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    assets = query_all("SELECT * FROM assets WHERE scan_id = ? ORDER BY id ASC", (scan_id,))

    components: List[Dict[str, Any]] = []
    for a in assets:
        meta = lookup_algorithm(a["algorithm"])
        details = json.loads(a["details_json"] or "{}")

        asset_type = "algorithm"
        if a["source"] == "certificate":
            asset_type = "certificate"
        elif a["source"] == "key":
            asset_type = "related-crypto-material"
        elif a["source"] == "network":
            asset_type = "protocol"

        primitive_map = {
            "kem": "kem",
            "kex": "key-agree",
            "signature": "signature",
            "symmetric": "ae",
            "hash": "hash",
        }
        primitive = primitive_map.get(meta.get("type", ""), "other")

        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-asset-{a['id']}",
                "name": a["algorithm"],
                "version": a["protocol"] or "1.0",
                "description": f"{a['usage']} at {a['location']} ({a['source']})",
                "cryptoProperties": {
                    "assetType": asset_type,
                    "algorithmProperties": {
                        "primitive": primitive,
                        "parameterSetIdentifier": a["algorithm"],
                        "executionEnvironment": a["source"],
                        "standard": meta.get("standard", "Unknown"),
                        "quantumStatus": meta.get("quantum_status", "vulnerable"),
                    },
                    "nistQuantumSecurityLevel": int(meta.get("nist_level", 0)),
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": a["location"],
                            "additionalContext": details,
                        }
                    ]
                },
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utc_now_iso(),
            "tools": [{"vendor": "Quantum Guard", "name": "PS07 CBOM Scanner", "version": "1.0.0"}],
            "properties": [
                {"name": "scan_id", "value": str(scan_id)},
                {"name": "scan_kind", "value": scan["kind"] if scan else "before"},
            ],
        },
        "components": components,
    }
