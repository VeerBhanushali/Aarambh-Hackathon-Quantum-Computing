"""FastAPI Application for Quantum Guard (PS07 Post-Quantum Cryptography Assessment & Migration Platform)."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.benchmark import export_benchmarks_csv, get_latest_benchmarks, run_benchmarks
from app.capabilities import detect_capabilities
from app.config import ALGORITHM_REGISTRY, PKI_DIR
from app.crypto_lab.hybrid import run_hybrid_demo
from app.crypto_lab.policy import run_policy_tests
from app.db import (
    get_assumptions,
    get_audit_logs,
    get_conn,
    init_db,
    log_audit,
    query_all,
    query_one,
    set_assumptions,
    utc_now_iso,
)
from app.discovery.cbom import export_cbom, run_full_scan
from app.discovery.code import ensure_sample_codebase
from app.enterprise import (
    reconfigure,
    reset_to_initial_profiles,
    rotate_service_certificate,
    run_dual_cert_demo,
    start_all,
    start_service,
    status as enterprise_status,
    stop_all,
)
from app.pki import (
    ensure_bootstrap_certs,
    init_pki,
    issue_leaf_certificate,
    list_certificates,
    verify_certificate_by_id,
)
from app.planner import apply_plan, compare_before_after, generate_plan, get_latest_plan
from app.risk import evaluate_scan_risks, get_findings_for_scan, get_readiness_summary
from app.vault import get_key_record, list_keys

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite schema, sample codebase, and bootstrap certificates on startup."""
    init_db()
    ensure_sample_codebase()
    ensure_bootstrap_certs()
    yield
    if os.environ.get("QG_KEEP_SERVICES_ON_SHUTDOWN") != "1":
        stop_all()


app = FastAPI(
    title="Quantum Guard — PS07 PQC Assessment & Migration Platform",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def global_json_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return structured JSON errors instead of crashing on unhandled exceptions."""
    return JSONResponse(
        status_code=500,
        content={"error": True, "message": str(exc), "type": type(exc).__name__},
    )


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --- Pydantic Request Schemas ---
class AssumptionsRequest(BaseModel):
    years_to_crqc: int = 10
    migration_years: int = 3


class PKIIssueRequest(BaseModel):
    name: str = "custom-leaf"
    alg: str = "ML-DSA-65"


class HybridLabRequest(BaseModel):
    message: str = "Confidential Swift Wire: $25,000,000 — Protect against Harvest-Now-Decrypt-Later"
    mode: str = "hybrid"
    tamper: bool = False


class BenchmarkRequest(BaseModel):
    n: int = 40


class ReconfigureRequest(BaseModel):
    service: str
    profile: str


# --- Core & Foundation Routes (Prompt 0) ---
@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html_path = STATIC_DIR / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/status")
def api_status() -> Dict[str, Any]:
    init_db()
    caps = detect_capabilities()
    return {
        "status": "ok",
        "app": "Quantum Guard",
        "capabilities": caps,
        "algorithm_registry_count": len(ALGORITHM_REGISTRY),
        "assumptions": get_assumptions(),
    }


@app.get("/api/registry")
def api_registry() -> Dict[str, Any]:
    return {"registry": ALGORITHM_REGISTRY}


# --- Enterprise & Discovery Routes (Prompt 1) ---
@app.get("/api/enterprise")
def api_get_enterprise() -> Dict[str, Any]:
    return {"services": enterprise_status()}


@app.post("/api/enterprise/start")
def api_start_enterprise(reset: bool = Query(default=False)) -> Dict[str, Any]:
    if reset:
        svcs = reset_to_initial_profiles()
    else:
        svcs = start_all()
    return {"status": "started", "services": svcs}


@app.post("/api/enterprise/stop")
def api_stop_enterprise() -> Dict[str, Any]:
    svcs = stop_all()
    return {"status": "stopped", "services": svcs}


@app.post("/api/enterprise/reconfigure")
def api_reconfigure_enterprise(req: ReconfigureRequest) -> Dict[str, Any]:
    svc = reconfigure(req.service, req.profile, actor="api_user")
    return {"status": "reconfigured", "service": svc}


@app.post("/api/scan")
def api_run_scan(kind: str = Query(default="before")) -> Dict[str, Any]:
    # Ensure services are listening before scanning network
    svcs = enterprise_status()
    if not any(s["running"] for s in svcs):
        start_all()
    return run_full_scan(kind=kind)


@app.get("/api/assets")
def api_get_assets(
    scan_id: Optional[int] = Query(default=None),
    source: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    if scan_id is None:
        latest = query_one("SELECT id, kind, started_at FROM scans ORDER BY id DESC LIMIT 1")
        if not latest:
            return {"scan_id": None, "assets": []}
        scan_id = int(latest["id"])

    if source and source != "all":
        rows = query_all(
            "SELECT * FROM assets WHERE scan_id = ? AND source = ? ORDER BY id ASC",
            (scan_id, source),
        )
    else:
        rows = query_all("SELECT * FROM assets WHERE scan_id = ? ORDER BY id ASC", (scan_id,))

    assets = []
    for r in rows:
        item = dict(r)
        item["details"] = json.loads(item.pop("details_json", "{}"))
        assets.append(item)
    return {"scan_id": scan_id, "assets": assets}


@app.get("/api/cbom/{scan_id}")
def api_get_cbom(scan_id: int) -> JSONResponse:
    cbom_doc = export_cbom(scan_id)
    return JSONResponse(
        content=cbom_doc,
        headers={"Content-Disposition": f'attachment; filename="quantum-guard-cbom-scan-{scan_id}.json"'},
    )


# --- Risk & Migration Planner Routes (Prompt 2) ---
@app.get("/api/findings")
def api_get_findings(scan_id: Optional[int] = Query(default=None)) -> Dict[str, Any]:
    return get_findings_for_scan(scan_id)


@app.get("/api/readiness")
def api_get_readiness(scan_id: Optional[int] = Query(default=None)) -> Dict[str, Any]:
    return get_readiness_summary(scan_id)


@app.post("/api/assumptions")
def api_update_assumptions(req: AssumptionsRequest) -> Dict[str, Any]:
    updated = set_assumptions(req.years_to_crqc, req.migration_years)
    # Re-evaluate latest scan findings with the new Mosca parameters
    latest = query_one("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
    summary = None
    if latest:
        summary = evaluate_scan_risks(int(latest["id"]))
    return {"assumptions": updated, "summary": summary}


@app.post("/api/plan")
def api_create_plan(scan_id: Optional[int] = Query(default=None)) -> Dict[str, Any]:
    return generate_plan(scan_id)


@app.get("/api/plan")
def api_get_plan() -> Dict[str, Any]:
    return get_latest_plan()


@app.post("/api/apply")
def api_apply_plan() -> Dict[str, Any]:
    return apply_plan()


@app.get("/api/compare")
def api_compare() -> Dict[str, Any]:
    return compare_before_after()


# --- PKI & Certificate Migration Routes (Prompt 3) ---
@app.post("/api/pki/init")
def api_pki_init() -> Dict[str, Any]:
    return init_pki()


@app.get("/api/pki/certificates")
def api_pki_certificates() -> Dict[str, Any]:
    return list_certificates()


@app.post("/api/pki/issue")
def api_pki_issue(req: PKIIssueRequest) -> Dict[str, Any]:
    return issue_leaf_certificate(req.name, req.alg)


@app.post("/api/pki/verify/{cert_id}")
def api_pki_verify(cert_id: int) -> Dict[str, Any]:
    return verify_certificate_by_id(cert_id)


@app.post("/api/pki/rotate/{service}")
def api_pki_rotate(service: str) -> Dict[str, Any]:
    return rotate_service_certificate(service)


@app.post("/api/pki/dual-cert-demo")
def api_pki_dual_cert_demo() -> Dict[str, Any]:
    return run_dual_cert_demo()


# --- Hybrid Lab & Policy Tests Routes (Prompt 4) ---
@app.post("/api/lab/hybrid")
def api_lab_hybrid(req: HybridLabRequest) -> Dict[str, Any]:
    return run_hybrid_demo(req.message, mode=req.mode, tamper=req.tamper)


@app.post("/api/lab/policy-tests")
def api_lab_policy_tests() -> Dict[str, Any]:
    return run_policy_tests()


# --- Benchmarks & Key Vault Routes (Prompt 5) ---
@app.post("/api/benchmark")
def api_run_benchmark(req: BenchmarkRequest) -> Dict[str, Any]:
    return run_benchmarks(n=req.n)


@app.get("/api/benchmarks/latest")
def api_get_latest_benchmarks() -> Dict[str, Any]:
    return get_latest_benchmarks()


@app.get("/api/benchmarks/{run_id}/csv")
def api_export_benchmarks_csv(run_id: str) -> PlainTextResponse:
    csv_text = export_benchmarks_csv(run_id)
    return PlainTextResponse(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="quantum-guard-benchmarks-{run_id}.csv"'},
    )


@app.get("/api/vault/keys")
def api_get_vault_keys() -> Dict[str, Any]:
    return {
        "keys": list_keys(),
        "production_notice": "Keys are encrypted at rest with AES-256-GCM (data/.master_key, chmod 600). In production, wrap master keys with an FIPS 140-3 HSM or Cloud KMS.",
    }


@app.post("/api/vault/rotate/{key_id}")
def api_vault_rotate(key_id: int) -> Dict[str, Any]:
    rec = get_key_record(key_id)
    if not rec:
        return {"error": True, "message": f"Key ID {key_id} not found"}

    name = rec["name"]
    alg = rec["alg"]
    if rec["purpose"] == "root-ca":
        return {
            "error": True,
            "message": "Root CA keys are rotated through an offline key ceremony (new root + cross-signing); "
            "not automated in this demo. Leaf keys can be rotated here.",
        }
    leaf_name = name[: -len("-key")] if name.endswith("-key") else name
    if not (PKI_DIR / f"{leaf_name}.crt").exists():
        return {
            "error": True,
            "message": f"{name} is a bootstrap self-signed key; initialize the PKI and rotate its CA-issued leaf instead.",
        }
    # Delegate to PKI leaf issuance, then restart running services so they load the new leaf.
    issued = issue_leaf_certificate(leaf_name, alg)
    restarted = [svc["name"] for svc in enterprise_status() if svc["running"]]
    for svc_name in restarted:
        start_service(svc_name)
    log_audit("vault", "rotate_key", name, f"Re-issued {leaf_name}; restarted {len(restarted)} running services")
    return {
        "status": "rotated",
        "previous_key_id": key_id,
        "new_certificate": issued,
        "restarted_services": restarted,
        "keys": list_keys(),
    }


@app.get("/api/audit")
def api_get_audit() -> Dict[str, Any]:
    return {"audit_log": get_audit_logs(limit=100)}


@app.post("/api/reset")
def api_reset_demo(keep_benchmarks: bool = Query(default=False)) -> Dict[str, Any]:
    """Reset the demo database to a clean slate, stop all running TLS services, and re-seed initial profiles."""
    stop_all()
    conn = get_conn()
    try:
        conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM assets")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM plans")
        if not keep_benchmarks:
            conn.execute("DELETE FROM benchmarks")
        conn.execute("DELETE FROM audit_log")
        conn.commit()
    finally:
        conn.close()

    init_db()
    reset_to_initial_profiles()
    stop_all()
    return {
        "status": "reset",
        "message": "Database cleared, services reset to initial profiles and stopped. Ready for a fresh live scan!",
    }


# --- Overview & Printable Executive Report (Prompt 6) ---
@app.get("/api/overview")
def api_overview() -> Dict[str, Any]:
    readiness = get_readiness_summary()
    comp = compare_before_after()
    plan = get_latest_plan()
    certs_data = list_certificates()
    keys_data = list_keys()
    findings_data = get_findings_for_scan()

    pqc_certs = sum(
        1
        for c in certs_data.get("certificates", [])
        if ("ML-DSA" in c["key_alg"] or "SLH-DSA" in c["key_alg"]) and c["status"] == "active"
    )
    due_keys = sum(1 for k in keys_data if k["status"] == "due")

    return {
        "readiness": readiness,
        "comparison": comp,
        "plan": {
            "total_items": plan.get("total_items", 0),
            "resolved_count": plan.get("resolved_count", 0),
            "progress_pct": plan.get("progress_pct", 0.0),
            "auto_progress_pct": plan.get("auto_progress_pct", 0.0),
            "waves": {
                "wave_1": len(plan.get("waves", {}).get("wave_1", [])),
                "wave_2": len(plan.get("waves", {}).get("wave_2", [])),
                "wave_3": len(plan.get("waves", {}).get("wave_3", [])),
            },
            "wave_progress": {
                w: {
                    "applied": sum(1 for it in items if it.get("status") == "applied"),
                    "failed": sum(1 for it in items if it.get("status") == "failed"),
                    "pending": sum(1 for it in items if it.get("status") not in ("applied", "failed")),
                }
                for w, items in plan.get("waves", {}).items()
            },
        },
        "pqc_certificates_issued": pqc_certs,
        "keys_due_for_rotation": due_keys,
        "total_keys": len(keys_data),
        "findings": findings_data.get("findings", []),
    }


@app.get("/api/report", response_class=HTMLResponse)
def api_executive_report() -> HTMLResponse:
    """Generate a printable HTML executive summary report."""
    comp = compare_before_after()
    readiness = get_readiness_summary()
    findings_data = get_findings_for_scan()
    plan = get_latest_plan()
    bench = get_latest_benchmarks()
    assumptions = get_assumptions()
    scan_id = readiness.get("scan_id") or 1

    top_findings = findings_data.get("findings", [])[:12]
    rows_html = "".join(
        f"<tr><td>{f['location']}</td><td>{f['source']}</td><td><b>{f['algorithm']}</b></td>"
        f"<td><span class='sev-{f['severity']}'>{f['severity'].upper()} ({f['score']})</span></td>"
        f"<td>{'YES' if f['hndl_urgent'] else 'No'}</td><td>{f['ir8547_status']}</td></tr>"
        for f in top_findings
    )

    plan_html = "".join(
        f"<tr><td>Wave {p['wave']}</td><td>{p['location']}</td><td>{p['current_algorithm']}</td>"
        f"<td><b>{p['recommended_target']}</b> ({p['standard']})</td><td>{p['effort']}</td><td>{p['status'].upper()}</td></tr>"
        for p in plan.get("items", [])[:15]
    )

    takeaways_html = "".join(f"<li>{t}</li>" for t in bench.get("takeaways", []))
    mi = bench.get("machine_info", {})

    before_r = comp.get("before_readiness", readiness.get("readiness_score", 0.0))
    after_r = comp.get("after_readiness", readiness.get("readiness_score", 0.0))
    before_net = comp.get("before_network_readiness", readiness.get("network_readiness_score", 0.0))
    after_net = comp.get("after_network_readiness", readiness.get("network_readiness_score", 0.0))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Quantum Guard — Executive PQC Assessment & Migration Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; margin: 32px; line-height: 1.45; }}
  h1 {{ margin-bottom: 4px; color: #0f172a; }}
  h2 {{ margin-top: 26px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; color: #1e293b; }}
  .meta {{ color: #475569; font-size: 0.9rem; margin-bottom: 20px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 16px 0; }}
  .kpi {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc; }}
  .kpi .label {{ font-size: 0.8rem; color: #64748b; text-transform: uppercase; }}
  .kpi .val {{ font-size: 1.4rem; font-weight: 700; color: #0f172a; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.85rem; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
  th {{ background: #f1f5f9; }}
  .sev-critical {{ color: #dc2626; font-weight: 700; }}
  .sev-high {{ color: #ea580c; font-weight: 700; }}
  .sev-medium {{ color: #ca8a04; font-weight: 600; }}
  .sev-low, .sev-ok {{ color: #16a34a; font-weight: 600; }}
  .btn-print {{ background: #2563eb; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; float: right; }}
  @media print {{ .no-print {{ display: none; }} body {{ margin: 12px; }} }}
</style>
</head>
<body>
  <button class="btn-print no-print" onclick="window.print()">Print / Save as PDF</button>
  <h1>Quantum Guard — Executive Post-Quantum Security Report</h1>
  <div class="meta">
    Generated: {utc_now_iso()} | Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547 |
    <a href="/api/cbom/{scan_id}">Download CycloneDX CBOM (Scan #{scan_id})</a>
  </div>

  <div class="kpi-grid">
    <div class="kpi">
      <div class="label">Overall Readiness (Before &rarr; After)</div>
      <div class="val">{before_r}% &rarr; {after_r}%</div>
    </div>
    <div class="kpi">
      <div class="label">Network TLS Readiness</div>
      <div class="val">{before_net}% &rarr; {after_net}%</div>
    </div>
    <div class="kpi">
      <div class="label">HNDL-Urgent Assets</div>
      <div class="val">{readiness.get('hndl_urgent_count', 0)}</div>
    </div>
    <div class="kpi">
      <div class="label">Mosca Assumptions</div>
      <div class="val">CRQC: {assumptions['years_to_crqc']}y | Mig: {assumptions['migration_years']}y</div>
    </div>
  </div>

  <h2>1. Top Cryptographic Vulnerability Findings</h2>
  <table>
    <thead><tr><th>Asset Location</th><th>Source</th><th>Algorithm</th><th>Severity (Score)</th><th>HNDL Urgent</th><th>NIST IR 8547 Status</th></tr></thead>
    <tbody>{rows_html or "<tr><td colspan='6'>No findings recorded yet.</td></tr>"}</tbody>
  </table>

  <h2>2. Post-Quantum Migration Plan by Wave</h2>
  <table>
    <thead><tr><th>Wave</th><th>Location</th><th>Current</th><th>Recommended Target</th><th>Effort</th><th>Status</th></tr></thead>
    <tbody>{plan_html or "<tr><td colspan='6'>No migration plan generated yet.</td></tr>"}</tbody>
  </table>

  <h2>3. Empirical Benchmark Takeaways & Machine Specs</h2>
  <p><b>Environment:</b> OS: {mi.get('os', 'N/A')} | CPU: {mi.get('cpu', 'N/A')} ({mi.get('cores', 'N/A')} cores) | Python: {mi.get('python', 'N/A')} | OpenSSL: {mi.get('openssl_version', 'N/A')}</p>
  <ul>{takeaways_html or "<li>Run benchmarks in the dashboard to populate empirical measurements.</li>"}</ul>
</body>
</html>"""
    return HTMLResponse(html)
