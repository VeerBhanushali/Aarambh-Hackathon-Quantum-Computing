"""FastAPI Application for Quantum Guard (PS07 Post-Quantum Cryptography Assessment & Migration Platform)."""
from __future__ import annotations

from html import escape as html_escape
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.benchmark import export_benchmarks_csv, get_latest_benchmarks, run_benchmarks
from app.capabilities import detect_capabilities
from app.config import ALGORITHM_REGISTRY, PKI_DIR
from app.crypto_lab.hybrid import run_hybrid_demo, run_qday_replay
from app.discovery.live import SUGGESTED_HOSTS, scan_public_host
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://quantumguard-lab.veerbhanushali.in",
        "https://quantumguard-backend.veerbhanushali.in",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


class QDayRequest(BaseModel):
    message: str = "Patient record #4471: diagnosis confidential until 2051"


class LiveScanRequest(BaseModel):
    host: str


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


@app.post("/api/lab/qday")
def api_lab_qday(req: QDayRequest) -> Dict[str, Any]:
    return run_qday_replay(req.message)


@app.get("/api/live-scan/suggestions")
def api_live_scan_suggestions() -> Dict[str, Any]:
    return {"hosts": SUGGESTED_HOSTS}


@app.post("/api/live-scan")
def api_live_scan(req: LiveScanRequest) -> Any:
    try:
        return scan_public_host(req.host)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": True, "message": str(exc)})


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
    """Generate a structured, human-readable HTML/PDF executive summary report with the Quantum Guard UI theme."""
    comp = compare_before_after()
    readiness = get_readiness_summary()
    findings_data = get_findings_for_scan()
    plan = get_latest_plan()
    assumptions = get_assumptions()
    scan_id = readiness.get("scan_id") or 1

    # Ensure there is at least one scan if none exists yet
    if not findings_data.get("findings"):
        svcs = enterprise_status()
        if not any(s["running"] for s in svcs):
            start_all()
        run_full_scan(kind="before")
        comp = compare_before_after()
        readiness = get_readiness_summary()
        findings_data = get_findings_for_scan()
        plan = get_latest_plan()
        scan_id = readiness.get("scan_id") or 1

    top_findings = findings_data.get("findings", [])[:12]
    rows_html = "".join(
        f"<tr>"
        f"<td><b>{html_escape(str(f['location']))}</b><br/><span style='color:#64748b;font-size:11px;'>Source: {html_escape(str(f['source']))}</span></td>"
        f"<td><code>{html_escape(str(f['algorithm']))}</code></td>"
        f"<td><span class='pill sev-{f['severity']}'>{f['severity'].upper()} ({f['score']}/100)</span></td>"
        f"<td>{'<b style=\"color:#dc2626;\">Yes — Urgent HNDL Exposure</b>' if f['hndl_urgent'] else '<span style=\"color:#059669;\">No — Protected</span>'}</td>"
        f"<td>{html_escape(str(f['ir8547_status']))}</td>"
        f"</tr>"
        for f in top_findings
    )

    plan_html = "".join(
        f"<tr>"
        f"<td><span class='pill wave-pill'>Wave {p['wave']}</span></td>"
        f"<td><b>{html_escape(str(p['location']))}</b></td>"
        f"<td><code>{html_escape(str(p['current_algorithm']))}</code></td>"
        f"<td><b style='color:#7c3aed;'>{html_escape(str(p['recommended_target']))}</b><br/><span style='color:#64748b;font-size:11px;'>{html_escape(str(p['standard']))}</span></td>"
        f"<td><span class='pill status-{p['status']}'>{p['status'].upper()}</span></td>"
        f"</tr>"
        for p in plan.get("items", [])[:15]
    )

    before_r = comp.get("before_readiness", readiness.get("readiness_score", 0.0))
    after_r = comp.get("after_readiness", readiness.get("readiness_score", 0.0))
    before_net = comp.get("before_network_readiness", readiness.get("network_readiness_score", 0.0))
    after_net = comp.get("after_network_readiness", readiness.get("network_readiness_score", 0.0))
    hndl_count = readiness.get("hndl_urgent_count", 0)
    crit_count = readiness.get("severity_counts", {}).get("critical", 0) + readiness.get("severity_counts", {}).get("high", 0)

    exec_summary = (
        f"Your organization's current Post-Quantum Readiness is <b>{after_r}%</b> (improved from <b>{before_r}%</b> baseline), "
        f"with Network TLS Readiness at <b>{after_net}%</b>. "
        f"We identified <b>{hndl_count} endpoints</b> vulnerable to Harvest-Now-Decrypt-Later (HNDL) interception where "
        f"data secrecy plus migration time exceeds the estimated {assumptions['years_to_crqc']}-year Quantum Threat Horizon."
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Quantum Guard — Executive Post-Quantum Readiness Report</title>
<link rel="icon" type="image/svg+xml" href="/static/logo.svg"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap');
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #0f172a;
    margin: 0;
    padding: 32px 20px;
    background: linear-gradient(135deg, #f8fafc 0%, #f3e8ff 50%, #eff6ff 100%);
    line-height: 1.55;
  }}
  .page {{
    max-width: 960px;
    margin: 0 auto;
    background: #ffffff;
    border: 1.5px solid #e2e8f0;
    border-radius: 22px;
    padding: 36px 40px;
    box-shadow: 0 20px 50px -12px rgba(15, 23, 42, 0.08);
  }}
  .top-actions {{
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-bottom: 18px;
  }}
  .btn {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: 10px;
    font-size: 13px;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
    border: 1.5px solid #7c3aed;
    background: #ffffff;
    color: #7c3aed;
  }}
  .btn-primary {{
    background: linear-gradient(135deg, #7c3aed, #2563eb);
    color: #ffffff;
    border: none;
  }}
  .report-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 22px;
    border-bottom: 2px solid #f1f5f9;
    margin-bottom: 22px;
  }}
  .brand-row {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}
  .brand-tag {{
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #7c3aed;
  }}
  h1 {{
    font-size: 24px;
    font-weight: 800;
    margin: 2px 0 4px;
    color: #0f172a;
    letter-spacing: -0.02em;
  }}
  .meta {{
    color: #64748b;
    font-size: 12px;
  }}
  .summary-banner {{
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.06), rgba(37, 99, 235, 0.06));
    border: 1.5px solid rgba(124, 58, 237, 0.24);
    border-radius: 14px;
    padding: 16px 20px;
    margin-bottom: 22px;
  }}
  .summary-banner h3 {{
    margin: 0 0 6px;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #7c3aed;
  }}
  .summary-banner p {{
    margin: 0;
    font-size: 14px;
    color: #1e293b;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin: 20px 0 28px;
  }}
  .kpi {{
    border: 1.5px solid #e2e8f0;
    border-radius: 14px;
    padding: 14px 16px;
    background: #f8fafc;
  }}
  .kpi .label {{
    font-size: 11px;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .kpi .val {{
    font-size: 22px;
    font-weight: 800;
    color: #0f172a;
    margin-top: 6px;
  }}
  .kpi .sub {{
    font-size: 11px;
    color: #64748b;
    margin-top: 3px;
  }}
  .section-box {{
    margin-top: 26px;
  }}
  .section-title {{
    font-size: 16px;
    font-weight: 800;
    color: #0f172a;
    margin: 0 0 4px;
  }}
  .section-sub {{
    font-size: 12px;
    color: #64748b;
    margin: 0 0 12px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    border-radius: 12px;
    overflow: hidden;
  }}
  th, td {{
    border: 1px solid #e2e8f0;
    padding: 10px 12px;
    text-align: left;
    vertical-align: middle;
  }}
  th {{
    background: #f8fafc;
    color: #475569;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  code {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    background: #f1f5f9;
    color: #7c3aed;
    padding: 2px 6px;
    border-radius: 5px;
  }}
  .pill {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
  }}
  .sev-critical, .sev-high {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
  .sev-medium {{ background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }}
  .sev-low, .sev-ok {{ background: #ecfdf5; color: #059669; border: 1px solid #a7f3d0; }}
  .wave-pill {{ background: #f3e8ff; color: #7c3aed; border: 1px solid #ddd6fe; }}
  .status-applied {{ background: #ecfdf5; color: #059669; border: 1px solid #a7f3d0; }}
  .status-pending {{ background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }}
  .footer {{
    margin-top: 30px;
    padding-top: 16px;
    border-top: 1px solid #e2e8f0;
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: #64748b;
  }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ background: #ffffff; padding: 0; }}
    .page {{ box-shadow: none; border: none; padding: 16px; }}
  }}
</style>
</head>
<body>
  <div class="page">
    <div class="top-actions no-print">
      <a class="btn" href="/api/cbom/{scan_id}">Download CycloneDX CBOM (JSON)</a>
      <button class="btn btn-primary" onclick="window.print()">Print / Save as PDF</button>
    </div>

    <div class="report-header">
      <div class="brand-row">
        <img src="/static/logo.svg" alt="QG" style="width:48px;height:48px;border-radius:12px;" />
        <div>
          <div class="brand-tag">Quantum Guard · Post-Quantum Security Posture Report</div>
          <h1>Executive Cryptographic Readiness Summary</h1>
          <div class="meta">Generated: {utc_now_iso()} · Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547</div>
        </div>
      </div>
      <div style="text-align:right;">
        <span class="pill {'sev-low' if after_r >= 70 else 'sev-critical'}" style="font-size:13px;padding:6px 14px;">
          Readiness: {after_r}%
        </span>
      </div>
    </div>

    <div class="summary-banner">
      <h3>Executive Summary (Plain-English Overview)</h3>
      <p>{exec_summary}</p>
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="label">Overall Readiness</div>
        <div class="val" style="color:#7c3aed;">{before_r}% &rarr; {after_r}%</div>
        <div class="sub">Before vs. After Remediation</div>
      </div>
      <div class="kpi">
        <div class="label">Network TLS Readiness</div>
        <div class="val" style="color:#059669;">{before_net}% &rarr; {after_net}%</div>
        <div class="sub">Hybrid X25519MLKEM768 Adoption</div>
      </div>
      <div class="kpi">
        <div class="label">HNDL At-Risk Endpoints</div>
        <div class="val" style="color:#dc2626;">{hndl_count}</div>
        <div class="sub">Vulnerable to Traffic Harvesting</div>
      </div>
      <div class="kpi">
        <div class="label">Critical / High Findings</div>
        <div class="val">{crit_count}</div>
        <div class="sub">CRQC Horizon: {assumptions['years_to_crqc']} yrs</div>
      </div>
    </div>

    <div class="section-box">
      <h2 class="section-title">1. Discovered Cryptographic Risks &amp; HNDL Exposure</h2>
      <p class="section-sub">Assets using classical RSA, ECDHE, or legacy TLS that can be recorded today and decrypted by a future quantum computer.</p>
      <table>
        <thead>
          <tr>
            <th>Endpoint / Asset</th>
            <th>Detected Algorithm</th>
            <th>Risk Level</th>
            <th>Harvest-Now-Decrypt-Later</th>
            <th>NIST IR 8547 Timeline</th>
          </tr>
        </thead>
        <tbody>{rows_html or "<tr><td colspan='5'>All scanned endpoints are quantum-safe.</td></tr>"}</tbody>
      </table>
    </div>

    <div class="section-box">
      <h2 class="section-title">2. Prioritized 3-Wave Remediation Plan</h2>
      <p class="section-sub">Step-by-step upgrade path to NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).</p>
      <table>
        <thead>
          <tr>
            <th>Wave</th>
            <th>Target Service / File</th>
            <th>Current Crypto</th>
            <th>Recommended Quantum-Safe Upgrade</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>{plan_html or "<tr><td colspan='5'>No pending remediation items.</td></tr>"}</tbody>
      </table>
    </div>

    <div class="footer">
      <span>Quantum Guard · NIST FIPS 203 / 204 / 205 Compliance Engine</span>
      <span>Scan ID #{scan_id} · CycloneDX 1.6 CBOM Verified</span>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(html)


# ==============================================================================
# SAAS AUTH (RBAC), SUPABASE CLOUD PERSISTENCE & RESEND EMAIL REPORT ENDPOINTS
# ==============================================================================
from app.saas import (
    ensure_saas_local_tables,
    list_recent_target_scans,
    login_user,
    register_user,
    render_target_report_html,
    scan_and_store_target,
    send_report_via_resend,
    supabase_status,
    verify_session_token,
)


class AuthRegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str = ""
    organization: str = ""
    role: str = "ciso"


class AuthLoginRequest(BaseModel):
    email: str
    password: str


class SaaSTargetScanRequest(BaseModel):
    target: str


class SaaSReportEmailRequest(BaseModel):
    to_email: str = ""
    scan_data: Dict[str, Any]


def _extract_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization") or request.query_params.get("token")
    return verify_session_token(auth_header)


@app.get("/api/saas/status")
def api_saas_status(request: Request) -> Dict[str, Any]:
    ensure_saas_local_tables()
    user = _extract_user_from_request(request)
    return {
        **supabase_status(),
        "authenticated": user is not None,
        "user": user,
    }


@app.post("/api/auth/register")
def api_auth_register(req: AuthRegisterRequest) -> JSONResponse:
    try:
        res = register_user(
            email=req.email,
            password=req.password,
            full_name=req.full_name,
            organization=req.organization,
            role=req.role,
        )
        return JSONResponse(res)
    except ValueError as exc:
        return JSONResponse({"error": True, "message": str(exc)}, status_code=400)


@app.post("/api/auth/login")
def api_auth_login(req: AuthLoginRequest) -> JSONResponse:
    try:
        res = login_user(email=req.email, password=req.password)
        return JSONResponse(res)
    except ValueError as exc:
        return JSONResponse({"error": True, "message": str(exc)}, status_code=401)


@app.get("/api/auth/me")
def api_auth_me(request: Request) -> JSONResponse:
    user = _extract_user_from_request(request)
    if not user:
        return JSONResponse({"authenticated": False, "user": None}, status_code=401)
    return JSONResponse({"authenticated": True, "user": user})


@app.post("/api/saas/scan-target")
def api_saas_scan_target(req: SaaSTargetScanRequest, request: Request) -> JSONResponse:
    user = _extract_user_from_request(request)
    try:
        result = scan_and_store_target(req.target, user=user)
        return JSONResponse(result)
    except ValueError as exc:
        return JSONResponse({"error": True, "message": str(exc)}, status_code=400)


@app.get("/api/saas/scans")
def api_saas_scans(limit: int = Query(15)) -> Dict[str, Any]:
    return {"scans": list_recent_target_scans(limit=limit)}


@app.post("/api/saas/report-html", response_class=HTMLResponse)
def api_saas_report_html(req: SaaSReportEmailRequest, request: Request) -> HTMLResponse:
    user = _extract_user_from_request(request)
    if not user:
        return HTMLResponse("<h3>Authentication Required: Please Sign In to unlock the full PQC Report.</h3>", status_code=401)
    html_doc = render_target_report_html(req.scan_data, user)
    return HTMLResponse(html_doc)


@app.post("/api/saas/report-email")
def api_saas_report_email(req: SaaSReportEmailRequest, request: Request) -> JSONResponse:
    user = _extract_user_from_request(request)
    if not user:
        return JSONResponse(
            {"error": True, "auth_required": True, "message": "Please Sign In or Create a Free Account to unlock & email your PQC Readiness Report."},
            status_code=401,
        )
    try:
        result = send_report_via_resend(req.to_email or user["email"], req.scan_data, user)
        return JSONResponse(result)
    except Exception as exc:
        return JSONResponse({"error": True, "message": str(exc)}, status_code=400)


@app.api_route("/api/webhooks/resend", methods=["GET", "POST"])
async def api_webhooks_resend(request: Request) -> JSONResponse:
    if request.method == "GET":
        return JSONResponse({
            "webhook_active": True,
            "endpoint": "https://quantumguard-lab.veerbhanushali.in/api/webhooks/resend",
            "link_tracker_domain": "rsend.quantumguard-lab.veerbhanushali.in",
            "send_domain": "send.quantumguard-lab.veerbhanushali.in",
        })
    payload = await request.json()
    evt_type = str(payload.get("type", "email.event")).upper().replace(".", "_")
    data = payload.get("data") or {}
    to_list = data.get("to") or []
    to_email = to_list[0] if isinstance(to_list, list) and to_list else str(to_list or "recipient")
    clicked_link = (data.get("click") or {}).get("link") or ""
    detail = f"Clicked link: {clicked_link}" if clicked_link else f"Resend event {payload.get('type')} (id={data.get('email_id')})"
    log_audit(to_email, f"RESEND_{evt_type}", clicked_link or "resend-webhook", detail)
    return JSONResponse({"received": True, "event": payload.get("type")})


@app.get("/worker", response_class=HTMLResponse)
def openssl_worker_status_page() -> HTMLResponse:
    caps = detect_capabilities()
    return HTMLResponse(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Quantum Guard — Docker OpenSSL 3.5 Worker Node</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; color: #0f172a; margin: 40px; }}
    .box {{ max-width: 720px; margin: 0 auto; background: #fff; border: 1.5px solid #7c3aed; border-radius: 18px; padding: 28px; box-shadow: 0 12px 32px rgba(15,23,42,0.06); }}
    .pill {{ display: inline-block; padding: 4px 12px; border-radius: 999px; border: 1.5px solid #10b981; color: #059669; font-weight: 800; font-size: 12px; }}
    code {{ background: #f1f5f9; color: #7c3aed; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="box">
    <span class="pill">&#9679; DOCKER OPENSSL 3.5 WORKER ONLINE</span>
    <h1 style="margin:10px 0 4px;">Quantum Guard — C-Engine OpenSSL Worker Page</h1>
    <p style="color:#64748b;font-size:14px;">This container provides low-level OpenSSL 3.5+ NIST FIPS 203/204/205 operations for the Next.js Full-Stack App at <b>https://quantumguard-lab.veerbhanushali.in</b>.</p>
    <ul>
      <li><b>OpenSSL Binary:</b> <code>{caps.get('openssl_version')}</code></li>
      <li><b>ML-KEM (FIPS 203):</b> <code>{caps.get('openssl_mlkem')}</code></li>
      <li><b>ML-DSA (FIPS 204):</b> <code>{caps.get('openssl_mldsa')}</code></li>
      <li><b>SLH-DSA (FIPS 205):</b> <code>{caps.get('openssl_slhdsa')}</code></li>
    </ul>
  </div>
</body>
</html>""")


