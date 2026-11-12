"""SaaS Authentication (RBAC), Supabase Cloud Persistence, Target Scanner & Resend Email Delivery."""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import BASE_DIR
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.discovery.live import scan_public_host


def load_dotenv_if_present() -> None:
    """Load key=value pairs from .env in project root without external dependencies."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and (k not in os.environ or not os.environ[k]):
            os.environ[k] = v


load_dotenv_if_present()

VALID_ROLES = {
    "ciso": "CISO / Executive Viewer",
    "secops": "SecOps / Discovery Analyst",
    "pki_admin": "PKI & Crypto Administrator",
    "auditor": "Compliance Auditor",
}


def ensure_saas_local_tables() -> None:
    """Ensure local SQLite mirror tables exist for offline resiliency."""
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS saas_users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                organization TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'ciso',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS saas_target_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                target_host TEXT NOT NULL,
                verdict TEXT NOT NULL,
                readiness_score INTEGER,
                kex_group TEXT,
                cert_alg TEXT,
                tls12_accepted INTEGER DEFAULT 0,
                full_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def _supabase_config() -> Dict[str, str]:
    load_dotenv_if_present()
    url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_ANON_KEY") or ""
    return {"url": url, "key": key, "domain": os.environ.get("APP_DOMAIN", "quantumguard-lab.veerbhanushali.in")}


def supabase_status() -> Dict[str, Any]:
    cfg = _supabase_config()
    resend_key = os.environ.get("RESEND_API_KEY", "").strip()
    return {
        "supabase_connected": bool(cfg["url"] and cfg["key"]),
        "supabase_url": cfg["url"] or None,
        "supabase_project_ref": os.environ.get("SUPABASE_PROJECT_REF", "irjstudhbbjtnxqulriw"),
        "app_domain": cfg["domain"],
        "resend_configured": bool(resend_key and not resend_key.startswith("re_your_")),
        "resend_from": os.environ.get(
            "RESEND_FROM_EMAIL", "Quantum Guard <reports@quantumguard-lab.veerbhanushali.in>"
        ),
        "roles": VALID_ROLES,
    }


def _supabase_request(
    method: str,
    table_or_path: str,
    payload: Optional[Any] = None,
    query_params: str = "",
) -> Optional[Any]:
    """Perform a REST call against Supabase PostgREST. Returns parsed JSON or None on offline/error."""
    cfg = _supabase_config()
    if not cfg["url"] or not cfg["key"]:
        return None
    endpoint = f"{cfg['url']}/rest/v1/{table_or_path.lstrip('/')}"
    if query_params:
        endpoint = f"{endpoint}?{query_params.lstrip('?')}"
    headers = {
        "apikey": cfg["key"],
        "Authorization": f"Bearer {cfg['key']}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
        "User-Agent": "QuantumGuard-SaaS/1.0",
    }
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    try:
        req = urllib.request.Request(endpoint, data=data_bytes, headers=headers, method=method.upper())
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else []
    except Exception:
        return None


# --- Password Hashing & Stateless HMAC-JWT ---
def _hash_password(password: str, salt: Optional[str] = None) -> str:
    salt_str = salt or secrets.token_hex(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt_str.encode("utf-8"),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"{salt_str}${derived.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    if "$" not in stored_hash:
        return False
    salt_str, _ = stored_hash.split("$", 1)
    expected = _hash_password(password, salt=salt_str)
    return hmac.compare_digest(expected, stored_hash)


def _jwt_secret() -> bytes:
    load_dotenv_if_present()
    sec = os.environ.get("QG_JWT_SECRET", "qg-default-quantum-guard-secret-key-2026")
    return sec.encode("utf-8")


def create_session_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["email"],
        "name": user.get("full_name", ""),
        "org": user.get("organization", ""),
        "role": user.get("role", "ciso"),
        "exp": int(time.time()) + 86400 * 7,
    }
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(_jwt_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    raw_token = token.replace("Bearer ", "").strip()
    if "." not in raw_token:
        return None
    b64, sig = raw_token.rsplit(".", 1)
    expected_sig = hmac.new(_jwt_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))
        if data.get("exp", 0) < int(time.time()):
            return None
        return {
            "email": data["sub"],
            "full_name": data.get("name", ""),
            "organization": data.get("org", ""),
            "role": data.get("role", "ciso"),
            "role_label": VALID_ROLES.get(data.get("role", "ciso"), "CISO / Executive Viewer"),
        }
    except Exception:
        return None


def register_user(email: str, password: str, full_name: str, organization: str, role: str = "ciso") -> Dict[str, Any]:
    ensure_saas_local_tables()
    clean_email = (email or "").strip().lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Please enter a valid work or personal email address.")
    if len(password or "") < 6:
        raise ValueError("Password must be at least 6 characters.")
    clean_role = role if role in VALID_ROLES else "ciso"
    pw_hash = _hash_password(password)
    now = utc_now_iso()
    user_id = secrets.token_hex(16)

    # Check if already registered in Supabase
    existing_sb = _supabase_request(
        "GET", "qg_users", query_params=f"email=eq.{urllib.parse.quote(clean_email)}&select=id,email"
    )
    if existing_sb and len(existing_sb) > 0:
        raise ValueError(f"Account '{clean_email}' already exists. Please Sign In instead.")

    existing_local = query_one("SELECT id FROM saas_users WHERE email = ?", (clean_email,))
    if existing_local:
        raise ValueError(f"Account '{clean_email}' already exists. Please Sign In instead.")

    # Save to Supabase
    sb_rows = _supabase_request(
        "POST",
        "qg_users",
        payload={
            "email": clean_email,
            "full_name": full_name.strip() or clean_email.split("@")[0],
            "organization": organization.strip() or "Enterprise Workspace",
            "role": clean_role,
            "password_hash": pw_hash,
        },
    )
    if sb_rows and isinstance(sb_rows, list) and len(sb_rows) > 0:
        user_id = str(sb_rows[0].get("id", user_id))

    # Mirror to local SQLite
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO saas_users (id, email, full_name, organization, role, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                clean_email,
                full_name.strip() or clean_email.split("@")[0],
                organization.strip() or "Enterprise Workspace",
                clean_role,
                pw_hash,
                now,
            ),
        )

    user_obj = {
        "id": user_id,
        "email": clean_email,
        "full_name": full_name.strip() or clean_email.split("@")[0],
        "organization": organization.strip() or "Enterprise Workspace",
        "role": clean_role,
        "role_label": VALID_ROLES.get(clean_role, "CISO / Executive Viewer"),
    }
    log_audit(clean_email, "SAAS_REGISTER", user_obj["organization"], f"Registered as {user_obj['role_label']} ({user_obj['organization']})")
    _supabase_request(
        "POST",
        "qg_audit_events",
        payload={
            "user_email": clean_email,
            "role": clean_role,
            "action": "SAAS_REGISTER",
            "target": user_obj["organization"],
            "detail": f"Registered role {user_obj['role_label']}",
        },
    )
    token = create_session_token(user_obj)
    return {"user": user_obj, "token": token, "stored_in_supabase": bool(sb_rows)}


def login_user(email: str, password: str) -> Dict[str, Any]:
    ensure_saas_local_tables()
    clean_email = (email or "").strip().lower()
    if not clean_email or not password:
        raise ValueError("Email and password are required.")

    user_row: Optional[Dict[str, Any]] = None
    sb_rows = _supabase_request(
        "GET",
        "qg_users",
        query_params=f"email=eq.{urllib.parse.quote(clean_email)}&select=id,email,full_name,organization,role,password_hash",
    )
    if sb_rows and isinstance(sb_rows, list) and len(sb_rows) > 0:
        user_row = sb_rows[0]
    else:
        user_row = query_one("SELECT * FROM saas_users WHERE email = ?", (clean_email,))

    if not user_row or not _verify_password(password, user_row.get("password_hash", "")):
        raise ValueError("Invalid email or password.")

    role = user_row.get("role", "ciso")
    user_obj = {
        "id": str(user_row.get("id", "")),
        "email": user_row["email"],
        "full_name": user_row.get("full_name", ""),
        "organization": user_row.get("organization", ""),
        "role": role,
        "role_label": VALID_ROLES.get(role, "CISO / Executive Viewer"),
    }
    log_audit(clean_email, "SAAS_LOGIN", user_obj["organization"], f"Signed in ({user_obj['role_label']})")
    token = create_session_token(user_obj)
    return {"user": user_obj, "token": token}


# --- Unified Target Scanner + Remediation Builder + Supabase Storage ---
def scan_and_store_target(target_input: str, user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scan any public hostname/URL on port 443, generate a 3-wave PQC remediation plan, and save to Supabase."""
    ensure_saas_local_tables()
    raw = (target_input or "").strip()
    if not raw:
        raise ValueError("Enter a target domain (e.g. cloudflare.com, google.com, or veerbhanushali.in).")

    scan = scan_public_host(raw)
    host = scan["host"]
    is_hybrid = scan.get("kex_status") == "hybrid"
    risk_score = scan.get("score") if scan.get("score") is not None else 50
    readiness_score = max(0, min(100, 100 - int(risk_score)))
    kex_group = (scan.get("pqc_probe") or {}).get("negotiated_group") or "unknown"
    cert_alg = (scan.get("certificate") or {}).get("signature_algorithm") or "unknown"
    tls12_accepted = bool(scan.get("tls12_accepted"))

    # Build a tailored 3-Wave PQC Migration Roadmap for this scanned domain
    waves = [
        {
            "wave": 1,
            "title": "Wave 1: Hybrid TLS 1.3 Key Exchange (Defeat Harvest-Now-Decrypt-Later)",
            "status": "APPLIED / QUANTUM-SAFE" if is_hybrid else "ACTION REQUIRED (HNDL URGENT)",
            "current": kex_group,
            "recommended": "X25519MLKEM768 (FIPS 203 Hybrid KEM)",
            "config_snippet": "ssl_conf_command Groups X25519MLKEM768:X25519:secp256r1;",
        },
        {
            "wave": 2,
            "title": "Wave 2: Dual-Certificate / Post-Quantum Leaf Authentication",
            "status": "ACTION REQUIRED (By 2030)" if "DSA" not in cert_alg.upper() else "QUANTUM-SAFE",
            "current": cert_alg,
            "recommended": "ML-DSA-65 (FIPS 204) Dual-Cert with ECDSA P-256 fallback",
            "config_snippet": "openssl req -newkey mldsa65 -x509 -days 365 -out leaf_mldsa65.crt",
        },
        {
            "wave": 3,
            "title": "Wave 3: Disable Legacy TLS 1.2 & Enforce Strict TLS 1.3 PQC Policy",
            "status": "ACTION REQUIRED" if tls12_accepted else "COMPLIANT (TLS 1.2 Disabled)",
            "current": "TLS 1.2 Accepted" if tls12_accepted else "TLS 1.3 Only",
            "recommended": "TLS 1.3 Minimum +SLH-DSA-128s Root CA (FIPS 205)",
            "config_snippet": "ssl_protocols TLSv1.3;",
        },
    ]

    enriched = {
        **scan,
        "readiness_score": readiness_score,
        "hndl_urgent": not is_hybrid,
        "remediation_waves": waves,
        "scanned_by": user["email"] if user else "anonymous",
    }

    # Save to Supabase public.qg_target_scans
    sb_row = _supabase_request(
        "POST",
        "qg_target_scans",
        payload={
            "user_email": user["email"] if user else None,
            "target_host": host,
            "verdict": scan.get("verdict", "Assessed"),
            "readiness_score": readiness_score,
            "kex_group": kex_group,
            "cert_alg": cert_alg,
            "tls12_accepted": tls12_accepted,
            "full_payload": enriched,
        },
    )
    scan_id = (
        sb_row[0].get("id")
        if (sb_row and isinstance(sb_row, list) and len(sb_row) > 0)
        else None
    )

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO saas_target_scans
            (user_email, target_host, verdict, readiness_score, kex_group, cert_alg, tls12_accepted, full_payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["email"] if user else None,
                host,
                scan.get("verdict", "Assessed"),
                readiness_score,
                kex_group,
                cert_alg,
                1 if tls12_accepted else 0,
                json.dumps(enriched),
                utc_now_iso(),
            ),
        )
        local_id = cur.lastrowid

    enriched["scan_record_id"] = scan_id or local_id
    enriched["stored_in_supabase"] = bool(sb_row)
    return enriched


def list_recent_target_scans(limit: int = 15) -> List[Dict[str, Any]]:
    ensure_saas_local_tables()
    sb_rows = _supabase_request(
        "GET",
        "qg_target_scans",
        query_params=f"select=id,user_email,target_host,verdict,readiness_score,kex_group,cert_alg,tls12_accepted,created_at&order=id.desc&limit={int(limit)}",
    )
    if sb_rows and isinstance(sb_rows, list):
        return sb_rows
    return query_all(
        "SELECT id, user_email, target_host, verdict, readiness_score, kex_group, cert_alg, tls12_accepted, created_at FROM saas_target_scans ORDER BY id DESC LIMIT ?",
        (int(limit),),
    )


def render_target_report_html(scan_data: Dict[str, Any], user: Dict[str, Any]) -> str:
    """Render an Executive Post-Quantum Readiness Report HTML for a scanned target."""
    host = html.escape(str(scan_data.get("host") or scan_data.get("target_host") or "Enterprise Target"))
    verdict = html.escape(str(scan_data.get("verdict", "Assessed")))
    readiness = int(scan_data.get("readiness_score") or 0)
    pqc_probe = scan_data.get("pqc_probe") or {}
    cert = scan_data.get("certificate") or {}
    kex = html.escape(str(pqc_probe.get("negotiated_group") or scan_data.get("kex_group") or "unknown"))
    cert_alg = html.escape(str(cert.get("signature_algorithm") or scan_data.get("cert_alg") or "unknown"))
    issuer = html.escape(str(cert.get("issuer") or "Public CA"))
    tls12 = "Yes (Legacy Fallback Enabled)" if scan_data.get("tls12_accepted") else "No (TLS 1.3 Strict)"
    waves = scan_data.get("remediation_waves") or []
    reasons = scan_data.get("reasons") or []

    waves_html = "".join(
        f"""
        <tr>
          <td><b>Wave {w.get('wave')}</b><br/><span style="color:#64748b;font-size:12px;">{html.escape(str(w.get('title')))}</span></td>
          <td><code>{html.escape(str(w.get('current')))}</code></td>
          <td><b style="color:#7c3aed;">{html.escape(str(w.get('recommended')))}</b><br/><code>{html.escape(str(w.get('config_snippet')))}</code></td>
          <td><b>{html.escape(str(w.get('status')))}</b></td>
        </tr>
        """
        for w in waves
    )
    reasons_html = "".join(f"<li>{html.escape(str(r))}</li>" for r in reasons)
    badge_color = "#10b981" if readiness >= 75 else "#ef4444"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Quantum Guard Report — {host}</title>
  <link rel="icon" type="image/svg+xml" href="/static/logo.svg" />
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
    body {{ font-family: 'Plus Jakarta Sans', 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #f8fafc 0%, #f3e8ff 50%, #eff6ff 100%); color: #0f172a; margin: 0; padding: 32px 20px; line-height: 1.55; }}
    .report-box {{ max-width: 920px; margin: 0 auto; background: #ffffff; border: 1.5px solid #e2e8f0; border-radius: 22px; padding: 34px 38px; box-shadow: 0 20px 45px rgba(15,23,42,0.08); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 18px; margin-bottom: 22px; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 999px; border: 2px solid {badge_color}; color: {badge_color}; font-weight: 800; font-size: 13px; }}
    .summary-box {{ background: linear-gradient(135deg, rgba(124,58,237,0.06), rgba(37,99,235,0.06)); border: 1.5px solid rgba(124,58,237,0.22); border-radius: 14px; padding: 14px 18px; margin-bottom: 20px; font-size: 13.5px; }}
    .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0; }}
    .kpi {{ border: 1.5px solid #e2e8f0; border-radius: 14px; padding: 14px; background: #f8fafc; }}
    .kpi-lbl {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.04em; }}
    .kpi-val {{ font-size: 20px; font-weight: 800; margin-top: 4px; color: #0f172a; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; color: #475569; font-size: 11px; text-transform: uppercase; font-weight: 800; }}
    code {{ background: #f1f5f9; color: #7c3aed; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
    @media print {{ .no-print {{ display: none; }} body {{ padding: 0; background: #fff; }} .report-box {{ box-shadow: none; border: none; }} }}
  </style>
</head>
<body>
  <div class="report-box">
    <div class="no-print" style="text-align:right; margin-bottom:12px;">
      <button onclick="window.print()" style="background:linear-gradient(135deg,#7c3aed,#2563eb);border:none;color:#fff;padding:8px 18px;border-radius:10px;font-weight:700;cursor:pointer;">Print / Save as PDF</button>
    </div>
    <div class="header">
      <div style="display:flex;align-items:center;gap:14px;">
        <img src="/static/logo.svg" alt="QG" style="width:46px;height:46px;border-radius:12px;" />
        <div>
          <div style="font-size:11px;font-weight:800;color:#7c3aed;text-transform:uppercase;letter-spacing:0.08em;">Quantum Guard · Post-Quantum Readiness Assessment</div>
          <h1 style="margin:3px 0;font-size:23px;">Domain Security Report: {host}</h1>
          <div style="font-size:12px;color:#64748b;">Prepared for <b>{html.escape(user.get('full_name', user['email']))}</b> ({html.escape(user.get('role_label', 'CISO'))} · {html.escape(user.get('organization', 'Enterprise'))})</div>
        </div>
      </div>
      <div class="badge">{verdict}</div>
    </div>

    <div class="summary-box">
      <b style="color:#7c3aed;text-transform:uppercase;font-size:11px;letter-spacing:0.06em;">Plain-English Summary</b><br/>
      Target <b>{host}</b> achieved a Quantum Readiness score of <b>{readiness}%</b> using key exchange group <code>{kex}</code> and certificate signature <code>{cert_alg}</code>.
    </div>

    <div class="kpi-row">
      <div class="kpi"><div class="kpi-lbl">Quantum Readiness</div><div class="kpi-val" style="color:{badge_color};">{readiness}%</div></div>
      <div class="kpi"><div class="kpi-lbl">Key Exchange (KEM)</div><div class="kpi-val" style="font-size:15px;">{kex}</div></div>
      <div class="kpi"><div class="kpi-lbl">Certificate Signature</div><div class="kpi-val" style="font-size:15px;">{cert_alg}</div></div>
      <div class="kpi"><div class="kpi-lbl">TLS 1.2 Fallback</div><div class="kpi-val" style="font-size:14px;">{tls12}</div></div>
    </div>

    <h3 style="margin-bottom:6px;">1. Key Security Findings &amp; Harvest-Now-Decrypt-Later (HNDL) Assessment</h3>
    <ul style="margin-top:4px;">{reasons_html}</ul>
    <p style="font-size:12px;color:#64748b;">Certificate Issuer: {issuer} · Standards Reference: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547.</p>

    <h3 style="margin-bottom:6px;">2. Recommended 3-Wave Upgrade Roadmap</h3>
    <table>
      <thead><tr><th>Migration Wave</th><th>Current Configuration</th><th>Recommended NIST Quantum-Safe Upgrade</th><th>Status</th></tr></thead>
      <tbody>{waves_html}</tbody>
    </table>
  </div>
</body>
</html>"""


def send_report_via_resend(
    to_email: str,
    scan_data: Dict[str, Any],
    user: Dict[str, Any],
) -> Dict[str, Any]:
    """Send the generated HTML report via Resend API (https://api.resend.com/emails)."""
    load_dotenv_if_present()
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_email = os.environ.get(
        "RESEND_FROM_EMAIL", "Quantum Guard <reports@quantumguard-lab.veerbhanushali.in>"
    )
    recipient = (to_email or user.get("email") or "").strip()
    if not recipient or "@" not in recipient:
        raise ValueError("Valid recipient email is required.")

    host = str(scan_data.get("host") or scan_data.get("target_host") or "Enterprise Target")
    html_body = render_target_report_html(scan_data, user)

    if not api_key or api_key.startswith("re_your_"):
        log_audit(recipient, "RESEND_QUEUED", host, f"Report generated for {host} (awaiting RESEND_API_KEY in .env)")
        return {
            "sent": False,
            "resend_configured": False,
            "recipient": recipient,
            "from": from_email,
            "target_host": host,
            "message": f"Report generated for {host}! Add your RESEND_API_KEY in .env (domain: quantumguard-lab.veerbhanushali.in) to deliver live emails; opening report preview now.",
        }

    payload = {
        "from": from_email,
        "to": [recipient],
        "subject": f"[Quantum Guard] PQC Readiness & HNDL Report for {host} ({scan_data.get('readiness_score', 0)}%)",
        "html": html_body,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "QuantumGuard-SaaS/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            log_audit(recipient, "RESEND_SENT", host, f"Emailed PQC report for {host} (id={res_data.get('id')})")
            return {
                "sent": True,
                "resend_configured": True,
                "email_id": res_data.get("id"),
                "recipient": recipient,
                "from": from_email,
                "target_host": host,
                "message": f"Executive PQC Report for {host} emailed to {recipient} via Resend!",
            }
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Resend API error ({exc.code}): {err_body}") from exc
