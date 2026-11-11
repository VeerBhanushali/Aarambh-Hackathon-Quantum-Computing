"""PKI and Certificate Migration module using OpenSSL 3.5+ CLI."""
from __future__ import annotations

import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.capabilities import detect_capabilities
from app.config import CERTS_DIR, OPENSSL_BIN, PKI_DIR
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.vault import _chmod_600, key_available, materialize_keys, register_key


def _run_cmd(args: List[str], timeout: float = 10.0) -> Tuple[int, str]:
    """Run an OpenSSL command with timeout and return (returncode, combined_output)."""
    proc = subprocess.run(
        [OPENSSL_BIN, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return proc.returncode, out.strip()


def _write_ext_file(path: Path) -> None:
    """Write standard X.509 v3 leaf certificate extensions file."""
    content = (
        "basicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth, clientAuth\n"
        "subjectAltName = DNS:localhost, IP:127.0.0.1\n"
    )
    path.write_text(content, encoding="utf-8")


def _record_certificate(
    name: str,
    ca_name: str,
    subject: str,
    key_alg: str,
    sig_alg: str,
    days: int,
    cert_path: Path,
    status: str = "active",
) -> int:
    """Store certificate metadata in SQLite."""
    now = datetime.now(timezone.utc)
    not_before = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    try:
        conn.execute("UPDATE certificates SET status = 'rotated' WHERE name = ? AND status = 'active'", (name,))
        cur = conn.execute(
            """
            INSERT INTO certificates (name, ca_name, subject, key_alg, sig_alg, not_before, not_after, path, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, ca_name, subject, key_alg, sig_alg, not_before, not_after, str(cert_path), status),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def _der_size(cert_path: Path) -> int:
    """Compute DER-encoded byte size of a PEM certificate using openssl x509 -outform DER."""
    if not cert_path.exists():
        return 0
    try:
        proc = subprocess.run(
            [OPENSSL_BIN, "x509", "-in", str(cert_path), "-outform", "DER"],
            capture_output=True,
            timeout=5.0,
            check=False,
        )
        return len(proc.stdout) if proc.returncode == 0 else cert_path.stat().st_size
    except Exception:
        return cert_path.stat().st_size


def ensure_bootstrap_certs() -> None:
    """Generate initial classical RSA-2048 and ECDSA P-256 self-signed certs + ML-DSA cert if missing."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    rsa_key = CERTS_DIR / "rsa2048.key"
    rsa_crt = CERTS_DIR / "rsa2048.crt"
    ecdsa_key = CERTS_DIR / "ecdsa_p256.key"
    ecdsa_crt = CERTS_DIR / "ecdsa_p256.crt"

    if not rsa_crt.exists() or not key_available(rsa_key):
        _run_cmd(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(rsa_key),
                "-out",
                str(rsa_crt),
                "-days",
                "365",
                "-subj",
                "/CN=localhost/O=QuantumGuard-Legacy-RSA",
            ]
        )
        _chmod_600(rsa_key)
        register_key("bootstrap-rsa2048-key", "RSA-2048", "tls-leaf", rsa_key, rotate_days=90)
        _record_certificate(
            "bootstrap-rsa2048",
            "Self-Signed",
            "CN=localhost, O=QuantumGuard-Legacy-RSA",
            "RSA-2048",
            "sha256WithRSAEncryption",
            365,
            rsa_crt,
        )

    if not ecdsa_crt.exists() or not key_available(ecdsa_key):
        _run_cmd(
            [
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                str(ecdsa_key),
                "-out",
                str(ecdsa_crt),
                "-days",
                "365",
                "-subj",
                "/CN=localhost/O=QuantumGuard-Classical-ECDSA",
            ]
        )
        _chmod_600(ecdsa_key)
        register_key("bootstrap-ecdsa-p256-key", "ECDSA-P256", "tls-leaf", ecdsa_key, rotate_days=90)
        _record_certificate(
            "bootstrap-ecdsa-p256",
            "Self-Signed",
            "CN=localhost, O=QuantumGuard-Classical-ECDSA",
            "ECDSA-P256",
            "ecdsa-with-SHA256",
            365,
            ecdsa_crt,
        )


def _ensure_cas() -> bool:
    """Create the Root CAs that are missing. Returns True if the SLH-DSA CA is available."""
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    caps = detect_capabilities()

    # 1. Classical Root CA (ECDSA P-384, 10 years)
    c_ca_key = PKI_DIR / "classical_root_ca.key"
    c_ca_crt = PKI_DIR / "classical_root_ca.crt"
    if not c_ca_crt.exists():
        _run_cmd(
            [
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-384",
                "-nodes",
                "-keyout",
                str(c_ca_key),
                "-out",
                str(c_ca_crt),
                "-days",
                "3650",
                "-subj",
                "/CN=QuantumGuard Classical Root CA/O=QuantumGuard",
            ]
        )
        _chmod_600(c_ca_key)
        register_key("classical-root-ca-key", "ECDSA-P384", "root-ca", c_ca_key, rotate_days=1825)
        _record_certificate(
            "Classical Root CA",
            "Self-Signed",
            "CN=QuantumGuard Classical Root CA",
            "ECDSA-P384",
            "ecdsa-with-SHA384",
            3650,
            c_ca_crt,
        )
        log_audit("pki", "create_ca", "Classical Root CA", "Created ECDSA P-384 Root CA (10y)")

    # 2. PQC Root CA (ML-DSA-87, 10 years)
    pqc_ca_key = PKI_DIR / "pqc_root_ca.key"
    pqc_ca_crt = PKI_DIR / "pqc_root_ca.crt"
    if not pqc_ca_crt.exists() and caps.get("openssl_mldsa"):
        _run_cmd(["genpkey", "-algorithm", "ML-DSA-87", "-out", str(pqc_ca_key)])
        _run_cmd(
            [
                "req",
                "-x509",
                "-new",
                "-key",
                str(pqc_ca_key),
                "-out",
                str(pqc_ca_crt),
                "-days",
                "3650",
                "-subj",
                "/CN=QuantumGuard PQC Root CA (ML-DSA-87)/O=QuantumGuard",
            ]
        )
        _chmod_600(pqc_ca_key)
        register_key("pqc-root-ca-key", "ML-DSA-87", "root-ca", pqc_ca_key, rotate_days=1825)
        _record_certificate(
            "PQC Root CA",
            "Self-Signed",
            "CN=QuantumGuard PQC Root CA (ML-DSA-87)",
            "ML-DSA-87",
            "ML-DSA-87",
            3650,
            pqc_ca_crt,
        )
        log_audit("pki", "create_ca", "PQC Root CA", "Created ML-DSA-87 Root CA (10y, FIPS 204)")

    # 3. Optional SLH-DSA Root CA (FIPS 205)
    slh_ca_key = PKI_DIR / "slhdsa_root_ca.key"
    slh_ca_crt = PKI_DIR / "slhdsa_root_ca.crt"
    slh_available = False
    if caps.get("openssl_slhdsa"):
        if not slh_ca_crt.exists():
            rc, _ = _run_cmd(["genpkey", "-algorithm", "SLH-DSA-SHA2-128s", "-out", str(slh_ca_key)])
            if rc == 0:
                rc2, _ = _run_cmd(
                    [
                        "req",
                        "-x509",
                        "-new",
                        "-key",
                        str(slh_ca_key),
                        "-out",
                        str(slh_ca_crt),
                        "-days",
                        "3650",
                        "-subj",
                        "/CN=QuantumGuard SLH-DSA Root CA/O=QuantumGuard",
                    ]
                )
                if rc2 == 0:
                    slh_available = True
                    _chmod_600(slh_ca_key)
                    register_key("slhdsa-root-ca-key", "SLH-DSA-SHA2-128s", "root-ca", slh_ca_key, rotate_days=1825)
                    _record_certificate(
                        "SLH-DSA Root CA",
                        "Self-Signed",
                        "CN=QuantumGuard SLH-DSA Root CA",
                        "SLH-DSA-SHA2-128s",
                        "SLH-DSA-SHA2-128s",
                        3650,
                        slh_ca_crt,
                    )
                    log_audit("pki", "create_ca", "SLH-DSA Root CA", "Created SLH-DSA-SHA2-128s Root CA (FIPS 205)")
        else:
            slh_available = True

    return slh_available


def _existing_leaf(name: str) -> Dict[str, Any] | None:
    """Return the active DB record for a leaf whose cert and (encrypted) key are already on disk."""
    crt = PKI_DIR / f"{name}.crt"
    if not crt.exists() or not key_available(PKI_DIR / f"{name}.key"):
        return None
    row = query_one("SELECT * FROM certificates WHERE name = ? AND status = 'active' ORDER BY id DESC LIMIT 1", (name,))
    if not row:
        return None
    return {
        "id": row["id"],
        "name": name,
        "ca_name": row["ca_name"],
        "key_alg": row["key_alg"],
        "sig_alg": row["sig_alg"],
        "path": crt.name,
        "der_bytes": _der_size(crt),
        "reused": True,
    }


def init_pki() -> Dict[str, Any]:
    """Initialize Classical Root CA (ECDSA P-384), PQC Root CA (ML-DSA-87), SLH-DSA Root CA, and default leaves.

    Idempotent: existing CAs and leaves are reused (use rotate/issue to get fresh leaves).
    """
    caps = detect_capabilities()
    slh_available = _ensure_cas()
    c_ca_crt = PKI_DIR / "classical_root_ca.crt"
    pqc_ca_crt = PKI_DIR / "pqc_root_ca.crt"

    c_leaf = _existing_leaf("classical-leaf") or issue_leaf_certificate("classical-leaf", "ECDSA-P256")
    pqc_leaf: Dict[str, Any] | None = None
    if caps.get("openssl_mldsa") and pqc_ca_crt.exists():
        pqc_leaf = _existing_leaf("pqc-leaf") or issue_leaf_certificate("pqc-leaf", "ML-DSA-65")

    return {
        "status": "initialized",
        "classical_ca": str(c_ca_crt.name),
        "pqc_ca": str(pqc_ca_crt.name) if pqc_ca_crt.exists() else None,
        "pqc_available": pqc_leaf is not None,
        "degraded_reason": None if pqc_leaf else "OpenSSL on this machine has no ML-DSA support (needs 3.5+); PQC CA skipped.",
        "slh_dsa_ca_available": slh_available,
        "classical_leaf": c_leaf,
        "pqc_leaf": pqc_leaf,
        "size_comparison_bytes": {
            "classical_leaf_der": _der_size(PKI_DIR / "classical-leaf.crt"),
            "pqc_leaf_der": _der_size(PKI_DIR / "pqc-leaf.crt"),
        },
    }


def issue_leaf_certificate(name: str, alg: str = "ML-DSA-65") -> Dict[str, Any]:
    """Issue a leaf certificate signed by either Classical Root CA or PQC Root CA."""
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    ext_file = PKI_DIR / "leaf_ext.cnf"
    _write_ext_file(ext_file)

    safe_name = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip() or "leaf"
    key_path = PKI_DIR / f"{safe_name}.key"
    csr_path = PKI_DIR / f"{safe_name}.csr"
    crt_path = PKI_DIR / f"{safe_name}.crt"

    alg_upper = alg.upper()
    if "ML-DSA" in alg_upper or "PQC" in alg_upper:
        key_alg = "ML-DSA-65"
        ca_name = "PQC Root CA"
        ca_crt = PKI_DIR / "pqc_root_ca.crt"
        ca_key = PKI_DIR / "pqc_root_ca.key"
        _ensure_cas()
        if not ca_crt.exists():
            raise RuntimeError("PQC Root CA unavailable: this OpenSSL build has no ML-DSA support (needs 3.5+).")
        _run_cmd(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(key_path)])
        sig_alg = "ML-DSA-87"  # the leaf is signed by the ML-DSA-87 root
    else:
        key_alg = "ECDSA-P256"
        ca_name = "Classical Root CA"
        ca_crt = PKI_DIR / "classical_root_ca.crt"
        ca_key = PKI_DIR / "classical_root_ca.key"
        _ensure_cas()
        if not ca_crt.exists():
            raise RuntimeError("Classical Root CA could not be created; check the openssl CLI.")
        _run_cmd(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key_path)])
        sig_alg = "ecdsa-with-SHA256"

    _chmod_600(key_path)
    subj = f"/CN=localhost/O=QuantumGuard/OU={safe_name}"
    rc, out = _run_cmd(["req", "-new", "-key", str(key_path), "-out", str(csr_path), "-subj", subj])
    if rc != 0:
        raise RuntimeError(f"CSR generation failed for {safe_name}: {out[:300]}")
    # CA private key is decrypted from the vault only for the duration of the signing command.
    with materialize_keys(ca_key):
        rc, out = _run_cmd(
            [
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(crt_path),
                "-days",
                "90",
                "-extfile",
                str(ext_file),
            ]
        )
    if rc != 0:
        raise RuntimeError(f"Leaf signing failed for {safe_name}: {out[:300]}")

    register_key(f"{safe_name}-key", key_alg, "tls-leaf", key_path, rotate_days=90)
    cert_id = _record_certificate(safe_name, ca_name, f"CN=localhost, OU={safe_name}", key_alg, sig_alg, 90, crt_path)
    log_audit("pki", "issue_leaf", safe_name, f"Issued {key_alg} leaf signed by {ca_name}")

    return {
        "id": cert_id,
        "name": safe_name,
        "ca_name": ca_name,
        "key_alg": key_alg,
        "sig_alg": sig_alg,
        "path": str(crt_path.name),
        "der_bytes": _der_size(crt_path),
    }


def verify_chain(cert_path: Path, ca_path: Path) -> Dict[str, Any]:
    """Verify certificate chain using `openssl verify -CAfile <ca> <cert>`."""
    rc, out = _run_cmd(["verify", "-CAfile", str(ca_path), str(cert_path)])
    verified = rc == 0 and ": OK" in out
    log_audit(
        "pki",
        "verify_chain",
        cert_path.name,
        f"CA={ca_path.name}, verified={verified}, output={out[:120]}",
    )
    return {
        "verified": verified,
        "cert": cert_path.name,
        "ca": ca_path.name,
        "output": out,
    }


def verify_certificate_by_id(cert_id: int) -> Dict[str, Any]:
    """Verify a certificate stored in SQLite against its issuing CA."""
    row = query_one("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    if not row:
        return {"verified": False, "error": f"Certificate id {cert_id} not found"}

    cert_path = Path(row["path"])
    ca_name = row["ca_name"]
    if ca_name == "PQC Root CA":
        ca_path = PKI_DIR / "pqc_root_ca.crt"
    elif ca_name == "Classical Root CA":
        ca_path = PKI_DIR / "classical_root_ca.crt"
    elif ca_name == "SLH-DSA Root CA":
        ca_path = PKI_DIR / "slhdsa_root_ca.crt"
    else:
        ca_path = cert_path  # Self-signed

    return verify_chain(cert_path, ca_path)


def list_certificates() -> Dict[str, Any]:
    """Return all certificates with DER byte sizes and CA summary."""
    rows = query_all("SELECT * FROM certificates ORDER BY id DESC")
    certs: List[Dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        p = Path(item["path"])
        item["der_bytes"] = _der_size(p)
        item["filename"] = p.name
        certs.append(item)

    c_leaf = PKI_DIR / "classical-leaf.crt"
    p_leaf = PKI_DIR / "pqc-leaf.crt"
    return {
        "certificates": certs,
        "size_comparison": {
            "classical_ecdsa_der_bytes": _der_size(c_leaf) if c_leaf.exists() else 0,
            "pqc_mldsa65_der_bytes": _der_size(p_leaf) if p_leaf.exists() else 0,
        },
    }
