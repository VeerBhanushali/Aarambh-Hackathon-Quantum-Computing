"""Simulated Enterprise TLS Services (openssl s_server) and Dual-Certificate Demo."""
from __future__ import annotations

import atexit
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.config import CERTS_DIR, DATA_DIR, DEFAULT_SERVICES, OPENSSL_BIN, PKI_DIR
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.pki import ensure_bootstrap_certs, init_pki, issue_leaf_certificate
from app.vault import key_available, materialize_keys

# Active child processes keyed by service name
_PROCESSES: Dict[str, subprocess.Popen] = {}


def _cleanup_on_exit() -> None:
    """Terminate all child openssl s_server processes when Python exits."""
    for name in list(_PROCESSES.keys()):
        try:
            stop_service(name)
        except Exception:
            pass


atexit.register(_cleanup_on_exit)


def _is_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    """Return True if a TCP listener is accepting connections on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _resolve_cert_and_key(kind: str) -> Tuple[Path, Path]:
    """Return (cert_path, key_path) preferring PKI CA leaves if initialized, else bootstrap certs."""
    ensure_bootstrap_certs()
    if kind == "rsa":
        crt = CERTS_DIR / "rsa2048.crt"
        key = CERTS_DIR / "rsa2048.key"
    elif kind == "mldsa":
        pqc_crt = PKI_DIR / "pqc-leaf.crt"
        pqc_key = PKI_DIR / "pqc-leaf.key"
        if not pqc_crt.exists() or not key_available(pqc_key):
            init_pki()
        if not pqc_crt.exists():
            raise RuntimeError("ML-DSA leaf unavailable: OpenSSL 3.5+ with ML-DSA is required for this profile.")
        crt, key = pqc_crt, pqc_key
    else:  # ecdsa
        c_crt = PKI_DIR / "classical-leaf.crt"
        c_key = PKI_DIR / "classical-leaf.key"
        if c_crt.exists() and key_available(c_key):
            crt, key = c_crt, c_key
        else:
            crt = CERTS_DIR / "ecdsa_p256.crt"
            key = CERTS_DIR / "ecdsa_p256.key"
    return crt, key


def spawn_tls_server(args: List[str], port: int, wait_s: float = 3.0) -> subprocess.Popen:
    """Start an `openssl s_server` child process with keys decrypted only during start-up.

    CRYPTO RULE: keys referenced by -key/-dkey are decrypted from the vault, s_server loads them
    into memory before binding the port, and the plaintext files are deleted once the port is open.
    """
    key_paths = [Path(args[i + 1]) for i, a in enumerate(args[:-1]) if a in ("-key", "-dkey")]
    log_dir = DATA_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with materialize_keys(*key_paths), open(log_dir / f"s_server_{port}.log", "wb") as log_fh:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=log_fh,
        )
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            if _is_port_open(port) or proc.poll() is not None:
                break
            time.sleep(0.05)
    return proc


def stop_process(proc: subprocess.Popen) -> None:
    """Terminate a child process, killing it if it does not exit promptly."""
    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def build_profile_args(profile: str, port: int) -> List[str]:
    """Map a profile name to `openssl s_server` CLI arguments."""
    base = [OPENSSL_BIN, "s_server", "-accept", f"127.0.0.1:{port}", "-www", "-quiet"]

    if profile == "legacy_tls12_rsa":
        crt, key = _resolve_cert_and_key("rsa")
        return base + [
            "-tls1_2",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "tls13_ecdhe_rsa":
        crt, key = _resolve_cert_and_key("rsa")
        return base + [
            "-tls1_3",
            "-groups",
            "P-256:X25519",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "tls13_ecdhe_ecdsa":
        crt, key = _resolve_cert_and_key("ecdsa")
        return base + [
            "-tls1_3",
            "-groups",
            "P-256:X25519",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "hybrid_mlkem_ecdsa":
        crt, key = _resolve_cert_and_key("ecdsa")
        return base + [
            "-tls1_3",
            "-groups",
            "X25519MLKEM768:X25519",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "hybrid_mlkem_mldsa":
        crt, key = _resolve_cert_and_key("mldsa")
        return base + [
            "-tls1_3",
            "-groups",
            "X25519MLKEM768:X25519",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "pqc_only_mldsa":
        crt, key = _resolve_cert_and_key("mldsa")
        return base + [
            "-tls1_3",
            "-groups",
            "X25519MLKEM768",
            "-cert",
            str(crt),
            "-key",
            str(key),
        ]

    if profile == "dual_cert_hybrid":
        c_crt, c_key = _resolve_cert_and_key("ecdsa")
        p_crt, p_key = _resolve_cert_and_key("mldsa")
        return base + [
            "-tls1_3",
            "-groups",
            "X25519MLKEM768:X25519",
            "-cert",
            str(c_crt),
            "-key",
            str(c_key),
            "-dcert",
            str(p_crt),
            "-dkey",
            str(p_key),
        ]

    # Default fallback
    crt, key = _resolve_cert_and_key("ecdsa")
    return base + ["-tls1_3", "-groups", "X25519MLKEM768:X25519", "-cert", str(crt), "-key", str(key)]


def start_service(name: str) -> Dict[str, Any]:
    """Start or restart a single simulated enterprise TLS service."""
    row = query_one("SELECT * FROM services WHERE name = ?", (name,))
    if not row:
        raise ValueError(f"Unknown service: {name}")

    stop_service(name)
    port = int(row["port"])
    profile = str(row["profile"])
    error = None
    try:
        args = build_profile_args(profile, port)
        proc = spawn_tls_server(args, port)
        _PROCESSES[name] = proc
        running = _is_port_open(port)
        if not running:
            log_file = DATA_DIR / "logs" / f"s_server_{port}.log"
            error = (log_file.read_text(errors="replace").strip()[:300] if log_file.exists() else "") or "s_server did not start"
    except Exception as exc:  # e.g. profile needs ML-DSA but OpenSSL < 3.5
        running = False
        error = str(exc)
    return {
        "error": error,
        "name": name,
        "port": port,
        "profile": profile,
        "exposure": row["exposure"],
        "data_secrecy_years": row["data_secrecy_years"],
        "running": running,
    }


def stop_service(name: str) -> None:
    """Stop a single enterprise service subprocess if running."""
    proc = _PROCESSES.pop(name, None)
    if proc is not None:
        stop_process(proc)


def start_all() -> List[Dict[str, Any]]:
    """Ensure bootstrap certs exist and start all 5 enterprise services."""
    ensure_bootstrap_certs()
    services = query_all("SELECT * FROM services ORDER BY port ASC")
    results: List[Dict[str, Any]] = []
    for svc in services:
        results.append(start_service(svc["name"]))
    log_audit("enterprise", "start_all", "all_services", f"Started {len(results)} TLS services")
    return results


def stop_all() -> List[Dict[str, Any]]:
    """Stop all running enterprise services."""
    for name in list(_PROCESSES.keys()):
        stop_service(name)
    log_audit("enterprise", "stop_all", "all_services", "Stopped all TLS services")
    return status()


def reset_to_initial_profiles() -> List[Dict[str, Any]]:
    """Reset all 5 enterprise services back to their initial pre-migration profiles."""
    conn = get_conn()
    try:
        now = utc_now_iso()
        for svc in DEFAULT_SERVICES:
            conn.execute(
                "UPDATE services SET profile = ?, updated_at = ? WHERE name = ?",
                (svc["profile"], now, svc["name"]),
            )
        conn.commit()
    finally:
        conn.close()
    return start_all()


def status() -> List[Dict[str, Any]]:
    """Return status of all 5 configured services."""
    services = query_all("SELECT * FROM services ORDER BY port ASC")
    result: List[Dict[str, Any]] = []
    for svc in services:
        port = int(svc["port"])
        proc = _PROCESSES.get(svc["name"])
        alive = (proc is not None and proc.poll() is None) or _is_port_open(port)
        result.append(
            {
                "name": svc["name"],
                "port": port,
                "profile": svc["profile"],
                "exposure": svc["exposure"],
                "data_secrecy_years": svc["data_secrecy_years"],
                "updated_at": svc["updated_at"],
                "running": alive,
            }
        )
    return result


def reconfigure(service: str, profile: str, actor: str = "planner") -> Dict[str, Any]:
    """Reconfigure a service to a new TLS/PQC profile, restart it if active, and log to audit_log."""
    row = query_one("SELECT * FROM services WHERE name = ?", (service,))
    if not row:
        raise ValueError(f"Service {service} not found")

    old_profile = row["profile"]
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE services SET profile = ?, updated_at = ? WHERE name = ?",
            (profile, utc_now_iso(), service),
        )
        conn.commit()
    finally:
        conn.close()

    log_audit(actor, "reconfigure_service", service, f"Profile changed: {old_profile} -> {profile}")
    return start_service(service)


def rotate_service_certificate(service: str) -> Dict[str, Any]:
    """Issue a fresh leaf certificate for a service, restart the service, and log the rotation."""
    row = query_one("SELECT * FROM services WHERE name = ?", (service,))
    if not row:
        raise ValueError(f"Service {service} not found")

    profile = str(row["profile"])
    alg = "ML-DSA-65" if "mldsa" in profile or "dual" in profile else "ECDSA-P256"
    leaf = issue_leaf_certificate(f"{service}-leaf", alg)

    # Also refresh standard leaf used by profiles
    if alg == "ML-DSA-65":
        issue_leaf_certificate("pqc-leaf", "ML-DSA-65")
    else:
        issue_leaf_certificate("classical-leaf", "ECDSA-P256")

    svc_state = start_service(service)
    log_audit("pki", "rotate_service_cert", service, f"Rotated certificate to fresh {alg} leaf")
    return {"service": svc_state, "certificate": leaf}


def run_dual_cert_demo() -> Dict[str, Any]:
    """Run dual-certificate serving on a dedicated ephemeral port (9449) and probe with classical vs PQC clients."""
    init_pki()
    demo_port = 9449
    args = build_profile_args("dual_cert_hybrid", demo_port)
    proc = spawn_tls_server(args, demo_port)
    try:
        if not _is_port_open(demo_port):
            raise RuntimeError("Dual-certificate s_server failed to start (needs OpenSSL 3.5+ with ML-DSA).")

        # Client A: Legacy/Classical client restricted to classical ECDSA signature algorithm & X25519 group
        cmd_old = [
            OPENSSL_BIN,
            "s_client",
            "-connect",
            f"127.0.0.1:{demo_port}",
            "-tls1_3",
            "-sigalgs",
            "ecdsa_secp256r1_sha256",
            "-groups",
            "X25519:P-256",
            "-showcerts",
        ]
        p_old = subprocess.run(cmd_old, input="Q\n", capture_output=True, text=True, timeout=5.0, check=False)
        out_old = (p_old.stdout or "") + "\n" + (p_old.stderr or "")

        # Client B: Modern PQC-capable client preferring ML-DSA-65 and X25519MLKEM768
        cmd_new = [
            OPENSSL_BIN,
            "s_client",
            "-connect",
            f"127.0.0.1:{demo_port}",
            "-tls1_3",
            "-sigalgs",
            "mldsa65:ecdsa_secp256r1_sha256",
            "-groups",
            "X25519MLKEM768:X25519",
            "-showcerts",
        ]
        p_new = subprocess.run(cmd_new, input="Q\n", capture_output=True, text=True, timeout=5.0, check=False)
        out_new = (p_new.stdout or "") + "\n" + (p_new.stderr or "")

        from app.discovery.network import parse_s_client_output

        parsed_old = parse_s_client_output(out_old)
        parsed_new = parse_s_client_output(out_new)

        log_audit(
            "pki",
            "dual_cert_demo",
            f"127.0.0.1:{demo_port}",
            f"Old client got {parsed_old.get('peer_signature_type')}, New client got {parsed_new.get('peer_signature_type')}",
        )
        return {
            "port": demo_port,
            "profile": "dual_cert_hybrid",
            "classical_client": {
                "description": "Restricted to classical sigalgs (ecdsa_secp256r1_sha256) & X25519",
                "negotiated_group": parsed_old.get("group", "unknown"),
                "peer_signature_type": parsed_old.get("peer_signature_type", "unknown"),
                "subject": parsed_old.get("cert_subject", "unknown"),
                "issuer": parsed_old.get("cert_issuer", "unknown"),
                "cert_sig_alg": parsed_old.get("cert_sig_alg", "unknown"),
            },
            "pqc_client": {
                "description": "PQC-capable client (mldsa65 + X25519MLKEM768)",
                "negotiated_group": parsed_new.get("group", "unknown"),
                "peer_signature_type": parsed_new.get("peer_signature_type", "unknown"),
                "subject": parsed_new.get("cert_subject", "unknown"),
                "issuer": parsed_new.get("cert_issuer", "unknown"),
                "cert_sig_alg": parsed_new.get("cert_sig_alg", "unknown"),
            },
        }
    finally:
        stop_process(proc)
