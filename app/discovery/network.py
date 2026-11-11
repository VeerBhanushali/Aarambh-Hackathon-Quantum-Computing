"""Network TLS Scanner using `openssl s_client` against Enterprise Services."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from app.config import OPENSSL_BIN, SCANS_DIR, lookup_algorithm
from app.db import get_conn, query_all


def _extract_cert_details_from_pem(pem_text: str) -> Dict[str, str]:
    """Extract subject, issuer, public key algorithm, signature algorithm, and expiry from PEM certificate."""
    match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        pem_text,
        re.DOTALL,
    )
    if not match:
        return {}

    cert_pem = match.group(1)
    try:
        proc = subprocess.run(
            [OPENSSL_BIN, "x509", "-noout", "-text"],
            input=cert_pem,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        txt = proc.stdout or ""
    except Exception:
        return {}

    subj_m = re.search(r"Subject:\s*(.+)", txt)
    iss_m = re.search(r"Issuer:\s*(.+)", txt)
    sig_m = re.search(r"Signature Algorithm:\s*([^\r\n]+)", txt)
    pk_m = re.search(r"Public Key Algorithm:\s*([^\r\n]+)", txt)
    bits_m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", txt)
    curve_m = re.search(r"NIST CURVE:\s*([^\r\n]+)", txt)
    after_m = re.search(r"Not After\s*:\s*([^\r\n]+)", txt)

    return {
        "cert_subject": subj_m.group(1).strip() if subj_m else "unknown",
        "cert_issuer": iss_m.group(1).strip() if iss_m else "unknown",
        "cert_sig_alg": sig_m.group(1).strip() if sig_m else "unknown",
        "cert_pubkey_alg": pk_m.group(1).strip() if pk_m else "unknown",
        "cert_bits": bits_m.group(1).strip() if bits_m else "",
        "cert_curve": curve_m.group(1).strip() if curve_m else "",
        "cert_not_after": after_m.group(1).strip() if after_m else "unknown",
    }


def parse_s_client_output(raw: str) -> Dict[str, Any]:
    """Tolerant parser for `openssl s_client` stdout/stderr output."""
    proto_m = re.search(r"Protocol\s*:\s*([^\r\n]+)", raw)
    if not proto_m:
        proto_m = re.search(r"New,\s*(TLSv[0-9.]+),\s*Cipher\s+is", raw)

    cipher_m = re.search(r"Cipher\s*:\s*([^\r\n]+)", raw)
    if not cipher_m:
        cipher_m = re.search(r"Cipher\s+is\s+([^\r\n\s]+)", raw)

    group_m = re.search(r"Negotiated TLS1\.3 group:\s*([^\r\n]+)", raw)
    if not group_m:
        group_m = re.search(r"(?:Server|Peer) Temp Key:\s*([^\r\n,]+)", raw)
    if not group_m:
        group_m = re.search(r"Shared groups:\s*([^\r\n:]+)", raw)

    sig_m = re.search(r"Peer signature type:\s*([^\r\n]+)", raw)
    if not sig_m:
        sig_m = re.search(r"Peer signing digest:\s*([^\r\n]+)", raw)

    protocol = proto_m.group(1).strip() if proto_m else "unknown"
    cipher = cipher_m.group(1).strip() if cipher_m else "unknown"
    group = group_m.group(1).strip() if group_m else "unknown"
    peer_sig = sig_m.group(1).strip() if sig_m else "unknown"

    if cipher in ("0000", "(NONE)"):
        cipher = "unknown"

    cert_info = _extract_cert_details_from_pem(raw)

    # Normalize key exchange algorithm name
    kex_alg = "unknown"
    g_up = group.upper()
    c_up = cipher.upper()
    if "X25519MLKEM768" in g_up:
        kex_alg = "X25519MLKEM768"
    elif "SECP256R1MLKEM768" in g_up:
        kex_alg = "SecP256r1MLKEM768"
    elif "X25519" in g_up:
        kex_alg = "X25519"
    elif "P-256" in g_up or "SECP256R1" in g_up or "PRIME256V1" in g_up or "ECDH" in g_up:
        kex_alg = "ECDH-P256"
    elif "ECDHE" in c_up:
        kex_alg = "ECDH-P256"

    # Normalize peer signature / authentication algorithm.
    # The server's own key is what authenticates the session: use the negotiated peer signature type
    # first, then the leaf's public-key algorithm. The certificate's *signature* algorithm belongs to
    # the issuing CA (e.g. an ML-DSA-65 leaf signed by an ML-DSA-87 root) and is only a last resort.
    ps_up = peer_sig.upper().replace("-", "").replace("_", "")
    cpk_up = cert_info.get("cert_pubkey_alg", "").upper()
    cs_up = cert_info.get("cert_sig_alg", "").upper()
    cpk_n = cpk_up.replace("-", "").replace("_", "")

    def _classify(token: str) -> str:
        for lvl in ("44", "65", "87"):
            if f"MLDSA{lvl}" in token:
                return f"ML-DSA-{lvl}"
        if "SLHDSA" in token:
            return "SLH-DSA-SHA2-128s"
        if "ED25519" in token:
            return "Ed25519"
        if "ECDSA" in token or "IDECPUBLICKEY" in token:
            if "384" in token:
                return "ECDSA-P384"
            return "ECDSA-P256"
        if "RSA" in token:
            return "RSA-3072" if cert_info.get("cert_bits") == "3072" else "RSA-2048"
        return "unknown"

    sig_alg = _classify(ps_up)
    if sig_alg == "unknown":
        sig_alg = _classify(cpk_n)
    if sig_alg == "unknown":
        sig_alg = _classify(cs_up.replace("-", "").replace("_", ""))
    if sig_alg == "unknown" and "RSA" in c_up:
        sig_alg = "RSA-2048"

    # Normalize symmetric cipher
    sym_alg = "unknown"
    if "AES_256_GCM" in c_up or "AES256-GCM" in c_up:
        sym_alg = "AES-256-GCM"
    elif "AES_128_GCM" in c_up or "AES128-GCM" in c_up:
        sym_alg = "AES-128-GCM"

    connected = cipher != "unknown" and protocol != "unknown"
    return {
        "connected": connected,
        "protocol": protocol,
        "cipher": cipher,
        "group": group,
        "peer_signature_type": peer_sig,
        "kex_alg": kex_alg,
        "sig_alg": sig_alg,
        "sym_alg": sym_alg,
        **cert_info,
    }


def _probe_service(port: int, extra_args: List[str]) -> str:
    """Run a single `openssl s_client` probe with 5s timeout and stdin closed."""
    cmd = [
        OPENSSL_BIN,
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-servername",
        "localhost",
        "-showcerts",
        *extra_args,
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception as exc:
        return f"PROBE_ERROR: {exc}"


def scan_network(scan_id: int) -> List[Dict[str, Any]]:
    """Probe all configured enterprise services and record network cryptographic assets."""
    scan_folder = SCANS_DIR / str(scan_id)
    scan_folder.mkdir(parents=True, exist_ok=True)

    services = query_all("SELECT * FROM services ORDER BY port ASC")
    discovered: List[Dict[str, Any]] = []

    conn = get_conn()
    try:
        for svc in services:
            name = svc["name"]
            port = int(svc["port"])

            # 3 probes per specification: default TLS 1.3, hybrid ML-KEM TLS 1.3, TLS 1.2
            out_tls13 = _probe_service(port, ["-tls1_3"])
            out_pqc = _probe_service(port, ["-tls1_3", "-groups", "X25519MLKEM768"])
            out_tls12 = _probe_service(port, ["-tls1_2"])

            raw_log_path = scan_folder / f"{name}_{port}.txt"
            raw_log_path.write_text(
                f"=== PROBE TLS 1.3 DEFAULT ===\n{out_tls13}\n"
                f"=== PROBE TLS 1.3 X25519MLKEM768 ===\n{out_pqc}\n"
                f"=== PROBE TLS 1.2 ===\n{out_tls12}\n",
                encoding="utf-8",
            )

            p_pqc = parse_s_client_output(out_pqc)
            p_13 = parse_s_client_output(out_tls13)
            p_12 = parse_s_client_output(out_tls12)

            # Pick the best successful probe representing the service's active capabilities
            chosen = p_pqc if p_pqc["connected"] else (p_13 if p_13["connected"] else p_12)
            location = f"{name} (127.0.0.1:{port})"

            # 1. Key Exchange Asset
            kex_alg = chosen.get("kex_alg", "unknown")
            if kex_alg != "unknown":
                meta = lookup_algorithm(kex_alg)
                details = {
                    "service": name,
                    "port": port,
                    "exposure": svc["exposure"],
                    "data_secrecy_years": svc["data_secrecy_years"],
                    "profile": svc["profile"],
                    "cipher": chosen.get("cipher"),
                    "negotiated_group": chosen.get("group"),
                    "peer_signature_type": chosen.get("peer_signature_type"),
                    "pqc_supported": p_pqc["connected"],
                    "tls12_enabled": p_12["connected"],
                }
                cur = conn.execute(
                    """
                    INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                    VALUES (?, 'network', ?, ?, ?, 'key_exchange', ?, ?)
                    """,
                    (
                        scan_id,
                        location,
                        kex_alg,
                        meta["family"],
                        chosen.get("protocol", "unknown"),
                        json.dumps(details),
                    ),
                )
                discovered.append({"id": cur.lastrowid, "location": location, "algorithm": kex_alg, "usage": "key_exchange"})

            # 2. TLS Leaf Authentication / Signature Asset
            sig_alg = chosen.get("sig_alg", "unknown")
            if sig_alg != "unknown":
                meta_sig = lookup_algorithm(sig_alg)
                details_sig = {
                    "service": name,
                    "port": port,
                    "exposure": svc["exposure"],
                    "data_secrecy_years": svc["data_secrecy_years"],
                    "profile": svc["profile"],
                    "cert_subject": chosen.get("cert_subject"),
                    "cert_issuer": chosen.get("cert_issuer"),
                    "cert_not_after": chosen.get("cert_not_after"),
                    "peer_signature_type": chosen.get("peer_signature_type"),
                }
                cur2 = conn.execute(
                    """
                    INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                    VALUES (?, 'network', ?, ?, ?, 'tls_authentication', ?, ?)
                    """,
                    (
                        scan_id,
                        location,
                        sig_alg,
                        meta_sig["family"],
                        chosen.get("protocol", "unknown"),
                        json.dumps(details_sig),
                    ),
                )
                discovered.append(
                    {"id": cur2.lastrowid, "location": location, "algorithm": sig_alg, "usage": "tls_authentication"}
                )

            # 3. Symmetric Cipher Asset
            sym_alg = chosen.get("sym_alg", "unknown")
            if sym_alg != "unknown":
                meta_sym = lookup_algorithm(sym_alg)
                details_sym = {
                    "service": name,
                    "port": port,
                    "exposure": svc["exposure"],
                    "data_secrecy_years": svc["data_secrecy_years"],
                    "cipher_suite": chosen.get("cipher"),
                }
                cur3 = conn.execute(
                    """
                    INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                    VALUES (?, 'network', ?, ?, ?, 'symmetric_encryption', ?, ?)
                    """,
                    (
                        scan_id,
                        location,
                        sym_alg,
                        meta_sym["family"],
                        chosen.get("protocol", "unknown"),
                        json.dumps(details_sym),
                    ),
                )
                discovered.append(
                    {"id": cur3.lastrowid, "location": location, "algorithm": sym_alg, "usage": "symmetric_encryption"}
                )

        conn.commit()
    finally:
        conn.close()

    return discovered
