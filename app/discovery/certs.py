"""Certificate and Key File Scanner over data/certs/ and data/pki/."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from app.config import CERTS_DIR, OPENSSL_BIN, PKI_DIR, lookup_algorithm
from app.db import get_conn


def _inspect_cert_file(path: Path) -> Dict[str, Any]:
    """Use `openssl x509 -in <path> -noout -text` to inspect a certificate file."""
    try:
        proc = subprocess.run(
            [OPENSSL_BIN, "x509", "-in", str(path), "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        txt = proc.stdout or ""
    except Exception:
        txt = ""

    subj_m = re.search(r"Subject:\s*(.+)", txt)
    iss_m = re.search(r"Issuer:\s*(.+)", txt)
    sig_m = re.search(r"Signature Algorithm:\s*([^\r\n]+)", txt)
    pk_m = re.search(r"Public Key Algorithm:\s*([^\r\n]+)", txt)
    bits_m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", txt)
    curve_m = re.search(r"NIST CURVE:\s*([^\r\n]+)", txt)
    after_m = re.search(r"Not After\s*:\s*([^\r\n]+)", txt)

    sig_raw = sig_m.group(1).strip() if sig_m else "unknown"
    pk_raw = pk_m.group(1).strip() if pk_m else "unknown"
    bits = bits_m.group(1).strip() if bits_m else ""
    curve = curve_m.group(1).strip() if curve_m else ""

    # Normalize key/signature algorithm to Algorithm Registry name
    combined = f"{pk_raw} {sig_raw} {curve} {bits}".upper()
    if "ML-DSA-87" in combined or "MLDSA87" in combined:
        alg = "ML-DSA-87"
    elif "ML-DSA-65" in combined or "MLDSA65" in combined:
        alg = "ML-DSA-65"
    elif "ML-DSA-44" in combined or "MLDSA44" in combined:
        alg = "ML-DSA-44"
    elif "SLH-DSA" in combined:
        alg = "SLH-DSA-SHA2-128s"
    elif "P-384" in combined or "SECP384R1" in combined:
        alg = "ECDSA-P384"
    elif "P-256" in combined or "PRIME256V1" in combined or "ECDSA" in combined or "ID-ECPUBLICKEY" in combined:
        alg = "ECDSA-P256"
    elif "RSA" in combined:
        alg = "RSA-2048"
    else:
        alg = "RSA-2048"

    return {
        "algorithm": alg,
        "subject": subj_m.group(1).strip() if subj_m else path.name,
        "issuer": iss_m.group(1).strip() if iss_m else "unknown",
        "sig_alg": sig_raw,
        "pubkey_alg": pk_raw,
        "key_bits": bits or curve or alg,
        "not_after": after_m.group(1).strip() if after_m else "unknown",
        "file_bytes": path.stat().st_size,
    }


def scan_certs_and_keys(scan_id: int) -> List[Dict[str, Any]]:
    """Scan data/certs/ and data/pki/ for X.509 certificates and private key files."""
    results: List[Dict[str, Any]] = []
    conn = get_conn()
    try:
        for folder in (CERTS_DIR, PKI_DIR):
            if not folder.exists():
                continue
            for path in sorted(folder.iterdir()):
                if not path.is_file():
                    continue

                if path.suffix.lower() in (".crt", ".pem"):
                    info = _inspect_cert_file(path)
                    alg = info["algorithm"]
                    meta = lookup_algorithm(alg)
                    location = f"{folder.name}/{path.name}"
                    usage = "ca_certificate" if "ca" in path.name.lower() else "leaf_certificate"
                    details = {
                        **info,
                        "exposure": "public" if "rsa" in path.name.lower() else "internal",
                        "data_secrecy_years": 10,
                    }
                    cur = conn.execute(
                        """
                        INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                        VALUES (?, 'certificate', ?, ?, ?, ?, 'X.509', ?)
                        """,
                        (scan_id, location, alg, meta["family"], usage, json.dumps(details)),
                    )
                    results.append({"id": cur.lastrowid, "source": "certificate", "location": location, "algorithm": alg})

                elif path.suffix.lower() == ".key":
                    name_low = path.name.lower()
                    if "mldsa" in name_low or "pqc" in name_low:
                        alg = "ML-DSA-87" if "root" in name_low else "ML-DSA-65"
                    elif "slhdsa" in name_low:
                        alg = "SLH-DSA-SHA2-128s"
                    elif "classical_root" in name_low:
                        alg = "ECDSA-P384"
                    elif "ecdsa" in name_low or "classical" in name_low:
                        alg = "ECDSA-P256"
                    else:
                        alg = "RSA-2048"

                    meta = lookup_algorithm(alg)
                    location = f"{folder.name}/{path.name}"
                    enc_exists = Path(str(path) + ".enc").exists()
                    details = {
                        "filename": path.name,
                        "encrypted_at_rest": enc_exists,
                        "file_bytes": path.stat().st_size,
                        "exposure": "internal",
                        "data_secrecy_years": 15,
                    }
                    cur = conn.execute(
                        """
                        INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                        VALUES (?, 'key', ?, ?, ?, 'private_key', 'PKCS#8', ?)
                        """,
                        (scan_id, location, alg, meta["family"], json.dumps(details)),
                    )
                    results.append({"id": cur.lastrowid, "source": "key", "location": location, "algorithm": alg})

        conn.commit()
    finally:
        conn.close()

    return results
