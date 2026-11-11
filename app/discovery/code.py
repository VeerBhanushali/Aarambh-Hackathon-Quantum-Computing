"""Source-code cryptographic scanner and Synthetic Sample Codebase generator."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.config import SAMPLE_APP_DIR, lookup_algorithm
from app.db import get_conn

# 16 Regex/AST-lite pattern rules mapping code usage to Algorithm Registry names
CODE_RULES: List[Tuple[str, str, str, str]] = [
    (r"rsa\.generate_private_key\s*\(.*?2048", "RSA-2048", "key_generation", "Python RSA-2048 key generation"),
    (r"RSA\.generate\s*\(\s*2048", "RSA-2048", "key_generation", "PyCryptodome RSA-2048 key generation"),
    (r"ec\.SECP256R1\s*\(", "ECDSA-P256", "signing", "Python ECDSA P-256 curve usage"),
    (r"createECDH\s*\(\s*['\"]prime256v1['\"]\s*\)", "ECDH-P256", "key_exchange", "Node.js ECDH prime256v1 key exchange"),
    (r"hashlib\.md5\s*\(", "MD5", "hashing", "Broken MD5 hash digest call"),
    (r"createHash\s*\(\s*['\"]md5['\"]\s*\)", "MD5", "hashing", "Node.js broken MD5 hash"),
    (r"hashlib\.sha1\s*\(", "SHA-1", "hashing", "Deprecated SHA-1 digest call"),
    (r"createHash\s*\(\s*['\"]sha1['\"]\s*\)", "SHA-1", "hashing", "Node.js deprecated SHA-1 hash"),
    (r"AES-128-CBC|algorithms\.AES128|AES\.new\([^,]+,\s*AES\.MODE_CBC", "AES-128-CBC", "symmetric_encryption", "AES-128-CBC encryption"),
    (r"AESGCM\s*\(|AES-256-GCM", "AES-256-GCM", "symmetric_encryption", "AES-256-GCM authenticated encryption"),
    (r"algorithm\s*=\s*['\"]RS256['\"]|alg:\s*['\"]RS256['\"]", "RS256", "jwt_signing", "JWT RS256 (RSA-SHA256) token signing"),
    (r"algorithm\s*=\s*['\"]ES256['\"]|alg:\s*['\"]ES256['\"]", "ES256", "jwt_signing", "JWT ES256 (ECDSA-P256) token signing"),
    (r"DES3|TripleDES|des-ede3-cbc", "3DES", "symmetric_encryption", "Broken 3DES symmetric cipher"),
    (r"ARC4|Cipher\.RC4|createCipheriv\(['\"]rc4", "RC4", "symmetric_encryption", "Prohibited RC4 stream cipher"),
    (r"dh\.generate_parameters|createDiffieHellman\s*\(", "DH", "key_exchange", "Classical finite-field Diffie-Hellman"),
    (r"dsa\.generate_private_key\s*\(", "DSA", "signing", "Legacy FIPS 186-4 DSA signature key"),
    (r"ssl_protocols\s+[^;]*TLSv1\.2", "RSA-2048", "tls_config", "Legacy TLSv1.2 static configuration"),
]


def ensure_sample_codebase() -> None:
    """Create synthetic sample company codebase in data/sample_app/ if missing."""
    SAMPLE_APP_DIR.mkdir(parents=True, exist_ok=True)

    py_file = SAMPLE_APP_DIR / "auth_service.py"
    if not py_file.exists():
        py_file.write_text(
            """# SYNTHETIC SAMPLE CODE FOR QUANTUM GUARD DISCOVERY SCANNER (DO NOT USE IN PRODUCTION)
import hashlib
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, dsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

def generate_legacy_auth_keys():
    # Legacy RSA-2048 keypair used for customer token signing
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # ECDSA P-256 signing key for internal microservice calls
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    # Legacy DSA key and Diffie-Hellman parameters
    dsa_key = dsa.generate_private_key(key_size=2048)
    dh_params = dh.generate_parameters(generator=2, key_size=2048)
    return rsa_key, ecc_key, dsa_key, dh_params

def legacy_checksums(payload: bytes):
    # Broken hash functions flagged by NIST IR 8547 / FIPS 180-4
    legacy_md5 = hashlib.md5(payload).hexdigest()
    legacy_sha1 = hashlib.sha1(payload).hexdigest()
    return legacy_md5, legacy_sha1

def issue_session_jwt(secret_key, user_id: str):
    token_rsa = jwt.encode({"sub": user_id}, secret_key, algorithm="RS256")
    token_ecc = jwt.encode({"sub": user_id}, secret_key, algorithm="ES256")
    return token_rsa, token_ecc

def encrypt_records(key128: bytes, key256: bytes, iv: bytes, data: bytes):
    # Legacy AES-128-CBC and 3DES usage
    cipher_128 = Cipher(algorithms.AES128(key128), modes.CBC(iv))
    cipher_3des = Cipher(algorithms.TripleDES(key128), modes.CBC(iv[:8]))
    cipher_rc4 = Cipher(algorithms.ARC4(key128), mode=None)
    # Approved AES-256-GCM
    aead = AESGCM(key256)
    return cipher_128, cipher_3des, cipher_rc4, aead
""",
            encoding="utf-8",
        )

    js_file = SAMPLE_APP_DIR / "payment_gateway.js"
    if not js_file.exists():
        js_file.write_text(
            """// SYNTHETIC SAMPLE CODE FOR QUANTUM GUARD DISCOVERY SCANNER
const crypto = require('crypto');

function negotiateChannel() {
    // Quantum-vulnerable ECDH key exchange over prime256v1 (P-256)
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return ecdh;
}

function legacyInvoiceHash(buf) {
    const md5 = crypto.createHash('md5').update(buf).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buf).digest('hex');
    const cipher = crypto.createCipheriv('AES-128-CBC', Buffer.alloc(16), Buffer.alloc(16));
    return { md5, sha1, cipher };
}
""",
            encoding="utf-8",
        )

    conf_file = SAMPLE_APP_DIR / "nginx_tls.conf"
    if not conf_file.exists():
        conf_file.write_text(
            """# SYNTHETIC NGINX CONFIGURATION FOR QUANTUM GUARD DISCOVERY SCANNER
server {
    listen 443 ssl;
    server_name legacy.enterprise.internal;
    ssl_protocols TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA;
}
""",
            encoding="utf-8",
        )


def scan_code(scan_id: int, root_folder: Path | None = None) -> List[Dict[str, Any]]:
    """Scan Python, JS, and config files for cryptographic usage patterns."""
    ensure_sample_codebase()
    target_dir = root_folder or SAMPLE_APP_DIR
    findings: List[Dict[str, Any]] = []

    conn = get_conn()
    try:
        for file_path in sorted(target_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in (".py", ".js", ".ts", ".conf", ".yaml", ".yml", ".json"):
                continue

            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for pattern, alg_name, usage, desc in CODE_RULES:
                    if re.search(pattern, line):
                        meta = lookup_algorithm(alg_name)
                        rel_name = file_path.name
                        location = f"{rel_name}:{idx}"
                        protocol = "TLSv1.2" if usage == "tls_config" else "application"
                        details = {
                            "file": rel_name,
                            "line": idx,
                            "snippet": stripped[:140],
                            "description": desc,
                            "exposure": "internal",
                            "data_secrecy_years": 10,
                        }
                        cur = conn.execute(
                            """
                            INSERT INTO assets (scan_id, source, location, algorithm, family, usage, protocol, details_json)
                            VALUES (?, 'code', ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                scan_id,
                                location,
                                alg_name,
                                meta["family"],
                                usage,
                                protocol,
                                json.dumps(details),
                            ),
                        )
                        findings.append(
                            {
                                "id": cur.lastrowid,
                                "location": location,
                                "algorithm": alg_name,
                                "usage": usage,
                                "snippet": stripped[:100],
                            }
                        )
        conn.commit()
    finally:
        conn.close()

    return findings
