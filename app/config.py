"""Configuration, paths, thresholds, and the Algorithm Registry for Quantum Guard."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"
DB_PATH: Path = DATA_DIR / "quantum_guard.db"
CERTS_DIR: Path = DATA_DIR / "certs"
PKI_DIR: Path = DATA_DIR / "pki"
SCANS_DIR: Path = DATA_DIR / "scans"
SAMPLE_APP_DIR: Path = DATA_DIR / "sample_app"
MASTER_KEY_PATH: Path = DATA_DIR / ".master_key"

for _d in (DATA_DIR, CERTS_DIR, PKI_DIR, SCANS_DIR, SAMPLE_APP_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def find_openssl_bin() -> str:
    """Locate the OpenSSL CLI binary (preferring 3.5+ installations)."""
    env_bin = os.environ.get("OPENSSL_BIN")
    if env_bin and Path(env_bin).exists():
        return env_bin

    candidates = [
        r"A:\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c

    which_bin = shutil.which("openssl")
    return which_bin or "openssl"


OPENSSL_BIN: str = find_openssl_bin()

# NIST IR 8547 timeline & Mosca defaults
IR8547_DEPRECATION_YEAR: int = 2030
IR8547_DISALLOWANCE_YEAR: int = 2035
DEFAULT_MIGRATION_YEARS: int = 3
DEFAULT_YEARS_TO_CRQC: int = 10

# Simulated Enterprise Services (Prompt 1)
DEFAULT_SERVICES: List[Dict[str, Any]] = [
    {
        "name": "legacy-web",
        "port": 9441,
        "exposure": "public",
        "data_secrecy_years": 2,
        "profile": "legacy_tls12_rsa",
    },
    {
        "name": "customer-api",
        "port": 9442,
        "exposure": "public",
        "data_secrecy_years": 5,
        "profile": "tls13_ecdhe_ecdsa",
    },
    {
        "name": "payments-core",
        "port": 9443,
        "exposure": "internal",
        "data_secrecy_years": 15,
        "profile": "tls13_ecdhe_rsa",
    },
    {
        "name": "hr-records",
        "port": 9444,
        "exposure": "internal",
        "data_secrecy_years": 25,
        "profile": "tls13_ecdhe_ecdsa",
    },
    {
        "name": "pqc-pilot",
        "port": 9445,
        "exposure": "internal",
        "data_secrecy_years": 10,
        "profile": "hybrid_mlkem_ecdsa",
    },
]

# Algorithm Registry mapping algorithm names to metadata
# quantum_status values: "vulnerable", "pqc", "hybrid", "symmetric_ok", "weak", "broken"
ALGORITHM_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Classical RSA
    "RSA-2048": {
        "family": "rsa",
        "type": "signature",
        "standard": "FIPS 186-5 / SP 800-56B",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "RSA-3072": {
        "family": "rsa",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "RSA-4096": {
        "family": "rsa",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "RSA": {
        "family": "rsa",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "RS256": {
        "family": "rsa",
        "type": "signature",
        "standard": "RFC 7518 (JWS)",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    # Classical ECC / ECDH / X25519 / DH / DSA
    "ECDSA-P256": {
        "family": "ecc",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "ECDSA-P384": {
        "family": "ecc",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "ECDSA": {
        "family": "ecc",
        "type": "signature",
        "standard": "FIPS 186-5",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "ES256": {
        "family": "ecc",
        "type": "signature",
        "standard": "RFC 7518 (JWS)",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "Ed25519": {
        "family": "ecc",
        "type": "signature",
        "standard": "FIPS 186-5 / RFC 8032",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "ECDH-P256": {
        "family": "ecc",
        "type": "kex",
        "standard": "SP 800-56A",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "P-256": {
        "family": "ecc",
        "type": "kex",
        "standard": "SP 800-56A",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "X25519": {
        "family": "x25519",
        "type": "kex",
        "standard": "RFC 7748 / SP 800-56A",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "ECDHE": {
        "family": "ecc",
        "type": "kex",
        "standard": "SP 800-56A",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "DH": {
        "family": "dh",
        "type": "kex",
        "standard": "SP 800-56A",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    "DSA": {
        "family": "dsa",
        "type": "signature",
        "standard": "FIPS 186-4",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    },
    # Hybrid KEM / KEX
    "X25519MLKEM768": {
        "family": "ml-kem",
        "type": "kem",
        "standard": "FIPS 203 + RFC 7748 (Hybrid)",
        "quantum_status": "hybrid",
        "nist_level": 3,
    },
    "SecP256r1MLKEM768": {
        "family": "ml-kem",
        "type": "kem",
        "standard": "FIPS 203 + SP 800-56A (Hybrid)",
        "quantum_status": "hybrid",
        "nist_level": 3,
    },
    # Post-Quantum KEM (FIPS 203)
    "ML-KEM-512": {
        "family": "ml-kem",
        "type": "kem",
        "standard": "FIPS 203",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    "ML-KEM-768": {
        "family": "ml-kem",
        "type": "kem",
        "standard": "FIPS 203",
        "quantum_status": "pqc",
        "nist_level": 3,
    },
    "ML-KEM-1024": {
        "family": "ml-kem",
        "type": "kem",
        "standard": "FIPS 203",
        "quantum_status": "pqc",
        "nist_level": 5,
    },
    # Post-Quantum Digital Signatures (FIPS 204 - ML-DSA)
    "ML-DSA-44": {
        "family": "ml-dsa",
        "type": "signature",
        "standard": "FIPS 204",
        "quantum_status": "pqc",
        "nist_level": 2,
    },
    "ML-DSA-65": {
        "family": "ml-dsa",
        "type": "signature",
        "standard": "FIPS 204",
        "quantum_status": "pqc",
        "nist_level": 3,
    },
    "ML-DSA-87": {
        "family": "ml-dsa",
        "type": "signature",
        "standard": "FIPS 204",
        "quantum_status": "pqc",
        "nist_level": 5,
    },
    # Post-Quantum Hash-Based Signatures (FIPS 205 - SLH-DSA)
    "SLH-DSA-SHA2-128s": {
        "family": "slh-dsa",
        "type": "signature",
        "standard": "FIPS 205",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    "SLH-DSA-SHA2-128f": {
        "family": "slh-dsa",
        "type": "signature",
        "standard": "FIPS 205",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    "SLH-DSA-SHAKE-128s": {
        "family": "slh-dsa",
        "type": "signature",
        "standard": "FIPS 205",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    "SLH-DSA-SHAKE-128f": {
        "family": "slh-dsa",
        "type": "signature",
        "standard": "FIPS 205",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    "SLH-DSA": {
        "family": "slh-dsa",
        "type": "signature",
        "standard": "FIPS 205",
        "quantum_status": "pqc",
        "nist_level": 1,
    },
    # Symmetric & Hashes
    "AES-256-GCM": {
        "family": "aes",
        "type": "symmetric",
        "standard": "FIPS 197 / SP 800-38D",
        "quantum_status": "symmetric_ok",
        "nist_level": 5,
    },
    "AES-256": {
        "family": "aes",
        "type": "symmetric",
        "standard": "FIPS 197",
        "quantum_status": "symmetric_ok",
        "nist_level": 5,
    },
    "AES-128-GCM": {
        "family": "aes",
        "type": "symmetric",
        "standard": "FIPS 197 / SP 800-38D",
        "quantum_status": "weak",
        "nist_level": 1,
    },
    "AES-128-CBC": {
        "family": "aes",
        "type": "symmetric",
        "standard": "FIPS 197 / SP 800-38A",
        "quantum_status": "weak",
        "nist_level": 1,
    },
    "AES-128": {
        "family": "aes",
        "type": "symmetric",
        "standard": "FIPS 197",
        "quantum_status": "weak",
        "nist_level": 1,
    },
    "SHA-256": {
        "family": "sha",
        "type": "hash",
        "standard": "FIPS 180-4",
        "quantum_status": "symmetric_ok",
        "nist_level": 3,
    },
    "SHA-384": {
        "family": "sha",
        "type": "hash",
        "standard": "FIPS 180-4",
        "quantum_status": "symmetric_ok",
        "nist_level": 5,
    },
    "SHA-512": {
        "family": "sha",
        "type": "hash",
        "standard": "FIPS 180-4",
        "quantum_status": "symmetric_ok",
        "nist_level": 5,
    },
    # Broken / Legacy
    "MD5": {
        "family": "md5",
        "type": "hash",
        "standard": "RFC 1321 (Broken)",
        "quantum_status": "broken",
        "nist_level": 0,
    },
    "SHA-1": {
        "family": "sha1",
        "type": "hash",
        "standard": "FIPS 180-4 (Deprecated/Broken)",
        "quantum_status": "broken",
        "nist_level": 0,
    },
    "DES": {
        "family": "des",
        "type": "symmetric",
        "standard": "FIPS 46-3 (Withdrawn)",
        "quantum_status": "broken",
        "nist_level": 0,
    },
    "3DES": {
        "family": "3des",
        "type": "symmetric",
        "standard": "SP 800-67 (Disallowed)",
        "quantum_status": "broken",
        "nist_level": 0,
    },
    "RC4": {
        "family": "rc4",
        "type": "symmetric",
        "standard": "RFC 7465 (Prohibited)",
        "quantum_status": "broken",
        "nist_level": 0,
    },
}


def lookup_algorithm(alg_name: str) -> Dict[str, Any]:
    """Lookup algorithm metadata from registry with normalized fallback matching."""
    if not alg_name:
        return {
            "family": "unknown",
            "type": "unknown",
            "standard": "Unknown",
            "quantum_status": "vulnerable",
            "nist_level": 0,
        }
    if alg_name in ALGORITHM_REGISTRY:
        return ALGORITHM_REGISTRY[alg_name]

    upper = alg_name.upper().strip()
    for key, val in ALGORITHM_REGISTRY.items():
        if key.upper() == upper:
            return val

    # Substring heuristics for TLS / OpenSSL output variants
    if "X25519MLKEM768" in upper or "MLKEM" in upper and ("X25519" in upper or "SECP" in upper):
        return ALGORITHM_REGISTRY["X25519MLKEM768"]
    if "ML-KEM-768" in upper or "MLKEM768" in upper:
        return ALGORITHM_REGISTRY["ML-KEM-768"]
    if "ML-KEM-512" in upper or "MLKEM512" in upper:
        return ALGORITHM_REGISTRY["ML-KEM-512"]
    if "ML-KEM-1024" in upper or "MLKEM1024" in upper:
        return ALGORITHM_REGISTRY["ML-KEM-1024"]
    if "ML-DSA-87" in upper or "MLDSA87" in upper:
        return ALGORITHM_REGISTRY["ML-DSA-87"]
    if "ML-DSA-65" in upper or "MLDSA65" in upper:
        return ALGORITHM_REGISTRY["ML-DSA-65"]
    if "ML-DSA-44" in upper or "MLDSA44" in upper:
        return ALGORITHM_REGISTRY["ML-DSA-44"]
    if "SLH-DSA" in upper or "SLHDSA" in upper:
        return ALGORITHM_REGISTRY["SLH-DSA-SHA2-128s"]
    if "X25519" in upper:
        return ALGORITHM_REGISTRY["X25519"]
    if "ECDSA" in upper:
        if "384" in upper:
            return ALGORITHM_REGISTRY["ECDSA-P384"]
        return ALGORITHM_REGISTRY["ECDSA-P256"]
    if "ECDHE" in upper or "ECDH" in upper or "P-256" in upper or "PRIME256V1" in upper:
        return ALGORITHM_REGISTRY["ECDH-P256"]
    if "RSA" in upper or "RS256" in upper:
        return ALGORITHM_REGISTRY["RSA-2048"]
    if "AES-256" in upper or "AES256" in upper:
        return ALGORITHM_REGISTRY["AES-256-GCM"]
    if "AES-128" in upper or "AES128" in upper:
        return ALGORITHM_REGISTRY["AES-128-GCM"]
    if "MD5" in upper:
        return ALGORITHM_REGISTRY["MD5"]
    if "SHA-1" in upper or "SHA1" in upper:
        return ALGORITHM_REGISTRY["SHA-1"]
    if "3DES" in upper or "DES-EDE" in upper:
        return ALGORITHM_REGISTRY["3DES"]
    if "DES" in upper:
        return ALGORITHM_REGISTRY["DES"]
    if "RC4" in upper:
        return ALGORITHM_REGISTRY["RC4"]

    return {
        "family": "unknown",
        "type": "unknown",
        "standard": "Unknown",
        "quantum_status": "vulnerable",
        "nist_level": 0,
    }
