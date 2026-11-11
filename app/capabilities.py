"""Runtime capability detection for OpenSSL 3.5+ and liboqs-python."""
from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from app.config import OPENSSL_BIN

_CACHED_CAPABILITIES: Optional[Dict[str, Any]] = None


def _run_openssl(args: List[str], timeout: float = 5.0) -> str:
    """Run an openssl CLI command and return combined stdout."""
    try:
        proc = subprocess.run(
            [OPENSSL_BIN, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception as exc:
        return f"ERROR: {exc}"


def _parse_openssl_version(version_str: str) -> tuple[int, int, int]:
    """Extract (major, minor, patch) from `openssl version` output."""
    match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", version_str)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def detect_capabilities(force_refresh: bool = False) -> Dict[str, Any]:
    """Detect OpenSSL 3.5+ PQC support and optional liboqs mechanisms."""
    global _CACHED_CAPABILITIES
    if _CACHED_CAPABILITIES is not None and not force_refresh:
        return _CACHED_CAPABILITIES

    version_out = _run_openssl(["version"]).strip().splitlines()[0] if OPENSSL_BIN else "Not found"
    major, minor, patch = _parse_openssl_version(version_out)
    openssl_ge_35 = (major > 3) or (major == 3 and minor >= 5)

    kem_out = _run_openssl(["list", "-kem-algorithms"]) if openssl_ge_35 else ""
    sig_out = _run_openssl(["list", "-signature-algorithms"]) if openssl_ge_35 else ""

    openssl_mlkem = "ML-KEM-768" in kem_out or "MLKEM768" in kem_out
    openssl_mldsa = "ML-DSA-65" in sig_out or "MLDSA65" in sig_out
    openssl_slhdsa = "SLH-DSA" in sig_out

    # Check liboqs-python availability dynamically without hardcoding mechanism names
    oqs_available = False
    oqs_version = None
    oqs_mlkem_768 = None
    oqs_mldsa_65 = None
    oqs_slhdsa = None
    enabled_kems: List[str] = []
    enabled_sigs: List[str] = []

    try:
        import oqs  # type: ignore

        oqs_available = True
        oqs_version = getattr(oqs, "__version__", "installed")
        enabled_kems = list(oqs.get_enabled_kem_mechanisms())
        enabled_sigs = list(oqs.get_enabled_sig_mechanisms())

        for k in enabled_kems:
            if "ML-KEM-768" in k.upper() or "KYBER768" in k.upper():
                oqs_mlkem_768 = k
                break

        for s in enabled_sigs:
            if "ML-DSA-65" in s.upper() or "DILITHIUM3" in s.upper():
                oqs_mldsa_65 = s
                break

        for s in enabled_sigs:
            if "SLH_DSA" in s.upper() or "SLH-DSA" in s.upper() or "SPHINCS" in s.upper():
                oqs_slhdsa = s
                break
    except Exception:
        oqs_available = False

    _CACHED_CAPABILITIES = {
        "openssl_bin": OPENSSL_BIN,
        "openssl_version": version_out,
        "openssl_version_tuple": [major, minor, patch],
        "openssl_ge_35": openssl_ge_35,
        "openssl_mlkem": openssl_mlkem,
        "openssl_mldsa": openssl_mldsa,
        "openssl_slhdsa": openssl_slhdsa,
        "oqs_available": oqs_available,
        "oqs_version": oqs_version,
        "oqs_mechanisms": {
            "ml_kem_768": oqs_mlkem_768 or ("ML-KEM-768 (OpenSSL CLI)" if openssl_mlkem else None),
            "ml_dsa_65": oqs_mldsa_65 or ("ML-DSA-65 (OpenSSL CLI)" if openssl_mldsa else None),
            "slh_dsa": oqs_slhdsa or ("SLH-DSA-SHA2-128s (OpenSSL CLI)" if openssl_slhdsa else None),
        },
        "pqc_backend": "liboqs" if oqs_available else ("openssl-3.5-cli" if openssl_ge_35 else "degraded"),
        "machine": {
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor() or platform.machine(),
            "cores": os.cpu_count() if "os" in sys.modules else 4,
            "python": sys.version.split()[0],
        },
    }
    return _CACHED_CAPABILITIES
