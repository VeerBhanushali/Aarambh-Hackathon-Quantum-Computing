"""Live real-world TLS scanner: is a public website quantum-ready?

Probes a public host on port 443 with `openssl s_client` (OpenSSL 3.5+) and reports whether it negotiates the
hybrid post-quantum group X25519MLKEM768, which TLS version it speaks, and which certificate algorithm it uses.

Safety: only DNS hostnames, only port 443, and the resolved addresses must all be public (no loopback, private,
link-local or reserved ranges), so the endpoint cannot be used to probe internal networks.

Honesty: the certificate chain is verified against the public Mozilla trust store (certifi). If verification fails,
a proxy or firewall is probably intercepting TLS, and the results describe that proxy, not the website; the
response says so instead of reporting misleading numbers.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from typing import Any, Dict, List

from app.config import OPENSSL_BIN
from app.db import log_audit
from app.discovery.network import parse_s_client_output

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")

# Default suggestions for the UI; results are always measured live, never stored here.
SUGGESTED_HOSTS: List[str] = [
    "cloudflare.com",
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.in",
    "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
]


def _mozilla_ca_file() -> str | None:
    """Path to the Mozilla CA bundle shipped with certifi (public trust only, no local/proxy CAs)."""
    try:
        import certifi

        return certifi.where()
    except Exception:
        return None


def normalize_host(raw: str) -> str:
    """Turn user input like 'https://www.Bank.com/login' into 'www.bank.com'; raise ValueError if invalid."""
    h = (raw or "").strip().lower()
    h = re.sub(r"^[a-z]+://", "", h)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    if ":" in h:
        host, port = h.rsplit(":", 1)
        if port not in ("", "443"):
            raise ValueError("Only port 443 (HTTPS) can be scanned.")
        h = host
    h = h.rstrip(".")
    if not _HOST_RE.match(h):
        raise ValueError("Enter a public website name such as example.com (IP addresses are not accepted).")
    return h


def _check_public(host: str) -> List[str]:
    """Resolve host and refuse anything that is not a public internet address."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {host}: {exc.strerror or exc}") from exc
    addrs = sorted({info[4][0] for info in infos})
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_global:
            raise ValueError(f"{host} resolves to a non-public address ({a}); only public websites can be scanned.")
    return addrs


def _s_client(host: str, extra: List[str], timeout: float = 8.0) -> tuple[str, float]:
    """Run one s_client probe and return (combined output, elapsed ms)."""
    cmd = [OPENSSL_BIN, "s_client", "-connect", f"{host}:443", "-servername", host, *extra]
    ca = _mozilla_ca_file()
    if ca:
        cmd += ["-CAfile", ca, "-verify_hostname", host]
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired:
        out = "PROBE_TIMEOUT"
    return out, round((time.perf_counter() - t0) * 1000, 1)


def _verify_result(raw: str) -> Dict[str, Any]:
    m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", raw)
    issuer = re.search(r"^issuer=(.+)$", raw, re.MULTILINE)
    code = int(m.group(1)) if m else -1
    return {
        "verified": code == 0,
        "verify_message": m.group(2) if m else "no verification result",
        "issuer": issuer.group(1).strip() if issuer else "unknown",
    }


def assess_live(pqc: Dict[str, Any], default: Dict[str, Any], tls12_ok: bool) -> Dict[str, Any]:
    """Turn probe results into a verdict, score and plain-language reasons (pure function, unit-tested)."""
    reasons: List[str] = []
    if pqc["connected"] and pqc["kex_alg"] == "X25519MLKEM768":
        kex_status = "hybrid"
        score = 10
        verdict = "Quantum-ready key exchange"
        reasons.append("Negotiates X25519MLKEM768 (FIPS 203 ML-KEM + X25519): recorded traffic is protected against harvest-now-decrypt-later.")
    elif default["connected"]:
        kex_status = "vulnerable"
        score = 80
        verdict = "Not quantum-ready"
        reasons.append(
            f"Refused the post-quantum hybrid group and fell back to {default['kex_alg']}: traffic recorded today could be decrypted by a future quantum computer."
        )
    else:
        return {"verdict": "Unreachable", "score": None, "kex_status": "unknown", "reasons": ["No TLS handshake completed."]}

    sig = (pqc if pqc["connected"] else default).get("sig_alg", "unknown")
    if sig.startswith("ML-DSA") or sig.startswith("SLH-DSA"):
        reasons.append(f"Certificate uses {sig} (post-quantum signature).")
    elif sig != "unknown":
        reasons.append(
            f"Certificate signs with {sig}: expected today, since public CAs do not issue ML-DSA certificates yet. Must migrate before 2030-2035 (NIST IR 8547)."
        )
    if tls12_ok:
        reasons.append("Still accepts TLS 1.2, which cannot carry post-quantum key exchange; old clients get no protection.")
        if kex_status == "hybrid":
            score = max(score, 15)
    return {"verdict": verdict, "score": score, "kex_status": kex_status, "reasons": reasons}


def scan_public_host(raw_host: str) -> Dict[str, Any]:
    """Probe a public website and report its post-quantum readiness."""
    host = normalize_host(raw_host)
    addrs = _check_public(host)

    out_pqc, ms_pqc = _s_client(host, ["-tls1_3", "-groups", "X25519MLKEM768:X25519"])
    out_def, ms_def = _s_client(host, ["-tls1_3", "-groups", "X25519:P-256"])
    out_12, _ = _s_client(host, ["-tls1_2", "-no_tls1_3"])

    pqc = parse_s_client_output(out_pqc)
    default = parse_s_client_output(out_def)
    tls12 = parse_s_client_output(out_12)
    trust = _verify_result(out_pqc if pqc["connected"] else out_def)

    result: Dict[str, Any] = {
        "host": host,
        "addresses": addrs,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "openssl": OPENSSL_BIN,
        "pqc_probe": {
            "offered": "X25519MLKEM768, X25519",
            "connected": pqc["connected"],
            "negotiated_group": pqc["group"],
            "protocol": pqc["protocol"],
            "cipher": pqc["cipher"],
            "handshake_ms": ms_pqc,
        },
        "classical_probe": {
            "offered": "X25519, P-256",
            "connected": default["connected"],
            "negotiated_group": default["group"],
            "handshake_ms": ms_def,
        },
        "tls12_accepted": tls12["connected"],
        "certificate": {
            "signature_algorithm": (pqc if pqc["connected"] else default).get("sig_alg", "unknown"),
            "peer_signature_type": (pqc if pqc["connected"] else default).get("peer_signature_type", "unknown"),
            **trust,
        },
        "interception_suspected": (pqc["connected"] or default["connected"]) and not trust["verified"],
        **assess_live(pqc, default, tls12["connected"]),
    }
    if result["interception_suspected"]:
        # Never report the proxy's crypto as the website's.
        result["verdict"] = "Cannot tell — TLS is being intercepted on this network"
        result["score"] = None
        result["kex_status"] = "unknown"
        result["reasons"] = [
            "The negotiated group and certificate shown below belong to the intercepting proxy, so they say nothing about this website."
        ]
        result["warning"] = (
            f"The certificate did not verify against the public Mozilla trust store (issuer: {trust['issuer']}). "
            "A proxy or firewall on this network is probably intercepting TLS, so these results describe the proxy, "
            "not the website. Re-run on an unfiltered network (e.g. a phone hotspot)."
        )
    log_audit("live_scan", "scan_public_host", host, f"verdict={result['verdict']}, intercepted={result['interception_suspected']}")
    return result
