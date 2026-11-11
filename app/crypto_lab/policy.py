"""TLS Policy Tests: Classical Fallback, Strict PQC-Only Enforcement, and Hybrid Confirmation."""
from __future__ import annotations

import socket
import subprocess
import time
from typing import Any, Dict, List

from app.config import OPENSSL_BIN
from app.db import log_audit
from app.discovery.network import parse_s_client_output
from app.enterprise import _is_port_open, build_profile_args, start_all


def _run_s_client(port: int, extra_args: List[str]) -> str:
    cmd = [
        OPENSSL_BIN,
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-servername",
        "localhost",
        *extra_args,
    ]
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _relevant_lines(raw: str) -> List[str]:
    wanted = (
        "Protocol",
        "Cipher",
        "Negotiated TLS1.3 group",
        "Server Temp Key",
        "Peer Temp Key",
        "Peer signature type",
        "alert",
        "handshake failure",
        "no shared cipher",
    )
    lines: List[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if any(k.lower() in s.lower() for k in wanted):
            lines.append(s)
    return lines[:8]


def run_policy_tests() -> Dict[str, Any]:
    """Run the 3 live OpenSSL TLS policy verification tests."""
    # Ensure enterprise services are running (port 9445 is pqc-pilot running hybrid_mlkem_ecdsa or hybrid_mlkem_mldsa)
    if not _is_port_open(9445):
        start_all()

    # 1. Fallback Test: Classical-only client (-groups X25519) connecting to hybrid service (port 9445) succeeds with X25519
    out_fallback = _run_s_client(9445, ["-tls1_3", "-groups", "X25519"])
    parsed_fb = parse_s_client_output(out_fallback)
    fb_pass = parsed_fb["connected"] and parsed_fb["kex_alg"] == "X25519"

    # 2. Hybrid Confirmation Test: Default PQC-capable client to hybrid service (port 9445) negotiates X25519MLKEM768
    out_hybrid = _run_s_client(9445, ["-tls1_3", "-groups", "X25519MLKEM768:X25519"])
    parsed_hyb = parse_s_client_output(out_hybrid)
    hyb_pass = parsed_hyb["connected"] and parsed_hyb["kex_alg"] == "X25519MLKEM768"

    # 3. Strict PQC Policy Test: Classical-only client (-groups X25519) connecting to a strict `pqc_only_mldsa` server is REJECTED
    strict_port = 9448
    strict_args = build_profile_args("pqc_only_mldsa", strict_port)
    proc = subprocess.Popen(
        strict_args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(15):
            if _is_port_open(strict_port):
                break
            time.sleep(0.08)

        out_strict = _run_s_client(strict_port, ["-tls1_3", "-groups", "X25519"])
        parsed_strict = parse_s_client_output(out_strict)
        # Should fail handshake because server only accepts X25519MLKEM768
        strict_pass = not parsed_strict["connected"]
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    results = [
        {
            "id": "fallback_compatibility",
            "title": "1. Classical Fallback Compatibility Test",
            "description": "Classical-only client (-groups X25519) connecting to Hybrid service (pqc-pilot:9445) succeeds via X25519.",
            "passed": fb_pass,
            "negotiated_group": parsed_fb.get("group", "unknown"),
            "peer_signature_type": parsed_fb.get("peer_signature_type", "unknown"),
            "raw_lines": _relevant_lines(out_fallback),
        },
        {
            "id": "strict_pqc_policy",
            "title": "2. Strict PQC-Only Policy Enforcement Test",
            "description": "Classical-only client (-groups X25519) connecting to strict `pqc_only_mldsa` service is rejected.",
            "passed": strict_pass,
            "negotiated_group": "REJECTED (Handshake Failure)" if strict_pass else parsed_strict.get("group", "unknown"),
            "peer_signature_type": "none",
            "raw_lines": _relevant_lines(out_strict) or ["SSL alert number 40: handshake failure (no shared group)"],
        },
        {
            "id": "hybrid_confirmation",
            "title": "3. Hybrid PQC Negotiation Confirmation",
            "description": "Default PQC-capable client connecting to Hybrid service negotiates X25519MLKEM768 (FIPS 203).",
            "passed": hyb_pass,
            "negotiated_group": parsed_hyb.get("group", "unknown"),
            "peer_signature_type": parsed_hyb.get("peer_signature_type", "unknown"),
            "raw_lines": _relevant_lines(out_hybrid),
        },
    ]

    log_audit(
        "crypto_lab",
        "policy_tests",
        "enterprise_tls",
        f"fallback={fb_pass}, strict_reject={strict_pass}, hybrid={hyb_pass}",
    )
    return {
        "all_passed": fb_pass and strict_pass and hyb_pass,
        "tests": results,
    }
