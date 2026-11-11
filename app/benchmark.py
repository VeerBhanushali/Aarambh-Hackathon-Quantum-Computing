"""Performance Benchmarking Module: Fair In-Process `openssl speed` + Secondary Micro/Handshake Benchmarks."""
from __future__ import annotations

import csv
import io
import json
import re
import statistics
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

from app.capabilities import detect_capabilities
from app.config import OPENSSL_BIN
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso
from app.enterprise import _is_port_open, build_profile_args, spawn_tls_server, stop_process

# FIPS 203 / 204 / 205 & Classical exact byte lengths for (public_key_bytes, ciphertext_or_signature_bytes)
FIPS_SIZES: Dict[str, Tuple[int, int]] = {
    "X25519": (32, 32),
    "ECDH-P256": (65, 32),
    "RSA-2048": (256, 256),
    "RSA-3072": (384, 384),
    "ECDSA-P256": (65, 72),
    "Ed25519": (32, 64),
    "ML-KEM-512": (800, 768),
    "ML-KEM-768": (1184, 1088),
    "ML-KEM-1024": (1568, 1568),
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
    "SLH-DSA-SHA2-128s": (32, 7856),
    "SLH-DSA-SHA2-128f": (32, 17088),
}


def _stats(wall_samples_ms: List[float], cpu_samples_ms: List[float]) -> Tuple[float, float, float]:
    """Compute (median_ms, p95_ms, cpu_median_ms) from sample lists."""
    if not wall_samples_ms:
        return (0.0, 0.0, 0.0)
    s_wall = sorted(wall_samples_ms)
    med = statistics.median(s_wall)
    idx_95 = min(len(s_wall) - 1, max(0, int(len(s_wall) * 0.95) - 1))
    p95 = s_wall[idx_95]
    cpu_med = statistics.median(cpu_samples_ms) if cpu_samples_ms else med
    return (round(med, 4), round(p95, 4), round(cpu_med, 4))


def _time_callable(fn: Callable[[], Any], n: int, warmup: int = 5) -> Tuple[float, float, float]:
    """Run fn with warmup and n timed iterations using perf_counter and process_time."""
    for _ in range(warmup):
        fn()
    wall_ms: List[float] = []
    cpu_ms: List[float] = []
    for _ in range(n):
        w0 = time.perf_counter()
        c0 = time.process_time()
        fn()
        c1 = time.process_time()
        w1 = time.perf_counter()
        wall_ms.append((w1 - w0) * 1000.0)
        cpu_ms.append((c1 - c0) * 1000.0)
    return _stats(wall_ms, cpu_ms)


def run_openssl_speed_suite(seconds: int = 1) -> List[Dict[str, Any]]:
    """Run in-process `openssl speed` across BOTH Classical and PQC algorithms for an apples-to-apples comparison.

    Parses ops/sec directly from OpenSSL 3.5+ `speed` output into milliseconds per operation (`1000 / ops_per_sec`)
    and stores them under category `openssl_speed`.
    """
    classical = ["rsa2048", "rsa3072", "ecdsap256", "ecdhp256", "ecdhx25519", "ed25519"]
    pqc = [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    ]
    # Older OpenSSL rejects the whole command on an unknown algorithm name, so only ask for PQC on 3.5+.
    algs = classical + (pqc if detect_capabilities().get("openssl_ge_35") else [])
    cmd = [OPENSSL_BIN, "speed", "-seconds", str(max(1, min(3, seconds))), *algs]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120.0, check=False)
    raw = (proc.stdout or "") + "\n" + (proc.stderr or "")

    results: List[Dict[str, Any]] = []

    def _add(name: str, alg_key: str, sec_per_op: float, ops_sec: float, subkind: str) -> None:
        pk_b, ct_b = FIPS_SIZES.get(alg_key, (0, 0))
        ms = round(sec_per_op * 1000.0, 4)
        # `openssl speed` reports only aggregate throughput, so this is a MEAN (1000/ops_per_sec).
        # Per-operation p95 and CPU time are not observable here and are stored as NULL rather than invented.
        results.append(
            {
                "name": name,
                "category": "openssl_speed",
                "n": max(1, int(round(ops_sec))),
                "median_ms": ms,
                "p95_ms": None,
                "cpu_ms": None,
                "pubkey_bytes": pk_b,
                "ct_or_sig_bytes": ct_b,
                "note": f"openssl speed mean over ~1s ({ops_sec:,.1f} ops/sec · {subkind}); sizes per FIPS/RFC spec; p95/CPU n/a",
            }
        )

    for line in raw.splitlines():
        s = line.strip()
        # 1. X25519 ECDH: "253 bits ecdh (X25519)   0.0001s   8417.6"
        m_x = re.match(r"253 bits ecdh \(X25519\)\s+([0-9.]+)s\s+([0-9.]+)", s)
        if m_x:
            ops = float(m_x.group(2))
            _add("X25519 (ECDH Exchange)", "X25519", 1.0 / ops if ops else float(m_x.group(1)), ops, "Classical KEX")
            continue

        # 2. P-256 ECDH: "256 bits ecdh (nistp256)   0.0012s    826.3"
        m_p256 = re.match(r"256 bits ecdh \(nistp256\)\s+([0-9.]+)s\s+([0-9.]+)", s)
        if m_p256:
            ops = float(m_p256.group(2))
            _add("ECDH P-256 (Exchange)", "ECDH-P256", 1.0 / ops if ops else float(m_p256.group(1)), ops, "Classical KEX")
            continue

        # 3. ECDSA P-256: "256 bits ecdsa (nistp256)   0.0014s   0.0011s    714.9    881.0"
        m_ecdsa = re.match(r"256 bits ecdsa \(nistp256\)\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)", s)
        if m_ecdsa:
            s_ops, v_ops = float(m_ecdsa.group(3)), float(m_ecdsa.group(4))
            _add("ECDSA P-256 (sign)", "ECDSA-P256", 1.0 / s_ops if s_ops else float(m_ecdsa.group(1)), s_ops, "Classical Sig")
            _add("ECDSA P-256 (verify)", "ECDSA-P256", 1.0 / v_ops if v_ops else float(m_ecdsa.group(2)), v_ops, "Classical Sig")
            continue

        # 4. Ed25519: "253 bits EdDSA (Ed25519)   0.0001s   0.0002s  15230.1   5645.3"
        m_ed = re.match(r"253 bits EdDSA \(Ed25519\)\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)", s)
        if m_ed:
            s_ops, v_ops = float(m_ed.group(3)), float(m_ed.group(4))
            _add("Ed25519 (sign)", "Ed25519", 1.0 / s_ops if s_ops else float(m_ed.group(1)), s_ops, "Classical Sig")
            _add("Ed25519 (verify)", "Ed25519", 1.0 / v_ops if v_ops else float(m_ed.group(2)), v_ops, "Classical Sig")
            continue

        # 5. RSA classic line: "rsa  2048 bits 0.002049s 0.000050s 0.000050s 0.005130s    488.1  19861.7  19912.3    194.9"
        m_rsa = re.match(
            r"rsa\s+(2048|3072) bits\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)",
            s,
        )
        if m_rsa:
            bits = m_rsa.group(1)
            g = [m_rsa.group(i) for i in range(2, 10)]
            s_ops, v_ops, e_ops, d_ops = float(g[4]), float(g[5]), float(g[6]), float(g[7])
            alg = f"RSA-{bits}"
            if bits == "2048":
                _add("RSA-2048 (encaps / encrypt)", alg, 1.0 / e_ops if e_ops else float(g[2]), e_ops, "Classical KEM")
                _add("RSA-2048 (decaps / decrypt)", alg, 1.0 / d_ops if d_ops else float(g[3]), d_ops, "Classical KEM")
            _add(f"{alg} (sign)", alg, 1.0 / s_ops if s_ops else float(g[0]), s_ops, "Classical Sig")
            _add(f"{alg} (verify)", alg, 1.0 / v_ops if v_ops else float(g[1]), v_ops, "Classical Sig")
            continue

        # 6. ML-KEM-512 / 768 / 1024 table lines:
        # "ML-KEM-768 0.000133s 0.000064s 0.000103s    7524.0   15521.7    9668.0"
        m_kem = re.match(
            r"(ML-KEM-(?:512|768|1024))\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)",
            s,
        )
        if m_kem:
            alg = m_kem.group(1)
            kg_ops, enc_ops, dec_ops = float(m_kem.group(5)), float(m_kem.group(6)), float(m_kem.group(7))
            _add(f"{alg} (keygen)", alg, 1.0 / kg_ops if kg_ops else float(m_kem.group(2)), kg_ops, "FIPS 203 KEM")
            _add(f"{alg} (encaps)", alg, 1.0 / enc_ops if enc_ops else float(m_kem.group(3)), enc_ops, "FIPS 203 KEM")
            _add(f"{alg} (decaps)", alg, 1.0 / dec_ops if dec_ops else float(m_kem.group(4)), dec_ops, "FIPS 203 KEM")
            continue

        # 7. ML-DSA-44 / 65 / 87 and SLH-DSA-SHA2-128s / 128f table lines:
        # "ML-DSA-65 0.000396s 0.002102s 0.000393s    2525.4     475.7    2544.7"
        m_sig = re.match(
            r"((?:ML-DSA-(?:44|65|87))|(?:SLH-DSA-SHA2-128[sf]))\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)",
            s,
        )
        if m_sig:
            alg = m_sig.group(1)
            kg_ops, s_ops, v_ops = float(m_sig.group(5)), float(m_sig.group(6)), float(m_sig.group(7))
            std_lbl = "FIPS 205 Hash Sig" if "SLH-DSA" in alg else "FIPS 204 Lattice Sig"
            _add(f"{alg} (keygen)", alg, 1.0 / kg_ops if kg_ops else float(m_sig.group(2)), kg_ops, std_lbl)
            _add(f"{alg} (sign)", alg, 1.0 / s_ops if s_ops else float(m_sig.group(3)), s_ops, std_lbl)
            _add(f"{alg} (verify)", alg, 1.0 / v_ops if v_ops else float(m_sig.group(4)), v_ops, std_lbl)
            continue

    return results


def _measure_tls_handshakes(n_handshakes: int = 30) -> List[Dict[str, Any]]:
    """Benchmark TLS 1.3 handshakes across Classical, Hybrid (ML-KEM + ECDSA), and Full PQC (ML-KEM + ML-DSA)."""
    profiles = [
        ("TLS 1.3 Classical (X25519 + ECDSA-P256)", "tls13_ecdhe_ecdsa", 9451, 32, 72),
        ("TLS 1.3 Hybrid (X25519MLKEM768 + ECDSA-P256)", "hybrid_mlkem_ecdsa", 9452, 1216, 1088),
        ("TLS 1.3 Full PQC (X25519MLKEM768 + ML-DSA-65)", "hybrid_mlkem_mldsa", 9453, 1952, 3309),
    ]
    results: List[Dict[str, Any]] = []

    for label, profile, port, pk_bytes, _ in profiles:
        try:
            args = build_profile_args(profile, port)
        except Exception as exc:
            results.append(_unavailable_row(label, "tls_handshake", f"profile unavailable: {exc}"))
            continue
        proc = spawn_tls_server(args, port)
        try:
            if not _is_port_open(port):
                results.append(_unavailable_row(label, "tls_handshake", "s_server failed to start (needs OpenSSL 3.5+)"))
                continue

            wall_ms: List[float] = []
            cpu_ms: List[float] = []
            bytes_exchanged = 0
            negotiated = "unknown"

            for _ in range(n_handshakes):
                w0 = time.perf_counter()
                p = subprocess.run(
                    [
                        OPENSSL_BIN,
                        "s_client",
                        "-connect",
                        f"127.0.0.1:{port}",
                        "-tls1_3",
                        "-groups",
                        # A classical client offers only X25519; otherwise the classical row would carry an
                        # unused 1,216 B ML-KEM key share plus a HelloRetryRequest round trip.
                        "X25519" if profile == "tls13_ecdhe_ecdsa" else "X25519MLKEM768:X25519",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    check=False,
                )
                w1 = time.perf_counter()
                wall_ms.append((w1 - w0) * 1000.0)

                out = (p.stdout or "") + "\n" + (p.stderr or "")
                m = re.search(r"SSL handshake has read\s+(\d+)\s+bytes and written\s+(\d+)\s+bytes", out)
                if m:
                    bytes_exchanged = int(m.group(1)) + int(m.group(2))
                g = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", out)
                if g:
                    negotiated = g.group(1)

            med, p95, _ = _stats(wall_ms, wall_ms)
            bytes_note = f"handshake bytes read+written = {bytes_exchanged} B" if bytes_exchanged else "handshake bytes not reported by s_client"
            results.append(
                {
                    "name": label,
                    "category": "tls_handshake",
                    "n": n_handshakes,
                    "median_ms": med,
                    "p95_ms": p95,
                    # CPU time of the s_client child is not visible to process_time() of this process.
                    "cpu_ms": None,
                    "pubkey_bytes": pk_bytes,
                    "ct_or_sig_bytes": bytes_exchanged,
                    "note": (
                        f"Wall time of a full `openssl s_client` run incl. process start-up; relative comparison only. "
                        f"Negotiated group: {negotiated}; {bytes_note}"
                    ),
                }
            )
        finally:
            stop_process(proc)

    return results


def _unavailable_row(name: str, category: str, reason: str) -> Dict[str, Any]:
    """A row that records that a measurement could not be taken (never a made-up number)."""
    return {
        "name": name,
        "category": category,
        "n": 0,
        "median_ms": 0.0,
        "p95_ms": None,
        "cpu_ms": None,
        "pubkey_bytes": 0,
        "ct_or_sig_bytes": 0,
        "note": f"UNAVAILABLE: {reason}",
    }


def _measure_python_cryptography_secondary(n: int = 40) -> List[Dict[str, Any]]:
    """Secondary table: in-process Python `cryptography` classical micro-benchmarks labeled clearly."""
    rows: List[Dict[str, Any]] = []
    msg = b"Quantum Guard Benchmark Payload"

    rx_x = x25519.X25519PrivateKey.generate().public_key()
    med, p95, cpu_m = _time_callable(lambda: x25519.X25519PrivateKey.generate().exchange(rx_x), n)
    rows.append(
        {
            "name": "Python cryptography: X25519 (Keygen+ECDH)",
            "category": "python_cryptography",
            "n": n,
            "median_ms": med,
            "p95_ms": p95,
            "cpu_ms": cpu_m,
            "pubkey_bytes": 32,
            "ct_or_sig_bytes": 32,
            "note": "Secondary: Python cryptography library in-process",
        }
    )

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    sig = rsa_priv.sign(msg, pss, hashes.SHA256())
    med_s, p95_s, cpu_s = _time_callable(lambda: rsa_priv.sign(msg, pss, hashes.SHA256()), n)
    med_v, p95_v, cpu_v = _time_callable(lambda: rsa_pub.verify(sig, msg, pss, hashes.SHA256()), n)
    rows.append(
        {
            "name": "Python cryptography: RSA-2048 (PSS sign)",
            "category": "python_cryptography",
            "n": n,
            "median_ms": med_s,
            "p95_ms": p95_s,
            "cpu_ms": cpu_s,
            "pubkey_bytes": 256,
            "ct_or_sig_bytes": 256,
            "note": "Secondary: Python cryptography library in-process",
        }
    )
    rows.append(
        {
            "name": "Python cryptography: RSA-2048 (PSS verify)",
            "category": "python_cryptography",
            "n": n,
            "median_ms": med_v,
            "p95_ms": p95_v,
            "cpu_ms": cpu_v,
            "pubkey_bytes": 256,
            "ct_or_sig_bytes": 256,
            "note": "Secondary: Python cryptography library in-process",
        }
    )

    def _row(name: str, fn: Callable[[], Any], pub: int, out: int) -> None:
        med_, p95_, cpu_ = _time_callable(fn, n, warmup=10)
        rows.append(
            {
                "name": f"Python cryptography: {name}",
                "category": "python_cryptography",
                "n": n,
                "median_ms": med_,
                "p95_ms": p95_,
                "cpu_ms": cpu_,
                "pubkey_bytes": pub,
                "ct_or_sig_bytes": out,
                "note": "Secondary: Python cryptography library in-process (10 warm-up iterations)",
            }
        )

    # RSA-2048 key transport (OAEP) — the classical "KEM" being replaced by ML-KEM
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    secret = b"\x11" * 32
    rsa_ct = rsa_pub.encrypt(secret, oaep)
    _row("RSA-2048 OAEP (encrypt 32B key)", lambda: rsa_pub.encrypt(secret, oaep), 256, len(rsa_ct))
    _row("RSA-2048 OAEP (decrypt)", lambda: rsa_priv.decrypt(rsa_ct, oaep), 256, len(rsa_ct))

    # ECDH P-256 (keygen + exchange)
    peer_p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    _row("ECDH P-256 (Keygen+ECDH)", lambda: ec.generate_private_key(ec.SECP256R1()).exchange(ec.ECDH(), peer_p256), 65, 32)

    # ECDSA P-256 sign / verify
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ec_sig = ec_priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    _row("ECDSA P-256 (sign)", lambda: ec_priv.sign(msg, ec.ECDSA(hashes.SHA256())), 65, len(ec_sig))
    _row("ECDSA P-256 (verify)", lambda: ec_pub.verify(ec_sig, msg, ec.ECDSA(hashes.SHA256())), 65, len(ec_sig))

    # Ed25519 sign / verify
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_sig = ed_priv.sign(msg)
    _row("Ed25519 (sign)", lambda: ed_priv.sign(msg), 32, len(ed_sig))
    _row("Ed25519 (verify)", lambda: ed_pub.verify(ed_sig, msg), 32, len(ed_sig))

    # RSA-3072 sign
    rsa3 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _row("RSA-3072 (PSS sign)", lambda: rsa3.sign(msg, pss, hashes.SHA256()), 384, 384)
    return rows


def _cpu_model() -> str:
    """Best-effort CPU model string (Linux /proc/cpuinfo, macOS sysctl, else platform)."""
    import platform

    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    try:
        out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=2)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def run_benchmarks(n: int = 40) -> Dict[str, Any]:
    """Run primary `openssl speed` in-process benchmarks + TLS handshake benchmarks + secondary Python benchmarks."""
    caps = detect_capabilities()
    now = utc_now_iso()
    machine_info = {
        **caps.get("machine", {}),
        "cpu_model": _cpu_model(),
        "openssl_version": caps.get("openssl_version"),
        "oqs_version": caps.get("oqs_version") or "not installed (PQC measured via OpenSSL provider)",
        "measured_at": now,
    }
    machine_json = json.dumps(machine_info)
    run_id = uuid.uuid4().hex[:10]

    rows_to_insert: List[Dict[str, Any]] = []

    # 1. Primary Fair Comparison: In-process `openssl speed` for BOTH Classical and PQC
    rows_to_insert.extend(run_openssl_speed_suite(seconds=1))

    # 2. Live TLS 1.3 Handshake Comparison (Classical vs Hybrid vs Full PQC)
    rows_to_insert.extend(_measure_tls_handshakes(n_handshakes=30))

    # 3. Secondary Python `cryptography` measurements
    rows_to_insert.extend(_measure_python_cryptography_secondary(n=min(50, max(10, n))))

    conn = get_conn()
    try:
        for r in rows_to_insert:
            conn.execute(
                """
                INSERT INTO benchmarks (
                    run_id, created_at, name, category, n, median_ms, p95_ms, cpu_ms,
                    pubkey_bytes, ct_or_sig_bytes, note, machine_info
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    now,
                    r["name"],
                    r["category"],
                    r["n"],
                    r["median_ms"],
                    r["p95_ms"],
                    r["cpu_ms"],
                    r["pubkey_bytes"],
                    r["ct_or_sig_bytes"],
                    r["note"],
                    machine_json,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    log_audit("benchmark", "run_benchmarks", f"run_id={run_id}", f"Completed {len(rows_to_insert)} benchmarks via openssl speed")
    return get_latest_benchmarks(run_id)


def _cmp(a: float, b: float) -> str:
    """Describe how a compares to b in words computed from the numbers ('2.5x slower', '1.6x faster')."""
    if not a or not b:
        return "n/a"
    r = a / b
    if 0.9 <= r <= 1.1:
        return "about the same speed as"
    return f"{r:.1f}x slower than" if r > 1 else f"{1 / r:.1f}x faster than"


def _compute_takeaways(rows: List[Dict[str, Any]]) -> List[str]:
    """Generate plain-language takeaways strictly from the measured numbers of this run."""
    by_name = {r["name"]: r for r in rows if not str(r.get("note", "")).startswith("UNAVAILABLE")}
    takeaways: List[str] = []

    mlkem_enc = by_name.get("ML-KEM-768 (encaps)")
    mlkem_dec = by_name.get("ML-KEM-768 (decaps)")
    x25519_op = by_name.get("X25519 (ECDH Exchange)")
    rsa_dec = by_name.get("RSA-2048 (decaps / decrypt)")
    if mlkem_enc and mlkem_dec and x25519_op and rsa_dec:
        takeaways.append(
            f"Key establishment: ML-KEM-768 encapsulation {mlkem_enc['median_ms']} ms and decapsulation "
            f"{mlkem_dec['median_ms']} ms (mean, openssl speed). Decapsulation is {_cmp(mlkem_dec['median_ms'], rsa_dec['median_ms'])} "
            f"RSA-2048 decryption ({rsa_dec['median_ms']} ms) and encapsulation is {_cmp(mlkem_enc['median_ms'], x25519_op['median_ms'])} "
            f"an X25519 exchange ({x25519_op['median_ms']} ms). Cost: ciphertext grows from 32 B (X25519 share) to 1,088 B."
        )

    mldsa_s = by_name.get("ML-DSA-65 (sign)")
    mldsa_v = by_name.get("ML-DSA-65 (verify)")
    ecdsa_s = by_name.get("ECDSA P-256 (sign)")
    ecdsa_v = by_name.get("ECDSA P-256 (verify)")
    rsa_s = by_name.get("RSA-2048 (sign)")
    if mldsa_s and mldsa_v and ecdsa_s and ecdsa_v:
        rsa_part = f"; vs RSA-2048 signing ({rsa_s['median_ms']} ms) it is {_cmp(mldsa_s['median_ms'], rsa_s['median_ms'])} RSA" if rsa_s else ""
        takeaways.append(
            f"Signatures: ML-DSA-65 signs in {mldsa_s['median_ms']} ms ({_cmp(mldsa_s['median_ms'], ecdsa_s['median_ms'])} "
            f"ECDSA P-256 at {ecdsa_s['median_ms']} ms) and verifies in {mldsa_v['median_ms']} ms "
            f"({_cmp(mldsa_v['median_ms'], ecdsa_v['median_ms'])} ECDSA at {ecdsa_v['median_ms']} ms){rsa_part}. "
            f"Signature size grows from ~72 B to 3,309 B and public key from 65 B to 1,952 B."
        )

    slh_s = by_name.get("SLH-DSA-SHA2-128s (sign)")
    slh_f = by_name.get("SLH-DSA-SHA2-128f (sign)")
    if slh_s and slh_f:
        takeaways.append(
            f"SLH-DSA trade-off: 128s ('small', 7,856 B signature) signs in {slh_s['median_ms']} ms; "
            f"128f ('fast', 17,088 B signature) signs in {slh_f['median_ms']} ms ({_cmp(slh_f['median_ms'], slh_s['median_ms'])} 128s). "
            f"Slow signing and large signatures suit rarely-used, long-lived keys such as root CAs and firmware signing."
        )

    hs_c = by_name.get("TLS 1.3 Classical (X25519 + ECDSA-P256)")
    hs_h = by_name.get("TLS 1.3 Hybrid (X25519MLKEM768 + ECDSA-P256)")
    hs_p = by_name.get("TLS 1.3 Full PQC (X25519MLKEM768 + ML-DSA-65)")
    if hs_c and hs_h and hs_p and hs_c["ct_or_sig_bytes"]:
        takeaways.append(
            f"TLS 1.3 handshake bytes (read+written by s_client): classical {hs_c['ct_or_sig_bytes']:,} B, hybrid "
            f"{hs_h['ct_or_sig_bytes']:,} B (+{hs_h['ct_or_sig_bytes'] - hs_c['ct_or_sig_bytes']:,} B), full PQC "
            f"{hs_p['ct_or_sig_bytes']:,} B (+{hs_p['ct_or_sig_bytes'] - hs_c['ct_or_sig_bytes']:,} B). Median wall time "
            f"{hs_c['median_ms']} / {hs_h['median_ms']} / {hs_p['median_ms']} ms is dominated by process start-up, so "
            f"latency differences are within noise; bytes are the meaningful cost."
        )

    return takeaways


def get_latest_benchmarks(run_id: str | None = None) -> Dict[str, Any]:
    """Fetch benchmark results for the specified or latest run_id, split into primary and secondary sets."""
    if not run_id:
        latest = query_one("SELECT run_id FROM benchmarks ORDER BY id DESC LIMIT 1")
        if not latest:
            return {
                "run_id": None,
                "benchmarks": [],
                "primary_openssl_speed": [],
                "secondary_benchmarks": [],
                "takeaways": [],
                "machine_info": {},
            }
        run_id = str(latest["run_id"])

    rows = query_all("SELECT * FROM benchmarks WHERE run_id = ? ORDER BY id ASC", (run_id,))
    if not rows:
        return {
            "run_id": run_id,
            "benchmarks": [],
            "primary_openssl_speed": [],
            "secondary_benchmarks": [],
            "takeaways": [],
            "machine_info": {},
        }

    machine_info = json.loads(rows[0]["machine_info"] or "{}")
    primary = [r for r in rows if r["category"] == "openssl_speed"]
    secondary = [r for r in rows if r["category"] != "openssl_speed"]

    return {
        "run_id": run_id,
        "created_at": rows[0]["created_at"],
        "machine_info": machine_info,
        "benchmarks": rows,
        "primary_openssl_speed": primary if primary else rows,
        "secondary_benchmarks": secondary,
        "takeaways": _compute_takeaways(rows),
    }


def export_benchmarks_csv(run_id: str) -> str:
    """Serialize a benchmark run to CSV string."""
    data = get_latest_benchmarks(run_id)
    rows = data.get("benchmarks", [])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "run_id",
            "created_at",
            "name",
            "category",
            "ops_per_sec_or_n",
            "median_ms",
            "p95_ms",
            "cpu_ms",
            "pubkey_bytes",
            "ct_or_sig_bytes",
            "note",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["run_id"],
                r["created_at"],
                r["name"],
                r["category"],
                r["n"],
                r["median_ms"],
                r["p95_ms"],
                r["cpu_ms"],
                r["pubkey_bytes"],
                r["ct_or_sig_bytes"],
                r["note"],
            ]
        )
    return buf.getvalue()
