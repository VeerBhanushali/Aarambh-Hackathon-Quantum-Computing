"""Application-level Hybrid Encryption Lab (X25519 + ML-KEM-768 -> HKDF-SHA256 -> AES-256-GCM)."""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.capabilities import detect_capabilities
from app.config import OPENSSL_BIN
from app.db import log_audit


def _fp8(secret_bytes: bytes) -> str:
    """Return ONLY the first 8 hex chars of a SHA-256 fingerprint of a shared secret (never raw key material)."""
    return hashlib.sha256(secret_bytes).hexdigest()[:8]


def _mlkem768_keygen_encap_decap() -> Tuple[bytes, bytes, bytes, bytes, float, float, float, str]:
    """Perform real ML-KEM-768 keygen, encapsulate, and decapsulate via liboqs or OpenSSL 3.5+ CLI.

    Returns (pub_bytes, ct_pq, ss_sender, ss_receiver, keygen_ms, encap_ms, decap_ms, backend_used).
    """
    caps = detect_capabilities()
    if caps.get("oqs_available"):
        import oqs  # type: ignore

        alg = caps["oqs_mechanisms"]["ml_kem_768"] or "ML-KEM-768"
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(alg) as receiver_kem:
            pub_key = receiver_kem.generate_keypair()
            t1 = time.perf_counter()
            with oqs.KeyEncapsulation(alg) as sender_kem:
                ct_pq, ss_sender = sender_kem.encap_secret(pub_key)
                t2 = time.perf_counter()
            ss_receiver = receiver_kem.decap_secret(ct_pq)
            t3 = time.perf_counter()
        return (
            pub_key,
            ct_pq,
            ss_sender,
            ss_receiver,
            round((t1 - t0) * 1000, 3),
            round((t2 - t1) * 1000, 3),
            round((t3 - t2) * 1000, 3),
            f"liboqs ({alg})",
        )

    # OpenSSL 3.5+ CLI native ML-KEM-768 execution
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        priv_pem = tmp / "mlkem_priv.pem"
        pub_der = tmp / "mlkem_pub.der"
        ct_file = tmp / "mlkem_ct.bin"
        ss_s_file = tmp / "ss_sender.bin"
        ss_r_file = tmp / "ss_receiver.bin"

        t0 = time.perf_counter()
        subprocess.run(
            [OPENSSL_BIN, "genpkey", "-algorithm", "ML-KEM-768", "-out", str(priv_pem)],
            check=True,
            capture_output=True,
            timeout=5.0,
        )
        subprocess.run(
            [OPENSSL_BIN, "pkey", "-in", str(priv_pem), "-pubout", "-outform", "DER", "-out", str(pub_der)],
            check=True,
            capture_output=True,
            timeout=5.0,
        )
        t1 = time.perf_counter()

        subprocess.run(
            [
                OPENSSL_BIN,
                "pkeyutl",
                "-encap",
                "-pubin",
                "-inkey",
                str(pub_der),
                "-keyform",
                "DER",
                "-out",
                str(ct_file),
                "-secret",
                str(ss_s_file),
            ],
            check=True,
            capture_output=True,
            timeout=5.0,
        )
        t2 = time.perf_counter()

        subprocess.run(
            [
                OPENSSL_BIN,
                "pkeyutl",
                "-decap",
                "-inkey",
                str(priv_pem),
                "-in",
                str(ct_file),
                "-secret",
                str(ss_r_file),
            ],
            check=True,
            capture_output=True,
            timeout=5.0,
        )
        t3 = time.perf_counter()

        pub_bytes = pub_der.read_bytes()
        ct_pq = ct_file.read_bytes()
        ss_sender = ss_s_file.read_bytes()
        ss_receiver = ss_r_file.read_bytes()

        # Raw ML-KEM-768 public key is 1184 bytes (DER SubjectPublicKeyInfo has a 24-byte ASN.1 header = 1208 bytes)
        raw_pub = pub_bytes[-1184:] if len(pub_bytes) >= 1184 else pub_bytes

        return (
            raw_pub,
            ct_pq,
            ss_sender,
            ss_receiver,
            round((t1 - t0) * 1000, 3),
            round((t2 - t1) * 1000, 3),
            round((t3 - t2) * 1000, 3),
            "OpenSSL 3.5+ CLI (ML-KEM-768)",
        )


def combine_hybrid_key(
    ss_classical: bytes,
    ss_pq: bytes,
    eph_x25519_pub: bytes,
    ct_pq: bytes,
) -> bytes:
    """Combine classical and post-quantum shared secrets via HKDF-SHA256.

    CRYPTO RULE NOTE:
    Binding the public values (`eph_x25519_pub || ct_pq`) into the HKDF `info` context follows the
    approach used by IETF/NIST hybrid KEM combiner designs (e.g., X25519MLKEM768 / Chempat).
    This ensures IND-CCA2 transcript binding and guarantees that the derived key remains secure
    if EITHER X25519 OR ML-KEM-768 remains unbroken.
    """
    ikm = ss_classical + ss_pq
    info = b"quantum-guard-hybrid-v1" + eph_x25519_pub + ct_pq
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)


def run_hybrid_demo(message: str, mode: str = "hybrid", tamper: bool = False) -> Dict[str, Any]:
    """Execute end-to-end Hybrid (X25519 + ML-KEM-768) or Classical-only (X25519) encryption demo."""
    if not message:
        message = "Top-Secret Payment Instruction: Transfer $10,000,000 to Quantum Reserve."

    is_hybrid = mode.lower() != "classical"
    if is_hybrid:
        caps = detect_capabilities()
        if not (caps.get("oqs_available") or caps.get("openssl_mlkem")):
            return {
                "error": True,
                "success": False,
                "message": (
                    "ML-KEM-768 unavailable: install liboqs-python or point OPENSSL_BIN at OpenSSL 3.5+. "
                    "Classical mode still works."
                ),
                "mode": "hybrid",
            }

    # Step 1: Receiver static X25519 keypair
    t_x0 = time.perf_counter()
    rx_x25519_priv = x25519.X25519PrivateKey.generate()
    rx_x25519_pub = rx_x25519_priv.public_key()
    rx_x25519_pub_bytes = rx_x25519_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    t_x1 = time.perf_counter()

    # Step 2: Sender ephemeral X25519 ECDH
    tx_x25519_priv = x25519.X25519PrivateKey.generate()
    tx_x25519_pub_bytes = tx_x25519_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ss_classical_tx = tx_x25519_priv.exchange(rx_x25519_pub)
    t_x2 = time.perf_counter()

    # Receiver X25519 ECDH recomputation
    ss_classical_rx = rx_x25519_priv.exchange(x25519.X25519PublicKey.from_public_bytes(tx_x25519_pub_bytes))
    t_x3 = time.perf_counter()

    x25519_keygen_ms = round((t_x1 - t_x0) * 1000, 3)
    x25519_encap_ms = round((t_x2 - t_x1) * 1000, 3)
    x25519_decap_ms = round((t_x3 - t_x2) * 1000, 3)

    if is_hybrid:
        (
            mlkem_pub,
            ct_pq,
            ss_pq_tx,
            ss_pq_rx,
            pq_keygen_ms,
            pq_encap_ms,
            pq_decap_ms,
            pq_backend,
        ) = _mlkem768_keygen_encap_decap()
    else:
        mlkem_pub = b""
        ct_pq = b""
        ss_pq_tx = b""
        ss_pq_rx = b""
        pq_keygen_ms = 0.0
        pq_encap_ms = 0.0
        pq_decap_ms = 0.0
        pq_backend = "None (Classical X25519 Only)"

    # Step 3: HKDF-SHA256 Key Derivation with transcript binding
    t_k0 = time.perf_counter()
    aes_key_tx = combine_hybrid_key(ss_classical_tx, ss_pq_tx, tx_x25519_pub_bytes, ct_pq)
    aes_key_rx = combine_hybrid_key(ss_classical_rx, ss_pq_rx, tx_x25519_pub_bytes, ct_pq)
    t_k1 = time.perf_counter()
    hkdf_ms = round((t_k1 - t_k0) * 1000, 3)

    # Step 4: AES-256-GCM Encryption (random 12-byte nonce, AAD = "quantum-guard")
    t_e0 = time.perf_counter()
    nonce = os.urandom(12)
    aad = b"quantum-guard"
    aead_tx = AESGCM(aes_key_tx)
    ciphertext = aead_tx.encrypt(nonce, message.encode("utf-8"), aad)
    t_e1 = time.perf_counter()
    encrypt_ms = round((t_e1 - t_e0) * 1000, 3)

    if tamper:
        # Flip one bit in the ciphertext to verify AEAD authentication failure
        ba = bytearray(ciphertext)
        ba[0] ^= 0xFF
        ciphertext = bytes(ba)

    # Step 5: Receiver AES-256-GCM Decryption & verification
    t_d0 = time.perf_counter()
    aead_rx = AESGCM(aes_key_rx)
    try:
        decrypted_bytes = aead_rx.decrypt(nonce, ciphertext, aad)
        decrypted_text = decrypted_bytes.decode("utf-8")
        success = decrypted_text == message
        error_msg = None
    except Exception as exc:
        decrypted_text = None
        success = False
        error_msg = f"AES-256-GCM authentication tag verification failed: {type(exc).__name__}"
    t_d1 = time.perf_counter()
    decrypt_ms = round((t_d1 - t_d0) * 1000, 3)

    total_handshake_overhead = len(tx_x25519_pub_bytes) + len(ct_pq)

    steps = [
        {
            "step": 1,
            "party": "Receiver -> Sender",
            "title": "Publish Receiver Public Keys",
            "detail": (
                f"X25519 pub ({len(rx_x25519_pub_bytes)} B)"
                + (f" + ML-KEM-768 pub ({len(mlkem_pub)} B)" if is_hybrid else " (Classical only)")
            ),
            "bytes": len(rx_x25519_pub_bytes) + len(mlkem_pub),
            "time_ms": round(x25519_keygen_ms + pq_keygen_ms, 3),
        },
        {
            "step": 2,
            "party": "Sender -> Receiver",
            "title": "Ephemeral ECDH + ML-KEM-768 Encapsulation" if is_hybrid else "Ephemeral X25519 ECDH",
            "detail": (
                f"Send eph_x25519_pub ({len(tx_x25519_pub_bytes)} B)"
                + (f" + ct_pq ({len(ct_pq)} B)" if is_hybrid else "")
                + f" | ss_classical fp8={_fp8(ss_classical_tx)}"
                + (f", ss_pq fp8={_fp8(ss_pq_tx)}" if is_hybrid else "")
            ),
            "bytes": total_handshake_overhead,
            "time_ms": round(x25519_encap_ms + pq_encap_ms, 3),
        },
        {
            "step": 3,
            "party": "Both Parties",
            "title": "HKDF-SHA256 Hybrid Combiner (Transcript-Bound)",
            "detail": (
                f"HKDF-SHA256(ikm=ss_classical||ss_pq, info='quantum-guard-hybrid-v1'||eph_pub||ct_pq) "
                f"-> Derived AES-256 key fp8={_fp8(aes_key_tx)}"
            ),
            "bytes": 32,
            "time_ms": hkdf_ms,
        },
        {
            "step": 4,
            "party": "Sender -> Receiver",
            "title": "AES-256-GCM Authenticated Encryption",
            "detail": f"12-byte nonce + {len(ciphertext)} B ciphertext (includes 16-byte GCM tag), AAD='quantum-guard'",
            "bytes": 12 + len(ciphertext),
            "time_ms": encrypt_ms,
        },
        {
            "step": 5,
            "party": "Receiver",
            "title": "Decapsulate, Derive Key & Verify AES-256-GCM",
            "detail": (
                f"Derived key fp8={_fp8(aes_key_rx)} matches sender ({_fp8(aes_key_tx) == _fp8(aes_key_rx)}); "
                + ("plaintext verified!" if success else f"FAILED: {error_msg}")
            ),
            "bytes": len(decrypted_text.encode("utf-8")) if decrypted_text else 0,
            "time_ms": round(x25519_decap_ms + pq_decap_ms + decrypt_ms, 3),
        },
    ]

    log_audit(
        "crypto_lab",
        f"hybrid_demo_{mode}",
        pq_backend,
        f"success={success}, overhead={total_handshake_overhead}B",
    )

    return {
        "mode": "hybrid" if is_hybrid else "classical",
        "backend": pq_backend,
        "success": success,
        "error": error_msg,
        "original_message": message,
        "decrypted_message": decrypted_text,
        "fingerprints_sha256_8": {
            "ss_classical": _fp8(ss_classical_tx),
            "ss_pq": _fp8(ss_pq_tx) if is_hybrid else None,
            "combined_aes256_key": _fp8(aes_key_tx),
            "receiver_aes256_key": _fp8(aes_key_rx),
        },
        "sizes_bytes": {
            "x25519_pub": len(tx_x25519_pub_bytes),
            "mlkem768_pub": len(mlkem_pub),
            "mlkem768_ciphertext": len(ct_pq),
            "total_kex_overhead": total_handshake_overhead,
            "aes_gcm_nonce": 12,
            "aes_gcm_ciphertext_with_tag": len(ciphertext),
        },
        "timings_ms": {
            "x25519_keygen": x25519_keygen_ms,
            "x25519_exchange": x25519_encap_ms,
            "mlkem768_keygen": pq_keygen_ms,
            "mlkem768_encaps": pq_encap_ms,
            "mlkem768_decaps": pq_decap_ms,
            "hkdf_combine": hkdf_ms,
            "aes_gcm_encrypt": encrypt_ms,
            "aes_gcm_decrypt": decrypt_ms,
            "total_ms": round(
                x25519_keygen_ms
                + x25519_encap_ms
                + x25519_decap_ms
                + pq_keygen_ms
                + pq_encap_ms
                + pq_decap_ms
                + hkdf_ms
                + encrypt_ms
                + decrypt_ms,
                3,
            ),
        },
        "steps": steps,
        "hndl_explanation": {
            "captured_transcript_bytes": total_handshake_overhead + 12 + len(ciphertext),
            "classical_only_risk": (
                "In Classical-Only mode (32 B X25519 pubkey), a 'Harvest-Now-Decrypt-Later' attacker records the "
                "transcript today and runs Shor's algorithm on a future CRQC to recover ss_classical and decrypt the message."
            ),
            "hybrid_protection": (
                "In Hybrid mode (32 B X25519 + 1088 B ML-KEM-768 ciphertext bound via HKDF-SHA256), even if Shor's "
                "algorithm breaks X25519, the attacker must ALSO break FIPS 203 ML-KEM-768 (Module-LWE) to recover the AES-256 key."
            ),
        },
    }
