"""Key Vault: encrypted private key storage at rest, key inventory, rotation checks, and audit logging."""
from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import MASTER_KEY_PATH
from app.db import get_conn, log_audit, query_all, query_one, utc_now_iso


def _chmod_600(path: Path) -> None:
    """Restrict file permissions to owner read/write where supported."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def get_master_key() -> bytes:
    """Return 32-byte master key from QG_MASTER_KEY env or persistent data/.master_key."""
    env_key = os.environ.get("QG_MASTER_KEY")
    if env_key:
        raw = bytes.fromhex(env_key) if len(env_key) == 64 else env_key.encode("utf-8")[:32].ljust(32, b"0")
        return raw

    if MASTER_KEY_PATH.exists():
        return MASTER_KEY_PATH.read_bytes()[:32]

    key = AESGCM.generate_key(bit_length=256)
    MASTER_KEY_PATH.write_bytes(key)
    _chmod_600(MASTER_KEY_PATH)
    log_audit("vault", "generate_master_key", str(MASTER_KEY_PATH.name), "Generated local AES-256-GCM master key")
    return key


def encrypt_key_at_rest(key_path: Path) -> Path:
    """Encrypt a private key file at rest into <path>.enc using AES-256-GCM."""
    enc_path = Path(str(key_path) + ".enc")
    if not key_path.exists():
        return enc_path

    plaintext = key_path.read_bytes()
    master = get_master_key()
    aesgcm = AESGCM(master)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, b"quantum-guard-vault-v1")
    enc_path.write_bytes(nonce + ct)
    _chmod_600(enc_path)
    _chmod_600(key_path)
    return enc_path


def decrypt_key_to_temp(enc_path: Path, target_path: Path) -> Path:
    """Decrypt <path>.enc to target_path with chmod 600 for service startup."""
    if not enc_path.exists() and target_path.exists():
        return target_path

    blob = enc_path.read_bytes()
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(get_master_key())
    plaintext = aesgcm.decrypt(nonce, ct, b"quantum-guard-vault-v1")
    target_path.write_bytes(plaintext)
    _chmod_600(target_path)
    log_audit("vault", "decrypt_key_for_service", target_path.name, "Decrypted key for active TLS process")
    return target_path


def register_key(
    name: str,
    alg: str,
    purpose: str,
    key_path: Path,
    rotate_days: int = 90,
    status: str = "active",
) -> int:
    """Encrypt key at rest and record metadata in the keys table (never storing key material)."""
    encrypt_key_at_rest(key_path)
    now_dt = datetime.now(timezone.utc)
    created_at = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    rotate_by = (now_dt + timedelta(days=rotate_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    try:
        # Mark older keys of the same name as rotated if re-issuing
        conn.execute("UPDATE keys SET status = 'rotated' WHERE name = ? AND status = 'active'", (name,))
        cur = conn.execute(
            """
            INSERT INTO keys (name, alg, purpose, created_at, rotate_by, path, encrypted, status)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (name, alg, purpose, created_at, rotate_by, str(key_path.name), status),
        )
        conn.commit()
        key_id = int(cur.lastrowid or 0)
    finally:
        conn.close()

    log_audit("vault", "register_key", name, f"alg={alg}, purpose={purpose}, encrypted=AES-256-GCM")
    return key_id


def list_keys() -> List[Dict[str, Any]]:
    """Return key inventory with rotation status check. Never returns private key content."""
    rows = query_all("SELECT id, name, alg, purpose, created_at, rotate_by, path, encrypted, status FROM keys ORDER BY id DESC")
    now_iso = utc_now_iso()
    result: List[Dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        if item["status"] == "active" and item["rotate_by"] < now_iso:
            item["status"] = "due"
        result.append(item)
    return result


def get_key_record(key_id: int) -> Dict[str, Any] | None:
    """Return a single key metadata record by ID."""
    return query_one(
        "SELECT id, name, alg, purpose, created_at, rotate_by, path, encrypted, status FROM keys WHERE id = ?",
        (key_id,),
    )
