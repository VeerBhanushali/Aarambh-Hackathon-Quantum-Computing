"""SQLite database management and helper functions for Quantum Guard."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import DB_PATH, DEFAULT_MIGRATION_YEARS, DEFAULT_SERVICES, DEFAULT_YEARS_TO_CRQC


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn() -> sqlite3.Connection:
    """Create a SQLite connection with row factory configured."""
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create all required tables and seed initial services and settings."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS services (
                name TEXT PRIMARY KEY,
                port INT NOT NULL,
                profile TEXT NOT NULL,
                exposure TEXT NOT NULL CHECK(exposure IN ('public', 'internal')),
                data_secrecy_years INT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK(kind IN ('before', 'after')),
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INT NOT NULL,
                source TEXT NOT NULL CHECK(source IN ('network', 'code', 'certificate', 'key')),
                location TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                family TEXT NOT NULL,
                usage TEXT NOT NULL,
                protocol TEXT,
                details_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INT NOT NULL,
                asset_id INT NOT NULL,
                severity TEXT NOT NULL,
                score INT NOT NULL,
                ir8547_status TEXT NOT NULL,
                hndl_urgent INT NOT NULL,
                reasons_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INT NOT NULL,
                created_at TEXT NOT NULL,
                items_json TEXT NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ca_name TEXT NOT NULL,
                subject TEXT NOT NULL,
                key_alg TEXT NOT NULL,
                sig_alg TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                alg TEXT NOT NULL,
                purpose TEXT NOT NULL,
                created_at TEXT NOT NULL,
                rotate_by TEXT NOT NULL,
                path TEXT NOT NULL,
                encrypted INT NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS benchmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                n INT NOT NULL,
                median_ms REAL NOT NULL,
                p95_ms REAL NOT NULL,
                cpu_ms REAL NOT NULL,
                pubkey_bytes INT NOT NULL,
                ct_or_sig_bytes INT NOT NULL,
                note TEXT,
                machine_info TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )

        # Seed default enterprise services if missing
        now = utc_now_iso()
        for svc in DEFAULT_SERVICES:
            cur.execute(
                """
                INSERT OR IGNORE INTO services (name, port, profile, exposure, data_secrecy_years, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    svc["name"],
                    svc["port"],
                    svc["profile"],
                    svc["exposure"],
                    svc["data_secrecy_years"],
                    now,
                ),
            )

        # Seed default Mosca assumptions
        cur.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('years_to_crqc', ?)",
            (str(DEFAULT_YEARS_TO_CRQC),),
        )
        cur.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('migration_years', ?)",
            (str(DEFAULT_MIGRATION_YEARS),),
        )

        conn.commit()
    finally:
        conn.close()


def log_audit(actor: str, action: str, target: str, detail: str) -> None:
    """Append an entry to the audit_log table."""
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (utc_now_iso(), actor, action, target, detail),
        )
        conn.commit()
    finally:
        conn.close()


# Ensure SQLite tables exist immediately when db module is imported
init_db()


def get_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Fetch recent audit log entries."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_assumptions() -> Dict[str, int]:
    """Retrieve Mosca shelf-life assumption parameters."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        data = {r["key"]: r["value"] for r in rows}
        return {
            "years_to_crqc": int(data.get("years_to_crqc", DEFAULT_YEARS_TO_CRQC)),
            "migration_years": int(data.get("migration_years", DEFAULT_MIGRATION_YEARS)),
        }
    finally:
        conn.close()


def set_assumptions(years_to_crqc: int, migration_years: int) -> Dict[str, int]:
    """Update Mosca shelf-life assumption parameters."""
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('years_to_crqc', ?)",
            (str(years_to_crqc),),
        )
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('migration_years', ?)",
            (str(migration_years),),
        )
        conn.commit()
    finally:
        conn.close()
    log_audit(
        "user",
        "update_assumptions",
        "risk_engine",
        f"Set years_to_crqc={years_to_crqc}, migration_years={migration_years}",
    )
    return get_assumptions()


def query_all(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Execute a SELECT query and return a list of dicts."""
    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Execute a SELECT query and return a single dict or None."""
    conn = get_conn()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
