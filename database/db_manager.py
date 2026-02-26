"""
Database Manager Module
=======================
Handles all SQLite operations for scan logging, analytics retrieval,
and CSV export. Thread-safe with connection-per-call pattern.
"""

import sqlite3
import csv
import os
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "phishing_scans.db")

_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    """Create a new connection (safe for multi-threaded use)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def initialize_database() -> None:
    """Create the scans table if it does not exist."""
    with _lock:
        conn = _get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    url         TEXT    NOT NULL,
                    risk_score  REAL    NOT NULL,
                    classification TEXT NOT NULL,
                    confidence  REAL    DEFAULT 0.0,
                    api_used    INTEGER DEFAULT 0,
                    engine      TEXT    DEFAULT '',
                    reasoning   TEXT    DEFAULT '',
                    timestamp   TEXT    NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp
                ON scans(timestamp);
            """)
            # Phished credentials table for simulation tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS phished_credentials (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT    NOT NULL,
                    password    TEXT    NOT NULL,
                    preset      TEXT    NOT NULL,
                    ip_address  TEXT    DEFAULT '',
                    user_agent  TEXT    DEFAULT '',
                    timestamp   TEXT    NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_phished_timestamp
                ON phished_credentials(timestamp);
            """)
            conn.commit()
        finally:
            conn.close()


def insert_scan(
    url: str,
    risk_score: float,
    classification: str,
    confidence: float = 0.0,
    api_used: bool = False,
    engine: str = "",
    reasoning: str = "",
) -> int:
    """Insert a new scan record and return the row id."""
    with _lock:
        conn = _get_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO scans
                    (url, risk_score, classification, confidence,
                     api_used, engine, reasoning, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    round(risk_score, 2),
                    classification,
                    round(confidence, 2),
                    1 if api_used else 0,
                    engine,
                    reasoning,
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def get_recent_scans(limit: int = 50) -> List[Dict]:
    """Return the most recent scans."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_count() -> int:
    """Total number of scans in the database."""
    conn = _get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        conn.close()


def get_classification_counts() -> Dict[str, int]:
    """Return counts grouped by classification."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT classification, COUNT(*) as cnt FROM scans GROUP BY classification"
        ).fetchall()
        return {r["classification"]: r["cnt"] for r in rows}
    finally:
        conn.close()


def get_risk_trend(days: int = 30) -> List[Tuple[str, float]]:
    """Average risk score per day for the last N days."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = _get_connection()
    try:
        rows = conn.execute(
            """
            SELECT DATE(timestamp) as day, AVG(risk_score) as avg_risk
            FROM scans
            WHERE timestamp >= ?
            GROUP BY DATE(timestamp)
            ORDER BY day
            """,
            (cutoff,),
        ).fetchall()
        return [(r["day"], round(r["avg_risk"], 2)) for r in rows]
    finally:
        conn.close()


def get_top_keywords(limit: int = 10) -> List[Tuple[str, int]]:
    """Extract most common suspicious keywords found in reasoning."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT reasoning FROM scans WHERE reasoning != ''"
        ).fetchall()
        keyword_counts: Dict[str, int] = {}
        target_keywords = [
            "login", "verify", "secure", "account", "update", "bank",
            "paypal", "password", "confirm", "suspend", "urgent",
            "click", "free", "winner", "prize", "alert", "warning",
        ]
        for row in rows:
            text = row["reasoning"].lower()
            for kw in target_keywords:
                if kw in text:
                    keyword_counts[kw] = keyword_counts.get(kw, 0) + 1
        sorted_kw = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_kw[:limit]
    finally:
        conn.close()


def get_api_usage_ratio() -> Tuple[int, int]:
    """Return (api_count, local_count)."""
    conn = _get_connection()
    try:
        api = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE api_used = 1"
        ).fetchone()[0]
        local = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE api_used = 0"
        ).fetchone()[0]
        return (api, local)
    finally:
        conn.close()


def export_to_csv(filepath: str) -> int:
    """Export all scans to CSV. Returns number of rows exported."""
    conn = _get_connection()
    try:
        rows = conn.execute("SELECT * FROM scans ORDER BY id").fetchall()
        if not rows:
            return 0
        keys = rows[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in rows:
                writer.writerow(dict(r))
        return len(rows)
    finally:
        conn.close()


def clear_all_scans() -> int:
    """Delete all scan records. Returns deleted count."""
    with _lock:
        conn = _get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            conn.execute("DELETE FROM scans")
            conn.commit()
            return count
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Phished Credentials Management (Simulation)
# ---------------------------------------------------------------------------

def insert_phished_credential(
    username: str,
    password: str,
    preset: str,
    ip_address: str = "",
    user_agent: str = "",
) -> int:
    """Insert a phished credential record (for simulation tracking)."""
    with _lock:
        conn = _get_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO phished_credentials
                    (username, password, preset, ip_address, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    password,
                    preset,
                    ip_address,
                    user_agent,
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def get_phished_credentials(limit: int = 100) -> List[Dict]:
    """Return the most recent phished credentials."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM phished_credentials ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_phished_count() -> int:
    """Total number of phished credentials in the database."""
    conn = _get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM phished_credentials").fetchone()[0]
    finally:
        conn.close()


def get_phished_by_preset() -> Dict[str, int]:
    """Return counts grouped by preset template."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT preset, COUNT(*) as cnt FROM phished_credentials GROUP BY preset"
        ).fetchall()
        return {r["preset"]: r["cnt"] for r in rows}
    finally:
        conn.close()


def clear_all_phished_credentials() -> int:
    """Delete all phished credential records. Returns deleted count."""
    with _lock:
        conn = _get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM phished_credentials").fetchone()[0]
            conn.execute("DELETE FROM phished_credentials")
            conn.commit()
            return count
        finally:
            conn.close()
