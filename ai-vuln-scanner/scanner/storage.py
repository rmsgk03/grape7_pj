from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .rules import Finding


DB_PATH = Path(__file__).resolve().parent.parent / "scan_results.sqlite3"


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source_code TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            )
            """
        )


def save_scan(source_code: str, findings: list[Finding]) -> None:
    init_db()
    payload = [finding.to_dict() for finding in findings]
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (created_at, source_code, finding_count, findings_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(timespec="seconds"),
                source_code,
                len(findings),
                json.dumps(payload, ensure_ascii=False),
            ),
        )


def load_stats() -> list[dict[str, object]]:
    init_db()
    stats: dict[str, int] = {}
    with connect() as conn:
        rows = conn.execute("SELECT findings_json FROM scans").fetchall()
    for (findings_json,) in rows:
        for item in json.loads(findings_json):
            name = item.get("vulnerability", "Unknown")
            stats[name] = stats.get(name, 0) + 1
    return [{"vulnerability": key, "count": value} for key, value in sorted(stats.items())]


def load_recent_scans(limit: int = 10) -> list[dict[str, object]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, finding_count, findings_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    result = []
    for created_at, finding_count, findings_json in rows:
        findings = json.loads(findings_json)
        result.append(
            {
                "created_at": created_at,
                "finding_count": finding_count,
                "vulnerabilities": ", ".join(sorted({item["vulnerability"] for item in findings})) or "None",
            }
        )
    return result
