"""SQLite 持久化。

审计结论（评分、漏洞、gas、规则版本）在扫描完成后整体落库：
- 列表与详情读取同一条记录，结论必然一致；
- 记录保存当时的 rules_version，规则更新后历史记录的评分口径保持稳定。
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import List, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.environ.get("AUDIT_DB_PATH", os.path.join(DB_DIR, "audits.db"))


def _connect() -> sqlite3.Connection:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audits (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                code          TEXT NOT NULL,
                score         INTEGER NOT NULL,
                rules_version TEXT NOT NULL,
                result_json   TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_audit(audit_id: str, filename: str, code: str, result: dict, rules_version: str) -> None:
    created_at = result["timestamp"]
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audits (id, filename, code, score, rules_version, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                filename,
                code,
                int(result["score"]),
                rules_version,
                json.dumps(result, ensure_ascii=False),
                created_at,
            ),
        )
        conn.commit()


def _row_to_full(row: sqlite3.Row) -> dict:
    # 历史记录原样返回落库时的完整结论，不重新扫描、不重新评分
    return json.loads(row["result_json"])


def list_audits(limit: int = 100) -> List[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, filename, score, rules_version, result_json, created_at
            FROM audits ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    summaries = []
    for row in rows:
        full = _row_to_full(row)
        summaries.append(
            {
                "id": row["id"],
                "filename": row["filename"],
                "score": row["score"],
                "vulnerabilityCount": len(full.get("vulnerabilities", [])),
                "rulesVersion": row["rules_version"],
                "timestamp": row["created_at"],
            }
        )
    return summaries


def get_audit(audit_id: str) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    if row is None:
        return None
    return _row_to_full(row)


def format_timestamp(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")
