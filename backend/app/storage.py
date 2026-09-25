"""审计记录持久化（SQLite）。

- 审计结果在扫描完成时整体落库；扫描失败不产生任何记录，客户端可直接重试。
- 读取历史时原样返回存储的评分与结论，不用新规则重算，
  保证历史记录的评分口径稳定、列表与详情一致。
"""
import json
import os
import sqlite3
from typing import List, Optional

DB_PATH = os.environ.get(
    "AUDIT_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audits.db"),
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    score INTEGER NOT NULL,
    scoring_version TEXT NOT NULL,
    vuln_count INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(_SCHEMA)


def save_audit(result: dict) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO audits (id, filename, score, scoring_version, vuln_count, result_json, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result["id"],
                result["filename"],
                result["score"],
                result["scoringVersion"],
                len(result["vulnerabilities"]),
                json.dumps(result, ensure_ascii=False),
                result["timestamp"],
            ),
        )


def list_audits() -> List[dict]:
    """历史列表：与详情同源于同一条落库记录。"""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, filename, score, scoring_version, vuln_count, created_at"
            " FROM audits ORDER BY created_at DESC, id DESC"
        ).fetchall()
    return [
        {
            "id": row["id"],
            "filename": row["filename"],
            "score": row["score"],
            "scoringVersion": row["scoring_version"],
            "vulnerabilityCount": row["vuln_count"],
            "timestamp": row["created_at"],
        }
        for row in rows
    ]


def get_audit(audit_id: str) -> Optional[dict]:
    """审计详情：返回落库时的完整结果（含当时的评分，不重算）。"""
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["result_json"])
