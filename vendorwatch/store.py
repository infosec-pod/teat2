"""SQLite persistence: findings history, de-duplication and alert bookkeeping."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    type TEXT NOT NULL,              -- cve | news | exploit | advisory
    priority TEXT NOT NULL,          -- P1 (act now) .. P4 (info)
    title TEXT NOT NULL,
    url TEXT,
    published TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',   -- open | accepted | resolved
    notified_priority TEXT,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_findings_asset ON findings(asset_id);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS score_history (
    ts TEXT NOT NULL, asset_id TEXT NOT NULL, score INTEGER NOT NULL, grade TEXT NOT NULL
);
"""

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------------------------------------------------------------- state
    def get_state(self, k: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
        return row["v"] if row else default

    def set_state(self, k: str, v: str) -> None:
        self.db.execute("INSERT INTO state(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
        self.db.commit()

    # ---------------------------------------------------------------- findings
    def get(self, key: str) -> dict | None:
        row = self.db.execute("SELECT * FROM findings WHERE key=?", (key,)).fetchone()
        return self._row(row) if row else None

    def has(self, key: str) -> bool:
        return self.db.execute("SELECT 1 FROM findings WHERE key=?", (key,)).fetchone() is not None

    def upsert(self, f: dict) -> tuple[str, dict | None]:
        """Insert/update a finding. Returns (change, previous) where change is new|escalated|updated|same."""
        prev = self.get(f["key"])
        ts = now_iso()
        data = json.dumps(f.get("data", {}), default=str)
        if prev is None:
            self.db.execute(
                "INSERT INTO findings(key,asset_id,type,priority,title,url,published,first_seen,last_seen,data)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f["key"], f["asset_id"], f["type"], f["priority"], f["title"], f.get("url", ""),
                 f.get("published", ""), ts, ts, data),
            )
            self.db.commit()
            return "new", None
        self.db.execute(
            "UPDATE findings SET priority=?, title=?, url=?, published=COALESCE(NULLIF(?,''),published),"
            " last_seen=?, data=? WHERE key=?",
            (f["priority"], f["title"], f.get("url", ""), f.get("published", ""), ts, data, f["key"]),
        )
        self.db.commit()
        if PRIORITY_RANK[f["priority"]] < PRIORITY_RANK[prev["priority"]]:
            return "escalated", prev
        if f["priority"] != prev["priority"]:
            return "updated", prev
        return "same", prev

    def mark_notified(self, key: str, priority: str) -> None:
        self.db.execute("UPDATE findings SET notified_priority=? WHERE key=?", (priority, key))
        self.db.commit()

    def set_status(self, key: str, status: str) -> bool:
        cur = self.db.execute("UPDATE findings SET status=? WHERE key=? OR key LIKE ?", (status, key, f"%:{key}"))
        self.db.commit()
        return cur.rowcount > 0

    def findings(self, asset_id: str | None = None, types: list[str] | None = None, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM findings WHERE 1=1", []
        if asset_id:
            q += " AND asset_id=?"
            args.append(asset_id)
        if types:
            q += f" AND type IN ({','.join('?' * len(types))})"
            args += types
        if status:
            q += " AND status=?"
            args.append(status)
        q += " ORDER BY priority ASC, COALESCE(published, first_seen) DESC"
        return [self._row(r) for r in self.db.execute(q, args).fetchall()]

    def record_score(self, asset_id: str, score: int, grade: str) -> None:
        self.db.execute("INSERT INTO score_history VALUES(?,?,?,?)", (now_iso(), asset_id, score, grade))
        self.db.commit()

    def score_history(self, asset_id: str, limit: int = 30) -> list[dict]:
        rows = self.db.execute(
            "SELECT ts, score, grade FROM score_history WHERE asset_id=? ORDER BY ts DESC LIMIT ?", (asset_id, limit)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d.get("data") or "{}")
        return d
