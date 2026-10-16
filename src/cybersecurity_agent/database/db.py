import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cybersecurity_agent.database.model import CVERecord

DEFAULT_DB_PATH = Path(__file__).resolve().parents[3] / "cybersecurity_agent" / "datasets" / "cve_intel.db"

_CVE_COLUMNS = "source, in_kev, epss_score, status, description, vulnerability, reason, actions, last_updated"
_NEWS_COLUMNS = "source, status, description, last_updated"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteDb:
    """SQLite-backed store of CTI intel — both CVE records (CISA KEV + EPSS)
    and RSS/news items — keyed by `source` (a CVE ID for the former, an
    article link for the latter). Opens a short-lived connection per
    operation rather than holding one open, so a single instance is safe to
    share across threads/async tasks (e.g. the periodic ingest cycle and the
    Streamlit UI thread).
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
              CREATE TABLE IF NOT EXISTS cve_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT UNIQUE NOT NULL,
                in_kev INTEGER,
                epss_score REAL,
                status TEXT CHECK (status IN ('defended', 'irrelevant', 'relevant', 'alerted')) DEFAULT NULL,
                description TEXT,
                vulnerability TEXT,
                reason TEXT,
                actions TEXT,
                last_updated TEXT
              );
                """
            )

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_to_cve_record(row) -> CVERecord:
        source, in_kev, epss_score, status, description, vulnerability, reason, actions, last_updated = row
        return CVERecord(
            source=source,
            in_kev=bool(in_kev),
            epss_score=epss_score,
            status=status,
            description=description,
            vulnerability=vulnerability,
            reason=reason,
            actions=actions,
            last_updated=last_updated,
        )

    def source_exists(self, source: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM cve_intel WHERE source = ?", (source,)).fetchone()
        return row is not None

    def get(self, source: str) -> Optional[CVERecord]:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {_CVE_COLUMNS} FROM cve_intel WHERE source = ? AND in_kev IS NOT NULL", (source,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_cve_record(row)

    def upsert(self, record: CVERecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_intel (source, in_kev, epss_score, status, description, vulnerability, reason, actions, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    in_kev = excluded.in_kev,
                    epss_score = excluded.epss_score,
                    status = excluded.status,
                    description = excluded.description,
                    vulnerability = excluded.vulnerability,
                    reason = excluded.reason,
                    actions = excluded.actions,
                    last_updated = excluded.last_updated
                """,
                (
                    record.source, int(record.in_kev), record.epss_score, record.status,
                    record.description, record.vulnerability, record.reason, record.actions,
                    record.last_updated,
                ),
            )

    def all_cve_records(self) -> List[CVERecord]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_CVE_COLUMNS} FROM cve_intel WHERE in_kev IS NOT NULL ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_cve_record(r) for r in rows]


    def get_by_status(self, status: str) -> List[CVERecord]:
        """CVE records tagged with a given lifecycle status, e.g. 'relevant' —
        used by the ID agent to find triaged-but-not-yet-actioned CVEs
        without re-scanning ones it (or the ingest cycle) already handled.
        """
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_CVE_COLUMNS} FROM cve_intel WHERE status = ? AND in_kev IS NOT NULL", (status,)
            ).fetchall()
        return [self._row_to_cve_record(r) for r in rows]
