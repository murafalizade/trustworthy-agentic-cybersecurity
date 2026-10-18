"""Stateful event-frequency tracking for brute-force / scan detection.

A single suspicious-looking line (one failed login, one 404) is rarely
actionable on its own. What turns it into a real signal is repetition —
20 failed logins for the same user in a minute, the same source IP hitting
50 distinct paths. Because the agent is called once per log line/batch, that
repetition has to be tracked *across* calls, not reasoned about from a single
prompt — hence a small persistent counter store rather than relying on the
model's own (nonexistent) memory of prior calls. This is what keeps slow,
low-and-noise brute-force attempts from being scored as a true negative just
because any single line looks unremarkable.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "id_events.db"


class EventFrequencyStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    occurred_at REAL NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_key ON events(key);")

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def record_and_count(self, key: str, window_seconds: int) -> int:
        """Records one occurrence of `key` now, then returns how many
        occurrences of that same key happened within the trailing
        `window_seconds`, including this one.
        """
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds
        with self._connect() as conn:
            conn.execute("INSERT INTO events (key, occurred_at) VALUES (?, ?)", (key, now))
            conn.execute("DELETE FROM events WHERE occurred_at < ?", (cutoff,))
            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE key = ? AND occurred_at >= ?",
                (key, cutoff),
            ).fetchone()
        return row[0] if row else 0
