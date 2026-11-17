"""Transactional local audit journal with an authenticated record chain."""

import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime


ZERO = "0" * 64


class AuditJournal:
    def __init__(self, path, key):
        if len(key) < 32:
            raise ValueError("AUDIT_KEY_HEX должен содержать не менее 32 байт")
        self.path = path
        self.key = key
        with self.connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY,
                    body TEXT NOT NULL,
                    mac TEXT NOT NULL
                )
            """)
            connection.execute("CREATE TABLE IF NOT EXISTS biometric_assertions (id TEXT PRIMARY KEY)")

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def signature(self, sequence, previous, body):
        message = f"{sequence}:{previous}:{body}".encode("utf-8")
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()

    def record(self, event, outcome, details, *, actor="monitor", run_id=None, assertion_id=None):
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if assertion_id:
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO biometric_assertions VALUES (?)", (assertion_id,)
                )
                if inserted.rowcount != 1:
                    raise ValueError("Биометрическое утверждение уже использовано")
            tail = connection.execute(
                "SELECT sequence, mac FROM audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            last_sequence, last_mac = tail or (0, ZERO)
            sequence = last_sequence + 1
            body = json.dumps({
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event, "actor": actor, "outcome": outcome, "run_id": run_id,
                "details": details,
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            mac = self.signature(sequence, last_mac, body)
            connection.execute("INSERT INTO audit VALUES (?, ?, ?)", (sequence, body, mac))

    def verify(self, checkpoint=None):
        previous, count = ZERO, 0
        checkpoint_matched = checkpoint is None or checkpoint == (0, ZERO)
        with self.connection() as connection:
            records = connection.execute("SELECT sequence, body, mac FROM audit ORDER BY sequence")
            for sequence, body, mac in records:
                if sequence != count + 1 or not hmac.compare_digest(
                    mac, self.signature(sequence, previous, body)
                ):
                    raise ValueError(f"Нарушена целостность записи {sequence}")
                count, previous = sequence, mac
                if checkpoint == (count, previous):
                    checkpoint_matched = True
        if not checkpoint_matched:
            raise ValueError("В журнале отсутствует доверенная контрольная точка")
        return count, previous
