"""Session metadata and immutable assessment artifact storage."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from perfektblue.errors import SessionError
from perfektblue.models import AssessmentResult, Evidence
from perfektblue.paths import AppPaths, get_paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target_address TEXT NOT NULL,
    target_name TEXT,
    backend TEXT NOT NULL,
    verdict TEXT NOT NULL,
    verdict_reason TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    interrupted INTEGER NOT NULL DEFAULT 0,
    artifact_dir TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    target TEXT,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
"""


class SessionStore:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or get_paths()
        self.paths.ensure()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.paths.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise SessionError(str(exc)) from exc
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def save(self, result: AssessmentResult) -> Path:
        artifact_dir = self.paths.sessions_dir / result.session_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        report_path = artifact_dir / "result.json"
        temporary = report_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        temporary.replace(report_path)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO sessions
                (id, target_address, target_name, backend, verdict, verdict_reason,
                 started_at, completed_at, interrupted, artifact_dir)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.session_id,
                    result.target.address,
                    result.target.name,
                    result.target.backend,
                    result.injection_verdict.value,
                    result.verdict_reason,
                    result.started_at,
                    result.completed_at,
                    int(result.interrupted),
                    str(artifact_dir),
                ),
            )
            connection.execute("DELETE FROM evidence WHERE session_id = ?", (result.session_id,))
            connection.executemany(
                """
                INSERT INTO evidence
                (id, session_id, kind, source, confidence, target, timestamp, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.id,
                        result.session_id,
                        item.kind,
                        item.source,
                        item.confidence,
                        item.target,
                        item.timestamp,
                        json.dumps(asdict(item), sort_keys=True),
                    )
                    for item in result.evidence
                ],
            )
        return report_path

    def add_artifact(
        self, session_id: str, name: str, content: str | bytes, binary: bool = False
    ) -> Path:
        safe_name = Path(name).name
        artifact_dir = self.paths.sessions_dir / session_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        destination = artifact_dir / safe_name
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        if binary:
            if not isinstance(content, bytes):
                raise SessionError("binary artifact content must be bytes")
            temporary.write_bytes(content)
        else:
            if not isinstance(content, str):
                raise SessionError("text artifact content must be a string")
            temporary.write_text(content, encoding="utf-8")
        temporary.replace(destination)
        return destination

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def load_result(self, session_id: str) -> dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise SessionError(f"session not found: {session_id}")
        path = Path(session["artifact_dir"]) / "result.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SessionError(f"cannot load session result: {exc}") from exc
        if not isinstance(payload, dict):
            raise SessionError("stored session result is not a JSON object")
        return payload

    def import_legacy_can(self, path: Path) -> list[Evidence]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SessionError(f"cannot import legacy CAN data: {exc}") from exc
        if not isinstance(payload, dict):
            raise SessionError("legacy CAN database must be an object")
        evidence: list[Evidence] = []
        for arbitration_id, data in payload.items():
            if not isinstance(arbitration_id, str) or not isinstance(data, list):
                continue
            evidence.append(
                Evidence(
                    kind="legacy-can-frame",
                    source="legacy-import",
                    value={"arbitration_id": arbitration_id, "data": data},
                    confidence=50.0,
                    detail=(
                        "Imported from legacy can_command_db.json; timing and "
                        "repetition are unknown."
                    ),
                )
            )
        return evidence
