import json
import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path("mini_siem.db")


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    """
    Create the database tables if they do not already exist.

    events:
        Valid normalized security events.

    dead_letters:
        Invalid events that failed validation.

    pipeline_state:
        Stores cursors so ingestion can resume where it left off.
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT,
                user TEXT,
                source_ip TEXT,
                raw_event TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dead_letters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reason TEXT NOT NULL,
                missing_fields TEXT NOT NULL,
                source TEXT,
                raw_event TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pipeline_state (
                source TEXT PRIMARY KEY,
                cursor TEXT NOT NULL
            )
            """
        )

        connection.commit()


def save_event(event: dict[str, Any]) -> bool:
    """
    Save a valid normalized event.

    Returns:
        True if inserted.
        False if it was a duplicate event_id.
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO events (
                event_id,
                timestamp,
                source,
                event_type,
                action,
                outcome,
                user,
                source_ip,
                raw_event
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                event["timestamp"],
                event["source"],
                event["event_type"],
                event["action"],
                event.get("outcome"),
                event.get("user"),
                event.get("source_ip"),
                json.dumps(event.get("raw", {})),
            ),
        )

        connection.commit()

        return cursor.rowcount == 1


def save_dead_letter(
    normalized_event: dict[str, Any],
    missing_fields: list[str],
) -> None:
    """
    Save an invalid event to the dead-letter table.
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO dead_letters (
                reason,
                missing_fields,
                source,
                raw_event
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "missing required fields",
                json.dumps(missing_fields),
                normalized_event.get("source"),
                json.dumps(normalized_event.get("raw", {})),
            ),
        )

        connection.commit()


def get_pipeline_cursor(source: str) -> str:
    """
    Get the last saved cursor for a source.

    If this source has never been ingested before, start at cursor 0.
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT cursor
            FROM pipeline_state
            WHERE source = ?
            """,
            (source,),
        )

        row = cursor.fetchone()

    if row is None:
        return "0"

    return row["cursor"]


def set_pipeline_cursor(source: str, cursor_value: str) -> None:
    """
    Save the latest cursor for a source.
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO pipeline_state (source, cursor)
            VALUES (?, ?)
            ON CONFLICT(source)
            DO UPDATE SET cursor = excluded.cursor
            """,
            (source, cursor_value),
        )

        connection.commit()


def get_all_events() -> list[dict[str, Any]]:
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                event_id,
                timestamp,
                source,
                event_type,
                action,
                outcome,
                user,
                source_ip,
                raw_event
            FROM events
            ORDER BY id ASC
            """
        )

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_all_dead_letters() -> list[dict[str, Any]]:
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                reason,
                missing_fields,
                source,
                raw_event
            FROM dead_letters
            ORDER BY id ASC
            """
        )

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def get_pipeline_state() -> list[dict[str, Any]]:
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT source, cursor
            FROM pipeline_state
            ORDER BY source ASC
            """
        )

        rows = cursor.fetchall()

    return [dict(row) for row in rows]