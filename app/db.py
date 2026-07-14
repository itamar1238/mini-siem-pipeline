import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("mini_siem.db")

def get_connection() -> sqlite3.Connection:
    """
        Opens a conenction to the sqlite database
        SQLite has evertything stored in a local file
    """

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def initialize_database() -> None:
    """
        Create the database tables if they dont exist
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
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

        connection.commit()

def save_event(event: dict[str, Any]) -> None:
    """
        Saves a valid normalized event into the SIEM events table
    """

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO events (
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

def save_dead_letter(
    normalized_event: dict[str, Any],
    missing_fields: list[str],
) -> None:
    """
    Save an invalid event to the dead-letter table.
    This lets us debug malformed events instead of silently dropping them.
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


def get_all_events() -> list[dict[str, Any]]:
    """
    Return all valid events from the fake SIEM.
    Useful for debugging and later for detections.
    """

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
    """
    Return all dead-lettered events.
    """

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