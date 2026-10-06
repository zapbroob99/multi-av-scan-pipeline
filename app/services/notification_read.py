"""The console's notification bell: recent detections and what each operator has seen.

Detections are completed scans with a recorded high or critical verdict, from
every source an operator can read (manual, API and ICAP, archive members
included). They are ordered by completion, not by scan ID, because a long scan
created earlier can finish after a newer one. Each operator has two markers,
both the newest (completed_at, scan ID) pair they acted on: "read" greys
detections out and stops counting them, "cleared" also removes them from the
list. Clearing implies reading. The scans themselves are untouched; history stays
on the dashboard and the API ledger.

Health problems are not stored here. The bell reads the same health report as
System > Overview, for administrators only: a failing system is a state, not an
event, so it cannot be marked as read away. No raw engine output is read.
"""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.browser_db_budget import apply_read_budget

PAGE_SIZE = 10
UNREAD_CAP = 99
DETECTION_VERDICTS = ("high", "critical")
_DETECTED = "j.status = 'completed' AND j.verdict IN ('high', 'critical')"


class Detection(BaseModel):
    scan_id: int
    source: str
    client_name: str | None
    filename: str
    archive_member: bool
    verdict: str
    risk_score: int | None
    completed_at: str
    unread: bool


class Notifications(BaseModel):
    detections: list[Detection]
    # Unread detections, counted up to UNREAD_CAP; capped says there are more.
    unread: int
    unread_capped: bool
    # Whether this operator has cleared the list before, so an empty list means
    # "nothing new" rather than "nothing ever detected".
    cleared: bool


class ThroughDetection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # The newest detection the operator was shown; later ones are unaffected.
    through_scan_id: int = Field(ge=1, le=9007199254740991)


Marker = tuple[object, int] | None
_MARKERS = {"read": ("notifications_seen_at", "notifications_seen_scan_id"),
            "cleared": ("notifications_cleared_at", "notifications_cleared_scan_id")}


def _markers(connection, user_id: int) -> dict[str, Marker]:
    row = connection.execute("""SELECT notifications_seen_at, notifications_seen_scan_id,
        notifications_cleared_at, notifications_cleared_scan_id FROM users WHERE id = ?""", (user_id,)).fetchone()
    markers: dict[str, Marker] = {}
    for name, (at, scan_id) in _MARKERS.items():
        valid = row is not None and row[at] is not None and row[scan_id] is not None
        markers[name] = (row[at], int(row[scan_id])) if valid else None
    return markers


def _after(marker: Marker) -> tuple[str, tuple]:
    if marker is None:
        return "", ()
    return " AND (j.completed_at > ? OR (j.completed_at = ? AND j.id > ?))", (marker[0], marker[0], marker[1])


def read(user_id: int) -> Notifications:
    with db.connect() as connection:
        apply_read_budget(connection)
        markers = _markers(connection, user_id)
        # Clearing implies reading, so the later of the two decides what is new.
        seen = max((marker for marker in markers.values() if marker is not None), default=None)
        listed, listed_values = _after(markers["cleared"])
        rows = connection.execute(f"""
            SELECT j.id, j.source, j.verdict, j.risk_score, j.completed_at, j.scan_role,
                   SUBSTR(COALESCE(j.relative_path, s.original_filename), 1, 256) AS filename,
                   SUBSTR(c.display_name, 1, 128) AS client_name
            FROM scan_jobs j
            JOIN samples s ON s.id = j.sample_id
            LEFT JOIN service_clients c ON c.id = j.service_client_id
            WHERE {_DETECTED}{listed}
            ORDER BY j.completed_at DESC, j.id DESC LIMIT ?""", (*listed_values, PAGE_SIZE)).fetchall()
        newer, values = _after(seen)
        unread = int(connection.execute(f"""
            SELECT COUNT(*) AS unread FROM (
                SELECT 1 FROM scan_jobs j WHERE {_DETECTED}{newer} LIMIT {UNREAD_CAP + 1}) AS recent""",
            values).fetchone()["unread"])
    detections = [Detection(
        scan_id=int(row["id"]), source=str(row["source"]), client_name=row["client_name"],
        filename=str(row["filename"] or ""), archive_member=row["scan_role"] == "child",
        verdict=str(row["verdict"]), risk_score=row["risk_score"], completed_at=str(row["completed_at"]),
        unread=seen is None or (row["completed_at"], int(row["id"])) > seen,
    ) for row in rows]
    return Notifications(detections=detections, unread=min(unread, UNREAD_CAP), unread_capped=unread > UNREAD_CAP,
                         cleared=markers["cleared"] is not None)


def _target(connection, body: ThroughDetection):
    target = connection.execute(f"""SELECT j.completed_at, j.id FROM scan_jobs j
        WHERE j.id = ? AND {_DETECTED}""", (body.through_scan_id,)).fetchone()
    if target is None:
        raise HTTPException(404, "That detection no longer exists. Refresh the notifications.")
    return target


def _advance(connection, user_id: int, marker: str, target) -> None:
    at, scan_id_column = _MARKERS[marker]
    seen_at, scan_id = target["completed_at"], int(target["id"])
    # One conditional update, so two tabs acting at once cannot move it backwards.
    connection.execute(f"""UPDATE users SET {at} = ?, {scan_id_column} = ?
        WHERE id = ? AND ({at} IS NULL OR {scan_id_column} IS NULL
            OR {at} < ? OR ({at} = ? AND {scan_id_column} < ?))""",
        (seen_at, scan_id, user_id, seen_at, seen_at, scan_id))


def mark_read(user_id: int, body: ThroughDetection) -> None:
    """Grey out every detection up to one the operator was shown; never backwards."""
    with db.connect() as connection:
        _advance(connection, user_id, "read", _target(connection, body))


def clear(user_id: int, body: ThroughDetection) -> None:
    """Remove every detection up to one the operator was shown from their list, and read it."""
    with db.connect() as connection:
        target = _target(connection, body)
        _advance(connection, user_id, "read", target)
        _advance(connection, user_id, "cleared", target)
