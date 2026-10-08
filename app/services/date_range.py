"""A creation-time window for the browser history lists (ledger, dashboard, audit).

The console sends whole days in the operator's own time zone as two instants:
``created_after`` is inclusive and ``created_before`` exclusive, both with an
explicit offset. They are compared in UTC against ``created_at``, which SQLite
stores as ``YYYY-MM-DD HH:MM:SS`` text and PostgreSQL as TIMESTAMPTZ, so each
database gets the form it compares correctly (a ``+00:00`` suffix would make
SQLite's text comparison wrong at second boundaries).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException

from app import database as db


def validated(after: datetime | None, before: datetime | None) -> tuple[datetime | None, datetime | None]:
    for value in (after, before):
        if value is not None and value.tzinfo is None:
            raise HTTPException(422, "Dates need a time zone offset, for example 2026-10-08T00:00:00+03:00.")
    if after is not None and before is not None and after >= before:
        raise HTTPException(422, "The start date must be before the end date.")
    return after, before


def parameter(value: datetime) -> str:
    utc = value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"{utc}+00:00" if db.using_postgres() else utc


def conditions(column: str, after: datetime | None, before: datetime | None) -> tuple[list[str], list[object]]:
    clauses: list[str] = []
    values: list[object] = []
    if after is not None:
        clauses.append(f"{column} >= ?")
        values.append(parameter(after))
    if before is not None:
        clauses.append(f"{column} < ?")
        values.append(parameter(before))
    return clauses, values
