"""Admin management of the institution SHA-256 blocklist and allowlist.

Entries are immutable: a hash is added to one list or removed. Moving a hash
between lists is a removal and a fresh addition, never an in-place edit, so a
blocked hash cannot become allowed through a request that meant something else.
The Hash List engine reads the table live, so changes apply to engine jobs that
run afterwards and never rewrite completed results.
"""
import re
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import database as db
from app.services.browser_db_budget import apply_read_budget


MAX_ADD = 1000
NOTE_LIMIT = 256
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class HashListEntry(BaseModel):
    id: int
    sha256: str
    list_kind: Literal["block", "allow"]
    note: str
    created_by: str | None
    created_at: int


class HashListCounts(BaseModel):
    block: int
    allow: int


class HashListPage(BaseModel):
    items: list[HashListEntry]
    next_before: int | None
    # Only on the first page: counting is a full scan of the list.
    counts: HashListCounts | None


class AddHashesBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    list_kind: Literal["block", "allow"]
    hashes: list[str] = Field(min_length=1, max_length=MAX_ADD)
    note: str = Field(default="", max_length=NOTE_LIMIT)


class ExistingHash(BaseModel):
    sha256: str
    # "removed" only when a concurrent removal won the race for this hash.
    list_kind: Literal["block", "allow", "removed"]


class HashesAdded(BaseModel):
    added: int
    existing: list[ExistingHash]


def normalize(values: list[str]) -> list[str]:
    """Validate every value before anything is written; keep first-seen order."""
    seen: dict[str, None] = {}
    for index, value in enumerate(values, start=1):
        digest = value.strip().lower() if isinstance(value, str) else ""
        if not SHA256_PATTERN.fullmatch(digest):
            raise HTTPException(422, f"Entry {index} is not a SHA-256 value (64 hexadecimal characters).")
        seen.setdefault(digest)
    return list(seen)


def page(*, limit: int, before: int | None, kind: str, query: str) -> HashListPage:
    conditions: list[str] = []
    values: list[object] = []
    if before is not None:
        conditions.append("id < ?")
        values.append(before)
    if kind != "all":
        conditions.append("list_kind = ?")
        values.append(kind)
    term = query.strip().lower()
    if SHA256_PATTERN.fullmatch(term):
        # The common case, answered from the unique index.
        conditions.append("sha256 = ?")
        values.append(term)
    elif term:
        # Literal match: an operator character must match itself, not widen the filter.
        escaped = term.replace("!", "!!").replace("%", "!%").replace("_", "!_")
        conditions.append("(sha256 LIKE ? ESCAPE '!' OR LOWER(note) LIKE ? ESCAPE '!')")
        values.extend([escaped + "%", "%" + escaped + "%"])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    with db.connect() as connection:
        apply_read_budget(connection)
        rows = connection.execute(f"""SELECT id, sha256, list_kind, SUBSTR(note, 1, {NOTE_LIMIT}) AS note,
            SUBSTR(created_by, 1, 128) AS created_by, created_at
            FROM hash_list_entries{where} ORDER BY id DESC LIMIT ?""", (*values, limit + 1)).fetchall()
        counts = None
        if before is None:
            count_rows = connection.execute("""SELECT list_kind, COUNT(*) AS entries
                FROM hash_list_entries GROUP BY list_kind""").fetchall()
            totals = {str(row["list_kind"]): int(row["entries"]) for row in count_rows}
            counts = HashListCounts(block=totals.get("block", 0), allow=totals.get("allow", 0))
    items = [HashListEntry(**{**dict(row), "note": row["note"] or ""}) for row in rows[:limit]]
    return HashListPage(items=items, next_before=items[-1].id if len(rows) > limit else None, counts=counts)


def add(body: AddHashesBody, created_by: str) -> HashesAdded:
    digests = normalize(body.hashes)
    existing = db.add_hash_list_entries([(digest, body.list_kind, body.note.strip()) for digest in digests],
                                        created_by)
    return HashesAdded(added=len(digests) - len(existing),
                       existing=[ExistingHash(sha256=digest, list_kind=kind) for digest, kind in existing])


def remove(entry_id: int) -> None:
    if not db.delete_hash_list_entry(entry_id):
        raise HTTPException(404, "Hash list entry not found. Refresh the list.")
