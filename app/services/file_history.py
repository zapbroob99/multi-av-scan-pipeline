"""What MASP itself has recorded about a file, by SHA-256: the local half of a hash lookup.

Every scan that settles (completed, failed, or decided by a rule at intake,
archive members included) updates one row per SHA-256 in the same transaction:
first and last seen, how many scans, how many had an engine detection, and the
latest scan's outcome with each engine's result and the engine and signature
versions that produced it. The row survives retention and scan deletion, so
the institution keeps its own memory of a file after the scans themselves are
gone; it holds no file name, client or sample content.

This is never a decision. It answers "what did our engines say about this exact
file, when, with which signatures", which a later signature update can change.
External reputation (VirusTotal and other hash engines) is a separate lookup:
it is not stored here and nothing here feeds it. A manual file scan may run a
reputation adapter as one of its engines; that result stays in the scan's own
report and is left out of this history (`external_adapter_keys`): the outcome
kept here is recomputed from MASP's own engines, and a scan that only a provider
answered does not make a file "seen by MASP".
"""
from __future__ import annotations

import json
import re
import time
from types import SimpleNamespace
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel

from app import database as db
from app.services.browser_db_budget import apply_read_budget
from app.services.profile_policy import not_allowed_by_code
from app.services.scoring import calculate_risk

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ENGINES = 32
RECENT_SCANS = 20


def ensure_schema(connection: Any) -> None:
    connection.execute('''CREATE TABLE IF NOT EXISTS file_history (
        sha256 TEXT PRIMARY KEY,
        first_seen_at BIGINT NOT NULL,
        last_seen_at BIGINT NOT NULL,
        scan_count BIGINT NOT NULL,
        detected_count BIGINT NOT NULL,
        last_detected_at BIGINT,
        last_scan_id BIGINT,
        last_status TEXT,
        last_verdict TEXT,
        last_risk_score INTEGER,
        last_rule_action TEXT,
        last_not_allowed TEXT,
        last_engines_json TEXT
    )''')
    # Finding the scans of one file: by digest, then by sample.
    connection.execute('CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples (sha256)')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_scan_jobs_sample ON scan_jobs (sample_id, id)')


def external_adapter_keys() -> tuple[str, ...]:
    """Adapters that ask an outside reputation service rather than examine the file here."""
    from app.services.engine_registry import REGISTERED_ADAPTERS
    return tuple(sorted(key for key, adapter in REGISTERED_ADAPTERS.items()
                        if adapter.capabilities.supports_hash_lookup or adapter.capabilities.consumes_external_quota))


def _local_results(alias: str = 'r') -> tuple[str, str, tuple[str, ...]]:
    """Joins and a condition keeping only results produced by MASP's own engines.

    A result names its engine; the scan's engine job (or, for results older than
    engine jobs, the instance of that name) says which adapter produced it.
    """
    keys = external_adapter_keys() or ('',)
    joins = (f'LEFT JOIN scan_engine_jobs ej ON ej.scan_job_id = {alias}.scan_job_id AND ej.engine_name = {alias}.engine_name '
             f'LEFT JOIN engine_instances ei ON ei.display_name = {alias}.engine_name')
    condition = f"COALESCE(ej.engine_key, ei.adapter_key, '') NOT IN ({', '.join('?' for _ in keys)})"
    return joins, condition, keys


def _epoch(column: str) -> str:
    return (f"CAST(EXTRACT(EPOCH FROM {column}) AS BIGINT)" if db.using_postgres()
            else f"CAST(strftime('%s', {column}) AS INTEGER)")


def backfill(connection: Any) -> None:
    """Fill the table once from the scans already recorded, when it is still empty.

    Counts and times come from the scans; the latest outcome is read live from
    the latest scan while it still exists. Several processes start together, so
    a row another one inserted first is left alone.
    """
    if connection.execute('SELECT 1 FROM file_history LIMIT 1').fetchone() is not None:
        return
    joins, local, excluded = _local_results()
    detected = (f"EXISTS (SELECT 1 FROM engine_results r {joins} WHERE r.scan_job_id = j.id "
                f"AND r.status = 'completed' AND r.detected = ? AND {local})")
    settled = _epoch('COALESCE(j.completed_at, j.failed_at, j.created_at)')
    connection.execute(f'''INSERT INTO file_history
        (sha256, first_seen_at, last_seen_at, scan_count, detected_count, last_detected_at, last_scan_id)
        SELECT s.sha256, MIN({_epoch('j.created_at')}), MAX({settled}), COUNT(*),
               SUM(CASE WHEN {detected} THEN 1 ELSE 0 END),
               MAX(CASE WHEN {detected} THEN {settled} END), MAX(j.id)
        FROM scan_jobs j JOIN samples s ON s.id = j.sample_id
        WHERE j.status IN ('completed', 'failed') AND s.sha256 IS NOT NULL
          AND (NOT EXISTS (SELECT 1 FROM engine_results r0 WHERE r0.scan_job_id = j.id)
               OR EXISTS (SELECT 1 FROM engine_results r {joins} WHERE r.scan_job_id = j.id AND {local}))
        GROUP BY s.sha256
        ON CONFLICT (sha256) DO NOTHING''', (db.db_bool(True), *excluded, db.db_bool(True), *excluded, *excluded))


def _version(value: Any) -> str | None:
    # A version naming a path (old YARA results recorded the rules directory)
    # says nothing useful and must not leave the server.
    text = str(value or '').strip()[:64]
    return None if not text or '/' in text or '\\' in text else text


def _engines(connection: Any, scan_id: int) -> list[dict]:
    joins, local, excluded = _local_results()
    rows = connection.execute(f'''SELECT r.engine_name, r.status, r.detected, SUBSTR(r.signature, 1, 200) AS signature,
        r.engine_version, r.signature_version FROM engine_results r {joins}
        WHERE r.scan_job_id = ? AND {local} ORDER BY r.id LIMIT ?''',
        (scan_id, *excluded, MAX_ENGINES)).fetchall()
    return [{'engine_name': str(row['engine_name'])[:128], 'status': str(row['status']),
             'detected': bool(row['detected']) and str(row['status']) == 'completed',
             'signature': row['signature'] if row['detected'] else None,
             'engine_version': _version(row['engine_version']), 'signature_version': _version(row['signature_version'])}
            for row in rows]


def _outcome(connection: Any, scan_id: int) -> dict | None:
    """The scan's outcome as MASP's own engines saw it; None when only a provider answered.

    A scan without any engine result (decided by a rule at intake) keeps its
    recorded outcome. When a reputation engine also ran, the recorded verdict
    includes it, so the outcome is scored again from the local results with the
    shared scoring rules.
    """
    scan = connection.execute('''SELECT s.sha256, j.status, j.verdict, j.risk_score, j.rule_action, j.not_allowed
        FROM scan_jobs j JOIN samples s ON s.id = j.sample_id WHERE j.id = ?''', (scan_id,)).fetchone()
    if scan is None or not scan['sha256']:
        return None
    joins, local, excluded = _local_results()
    counts = connection.execute(f'''SELECT COUNT(*) AS total, SUM(CASE WHEN {local} THEN 1 ELSE 0 END) AS own
        FROM engine_results r {joins} WHERE r.scan_job_id = ?''', (*excluded, scan_id)).fetchone()
    total, own = int(counts['total'] or 0), int(counts['own'] or 0)
    if total and not own:
        return None
    outcome = dict(scan)
    outcome['engines'] = engines = _engines(connection, scan_id)
    if own < total:
        if not any(engine['status'] == 'completed' for engine in engines):
            outcome.update(status='failed', verdict='info', risk_score=None)
        else:
            assessment = calculate_risk([SimpleNamespace(**engine) for engine in engines])  # type: ignore[misc]
            outcome.update(verdict=assessment.verdict, risk_score=assessment.score)
    return outcome


def record(connection: Any, scan_id: int, now: int | None = None) -> None:
    """Fold one settled scan into its file's row, in the settling transaction.

    Settling the latest scan of a file again (a retry) replaces its outcome
    without counting the file as seen once more.
    """
    scan = _outcome(connection, scan_id)
    if scan is None:
        return
    current = int(time.time()) if now is None else now
    engines = scan['engines']
    detected = any(engine['detected'] for engine in engines)
    newer = 'excluded.last_scan_id >= COALESCE(file_history.last_scan_id, 0)'
    repeat = 'file_history.last_scan_id = excluded.last_scan_id'
    latest = ', '.join(f'{column} = CASE WHEN {newer} THEN excluded.{column} ELSE file_history.{column} END'
                       for column in ('last_scan_id', 'last_status', 'last_verdict', 'last_risk_score',
                                      'last_rule_action', 'last_not_allowed', 'last_engines_json'))
    connection.execute(f'''INSERT INTO file_history
        (sha256, first_seen_at, last_seen_at, scan_count, detected_count, last_detected_at, last_scan_id,
         last_status, last_verdict, last_risk_score, last_rule_action, last_not_allowed, last_engines_json)
        VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (sha256) DO UPDATE SET
          first_seen_at = CASE WHEN excluded.first_seen_at < file_history.first_seen_at
                               THEN excluded.first_seen_at ELSE file_history.first_seen_at END,
          last_seen_at = CASE WHEN excluded.last_seen_at > file_history.last_seen_at
                              THEN excluded.last_seen_at ELSE file_history.last_seen_at END,
          scan_count = file_history.scan_count + CASE WHEN {repeat} THEN 0 ELSE 1 END,
          detected_count = file_history.detected_count + CASE WHEN {repeat} THEN 0 ELSE excluded.detected_count END,
          last_detected_at = COALESCE(excluded.last_detected_at, file_history.last_detected_at),
          {latest}''',
        (scan['sha256'], current, current, 1 if detected else 0, current if detected else None, scan_id,
         scan['status'], scan['verdict'], scan['risk_score'], scan['rule_action'], scan['not_allowed'],
         json.dumps(engines, separators=(',', ':'))))


class EngineFact(BaseModel):
    engine_name: str
    status: str
    detected: bool
    signature: str | None
    engine_version: str | None
    signature_version: str | None


class HistoryFacts(BaseModel):
    """What MASP recorded about the file; safe to share with every integration."""
    seen: bool
    first_seen_at: int | None = None
    last_seen_at: int | None = None
    scan_count: int = 0
    detected_count: int = 0
    last_detected_at: int | None = None
    last_status: str | None = None
    last_verdict: str | None = None
    last_risk_score: int | None = None
    last_rule_action: str | None = None
    last_not_allowed: str | None = None
    last_engines: list[EngineFact] = []


class FileScan(BaseModel):
    id: int
    source: str
    scan_role: str
    status: str
    verdict: str
    risk_score: int | None
    created_at: str
    filename: str
    client_id: int | None
    client_name: str | None
    exception_id: int | None
    not_allowed: str | None
    rule_action: str | None
    not_allowed_label: str | None = None


class ActiveException(BaseModel):
    id: int
    scope: str
    reason: str


class FileHistory(HistoryFacts):
    """The browser's file page: the facts plus where this file has been seen."""
    sha256: str
    last_not_allowed_label: str | None = None
    hash_list: str | None
    exceptions: list[ActiveException]
    recent_scans: list[FileScan]


def normalized(value: str) -> str:
    digest = value.strip().lower()
    if not SHA256.fullmatch(digest):
        raise HTTPException(422, "Enter the file's full SHA-256 (64 hexadecimal characters).")
    return digest


def facts(connection: Any, sha256: str) -> HistoryFacts:
    row = connection.execute('SELECT * FROM file_history WHERE sha256 = ?', (sha256,)).fetchone()
    if row is None:
        return HistoryFacts(seen=False)
    values = dict(row)
    engines_json = values.get('last_engines_json')
    if engines_json is None and values.get('last_scan_id') is not None:
        # A row filled from older scans: read the latest outcome while that scan exists.
        scan = _outcome(connection, int(values['last_scan_id']))
        if scan is not None:
            values.update(last_status=scan['status'], last_verdict=scan['verdict'], last_risk_score=scan['risk_score'],
                          last_rule_action=scan['rule_action'], last_not_allowed=scan['not_allowed'])
            engines = scan['engines']
        else:
            engines = []
    else:
        try:
            engines = json.loads(engines_json or '[]')
        except (TypeError, ValueError):
            engines = []
    return HistoryFacts(
        seen=True, first_seen_at=values['first_seen_at'], last_seen_at=values['last_seen_at'],
        scan_count=values['scan_count'], detected_count=values['detected_count'],
        last_detected_at=values['last_detected_at'], last_status=values.get('last_status'),
        last_verdict=values.get('last_verdict'), last_risk_score=values.get('last_risk_score'),
        last_rule_action=values.get('last_rule_action'), last_not_allowed=values.get('last_not_allowed'),
        last_engines=[EngineFact(**engine) for engine in engines if isinstance(engine, dict)][:MAX_ENGINES])


def read(sha256: str) -> FileHistory:
    """The file page: recorded facts, hash list and exception state, and recent scans."""
    digest = normalized(sha256)
    now = int(time.time())
    with db.connect() as connection:
        apply_read_budget(connection)
        found = facts(connection, digest)
        listed = connection.execute('SELECT list_kind FROM hash_list_entries WHERE sha256 = ?', (digest,)).fetchone()
        exceptions = connection.execute('''SELECT e.id, e.service_client_id, SUBSTR(e.reason, 1, 500) AS reason,
            SUBSTR(c.display_name, 1, 100) AS client_name
            FROM scan_exceptions e LEFT JOIN service_clients c ON c.id = e.service_client_id
            WHERE e.sha256 = ? AND e.revoked_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > ?)
            ORDER BY e.id DESC LIMIT 20''', (digest, now)).fetchall()
        scans = connection.execute('''SELECT j.id, j.source, j.scan_role, j.status, j.verdict, j.risk_score, j.created_at,
            SUBSTR(s.original_filename, 1, 256) AS filename, j.service_client_id AS client_id,
            SUBSTR(c.display_name, 1, 100) AS client_name, j.exception_id, j.not_allowed, j.rule_action
            FROM samples s JOIN scan_jobs j ON j.sample_id = s.id
            LEFT JOIN service_clients c ON c.id = j.service_client_id
            WHERE s.sha256 = ? ORDER BY j.id DESC LIMIT ?''', (digest, RECENT_SCANS)).fetchall()
    label = lambda code: entry.label if (entry := not_allowed_by_code(code)) else None
    return FileHistory(
        **found.model_dump(), sha256=digest, last_not_allowed_label=label(found.last_not_allowed),
        hash_list=listed['list_kind'] if listed else None,
        exceptions=[ActiveException(id=row['id'], reason=row['reason'],
                                    scope='All clients' if row['service_client_id'] is None
                                    else f"#{row['service_client_id']} {row['client_name'] or 'client'}")
                    for row in exceptions],
        recent_scans=[FileScan(**{**dict(row), 'created_at': str(row['created_at']),
                                  'not_allowed_label': label(row['not_allowed'])}) for row in scans])


def public(sha256: str) -> dict:
    """The integration API's view: recorded facts only, times as UTC ISO 8601."""
    with db.connect() as connection:
        apply_read_budget(connection)
        found = facts(connection, sha256)
    iso = lambda value: (datetime.fromtimestamp(int(value), timezone.utc).isoformat().replace('+00:00', 'Z')
                         if value is not None else None)
    return {
        'seen': found.seen, 'first_seen_at': iso(found.first_seen_at), 'last_seen_at': iso(found.last_seen_at),
        'scan_count': found.scan_count, 'detected_count': found.detected_count,
        'last_detected_at': iso(found.last_detected_at), 'last_status': found.last_status,
        'last_verdict': found.last_verdict,
        'last_engines': [engine.model_dump() for engine in found.last_engines],
        'note': 'Recorded by this MASP deployment at the times shown; not a current verdict.',
    }
