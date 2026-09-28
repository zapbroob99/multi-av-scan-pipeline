"""One file an operator can attach to a support request.

It gathers what a remote helper asks for first -- versions, the health report,
configuration, worker and engine state, recent failures and recent
administrative changes -- so nobody has to collect screenshots or container
logs by hand.

What stays out: secrets (passwords, tokens, keys, credentialed URLs), sample
content, filenames and hashes of scanned files, and the source addresses of
console users. Configuration values that are not secrets, including host names
and paths from the deployment configuration, are included because they are
usually the cause; the console tells the operator to review the file before
sharing it outside the institution.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import time

from pydantic import BaseModel

from app import database as db
from app.services import about_read, audit_read, delivery_read, intake_read, worker_admin
from app.services.browser_db_budget import apply_read_budget
from app.services.deferred_storage import redact_paths
from app.services.health_read import HealthReport


SCHEMA_VERSION = 1
SECRET_KEY = re.compile(r'(PASSWORD|TOKEN|SECRET|API_KEY|ENCRYPTION_KEY|DATABASE_URL|WEBHOOK_URL|CREDENTIAL)', re.I)
URL_CREDENTIALS = re.compile(r'(\w+://)[^/@\s]+@')
RECENT_RESULTS = 500
FAILURE_LIMIT = 30
AUDIT_LIMIT = 30
TEXT_LIMIT = 300


class SupportBundle(BaseModel):
    filename: str
    media_type: str
    content: str


def redacted_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environ is None else environ
    result = {}
    for key in sorted(values):
        if not (key.startswith('MASP_') or key == 'FORWARDED_ALLOW_IPS'):
            continue
        value = values[key]
        if SECRET_KEY.search(key):
            result[key] = '(set, redacted)' if value.strip() else '(empty)'
        else:
            result[key] = URL_CREDENTIALS.sub(r'\1<redacted>@', value)[:TEXT_LIMIT]
    return result


def _recent_engine_failures(connection) -> list[dict]:
    # Newest results by primary key, then filtered: bounded regardless of history size.
    rows = connection.execute(f'''SELECT id, scan_job_id, SUBSTR(engine_name, 1, 128) AS engine_name, status,
        SUBSTR(COALESCE(error_message, ''), 1, {TEXT_LIMIT}) AS error_message, created_at
        FROM engine_results ORDER BY id DESC LIMIT ?''', (RECENT_RESULTS,)).fetchall()
    return [{'scan_id': int(row['scan_job_id']), 'engine': str(row['engine_name']), 'status': str(row['status']),
             'error': redact_paths(str(row['error_message'])), 'at': str(row['created_at'])}
            for row in rows if str(row['status']) == 'failed'][:FAILURE_LIMIT]


def build(health: HealthReport, engines: list[dict], now: float | None = None) -> SupportBundle:
    current = time.time() if now is None else now
    stamp = datetime.fromtimestamp(current, timezone.utc)
    with db.connect() as connection:
        apply_read_budget(connection)
        failures = _recent_engine_failures(connection)
        queue = {str(row['status']): int(row['n']) for row in connection.execute(
            "SELECT status, COUNT(*) AS n FROM scan_jobs WHERE status IN ('queued', 'running', 'finalizing') GROUP BY status").fetchall()}
    workers = worker_admin.page(limit=100, after=None)
    audit = audit_read.page(limit=AUDIT_LIMIT, before=None, query='', outcome='all')
    bundle = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': stamp.isoformat(),
        'excluded': ['secrets (values of password, token, key and credentialed URL settings)',
                     'sample content, filenames and hashes', 'console user source addresses',
                     'audit event details'],
        'about': about_read.snapshot(admin=True).model_dump(),
        'health': health.model_dump(),
        'active_scans': queue,
        'configuration': redacted_environment(),
        'workers': [item.model_dump() for item in workers.items],
        'engines': engines,
        'intake': intake_read.overview().model_dump(),
        'delivery': delivery_read.overview(now=current).model_dump(),
        'recent_engine_failures': failures,
        'recent_audit': [{key: getattr(event, key) for key in
                          ('created_at', 'actor_type', 'actor_name', 'action', 'target_type', 'target_id', 'outcome', 'request_id')}
                         for event in audit.items],
    }
    return SupportBundle(filename=f"masp-support-{stamp.strftime('%Y%m%dT%H%M%SZ')}.json",
                         media_type='application/json',
                         content=json.dumps(bundle, indent=2, sort_keys=True, default=str))
