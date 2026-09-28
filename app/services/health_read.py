"""One answer to "is MASP working, and if not, where do I look?".

Every other System screen shows one part of the scan chain in detail. This one
evaluates each part against the same rule of thumb an operator would apply and
returns a state, a one-line summary and the screen to open next. It reads only
what already exists: worker heartbeats, engine health reports, queue and intake
tables, the ICAP gateway's activity record and the sample storage filesystem.

States: ``critical`` means scanning is failing or will fail (for ICAP, uploads
are being blocked); ``warning`` needs attention soon; ``unknown`` means the
signal is missing; ``inactive`` means the part is not in use and is left out of
the overall state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import shutil
import time
from typing import Literal

from pydantic import BaseModel

from app import database as db
from app.icap.activity import FLUSH_SECONDS as ICAP_FLUSH_SECONDS, SETTING_PREFIX as ICAP_SETTING_PREFIX
from app.services import intake_read
from app.services.browser_db_budget import apply_read_budget
from app.services.sample_paths import STORAGE_DIR
from app.services.worker_runtime import get_worker_status


State = Literal['ok', 'warning', 'critical', 'unknown', 'inactive']
RANK = {'inactive': 0, 'ok': 1, 'unknown': 2, 'warning': 3, 'critical': 4}

QUEUE_WARNING_SECONDS = 60
QUEUE_CRITICAL_SECONDS = 300          # matches the documented alert
SIGNATURE_WARNING_SECONDS = 2 * 86400
SIGNATURE_CRITICAL_SECONDS = 7 * 86400
DISK_WARNING_PERCENT = 80
DISK_CRITICAL_PERCENT = 90
DEFERRED_WARNING_SECONDS = 900
DEFERRED_CRITICAL_SECONDS = 3600
NOTIFY_CRITICAL_SECONDS = 3600
ICAP_STALE_SECONDS = 3 * ICAP_FLUSH_SECONDS
ICAP_FORGOTTEN_SECONDS = 7 * 86400    # a listener silent this long was removed, not stopped
RECENT_SECONDS = 3600


class HealthCheck(BaseModel):
    key: str
    label: str
    state: State
    summary: str
    detail: str | None = None
    link: str | None = None


class HealthReport(BaseModel):
    overall: Literal['ok', 'warning', 'critical', 'unknown']
    checks: list[HealthCheck]
    waiting_reason: str | None
    generated_at: str


class EngineState(BaseModel):
    """The Engines screen's own health verdict, so both screens always agree."""
    name: str
    adapter_key: str
    state: str
    detail: str


def _when(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace(' ', 'T').replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age_text(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f'{seconds} s'
    if seconds < 5400:
        return f'{round(seconds / 60)} min'
    if seconds < 172800:
        return f'{round(seconds / 3600)} h'
    return f'{round(seconds / 86400)} d'


def _names(items: list[str], limit: int = 4) -> str:
    shown = ', '.join(items[:limit])
    return shown + (f' and {len(items) - limit} more' if len(items) > limit else '')


def workers_check(status: dict[str, object]) -> HealthCheck:
    nodes = status.get('nodes') if isinstance(status.get('nodes'), list) else []
    schedulable = int(status.get('schedulable_count') or 0)
    online = int(status.get('online_count') or 0)
    expected_offline = [str(n.get('display_name') or n.get('node_id')) for n in nodes
                        if isinstance(n, dict) and n.get('lifecycle_state') == 'active' and not n.get('online')]
    link = '/system'
    if not nodes and not online:
        return HealthCheck(key='workers', label='Workers', state='critical', link=link,
                           summary='No worker has registered.',
                           detail='Start the worker service; scans cannot run without one.')
    if schedulable == 0:
        reason = ('Online workers are draining or disabled.' if online
                  else 'Every worker is offline.')
        return HealthCheck(key='workers', label='Workers', state='critical', link=link,
                           summary='No worker is accepting work.', detail=reason)
    if expected_offline:
        return HealthCheck(key='workers', label='Workers', state='warning', link=link,
                           summary=f'{schedulable} accepting work; {len(expected_offline)} active worker(s) offline.',
                           detail=f'Offline: {_names(expected_offline)}. Drain or disable a worker that was removed on purpose.')
    return HealthCheck(key='workers', label='Workers', state='ok', link=link,
                       summary=f'{schedulable} worker(s) accepting work.')


def queue_check(queued: int, oldest_age: float | None, waiting_reason: str | None) -> HealthCheck:
    link = '/system/runtime'
    if not queued or oldest_age is None:
        return HealthCheck(key='queue', label='Scan queue', state='ok', link=link, summary='No scan is waiting to start.')
    state: State = ('critical' if oldest_age >= QUEUE_CRITICAL_SECONDS
                    else 'warning' if oldest_age >= QUEUE_WARNING_SECONDS else 'ok')
    return HealthCheck(key='queue', label='Scan queue', state=state, link=link,
                       summary=f'{queued} scan(s) waiting; the oldest for {age_text(oldest_age)}.',
                       detail=waiting_reason if state != 'ok' else None)


def engines_check(engines: list[EngineState]) -> HealthCheck:
    link = '/engines'
    active = [e for e in engines if e.state != 'disabled']
    if not active:
        return HealthCheck(key='engines', label='Engines', state='critical', link=link,
                           summary='No engine is enabled.', detail='Add or enable an engine; scans need at least one.')
    failing = [e for e in active if e.state in {'failed', 'unavailable', 'stale'}]
    waiting = [e for e in active if e.state in {'pending', 'running', 'unknown'}]
    if failing:
        first = failing[0]
        return HealthCheck(key='engines', label='Engines', state='critical', link=link,
                           summary=f'{len(failing)} of {len(active)} enabled engine(s) failing: {_names([e.name for e in failing])}.',
                           detail=f'{first.name}: {first.detail}')
    if waiting:
        return HealthCheck(key='engines', label='Engines', state='warning', link=link,
                           summary=f'{len(waiting)} engine(s) not yet confirmed by a worker check: {_names([e.name for e in waiting])}.',
                           detail='Use Test connection on the Engines screen to request a check.')
    return HealthCheck(key='engines', label='Engines', state='ok', link=link,
                       summary=f'{len(active)} enabled engine(s) healthy.')


def signatures_check(engines: list[EngineState], records: list, now: float) -> HealthCheck:
    link = '/engines'
    clamav = [e for e in engines if e.adapter_key == 'clamav' and e.state != 'disabled']
    if not clamav:
        return HealthCheck(key='signatures', label='ClamAV signatures', state='inactive', link=link,
                           summary='No ClamAV engine is enabled.')
    newest: tuple[datetime, str] | None = None
    for record in records:
        try:
            details = json.loads(record.details_json or '{}')
        except (TypeError, ValueError):
            continue
        if not isinstance(details, dict) or details.get('adapter_key') != 'clamav':
            continue
        probe = details.get('probe')
        if not isinstance(probe, dict):
            continue
        signed = _when(probe.get('signature_date'))
        if signed and (newest is None or signed > newest[0]):
            newest = (signed, str(probe.get('signature_version') or '?'))
    if newest is None:
        return HealthCheck(key='signatures', label='ClamAV signatures', state='unknown', link=link,
                           summary='No worker has reported the signature version yet.',
                           detail='Workers report it with their engine health check. Request a check on the Engines screen.')
    age = now - newest[0].timestamp()
    state: State = ('critical' if age >= SIGNATURE_CRITICAL_SECONDS
                    else 'warning' if age >= SIGNATURE_WARNING_SECONDS else 'ok')
    return HealthCheck(key='signatures', label='ClamAV signatures', state=state, link=link,
                       summary=f'Database {newest[1]}, published {age_text(age)} ago.',
                       detail=None if state == 'ok' else
                       'Signature updates are not arriving. Check the clamav container log and its access to the update mirror.')


def storage_check(path=STORAGE_DIR) -> HealthCheck:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return HealthCheck(key='storage', label='Sample storage', state='unknown',
                           summary='Storage usage could not be read.')
    percent = round(100 * usage.used / usage.total) if usage.total else 0
    state: State = ('critical' if percent >= DISK_CRITICAL_PERCENT
                    else 'warning' if percent >= DISK_WARNING_PERCENT else 'ok')
    return HealthCheck(key='storage', label='Sample storage', state=state, link='/system/retention',
                       summary=f'{percent}% used; {usage.free / 1024 ** 3:.1f} GiB free.',
                       detail=None if state == 'ok' else
                       'New uploads fail when the disk is full. Enable retention or add capacity.')


def intake_checks(overview: intake_read.IntakeOverview) -> list[HealthCheck]:
    link = '/system/intake'
    worker = overview.manifest_worker
    if overview.manifest_record_invalid:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='unknown', link=link,
                               summary='The manifest worker record is unreadable.')
    elif worker is None:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='inactive', link=link,
                               summary='No manifest worker has run.')
    elif worker.stale:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='critical', link=link,
                               summary=f'Last cycle {age_text(worker.age_seconds)} ago; manifests are not being read.',
                               detail='Check that the manifest-intake service is running and the share is mounted.')
    elif not worker.ok:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='warning', link=link,
                               summary='The last cycle failed.', detail=worker.error)
    elif overview.rejections_total:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='warning', link=link,
                               summary=f'{overview.rejections_total} rejected manifest(s).',
                               detail=overview.rejections[0].reason if overview.rejections else None)
    else:
        manifest = HealthCheck(key='manifest', label='Manifest intake', state='ok', link=link,
                               summary=f'Last cycle {age_text(worker.age_seconds)} ago.')

    queue = overview.queue
    waiting = queue.oldest_pending_age_seconds
    failures = len(overview.failures)
    if waiting is None and not failures and not (queue.claimed or queue.queued):
        deferred = HealthCheck(key='deferred', label='Deferred copies', state='inactive' if worker is None else 'ok',
                               link=link, summary='Nothing waiting to be copied.')
    else:
        state: State = 'ok'
        if waiting is not None and waiting >= DEFERRED_CRITICAL_SECONDS:
            state = 'critical'
        elif (waiting is not None and waiting >= DEFERRED_WARNING_SECONDS) or failures:
            state = 'warning'
        parts = [f'{queue.pending} waiting' + (f', oldest {age_text(waiting)}' if waiting is not None else '')]
        if failures:
            parts.append(f"{failures}{'+' if overview.failures_truncated else ''} failed before scanning")
        deferred = HealthCheck(key='deferred', label='Deferred copies', state=state, link=link,
                               summary='; '.join(parts) + '.',
                               detail='Failed submissions can be retried from Deferred intake.' if failures else None)
    return [manifest, deferred]


def notifications_check(connection, now: float) -> HealthCheck:
    link = '/system/delivery'
    row = connection.execute('''SELECT COUNT(*) AS pending,
        SUM(CASE WHEN attempt_count > 0 THEN 1 ELSE 0 END) AS retrying, MIN(created_at) AS oldest
        FROM notification_outbox WHERE status IN ('pending', 'delivering')''').fetchone()
    total = connection.execute('SELECT COUNT(*) AS n FROM notification_outbox').fetchone()
    if not int(total['n'] or 0):
        return HealthCheck(key='notifications', label='SIEM notifications', state='inactive', link=link,
                           summary='No notification has been produced.')
    pending, retrying = int(row['pending'] or 0), int(row['retrying'] or 0)
    if not pending:
        return HealthCheck(key='notifications', label='SIEM notifications', state='ok', link=link,
                           summary='Every notification was delivered.')
    oldest = _when(row['oldest'])
    age = now - oldest.timestamp() if oldest else 0
    state: State = 'critical' if age >= NOTIFY_CRITICAL_SECONDS else 'warning' if retrying else 'ok'
    return HealthCheck(key='notifications', label='SIEM notifications', state=state, link=link,
                       summary=f'{pending} undelivered, oldest {age_text(age)}' + (f'; {retrying} failed at least once.' if retrying else '.'),
                       detail=None if state == 'ok' else 'Check the notification service and the SIEM webhook.')


def icap_gateways(settings: dict[str, str]) -> list[dict]:
    gateways = []
    for key, value in sorted(settings.items()):
        try:
            record = json.loads(value)
            int(record['at'])
        except (TypeError, ValueError, KeyError):
            continue
        record['key'] = key.removeprefix(ICAP_SETTING_PREFIX)
        gateways.append(record)
    return gateways


def icap_check(gateways: list[dict], now: float) -> HealthCheck:
    link = '/system/delivery'
    current = [g for g in gateways if now - int(g['at']) < ICAP_FORGOTTEN_SECONDS]
    if not current:
        return HealthCheck(key='icap', label='ICAP gateway', state='inactive', link=link,
                           summary='No ICAP gateway has reported.')
    stopped = [g for g in current if now - int(g['at']) >= ICAP_STALE_SECONDS]
    if stopped:
        g = stopped[0]
        return HealthCheck(key='icap', label='ICAP gateway', state='critical', link=link,
                           summary=f"Gateway for client {g.get('client_key')} on port {g.get('port')} last reported {age_text(now - int(g['at']))} ago.",
                           detail='A stopped fail-closed gateway blocks every upload. Check the icap container.')
    recent = [e for g in current for e in g.get('events') or []
              if isinstance(e, dict) and now - int(e.get('at') or 0) < RECENT_SECONDS]
    rejected = [e for e in recent if e.get('kind') == 'rejected']
    failing = [e for e in recent if e.get('kind') in {'fail_action', 'error'}]
    if rejected or failing:
        parts = []
        if rejected:
            parts.append(f'{len(rejected)} refused connection(s)')
        if failing:
            parts.append(f'{len(failing)} fail-closed answer(s) or error(s)')
        first = (rejected or failing)[0]
        return HealthCheck(key='icap', label='ICAP gateway', state='warning', link=link,
                           summary=f"{' and '.join(parts)} in the last hour.",
                           detail=str(first.get('detail')) + (f" ({first.get('peer')})" if first.get('peer') else ''))
    requests = sum(int((g.get('counters') or {}).get('requests') or 0) for g in current)
    return HealthCheck(key='icap', label='ICAP gateway', state='ok', link=link,
                       summary=f'{len(current)} gateway(s) reporting; {requests} request(s) since start.')


def waiting_reason(status: dict[str, object], engines: list[EngineState], queued: int) -> str | None:
    """Why queued scans are not starting, in the order an operator would check."""
    if not queued:
        return None
    if not int(status.get('schedulable_count') or 0):
        return 'No worker is online and accepting work, so queued scans cannot start.'
    unplaced = [e.name for e in engines if e.state == 'unavailable']
    if unplaced:
        return (f'No active worker can run {_names(unplaced)}. Scans that need these engines wait for them; '
                'start a matching worker or change the pool placement.')
    workers = status.get('workers') if isinstance(status.get('workers'), list) else []
    busy = [w for w in workers if isinstance(w, dict) and w.get('online') and w.get('state') == 'running']
    schedulable = int(status.get('schedulable_count') or 0)
    if busy and len(busy) >= schedulable:
        return f'All {schedulable} accepting worker(s) are busy; queued scans start as capacity frees up.'
    return ('Workers are online and not all busy. If the wait keeps growing, check the worker log '
            'for claim errors.')


def report(engines: list[EngineState], *, now: float | None = None) -> HealthReport:
    current = time.time() if now is None else now
    status = get_worker_status()
    records = db.list_engine_node_health()
    overview = intake_read.overview()
    gateways = icap_gateways(db.list_settings_by_prefix(ICAP_SETTING_PREFIX))
    with db.connect() as connection:
        apply_read_budget(connection)
        queue = connection.execute('''SELECT COUNT(*) AS queued, MIN(created_at) AS oldest
            FROM scan_jobs WHERE status = 'queued' ''').fetchone()
        notifications = notifications_check(connection, current)
    queued = int(queue['queued'] or 0)
    oldest = _when(queue['oldest'])
    oldest_age = current - oldest.timestamp() if oldest else None
    reason = waiting_reason(status, engines, queued) if oldest_age and oldest_age >= QUEUE_WARNING_SECONDS else None
    checks = [
        workers_check(status),
        queue_check(queued, oldest_age, reason),
        engines_check(engines),
        signatures_check(engines, records, current),
        storage_check(),
        *intake_checks(overview),
        icap_check(gateways, current),
        notifications,
    ]
    worst = max((c.state for c in checks), key=lambda s: RANK[s])
    return HealthReport(
        overall='ok' if worst == 'inactive' else worst,
        checks=checks,
        waiting_reason=reason,
        generated_at=datetime.fromtimestamp(current, timezone.utc).isoformat(),
    )
