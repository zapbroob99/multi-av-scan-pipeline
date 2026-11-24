"""Operator-facing scope and provenance, without deployment secrets or probes."""
import os
from typing import Literal

from pydantic import BaseModel

from app.services import scan_policy


class ConfigurationContext(BaseModel):
    source: str
    scope: str
    applies: str
    edit_at: str
    restart: str
    state: Literal['resolved', 'defaulted', 'clamped', 'invalid', 'unknown'] = 'resolved'
    note: str = ''


_POLICY_SCOPE = {
    'upload_max_bytes': ('API and console file uploads', 'New upload requests; accepted scans are unchanged.'),
    'api_max_wait_seconds': ('REST API upload responses', 'New requests; does not change worker execution timeouts.'),
    'api_retry_after_seconds': ('REST API polling guidance', 'Subsequent responses; does not set the scan execution interval.'),
    'siem_not_allowed_events': ('Creation of policy-not-allowed events',
        'When a new event is considered; existing outbox events are not removed or replayed.'),
}


def policy_context(key: str, override: str | None) -> ConfigurationContext:
    spec = scan_policy.spec_for(key)
    override = (override or '').strip()
    environment = scan_policy.env_value(key)
    raw = override or environment
    source = 'Console override' if override else f'API process environment ({spec.env_var})' if environment else 'Built-in default'
    state = 'resolved'
    note = ''
    if key == 'siem_not_allowed_events' and raw not in ('', '0', '1'):
        state, note = 'defaulted', 'Only 1 enables event creation. This configured value leaves it off.'
    elif raw:
        try:
            value = int(raw)
        except ValueError:
            state, note = 'defaulted', 'Configured value is not an integer. Runtime uses the built-in default.'
        else:
            if not spec.minimum <= value <= spec.maximum:
                state, note = 'clamped', 'Configured value is outside the supported range. Runtime uses the nearest supported bound.'
    scope, applies = _POLICY_SCOPE[key]
    if key == 'siem_not_allowed_events':
        note += (' ' if note else '') + 'Environment fallback shown here belongs to the API process. Workers may have different environment values.'
    return ConfigurationContext(source=source, scope=scope, applies=applies,
        edit_at=('Administration > Notifications' if key == 'siem_not_allowed_events' else 'Administration > Limits & API behavior') + '; blank removes the console override.',
        restart='Console saves: no restart. Environment changes: recreate/restart affected services.', state=state, note=note)


def http_context(valid: bool) -> ConfigurationContext:
    return ConfigurationContext(source='API process environment (MASP_HTTP_UPLOAD_MAX_BYTES)' if 'MASP_HTTP_UPLOAD_MAX_BYTES' in os.environ else 'Built-in HTTP body ceiling default',
        scope='Entire HTTP upload request, including multipart overhead; external proxy limits are not observed.',
        applies='New HTTP upload requests; a file policy of 0 does not remove this ceiling.',
        edit_at='API deployment configuration.', restart='Recreate/restart affected API services.',
        state='resolved' if valid else 'invalid', note='' if valid else 'Uploads are refused until deployment configuration is corrected.')


PROFILE_CONTEXT = ConfigurationContext(source='Saved client profile in the database',
    scope='This profile; ICAP uses the client default. Archive members match rules individually.',
    applies='Newly accepted routing. Accepted scans and retries keep their recorded routing snapshots.',
    edit_at='Policies > Scan profiles > connected system.', restart='No restart.')

PLACEMENT_CONTEXT = ConfigurationContext(source='Engine instances and worker pool bindings in the database',
    scope='Every profile using these engine instances.',
    applies='Future job claims use current placement and worker lifecycle. Running work remains subject to its lease.',
    edit_at='Scan infrastructure > Engines, Worker groups and Workers.', restart='No restart for placement or lifecycle changes.',
    note='Recorded worker checks are historical evidence, not proof of current capacity or eligibility.')
