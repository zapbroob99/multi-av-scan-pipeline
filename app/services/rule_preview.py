"""Saved-profile metadata preview. No samples, providers, queues or decisions."""
import hashlib
import json
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services import client_configuration
from app.services.content_types import TYPE_FAMILIES, classify_detected_type
from app.services.profile_rules import Action, ArchiveTreatment, MAX_SAFE_INTEGER, match


class RulePreviewBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    profile_id: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    expected_revision: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    source: Literal['api', 'icap']
    size_bytes: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    extension: str = Field(default='', max_length=16, pattern=r'^[a-z0-9]*$')
    # null = unknown header; unrecognized = inspection found no known signature.
    header_type: str | None = Field(default=None, max_length=32)

    @field_validator('header_type')
    @classmethod
    def known_type(cls, value):
        if value is not None and value != 'unrecognized' and value not in TYPE_FAMILIES:
            raise ValueError('Unknown header content type.')
        return value


class PreviewMatch(BaseModel):
    number: int
    action: Action
    engine_ids: list[int]
    archive: ArchiveTreatment | None


class PreviewLimit(BaseModel):
    label: str
    state: Literal['blocked', 'exceeds_limit', 'within_limit', 'unknown']
    explanation: str
    limit_bytes: int | None = None


class PreviewEngine(BaseModel):
    id: int
    name: str


class RulePreview(BaseModel):
    profile_id: int
    profile_revision: int
    observed_at: int
    configuration_fingerprint: str
    status: Literal['matched', 'ambiguous']
    matches: list[PreviewMatch]
    engines: list[PreviewEngine]
    limits: list[PreviewLimit]
    warnings: list[str]


def preview(client_id: int, body: RulePreviewBody) -> RulePreview:
    data = client_configuration.read(client_id, body.profile_id)
    profile = data.profile
    if data.managed or profile is None or profile.incomplete or profile.rules is None or profile.rules_invalid:
        raise HTTPException(409, 'Complete saved profile rules are required for a preview. Refresh and inspect the profile.')
    if profile.management_revision != body.expected_revision:
        raise HTTPException(409, 'Profile changed. Refresh the overview before previewing again.')
    if body.source == 'icap' and not profile.is_default:
        raise HTTPException(409, 'ICAP uses the current default profile. Refresh the overview.')

    # Enumerate the finite set of actual header classifications when unknown.
    # The real matcher handles ordering, size boundaries and extension families.
    # Missing knowledge never becomes a guessed PDF/clean/unrecognized header.
    types = [None, *TYPE_FAMILIES] if body.header_type is None else [None if body.header_type == 'unrecognized' else body.header_type]
    candidates = {}
    for header in types:
        classification = classify_detected_type(header, 'preview.' + body.extension if body.extension else 'preview')
        number, rule = match(profile.rules, size=body.size_bytes, classification=classification)
        candidates[number] = PreviewMatch(number=number, action=rule.action, engine_ids=rule.engines, archive=rule.archive)
    limits = []
    warnings = [
        'This is a preview of saved rules for the supplied metadata, not a scan or an allow decision.',
        'File exceptions, hash lists, archive contents, engine limits, worker capacity and external proxy limits are not evaluated.',
        'A real submission rechecks current configuration and inspects its own header; this preview does not reserve routing.',
    ]
    if not data.enabled or not profile.enabled:
        limits.append(PreviewLimit(label='Routing', state='blocked', explanation='Client or profile is disabled; new routing is unavailable. ICAP transport failures still follow its gateway fail mode.'))
    if body.source == 'api':
        limits.append(PreviewLimit(label='File size policy', state='exceeds_limit' if data.upload_policy_bytes and body.size_bytes > data.upload_policy_bytes else 'within_limit',
            limit_bytes=data.upload_policy_bytes, explanation='This file policy is separate from the HTTP request ceiling.'))
        ceiling = data.http_body_ceiling_bytes
        limits.append(PreviewLimit(label='HTTP request body',
            limit_bytes=ceiling,
            state='blocked' if not data.http_configuration_valid else 'exceeds_limit' if ceiling is not None and body.size_bytes >= ceiling else 'unknown',
            explanation='Invalid deployment ceiling: uploads are refused.' if not data.http_configuration_valid else
                'Includes multipart overhead. File size alone cannot prove the request fits.'))
    else:
        if not data.gateways:
            limits.append(PreviewLimit(label='ICAP gateway', state='unknown', explanation='No gateway report for this client. Transport limits and failure behavior are unknown.'))
        for gateway in data.gateways:
            state = 'unknown' if gateway.stale or gateway.max_bytes is None else 'exceeds_limit' if gateway.max_bytes and body.size_bytes > gateway.max_bytes else 'within_limit'
            fail = 'unknown' if gateway.fail_closed is None else 'block' if gateway.fail_closed else 'allow without scanning'
            limits.append(PreviewLimit(label=f'ICAP port {gateway.port}', state=state,
                limit_bytes=gateway.max_bytes, explanation=f'Last reported failure behavior: {fail}. ' +
                ('Report stale; current limit is unknown.' if gateway.stale else 'Reported settings do not prove current gateway reachability.')))
        if data.gateways_incomplete:
            warnings.append('Gateway inventory is incomplete; additional transport limits may exist.')
    selected = {engine for candidate in candidates.values() for engine in candidate.engine_ids}
    for engine in data.engines:
        if engine.id in selected:
            if not engine.eligible:
                warnings.append(f'{engine.name}: {engine.excluded_reason}')
            if engine.pool_id is not None and not engine.pool_enabled:
                warnings.append(f'{engine.name}: assigned worker pool is disabled or unavailable.')
    if len(candidates) > 1:
        warnings.append('Header content type is unknown. More than one first matching rule is possible; select the observed header type to resolve this.')
    basis = dict(client_id=client_id, enabled=data.enabled, profile=profile.model_dump(mode='json'), source=body.source,
        engines=[engine.model_dump(exclude={'observations', 'observations_incomplete'}) for engine in data.engines],
        upload_policy_bytes=data.upload_policy_bytes, http_body_ceiling_bytes=data.http_body_ceiling_bytes,
        http_configuration_valid=data.http_configuration_valid, gateways=[gateway.model_dump() for gateway in data.gateways],
        gateways_incomplete=data.gateways_incomplete)
    fingerprint = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return RulePreview(profile_id=profile.id, profile_revision=profile.management_revision, observed_at=data.observed_at,
        configuration_fingerprint=fingerprint, status='matched' if len(candidates) == 1 else 'ambiguous',
        matches=[candidates[number] for number in sorted(candidates)],
        engines=[PreviewEngine(id=engine.id, name=engine.name) for engine in data.engines if engine.id in selected],
        limits=limits, warnings=warnings)
