"""Manual browser hash lookups with bounded, secret-free result projection."""
from typing import Literal
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app.services.engine_registry import enabled_hash_engines, adapter_definition, run_hash_engine
from app.services.hash_scanning import HashEngineRun, HashEngineError, build_hash_scan_payload
from app.services.virustotal import normalize_sha256


class HashLookupBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    sha256: str = Field(min_length=64, max_length=128)


class HashEngineSummary(BaseModel):
    id: int
    name: str


class HashLookupOptions(BaseModel):
    engines: list[HashEngineSummary]


class HashProviderStats(BaseModel):
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    total: int


class HashLookupRow(HashEngineSummary):
    action: Literal['allow', 'review', 'block']
    found: bool
    # Legacy parity: a bounded, named projection of the provider result. The
    # raw payload, free-text reasons and the engine's policy configuration are
    # never returned; adapter text may carry deployment details.
    status: Literal['malicious', 'suspicious', 'undetected', 'stale', 'unknown', 'other']
    stats: HashProviderStats | None
    last_analysis_date: str | None
    permalink: str | None
    cached: bool | None
    duration_ms: int


PROVIDER_STATUSES = {'malicious', 'suspicious', 'undetected', 'stale', 'unknown'}


def _count(stats: dict, key: str) -> int:
    value = stats.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _row(run: HashEngineRun, row: dict) -> HashLookupRow:
    data = row.get('data') if isinstance(row.get('data'), dict) else {}
    stats = data.get('stats') if isinstance(data.get('stats'), dict) else None
    permalink = data.get('permalink')
    # Only an HTTPS provider link is rendered as a link; anything else is dropped.
    if not (isinstance(permalink, str) and permalink.startswith('https://') and len(permalink) <= 512):
        permalink = None
    analysed = data.get('last_analysis_date')
    cached = data.get('cached')
    return HashLookupRow(
        id=run.engine.id, name=run.engine.display_name[:512],
        action=row['decision']['action'], found=row['found'],
        status=row.get('status') if row.get('status') in PROVIDER_STATUSES else 'other',
        stats=HashProviderStats(**{key: _count(stats, key) for key in ('malicious', 'suspicious', 'undetected', 'harmless', 'total')})
        if stats is not None else None,
        last_analysis_date=analysed[:64] if isinstance(analysed, str) else None,
        permalink=permalink,
        cached=cached if isinstance(cached, bool) else None,
        duration_ms=max(0, int(row.get('duration_ms') or 0)),
    )


class HashLookupResult(BaseModel):
    sha256: str
    action: Literal['allow', 'review', 'block']
    reason: str
    results: list[HashLookupRow]


def engines():
    selected = enabled_hash_engines(source='manual')
    if len(selected) > 16:
        raise HTTPException(409, 'Browser hash lookup supports at most 16 enabled hash engines.')
    return selected


def options() -> HashLookupOptions:
    return HashLookupOptions(engines=[HashEngineSummary(id=e.id, name=e.display_name[:512]) for e in engines()])


def lookup(body: HashLookupBody) -> HashLookupResult:
    sha256 = normalize_sha256(body.sha256)
    selected = engines()
    if not selected:
        raise HTTPException(409, 'No hash-capable engine is added and enabled in MASP.')
    runs = []
    try:
        for engine in selected:
            runs.append(HashEngineRun(engine=engine, support_state=adapter_definition(engine.adapter_key).support_state,
                execution=run_hash_engine(engine, sha256)))
        payload = build_hash_scan_payload(sha256, runs)
    except HashEngineError as exc:
        headers = {'Retry-After': str(min(max(int(exc.retry_after), 1), 86400))} if exc.retry_after else None
        raise HTTPException(503, 'Hash lookup unavailable or quota exhausted. Earlier engines may have consumed quota; no complete decision is available.', headers=headers) from exc
    except Exception as exc:
        # Adapter messages and payloads may contain deployment details or secrets.
        raise HTTPException(502, 'Hash lookup failed. Earlier engines may have consumed quota; no complete decision is available.') from exc
    return HashLookupResult(sha256=sha256, action=payload['decision']['action'], reason=payload['decision']['reason'],
        results=[_row(run, row) for run, row in zip(runs, payload['results'])])
