from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import Request

from app.database import create_audit_event
from app.models import UserRecord
from app.services.auth import bearer_token_from_request


MAX_DETAIL_DEPTH = 4
MAX_DETAIL_ITEMS = 40
MAX_DETAIL_STRING = 500
MAX_DETAILS_JSON = 8_000
SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "raw_output",
    "content",
    "file_data",
)


def request_id_for(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "").strip()
    if supplied and SAFE_REQUEST_ID.fullmatch(supplied):
        return supplied
    return uuid.uuid4().hex


def token_fingerprint(token: str) -> str:
    return f"sha256:{hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]}"


def sanitize_details(value: Any, *, _depth: int = 0) -> Any:
    """Produce bounded JSON-safe audit metadata with secrets redacted."""
    if _depth >= MAX_DETAIL_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_DETAIL_STRING else value[:MAX_DETAIL_STRING] + "…"
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_DETAIL_ITEMS:
                sanitized["_truncated"] = True
                break
            safe_key = str(key)[:100]
            normalized_key = safe_key.lower().replace("-", "_")
            if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
                sanitized[safe_key] = "[redacted]"
            else:
                sanitized[safe_key] = sanitize_details(item, _depth=_depth + 1)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = list(value[:MAX_DETAIL_ITEMS])
        sanitized_items = [sanitize_details(item, _depth=_depth + 1) for item in items]
        if len(value) > MAX_DETAIL_ITEMS:
            sanitized_items.append("[truncated]")
        return sanitized_items
    return sanitize_details(str(value), _depth=_depth + 1)


def details_json(details: Mapping[str, Any] | None) -> str:
    encoded = json.dumps(
        sanitize_details(dict(details or {})),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(encoded) <= MAX_DETAILS_JSON:
        return encoded
    return json.dumps(
        {
            "_truncated": True,
            "original_length": len(encoded),
            "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def set_audit_context(
    request: Request,
    *,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: Mapping[str, Any] | None = None,
    actor: UserRecord | None = None,
    outcome: str | None = None,
) -> None:
    state = getattr(request, "state", None)
    if state is None:
        # Route functions are also exercised directly in unit tests and may be
        # called with a lightweight sentinel instead of a Starlette Request.
        return
    context = dict(getattr(state, "audit_context", {}) or {})
    if action is not None:
        context["action"] = action
    if target_type is not None:
        context["target_type"] = target_type
    if target_id is not None:
        context["target_id"] = str(target_id)
    if details:
        context["details"] = {**context.get("details", {}), **dict(details)}
    if actor is not None:
        context["actor"] = actor
    if outcome in {"success", "failure", "denied"}:
        context["outcome"] = outcome
    state.audit_context = context


def actor_for_request(request: Request, session_user: UserRecord | None) -> dict[str, str | None]:
    override = (getattr(request.state, "audit_context", {}) or {}).get("actor")
    user = override if isinstance(override, UserRecord) else session_user
    if user is not None:
        return {
            "actor_type": "user",
            "actor_id": str(user.id),
            "actor_name": user.username,
        }
    bearer_token = bearer_token_from_request(request)
    if bearer_token:
        fingerprint = token_fingerprint(bearer_token)
        return {
            "actor_type": "api_token",
            "actor_id": fingerprint,
            "actor_name": fingerprint,
        }
    return {"actor_type": "anonymous", "actor_id": None, "actor_name": None}


def append_http_audit_event(
    request: Request,
    *,
    status_code: int,
    session_user: UserRecord | None,
    error_type: str | None = None,
) -> int:
    context = dict(getattr(request.state, "audit_context", {}) or {})
    route = request.scope.get("route")
    route_path = getattr(route, "path", None) or request.url.path
    endpoint = request.scope.get("endpoint")
    endpoint_name = getattr(endpoint, "__name__", None)
    action = str(context.get("action") or endpoint_name or f"http.{request.method.lower()}")
    path_parts = [part for part in route_path.strip("/").split("/") if part]
    target_type = str(context.get("target_type") or (path_parts[0] if path_parts else "http_route"))
    path_params = dict(request.path_params)
    inferred_target_id = ",".join(str(value) for value in path_params.values()) or None
    default_outcome = (
        "denied" if status_code in {401, 403} else "failure" if status_code >= 400 else "success"
    )
    outcome = str(context.get("outcome") or default_outcome)
    base_details: dict[str, Any] = {
        "method": request.method,
        "route": route_path,
        "status_code": status_code,
    }
    if request.query_params:
        # Names are useful for investigations; values may contain submitted
        # hashes, filenames, or other case data and are intentionally omitted.
        base_details["query_keys"] = sorted(set(request.query_params.keys()))
    if path_params:
        base_details["path_params"] = path_params
    if error_type:
        base_details["error_type"] = error_type
    base_details.update(context.get("details", {}))
    actor = actor_for_request(request, session_user)
    source_ip = request.client.host if request.client is not None else None
    return create_audit_event(
        actor_type=str(actor["actor_type"]),
        actor_id=actor["actor_id"],
        actor_name=actor["actor_name"],
        action=action,
        target_type=target_type,
        target_id=(
            str(context["target_id"])
            if context.get("target_id") is not None
            else inferred_target_id
        ),
        outcome=outcome,
        source_ip=source_ip,
        request_id=str(request.state.audit_request_id),
        details_json=details_json(base_details),
    )


def should_audit_request(request: Request) -> bool:
    """Keep the ledger focused on security and administrative changes.

    This is intentionally not an access log. Normal navigation, scan/hash
    submission, API polling, report reads, and health/metrics scrapes belong in
    proxy/application access logs and must not grow the institutional audit
    table.
    """
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False

    path = request.url.path.rstrip("/") or "/"
    if path in {"/login", "/logout", "/account/password", "/scan-policy"}:
        return True
    if path.startswith("/users"):
        return True
    if path.startswith("/engines"):
        return not path.endswith("/test")
    if path.startswith("/workers"):
        return True
    if path == "/api/v1/worker-control/enroll":
        return True
    if path == "/system/retention/run":
        return True
    return path.endswith("/delete") and (
        path.startswith("/scans/") or path.startswith("/api-ledger/scans/")
    )
