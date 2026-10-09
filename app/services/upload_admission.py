"""Authenticate and bound upload bodies before FastAPI parses multipart data."""

import os

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartException

from app.services.auth import require_admin, require_api_token, require_user
from app.services.ingest import configured_upload_max_bytes


DEFAULT_HTTP_UPLOAD_MAX_BYTES = 64 * 1024 * 1024
MULTIPART_OVERHEAD_BYTES = 1024 * 1024
UPLOAD_PATHS = {"/scans", "/api/v1/scans", "/engines/yara/rules"}


UPLOAD_POLICY_SOURCE = "upload size policy"
DEPLOYMENT_CEILING_SOURCE = "deployment HTTP body ceiling (MASP_HTTP_UPLOAD_MAX_BYTES)"


def deployment_http_ceiling_bytes() -> int:
    """The raw deployment ceiling, for display. Lenient: a bad value reads as
    the built-in default here, so an admin read never 503s; enforcement still
    goes through ``upload_body_limit``, which does fail closed on a bad value."""
    try:
        return int(os.getenv("MASP_HTTP_UPLOAD_MAX_BYTES", str(DEFAULT_HTTP_UPLOAD_MAX_BYTES)))
    except ValueError:
        return DEFAULT_HTTP_UPLOAD_MAX_BYTES


def upload_body_limit_with_source() -> tuple[int, str]:
    """The byte ceiling an upload request must stay under, and which layer set it.

    The deployment ceiling is a backstop independent of the upload policy: a
    policy of 0 (no file-size limit) never raises it, so this can still bind
    even when an administrator removed the policy's own limit.
    """
    try:
        ceiling = int(os.getenv("MASP_HTTP_UPLOAD_MAX_BYTES", str(DEFAULT_HTTP_UPLOAD_MAX_BYTES)))
    except ValueError as exc:
        raise HTTPException(503, "Invalid HTTP upload byte limit.") from exc
    if ceiling <= 0:
        raise HTTPException(503, "HTTP upload byte limit must be positive.")
    file_limit = configured_upload_max_bytes()
    if file_limit and file_limit + MULTIPART_OVERHEAD_BYTES < ceiling:
        return file_limit + MULTIPART_OVERHEAD_BYTES, UPLOAD_POLICY_SOURCE
    return ceiling, DEPLOYMENT_CEILING_SOURCE


def upload_body_limit() -> int:
    return upload_body_limit_with_source()[0]


async def bounded_upload(request: Request, handler):
    """Call only AFTER authentication/CSRF; share byte admission across both UIs."""
    limit, source = await run_in_threadpool(upload_body_limit_with_source)
    detail = f"Upload body exceeds the {source} of {limit:,} bytes."
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length.") from exc
        if length < 0:
            raise HTTPException(400, "Invalid Content-Length.")
        if length > limit:
            raise HTTPException(413, detail)
    receive = request.receive
    received = 0
    exceeded = False

    async def bounded_receive():
        nonlocal received, exceeded
        message = await receive()
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > limit:
                exceeded = True
                # Let the multipart parser close its partial temp files.
                raise MultiPartException(detail)
        return message

    request._receive = bounded_receive
    try:
        return await handler(request)
    except Exception as exc:
        if exceeded:
            raise HTTPException(413, detail) from exc
        raise
    finally:
        request._receive = receive


class UploadAdmissionRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        if self.path not in UPLOAD_PATHS or "POST" not in (self.methods or set()):
            return handler

        async def admitted(request: Request):
            authenticate = (
                require_api_token if self.path == "/api/v1/scans"
                else require_admin if self.path == "/engines/yara/rules"
                else require_user
            )
            await run_in_threadpool(authenticate, request)
            return await bounded_upload(request, handler)

        return admitted
