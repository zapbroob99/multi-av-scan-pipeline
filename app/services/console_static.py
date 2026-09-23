"""Serve the built browser console from the application itself.

Production and pilot deployments run a single application image on port 8000,
so the console ships inside it rather than behind a separate web server. The
headers match the optional nginx overlay (frontend/nginx.conf.template): a
strict same-origin CSP, no framing and no caching of anything but fingerprinted
assets. The Vite dev server still serves /console itself during development.
"""
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse, Response

DEFAULT_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
PREFIX = "/console"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
       "form-action 'self'")
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"}

router = APIRouter(include_in_schema=False)


def dist_root() -> Path:
    configured = os.getenv("MASP_CONSOLE_DIST", "").strip()
    return (Path(configured) if configured else DEFAULT_DIST).resolve()


def _contained(root: Path, relative: str) -> Path | None:
    """Resolve a request path inside the build output, or None."""
    if not relative or any(part.startswith(".") for part in relative.split("/")):
        return None
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        return None
    return candidate if candidate.is_file() else None


def _index(root: Path) -> Response:
    index = root / "index.html"
    if not index.is_file():
        # Development runs the Vite server instead; an image always has a build.
        return Response("The browser console has not been built. Run `npm --prefix frontend run build`.",
                        status_code=503, media_type="text/plain; charset=utf-8",
                        headers={"Cache-Control": "no-store", **SECURITY_HEADERS})
    return FileResponse(index, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store", "Content-Security-Policy": CSP, **SECURITY_HEADERS})


@router.get(PREFIX)
def console_root() -> RedirectResponse:
    return RedirectResponse(PREFIX + "/", status_code=302)


@router.get(PREFIX + "/assets/{path:path}")
def console_asset(path: str) -> FileResponse:
    root = dist_root()
    asset = _contained(root / "assets", path) if (root / "assets").is_dir() else None
    if asset is None:
        # Never fall back to index.html for an asset: a stale hash must fail loudly.
        raise HTTPException(404)
    return FileResponse(asset, headers={"Cache-Control": "public, max-age=31536000, immutable", **SECURITY_HEADERS})


@router.get(PREFIX + "/{path:path}")
def console_page(path: str) -> Response:
    root = dist_root()
    file = _contained(root, path)
    if file is not None and file.name != "index.html":
        return FileResponse(file, headers={"Cache-Control": "no-store", "Content-Security-Policy": CSP,
                                           **SECURITY_HEADERS})
    # Client-side routes such as /console/scans/42 all load the single page.
    return _index(root)
