"""Asyncio ICAP server that fronts the MASP scan pipeline.

Reads an ICAP REQMOD/RESPMOD message, scans the encapsulated file through the
same intake + engines + decision logic as the REST API, and answers allow
(``204``) or block (``200`` with a replacement HTTP response). Fail-closed:
if a definitive verdict is not reached inside the wait window, the transfer is
blocked.
"""

from __future__ import annotations

import asyncio

from app.database import init_db
from app.icap import protocol
from app.icap.config import IcapConfig, load_icap_config
from app.services.ingest import UploadTooLargeError, store_bytes
from app.services.scan_intake import (
    enqueue_scan_from_stored_sample,
    scan_is_terminal,
    wait_for_terminal_scan,
)
from app.services.scan_assessment import resolve_scan_decision

ICAP_SOURCE = "icap"
_MAX_HEAD_BYTES = 64 * 1024


class IcapBodyError(Exception):
    """The encapsulated body could not be read as a complete, well-formed unit.

    Raised instead of silently returning a truncated buffer, so a framing
    anomaly is never scanned as if it were the whole file. The caller maps it to
    the configured fail policy (block when fail-closed).
    """


class IcapBodyTooLargeError(IcapBodyError):
    """The encapsulated body exceeded the configured size cap while reading."""


def log(message: str) -> None:
    print(f"[icap] {message}", flush=True)


_READ_SUBBLOCK_BYTES = 64 * 1024


async def _read(awaitable, timeout: float | None):
    """Await a single read op with an optional idle deadline.

    The deadline bounds how long one read may block with no progress; a stall
    becomes a fail-closed body error. It is not a total-transfer deadline —
    :func:`_read_exact_idle` renews it per sub-block so a large but steadily
    flowing body is not penalized.
    """
    if timeout is None or timeout <= 0:
        return await awaitable
    try:
        return await asyncio.wait_for(awaitable, timeout)
    except asyncio.TimeoutError as exc:
        raise IcapBodyError("read timed out") from exc


async def _read_exact_idle(
    reader: asyncio.StreamReader, size: int, idle_timeout: float | None
) -> bytes:
    """Read exactly ``size`` bytes, applying ``idle_timeout`` per sub-block read.

    Progress (any bytes) resets the idle deadline, so a large chunk arriving
    steadily never times out, while a peer that goes silent mid-chunk does. EOF
    before ``size`` bytes is a truncated body.
    """
    buffer = bytearray()
    while len(buffer) < size:
        want = min(_READ_SUBBLOCK_BYTES, size - len(buffer))
        block = await _read(reader.read(want), idle_timeout)
        if not block:
            raise IcapBodyError("truncated chunk in encapsulated body")
        buffer += block
    return bytes(buffer)


async def read_chunked_body(
    reader: asyncio.StreamReader,
    *,
    max_bytes: int | None = None,
    already_read: int = 0,
    read_timeout: float | None = None,
) -> tuple[bytes, bool]:
    """Read one HTTP chunked stream. Returns (decoded bytes, is_ieof).

    The cumulative size cap is enforced *while reading* (``already_read`` carries
    bytes counted by an earlier preview read of the same body), so an oversized
    transfer is rejected before it is fully buffered. Any framing anomaly — a
    non-hex chunk size, a truncated chunk, or EOF before the terminating
    zero-chunk — raises :class:`IcapBodyError` rather than returning a partial
    body.
    """
    out = bytearray()
    is_ieof = False
    while True:
        size_line = await _read(reader.readline(), read_timeout)
        if not size_line:
            raise IcapBodyError("connection closed before the chunked body ended")
        if not size_line.endswith(b"\r\n"):
            raise IcapBodyError(f"chunk size line not terminated by CRLF: {size_line!r}")
        head, _, ext = size_line.strip().partition(b";")
        if b"ieof" in ext:
            is_ieof = True
        try:
            chunk_size = int(head or b"0", 16)
        except ValueError as exc:
            raise IcapBodyError(f"invalid chunk size: {size_line!r}") from exc
        if chunk_size < 0:
            raise IcapBodyError(f"negative chunk size: {size_line!r}")
        if chunk_size == 0:
            # Terminating chunk: the stream must close with exactly a blank CRLF.
            # A missing final CRLF (EOF) or an unexpected chunk trailer is
            # malformed and fails closed.
            terminator = await _read(reader.readline(), read_timeout)
            if terminator != b"\r\n":
                raise IcapBodyError(f"chunked body not closed by a blank line: {terminator!r}")
            break
        if max_bytes is not None and already_read + len(out) + chunk_size > max_bytes:
            raise IcapBodyTooLargeError(
                f"chunked body exceeds {max_bytes} bytes"
            )
        chunk = await _read_exact_idle(reader, chunk_size, read_timeout)
        try:
            trailer = await _read(reader.readexactly(2), read_timeout)
        except asyncio.IncompleteReadError as exc:
            raise IcapBodyError("truncated chunk in encapsulated body") from exc
        if trailer != b"\r\n":
            raise IcapBodyError(f"chunk not terminated by CRLF: {trailer!r}")
        out += chunk
    return bytes(out), is_ieof


async def read_encapsulated_body(
    head: protocol.IcapHead,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    max_bytes: int | None = None,
    read_timeout: float | None = None,
) -> tuple[bytes, bytes]:
    """Read the encapsulated HTTP header block + body, honoring Preview.

    Returns ``(http_header_bytes, body_bytes)``. The header block is kept (not
    discarded) so an allow can be answered by echoing the original message back
    when the client did not offer ``Allow: 204``.
    """
    # RFC 3507 requires REQMOD/RESPMOD to carry an Encapsulated header that ends
    # in a body or null-body section. A missing or malformed one must fail closed
    # — without this, an absent/garbled header parses to "no body" and the
    # request is allowed through completely unscanned.
    raw_encapsulated = head.headers.get("encapsulated")
    if raw_encapsulated is None or not protocol.encapsulated_well_formed(
        raw_encapsulated, head.method
    ):
        raise IcapBodyError(
            f"missing or malformed Encapsulated header: {raw_encapsulated!r}"
        )

    hdr_len = protocol.header_block_length(head.encapsulated)
    if hdr_len > _MAX_HEAD_BYTES:
        raise IcapBodyError(
            f"encapsulated header block of {hdr_len} bytes exceeds "
            f"{_MAX_HEAD_BYTES}"
        )
    http_header = b""
    if hdr_len:
        try:
            http_header = await _read(reader.readexactly(hdr_len), read_timeout)
        except asyncio.IncompleteReadError as exc:
            raise IcapBodyError("truncated encapsulated header block") from exc

    if protocol.body_section(head.encapsulated) is None:
        return http_header, b""  # null-body: nothing to scan

    body, is_ieof = await read_chunked_body(
        reader, max_bytes=max_bytes, read_timeout=read_timeout
    )
    has_preview = "preview" in head.headers
    if has_preview and not is_ieof:
        # The client sent only a preview; ask for the rest, then append it. The
        # size cap carries the preview bytes already read so the combined body
        # is bounded.
        writer.write(protocol.build_continue())
        await writer.drain()
        rest, _ = await read_chunked_body(
            reader,
            max_bytes=max_bytes,
            already_read=len(body),
            read_timeout=read_timeout,
        )
        body += rest
    return http_header, body


def client_accepts_204(head: protocol.IcapHead) -> bool:
    """RFC 3507 4.6: a 204 is only legal when the client offered ``Allow: 204``
    or sent a preview (a preview may always be answered with 204)."""
    allow_values = {value.strip() for value in head.header("allow").split(",")}
    if "204" in allow_values:
        return True
    return "preview" in head.headers


def resolve_icap_action(scan, config: IcapConfig) -> str:
    """Map a (possibly unfinished) scan to 'allow' or 'block'."""
    if scan is None or not scan_is_terminal(scan):
        return "block" if config.fail_closed else "allow"
    if config.block_archives and scan.batch_id is not None:
        # Archive/container uploads are not independently member-scanned on the
        # ICAP path (children are only extracted lazily on parent detection, and
        # there is no batch-level verdict here), so they are rejected outright —
        # matching the REST vendor archive policy. Lifting this requires an eager
        # recursive member scan with a batch verdict.
        log("archive upload rejected (block_archives)")
        return "block"
    decision = resolve_scan_decision(scan)
    if decision.action == "block":
        return "block"
    if decision.action == "review" and config.block_on_review:
        return "block"
    return "allow"


async def scan_and_decide(
    filename: str,
    content_type: str,
    data: bytes,
    config: IcapConfig,
) -> str:
    """Store, scan, wait, and return 'allow' or 'block'. Never raises."""
    if not data:
        return "allow"  # nothing to scan
    try:
        stored_sample = store_bytes(
            filename, content_type, data, max_size_bytes=config.max_bytes
        )
    except UploadTooLargeError:
        log(f"{filename}: over size cap -> {'block' if config.fail_closed else 'allow'}")
        return "block" if config.fail_closed else "allow"

    try:
        scan = enqueue_scan_from_stored_sample(
            stored_sample,
            case_name="ICAP",
            priority="Normal",
            note="Submitted via ICAP gateway.",
            source=ICAP_SOURCE,
        )
        scan = await wait_for_terminal_scan(scan.id, config.wait_seconds)
        action = resolve_icap_action(scan, config)
        log(f"{filename} (scan {stored_sample.sha256[:12]}): {action}")
        return action
    except Exception as exc:  # noqa: BLE001 - fail-closed on any orchestration error
        log(f"{filename}: scan error {exc!r} -> {'block' if config.fail_closed else 'allow'}")
        return "block" if config.fail_closed else "allow"


async def respond_fail_action(
    writer: asyncio.StreamWriter,
    head: protocol.IcapHead,
    config: IcapConfig,
    reason: str,
) -> None:
    """Answer a request that could not be scanned, per the configured fail mode.

    Used when the body cannot be read as a complete unit. A non-204 allow cannot
    be expressed (the original body was never fully/validly read, so it cannot be
    echoed), so block is the safe fallback there.
    """
    action = "block" if config.fail_closed else "allow"
    log(f"{reason} -> {action}")
    if action == "allow" and client_accepts_204(head):
        writer.write(protocol.build_no_content())
    else:
        writer.write(protocol.build_block_response())
    await writer.drain()


async def _acquire_scan_slot(
    semaphore: asyncio.Semaphore, timeout: float | None
) -> bool:
    """Acquire a scan slot within ``timeout``. Returns False on timeout."""
    if timeout is None or timeout <= 0:
        await semaphore.acquire()
        return True
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout)
        return True
    except asyncio.TimeoutError:
        return False


async def handle_modification(
    head: protocol.IcapHead,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: IcapConfig,
) -> bool:
    """Handle one REQMOD/RESPMOD. Returns whether the connection may be reused.

    A body framing error leaves the stream desynchronized, so the connection is
    closed (returns False) after answering; a normal request keeps it alive.
    """
    body_reader = read_encapsulated_body(
        head,
        reader,
        writer,
        max_bytes=config.max_bytes,
        read_timeout=config.read_timeout_seconds,
    )
    try:
        # A total body deadline bounds slow-drip clients that keep resetting the
        # per-read idle timeout (e.g. one byte just under the idle window), which
        # would otherwise hold a scan slot indefinitely.
        if config.body_timeout_seconds and config.body_timeout_seconds > 0:
            http_header, data = await asyncio.wait_for(
                body_reader, config.body_timeout_seconds
            )
        else:
            http_header, data = await body_reader
    except asyncio.TimeoutError:
        await respond_fail_action(writer, head, config, "total body deadline exceeded")
        return False
    except IcapBodyTooLargeError:
        await respond_fail_action(writer, head, config, "body over size cap")
        return False
    except (IcapBodyError, asyncio.IncompleteReadError) as exc:
        await respond_fail_action(writer, head, config, f"unreadable body: {exc!r}")
        return False

    filename = f"icap_{head.method.lower()}.bin"
    action = await scan_and_decide(filename, "application/octet-stream", data, config)

    if action == "allow":
        if client_accepts_204(head):
            writer.write(protocol.build_no_content())
        else:
            # Client did not offer Allow: 204 — echo the original message back.
            writer.write(
                protocol.build_unmodified_response(head.encapsulated, http_header, data)
            )
    else:
        writer.write(protocol.build_block_response())
    await writer.drain()
    return True


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: IcapConfig,
    scan_slots: asyncio.Semaphore | None = None,
) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if isinstance(peer, tuple) else None
    if config.allowed_ips and peer_ip not in config.allowed_ips:
        log(f"rejected connection from {peer_ip} (not in allowlist)")
        writer.close()
        return

    read_timeout = config.read_timeout_seconds
    try:
        while True:
            try:
                raw_head = await _read(reader.readuntil(b"\r\n\r\n"), read_timeout)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                break
            except IcapBodyError:
                # Idle read timeout on the request line: drop a stalled peer.
                break

            try:
                head = protocol.parse_head(raw_head)
            except protocol.IcapProtocolError as exc:
                log(f"bad request from {peer_ip}: {exc}")
                writer.write(protocol.build_bad_request())
                await writer.drain()
                break

            if head.method == "OPTIONS":
                writer.write(
                    protocol.build_options_response(
                        preview_bytes=config.preview_bytes,
                        max_connections=config.max_connections,
                    )
                )
                await writer.drain()
                continue

            if head.method in {"REQMOD", "RESPMOD"}:
                # Admission control: bound concurrent in-flight scans (the
                # expensive part). Beyond the limit a request waits only up to the
                # admission timeout; if no slot frees it fails closed rather than
                # queueing unboundedly. The body is still unread at that point, so
                # the desynchronized connection is closed.
                if scan_slots is None:
                    keep_alive = await handle_modification(head, reader, writer, config)
                elif not await _acquire_scan_slot(scan_slots, config.admission_timeout_seconds):
                    await respond_fail_action(
                        writer, head, config, "admission timeout (no scan slot)"
                    )
                    break
                else:
                    try:
                        keep_alive = await handle_modification(head, reader, writer, config)
                    finally:
                        scan_slots.release()
                if not keep_alive:
                    break
                continue

            # Unsupported method: refuse cleanly.
            writer.write(protocol.build_method_not_allowed())
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def serve(config: IcapConfig | None = None) -> None:
    config = config or load_icap_config()
    init_db()

    scan_slots = asyncio.Semaphore(config.max_connections)

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handle_connection(reader, writer, config, scan_slots)

    server = await asyncio.start_server(_client, config.host, config.port)
    log(
        f"MASP ICAP gateway listening on {config.host}:{config.port} "
        f"(service '{config.service_name}', wait {config.wait_seconds}s, "
        f"fail-{'closed' if config.fail_closed else 'open'})"
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        log("shutting down")


if __name__ == "__main__":
    main()
