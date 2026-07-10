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


def log(message: str) -> None:
    print(f"[icap] {message}", flush=True)


async def read_chunked_body(reader: asyncio.StreamReader) -> tuple[bytes, bool]:
    """Read one HTTP chunked stream. Returns (decoded bytes, is_ieof)."""
    out = bytearray()
    is_ieof = False
    while True:
        size_line = await reader.readline()
        if not size_line:
            break
        head, _, ext = size_line.strip().partition(b";")
        if b"ieof" in ext:
            is_ieof = True
        try:
            chunk_size = int(head or b"0", 16)
        except ValueError:
            break
        if chunk_size == 0:
            # Consume the trailing CRLF that closes the chunked stream.
            await reader.readline()
            break
        chunk = await reader.readexactly(chunk_size)
        out += chunk
        await reader.readexactly(2)  # trailing CRLF after the chunk data
    return bytes(out), is_ieof


async def read_encapsulated_body(
    head: protocol.IcapHead,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> tuple[bytes, bytes]:
    """Read the encapsulated HTTP header block + body, honoring Preview.

    Returns ``(http_header_bytes, body_bytes)``. The header block is kept (not
    discarded) so an allow can be answered by echoing the original message back
    when the client did not offer ``Allow: 204``.
    """
    hdr_len = protocol.header_block_length(head.encapsulated)
    http_header = b""
    if hdr_len:
        http_header = await reader.readexactly(hdr_len)  # wrapped HTTP headers

    if protocol.body_section(head.encapsulated) is None:
        return http_header, b""  # null-body: nothing to scan

    body, is_ieof = await read_chunked_body(reader)
    has_preview = "preview" in head.headers
    if has_preview and not is_ieof:
        # The client sent only a preview; ask for the rest, then append it.
        writer.write(protocol.build_continue())
        await writer.drain()
        rest, _ = await read_chunked_body(reader)
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


async def handle_modification(
    head: protocol.IcapHead,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: IcapConfig,
) -> None:
    http_header, data = await read_encapsulated_body(head, reader, writer)
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


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: IcapConfig,
) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if isinstance(peer, tuple) else None
    if config.allowed_ips and peer_ip not in config.allowed_ips:
        log(f"rejected connection from {peer_ip} (not in allowlist)")
        writer.close()
        return

    try:
        while True:
            try:
                raw_head = await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                break
            except asyncio.LimitOverrunError:
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
                    protocol.build_options_response(preview_bytes=config.preview_bytes)
                )
                await writer.drain()
                continue

            if head.method in {"REQMOD", "RESPMOD"}:
                await handle_modification(head, reader, writer, config)
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

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handle_connection(reader, writer, config)

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
