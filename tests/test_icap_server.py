import asyncio
import unittest
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

from app.icap import protocol, server
from app.icap.config import IcapConfig
from app.models import StoredSample
from app.services.decisions import ScanDecision


@dataclass
class FakeScan:
    id: int = 1
    status: str = "completed"


class FakeWriter:
    def __init__(self, peer=("127.0.0.1", 5555)) -> None:
        self.buffer = bytearray()
        self._peer = peer
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, name: str):
        if name == "peername":
            return self._peer
        return None


async def _make_reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def reqmod_message(body: bytes, *, preview: int | None = None, ieof: bool = False) -> bytes:
    http_hdr = (
        b"PUT /upload HTTP/1.1\r\nHost: x\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
    )
    encapsulated = b"req-hdr=0, req-body=" + str(len(http_hdr)).encode()
    lines = [b"REQMOD icap://s/masp ICAP/1.0", b"Host: s", b"Allow: 204"]
    if preview is not None:
        lines.append(b"Preview: " + str(preview).encode())
    lines.append(b"Encapsulated: " + encapsulated)
    head = b"\r\n".join(lines) + b"\r\n\r\n"

    if preview is not None and not ieof:
        # Empty preview, remainder delivered after 100 Continue.
        body_bytes = b"0\r\n\r\n" + protocol.encode_chunked(body)
    elif preview is not None and ieof:
        body_bytes = (
            b"%x\r\n%s\r\n0; ieof\r\n\r\n" % (len(body), body) if body else b"0; ieof\r\n\r\n"
        )
    else:
        body_bytes = protocol.encode_chunked(body)
    return head + http_hdr + body_bytes


def null_body_reqmod() -> bytes:
    http_hdr = b"PUT /x HTTP/1.1\r\nHost: x\r\n\r\n"
    return (
        b"REQMOD icap://s/masp ICAP/1.0\r\nHost: s\r\nAllow: 204\r\n"
        b"Encapsulated: req-hdr=0, null-body=" + str(len(http_hdr)).encode() + b"\r\n\r\n"
        + http_hdr
    )


def run_handler(message: bytes, config: IcapConfig, *, decision_action="allow", terminal=True, store_error=None):
    writer = FakeWriter()
    stored = StoredSample(
        original_filename="icap.bin",
        stored_filename="stored.bin",
        storage_path="/tmp/stored.bin",
        content_type="application/octet-stream",
        size_bytes=8,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="ab" * 32,
    )
    scan = FakeScan(status="completed" if terminal else "running")
    decision = ScanDecision(
        action=decision_action,
        label="x",
        tone="neutral",
        confidence="high",
        policy="test",
        reason="test",
        reasons=[],
    )
    store_mock = patch.object(
        server, "store_bytes", side_effect=store_error, return_value=stored
    ) if store_error else patch.object(server, "store_bytes", return_value=stored)

    async def _run() -> None:
        reader = await _make_reader(message)
        await server.handle_connection(reader, writer, config)

    with store_mock, patch.object(
        server, "enqueue_scan_from_stored_sample", return_value=scan
    ), patch.object(
        server, "wait_for_terminal_scan", new=AsyncMock(return_value=scan)
    ), patch.object(
        server, "scan_is_terminal", return_value=terminal
    ), patch.object(
        server, "resolve_scan_decision", return_value=decision
    ):
        asyncio.run(_run())
    return bytes(writer.buffer), writer


class IcapServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = IcapConfig()

    def test_options_returns_capabilities(self) -> None:
        writer = FakeWriter()

        async def _run() -> None:
            reader = await _make_reader(b"OPTIONS icap://s/masp ICAP/1.0\r\nHost: s\r\n\r\n")
            await server.handle_connection(reader, writer, self.config)

        asyncio.run(_run())
        self.assertTrue(bytes(writer.buffer).startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"Methods:", bytes(writer.buffer))

    def test_clean_file_is_allowed_204(self) -> None:
        out, _ = run_handler(reqmod_message(b"clean-bytes"), self.config, decision_action="allow")
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_review_passes_by_default(self) -> None:
        out, _ = run_handler(reqmod_message(b"maybe"), self.config, decision_action="review")
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_review_blocks_when_configured(self) -> None:
        config = IcapConfig(block_on_review=True)
        out, _ = run_handler(reqmod_message(b"maybe"), config, decision_action="review")
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"HTTP/1.1 403 Forbidden", out)

    def test_malicious_file_is_blocked_200(self) -> None:
        out, _ = run_handler(reqmod_message(b"evil"), self.config, decision_action="block")
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"HTTP/1.1 403 Forbidden", out)

    def test_incomplete_scan_fails_closed(self) -> None:
        out, _ = run_handler(reqmod_message(b"slow"), self.config, terminal=False)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))

    def test_incomplete_scan_fails_open_when_configured(self) -> None:
        config = IcapConfig(fail_closed=False)
        out, _ = run_handler(reqmod_message(b"slow"), config, terminal=False)
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_oversized_file_is_blocked_when_fail_closed(self) -> None:
        from app.services.ingest import UploadTooLargeError

        out, _ = run_handler(
            reqmod_message(b"toobig"),
            self.config,
            store_error=UploadTooLargeError(10, 100),
        )
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))

    def test_null_body_is_allowed(self) -> None:
        out, _ = run_handler(null_body_reqmod(), self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_preview_requests_continue_then_blocks(self) -> None:
        out, _ = run_handler(
            reqmod_message(b"evil-body", preview=0),
            self.config,
            decision_action="block",
        )
        self.assertIn(b"ICAP/1.0 100 Continue\r\n\r\n", out)
        self.assertIn(b"ICAP/1.0 200 OK\r\n", out)

    def test_allowlist_rejects_unlisted_ip(self) -> None:
        config = IcapConfig(allowed_ips=frozenset({"10.0.0.1"}))
        writer = FakeWriter(peer=("192.168.1.9", 4444))

        async def _run() -> None:
            reader = await _make_reader(reqmod_message(b"x"))
            await server.handle_connection(reader, writer, config)

        asyncio.run(_run())
        self.assertEqual(bytes(writer.buffer), b"")
        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
