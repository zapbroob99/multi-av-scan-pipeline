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
    batch_id: int | None = None


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


def reqmod_message(
    body: bytes, *, preview: int | None = None, ieof: bool = False, allow_204: bool = True
) -> bytes:
    http_hdr = (
        b"PUT /upload HTTP/1.1\r\nHost: x\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
    )
    encapsulated = b"req-hdr=0, req-body=" + str(len(http_hdr)).encode()
    lines = [b"REQMOD icap://s/masp ICAP/1.0", b"Host: s"]
    if allow_204:
        lines.append(b"Allow: 204")
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


def run_handler(message: bytes, config: IcapConfig, *, decision_action="allow", terminal=True, store_error=None, batch_id=None):
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
    scan = FakeScan(status="completed" if terminal else "running", batch_id=batch_id)
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

    def test_allow_without_allow_204_echoes_unmodified(self) -> None:
        # Client did not offer Allow: 204 and did not preview -> must not 204;
        # the original message is echoed back in a 200 instead.
        out, _ = run_handler(
            reqmod_message(b"clean-bytes", allow_204=False),
            self.config,
            decision_action="allow",
        )
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertNotIn(b"204 No Content", out)
        self.assertIn(b"Encapsulated: req-hdr=0, req-body=", out)
        self.assertIn(b"PUT /upload HTTP/1.1", out)
        # No 403 replacement — this is an allow, the original bytes come back.
        self.assertNotIn(b"403 Forbidden", out)
        self.assertIn(b"clean-bytes", out)

    def test_preview_allows_204_without_allow_header(self) -> None:
        # A preview may always be answered with 204 even without Allow: 204.
        out, _ = run_handler(
            reqmod_message(b"clean", preview=0, allow_204=False),
            self.config,
            decision_action="allow",
        )
        self.assertIn(b"ICAP/1.0 204 No Content\r\n", out)

    def test_unknown_method_returns_405_with_istag(self) -> None:
        writer = FakeWriter()

        async def _run() -> None:
            reader = await _make_reader(b"FROBNICATE icap://s/masp ICAP/1.0\r\nHost: s\r\n\r\n")
            await server.handle_connection(reader, writer, self.config)

        asyncio.run(_run())
        out = bytes(writer.buffer)
        self.assertTrue(out.startswith(b"ICAP/1.0 405 Method Not Allowed\r\n"))
        self.assertIn(b"ISTag:", out)

    def test_malformed_request_returns_400(self) -> None:
        writer = FakeWriter()

        async def _run() -> None:
            reader = await _make_reader(b"GARBAGE-LINE\r\n\r\n")
            await server.handle_connection(reader, writer, self.config)

        asyncio.run(_run())
        out = bytes(writer.buffer)
        self.assertTrue(out.startswith(b"ICAP/1.0 400 Bad Request\r\n"))
        self.assertIn(b"ISTag:", out)

    def test_allowlist_rejects_unlisted_ip(self) -> None:
        config = IcapConfig(allowed_ips=frozenset({"10.0.0.1"}))
        writer = FakeWriter(peer=("192.168.1.9", 4444))

        async def _run() -> None:
            reader = await _make_reader(reqmod_message(b"x"))
            await server.handle_connection(reader, writer, config)

        asyncio.run(_run())
        self.assertEqual(bytes(writer.buffer), b"")
        self.assertTrue(writer.closed)


class IcapArchiveGateTests(unittest.TestCase):
    """Archive/container uploads are rejected on the ICAP path by default."""

    def test_archive_upload_is_blocked_even_when_clean(self) -> None:
        out, _ = run_handler(
            reqmod_message(b"PK-archive"),
            IcapConfig(),
            decision_action="allow",
            batch_id=7,
        )
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)

    def test_non_archive_upload_still_allowed(self) -> None:
        out, _ = run_handler(
            reqmod_message(b"plain"),
            IcapConfig(),
            decision_action="allow",
            batch_id=None,
        )
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_archive_gate_can_be_disabled(self) -> None:
        out, _ = run_handler(
            reqmod_message(b"PK-archive"),
            IcapConfig(block_archives=False),
            decision_action="allow",
            batch_id=7,
        )
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))


HTTP_HDR = b"PUT /upload HTTP/1.1\r\nHost: x\r\n\r\n"


def reqmod_head(encapsulated: bytes, *, allow_204: bool = True) -> bytes:
    lines = [b"REQMOD icap://s/masp ICAP/1.0", b"Host: s"]
    if allow_204:
        lines.append(b"Allow: 204")
    lines.append(b"Encapsulated: " + encapsulated)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def run_raw(message: bytes, config: IcapConfig):
    writer = FakeWriter()

    async def _run() -> None:
        reader = await _make_reader(message)
        await server.handle_connection(reader, writer, config)

    asyncio.run(_run())
    return bytes(writer.buffer), writer


class IcapBodyHardeningTests(unittest.TestCase):
    """A malformed or oversized body must fail closed, never scan a partial."""

    def setUp(self) -> None:
        self.config = IcapConfig()

    def _encap(self) -> bytes:
        return b"req-hdr=0, req-body=" + str(len(HTTP_HDR)).encode()

    def test_truncated_body_without_terminator_fails_closed(self) -> None:
        # A chunk is announced but the stream ends before the zero-chunk.
        message = reqmod_head(self._encap()) + HTTP_HDR + b"5\r\nhello\r\n"
        out, writer = run_raw(message, self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)
        self.assertTrue(writer.closed)

    def test_invalid_chunk_size_fails_closed(self) -> None:
        message = reqmod_head(self._encap()) + HTTP_HDR + b"zz\r\nhello\r\n"
        out, _ = run_raw(message, self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)

    def test_oversized_body_blocks_before_store(self) -> None:
        config = IcapConfig(max_bytes=4)
        message = (
            reqmod_head(self._encap()) + HTTP_HDR + protocol.encode_chunked(b"way too many bytes")
        )
        with patch.object(server, "store_bytes") as store_mock:
            out, _ = run_raw(message, config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)
        store_mock.assert_not_called()  # rejected while reading, never stored

    def test_oversized_body_fail_open_allows_204(self) -> None:
        config = IcapConfig(max_bytes=4, fail_closed=False)
        message = (
            reqmod_head(self._encap()) + HTTP_HDR + protocol.encode_chunked(b"way too many bytes")
        )
        out, _ = run_raw(message, config)
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))

    def test_oversized_header_block_fails_closed(self) -> None:
        # req-body offset (= header-block length) far beyond the header cap.
        message = reqmod_head(b"req-hdr=0, req-body=200000") + HTTP_HDR
        out, _ = run_raw(message, self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)

    def test_negative_chunk_size_fails_closed(self) -> None:
        message = reqmod_head(self._encap()) + HTTP_HDR + b"-5\r\nhello\r\n0\r\n\r\n"
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_bad_chunk_terminator_fails_closed(self) -> None:
        # 5 bytes of data followed by "XX" instead of CRLF.
        message = reqmod_head(self._encap()) + HTTP_HDR + b"5\r\nhelloXX0\r\n\r\n"
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_unexpected_chunk_trailer_fails_closed(self) -> None:
        message = reqmod_head(self._encap()) + HTTP_HDR + b"0\r\nTrailer: x\r\n\r\n"
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_missing_final_crlf_fails_closed(self) -> None:
        # Zero-chunk present but the closing blank line is missing (EOF).
        message = reqmod_head(self._encap()) + HTTP_HDR + b"5\r\nhello\r\n0\r\n"
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_lf_only_size_line_fails_closed(self) -> None:
        message = reqmod_head(self._encap()) + HTTP_HDR + b"5\nhello\r\n0\r\n\r\n"
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_total_body_deadline_fails_closed(self) -> None:
        # Body stalls mid-chunk; a small total deadline fires even though the
        # (large) per-read idle timeout has not, bounding slow-drip clients.
        async def _run():
            reader = asyncio.StreamReader()
            reader.feed_data(reqmod_head(self._encap()) + HTTP_HDR + b"5\r\nhel")
            # No feed_eof: the remaining 2 bytes never arrive.
            writer = FakeWriter()
            config = IcapConfig(read_timeout_seconds=60, body_timeout_seconds=0.05)
            await server.handle_connection(reader, writer, config)
            return bytes(writer.buffer)

        out = asyncio.run(_run())
        self.assertIn(b"403 Forbidden", out)


class IcapEncapsulatedValidationTests(unittest.TestCase):
    """A missing or malformed Encapsulated header must fail closed, not allow."""

    def setUp(self) -> None:
        self.config = IcapConfig()

    def test_missing_encapsulated_header_fails_closed(self) -> None:
        message = b"REQMOD icap://s/masp ICAP/1.0\r\nHost: s\r\nAllow: 204\r\n\r\n"
        out, _ = run_raw(message, self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)

    def test_malformed_encapsulated_offset_fails_closed(self) -> None:
        message = (
            reqmod_head(b"req-hdr=0, req-body=xyz")
            + HTTP_HDR
            + protocol.encode_chunked(b"data")
        )
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_encapsulated_without_body_section_fails_closed(self) -> None:
        message = reqmod_head(b"req-hdr=0") + HTTP_HDR
        out, _ = run_raw(message, self.config)
        self.assertIn(b"403 Forbidden", out)

    def test_opt_body_in_reqmod_fails_closed(self) -> None:
        # opt-body is not a REQMOD section; must not route to the no-body allow.
        message = reqmod_head(b"opt-body=0")
        out, _ = run_raw(message, self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)

    def test_genuine_null_body_is_still_allowed(self) -> None:
        out, _ = run_handler(null_body_reqmod(), self.config)
        self.assertTrue(out.startswith(b"ICAP/1.0 204 No Content\r\n"))


class IcapAdmissionTests(unittest.TestCase):
    """Read timeout (slow-loris) and concurrent-scan admission control."""

    def test_stalled_body_read_times_out(self) -> None:
        async def _run() -> None:
            reader = asyncio.StreamReader()
            reader.feed_data(b"5\r\n")  # announces a chunk, never delivers it, no EOF
            with self.assertRaises(server.IcapBodyError):
                await server.read_chunked_body(reader, read_timeout=0.05)

        asyncio.run(_run())

    def test_read_exact_idle_assembles_across_sub_blocks(self) -> None:
        async def _run() -> None:
            reader = asyncio.StreamReader()
            reader.feed_data(b"abcdef")
            reader.feed_eof()
            data = await server._read_exact_idle(reader, 5, None)
            self.assertEqual(data, b"abcde")

        asyncio.run(_run())

    def test_read_exact_idle_raises_on_truncation(self) -> None:
        async def _run() -> None:
            reader = asyncio.StreamReader()
            reader.feed_data(b"abc")  # only 3 of the requested 5
            reader.feed_eof()
            with self.assertRaises(server.IcapBodyError):
                await server._read_exact_idle(reader, 5, None)

        asyncio.run(_run())

    def test_semaphore_bounds_concurrent_scans(self) -> None:
        peak = 0
        current = 0

        async def fake_mod(head, reader, writer, config) -> bool:
            nonlocal peak, current
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.02)
            current -= 1
            return False  # close after one request

        async def _run(semaphore) -> None:
            async def one() -> None:
                reader = await _make_reader(reqmod_message(b"x"))
                await server.handle_connection(reader, FakeWriter(), IcapConfig(), semaphore)

            await asyncio.gather(one(), one(), one())

        with patch.object(server, "handle_modification", new=fake_mod):
            asyncio.run(_run(asyncio.Semaphore(1)))
        self.assertEqual(peak, 1)

    def test_admission_timeout_fails_closed(self) -> None:
        async def _run():
            semaphore = asyncio.Semaphore(1)
            await semaphore.acquire()  # exhaust the only slot
            reader = await _make_reader(reqmod_message(b"x"))
            writer = FakeWriter()
            config = IcapConfig(admission_timeout_seconds=0.05)
            await server.handle_connection(reader, writer, config, semaphore)
            return bytes(writer.buffer), writer

        out, writer = asyncio.run(_run())
        self.assertTrue(out.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"403 Forbidden", out)
        self.assertTrue(writer.closed)

    def test_without_semaphore_scans_run_concurrently(self) -> None:
        peak = 0
        current = 0

        async def fake_mod(head, reader, writer, config) -> bool:
            nonlocal peak, current
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.02)
            current -= 1
            return False

        async def _run() -> None:
            async def one() -> None:
                reader = await _make_reader(reqmod_message(b"x"))
                await server.handle_connection(reader, FakeWriter(), IcapConfig(), None)

            await asyncio.gather(one(), one(), one())

        with patch.object(server, "handle_modification", new=fake_mod):
            asyncio.run(_run())
        self.assertEqual(peak, 3)


if __name__ == "__main__":
    unittest.main()
