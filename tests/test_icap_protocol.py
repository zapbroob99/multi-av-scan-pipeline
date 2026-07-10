import unittest

from app.icap import protocol


class IcapProtocolParseTests(unittest.TestCase):
    def test_parse_reqmod_head(self) -> None:
        raw = (
            b"REQMOD icap://scanner:1344/masp ICAP/1.0\r\n"
            b"Host: scanner:1344\r\n"
            b"Allow: 204\r\n"
            b"Preview: 0\r\n"
            b"Encapsulated: req-hdr=0, req-body=170\r\n"
            b"\r\n"
        )
        head = protocol.parse_head(raw)
        self.assertEqual(head.method, "REQMOD")
        self.assertEqual(head.service, "masp")
        self.assertEqual(head.header("allow"), "204")
        self.assertIn("preview", head.headers)
        self.assertEqual(head.encapsulated, [("req-hdr", 0), ("req-body", 170)])

    def test_parse_options_head(self) -> None:
        head = protocol.parse_head(
            b"OPTIONS icap://h/masp ICAP/1.0\r\nHost: h\r\n\r\n"
        )
        self.assertEqual(head.method, "OPTIONS")
        self.assertEqual(head.service, "masp")
        self.assertEqual(head.encapsulated, [])

    def test_malformed_request_line_raises(self) -> None:
        with self.assertRaises(protocol.IcapProtocolError):
            protocol.parse_head(b"GARBAGE\r\n\r\n")

    def test_service_from_uri(self) -> None:
        self.assertEqual(protocol.service_from_uri("icap://host:1344/masp"), "masp")
        self.assertEqual(protocol.service_from_uri("icap://host/av?x=1"), "av")
        self.assertEqual(protocol.service_from_uri("icap://host"), "")

    def test_header_block_length_covers_all_headers_before_body(self) -> None:
        self.assertEqual(
            protocol.header_block_length([("req-hdr", 0), ("req-body", 170)]), 170
        )
        self.assertEqual(
            protocol.header_block_length(
                [("req-hdr", 0), ("res-hdr", 50), ("res-body", 120)]
            ),
            120,
        )
        self.assertEqual(
            protocol.header_block_length([("req-hdr", 0), ("null-body", 90)]), 90
        )

    def test_body_section_detection(self) -> None:
        self.assertEqual(
            protocol.body_section([("req-hdr", 0), ("req-body", 10)]), "req-body"
        )
        self.assertEqual(
            protocol.body_section([("res-hdr", 0), ("res-body", 10)]), "res-body"
        )
        self.assertIsNone(protocol.body_section([("req-hdr", 0), ("null-body", 10)]))


class IcapChunkedTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self) -> None:
        payload = b"EICAR-TEST-BYTES\x00\x01\x02"
        encoded = protocol.encode_chunked(payload)
        self.assertTrue(encoded.endswith(b"0\r\n\r\n"))
        self.assertEqual(protocol.decode_chunked(encoded), payload)

    def test_decode_multiple_chunks(self) -> None:
        raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(protocol.decode_chunked(raw), b"hello world")

    def test_encode_empty(self) -> None:
        self.assertEqual(protocol.encode_chunked(b""), b"0\r\n\r\n")
        self.assertEqual(protocol.decode_chunked(b"0\r\n\r\n"), b"")

    def test_ieof_marker_detection(self) -> None:
        self.assertTrue(protocol.chunked_is_ieof(b"4\r\ndata\r\n0; ieof\r\n\r\n"))
        self.assertFalse(protocol.chunked_is_ieof(b"4\r\ndata\r\n0\r\n\r\n"))


class IcapResponseBuildTests(unittest.TestCase):
    def test_options_response_advertises_capabilities(self) -> None:
        raw = protocol.build_options_response(preview_bytes=0)
        self.assertTrue(raw.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"Methods: REQMOD, RESPMOD", raw)
        self.assertIn(b"Allow: 204", raw)
        self.assertIn(b"Encapsulated: null-body=0", raw)
        self.assertTrue(raw.endswith(b"\r\n\r\n"))

    def test_no_content_allows_transfer(self) -> None:
        raw = protocol.build_no_content()
        self.assertTrue(raw.startswith(b"ICAP/1.0 204 No Content\r\n"))
        self.assertIn(b"null-body=0", raw)

    def test_block_response_wraps_http_403(self) -> None:
        raw = protocol.build_block_response(message="nope")
        self.assertTrue(raw.startswith(b"ICAP/1.0 200 OK\r\n"))
        self.assertIn(b"Encapsulated: res-hdr=0, res-body=", raw)
        self.assertIn(b"HTTP/1.1 403 Forbidden\r\n", raw)
        self.assertIn(b"Content-Length: 4\r\n", raw)
        self.assertTrue(raw.endswith(b"0\r\n\r\n"))

    def test_continue_response(self) -> None:
        self.assertEqual(protocol.build_continue(), b"ICAP/1.0 100 Continue\r\n\r\n")


if __name__ == "__main__":
    unittest.main()
