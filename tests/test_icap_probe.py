import unittest

from tools.icap_probe import verdict_kind


class IcapProbeVerdictTests(unittest.TestCase):
    def test_classifies_allow_204(self) -> None:
        self.assertEqual(verdict_kind(b"ICAP/1.0 204 No Content\r\n\r\n"), "allow")

    def test_classifies_echo_allow_200(self) -> None:
        self.assertEqual(verdict_kind(b"ICAP/1.0 200 OK\r\n\r\nHTTP/1.1 200 OK"), "allow")

    def test_classifies_block_200(self) -> None:
        self.assertEqual(
            verdict_kind(b"ICAP/1.0 200 OK\r\n\r\nHTTP/1.1 403 Forbidden"),
            "block",
        )

    def test_classifies_unknown_response(self) -> None:
        self.assertEqual(verdict_kind(b"ICAP/1.0 500 Server Error\r\n\r\n"), "unknown")


if __name__ == "__main__":
    unittest.main()
