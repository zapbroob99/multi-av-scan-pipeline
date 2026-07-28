"""Pure ICAP (RFC 3507) message parsing and response building.

No sockets or blocking I/O here so the wire format can be unit-tested in full.
The async read/write loop lives in ``app.icap.server``.
"""

from __future__ import annotations

from dataclasses import dataclass

ICAP_VERSION = "ICAP/1.0"
DEFAULT_ISTAG = "MASP-ICAP-1"
CRLF = b"\r\n"


class IcapProtocolError(ValueError):
    """Raised when an ICAP message cannot be parsed."""


@dataclass(frozen=True)
class IcapHead:
    method: str
    uri: str
    version: str
    headers: dict[str, str]
    encapsulated: list[tuple[str, int]]

    @property
    def service(self) -> str:
        return service_from_uri(self.uri)

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def parse_head(head: bytes) -> IcapHead:
    """Parse the ICAP request line + headers (the block ending in a blank line)."""
    text = head.decode("iso-8859-1")
    lines = text.split("\r\n")
    request_line = lines[0].strip()
    if not request_line:
        raise IcapProtocolError("Empty ICAP request line.")
    parts = request_line.split()
    if len(parts) != 3:
        raise IcapProtocolError(f"Malformed ICAP request line: {request_line!r}")
    method, uri, version = parts

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    encapsulated = parse_encapsulated(headers.get("encapsulated", ""))
    return IcapHead(
        method=method.upper(),
        uri=uri,
        version=version,
        headers=headers,
        encapsulated=encapsulated,
    )


def service_from_uri(uri: str) -> str:
    # icap://host:port/service -> service
    without_scheme = uri.split("://", 1)[-1]
    path = without_scheme.split("/", 1)
    if len(path) < 2:
        return ""
    return path[1].split("?", 1)[0].strip("/")


def parse_encapsulated(value: str) -> list[tuple[str, int]]:
    sections: list[tuple[str, int]] = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, _, offset = entry.partition("=")
        try:
            sections.append((name.strip(), int(offset.strip())))
        except ValueError:
            continue
    return sections


# The sections each request method may legally carry (RFC 3507 4.4). opt-body
# belongs to OPTIONS responses only and must never appear in REQMOD/RESPMOD —
# the body reader does not recognize it, so accepting it would route the message
# down the no-body path and allow it unscanned.
_ALLOWED_SECTIONS = {
    "REQMOD": {"req-hdr": False, "req-body": True, "null-body": True},
    "RESPMOD": {"req-hdr": False, "res-hdr": False, "res-body": True, "null-body": True},
}


def encapsulated_well_formed(raw: str, method: str) -> bool:
    """True if an ``Encapsulated`` header is valid for ``method`` (RFC 3507 4.4).

    Enforced, so a malformed header FAILS CLOSED instead of being treated as a
    no-body message that passes unscanned:

    - every entry is ``name=<non-negative int>`` with a section name legal for
      the method (so ``opt-body`` is rejected in REQMOD/RESPMOD);
    - offsets are non-decreasing in declared order;
    - exactly one body/null-body section, and it is the last element;
    - no duplicate sections.
    """
    allowed = _ALLOWED_SECTIONS.get(method.upper())
    if allowed is None:
        return False

    entries = [entry.strip() for entry in raw.split(",") if entry.strip()]
    if not entries:
        return False

    seen: set[str] = set()
    offsets: list[int] = []
    body_index: int | None = None
    for index, entry in enumerate(entries):
        name, sep, offset_text = entry.partition("=")
        if not sep:
            return False
        name = name.strip()
        if name not in allowed or name in seen:
            return False
        seen.add(name)
        try:
            offset = int(offset_text.strip())
        except ValueError:
            return False
        if offset < 0:
            return False
        offsets.append(offset)
        if allowed[name]:  # a body / null-body section
            if body_index is not None:
                return False  # more than one body section
            body_index = index

    if offsets != sorted(offsets):
        return False
    return body_index == len(entries) - 1


def body_section(encapsulated: list[tuple[str, int]]) -> str | None:
    """Return the name of the body section (req-body/res-body), or None."""
    for name, _ in encapsulated:
        if name in {"req-body", "res-body"}:
            return name
    return None


def header_block_length(encapsulated: list[tuple[str, int]]) -> int:
    """Bytes of encapsulated HTTP header material before the body starts.

    Encapsulated offsets are relative to the start of the encapsulated data, so
    the body (or null-body) offset is exactly the number of header bytes that
    precede it — covering req-hdr and res-hdr together.
    """
    for name, offset in encapsulated:
        if name in {"req-body", "res-body", "null-body"}:
            return max(0, offset)
    return 0


def decode_chunked(raw: bytes) -> bytes:
    """Decode an HTTP/1.1 chunked body into its raw bytes.

    Stops at the zero-length chunk. Chunk extensions (e.g. ``; ieof``) are
    ignored for the decoded output; use :func:`chunked_is_ieof` on the raw
    bytes to detect the ICAP preview end-of-file marker.
    """
    out = bytearray()
    index = 0
    length = len(raw)
    while index < length:
        line_end = raw.find(CRLF, index)
        if line_end == -1:
            break
        size_line = raw[index:line_end].split(b";", 1)[0].strip()
        if not size_line:
            index = line_end + 2
            continue
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            break
        index = line_end + 2
        if chunk_size == 0:
            break
        out += raw[index:index + chunk_size]
        index += chunk_size
        if raw[index:index + 2] == CRLF:
            index += 2
    return bytes(out)


def chunked_is_ieof(raw: bytes) -> bool:
    """True if a previewed chunked stream carries the ICAP ``ieof`` marker.

    RFC 3507 signals "the preview already contains the whole body" with a
    zero-length last chunk whose extension is ``ieof`` (``0; ieof\\r\\n\\r\\n``).
    """
    return b"; ieof" in raw or b";ieof" in raw


def encode_chunked(body: bytes) -> bytes:
    if not body:
        return b"0\r\n\r\n"
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)


def _istag_header(istag: str) -> bytes:
    return b'ISTag: "%s"\r\n' % istag.encode("ascii", "ignore")


def build_options_response(
    *,
    istag: str = DEFAULT_ISTAG,
    service_label: str = "MASP ICAP Gateway",
    methods: str = "REQMOD, RESPMOD",
    preview_bytes: int = 0,
    max_connections: int = 100,
    options_ttl: int = 3600,
) -> bytes:
    lines = [
        b"ICAP/1.0 200 OK",
        b"Methods: " + methods.encode("ascii"),
        b'ISTag: "' + istag.encode("ascii", "ignore") + b'"',
        b"Service: " + service_label.encode("ascii", "ignore"),
        b"Allow: 204",
    ]
    # Only advertise Preview when one is configured. MASP needs the whole file
    # to scan, so a preview buys nothing; advertising ``Preview: 0`` would just
    # force an extra 100-Continue round trip on every request.
    if preview_bytes > 0:
        lines.append(b"Preview: " + str(preview_bytes).encode("ascii"))
    lines.extend([
        b"Max-Connections: " + str(max_connections).encode("ascii"),
        b"Options-TTL: " + str(options_ttl).encode("ascii"),
        b"Encapsulated: null-body=0",
    ])
    return CRLF.join(lines) + CRLF + CRLF


def build_no_content(istag: str = DEFAULT_ISTAG) -> bytes:
    """204 No Content: allow the content through unmodified."""
    return (
        b"ICAP/1.0 204 No Content\r\n"
        + _istag_header(istag)
        + b"Encapsulated: null-body=0\r\n\r\n"
    )


def build_block_response(
    *,
    istag: str = DEFAULT_ISTAG,
    http_status: str = "403 Forbidden",
    message: str = "Blocked by MASP: malware detected.",
    content_type: str = "text/plain; charset=utf-8",
) -> bytes:
    """200 OK carrying a replacement HTTP response that rejects the transfer."""
    body = message.encode("utf-8")
    http_header = (
        b"HTTP/1.1 " + http_status.encode("ascii", "ignore") + b"\r\n"
        + b"Content-Type: " + content_type.encode("ascii", "ignore") + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
    )
    res_body = encode_chunked(body)
    encapsulated = b"res-hdr=0, res-body=" + str(len(http_header)).encode("ascii")
    return (
        b"ICAP/1.0 200 OK\r\n"
        + _istag_header(istag)
        + b"Encapsulated: " + encapsulated + b"\r\n\r\n"
        + http_header
        + res_body
    )


def build_unmodified_response(
    encapsulated: list[tuple[str, int]],
    http_header: bytes,
    body: bytes,
    *,
    istag: str = DEFAULT_ISTAG,
) -> bytes:
    """200 OK echoing the original message unchanged.

    RFC 3507 4.6: a ``204 No Content`` may only be sent when the client
    offered ``Allow: 204`` (or sent a preview). When it did not, "allow the
    transfer" must be expressed by returning the original encapsulated message
    verbatim in a 200. The header sections keep their original offsets; the
    body is re-chunked and its offset becomes the header-block length.
    """
    hdr_len = len(http_header)
    sections: list[str] = []
    for name, offset in encapsulated:
        if name in {"req-body", "res-body", "null-body"}:
            continue
        sections.append(f"{name}={offset}")

    body_name = body_section(encapsulated)
    if body_name is None:
        sections.append(f"null-body={hdr_len}")
        body_bytes = b""
    else:
        sections.append(f"{body_name}={hdr_len}")
        body_bytes = encode_chunked(body)

    encap = ", ".join(sections).encode("ascii")
    return (
        b"ICAP/1.0 200 OK\r\n"
        + _istag_header(istag)
        + b"Encapsulated: " + encap + b"\r\n\r\n"
        + http_header
        + body_bytes
    )


def build_method_not_allowed(istag: str = DEFAULT_ISTAG) -> bytes:
    """405 Method Not Allowed for methods other than OPTIONS/REQMOD/RESPMOD."""
    return (
        b"ICAP/1.0 405 Method Not Allowed\r\n"
        + _istag_header(istag)
        + b"Encapsulated: null-body=0\r\n\r\n"
    )


def build_bad_request(istag: str = DEFAULT_ISTAG) -> bytes:
    """400 Bad Request for messages that cannot be parsed."""
    return (
        b"ICAP/1.0 400 Bad Request\r\n"
        + _istag_header(istag)
        + b"Encapsulated: null-body=0\r\n\r\n"
    )


def build_continue() -> bytes:
    """100 Continue: ask the client to send the rest of a previewed body."""
    return b"ICAP/1.0 100 Continue\r\n\r\n"
