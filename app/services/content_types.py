"""Content classification from a bounded header, shared by every caller.

The ``file_type`` engine and storage protection's light tier must agree on what
a header is, so the signature table lives here once. Classification reads only
the bytes it is given; callers decide how many (never the whole file).
"""
from __future__ import annotations

from dataclasses import dataclass

# (offset, magic, type key). Ordered most specific first: a prefix that is also
# the prefix of another format must come after the longer one.
SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F", "lnk"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"%PDF-", "pdf"),
    (0, b"{\\rtf", "rtf"),
    (0, b"\x7fELF", "elf"),
    (0, b"\xfe\xed\xfa\xce", "macho"),
    (0, b"\xfe\xed\xfa\xcf", "macho"),
    (0, b"\xce\xfa\xed\xfe", "macho"),
    (0, b"\xcf\xfa\xed\xfe", "macho"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"PK\x07\x08", "zip"),
    # Also the Mach-O universal magic; a Java class is by far the more common
    # reading and both are executable, so the family is the same either way.
    (0, b"\xca\xfe\xba\xbe", "java_class"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"MSCF", "cab"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"<?xml", "xml"),
    (0, b"#!", "script"),
    (0, b"MZ", "pe"),
    (0, b"BM", "bmp"),
    (257, b"ustar", "tar"),
)

# Extensions an operator is likely to see, mapped to the content types that are
# legitimate for them. OOXML and JAR/APK are ZIP containers; legacy Office is
# OLE2. An extension absent here is treated as undeclared, never a mismatch.
EXTENSION_TYPES: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "png": frozenset({"png"}),
    "jpg": frozenset({"jpeg"}),
    "jpeg": frozenset({"jpeg"}),
    "gif": frozenset({"gif"}),
    "bmp": frozenset({"bmp"}),
    "zip": frozenset({"zip"}),
    "docx": frozenset({"zip"}),
    "xlsx": frozenset({"zip"}),
    "pptx": frozenset({"zip"}),
    "jar": frozenset({"zip"}),
    "apk": frozenset({"zip"}),
    "odt": frozenset({"zip"}),
    "ods": frozenset({"zip"}),
    "doc": frozenset({"ole2"}),
    "xls": frozenset({"ole2"}),
    "ppt": frozenset({"ole2"}),
    "msi": frozenset({"ole2"}),
    "rtf": frozenset({"rtf"}),
    "exe": frozenset({"pe"}),
    "dll": frozenset({"pe"}),
    "sys": frozenset({"pe"}),
    "so": frozenset({"elf"}),
    "class": frozenset({"java_class"}),
    "lnk": frozenset({"lnk"}),
    "gz": frozenset({"gzip"}),
    "tgz": frozenset({"gzip"}),
    "bz2": frozenset({"bzip2"}),
    "xz": frozenset({"xz"}),
    "7z": frozenset({"7z"}),
    "rar": frozenset({"rar"}),
    "cab": frozenset({"cab"}),
    "tar": frozenset({"tar"}),
    "xml": frozenset({"xml"}),
}

# Types that are executable or can carry code. A mismatch that lands here is
# reported at a higher severity than one that does not.
EXECUTABLE_TYPES = frozenset({"pe", "elf", "macho", "java_class", "lnk", "script", "ole2"})

# Content families an operator writes policy with. Every detected type belongs
# to exactly one; a header that matches nothing is "unrecognized" (plain text,
# CSV and most data formats have no magic bytes and land here).
TYPE_FAMILIES: dict[str, str] = {
    "pe": "executable", "elf": "executable", "macho": "executable",
    "java_class": "executable", "lnk": "executable",
    "script": "script",
    "zip": "archive", "7z": "archive", "rar": "archive", "gzip": "archive",
    "bzip2": "archive", "xz": "archive", "cab": "archive", "tar": "archive",
    "ooxml": "office", "ole2": "office", "rtf": "office",
    "pdf": "pdf",
    "png": "image", "jpeg": "image", "gif": "image", "bmp": "image",
    "xml": "markup",
}
UNRECOGNIZED = "unrecognized"
FAMILIES: tuple[str, ...] = (
    "executable", "script", "archive", "office", "pdf", "image", "markup", UNRECOGNIZED,
)

# Scripts and installers have no reliable magic bytes, so their extension adds
# a family on top of whatever the header shows. This is the honest limit of
# header inspection: a script renamed to .txt is only as visible as its header.
EXTENSION_FAMILIES: dict[str, str] = {
    **{ext: "script" for ext in (
        "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "hta", "sh", "bash", "zsh", "py", "pyw", "pl", "rb", "php", "scr",
    )},
    **{ext: "executable" for ext in ("exe", "dll", "sys", "msi", "msp", "com", "cpl", "lnk", "jar")},
}

# Office's own writer puts this part first, so it sits inside the first local
# header of a genuine OOXML document. Absent from the header means "a zip".
_OOXML_MARKER = b"[Content_Types].xml"


def declared_extension(filename: str) -> str:
    _, _, suffix = (filename or "").rpartition(".")
    return suffix.strip().lower() if suffix and suffix != filename else ""


def detect_type(header: bytes) -> str | None:
    for offset, magic, type_key in SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            return type_key
    return None


@dataclass(frozen=True)
class Classification:
    detected_type: str | None
    extension: str
    content_family: str
    families: frozenset[str]
    # None when the extension is unknown, so it cannot be compared.
    expected_types: frozenset[str] | None

    @property
    def mismatch(self) -> bool:
        return (self.detected_type is not None and self.expected_types is not None
                and self.detected_type not in self.expected_types)


def classify(header: bytes, filename: str) -> Classification:
    """Classify a header and a name into the families policy is written in."""
    detected = detect_type(header)
    if detected == "zip" and _OOXML_MARKER in header:
        detected = "ooxml"
    extension = declared_extension(filename)
    expected = EXTENSION_TYPES.get(extension)
    if expected is not None and "zip" in expected:
        # An OOXML refinement must not turn a real .docx into a mismatch.
        expected = expected | {"ooxml"}
    family = TYPE_FAMILIES.get(detected, UNRECOGNIZED) if detected else UNRECOGNIZED
    families = {family}
    if extension in EXTENSION_FAMILIES:
        families.add(EXTENSION_FAMILIES[extension])
    return Classification(detected, extension, family, frozenset(families), expected)
