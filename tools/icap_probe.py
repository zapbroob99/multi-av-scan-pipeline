"""Minimal ICAP client to test the MASP ICAP gateway by hand.

Acts like the storage system's ICAP client: sends an OPTIONS handshake, then a
REQMOD with a file, and prints whether MASP allowed (204) or blocked (200).

Examples (PowerShell):
    .venv\\Scripts\\python.exe tools\\icap_probe.py --options
    .venv\\Scripts\\python.exe tools\\icap_probe.py --file .\\README.md
    .venv\\Scripts\\python.exe tools\\icap_probe.py --eicar
"""

import argparse
import socket

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def talk(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    # The server keeps the connection open (keep-alive), so wait up to `timeout`
    # for the first response byte, then drain quickly and stop.
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            sock.settimeout(1.0)
        return b"".join(chunks)


def options_message(host: str, port: int, service: str) -> bytes:
    return (
        f"OPTIONS icap://{host}:{port}/{service} ICAP/1.0\r\n"
        f"Host: {host}:{port}\r\n\r\n"
    ).encode()


def reqmod_message(
    host: str, port: int, service: str, filename: str, body: bytes, *, allow_204: bool = True
) -> bytes:
    http_hdr = (
        f"PUT /{filename} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    encapsulated = f"req-hdr=0, req-body={len(http_hdr)}".encode()
    allow_line = b"Allow: 204\r\n" if allow_204 else b""
    head = (
        f"REQMOD icap://{host}:{port}/{service} ICAP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
    ).encode() + allow_line + b"Encapsulated: " + encapsulated + b"\r\n\r\n"
    return head + http_hdr + chunked


def verdict(response: bytes) -> str:
    status = response.split(b"\r\n", 1)[0].decode(errors="replace")
    if response.startswith(b"ICAP/1.0 204"):
        return f"ALLOW  ({status})"
    if response.startswith(b"ICAP/1.0 200") and b"403" in response:
        return f"BLOCK  ({status})"
    if response.startswith(b"ICAP/1.0 200"):
        return f"ALLOW  ({status}) [echoed unmodified, no Allow:204 offered]"
    return f"?      ({status})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1344)
    parser.add_argument("--service", default="masp")
    parser.add_argument("--timeout", type=float, default=60.0)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--file", help="Send this file's bytes.")
    group.add_argument("--eicar", action="store_true", help="Send the EICAR test string.")
    group.add_argument("--options", action="store_true", help="Only do the OPTIONS handshake.")
    parser.add_argument(
        "--no-allow-204",
        action="store_true",
        help="Omit Allow: 204 to exercise the RFC-required echo-unmodified allow path.",
    )
    args = parser.parse_args()

    opt = talk(args.host, args.port, options_message(args.host, args.port, args.service), args.timeout)
    print("OPTIONS  ->", opt.split(b"\r\n", 1)[0].decode(errors="replace"))
    if args.options:
        return

    if args.eicar:
        filename, body = "eicar.com", EICAR
    elif args.file:
        with open(args.file, "rb") as handle:
            body = handle.read()
        filename = args.file.replace("\\", "/").rsplit("/", 1)[-1]
    else:
        filename, body = "hello.txt", b"a clean harmless test file\n"

    resp = talk(
        args.host,
        args.port,
        reqmod_message(
            args.host, args.port, args.service, filename, body,
            allow_204=not args.no_allow_204,
        ),
        args.timeout,
    )
    print(f"REQMOD   -> {verdict(resp)}   [{filename}, {len(body)} bytes]")


if __name__ == "__main__":
    main()
