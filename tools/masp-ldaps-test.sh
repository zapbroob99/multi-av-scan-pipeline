#!/usr/bin/env bash
# Run on the pilot host. Only the saved LDAPS transport is probed.
set -eu
exec masp exec -T app python -u - <<'PY'
import os
import socket
import ssl
import sys

from app.services.connection_settings import environment_values, record

try:
    _, saved = record("ldap")
    values = saved["values"] if saved else environment_values("ldap")
    host = values["HOST"].strip()
    port = int(values["PORT"])
    if not host or "://" in host or not 1 <= port <= 65535:
        sys.exit("AYAR HATA: Directory host alanina yalniz DNS adini, port alanina port numarasini girin.")
    if values["TLS_MODE"].strip().lower() != "ldaps":
        sys.exit("AYAR HATA: Kayitli yontem LDAPS degil. Panelde TLS method alanini kontrol edin.")
except Exception as exc:
    sys.exit("AYAR HATA: Kayitli LDAP ayarlari okunamadi (" + type(exc).__name__ + ").")
print(f"Hedef: {host}:{port}  Yontem: LDAPS")
try:
    endpoints = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
except OSError as exc:
    sys.exit(f"DNS HATA: {exc}")
print("DNS OK:", ", ".join(dict.fromkeys(entry[4][0] for entry in endpoints)))
try:
    ca_file = os.getenv("MASP_LDAP_CA_CERT_FILE", "").strip() or None
    tls = ssl.create_default_context(cafile=ca_file, cadata=values["CA_PEM"] or None)
except (OSError, ValueError) as exc:
    sys.exit(f"CA HATA: Guven zinciri yuklenemedi ({type(exc).__name__}).")

failed = False
seen = set()
for family, kind, proto, _, address in endpoints:
    if address in seen:
        continue
    seen.add(address)
    peer = address[0]
    stage = "TCP"
    try:
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(5)
            sock.connect(address)
            print(f"TCP OK: {peer}:{port}")
            stage = "TLS"
            with tls.wrap_socket(sock, server_hostname=host) as secure:
                print(f"TLS OK: {peer} {secure.version()} (sertifika zinciri ve sunucu adi dogrulandi)")
    except OSError as exc:
        failed = True
        print(f"{stage} HATA: {peer}: {exc}")
print("Test bitti. LDAP bind veya kullanici girisi denenmedi.")
sys.exit(1 if failed else 0)
PY
