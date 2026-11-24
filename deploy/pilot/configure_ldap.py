"""Interactively prepare and verify a pilot LDAP environment before upgrade."""

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile


def ask(prompt, default=""):
    return input(prompt + (f" [{default}]" if default else "") + ": ").strip() or default


def collect():
    kind = ask("Dizin türü (ad/openldap)", "ad").lower()
    mode = ask("TLS yöntemi (ldaps/starttls)", "ldaps").lower()
    if kind not in {"ad", "openldap"} or mode not in {"ldaps", "starttls"}:
        raise ValueError("Dizin türü veya TLS yöntemi geçersiz.")
    host = ask("Dizin sunucusunun sertifikadaki DNS adı")
    port = ask("Dizin portu", "636" if mode == "ldaps" else "389")
    path = ask("Kurum CA zinciri PEM dosyasının sunucudaki yolu (sistem güveni için boş)")
    ca = ""
    if path:
        pem = Path(path).read_bytes()
        if len(pem) > 64000 or b"PRIVATE KEY" in pem:
            raise ValueError("Yalnızca genel CA sertifikalarını içeren PEM dosyası kullanın.")
        ssl.create_default_context(cadata=pem.decode("ascii"))
        ca = base64.b64encode(pem).decode("ascii")
    bind = ask("Salt okunur arama hesabının DN değeri")
    password = getpass.getpass("Arama hesabının parolası: ")
    base = ask("Kullanıcı arama kökü (Base DN)")
    admin = ask("MASP yönetici grubunun DN değeri (kullanılmıyorsa boş)")
    analyst = ask("MASP analist grubunun DN değeri (kullanılmıyorsa boş)")
    if not all((host, bind, password, base)) or not (admin or analyst):
        raise ValueError("Sunucu, arama hesabı/parolası, arama kökü ve en az bir grup gerekli.")
    attr = ask("Kullanıcı adı özniteliği", "sAMAccountName" if kind == "ad" else "uid")
    values = dict(ENABLED="1", HOST=host, PORT=port, TLS_MODE=mode, CA_CERT_FILE="",
                  CA_PEM_B64=ca, BIND_DN=bind, BIND_PASSWORD=password, BASE_DN=base,
                  ADMIN_GROUP_DN=admin, ANALYST_GROUP_DN=analyst, USERNAME_ATTRIBUTE=attr,
                  DISPLAY_NAME_ATTRIBUTE=ask("Görünen ad özniteliği", "displayName" if kind == "ad" else "cn"),
                  GROUP_ATTRIBUTE=ask("Doğrudan grup üyeliği özniteliği", "memberOf"),
                  USER_FILTER=ask("Kullanıcı arama filtresi", f"({attr}={{username}})"))
    return {"MASP_LDAP_" + key: value for key, value in values.items()}


def quoted(value):
    if any(ord(c) < 32 for c in value):
        raise ValueError("Ayar değerinde kontrol karakteri kullanılamaz.")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '$$') + '"'


PROBE = """
import json, os, sys
from app.services.ldap_auth import authenticate_ldap, load_ldap_config
from app.database import connect
try:
    args = json.load(sys.stdin)
    if any(os.getenv(k) != v for k, v in args['settings'].items()):
        sys.exit('LDAP ayarları Compose üzerinden doğru aktarılmadı.')
    user = authenticate_ldap(args['user'], args['password'], load_ldap_config(os.environ))
    if not user or user.role != args['role']:
        sys.exit('Test girişi veya beklenen rol doğrulanamadı.')
    with connect() as db:
        local = db.execute("SELECT 1 FROM users WHERE auth_source = 'local' AND LOWER(username) IN (LOWER(?), LOWER(?)) LIMIT 1",
                           (args['user'], user.username)).fetchone()
        if local:
            sys.exit('Test kullanıcı adı yerel MASP hesabıyla çakışıyor.')
except Exception as exc:
    sys.exit('LDAP ön kontrolü başarısız (' + type(exc).__name__ + '). DNS, port, TLS, bind, filtre ve grup eşlemesini kontrol edin.')
print('LDAP kimlik ve rol kontrolü başarılı.')
"""


def prepare(env_file, project):
    if not sys.stdin.isatty():
        raise ValueError("LDAP kurulumu etkileşimli bir SSH terminali gerektirir.")
    settings = collect()
    print("Geçiş öncesi test için yetkili bir dizin hesabı kullanın.")
    user = ask("Test kullanıcısı")
    role = ask("Bu hesap için beklenen MASP rolü (admin/analyst)")
    password = getpass.getpass("Test kullanıcısının parolası (saklanmaz): ")
    if not user or not password or role not in {"admin", "analyst"}:
        raise ValueError("Test hesabı, parolası ve beklenen rol gerekli.")
    verify_settings(env_file, project, "LDAP", settings, PROBE,
                    dict(settings=settings, user=user, password=password, role=role))


def verify_settings(env_file, project, name, settings, probe, probe_input=None):
    # Compose gives the last definition precedence. Preserve all existing dotenv
    # syntax, including multiline values. Replace only our own previous block.
    marker = f"# MASP managed {name} configuration"
    end_marker = f"\n# End MASP {name}\n"
    original = env_file.read_text(encoding="utf-8")
    start = original.find("\n" + marker + "\n")
    if start >= 0:
        end = original.index(end_marker, start)
        original = original[:start] + original[end + len(end_marker):]
    block = "\n" + marker + "\n" + "".join(f"{k}={quoted(v)}\n" for k, v in settings.items())
    with tempfile.NamedTemporaryFile(mode="w", dir=env_file.parent, encoding="utf-8",
                                     delete=False) as tmp:
        candidate = Path(tmp.name)
    try:
        candidate.write_text(original + block + end_marker.lstrip("\n"), encoding="utf-8")
        cmd = ["docker", "compose", "-p", project, "-f", str(env_file.parent / "docker-compose.pilot.yml"),
               "--env-file", str(candidate), "run", "--rm", "--no-deps", "-T",
               "--entrypoint", "python", "app", "-c", probe]
        subprocess.run(cmd, input=json.dumps(probe_input), text=True, check=True, timeout=120)
        os.replace(candidate, env_file)
    finally:
        candidate.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("env_file", type=Path)
    parser.add_argument("project")
    args = parser.parse_args()
    try:
        prepare(args.env_file.resolve(), args.project)
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt, EOFError):
        sys.exit("LDAP yapılandırması uygulanmadı. Önceki çalışan kurulum korunuyor.")
