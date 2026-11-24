"""Configure and verify Aselix from the candidate app before switching releases."""

import base64
from getpass import getpass
from pathlib import Path
import ssl
import subprocess
import sys

from configure_ldap import ask, verify_settings


PROBE = """
import sys
from fastapi import HTTPException
from app.services.aselix import ask, ChatQuestion
try:
    ask(ChatQuestion(question='Connection test. Reply OK.'))
except HTTPException as exc:
    sys.exit(exc.detail)
print('Aselix HTTPS, credential and model check passed.')
"""


def prepare(env_file, project):
    if not sys.stdin.isatty():
        raise ValueError("An interactive SSH terminal is required.")
    url = ask("Aselix HTTPS adresi (/v1/chat/completions dahil)")
    model = ask("Aselix model kimliği")
    key = getpass("Aselix API anahtarı (gizli): ")
    path = ask("Kurum CA sertifikasının PEM yolu (sistem güveni için boş)")
    ca = ""
    if path:
        with Path(path).open("rb") as f:
            pem = f.read(64001)
        if len(pem) > 64000 or b"PRIVATE KEY" in pem:
            raise ValueError("Provide a public CA chain in PEM format.")
        ssl.create_default_context(cadata=pem.decode("ascii"))
        ca = base64.b64encode(pem).decode("ascii")
    values = dict(ENABLED="1", URL=url, MODEL=model, API_KEY=key, CA_PEM_B64=ca)
    verify_settings(env_file, project, "Aselix", {"MASP_ASELIX_" + k: v for k, v in values.items()}, PROBE)


if __name__ == "__main__":
    try:
        prepare(Path(sys.argv[1]).resolve(), sys.argv[2])
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt, EOFError):
        sys.exit("Aselix ayarları uygulanamadı. Adres, model, anahtar ve CA sertifikasını kontrol edin.")
