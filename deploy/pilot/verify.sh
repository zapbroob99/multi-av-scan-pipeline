#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
if [[ ${1:-} == "--env-file" ]]; then
    [[ $# -eq 2 ]] || pilot_die "usage: verify.sh [--env-file PATH]"
    ENV_FILE="$2"
elif [[ $# -ne 0 ]]; then
    pilot_die "usage: verify.sh [--env-file PATH]"
fi

pilot_init "$ENV_FILE"
pilot_require_command docker
pilot_compose ps

max_bytes="$(pilot_compose exec -T app printenv MASP_UPLOAD_MAX_BYTES | tr -d '\r')"

printf '\n== REST API acceptance ==\n'
pilot_compose exec -T app python tools/verify_scan_api.py \
    --base-url http://127.0.0.1:8000 \
    --eicar \
    --expect-max-bytes "$max_bytes" \
    --require-engine static_metadata \
    --require-engine clamav \
    --require-engine yara

printf '\n== ICAP client binding ==\n'
# Resolved inside the icap container, so this is the key the gateway really uses:
# a value left in .env.pilot without restarting the gateway shows up here.
binding="$(pilot_compose exec -T icap python -c '
import os
from app import database as db
from app.services.health_read import icap_binding
key = os.getenv("MASP_ICAP_SERVICE_CLIENT_KEY", "").strip().lower() or "legacy-default"
with db.connect() as connection:
    found = icap_binding(connection, key)
print("MASP_ICAP_BINDING", found["binding"], key, found["binding_detail"] or "", found["client_name"] or "", sep="|")
' | tr -d '\r')" || pilot_die "could not read the ICAP client binding from the icap container"
# Importing the app may print to stdout (with PostgreSQL: "MASP DB pool enabled"),
# so only the marked line is the answer.
binding="$(printf '%s\n' "$binding" | sed -n 's/^MASP_ICAP_BINDING|//p' | tail -n 1)"
# Not tab-separated: read collapses empty whitespace-separated fields. The display
# name is free text, so it comes last and keeps any separator it contains.
IFS='|' read -r binding_state binding_key binding_detail binding_name <<< "$binding"
case "$binding_state" in
    client)
        printf 'ICAP scans are filed under service client %s (%s).\n' "$binding_name" "$binding_key" ;;
    legacy_default)
        printf 'WARNING: ICAP scans are filed under the compatibility client (legacy-default).\n'
        printf '         For an integration of its own, set MASP_ICAP_SERVICE_CLIENT_KEY in the env file\n'
        printf '         to the key on its Setup tab and run install.sh --no-build.\n' ;;
    unresolved)
        pilot_die "ICAP client key '$binding_key' does not resolve: $binding_detail Every ICAP request fails until the client and its profile are enabled or MASP_ICAP_SERVICE_CLIENT_KEY names an enabled client." ;;
    *)
        pilot_die "could not read the ICAP client binding: $binding" ;;
esac

printf '\n== ICAP acceptance ==\n'
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --options
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --expect allow
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --eicar --expect block

printf '\nMASP pilot acceptance checks passed.\n'
