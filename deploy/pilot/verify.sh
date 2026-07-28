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

printf '\n== ICAP acceptance ==\n'
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --options
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --expect allow
pilot_compose exec -T icap python tools/icap_probe.py \
    --host 127.0.0.1 --port 1344 --service masp --eicar --expect block

printf '\nMASP pilot acceptance checks passed.\n'
