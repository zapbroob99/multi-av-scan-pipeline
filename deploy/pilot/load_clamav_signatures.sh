#!/usr/bin/env bash
# Load ClamAV signature databases into the pilot's clamav-db volume.
#
# For hosts without access to database.clamav.net: fetch main, daily and
# bytecode (.cvd or .cld) on a connected machine, carry them over, and run this.
# Before the first start it replaces the database bundled in the ClamAV image,
# which dates from when the image was built and is usually months old; on a
# running stack clamd is told to reload.
#
# Usage: deploy/pilot/load_clamav_signatures.sh [--env-file PATH] SIGNATURE_DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
SOURCE_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            [[ $# -ge 2 ]] || pilot_die "--env-file requires a path"
            ENV_FILE="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,10p' "$0"
            exit 0
            ;;
        *)
            [[ -z "$SOURCE_DIR" ]] || pilot_die "unexpected argument: $1"
            SOURCE_DIR="$1"
            shift
            ;;
    esac
done

[[ -n "$SOURCE_DIR" ]] || pilot_die "give the directory that holds main, daily and bytecode databases"
[[ -d "$SOURCE_DIR" ]] || pilot_die "signature directory not found: $SOURCE_DIR"
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
for name in main daily bytecode; do
    if [[ ! -f "$SOURCE_DIR/$name.cvd" && ! -f "$SOURCE_DIR/$name.cld" ]]; then
        pilot_die "missing $name.cvd or $name.cld in $SOURCE_DIR"
    fi
done

pilot_init "$ENV_FILE"
pilot_require_command docker

# The clamav service's own image and volume; no network is needed for a copy.
# sigtool rejects a truncated or tampered database before it replaces a good one.
pilot_compose run --rm --no-deps -T --entrypoint sh -v "$SOURCE_DIR:/incoming:ro" clamav -c '
    set -e
    for file in /incoming/*.cvd /incoming/*.cld; do
        [ -f "$file" ] || continue
        sigtool --info "$file" | grep -E "^(Version|Build time):" | sed "s|^|$(basename "$file"): |"
    done
    # ClamAV 1.5 keeps detached .sign files beside the databases; carry them too.
    for file in /incoming/*.cvd /incoming/*.cld /incoming/*.sign; do
        [ -f "$file" ] || continue
        cp "$file" /var/lib/clamav/
    done
    chown -R clamav:clamav /var/lib/clamav
'

if [[ -n "$(pilot_compose ps -q clamav 2>/dev/null)" ]]; then
    # A running clamd reloads in place; scanning continues on the old database meanwhile.
    # The TCP command is used because clamdscan's default local socket differs by image.
    # A clamd that is still loading its database does not listen yet: wait for it.
    for _ in $(seq 1 90); do
        pong="$(pilot_compose exec -T clamav sh -c 'printf "zPING\0" | nc -w 5 127.0.0.1 3310' 2>/dev/null | tr -d '\000' || true)"
        [[ "$pong" == PONG* ]] && break
        sleep 2
    done
    reply="$(pilot_compose exec -T clamav sh -c 'printf "zRELOAD\0" | nc -w 10 127.0.0.1 3310' | tr -d '\000' || true)"
    [[ "$reply" == RELOADING* ]] || pilot_die "clamd did not accept the reload (reply: ${reply:-none}); restart the clamav service"
    echo "clamd is reloading the signatures."
else
    echo "Signatures are in place; clamd loads them when the stack starts."
fi
