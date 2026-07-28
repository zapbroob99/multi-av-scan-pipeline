#!/usr/bin/env bash

set -euo pipefail

PILOT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PILOT_ROOT_DIR="$(cd "$PILOT_SCRIPT_DIR/../.." && pwd)"
PILOT_COMPOSE_FILE="$PILOT_ROOT_DIR/docker-compose.pilot.yml"
PILOT_ENV_FILE=""
PILOT_PROJECT=""
PILOT_COMPOSE=()

pilot_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

pilot_init() {
    PILOT_ENV_FILE="${1:-${MASP_PILOT_ENV_FILE:-$PILOT_ROOT_DIR/.env.pilot}}"
    PILOT_PROJECT="${MASP_PILOT_PROJECT:-masp-pilot}"
    [[ -f "$PILOT_COMPOSE_FILE" ]] || pilot_die "compose file missing: $PILOT_COMPOSE_FILE"
    [[ -f "$PILOT_ENV_FILE" ]] || pilot_die "environment file missing: $PILOT_ENV_FILE"
    PILOT_COMPOSE=(
        docker compose
        -p "$PILOT_PROJECT"
        -f "$PILOT_COMPOSE_FILE"
        --env-file "$PILOT_ENV_FILE"
    )
}

pilot_require_command() {
    command -v "$1" >/dev/null 2>&1 || pilot_die "required command not found: $1"
}

pilot_env_value() {
    local key="$1"
    awk -F= -v wanted="$key" '
        $1 == wanted {
            sub(/^[^=]*=/, "")
            sub(/\r$/, "")
            print
            exit
        }
    ' "$PILOT_ENV_FILE"
}

pilot_storage_dir() {
    local value
    value="$(pilot_env_value MASP_STORAGE_DIR)"
    [[ -n "$value" ]] || pilot_die "MASP_STORAGE_DIR is empty"
    [[ "$value" == /* ]] || pilot_die "MASP_STORAGE_DIR must be an absolute Linux path"
    [[ "$value" != "/" ]] || pilot_die "MASP_STORAGE_DIR cannot be /"
    printf '%s\n' "$value"
}

pilot_rules_dir() {
    local value
    value="$(pilot_env_value MASP_RULES_DIR)"
    [[ -n "$value" ]] || pilot_die "MASP_RULES_DIR is empty"
    if [[ "$value" != /* ]]; then
        value="$PILOT_ROOT_DIR/$value"
    fi
    [[ "$value" != "/" ]] || pilot_die "MASP_RULES_DIR cannot be /"
    printf '%s\n' "$value"
}

pilot_prepare_data_dir() {
    local path="$1"
    mkdir -p "$path"
    if ! chmod 0750 "$path" 2>/dev/null; then
        printf 'WARNING: could not set Unix mode 0750 on %s; enforce equivalent host/storage ACLs.\n' \
            "$path" >&2
    fi
}

pilot_compose() {
    "${PILOT_COMPOSE[@]}" "$@"
}
