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

# The MASP containers run as the unprivileged fixed id baked into the image
# (Dockerfile: user/group 10001). Bind-mounted host directories keep their host
# ownership inside the container, so they must be owned by that id or the
# services cannot write samples, staging files, or rules.
PILOT_CONTAINER_UID="${PILOT_CONTAINER_UID:-10001}"
PILOT_CONTAINER_GID="${PILOT_CONTAINER_GID:-10001}"

pilot_prepare_data_dir() {
    local path="$1"
    mkdir -p "$path"
    if ! chmod 0750 "$path" 2>/dev/null; then
        printf 'WARNING: could not set Unix mode 0750 on %s; enforce equivalent host/storage ACLs.\n' \
            "$path" >&2
    fi
    # 0750 keeps the directory off-limits to other host users; the owner is the
    # container id so the unprivileged services can still write.
    #
    # Recursive on purpose. Upgrading a host whose containers previously ran as
    # root leaves the existing contents root-owned. Reads and deletes would still
    # work (they depend on the directory, which is chowned above), but REPLACING
    # an existing file fails -- overwriting a YARA rule from the admin UI is the
    # case that breaks. A metadata-only walk is cheap next to an install, and it
    # is idempotent, so it runs on every install rather than being a one-off
    # migration someone has to remember.
    if ! chown -R "$PILOT_CONTAINER_UID:$PILOT_CONTAINER_GID" "$path" 2>/dev/null; then
        printf 'WARNING: could not chown %s to %s:%s; the containers run as that id and need write access. Set it manually (chown -R %s:%s %s) or the pilot will fail to store samples.\n' \
            "$path" "$PILOT_CONTAINER_UID" "$PILOT_CONTAINER_GID" \
            "$PILOT_CONTAINER_UID" "$PILOT_CONTAINER_GID" "$path" >&2
    fi
}

pilot_compose() {
    "${PILOT_COMPOSE[@]}" "$@"
}
